#!/usr/bin/env python3
"""
v3.14.0 (#32): cloud inventory import — pull running instances from a cloud
provider into the RemotePower fleet as *agentless* device records. Read-only.

No cloud SDK is available server-side (stdlib + cryptography only), so the AWS
path implements SigV4 request signing by hand with `hmac`/`hashlib`. The signer
is verified against AWS's published "get-vanilla" test vector (see
tests/test_v3140.py), so it interoperates with the real EC2 API.

v1 ships the AWS EC2 provider; the module is structured so Azure/GCP (OAuth2
bearer flows) can slot in later. Credentials are supplied by api.py from config
(the secret key is write-only / scrubbed there) — this module never stores them.
"""
import datetime
import hashlib
import hmac
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


# ── AWS Signature Version 4 ──────────────────────────────────────────────────

def _hmac(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _signing_key(secret, datestamp, region, service):
    k = _hmac(('AWS4' + secret).encode('utf-8'), datestamp)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, 'aws4_request')


def sigv4_authorization(method, host, region, service, path, query, payload,
                        access_key, secret_key, amzdate, datestamp):
    """Return (authorization_header, signed_headers, payload_hash). `query` is
    the already-canonical (sorted, encoded) query string. Pure — the test suite
    drives it with AWS's fixed example inputs."""
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f'host:{host}\nx-amz-date:{amzdate}\n'
    signed_headers = 'host;x-amz-date'
    canonical_request = '\n'.join([
        method, path, query, canonical_headers, signed_headers, payload_hash])
    scope = f'{datestamp}/{region}/{service}/aws4_request'
    string_to_sign = '\n'.join([
        'AWS4-HMAC-SHA256', amzdate, scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
    signature = hmac.new(_signing_key(secret_key, datestamp, region, service),
                         string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    auth = (f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}')
    return auth, signed_headers, payload_hash


def _now():
    # Real wall-clock; isolated here so tests can pass a fixed time to the signer.
    return datetime.datetime.now(datetime.timezone.utc)


# ── AWS EC2 ──────────────────────────────────────────────────────────────────
_EC2_API_VERSION = '2016-11-15'
_EC2_NS = '{http://ec2.amazonaws.com/doc/2016-11-15/}'


def ec2_request_headers(region, access_key, secret_key, query, now=None):
    """Build the signed headers for an EC2 GET (Query API) call."""
    now = now or _now()
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    host = f'ec2.{region}.amazonaws.com'
    auth, _sh, _ph = sigv4_authorization('GET', host, region, 'ec2', '/', query,
                                         b'', access_key, secret_key, amzdate, datestamp)
    return host, {'Host': host, 'X-Amz-Date': amzdate, 'Authorization': auth}


def _canonical_query(params):
    # AWS canonical query: sorted by key, RFC3986-encoded.
    return '&'.join(f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
                    for k, v in sorted(params.items()))


def parse_ec2_instances(xml_text):
    """Parse a DescribeInstances XML response into flat instance dicts. Tolerant
    of the namespace and of missing optional fields."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    def _f(el, tag):
        c = el.find(_EC2_NS + tag)
        return c.text if c is not None and c.text is not None else ''

    for res in root.iter(_EC2_NS + 'instancesSet'):
        for inst in res.findall(_EC2_NS + 'item'):
            iid = _f(inst, 'instanceId')
            if not iid:
                continue
            name = ''
            tagset = inst.find(_EC2_NS + 'tagSet')
            if tagset is not None:
                for t in tagset.findall(_EC2_NS + 'item'):
                    if _f(t, 'key') == 'Name':
                        name = _f(t, 'value')
            state_el = inst.find(_EC2_NS + 'instanceState')
            state = _f(state_el, 'name') if state_el is not None else ''
            out.append({
                'instance_id': iid,
                'name': name or iid,
                'state': state,
                'type': _f(inst, 'instanceType'),
                'private_ip': _f(inst, 'privateIpAddress'),
                'public_ip': _f(inst, 'ipAddress'),
                'az': (_f(inst.find(_EC2_NS + 'placement'), 'availabilityZone')
                       if inst.find(_EC2_NS + 'placement') is not None else ''),
            })
    return out


def import_aws(region, access_key, secret_key, timeout=15, _opener=None):
    """Fetch running/all EC2 instances for one region. Returns a list of flat
    instance dicts (see parse_ec2_instances). Raises RuntimeError on failure.
    `_opener` is injected by tests to avoid a real network call."""
    params = {'Action': 'DescribeInstances', 'Version': _EC2_API_VERSION}
    query = _canonical_query(params)
    host, headers = ec2_request_headers(region, access_key, secret_key, query)
    url = f'https://{host}/?{query}'
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        opener = _opener or urllib.request.urlopen
        with opener(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:300] if hasattr(e, 'read') else ''
        raise RuntimeError(f'AWS EC2 API error (HTTP {e.code}): {detail}') from None
    except Exception as e:
        raise RuntimeError(f'Could not reach AWS EC2: {e}') from None
    return parse_ec2_instances(body)


def instance_to_device(provider, region, inst):
    """Map one cloud instance to an agentless device record fragment. The server
    merges this into DEVICES_FILE (stable id, agentless flag, tags)."""
    dev_id = f'{provider}-{inst["instance_id"]}'
    ip = inst.get('private_ip') or inst.get('public_ip') or ''
    return dev_id, {
        'name': inst.get('name') or inst['instance_id'],
        'ip': ip,
        'agentless': True,
        'source': f'cloud:{provider}',
        'cloud': {'provider': provider, 'region': region,
                  'instance_id': inst['instance_id'], 'type': inst.get('type', ''),
                  'state': inst.get('state', ''), 'az': inst.get('az', '')},
        'tags': [t for t in ('cloud', provider, region) if t],
    }
