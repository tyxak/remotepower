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
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import safe_xml


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
    # Defense-in-depth: a DescribeInstances response never carries a DTD or
    # entity declarations. Refuse any that do before parsing, so a tampered or
    # MITM'd response can't drive entity expansion (XXE / billion-laughs) through
    # xml.etree. (ET doesn't fetch external entities, but this also caps the DoS.)
    # safe_xml scans the WHOLE buffer for a DTD/entity (billion-laughs guard). The
    # previous inline check only looked at the first 4 KB — a DOCTYPE hidden behind
    # a larger leading comment slipped it (the exact bypass dmarc_monitor's M1 note
    # warns about). Centralised so the three XML call sites can't drift again.
    try:
        root = safe_xml.fromstring(xml_text)
    except (ET.ParseError, ValueError):
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


# AWS region shape — e.g. eu-west-1, us-east-2, us-gov-east-1 (≥1 middle word).
_REGION_RE = re.compile(r'^[a-z]{2}(-[a-z]+)+-\d$')


def import_aws(region, access_key, secret_key, timeout=15, _opener=None):
    """Fetch running/all EC2 instances for one region. Returns a list of flat
    instance dicts (see parse_ec2_instances). Raises RuntimeError on failure.
    `_opener` is injected by tests to avoid a real network call (and by the
    server with an SSRF-safe opener)."""
    # Region is operator-supplied; it's interpolated into the request host
    # (`ec2.<region>.amazonaws.com`), so pin it to the AWS region shape before
    # use — a value with /@#: could otherwise reshape the target host.
    if not isinstance(region, str) or not _REGION_RE.match(region):
        raise RuntimeError(f'Invalid AWS region: {region!r}')
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


def _bearer_get_json(url, token, timeout, _opener):
    """GET a JSON API with a bearer token. Returns the parsed object; raises
    RuntimeError on failure. Host is FIXED by the caller (no SSRF from input)."""
    import json as _json
    req = urllib.request.Request(url, headers={
        'Authorization': f'Bearer {token}', 'Accept': 'application/json',
        'User-Agent': 'RemotePower'}, method='GET')
    try:
        opener = _opener or urllib.request.urlopen
        with opener(req, timeout=timeout) as resp:
            return _json.loads(resp.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:300] if hasattr(e, 'read') else ''
        raise RuntimeError(f'API error (HTTP {e.code}): {detail}') from None
    except Exception as e:
        raise RuntimeError(f'Could not reach API: {e}') from None


def import_hetzner(token, timeout=15, _opener=None):
    """W6-44: Hetzner Cloud servers → flat instance dicts (same shape as EC2)."""
    data = _bearer_get_json('https://api.hetzner.cloud/v1/servers', token, timeout, _opener)
    out = []
    for s in (data.get('servers') or []):
        pub = (((s.get('public_net') or {}).get('ipv4') or {}).get('ip')) or ''
        priv = ''
        for pn in (s.get('private_net') or []):
            if pn.get('ip'):
                priv = pn['ip']
                break
        out.append({
            'instance_id': str(s.get('id', '')),
            'name': s.get('name', ''),
            'state': s.get('status', ''),
            'type': ((s.get('server_type') or {}).get('name')) or '',
            'public_ip': pub, 'private_ip': priv,
            'az': (((s.get('datacenter') or {}).get('location') or {}).get('name')) or '',
        })
    return out


def import_digitalocean(token, timeout=15, _opener=None):
    """W6-44: DigitalOcean droplets → flat instance dicts (same shape as EC2)."""
    data = _bearer_get_json('https://api.digitalocean.com/v2/droplets?per_page=200',
                            token, timeout, _opener)
    out = []
    for d in (data.get('droplets') or []):
        v4 = ((d.get('networks') or {}).get('v4')) or []
        pub = next((n.get('ip_address') for n in v4 if n.get('type') == 'public'), '')
        priv = next((n.get('ip_address') for n in v4 if n.get('type') == 'private'), '')
        out.append({
            'instance_id': str(d.get('id', '')),
            'name': d.get('name', ''),
            'state': d.get('status', ''),
            'type': d.get('size_slug', ''),
            'public_ip': pub or '', 'private_ip': priv or '',
            'az': ((d.get('region') or {}).get('slug')) or '',
        })
    return out


# ── v6.4.2: Azure + GCP ─────────────────────────────────────────────────────
# The module docstring said it was "structured so Azure/GCP (OAuth2 bearer
# flows) can slot in later". Later is now. Both need a client-credentials token
# exchange before the list call — which is the only thing that made them
# different from Hetzner/DigitalOcean, since `_bearer_get_json` already handles
# the half that follows.
#
# An operator on those clouds had NO bulk-inventory path: every VM added by
# hand as an agentless device, or enrolled one at a time. A shop with 60 Azure
# VMs across three subscriptions either kept a spreadsheet or wrote their own
# script against POST /api/devices and re-ran it on cron — re-implementing the
# decommission-not-delete logic the scheduled re-sync already has.


def _oauth2_token(url, form, timeout, _opener):
    """Client-credentials token exchange. Returns the access token.

    The token URL is built by the caller from a FIXED host plus an
    operator-supplied tenant/id, never from a free-form URL — the same posture
    as `_bearer_get_json`'s fixed hosts.
    """
    import json as _json
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json', 'User-Agent': 'RemotePower'}, method='POST')
    try:
        opener = _opener or urllib.request.urlopen
        with opener(req, timeout=timeout) as resp:
            tok = _json.loads(resp.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:300] if hasattr(e, 'read') else ''
        # The detail is the provider's own error body — "AADSTS7000215: Invalid
        # client secret" is the whole diagnosis, and swallowing it would leave
        # the operator guessing between a wrong secret, a wrong tenant and a
        # missing role assignment.
        raise RuntimeError(f'Token request failed (HTTP {e.code}): {detail}') from None
    except Exception as e:
        raise RuntimeError(f'Could not reach the token endpoint: {e}') from None
    access = (tok or {}).get('access_token')
    if not access:
        raise RuntimeError('Token endpoint returned no access_token')
    return access


_AZURE_API = '2023-07-01'


def import_azure(tenant_id, client_id, client_secret, subscription_id,
                 timeout=15, _opener=None):
    """Azure VMs → flat instance dicts (same shape as EC2).

    Uses the ARM list-all endpoint, so ONE call covers every resource group in
    the subscription — an operator with VMs spread across a dozen groups should
    not have to enumerate them.
    """
    tenant = urllib.parse.quote(str(tenant_id or '').strip(), safe='')
    sub = urllib.parse.quote(str(subscription_id or '').strip(), safe='')
    if not (tenant and sub and client_id and client_secret):
        raise RuntimeError('Azure needs tenant_id, client_id, client_secret and '
                           'subscription_id')
    token = _oauth2_token(
        f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
        {'grant_type': 'client_credentials', 'client_id': client_id,
         'client_secret': client_secret,
         'scope': 'https://management.azure.com/.default'},
        timeout, _opener)
    out = []
    url = (f'https://management.azure.com/subscriptions/{sub}'
           f'/providers/Microsoft.Compute/virtualMachines?api-version={_AZURE_API}')
    seen_pages = 0
    while url and seen_pages < 20:      # bounded: a paging loop must terminate
        data = _bearer_get_json(url, token, timeout, _opener)
        for vm in (data.get('value') or []):
            props = vm.get('properties') or {}
            hw = props.get('hardwareProfile') or {}
            # ARM's VM list does not carry NICs' addresses; the ipConfiguration
            # lives on a separate resource. Rather than fan out one call per VM
            # (60 VMs = 60 extra round trips), leave the IP blank — the device
            # is still created, and an operator can fill it in or let the agent
            # enrol. Claiming an IP we did not fetch would be worse.
            out.append({
                'instance_id': str(vm.get('name') or vm.get('id') or ''),
                'name': vm.get('name', ''),
                'state': str(props.get('provisioningState') or ''),
                'type': str(hw.get('vmSize') or ''),
                'public_ip': '', 'private_ip': '',
                'az': str(vm.get('location') or ''),
            })
        url = data.get('nextLink') or ''
        seen_pages += 1
    return out


def import_gcp(client_email, private_key, project_id, timeout=15, _opener=None):
    """GCP Compute instances → flat instance dicts (same shape as EC2).

    Service-account JWT bearer flow (RFC 7523): sign a short-lived assertion
    with the key from the downloaded service-account JSON and exchange it for
    an access token. `aggregatedList` returns every zone in one call.
    """
    project = urllib.parse.quote(str(project_id or '').strip(), safe='')
    if not (client_email and private_key and project):
        raise RuntimeError('GCP needs client_email, private_key and project_id')
    token = _oauth2_token(
        'https://oauth2.googleapis.com/token',
        {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
         'assertion': _gcp_assertion(client_email, private_key)},
        timeout, _opener)
    out = []
    url = (f'https://compute.googleapis.com/compute/v1/projects/{project}'
           f'/aggregatedList/instances?maxResults=500')
    pages = 0
    while url and pages < 20:
        data = _bearer_get_json(url, token, timeout, _opener)
        for zone_key, block in (data.get('items') or {}).items():
            for vm in ((block or {}).get('instances') or []):
                nic = ((vm.get('networkInterfaces') or [{}])[0]) or {}
                pub = ''
                for ac in (nic.get('accessConfigs') or []):
                    if ac.get('natIP'):
                        pub = ac['natIP']
                        break
                out.append({
                    'instance_id': str(vm.get('id') or vm.get('name') or ''),
                    'name': vm.get('name', ''),
                    'state': str(vm.get('status') or ''),
                    # machineType is a full resource URL; the operator wants
                    # "e2-medium", not the path it lives at.
                    'type': str(vm.get('machineType') or '').rsplit('/', 1)[-1],
                    'public_ip': pub,
                    'private_ip': str(nic.get('networkIP') or ''),
                    'az': str(zone_key).rsplit('/', 1)[-1],
                })
        tok = data.get('nextPageToken')
        url = (f'https://compute.googleapis.com/compute/v1/projects/{project}'
               f'/aggregatedList/instances?maxResults=500'
               f'&pageToken={urllib.parse.quote(str(tok), safe="")}') if tok else ''
        pages += 1
    return out


def _gcp_assertion(client_email, private_key):
    """A signed JWT asserting the service account, per RFC 7523."""
    import base64
    import json as _json
    import time as _time
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise RuntimeError('GCP import needs the `cryptography` package '
                           '(already a RemotePower dependency)') from None

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b'=')

    now = int(_time.time())
    header = b64(_json.dumps({'alg': 'RS256', 'typ': 'JWT'},
                             separators=(',', ':')).encode())
    claim = b64(_json.dumps({
        'iss': client_email,
        'scope': 'https://www.googleapis.com/auth/compute.readonly',
        'aud': 'https://oauth2.googleapis.com/token',
        'iat': now, 'exp': now + 3600,
    }, separators=(',', ':')).encode())
    signing_input = header + b'.' + claim
    try:
        key = serialization.load_pem_private_key(
            str(private_key).replace('\\n', '\n').encode(), password=None)
    except Exception as e:
        raise RuntimeError(f'Could not read the GCP private key: {e}') from None
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b'.' + b64(sig)).decode()


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
