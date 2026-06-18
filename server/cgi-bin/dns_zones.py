"""RemotePower DNS zone management — read/write DNS records through provider APIs.

Sibling to ``integrations.py``: each provider is a small class that talks one
registrar/DNS-host REST API through an injected SSRF-safe HTTP client, so every
provider is unit-testable with a fake client (no network). ``api.py`` owns the
client, credential resolution (reused from the ACME DNS-01 credential store) and
the admin-gated, audit-logged HTTP handlers; this module is just the per-provider
API clients + record normalisation.

A normalised record is a dict::

    {'id': '<provider record id>',
     'type': 'A'|'AAAA'|'CNAME'|'TXT'|'MX'|'NS'|'SRV'|'CAA'|...,
     'name': '<fully-qualified name>',
     'content': '<value>',          # multi-value RRsets join with '\\n'
     'ttl': <int seconds, 0/1 = provider auto>,
     'priority': <int|None>,        # MX/SRV
     'proxied': <bool|None>}        # Cloudflare only

Credentials come straight from ``config['acme_dns_credentials'][<acme_provider>]``
(the same scoped API tokens acme.sh already uses), so there is no second secret
store: set a token once under ACME and it drives both cert issuance and this
dashboard.
"""

import json

# Record types we expose in the editor. Providers may accept more; these cover
# the common set and keep the UI's <select> sane.
RECORD_TYPES = ('A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA')


class DNSError(Exception):
    """Any failure reaching/parsing a provider API. Handlers map it to a 4xx/502."""


# ── small helpers ──────────────────────────────────────────────────────────────
def _subname(name, zone, apex='@'):
    """Provider-relative label for a name within a zone. Apex collapses to
    ``apex`` (which differs per provider: '@', or '' for deSEC/Porkbun)."""
    name = (name or '').strip().rstrip('.')
    z = (zone or '').strip().rstrip('.')
    if name in ('', '@') or name == z:
        return apex
    if z and name.endswith('.' + z):
        return name[:-(len(z) + 1)]
    return name


def _fqdn(sub, zone):
    """Inverse of _subname: a fully-qualified name from a provider label."""
    sub = (sub or '').strip().rstrip('.')
    z = (zone or '').strip().rstrip('.')
    if sub in ('', '@'):
        return z
    if z and (sub == z or sub.endswith('.' + z)):
        return sub
    return sub + '.' + z if z else sub


def _int(x, default=0):
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


# ── provider base ──────────────────────────────────────────────────────────────
class DNSProvider:
    """One DNS-host API. Subclasses implement the five CRUD methods using
    ``self.client`` (an SSRF-safe HTTPClient) and ``self.creds`` (the resolved
    acme credential dict)."""

    key = ''               # internal provider key, e.g. 'cloudflare'
    label = ''             # human label
    acme_provider = ''     # which ACME_DNS_CREDENTIAL_FIELDS key holds the token
    base_url = ''          # API base; api.py builds the client from this
    supports_proxied = False
    cred_hint = ''         # shown in the UI when no token is configured

    def __init__(self, client, creds):
        self.client = client
        self.creds = creds or {}

    # subclasses override _auth() to return per-request headers
    def _auth(self):
        return {}

    def _req(self, method, path, body=None):
        headers = dict(self._auth())
        data = None
        if body is not None:
            headers.setdefault('Content-Type', 'application/json')
            data = json.dumps(body).encode()
        try:
            r = self.client.request(method, path, headers=headers, body=data)
        except DNSError:
            raise
        except Exception as e:  # network / SSRF guard / timeout
            raise DNSError(f'{e.__class__.__name__}: {e}'[:200])
        return r

    def _json(self, r, ctx=''):
        try:
            return r.json()
        except Exception:
            raise DNSError(f'{self.label}: invalid JSON{(" from " + ctx) if ctx else ""} (HTTP {r.status})')

    # CRUD surface — subclasses implement
    def list_zones(self):
        raise NotImplementedError

    def list_records(self, zone_id, zone_name):
        raise NotImplementedError

    def create_record(self, zone_id, zone_name, rec):
        raise NotImplementedError

    def update_record(self, zone_id, zone_name, rec_id, rec):
        raise NotImplementedError

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        raise NotImplementedError


# ── Cloudflare ──────────────────────────────────────────────────────────────────
class Cloudflare(DNSProvider):
    key = 'cloudflare'
    label = 'Cloudflare'
    acme_provider = 'dns_cf'
    base_url = 'https://api.cloudflare.com/client/v4'
    supports_proxied = True
    cred_hint = 'Set a Cloudflare API Token (CF_Token) with Zone:Read + DNS:Edit under ACME → DNS credentials.'

    def _auth(self):
        tok = self.creds.get('CF_Token')
        if not tok:
            raise DNSError('Cloudflare needs an API Token (CF_Token). A legacy Global Key is not supported here.')
        return {'Authorization': 'Bearer ' + tok}

    def _ok(self, j, ctx):
        if not j.get('success'):
            errs = j.get('errors') or []
            msg = '; '.join(str(e.get('message', e)) for e in errs) if errs else 'request failed'
            raise DNSError(f'Cloudflare: {msg}'[:200])

    def list_zones(self):
        r = self._req('GET', '/zones?per_page=50&status=active')
        j = self._json(r, 'zones'); self._ok(j, 'zones')
        return [{'id': z['id'], 'name': z['name']} for z in (j.get('result') or [])]

    def list_records(self, zone_id, zone_name):
        r = self._req('GET', f'/zones/{zone_id}/dns_records?per_page=100')
        j = self._json(r, 'records'); self._ok(j, 'records')
        out = []
        for rr in (j.get('result') or []):
            out.append({
                'id': rr.get('id'), 'type': rr.get('type'), 'name': rr.get('name'),
                'content': rr.get('content', ''), 'ttl': _int(rr.get('ttl'), 1),
                'priority': rr.get('priority'), 'proxied': bool(rr.get('proxied')),
            })
        return out

    def _body(self, zone_name, rec):
        b = {'type': rec['type'], 'name': _fqdn(rec.get('name'), zone_name),
             'content': rec.get('content', ''), 'ttl': _int(rec.get('ttl'), 1) or 1}
        if rec.get('type') in ('MX', 'SRV') and rec.get('priority') is not None:
            b['priority'] = _int(rec.get('priority'))
        if rec.get('type') in ('A', 'AAAA', 'CNAME'):
            b['proxied'] = bool(rec.get('proxied'))
        return b

    def create_record(self, zone_id, zone_name, rec):
        r = self._req('POST', f'/zones/{zone_id}/dns_records', self._body(zone_name, rec))
        self._ok(self._json(r, 'create'), 'create')

    def update_record(self, zone_id, zone_name, rec_id, rec):
        r = self._req('PUT', f'/zones/{zone_id}/dns_records/{rec_id}', self._body(zone_name, rec))
        self._ok(self._json(r, 'update'), 'update')

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        r = self._req('DELETE', f'/zones/{zone_id}/dns_records/{rec_id}')
        self._ok(self._json(r, 'delete'), 'delete')


# ── DigitalOcean ────────────────────────────────────────────────────────────────
class DigitalOcean(DNSProvider):
    key = 'digitalocean'
    label = 'DigitalOcean'
    acme_provider = 'dns_dgon'
    base_url = 'https://api.digitalocean.com/v2'
    cred_hint = 'Set a DigitalOcean API token (DO_API_KEY) with write scope under ACME → DNS credentials.'

    def _auth(self):
        tok = self.creds.get('DO_API_KEY')
        if not tok:
            raise DNSError('DigitalOcean needs an API token (DO_API_KEY).')
        return {'Authorization': 'Bearer ' + tok}

    def _check(self, r, ctx):
        if not (200 <= r.status < 300):
            try:
                msg = self._json(r, ctx).get('message', '')
            except DNSError:
                msg = ''
            raise DNSError(f'DigitalOcean: HTTP {r.status} {msg}'[:200])

    def list_zones(self):
        r = self._req('GET', '/domains?per_page=200')
        self._check(r, 'zones')
        return [{'id': d['name'], 'name': d['name']} for d in (self._json(r, 'zones').get('domains') or [])]

    def list_records(self, zone_id, zone_name):
        r = self._req('GET', f'/domains/{zone_id}/records?per_page=200')
        self._check(r, 'records')
        out = []
        for rr in (self._json(r, 'records').get('domain_records') or []):
            out.append({
                'id': rr.get('id'), 'type': rr.get('type'),
                'name': _fqdn(rr.get('name'), zone_name), 'content': rr.get('data', ''),
                'ttl': _int(rr.get('ttl'), 1800), 'priority': rr.get('priority'), 'proxied': None,
            })
        return out

    def _body(self, zone_name, rec):
        b = {'type': rec['type'], 'name': _subname(rec.get('name'), zone_name, apex='@'),
             'data': rec.get('content', ''), 'ttl': _int(rec.get('ttl'), 1800) or 1800}
        if rec.get('type') in ('MX', 'SRV') and rec.get('priority') is not None:
            b['priority'] = _int(rec.get('priority'))
        return b

    def create_record(self, zone_id, zone_name, rec):
        r = self._req('POST', f'/domains/{zone_id}/records', self._body(zone_name, rec))
        self._check(r, 'create')

    def update_record(self, zone_id, zone_name, rec_id, rec):
        r = self._req('PUT', f'/domains/{zone_id}/records/{rec_id}', self._body(zone_name, rec))
        self._check(r, 'update')

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        r = self._req('DELETE', f'/domains/{zone_id}/records/{rec_id}')
        self._check(r, 'delete')


# ── Hetzner DNS ─────────────────────────────────────────────────────────────────
class Hetzner(DNSProvider):
    key = 'hetzner'
    label = 'Hetzner'
    acme_provider = 'dns_hetzner'
    base_url = 'https://dns.hetzner.com/api/v1'
    cred_hint = 'Set a Hetzner DNS API token (HETZNER_Token) under ACME → DNS credentials.'

    def _auth(self):
        tok = self.creds.get('HETZNER_Token')
        if not tok:
            raise DNSError('Hetzner needs an API token (HETZNER_Token).')
        return {'Auth-API-Token': tok}

    def _check(self, r, ctx):
        if not (200 <= r.status < 300):
            raise DNSError(f'Hetzner: HTTP {r.status} on {ctx}')

    def list_zones(self):
        r = self._req('GET', '/zones')
        self._check(r, 'zones')
        return [{'id': z['id'], 'name': z['name']} for z in (self._json(r, 'zones').get('zones') or [])]

    def list_records(self, zone_id, zone_name):
        r = self._req('GET', f'/records?zone_id={zone_id}')
        self._check(r, 'records')
        out = []
        for rr in (self._json(r, 'records').get('records') or []):
            out.append({
                'id': rr.get('id'), 'type': rr.get('type'),
                'name': _fqdn(rr.get('name'), zone_name), 'content': rr.get('value', ''),
                'ttl': _int(rr.get('ttl'), 0), 'priority': None, 'proxied': None,
            })
        return out

    def _body(self, zone_id, zone_name, rec):
        b = {'zone_id': zone_id, 'type': rec['type'],
             'name': _subname(rec.get('name'), zone_name, apex='@'), 'value': rec.get('content', '')}
        ttl = _int(rec.get('ttl'), 0)
        if ttl:
            b['ttl'] = ttl
        return b

    def create_record(self, zone_id, zone_name, rec):
        r = self._req('POST', '/records', self._body(zone_id, zone_name, rec))
        self._check(r, 'create')

    def update_record(self, zone_id, zone_name, rec_id, rec):
        r = self._req('PUT', f'/records/{rec_id}', self._body(zone_id, zone_name, rec))
        self._check(r, 'update')

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        r = self._req('DELETE', f'/records/{rec_id}')
        self._check(r, 'delete')


# ── deSEC ───────────────────────────────────────────────────────────────────────
class Desec(DNSProvider):
    """deSEC models DNS as RRsets (one row per subname+type, holding a list of
    values), not individual records. We surface one normalised row per RRset
    with ``content`` = newline-joined values, and ``id`` = '<subname>|<type>'.
    Writes go through the bulk PATCH on the rrsets collection so the apex case
    needs no awkward empty-path URL. deSEC enforces TTL >= 3600."""
    key = 'desec'
    label = 'deSEC'
    acme_provider = 'dns_desec'
    base_url = 'https://desec.io/api/v1'
    cred_hint = 'Set a deSEC API token (DEDYN_TOKEN) under ACME → DNS credentials.'
    MIN_TTL = 3600

    def _auth(self):
        tok = self.creds.get('DEDYN_TOKEN')
        if not tok:
            raise DNSError('deSEC needs an API token (DEDYN_TOKEN).')
        return {'Authorization': 'Token ' + tok}

    def _check(self, r, ctx):
        if not (200 <= r.status < 300):
            raise DNSError(f'deSEC: HTTP {r.status} on {ctx}')

    def list_zones(self):
        r = self._req('GET', '/domains/')
        self._check(r, 'zones')
        try:
            doms = r.json()
        except Exception:
            raise DNSError('deSEC: invalid JSON (zones)')
        return [{'id': d['name'], 'name': d['name']} for d in (doms or [])]

    def list_records(self, zone_id, zone_name):
        r = self._req('GET', f'/domains/{zone_id}/rrsets/')
        self._check(r, 'records')
        try:
            rrsets = r.json()
        except Exception:
            raise DNSError('deSEC: invalid JSON (records)')
        out = []
        for rs in (rrsets or []):
            sub = rs.get('subname', '')
            rtype = rs.get('type')
            out.append({
                'id': f'{sub}|{rtype}', 'type': rtype,
                'name': _fqdn(sub, zone_name),
                'content': '\n'.join(rs.get('records') or []),
                'ttl': _int(rs.get('ttl'), self.MIN_TTL), 'priority': None, 'proxied': None,
            })
        return out

    def _values(self, content):
        # one value per line (or comma) — deSEC takes a list per RRset
        parts = [p.strip() for chunk in (content or '').split('\n') for p in chunk.split(',')]
        return [p for p in parts if p]

    def _patch(self, zone_id, sub, rtype, records, ttl):
        body = [{'subname': sub, 'type': rtype, 'ttl': max(self.MIN_TTL, _int(ttl, self.MIN_TTL)),
                 'records': records}]
        r = self._req('PATCH', f'/domains/{zone_id}/rrsets/', body)
        self._check(r, 'write')

    def create_record(self, zone_id, zone_name, rec):
        sub = _subname(rec.get('name'), zone_name, apex='')
        self._patch(zone_id, sub, rec['type'], self._values(rec.get('content')), rec.get('ttl'))

    def update_record(self, zone_id, zone_name, rec_id, rec):
        # id carries the original subname|type; let the edited name win if changed
        sub = _subname(rec.get('name'), zone_name, apex='')
        self._patch(zone_id, sub, rec['type'], self._values(rec.get('content')), rec.get('ttl'))

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        sub, _, rid_type = str(rec_id or '').partition('|')
        rtype = rtype or rid_type
        if not rtype:
            raise DNSError('deSEC: delete needs the record type')
        # empty records list removes the RRset
        r = self._req('PATCH', f'/domains/{zone_id}/rrsets/',
                      [{'subname': sub, 'type': rtype, 'records': []}])
        self._check(r, 'delete')


# ── Porkbun ─────────────────────────────────────────────────────────────────────
class Porkbun(DNSProvider):
    """Porkbun's API is POST-only with both keys in every JSON body (no auth
    header), and addresses zones by domain name. Record ``name`` in writes is
    the subdomain label ('' for apex)."""
    key = 'porkbun'
    label = 'Porkbun'
    acme_provider = 'dns_porkbun'
    base_url = 'https://api.porkbun.com/api/json/v3'
    cred_hint = 'Set Porkbun API Key + Secret API Key (PORKBUN_API_KEY / PORKBUN_SECRET_API_KEY) under ACME → DNS credentials, and enable API access on the domain.'

    def _keys(self, extra=None):
        ak = self.creds.get('PORKBUN_API_KEY')
        sk = self.creds.get('PORKBUN_SECRET_API_KEY')
        if not ak or not sk:
            raise DNSError('Porkbun needs PORKBUN_API_KEY and PORKBUN_SECRET_API_KEY.')
        body = {'apikey': ak, 'secretapikey': sk}
        if extra:
            body.update(extra)
        return body

    def _post(self, path, extra=None, ctx=''):
        r = self._req('POST', path, self._keys(extra))
        j = self._json(r, ctx)
        if str(j.get('status')) != 'SUCCESS':
            raise DNSError(f'Porkbun: {j.get("message", "request failed")}'[:200])
        return j

    def list_zones(self):
        j = self._post('/domain/listAll', ctx='zones')
        return [{'id': d['domain'], 'name': d['domain']} for d in (j.get('domains') or [])]

    def list_records(self, zone_id, zone_name):
        j = self._post(f'/dns/retrieve/{zone_id}', ctx='records')
        out = []
        for rr in (j.get('records') or []):
            out.append({
                'id': rr.get('id'), 'type': rr.get('type'), 'name': rr.get('name', ''),
                'content': rr.get('content', ''), 'ttl': _int(rr.get('ttl'), 600),
                'priority': _int(rr.get('prio')) if rr.get('prio') not in (None, '') else None,
                'proxied': None,
            })
        return out

    def _fields(self, zone_name, rec):
        f = {'name': _subname(rec.get('name'), zone_name, apex=''), 'type': rec['type'],
             'content': rec.get('content', ''), 'ttl': str(_int(rec.get('ttl'), 600) or 600)}
        if rec.get('type') in ('MX', 'SRV') and rec.get('priority') is not None:
            f['prio'] = str(_int(rec.get('priority')))
        return f

    def create_record(self, zone_id, zone_name, rec):
        self._post(f'/dns/create/{zone_id}', self._fields(zone_name, rec), ctx='create')

    def update_record(self, zone_id, zone_name, rec_id, rec):
        self._post(f'/dns/edit/{zone_id}/{rec_id}', self._fields(zone_name, rec), ctx='update')

    def delete_record(self, zone_id, zone_name, rec_id, name='', rtype=''):
        self._post(f'/dns/delete/{zone_id}/{rec_id}', ctx='delete')


# ── registry ────────────────────────────────────────────────────────────────────
PROVIDERS = {p.key: p for p in (Cloudflare, DigitalOcean, Hetzner, Desec, Porkbun)}


def list_providers():
    """UI catalog (no client). Each entry: key, label, acme_provider,
    supports_proxied, record_types, cred_hint."""
    out = []
    for p in PROVIDERS.values():
        out.append({
            'key': p.key, 'label': p.label, 'acme_provider': p.acme_provider,
            'supports_proxied': p.supports_proxied, 'record_types': list(RECORD_TYPES),
            'cred_hint': p.cred_hint,
        })
    out.sort(key=lambda c: c['label'].lower())
    return out
