"""RemotePower — agentless NetFlow/IPFIX flow ingest + read (v6.3.1)

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


import hmac
import time

# The flowd sidecar already caps its rollup; the server re-caps (never trust the
# sender) and keeps a small rolling history so the UI can show a short trend.
_FLOW_MAX_TALKERS = 30
_FLOW_MAX_CONVS = 30
_FLOW_HISTORY = 24          # rollup snapshots kept per device (~4h at 10s flush)
_FLOW_TTL_S = 6 * 3600      # drop snapshots older than this


def _flow_num(v, cap=None):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    if n < 0:
        return 0
    return min(n, cap) if cap is not None else n


def _ingest_flow(dev_id, agg):
    """Validate/cap one flowd rollup and store it as the device's latest flow
    snapshot (+ a short rolling history). Structure mirrors the sidecar's
    _aggregate output; every size is re-clamped here."""
    if not isinstance(agg, dict):
        return
    talkers = []
    for t in (agg.get('talkers') or [])[:_FLOW_MAX_TALKERS]:
        if isinstance(t, dict) and t.get('ip'):
            talkers.append({'ip': str(t['ip'])[:64],
                            'bytes': _flow_num(t.get('bytes')),
                            'pkts': _flow_num(t.get('pkts'))})
    convs = []
    for c in (agg.get('conversations') or [])[:_FLOW_MAX_CONVS]:
        if isinstance(c, dict) and c.get('src') and c.get('dst'):
            convs.append({'src': str(c['src'])[:64], 'dst': str(c['dst'])[:64],
                          'dport': _flow_num(c.get('dport'), 65535),
                          'proto': _flow_num(c.get('proto'), 255),
                          'bytes': _flow_num(c.get('bytes')),
                          'pkts': _flow_num(c.get('pkts'))})
    protos = {}
    if isinstance(agg.get('protos'), dict):
        for k, v in list(agg['protos'].items())[:16]:
            protos[str(k)[:12]] = _flow_num(v)
    now = int(time.time())
    snap = {
        'ts': now,
        'total_bytes': _flow_num(agg.get('total_bytes')),
        'total_packets': _flow_num(agg.get('total_packets')),
        'flows': _flow_num(agg.get('flows')),
        'talkers': talkers, 'conversations': convs, 'protos': protos,
    }
    with A._LockedUpdate(A.FLOW_FILE) as store:
        rec = store.get(dev_id) if isinstance(store.get(dev_id), dict) else {}
        rec['latest'] = snap
        hist = rec.get('history') if isinstance(rec.get('history'), list) else []
        hist.append({'ts': now, 'total_bytes': snap['total_bytes'],
                     'flows': snap['flows']})
        cutoff = now - _FLOW_TTL_S
        hist = [h for h in hist if int(h.get('ts') or 0) >= cutoff][-_FLOW_HISTORY:]
        rec['history'] = hist
        store[dev_id] = rec


def handle_flow_in(token_str):
    """POST /api/flow/in/<token> — the remotepower-flowd sidecar posts a
    per-device NetFlow/IPFIX rollup here (JSON body). Capability-token auth
    (kind='flow'), exactly like the syslog receiver; the daemon runs on
    loopback. No RBAC — the token IS the device scope."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
        return
    token_str = (token_str or '').strip()
    if not token_str or not token_str.startswith('rpwi_'):
        A._log_inbound('flow', '', '', '401', 'invalid token format')
        A.respond(401, {'error': 'invalid token'})
        return
    tokens = (A.load(A.INBOUND_WEBHOOKS_FILE) or {}).get('tokens', [])
    match = None
    for t in tokens:
        if hmac.compare_digest(t.get('token', ''), token_str) and t.get('enabled', True):
            match = t
            break
    if not match:
        A._log_inbound('flow', '', '', '401', 'invalid or disabled token')
        A.respond(401, {'error': 'invalid token'})
        return
    if (match.get('kind') or 'alert') != 'flow':
        A._log_inbound('flow', match.get('id'), match.get('label'), '400',
                       f'wrong url for {match.get("kind", "alert")} token')
        A.respond(400, {'error': 'this token is not a flow token — use its own URL'})
        return
    dev_id = match.get('scope_device_id')
    devs = A.load(A.DEVICES_FILE) or {}
    if not dev_id or dev_id not in devs:
        A._log_inbound('flow', match.get('id'), match.get('label'), '404',
                       'token target device no longer exists')
        A.respond(404, {'error': 'token target device no longer exists'})
        return
    body = A.get_json_obj()
    try:
        _ingest_flow(dev_id, body)
    except Exception as e:
        A.respond(500, {'error': f'flow ingest failed: {e}'})
        return
    now = int(time.time())
    try:
        with A._LockedUpdate(A.INBOUND_WEBHOOKS_FILE) as store:
            for t in store.get('tokens', []):
                if t.get('token') == token_str:
                    t['last_seen'] = now
                    t['hit_count'] = int(t.get('hit_count', 0)) + 1
                    break
    except Exception:
        pass
    A._log_inbound('flow', match.get('id'), match.get('label'), '200',
                   f'flows={A._flow_num(body.get("flows")) if isinstance(body, dict) else 0} '
                   f'dev={devs.get(dev_id, {}).get("name", dev_id)}')
    A.respond(200, {'ok': True})


def handle_device_flows(dev_id):
    """GET /api/devices/<id>/flows — the device's latest flow rollup + short
    history. Scoped like the other device sub-resources (this route is under
    /api/devices/<id>/, covered by _enforce_device_scope pre-dispatch)."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'invalid device id'})
        return
    devs = A._load_ro(A.DEVICES_FILE) or {}
    if dev_id not in devs:
        A.respond(404, {'error': 'device not found'})
        return
    rec = (A.load(A.FLOW_FILE) or {}).get(dev_id) or {}
    A.respond(200, {'latest': rec.get('latest') or {},
                    'history': rec.get('history') or []})
