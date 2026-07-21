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


# ── v6.3.1: flow-derived service-dependency verification ─────────────────────
# The discovery half (suggest depends_on edges from observed traffic) already
# lives in api._dependency_suggestions (agent peer-conns, W3-8). This adds the
# VERIFICATION half — the differentiated "missing edge" signal: a DECLARED
# depends_on edge that was carrying observed traffic and then went silent while
# BOTH endpoints are still online — a firewall/route/service break the
# device_offline signal never catches. Evidence comes from BOTH the agent
# peer-conns store AND the agentless flow receiver, so an edge visible only to a
# router's NetFlow export (neither host runs an agent) is still verified.

_DEP_EVIDENCE_TTL = 15 * 60      # peer-conn / flow snapshot older than this = no evidence
_DEP_DEFAULT_SILENCE_MIN = 30    # default minutes silent before dependency_missing fires


def _dep_ip_index(devices):
    """ip / hostname / interface-ip → device id (same index _dependency_suggestions
    builds; first writer wins so a primary ip isn't shadowed by an interface)."""
    idx = {}
    for did, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        for f in ('ip', 'hostname'):
            v = str(dev.get(f) or '').strip()
            if v:
                idx.setdefault(v, did)
        for nic in (dev.get('interfaces') or []):
            if isinstance(nic, dict) and nic.get('ip'):
                idx.setdefault(str(nic['ip']), did)
    return idx


def _dep_observed_edges(devices, now):
    """Set of unordered frozenset({did, up}) device pairs currently exchanging
    traffic, from FRESH agent peer-conns AND fresh flow-receiver conversations.
    Bidirectional: traffic in either direction confirms the (did depends on up)
    link is alive."""
    idx = _dep_ip_index(devices)
    edges = set()
    # (a) agent-observed outbound peers (directional did → peer-ip)
    peers = A.load(A.PEER_CONNS_FILE) or {}
    for did, rec in peers.items():
        if did not in devices or not isinstance(rec, dict):
            continue
        if (now - int(rec.get('ts') or 0)) > _DEP_EVIDENCE_TTL:
            continue
        for p in (rec.get('peers') or []):
            up = idx.get(str(p.get('ip') or ''))
            if up and up != did:
                edges.add(frozenset((did, up)))
    # (b) flow-receiver conversations (any exporter that saw both endpoints)
    flow = A.load(A.FLOW_FILE) or {}
    for rec in flow.values():
        latest = rec.get('latest') if isinstance(rec, dict) else None
        if not isinstance(latest, dict):
            continue
        if (now - int(latest.get('ts') or 0)) > _DEP_EVIDENCE_TTL:
            continue
        for c in (latest.get('conversations') or []):
            a = idx.get(str(c.get('src') or ''))
            b = idx.get(str(c.get('dst') or ''))
            if a and b and a != b:
                edges.add(frozenset((a, b)))
    return edges


def _dep_online(dev, now):
    if bool(dev.get('agentless', False)):
        return bool(A._agentless_online(dev))
    return (now - int(dev.get('last_seen', 0) or 0)) < A.get_online_ttl()


def _dependency_health(devices=None, state=None, now=None):
    """Classify every DECLARED depends_on edge (did → up) against observed
    traffic. Returns a list of edge rows for the UI + the sweep. Status:

      ok            — traffic observed within the evidence TTL.
      missing       — was observed before, now silent, BOTH endpoints online
                      (the fire-worthy signal).
      silent        — silent + was observed, but an endpoint is offline
                      (collateral of device_offline; not fired).
      unverifiable  — never observed (no flow/peer coverage of this edge).
    """
    if now is None:
        now = int(time.time())
    if devices is None:
        devices = A.load(A.DEVICES_FILE) or {}
    if state is None:
        state = A.load(A.FLOW_DEPS_FILE) or {}
    edges_state = state.get('edges') if isinstance(state.get('edges'), dict) else {}
    observed = _dep_observed_edges(devices, now)
    rows = []
    for did, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        down_online = _dep_online(dev, now)
        for up in (dev.get('depends_on') or []):
            if up not in devices:
                continue
            key = f'{did}:{up}'
            is_obs = frozenset((did, up)) in observed
            est = edges_state.get(key) if isinstance(edges_state.get(key), dict) else {}
            last_obs = int(est.get('last_observed') or 0)
            ever = bool(est.get('ever_observed'))
            up_online = _dep_online(devices[up], now)
            if is_obs:
                status = 'ok'
            elif not ever:
                status = 'unverifiable'
            elif down_online and up_online:
                status = 'missing'
            else:
                status = 'silent'
            rows.append({
                'device_id': did, 'device_name': dev.get('name', did),
                'upstream_id': up, 'upstream_name': devices[up].get('name', up),
                'dep_edge': key, 'status': status,
                'last_observed': last_obs, 'ever_observed': ever,
                'both_online': bool(down_online and up_online),
            })
    return rows


def handle_dependency_health():
    """GET /api/dependency-health — declared-dependency edges + observed-traffic
    status, scope/tenant-filtered. Read-only; available regardless of whether
    dependency alerting is enabled, so operators always see link health."""
    A.require_auth()
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    rows = _dependency_health(devices=devices)
    summary = {'ok': 0, 'missing': 0, 'silent': 0, 'unverifiable': 0}
    for r in rows:
        summary[r['status']] = summary.get(r['status'], 0) + 1
    A.respond(200, {'edges': rows, 'summary': summary,
                    'alerts_enabled': bool(A._config_ro().get('dependency_link_alerts', False))})


def run_flow_dep_check_if_due():
    """Cadence: refresh per-edge observed state and fire dependency_missing /
    dependency_restored for DECLARED depends_on edges. Opt-in via
    `dependency_link_alerts` (default off) — but the observed-state timestamps
    are ALWAYS maintained so the health view + a later opt-in have history.

    Edge-triggered on the observed→silent transition, both-online guarded, so it
    catches the silent break device_offline can't and never double-alerts a host
    that is simply down. fire_webhook is collected then called after the lock."""
    now = int(time.time())
    # cheap cadence gate on a read-only copy (like the other run_*_if_due sweeps)
    try:
        interval = int(A._config_ro().get('dependency_check_interval_s', 120))
    except (TypeError, ValueError):
        interval = 120
    interval = max(30, min(3600, interval))
    st = A.load(A.FLOW_DEPS_FILE) or {}
    if (now - int(st.get('last_run') or 0)) < interval:
        return
    devices = A.load(A.DEVICES_FILE) or {}
    observed = _dep_observed_edges(devices, now)
    alerts_on = bool(A._config_ro().get('dependency_link_alerts', False))
    try:
        silence_s = int(A._config_ro().get('dependency_silence_min',
                                           _DEP_DEFAULT_SILENCE_MIN)) * 60
    except (TypeError, ValueError):
        silence_s = _DEP_DEFAULT_SILENCE_MIN * 60
    silence_s = max(60, silence_s)
    pending = []          # (event, payload) fired AFTER the lock
    with A._LockedUpdate(A.FLOW_DEPS_FILE) as store:
        edges_state = store.get('edges') if isinstance(store.get('edges'), dict) else {}
        # declared edge set this tick (drop state for edges no longer declared)
        declared = set()
        for did, dev in devices.items():
            if not isinstance(dev, dict):
                continue
            for up in (dev.get('depends_on') or []):
                if up in devices:
                    declared.add(f'{did}:{up}')
        for key in list(edges_state):
            if key not in declared:
                edges_state.pop(key, None)
        for key in declared:
            did, up = key.split(':', 1)
            dev, updev = devices.get(did) or {}, devices.get(up) or {}
            est = edges_state.get(key) if isinstance(edges_state.get(key), dict) else {}
            is_obs = frozenset((did, up)) in observed
            if is_obs:
                was_alerted = bool(est.get('alerted'))
                est['last_observed'] = now
                est['ever_observed'] = True
                if was_alerted:
                    est['alerted'] = False
                    if alerts_on:
                        pending.append(('dependency_restored', {
                            'device_id': did, 'name': dev.get('name', did),
                            'dep_edge': key, 'upstream_id': up,
                            'upstream_name': updev.get('name', up)}))
            else:
                ever = bool(est.get('ever_observed'))
                last = int(est.get('last_observed') or 0)
                both_online = _dep_online(dev, now) and _dep_online(updev, now)
                if (alerts_on and ever and not est.get('alerted')
                        and both_online and (now - last) >= silence_s):
                    est['alerted'] = True
                    pending.append(('dependency_missing', {
                        'device_id': did, 'name': dev.get('name', did),
                        'dep_edge': key, 'upstream_id': up,
                        'upstream_name': updev.get('name', up),
                        'detail': f'no observed traffic for '
                                  f'{(now - last) // 60}m (both hosts online)'}))
            edges_state[key] = est
        store['edges'] = edges_state
        store['last_run'] = now
    for event, payload in pending:
        try:
            A.fire_webhook(event, payload)
        except Exception:
            pass
