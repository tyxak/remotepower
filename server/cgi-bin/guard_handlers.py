"""RemotePower — Integrity Guard — quarantine vault (list + restore/delete directives)

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


import time


# ── safety rails ─────────────────────────────────────────────────────────────
def _guard_maintenance_active(dev_id, dev):
    """True if this device is inside an active maintenance window right now.

    Integrity Guard degrades to REPORT-ONLY during declared change: a deploy is
    not an intrusion, and auto-quarantining a legitimate rollout would be the
    worst possible failure mode. Callers only consult this when a pushed check
    actually carries `protect`, so it stays off the heartbeat hot path for the
    (vast majority of) fleets with no quarantine configured.
    """
    windows = (A._load_ro(A.MAINT_FILE) or {}).get('windows') or []
    if not windows:
        return False
    now = int(time.time())
    grp = (dev or {}).get('group') or ''
    for w in windows:
        if not isinstance(w, dict):
            continue
        scope = (w.get('scope') or 'device').lower()
        applies = (scope == 'global'
                   or (scope == 'group' and grp and w.get('target') == grp)
                   or (scope == 'device' and dev_id and w.get('target') == dev_id))
        if applies and A._window_active(w, now):
            return True
    return False


# ── handlers ─────────────────────────────────────────────────────────────────
def handle_guard_quarantine_list():
    """GET /api/guard/quarantine — the Integrity Guard vault across the fleet:
    every quarantined file the agents reported, scoped to what the caller can see
    (role scope + tenant, via _scope_filter_devices). Read-only; no secrets."""
    A.require_auth()
    devs = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    out = []
    for did, dev in devs.items():
        if not isinstance(dev, dict):
            continue
        gq = (dev.get('sysinfo') or {}).get('guard_quarantine')
        if not isinstance(gq, list):
            continue
        name = dev.get('name') or did
        for e in gq[:50]:
            if isinstance(e, dict) and e.get('id'):
                out.append({'device_id': did, 'device': name,
                            'id': str(e.get('id'))[:64], 'orig': str(e.get('orig', ''))[:512],
                            'check': str(e.get('check', ''))[:64], 'ts': int(e.get('ts', 0) or 0)})
    out.sort(key=lambda x: x['ts'], reverse=True)
    A.respond(200, {'items': out})


def handle_guard_action():
    """POST /api/guard/action {device_id, id, op:'restore'|'delete'|'rebaseline'} — queue a
    one-shot directive: the agent restores the quarantined file to its origin (if
    that path is free) or deletes it from the vault. Operator/admin; tenant+scope
    enforced (a cross-tenant device id 403s)."""
    actor = A.require_write_role('manage checks')
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    did = A._sanitize_str(str(body.get('device_id', '')), 64).strip()
    qid = A._sanitize_str(str(body.get('id', '')), 64).strip()
    op = str(body.get('op', '')).strip()
    if op not in ('restore', 'delete', 'rebaseline'):
        A.respond(400, {'error': "op must be 'restore', 'delete' or 'rebaseline'"})
    if not qid:
        A.respond(400, {'error': 'id is required'})
    if not did:
        # Fleet/tag/group-scoped re-baseline: `qid` is a CHECK id, so fan the
        # directive out to every device that check actually applies to (and that
        # the caller can see). restore/delete address ONE vault entry on ONE
        # host and stay device-scoped.
        if op != 'rebaseline':
            A.respond(400, {'error': 'device_id is required'})
        defs = (A._load_ro(A.CONFIG_FILE) or {}).get('custom_checks') or []
        cdef = next((c for c in defs
                     if isinstance(c, dict) and str(c.get('id')) == qid), None)
        if not cdef:
            A.respond(404, {'error': 'check not found'})
        devs = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
        targets = [d for d, dev in devs.items()
                   if isinstance(dev, dict) and A._custom_check_applies(cdef, d, dev)]
        if not targets:
            A.respond(404, {'error': 'no devices in scope for this check'})
        for d in targets:
            _queue_guard_action(d, qid, op)
        A.audit_log(actor, 'guard_action', f'devices={len(targets)} id={qid} op={op}')
        A.respond(200, {'ok': True, 'devices': len(targets)})
    A._scope_block_device(did)     # 403s a device the caller can't see
    if not _queue_guard_action(did, qid, op):
        A.respond(404, {'error': 'device not found'})
    A.audit_log(actor, 'guard_action', f'device={did} id={qid} op={op}')
    A.respond(200, {'ok': True, 'devices': 1})


def _queue_guard_action(did, qid, op):
    """Queue one one-shot directive on a device. Idempotent per (id, op) so a
    double-click can't stack duplicates. False if the device is gone.

    v6.4.0 CRITICAL FIX: `_DeviceUpdate` yields the whole devices collection
    ({dev_id: dev}) — you MUST `.get(dev_id)` to reach the device. The old code
    treated the yielded value AS the device, so `guard_actions` was written to
    the collection's top level (next to the device ids), never onto the device
    — the heartbeat's `dev.get('guard_actions')` therefore never saw it and
    NO guard action (rebaseline / restore / delete) EVER reached the agent.
    This is why "Reset baseline did nothing." Now it targets the device row.

    For a rebaseline it also records the exact failing output the operator
    accepted, so the server suppresses the check authoritatively (see
    checks._eval_custom_check) — instant, surviving refresh/cache, not
    dependent on the agent round-trip; the agent still re-baselines on-host."""
    _resolve_recover = False   # fire custom_check_recovered after the lock
    _dev_name = did
    with A._DeviceUpdate(did) as devices:
        dev = devices.get(did) if isinstance(devices, dict) else None
        if not isinstance(dev, dict):
            return False
        _dev_name = dev.get('name', did)
        acts = dev.setdefault('guard_actions', [])
        if not any(isinstance(a, dict) and a.get('id') == qid and a.get('op') == op
                   for a in acts):
            acts.append({'id': qid, 'op': op})
        if op == 'rebaseline' and qid:
            # v6.4.0: record the EXACT failing output the operator is accepting,
            # so the server suppresses this check (server-authoritatively) until
            # the reported value changes AGAIN — instant, survives refresh/cache,
            # and doesn't depend on the agent round-trip. (The earlier approach
            # overwrote sysinfo, which the next heartbeat clobbered → "it comes
            # back on refresh".) The agent still re-baselines via the queued
            # guard action so its own on-host baseline agrees.
            si = dev.get('sysinfo')
            cur = (si.get('custom_check_results') or {}).get(qid) if isinstance(si, dict) else None
            cur_out = cur.get('output') if isinstance(cur, dict) else None
            if cur_out:
                dev.setdefault('custom_check_accepted', {})[qid] = str(cur_out)[:200]
            # Mark the edge-state recovered so the ingest sweep doesn't re-fire.
            st = dev.get('custom_check_state')
            _was_alerted = bool(st.get(qid, {}).get('alerted')) if isinstance(st, dict) else False
            if isinstance(st, dict) and qid in st:
                st[qid] = {'status': 'ok', 'output': 'change accepted as the new baseline',
                           'changed_at': int(A.time.time()), 'alerted': False}
            # The open custom_check_failed alert must actually RESOLVE — firing
            # custom_check_recovered (device_id + check_id sub_match) closes it
            # via _auto_resolve_alerts. Fire AFTER the lock (fire_webhook takes
            # its own alert/event locks). Fire regardless of _was_alerted: it's
            # a no-op if there is no matching open alert, and covers the case
            # where the alert exists but the edge-state was lost.
            _resolve_recover = True
        devices[did] = dev   # write the mutated device row back
    if op == 'rebaseline':
        if _resolve_recover:
            try:
                A.fire_webhook('custom_check_recovered', {
                    'device_id': did, 'name': _dev_name, 'check_id': qid})
            except Exception:
                pass
        # Bust the fleet-checks cache so the Checks page reflects the acceptance
        # on the very next load instead of up to its 15s TTL later.
        try:
            A._invalidate_load_cache(A._fleet_checks_cache_file())
            fc = A._fleet_checks_cache_file()
            if A.backend_exists(fc):
                A.save(fc, {})
        except Exception:
            pass
    return True
