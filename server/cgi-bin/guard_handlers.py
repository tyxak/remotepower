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
    """POST /api/guard/action {device_id, id, op:'restore'|'delete'} — queue a
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
    if op not in ('restore', 'delete'):
        A.respond(400, {'error': "op must be 'restore' or 'delete'"})
    if not did or not qid:
        A.respond(400, {'error': 'device_id and id are required'})
    A._scope_block_device(did)     # 403s a device the caller can't see
    with A._DeviceUpdate(did) as dev:
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'device not found'})
        acts = dev.setdefault('guard_actions', [])
        if not any(isinstance(a, dict) and a.get('id') == qid for a in acts):
            acts.append({'id': qid, 'op': op})
    A.audit_log(actor, 'guard_action', f'device={did} id={qid} op={op}')
    A.respond(200, {'ok': True})
