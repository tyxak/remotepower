"""RemotePower — The container hardening audit: the findings for every container, and accepting one (7.4.9)

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

import container_audit


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


MAX_ROWS = 1000
MAX_ACCEPTS_PER_HOST = 200


def _accepted_set(rows):
    return {(str(a.get('container') or ''), str(a.get('rule') or '')) for a in (rows or []) if isinstance(a, dict)}


def _row(dev_id, dev, entry, c, acc):
    """One container's audit row, or None when it was never audited."""
    found = container_audit.evaluate(c)
    if found is None:
        return None
    name = str(c.get('name') or '')
    live = []
    marked = []
    for f in found:
        g = dict(f, accepted=(name, f['rule']) in acc)
        marked.append(g)
        if not g['accepted']:
            live.append(g)
    return {'device_id': dev_id, 'device': dev.get('name', dev_id), 'monitored': dev.get('monitored') is not False,
            'container': name, 'image': str(c.get('image') or ''), 'tag': str(c.get('tag') or ''),
            'runtime': str(c.get('runtime') or ''), 'status': str(c.get('status') or ''),
            'reported_at': entry.get('ts', 0) if isinstance(entry.get('ts'), (int, float)) else 0,
            'counts': container_audit.count(live), 'worst': container_audit.worst(live), 'findings': marked}


def handle_container_audit():
    """GET /api/containers/audit — how every container in the fleet was started, and what that allows.

    One row per audited container with its findings (rule, severity, title, detail, and whether an administrator accepted
    it), worst first. `?min=critical|high|medium|low` leaves out the findings below that severity and the containers with
    none left (default low, which is everything); `?q=` filters on host, container or image. `summary` counts every audited
    container by its worst finding, whatever the filter, so the header does not move when the filter does; `not_audited`
    counts the containers whose agent has not reported their run options (an older agent, or a runtime that would not answer).
    Hosts outside the caller's tenant or role scope are not listed."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    floor = (qs.get('min', ['low'])[0] or 'low').lower()
    if floor not in container_audit.RANK:
        floor = 'low'
    q = (qs.get('q', [''])[0] or '').strip().lower()[:100]
    devices = A._scope_filter_devices(A._load_ro(A.DEVICES_FILE) or {})
    store = A.load(A.CONTAINERS_FILE) or {}
    accepts = A.load(A.CONTAINER_AUDIT_ACCEPTS_FILE) or {}
    ignored = A._ignored_keys('devices')
    rows = []
    summary = {s: 0 for s in container_audit.SEVERITIES}
    summary['clean'] = 0
    not_audited = 0
    for dev_id, entry in store.items():
        dev = devices.get(dev_id)
        if not isinstance(dev, dict) or dev_id in ignored or not isinstance(entry, dict):
            continue
        acc = _accepted_set(accepts.get(dev_id))
        for c in entry.get('items') or []:
            if not isinstance(c, dict):
                continue
            row = _row(dev_id, dev, entry, c, acc)
            if row is None:
                not_audited += 1
                continue
            summary[row['worst'] or 'clean'] += 1
            # a container is listed when it has a finding at or above the floor, accepted or not: an accepted finding has to
            # stay findable, or it could not be taken back. It no longer counts, so its row sorts after the ones that do.
            keep = [f for f in row['findings'] if container_audit.RANK[f['severity']] <= container_audit.RANK[floor]]
            if not keep:
                continue
            if q and q not in f"{row['device']} {row['container']} {row['image']}".lower():
                continue
            row['findings'] = keep
            rows.append(row)
    rows.sort(key=lambda r: tuple(-r['counts'][s] for s in container_audit.SEVERITIES) + (r['device'].lower(), r['container'].lower()))
    A.respond(200, {'containers': rows[:MAX_ROWS], 'truncated': len(rows) > MAX_ROWS, 'summary': summary,
                    'not_audited': not_audited, 'rules': {k: {'severity': v[0], 'title': v[1]} for k, v in container_audit.RULES.items()}})


def handle_device_container_audit(dev_id):
    """PUT /api/devices/<id>/container-audit — accept a finding for one container, or take the acceptance back.

    Body {"container": "<name>", "rule": "<rule id>", "accepted": true|false, "note": "<why>"}. An accepted finding stays in
    the list, marked, and stops counting: some containers need what the audit flags (a metrics agent mounts `/`, a manager
    mounts the engine socket), and an audit that cannot be told so is one people stop reading. Administrators only, and every
    change is audited. The container has to be one the host reports and the rule one of the audit's. The route is under
    /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused before this runs."""
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    body = A._read_valid(A.request_models.ContainerAuditAcceptRequest)
    container = A._sanitize_str(str(body.get('container') or ''), 256).strip()
    rule = str(body.get('rule') or '').strip()
    note = A._sanitize_str(str(body.get('note') or ''), 200).strip()
    accepted = body.get('accepted')
    if not isinstance(accepted, bool):    # 1 == True in Python, so `in (True, False)` would pass a number
        A.respond(400, {'error': 'accepted must be true or false'})
    if rule not in container_audit.RULES:
        A.respond(400, {'error': 'Unknown rule'})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict) or not A._tenant_visible(dev):
        A.respond(404, {'error': 'Host not found'})
    entry = A._entity_read_one(A.CONTAINERS_FILE, dev_id, None) or {}
    if not any(isinstance(c, dict) and c.get('name') == container for c in (entry.get('items') or [])):
        A.respond(404, {'error': 'Container not found'})
    full = False
    with A._LockedUpdate(A.CONTAINER_AUDIT_ACCEPTS_FILE) as store:
        rows = [a for a in (store.get(dev_id) or [])
                if isinstance(a, dict) and (a.get('container'), a.get('rule')) != (container, rule)]
        if accepted:
            if len(rows) >= MAX_ACCEPTS_PER_HOST:
                full = True
            else:
                rows.append({'container': container, 'rule': rule, 'by': actor, 'ts': int(A.time.time()), 'note': note})
        if not full:
            if rows:
                store[dev_id] = rows
            else:
                store.pop(dev_id, None)
    if full:
        A.respond(409, {'error': 'Too many findings are accepted on this host', 'max': MAX_ACCEPTS_PER_HOST})
    A.audit_log(actor, 'container_audit_accept' if accepted else 'container_audit_unaccept',
                f'device={dev_id} container={container[:80]} rule={rule}')
    A.respond(200, {'ok': True, 'accepted': accepted})
