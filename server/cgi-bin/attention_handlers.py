"""RemotePower — Needs-Attention quieting: class-level suppression rules + per-item ignores

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


def _ignored_load():
    data = A.load(A.IGNORED_ITEMS_FILE) or {}
    # Normalise — every category is always a list
    for k in ('needs_attention', 'stale_containers', 'devices'):
        if not isinstance(data.get(k), list):
            data[k] = []
    # v3.2.3: drop expired snoozes. needs_attention entries may carry
    # an `expires_at` epoch — when past, they vanish so the alert
    # comes back into view. Pure read-time filter; we never write
    # back here (a CGI request shouldn't take a file lock just to
    # clean up; the next /api/ignored POST or its own GET path
    # tolerates expired entries).
    now = int(A.time.time())
    data['needs_attention'] = [
        e for e in data['needs_attention']
        if not e.get('expires_at') or e['expires_at'] > now
    ]
    return data


def _ignored_keys(category):
    """Return the set of stable keys for a category, for O(1) lookup."""
    data = A._ignored_load()
    if category == 'needs_attention':
        return {entry.get('key') for entry in data['needs_attention'] if entry.get('key')}
    if category == 'stale_containers':
        return {f"{e.get('device_id','')}/{e.get('container','')}" for e in data['stale_containers']}
    if category == 'devices':
        return {e.get('id') for e in data['devices'] if e.get('id')}
    return set()


# ── v6.4.0: ignore lifecycle — stop the ignored-items list from piling up ──────
# The pile-up had one root cause: a permanent × ignore was NEVER garbage-
# collected. It lived forever even after its condition cleared, its device was
# removed, or its point-in-time event aged out of the 24h fleet-events window.
# On a big fleet that grows without bound and hides real recurrences. The
# machinery below GCs a moot ignore (#1), prunes a removed device's ignores (#2)
# and annotates each ignore with when it was last actually active (#5, surfaced
# in the UI so stale ignores can be bulk-cleared). Class-level suppression (#4)
# and the auto-heal recheck sweep (#3) live in their own blocks below.

def _na_suppress_rules():
    """The list of active suppression rules ({id,kind,scope,value,note,by,ts})."""
    data = A._load_ro(A.NA_SUPPRESS_FILE) or {}
    rules = data.get('rules') if isinstance(data, dict) else None
    return [r for r in rules if isinstance(r, dict) and r.get('kind')] if isinstance(rules, list) else []


def _na_item_suppressed(item, rules, devices, name_to_id):
    """True if any class rule covers this NA item. Matches on kind (or '*' = any
    kind) AND scope: all / device(id or name) / group / tag."""
    kind = str(item.get('kind') or '')
    did = item.get('device_id') or name_to_id.get(item.get('device'))
    dev = (devices.get(did) or {}) if did else {}
    grp = str(dev.get('group') or '')
    tags = dev.get('tags') or []
    for r in rules:
        rk = str(r.get('kind') or '')
        if rk not in ('*', 'any', kind):
            continue
        scope = str(r.get('scope') or 'all')
        val = str(r.get('value') or '')
        if scope == 'all':
            return True
        if scope == 'device' and val and (val == str(did or '') or val == str(item.get('device') or '')):
            return True
        if scope == 'group' and val and val == grp:
            return True
        if scope == 'tag' and val and val in tags:
            return True
    return False


def handle_na_suppress_list():
    """GET /api/na-suppress — the class-level NA suppression rules."""
    A.require_auth()
    A.respond(200, {'rules': A._na_suppress_rules(), 'scopes': list(A._NA_SUPPRESS_SCOPES)})


def handle_na_suppress_add():
    """POST /api/na-suppress {kind, scope, value, note} — add a suppression rule."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    kind = A._sanitize_str(str(body.get('kind', '')), 40).strip() or '*'
    scope = str(body.get('scope', 'all')).strip().lower()
    if scope not in A._NA_SUPPRESS_SCOPES:
        A.respond(400, {'error': f'scope must be one of {", ".join(A._NA_SUPPRESS_SCOPES)}'})
    value = A._sanitize_str(str(body.get('value', '')), 128).strip()
    if scope != 'all' and not value:
        A.respond(400, {'error': 'value required for this scope'})
    rule = {'id': A.secrets.token_hex(6), 'kind': kind, 'scope': scope, 'value': value,
            'note': A._sanitize_str(str(body.get('note', '')), 200), 'by': actor,
            'ts': int(A.time.time())}
    with A._LockedUpdate(A.NA_SUPPRESS_FILE) as data:
        rules = data.setdefault('rules', [])
        if not isinstance(rules, list):
            rules = data['rules'] = []
        if len(rules) >= 500:
            A.respond(400, {'error': 'rule limit reached (500)'})
        rules.append(rule)
    A.audit_log(actor, 'na_suppress_add', f'kind={kind} scope={scope}:{value}')
    A.respond(200, {'ok': True, 'rule': rule})


def handle_na_suppress_remove():
    """POST /api/na-suppress/remove {id} — delete a suppression rule."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    rid = A._sanitize_str(str(A.get_json_obj().get('id', '')), 16).strip()
    if not rid:
        A.respond(400, {'error': 'id required'})
    with A._LockedUpdate(A.NA_SUPPRESS_FILE) as data:
        rules = data.get('rules')
        if isinstance(rules, list):
            data['rules'] = [r for r in rules if (r or {}).get('id') != rid]
    A.audit_log(actor, 'na_suppress_remove', f'id={rid}')
    A.respond(200, {'ok': True})


def handle_ignored_list():
    """GET /api/ignored — full list across all categories."""
    A.require_auth()
    A.respond(200, A._ignored_load())


def handle_ignored_add():
    """POST /api/ignored — body {category, key/device_id/container/id, label?}."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    body = A._read_valid(A.request_models.IgnoredAddRequest)
    cat  = str(body.get('category', '')).strip()
    if cat not in ('needs_attention', 'stale_containers', 'devices'):
        A.respond(400, {'error': 'invalid category'}); return
    now  = int(A.time.time())
    with A._LockedUpdate(A.IGNORED_ITEMS_FILE) as data:
        for k in ('needs_attention', 'stale_containers', 'devices'):
            if not isinstance(data.get(k), list):
                data[k] = []
        if cat == 'needs_attention':
            key = A._sanitize_str(str(body.get('key', '')), 32)
            if not key:
                A.respond(400, {'error': 'key required'}); return
            # v3.2.3: optional `expires_at` (epoch seconds) for snoozes.
            # When set, the entry auto-disappears from the ignore list
            # after that time and the alert returns to Needs Attention.
            # Clamp to ≤ 30 days so a misclick can't bury an alert
            # forever — operators who really want permanent should use
            # the existing × ignore (no expires_at field).
            raw_exp = body.get('expires_at')
            expires_at = None
            if raw_exp is not None and raw_exp != '':
                try:
                    expires_at = int(raw_exp)
                except (TypeError, ValueError):
                    expires_at = None
                if expires_at is not None:
                    expires_at = min(expires_at, now + 30 * 86400)
                    if expires_at <= now:
                        expires_at = None
            existing = next((e for e in data['needs_attention']
                             if e.get('key') == key), None)
            if existing:
                # Re-snoozing extends or shortens; permanent ignore
                # (no expires_at posted) clears the snooze.
                if expires_at is None:
                    existing.pop('expires_at', None)
                else:
                    existing['expires_at'] = expires_at
                existing['ts'] = now
            else:
                entry = {
                    'key':   key,
                    'ts':    now,
                    'last_seen': now,   # v6.4.0 #1: seed for the GC sweep
                    'label': A._sanitize_str(str(body.get('label', '')), 200),
                }
                # v6.4.0 #2: remember the device so the device-removal prune can
                # target this ignore (the NA key itself is an opaque hash).
                _did = A._sanitize_str(str(body.get('device_id', '')), 64)
                if _did:
                    entry['device_id'] = _did
                if expires_at:
                    entry['expires_at'] = expires_at
                data['needs_attention'].append(entry)
        elif cat == 'stale_containers':
            did = A._sanitize_str(str(body.get('device_id', '')), 64)
            ctr = A._sanitize_str(str(body.get('container', '')), 200)
            if not did:
                A.respond(400, {'error': 'device_id required'}); return
            # v3.0.1: empty container = ignore the device entirely on the
            # Containers page (regardless of stale state). Non-empty container
            # = ignore that specific container row only.
            if not any(e.get('device_id') == did and e.get('container') == ctr
                       for e in data['stale_containers']):
                data['stale_containers'].append({
                    'device_id': did, 'container': ctr, 'ts': now,
                    'label': A._sanitize_str(str(body.get('label', '')), 200),
                })
        elif cat == 'devices':
            did = A._sanitize_str(str(body.get('id', '')), 64)
            if not did:
                A.respond(400, {'error': 'id required'}); return
            if not any(e.get('id') == did for e in data['devices']):
                data['devices'].append({
                    'id': did, 'ts': now,
                    'label': A._sanitize_str(str(body.get('label', '')), 200),
                })
    A.respond(200, {'ok': True})


def handle_ignored_remove():
    """POST /api/ignored/remove — body {category, key/device_id+container/id}."""
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'}); return
    body = A._read_valid(A.request_models.IgnoredRemoveRequest)
    cat  = str(body.get('category', '')).strip()
    if cat not in ('needs_attention', 'stale_containers', 'devices'):
        A.respond(400, {'error': 'invalid category'}); return
    with A._LockedUpdate(A.IGNORED_ITEMS_FILE) as data:
        for k in ('needs_attention', 'stale_containers', 'devices'):
            if not isinstance(data.get(k), list):
                data[k] = []
        if cat == 'needs_attention':
            key = str(body.get('key', ''))
            data['needs_attention'] = [e for e in data['needs_attention'] if e.get('key') != key]
        elif cat == 'stale_containers':
            did = str(body.get('device_id', ''))
            ctr = str(body.get('container', ''))
            data['stale_containers'] = [
                e for e in data['stale_containers']
                if not (e.get('device_id') == did and e.get('container') == ctr)
            ]
        elif cat == 'devices':
            did = str(body.get('id', ''))
            data['devices'] = [e for e in data['devices'] if e.get('id') != did]
    A.respond(200, {'ok': True})

