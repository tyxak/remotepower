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



# ── v6.4.2: the unified suppression view ─────────────────────────────────────
#
# "Why isn't this alerting?" had no single answer surface. Suppression state is
# split across SEVEN independent mechanisms, each with its own UI home:
#
#   alert mutes            alert_mutes.json      → Monitoring → Tuning
#   Needs-Attention ignores ignored_items.json   → Settings → Ignored items
#   NA class rules         na_suppress_rules.json→ Settings → Ignored items
#   accepted-risk CVEs     cve_ignore.json       → Security → CVE
#   exposure mutes         config.exposure_mutes → Security → Exposure
#   maintenance windows    maintenance.json      → Scheduling → Maintenance
#   quiet hours            config.quiet_hours    → a topbar moon and nothing else
#
# Only the last two are even discoverable during an incident, and only
# maintenance had a rollup. So a host that stops paging sends the operator to six
# pages across four accordion groups, each of which collapses the previous one.
# The product already treats this as a real question — the topbar's quiet-hours
# indicator carries the comment "why am I not being paged?" — that instinct just
# stopped at one of the seven.
#
# Read-only aggregation over stores that all already have list handlers; no new
# state. Every row carries `page`/`tab` so the UI can send the operator to the
# surface that can LIFT it, because a rollup you cannot act from is the same dead
# end one level up.

def handle_suppressions():
    """GET /api/suppressions — every active suppression, from all seven
    mechanisms, in one list. Read-only. Auth: require_auth (nothing here is a
    secret; it is the same data each owning page already shows)."""
    A.require_auth()
    now = int(A.time.time())
    cfg = A._config_ro() or {}
    # Scope + tenant, folded once. A tenant admin resolves to scope None, so
    # this has to be explicit — the same class as every other fleet aggregate.
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    visible = set(devices)
    all_devs = A.load(A.DEVICES_FILE) or {}

    def _dev_ok(did):
        """Keep fleet-level rows (no device) and rows for a visible device; drop
        a row naming a device that exists but is not this caller's."""
        if not did:
            return True
        return did not in all_devs or did in visible

    def _name(did):
        return (devices.get(did) or {}).get('name') or did or ''

    rows = []

    def add(kind, label, detail, page, tab=None, device_id='', extra=None):
        if not _dev_ok(device_id):
            return
        r = {'kind': kind, 'label': label, 'detail': detail,
             'page': page, 'device_id': device_id or '',
             'device_name': _name(device_id) if device_id else ''}
        if tab:
            r['tab'] = tab
        if extra:
            r.update(extra)
        rows.append(r)

    # 1. per-(host, event) alert mutes — expired ones are not in force, so they
    #    are not listed (listing one would say "silenced" when it is not).
    try:
        for m in (A._alert_mutes_load().get('mutes') or []):
            if A._mute_expired(m, now):
                continue
            what = m.get('container') and f"container {m['container']}" \
                or m.get('event') or 'all events'
            add('alert_mute', what,
                'Muted' + (' until it lapses' if m.get('expires_at')
                           else ' permanently'),
                'tuning', device_id=m.get('device_id') or '',
                extra={'expires_at': m.get('expires_at') or 0,
                       'id': m.get('id') or ''})
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: alert mutes: {e}\n')

    # 2 + 3. Needs-Attention per-item ignores and class-level rules.
    try:
        data = A._ignored_load()
        for cat, entries in (data or {}).items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                if not isinstance(e, dict):
                    continue
                add('na_ignore', f"{cat}: {e.get('id') or e.get('key') or '?'}",
                    'Hidden from Needs attention',
                    'settings', tab='ignored',
                    device_id=e.get('device_id') or '')
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: ignores: {e}\n')
    try:
        for r in (A._na_suppress_rules() or []):
            add('na_rule',
                f"{r.get('kind') or 'any'} / {r.get('severity') or 'any'}",
                'Class rule — hides matching Needs-attention items',
                'settings', tab='ignored',
                extra={'id': r.get('id') or ''})
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: na rules: {e}\n')

    # 4. accepted-risk CVEs.
    try:
        for vuln_id, meta in (A.load(A.CVE_IGNORE_FILE) or {}).items():
            meta = meta if isinstance(meta, dict) else {}
            add('cve_accepted', str(vuln_id)[:64],
                'Accepted risk' + (f" — {meta['reason']}"
                                   if meta.get('reason') else ''),
                'cve', device_id=meta.get('device_id') or '')
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: cve ignores: {e}\n')

    # 5. exposure mutes (a muted world-exposed port).
    try:
        for m in (cfg.get('exposure_mutes') or []):
            m = m if isinstance(m, dict) else {}
            add('exposure_mute',
                f"port {m.get('port', '?')}/{m.get('proto', 'tcp')}",
                'World-exposed-port check muted',
                'exposure', device_id=m.get('device_id') or '')
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: exposure: {e}\n')

    # 6. maintenance windows — ACTIVE ones only. A window that has not started
    #    is not suppressing anything yet, and saying it is would be the same
    #    class of lie this page exists to end.
    try:
        for w in ((A.load(A.MAINT_FILE) or {}).get('windows') or []):
            if not isinstance(w, dict):
                continue
            start = A._parse_iso(w.get('start'))
            end = A._parse_iso(w.get('end'))
            if start and end and not (start <= now <= end):
                continue
            add('maintenance',
                f"{w.get('scope') or 'global'}: {w.get('target') or 'fleet'}",
                'Maintenance window' + (f" — {w['reason']}"
                                        if w.get('reason') else ''),
                'maintenance',
                device_id=w.get('target') if w.get('scope') == 'device' else '',
                extra={'ends_at': end or 0})
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: maintenance: {e}\n')

    # 7. quiet hours — a schedule, not a per-host rule, so it is one row.
    try:
        qh = cfg.get('quiet_hours') or {}
        if qh.get('enabled'):
            add('quiet_hours',
                f"{qh.get('start') or '?'}–{qh.get('end') or '?'}",
                'Outbound delivery held outside these hours'
                + (f" (severity {qh['min_severity']} and above still deliver)"
                   if qh.get('min_severity') else ''),
                'settings', tab='dashboard')
    except Exception as e:
        A.sys.stderr.write(f'[remotepower] suppressions: quiet hours: {e}\n')

    counts = {}
    for r in rows:
        counts[r['kind']] = counts.get(r['kind'], 0) + 1
    rows.sort(key=lambda r: (r['kind'], r['device_name'].lower(), r['label']))
    A.respond(200, {'ok': True, 'suppressions': rows,
                    'total': len(rows), 'counts': counts})


def handle_mcp_acknowledge_alert():
    """POST /api/mcp/acknowledge_alert — an AI host acknowledges an alert.

    v6.4.2: the MCP server exposed 18 tools and a case-insensitive search for
    "alert" across the whole file returned nothing — so an assistant could
    reboot a host and could not read, let alone touch, the Alerts inbox, which
    is the product's primary triage surface. This is the one write that pairs
    with the new read tools, and it is deliberately the mildest one available:
    acknowledging changes who is expected to ACT and no fleet state at all.

    It cannot RESOLVE. Closing an alert is a judgement that the underlying
    problem is gone, and that stays an operator action in the dashboard.

    Rides `require_mcp_action` like every other MCP write, so a leaked MCP key
    is still confined to the allowlist and every call lands in the audit log
    with the originating AI host and the natural-language prompt.
    """
    user = A.require_mcp_action('acknowledge_alert')
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    alert_id = str(body.get('alert_id') or '').strip()
    if not alert_id:
        A.respond(400, {'error': 'alert_id required'})
    note = A._sanitize_str(str(body.get('note') or ''), 256)
    ai_host, ai_prompt = A.get_mcp_attribution()

    found = acked = None
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in (store.get('alerts') or []):
            if a.get('id') != alert_id:
                continue
            found = True
            # Same visibility gate the human ack uses — an MCP key confined to
            # a tenant or a role scope must not be able to ack outside it just
            # because this route is not under /api/devices/.
            if not A._alert_mutable_by_caller(a):
                A.respond(404, {'error': 'alert not found'})
            if a.get('resolved_at'):
                A.respond(409, {'error': 'alert already resolved'})
            if a.get('acknowledged_at'):
                A.respond(409, {'error': 'alert already acknowledged'})
            a['acknowledged_by'] = user
            a['acknowledged_at'] = int(A.time.time())
            if note:
                a['ack_note'] = note
            acked = dict(a)
            break
    if not found:
        A.respond(404, {'error': 'alert not found'})
    # audit_log is self-locking and auto-defers, but keeping it out of the block
    # is the house rule and costs nothing.
    A.audit_log(user, 'mcp_acknowledge_alert',
                f'alert={alert_id}' + (f' note={note!r}' if note else ''),
                ai_host=ai_host, ai_prompt=ai_prompt)
    A.respond(200, {'ok': True, 'alert_id': alert_id,
                    'acknowledged_by': user,
                    'severity': (acked or {}).get('severity'),
                    'title': (acked or {}).get('title')})
