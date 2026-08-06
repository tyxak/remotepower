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


# ── v6.4.2: Prometheus HTTP service discovery ────────────────────────────────
#
# RemotePower exposes its own metrics at /api/metrics and ships a Grafana pack,
# but there was no endpoint returning the FLEET in `http_sd_configs` shape. An
# operator scraping node_exporter alongside RemotePower had to hand-maintain a
# second target list, even though RemotePower already tracks every host's name,
# IP, group, tag, site and online state, and already re-syncs cloud instances
# automatically. A newly-enrolled or decommissioned host silently drifted out of
# prometheus.yml until someone noticed a missing graph.
#
# Same status-token auth as /api/metrics, so it drops into the same scrape
# config an operator already has.

def _prom_label(value):
    """Prometheus label values are UTF-8 and mostly unconstrained, but a name
    with a newline or a quote would corrupt the JSON consumer's view — and these
    come from agent-reported hostnames and operator-typed tags."""
    return A._sanitize_str(str(value or ''), 128).replace('"', '').replace('\\', '')


def handle_prometheus_sd():
    """GET /api/prometheus/sd?port=9100 — the fleet as Prometheus http_sd targets.

    Returns `[{"targets": ["host:port"], "labels": {...}}]`, one entry per
    device, so `http_sd_configs` keeps prometheus.yml in step with enrolment
    automatically.

    Auth mirrors /api/metrics exactly: `?token=<status token>` for a scrape
    config, or a normal session token for a browser. Deliberately NOT
    require_auth alone — a scraper has no session.
    """
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    qs_token = (qs.get('token') or [''])[0]
    if qs_token:
        cfg_token = (A.load(A.CONFIG_FILE) or {}).get('status_token') or ''
        if not A._ct_token_eq(qs_token, cfg_token):
            A.respond(401, {'error': 'invalid status token'})
    else:
        # Falls back to the normal gate, which also applies role scope + the
        # tenant gate through _scope_filter_devices below.
        A.require_auth()

    try:
        port = int((qs.get('port') or ['9100'])[0])
    except (TypeError, ValueError):
        port = 9100
    if not (1 <= port <= 65535):
        port = 9100
    only_online = (qs.get('online') or [''])[0] == '1'

    # A status-token scrape has no role scope and no tenant, and is the same
    # trust level as /api/metrics (which exposes the whole fleet) — so the
    # filter applies for a session caller and is a no-op for the scraper.
    devices = (A.load(A.DEVICES_FILE) or {}) if qs_token \
        else A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    now = int(A.time.time())
    ttl = A.get_online_ttl()

    out = []
    for did, d in devices.items():
        if not isinstance(d, dict) or d.get('decommissioned'):
            continue
        # An agentless device has no node_exporter to scrape; including it would
        # hand Prometheus a target that can only ever be down.
        if d.get('agentless'):
            continue
        host = (d.get('ip') or d.get('hostname') or '').strip()
        if not host:
            continue
        online = bool(d.get('last_seen')) and (now - int(d.get('last_seen') or 0)) < ttl
        if only_online and not online:
            continue
        labels = {
            '__meta_remotepower_id':      _prom_label(did),
            '__meta_remotepower_name':    _prom_label(d.get('name') or did),
            '__meta_remotepower_group':   _prom_label(d.get('group') or ''),
            '__meta_remotepower_site':    _prom_label(d.get('site') or ''),
            '__meta_remotepower_os':      _prom_label(d.get('os') or ''),
            '__meta_remotepower_online':  'true' if online else 'false',
            # `instance` is what Prometheus keys a series on; without it every
            # target would be labelled by IP and a re-addressed host would look
            # like a brand-new one.
            'instance':                   _prom_label(d.get('name') or did),
        }
        tags = [t for t in (d.get('tags') or []) if t]
        if tags:
            # Prometheus SD has no list label type; the conventional shape is a
            # separator-delimited string a relabel rule can regex against.
            labels['__meta_remotepower_tags'] = ',' + ','.join(
                _prom_label(t) for t in tags[:32]) + ','
        out.append({'targets': [f'{_prom_label(host)}:{port}'], 'labels': labels})

    out.sort(key=lambda e: e['labels'].get('instance', ''))
    A.respond(200, out)


def handle_itsm_callback(token_str):
    """POST /api/itsm/in/<token> — an external ticket closed; resolve its alert.

    v6.4.2: the other half of the ITSM loop. A team living in Jira acks a
    `disk_predict_failure`, an issue opens, an engineer swaps the disk and
    closes the issue — and RemotePower's alert stayed open forever, counting in
    the inbox, holding the host in Needs Attention and dragging the fleet
    health score down until somebody remembered to resolve it a second time in
    a second UI. There was no inbound route back at all: the token kinds were
    alert/syslog/snmp_trap/flow, so a Jira issue-updated webhook had nowhere to
    land.

    Body: `{ticket_ref, status?}` — or any of the providers' own issue-updated
    shapes, which all carry the key somewhere different. Deliberately tolerant:
    the sender is a webhook template an operator pastes into Jira/ServiceNow/
    Zendesk, and rejecting it on shape would put us back where we started.
    """
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    tokens = (A.load(A.INBOUND_WEBHOOKS_FILE) or {}).get('tokens', [])
    token_str = (token_str or '').strip()
    if not token_str or not token_str.startswith('rpwi_'):
        A._log_inbound('itsm', '', '', '401', 'invalid token format')
        A.respond(401, {'error': 'invalid token'})
    match = None
    for t in tokens:
        if A.hmac.compare_digest(t.get('token', ''), token_str) and t.get('enabled', True):
            match = t
            break
    if not match:
        A._log_inbound('itsm', '', '', '401', 'invalid or disabled token')
        A.respond(401, {'error': 'invalid or disabled token'})
    if (match.get('kind') or 'alert') != 'itsm':
        A._log_inbound('itsm', match.get('id'), match.get('label'), '400',
                     f'wrong url for {match.get("kind", "alert")} token')
        A.respond(400, {'error': f'this token is a {match.get("kind", "alert")} '
                               f'token — use the corresponding URL'})
    body = A.get_json_obj()
    ref, status = A._itsm_callback_fields(body)
    if not ref:
        A._log_inbound('itsm', match.get('id'), match.get('label'), '400',
                     'no ticket reference in body')
        A.respond(400, {'error': 'could not find a ticket key/number/id in the body '
                               '— send {"ticket_ref": "..."} if your template '
                               'cannot be shaped'})
    if not A._itsm_status_is_closed(status):
        A._log_inbound('itsm', match.get('id'), match.get('label'), '200',
                     f'{ref} status={status or "?"} — not a closing state, ignored')
        A.respond(200, {'ok': True, 'resolved': 0, 'reason': 'not a closing status'})
    now = int(A.time.time())
    n = 0
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in store.get('alerts', []):
            if a.get('resolved_at') or str(a.get('ticket_ref') or '') != ref:
                continue
            a['resolved_at'] = now
            a['resolved_by'] = f'itsm:{ref}'[:64]
            n += 1
    A._log_inbound('itsm', match.get('id'), match.get('label'), '200',
                 f'resolved {n} alert(s) from ticket {ref}')
    A.audit_log(f'inbound:{match.get("label", match.get("id", "?"))}',
              'itsm_callback', f'ticket={ref} status={status} resolved={n}')
    A.respond(200, {'ok': True, 'resolved': n, 'ticket_ref': ref})


# The key lives somewhere different in every provider's issue-updated payload,
# and each is a template the operator pastes in rather than a schema we control.
_ITSM_REF_PATHS = (
    ('ticket_ref',),                     # ours, for a template that can be shaped
    ('issue', 'key'),                    # Jira
    ('key',),                            # Jira, flattened
    ('ticket', 'id'),                    # Zendesk
    ('number',),                         # ServiceNow
    ('sys_id',),                         # ServiceNow, when the number is absent
)
_ITSM_STATUS_PATHS = (
    ('status',),
    ('issue', 'fields', 'status', 'name'),
    ('ticket', 'status'),
    ('state',),
)
# What each provider calls "done". `6`/`7` are ServiceNow's Resolved/Closed.
_ITSM_CLOSED = {'closed', 'resolved', 'solved', 'done', 'complete', 'completed',
                'fixed', '6', '7'}


def _dig(obj, path):
    cur = obj
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _itsm_callback_fields(body):
    """(ticket_ref, status) from whichever provider shape arrived."""
    if not isinstance(body, dict):
        return '', ''
    ref = ''
    for path in _ITSM_REF_PATHS:
        v = A._dig(body, path)
        if v not in (None, ''):
            ref = A._sanitize_str(str(v), 128)
            break
    status = ''
    for path in _ITSM_STATUS_PATHS:
        v = A._dig(body, path)
        if v not in (None, ''):
            status = A._sanitize_str(str(v), 64)
            break
    return ref, status


def _itsm_status_is_closed(status):
    """True when the provider says the ticket is done.

    An ABSENT status counts as closed: several providers let an operator wire a
    webhook that only fires ON transition-to-done and sends no status field at
    all. Refusing those would leave the loop open for exactly the setups that
    configured it most carefully.
    """
    if not status:
        return True
    return str(status).strip().lower() in _ITSM_CLOSED


# ── v6.4.2: threshold blast-radius preview ──────────────────────────────────
# Settings → Alert parameters exposes ~70 numeric firing thresholds plus the
# grade/risk cutoffs and per-factor weights, and POST /api/config applied them
# FLEET-WIDE on save with no preview step. Nothing computed how many hosts
# would newly breach.
#
# An operator wants fewer disk pages, drops disk_warn_percent from 90 to 80,
# and hits Save. Because _host_checks() is recomputed for the whole fleet on
# the next read, the change fans out instantly: on a 400-host fleet that is a
# hundred simultaneous new breaches, a Needs-Attention avalanche and a paging
# storm, at which point the only recovery is Settings → Advanced →
# Configuration history.
#
# The blast-radius idea already exists in this codebase — `_blast_radius_guard`
# gates batch reboot/shutdown — but it is scoped to power actions. And the data
# needed to answer "how many hosts sit between 80 and 90 right now" is already
# loaded on the server; nothing exposed it before the save.
#
# The preview re-runs the REAL checks engine against the proposed config rather
# than reimplementing any threshold's meaning. A second copy of "what counts as
# breaching" would drift from the first, and a preview that disagrees with what
# actually happens is worse than no preview.
_PREVIEW_EXAMPLE_HOSTS = 5


def _preview_check_map(devices, cfg, scripts, hw_all, cve_all, eta_all, now, ttl):
    """{device_id: {check_key: status}} for one config."""
    out = {}
    kwargs = A._checks_threshold_kwargs(cfg)
    disabled_all = cfg.get('host_checks_disabled') or {}
    custom_defs = cfg.get('custom_checks') or []
    exposure_mutes = cfg.get('exposure_mutes') or []
    for did, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        rows = A._host_checks(did, dev, hw_all.get(did) or {},
                              disabled_all.get(did) or [], now, ttl,
                              cve_high=cve_all.get(did), disk_eta=eta_all.get(did),
                              custom_defs=custom_defs, scripts=scripts,
                              exposure_mutes=exposure_mutes, **kwargs)
        out[did] = {r.get('key'): r.get('status') for r in rows
                    if isinstance(r, dict) and r.get('enabled', True)}
    return out


_BREACH = ('warning', 'critical')


def handle_threshold_preview():
    """POST /api/config/threshold-preview — what would this change break?

    Body is the same shape POST /api/config takes; only keys the threshold
    save-loops actually accept are considered, so pasting a whole settings
    payload is fine.
    """
    A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    tunable = A._alert_param_config_keys()
    cfg = A.load(A.CONFIG_FILE) or {}
    proposed_vals = {}
    for k, v in body.items():
        if k not in tunable:
            continue
        try:
            nv = float(v)
        except (TypeError, ValueError):
            continue
        if cfg.get(k) is None or float(cfg.get(k, 0) or 0) != nv:
            proposed_vals[k] = int(nv) if nv == int(nv) else nv
    if not proposed_vals:
        A.respond(200, {'changed': {}, 'newly_breaching': [], 'newly_passing': [],
                        'hosts_evaluated': 0, 'not_evaluated': [],
                        'note': 'None of these values differ from what is saved.'})
    # v6.4.2 (audit): the preview recomputes the CHECKS engine only, which reads
    # ~7 of the ~90 alert-parameter thresholds. The rest fire through the metric
    # ingest, the risk/reliability scoring, tls_monitor and the attention engine
    # — none of which this preview evaluates. Reporting them as zero blast
    # radius (the UI's "no host changes state") is precisely the kind of
    # false-reassurance this feature exists to prevent. So partition the changed
    # keys: probe which ones actually feed _checks_threshold_kwargs (no
    # hardcoded list to drift), and surface the rest as "not assessed" rather
    # than silently implying they are safe.
    _base_kwargs = A._checks_threshold_kwargs(cfg)
    _evaluated, _not_evaluated = {}, []
    for k, v in proposed_vals.items():
        if A._checks_threshold_kwargs({**cfg, k: v}) != _base_kwargs:
            _evaluated[k] = v
        else:
            _not_evaluated.append(k)
    # SEC: scope-filtered like every other fleet-wide view — a preview that
    # counts hosts the caller cannot see is a host-count leak.
    devices = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    scripts = A._load_custom_scripts()
    hw_all = (A.load(A.HARDWARE_FILE) or {}) if A.backend_exists(A.HARDWARE_FILE) else {}
    cve_all = A._cve_high_counts()
    eta_all = A._disk_fill_eta(devices)
    now = int(A.time.time())
    ttl = A.get_online_ttl()
    before = _preview_check_map(devices, cfg, scripts, hw_all, cve_all, eta_all, now, ttl)
    after = _preview_check_map(devices, {**cfg, **_evaluated}, scripts,
                               hw_all, cve_all, eta_all, now, ttl)
    worse, better = {}, {}
    for did, rows in after.items():
        for key, status in rows.items():
            was = (before.get(did) or {}).get(key)
            if was == status:
                continue
            name = (devices.get(did) or {}).get('name', did)
            if status in _BREACH and was not in _BREACH:
                worse.setdefault(key, []).append({'device_id': did, 'name': name,
                                                  'to': status})
            elif was in _BREACH and status not in _BREACH:
                better.setdefault(key, []).append({'device_id': did, 'name': name,
                                                  'from': was})

    def _rows(d):
        return sorted(
            ({'check': k, 'hosts': len(v),
              'examples': [x['name'] for x in v[:_PREVIEW_EXAMPLE_HOSTS]]}
             for k, v in d.items()),
            key=lambda r: -r['hosts'])

    A.respond(200, {
        'changed': proposed_vals,
        'hosts_evaluated': len(devices),
        'newly_breaching': _rows(worse),
        'newly_passing': _rows(better),
        'total_newly_breaching': sum(len(v) for v in worse.values()),
        'total_newly_passing': sum(len(v) for v in better.values()),
        # v6.4.2 (audit): the changed thresholds this preview could NOT assess.
        # Surfaced so "no host changes state" is never read as "all your changes
        # are safe" — most alert parameters fire outside the checks engine.
        'not_evaluated': sorted(_not_evaluated),
        'evaluated': sorted(_evaluated),
        # Said explicitly because the obvious assumption is wrong, and a preview
        # that lets an operator believe it would be a worse kind of missing.
        'note': 'Counts are CHECK results recomputed against your proposed '
                'values. Thresholds that fire through the metric, risk or '
                'attention engine are not assessed by this preview (listed under '
                'not_evaluated). Alerts already open are not resolved by a '
                'threshold change — they clear on their own recover events, or '
                'by muting them under Monitoring → Tuning.',
    })


# ── v6.4.2: data-subject rights (GDPR Art. 15 / 17) ─────────────────────────
# `handle_user_delete` was `del users[username]; save(...)`. It did not unlink
# the avatar, prune the token rows, or touch anything else that names the
# person — and RemotePower holds personal data well outside users.json: the
# Contacts directory (name / role / company / email / phone / notes), ticket
# authors and assignees, ticket comment authors, time-billing entries, scoped
# notes and audit actor fields.
#
# So an EU MSP receiving an Article 17 erasure request from a departed
# contractor could delete the account and still be left with their avatar JPEG
# on disk, their name on forty ticket comments and every timesheet line, their
# phone number in Contacts — and no report that even enumerates where it all
# is. The answer had to be assembled by grepping the data directory.
#
# The product already ships an explicitly GDPR-framed PII SCANNER, which finds
# regulated data on managed HOSTS. That is exactly why a buyer assumes the
# subject-rights side exists.
#
# Two deliberate limits, both stated in the response rather than glossed:
#   * The AUDIT LOG is never rewritten. It is hash-chained, and editing a
#     chained entry destroys the tamper-evidence that makes it evidence at all.
#     Audit references are REPORTED, never erased — which is the lawful answer
#     (Art. 17(3)(b)/(e)) and not a limitation to hide.
#   * Backups already taken still contain the data. An erasure tool that
#     implied otherwise would be worse than none.
_SUBJECT_TEXT_FIELDS = ('name', 'email', 'phone', 'company', 'role', 'notes')


def _subject_matches(value, who, email):
    v = str(value or '').strip().lower()
    if not v:
        return False
    return v == who or (bool(email) and v == email)


def _subject_scan(who, email=''):
    """Every place this instance names a person. Read-only.

    Deliberately enumerates rather than greps: a grep over the data directory
    is what the operator was reduced to, and it cannot distinguish "the word
    appears" from "this record is about them".
    """
    who = str(who or '').strip().lower()
    email = str(email or '').strip().lower()
    found = []

    def add(store, kind, ref, detail, erasable):
        found.append({'store': store, 'kind': kind, 'ref': str(ref)[:120],
                      'detail': str(detail)[:200], 'erasable': erasable})

    users = A.load(A.USERS_FILE) or {}
    for u, rec in users.items():
        if u.lower() == who or (email and str((rec or {}).get('email', '')).lower() == email):
            add('users.json', 'account', u, f"role={rec.get('role', '?')}", True)
    if A.AVATARS_DIR and who:
        try:
            for f in A.AVATARS_DIR.glob(f'{who}.*'):
                add('avatars/', 'avatar', f.name, 'profile image', True)
        except OSError as e:
            # An unreadable avatar directory must not sink the whole report —
            # but it must not be silent either. A subject-access report that
            # under-reports because a directory listing failed is exactly the
            # kind of quiet incompleteness this endpoint exists to prevent, so
            # say so in the report rather than only in the log.
            A.sys.stderr.write(f'[remotepower] avatar scan failed: {e}\n')
            add('avatars/', 'avatar', '(unreadable)',
                f'could not list the avatar directory: {str(e)[:80]}', False)
    toks = A.load(A.TOKENS_FILE) or {}
    n_tok = sum(1 for t in (toks.values() if isinstance(toks, dict) else [])
                if isinstance(t, dict) and str(t.get('user', '')).lower() == who)
    if n_tok:
        add('tokens.json', 'session', f'{n_tok} token(s)',
            'inert once the account is gone (verify_token returns None), but '
            'still storage naming them', True)
    for cid, c in (A.load(A.CONTACTS_FILE) or {}).items():
        if not isinstance(c, dict):
            continue
        if any(_subject_matches(c.get(f), who, email) for f in _SUBJECT_TEXT_FIELDS):
            add('contacts.json', 'contact', cid,
                f"{c.get('name', '')} · {c.get('email', '')}", True)
    tickets = (A.load(A.TICKETS_FILE) or {}).get('tickets') or []
    t_auth = [t for t in tickets if isinstance(t, dict)
              and (_subject_matches(t.get('created_by'), who, email)
                   or _subject_matches(t.get('assignee'), who, email))]
    if t_auth:
        add('tickets.json', 'ticket', f'{len(t_auth)} ticket(s)',
            'created_by / assignee', False)
    n_comments = sum(
        1 for t in tickets if isinstance(t, dict)
        for c in (t.get('comments') or [])
        if isinstance(c, dict) and _subject_matches(c.get('by'), who, email))
    if n_comments:
        add('tickets.json', 'comment', f'{n_comments} comment(s)',
            'comment author', False)
    entries = (A.load(A.TIME_ENTRIES_FILE) or {}).get('entries') or []
    n_time = sum(1 for e in entries if isinstance(e, dict)
                 and _subject_matches(e.get('user') or e.get('by'), who, email))
    if n_time:
        add('time_entries.json', 'time entry', f'{n_time} entr(y/ies)',
            'billable work record', False)
    audit = (A.load(A.AUDIT_LOG_FILE) or {}).get('entries') or []
    n_audit = sum(1 for e in audit if isinstance(e, dict)
                  and _subject_matches(e.get('actor'), who, email))
    if n_audit:
        add('audit_log.json', 'audit entry', f'{n_audit} entr(y/ies)',
            'hash-chained — retained as evidence, never rewritten', False)
    return found


def handle_privacy_subject():
    """GET /api/privacy/subject?who=<username-or-name>[&email=] — Article 15.

    Enumerates every record this instance holds naming the person, and says
    which are erasable and which are retained.
    """
    actor = A.require_admin_or_auditor_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    who = A._sanitize_str((qs.get('who') or [''])[0], 64).strip()
    email = A._sanitize_str((qs.get('email') or [''])[0], 254).strip()
    if not who and not email:
        A.respond(400, {'error': 'who (username or display name) or email is required'})
    records = _subject_scan(who, email)
    A.audit_log(actor, 'privacy_subject_report',
                detail=f'who={who or email} records={len(records)}')
    A.respond(200, {
        'subject': {'who': who, 'email': email},
        'records': records,
        'erasable': sum(1 for r in records if r['erasable']),
        'retained': sum(1 for r in records if not r['erasable']),
        'notes': [
            'The audit log is hash-chained. Entries naming this person are '
            'retained as evidence and are never rewritten — editing one would '
            'destroy the tamper-evidence that makes the log evidence at all.',
            'Ticket, comment and time-entry authorship is retained as a '
            'business record. Erasing an account does not remove it.',
            'Backups taken before an erasure still contain the data. Rotate or '
            're-take them if your retention policy requires it.',
        ],
    })


def handle_privacy_erase():
    """POST /api/privacy/erase {who, confirm} — Article 17, for what can go.

    Erases the account, its avatar, its sessions and its contact record. Says
    exactly what it did NOT touch and why, rather than reporting a clean sweep
    it did not perform.
    """
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    who = A._sanitize_str(str(body.get('who', '')), 64).strip()
    if not who:
        A.respond(400, {'error': 'who is required'})
    if who.lower() == str(actor or '').lower():
        A.respond(400, {'error': 'refusing to erase the account you are signed in as'})
    if str(body.get('confirm') or '') != who:
        A.respond(400, {'error': 'confirm must repeat the subject exactly'})
    email = A._sanitize_str(str(body.get('email', '')), 254).strip()
    before = _subject_scan(who, email)
    low = who.lower()
    erased = []

    users = A.load(A.USERS_FILE) or {}
    target = next((u for u in users if u.lower() == low), None)
    if target:
        # The same last-admin guard handle_user_delete has — an erasure request
        # is not a reason to lock everyone out of the instance.
        admins = [u for u, d in users.items()
                  if (d or {}).get('role', 'admin') == 'admin']
        if len(admins) <= 1 and (users[target] or {}).get('role', 'admin') == 'admin':
            A.respond(400, {'error': 'that is the last admin account — transfer '
                                     'the role first'})
        with A._LockedUpdate(A.USERS_FILE) as store:
            store.pop(target, None)
        erased.append('account')

    try:
        for f in (A.AVATARS_DIR.glob(f'{low}.*') if A.AVATARS_DIR else []):
            f.unlink()
            erased.append('avatar')
    except Exception as e:                                  # pragma: no cover
        A.sys.stderr.write(f'[remotepower] avatar unlink failed: {e}\n')

    try:
        with A._LockedUpdate(A.TOKENS_FILE) as store:
            gone = [k for k, t in list(store.items())
                    if isinstance(t, dict) and str(t.get('user', '')).lower() == low]
            for k in gone:
                store.pop(k, None)
        if gone:
            erased.append(f'{len(gone)} session(s)')
    except Exception as e:                                  # pragma: no cover
        A.sys.stderr.write(f'[remotepower] token purge failed: {e}\n')

    try:
        with A._LockedUpdate(A.CONTACTS_FILE) as store:
            gone = [cid for cid, c in list(store.items())
                    if isinstance(c, dict)
                    and any(_subject_matches(c.get(f), low, email.lower())
                            for f in _SUBJECT_TEXT_FIELDS)]
            for cid in gone:
                store.pop(cid, None)
        if gone:
            erased.append(f'{len(gone)} contact record(s)')
    except Exception as e:                                  # pragma: no cover
        A.sys.stderr.write(f'[remotepower] contact purge failed: {e}\n')

    retained = [r for r in before if not r['erasable']]
    # The erasure ITSELF is audit-logged, naming the subject — that record is
    # the evidence the request was honoured, and is the one entry a DPO will
    # ask for. Stated in the response so it is not a surprise later.
    A.audit_log(actor, 'privacy_erase',
                detail=f'subject={who} erased={",".join(erased) or "nothing"} '
                       f'retained={len(retained)}')
    A.respond(200, {
        'ok': True, 'subject': who,
        'erased': erased,
        'retained': retained,
        'notes': [
            'This erasure is itself recorded in the audit log, naming the '
            'subject — that entry is the evidence the request was honoured.',
            'Hash-chained audit entries, ticket/comment authorship and time '
            'entries are retained as business and evidential records.',
            'Backups taken before now still contain the data.',
        ],
    })
