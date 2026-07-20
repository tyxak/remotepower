"""RemotePower — helpdesk ticket subsystem (handlers + IMAP/SLA engines).

The PILOT of the bound-module decomposition pattern for api.py's
request-coupled subsystems (distinct from the pure-sibling pattern of
notify.py / checks.py / integrations.py, which cannot host handlers):

  - api.py execs a PRIVATE instance of this module and binds its own
    ``globals()`` here (see api.py's loader block for why), and every api
    service is accessed as ``A.<name>`` — a DYNAMIC attribute lookup, so
    the test suite's monkeypatching of api.respond / api.require_auth /
    api.method keeps working unchanged, and the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) execution models both resolve
    to the same live namespace.
  - api.py then from-imports every public and private name back into its
    own globals, so the route tables (globals()[name]) and every existing
    internal caller are untouched.
  - Constants (TICKETS_FILE, TICKET_STATUSES, MAX_TICKETS, ...) stay in
    api.py — this module reads them through A. as well.

Calls BETWEEN these functions also go through ``A.`` — in the monolith
every call resolved through the module dict, so tests monkeypatch e.g.
api._tickets_enabled and expect handlers to see it. Adding a ticket
feature: edit here; if it needs a new route, add the row in
api.py's _PATTERN_ROUTE_DEFS / _build_exact_routes as usual.
"""
import re
import secrets
import sys
import time
import urllib
from datetime import datetime, timedelta, timezone

# The api namespace, bound by api.py at import time (see bind()). A dict-backed
# proxy rather than the module object: under the runpy CGI shim the executing
# api namespace is NOT reliably in sys.modules, and the test suite exec's api
# via importlib without registering it — globals() is the ONE live view that
# exists identically under every execution model. Attribute lookups are
# dynamic, so tests monkeypatching api.respond/api.method are seen here
# (a module object's __dict__ IS the same dict).


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

def _tickets_enabled():
    # v6.0.0 made the ticket system standard and hard-coded this True, ignoring
    # the config key entirely. v6.1.2 restores a real switch — but as an OPT-OUT
    # (default ON, so nothing changes for anyone who leaves it alone), because a
    # minimal homelab shouldn't have to carry a helpdesk it never opens.
    # Single source of truth: api._MODULES / api._module_on.
    return A._module_on('tickets')


def _ticket_sla_policy(ttype=None):
    """Per-priority SLA response targets in hours (config override merged on
    defaults). docs/master-improvement-scoping-internal.md #81: an optional
    ttype ('incident'/'request'/'change') resolves against the
    ``ticket_sla_by_type`` config override first -- a type's rule need only
    set the priorities it wants to override; unset priorities fall through to
    the type-agnostic ``ticket_sla`` policy this always returns."""
    raw = (A.load(A.CONFIG_FILE) or {}).get('ticket_sla') or {}
    out = dict(A.TICKET_SLA_DEFAULT_HOURS)
    for k in (1, 2, 3, 4):
        try:
            v = float(raw.get(str(k), raw.get(k)))
            if v > 0:
                out[k] = v
        except (TypeError, ValueError):
            pass
    if ttype and ttype in A.TICKET_TYPES:
        by_type = (A.load(A.CONFIG_FILE) or {}).get('ticket_sla_by_type') or {}
        type_raw = by_type.get(ttype) or {}
        for k in (1, 2, 3, 4):
            try:
                v = float(type_raw.get(str(k), type_raw.get(k)))
                if v > 0:
                    out[k] = v
            except (TypeError, ValueError):
                pass
    return out


def _ticket_auto_route(ttype):
    """docs/master-improvement-scoping-internal.md #81: optional default
    group/assignee for newly-created tickets of a given type, config key
    ``ticket_auto_route`` = {ttype: {'group':.., 'assignee':..}}. Returns
    (group, assignee), either possibly ''. Only applied when the CREATE
    request didn't already specify its own group/assignee -- an explicit
    operator choice always wins."""
    if not ttype or ttype not in A.TICKET_TYPES:
        return '', ''
    rules = (A.load(A.CONFIG_FILE) or {}).get('ticket_auto_route') or {}
    rule = rules.get(ttype) or {}
    if not isinstance(rule, dict):
        return '', ''
    return (A._sanitize_str(str(rule.get('group', '')), 64),
            A._sanitize_str(str(rule.get('assignee', '')), 64))


def _business_hours_cfg():
    """W2-29: business-hours calendar for SLA clocks. {enabled, tz_offset_min,
    weekly: {'0'..'6': [[startMin,endMin],...]}, holidays: ['YYYY-MM-DD']}.
    weekday 0=Monday..6=Sunday. Absent/disabled → wall-clock SLA (unchanged)."""
    c = (A.load(A.CONFIG_FILE) or {}).get('ticket_business_hours')
    return c if isinstance(c, dict) and c.get('enabled') else None


def _business_deadline(start_ts, seconds, spec):
    """Pure: wall-clock instant by which `seconds` of BUSINESS time elapse from
    `start_ts`, walking forward through the calendar's open windows only (the
    clock 'pauses' overnight / weekends / holidays). Falls back to wall-clock if
    no windows are configured so a misconfigured calendar can't push a deadline
    to infinity."""
    try:
        offset = int(spec.get('tz_offset_min', 0) or 0)
    except (TypeError, ValueError):
        offset = 0
    tz = timezone(timedelta(minutes=offset))
    weekly = spec.get('weekly') or {}
    holidays = set(spec.get('holidays') or [])
    remaining = float(seconds)
    cur = datetime.fromtimestamp(int(start_ts), tz)
    for _ in range(3700):     # ~10 years of days — safety bound
        if remaining <= 0:
            return int(cur.timestamp())
        day_key = str(cur.weekday())
        if cur.strftime('%Y-%m-%d') not in holidays:
            midnight = cur.replace(hour=0, minute=0, second=0, microsecond=0)
            for win in (weekly.get(day_key) or []):
                try:
                    s_min, e_min = int(win[0]), int(win[1])
                except (TypeError, ValueError, IndexError):
                    continue
                if e_min <= s_min:
                    continue
                w_start = max(cur, midnight + timedelta(minutes=s_min))
                w_end = midnight + timedelta(minutes=e_min)
                if w_start >= w_end:
                    continue
                avail = (w_end - w_start).total_seconds()
                if avail >= remaining:
                    return int((w_start + timedelta(seconds=remaining)).timestamp())
                remaining -= avail
        cur = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(start_ts) + int(seconds)     # never fit → wall-clock fallback


def _ticket_sla(t, policy=None):
    """Return (due_ts, breached) for a ticket from its priority + created_at.
    W2-29: when a business-hours calendar is enabled, the SLA target counts only
    business time (clock pauses outside hours). #81: an explicit `policy` (a
    caller opting into a specific what-if priority->hours dict, e.g. tests) is
    honoured as-is, priority-only, with no type merge; the normal no-`policy`
    path resolves this ticket's own type-aware policy via
    `_ticket_sla_policy(t.get('type'))`."""
    policy = policy or A._ticket_sla_policy(t.get('type'))
    hours = policy.get(A._coerce_priority(t.get('priority', 4)), 72)
    created = int(t.get('created_at') or 0)
    bh = _business_hours_cfg()
    if bh:
        due = _business_deadline(created, int(hours * 3600), bh)
    else:
        due = created + int(hours * 3600)
    open_st = ('ongoing', 'pending_customer', 'pending_internal')
    breached = bool(t.get('status') in open_st and int(time.time()) > due)
    return due, breached


def _ticket_public(t):
    out = {k: t.get(k) for k in ('id', 'number', 'subject', 'type', 'status',
           'device_id', 'device_name', 'alertid', 'to_email', 'parent', 'priority',
           'assignee', 'group', 'affected_devices', 'new_reply', 'created_by',
           'created_at', 'updated_at', 'csat')}
    # W2-29: server-computed SLA due/breached so the list honours the
    # business-hours calendar (the client used to derive it wall-clock).
    due, breached = _ticket_sla(t)
    out['sla_due'] = due
    out['sla_breached'] = breached
    return out


def handle_tickets():
    """GET /api/tickets[?q=&status=&type=] list/search, or POST create."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() == 'GET':
        A.require_auth()
        tickets = (A.load(A.TICKETS_FILE) or {}).get('tickets') or []
        qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
        q = (qs.get('q') or [''])[0].lower().strip()
        st = (qs.get('status') or [''])[0]
        ty = (qs.get('type') or [''])[0]
        out = []
        for t in tickets:
            if st and t.get('status') != st:
                continue
            if ty and t.get('type') != ty:
                continue
            hay = (f"{t.get('number','')} {t.get('subject','')} {t.get('device_name','')} "
                   f"{t.get('group','')} {t.get('assignee','')}").lower()
            if q and q not in hay:
                continue
            out.append(A._ticket_public(t))
        out.sort(key=lambda x: x.get('updated_at', 0), reverse=True)
        A.respond(200, {'ok': True, 'tickets': out[:1000]})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # v5.8.0 (SECURITY): creating a ticket mutates shared helpdesk state, so it
    # must be gated on a write-capable role — bare require_auth() admitted the
    # read-only roles (viewer/mcp/auditor/finance). Same fix as ticket email/delete.
    actor = A.require_write_role('open a ticket')
    body = A.get_json_obj()
    subject = A._sanitize_str(str(body.get('subject', '')), 200).strip()
    ttype = str(body.get('type', 'incident')).strip().lower()
    if ttype not in A.TICKET_TYPES:
        ttype = 'incident'
    device_id = str(body.get('device_id', '')).strip()
    alert_internal = str(body.get('alert_id', '')).strip()
    now = int(time.time())
    devices = A.load(A.DEVICES_FILE)
    dev_name = (devices.get(device_id) or {}).get('name', '') if device_id else ''
    alertid = ''
    number = None
    if alert_internal:
        # one ticket per alert — return the existing one if present
        for t in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or []):
            if t.get('alert_id') == alert_internal:
                A.respond(200, {'ok': True, 'id': t['id'], 'number': t['number'], 'existing': True})
        al = next((a for a in ((A.load(A.ALERTS_FILE) or {}).get('alerts') or [])
                   if a.get('id') == alert_internal), None)
        # SEC (v6.2.3): don't let a cross-tenant alert_id be linked/auto-acked/
        # stamped — 404 to hide its existence (mirrors the alert mutation handlers).
        if al and not A._alert_tenant_visible(al):
            A.respond(404, {'error': 'alert not found'})
        if al:
            alertid = al.get('alertid', '')
            number = A._alert_seq_num(alertid)   # alert-derived number = alert seq
            ttype = 'incident'                 # alerts are always incidents
            if not subject:
                subject = al.get('title') or al.get('event') or 'Alert'
            if not device_id:
                device_id = al.get('device_id', '')
                dev_name = al.get('device_name', '')
    # priority: alert-derived tickets inherit the alert severity (Major=1 is manual-only);
    # standalone tickets default to Low(4) unless the operator picks one.
    if alert_internal and 'priority' not in body:
        priority = A._severity_to_priority(
            (next((a for a in ((A.load(A.ALERTS_FILE) or {}).get('alerts') or [])
                   if a.get('id') == alert_internal), {}) or {}).get('severity'))
    else:
        priority = A._coerce_priority(body.get('priority', 4))
    if not subject:
        A.respond(400, {'error': 'subject required'})
    # multiple affected devices (validated); primary device_id is included first
    affected = []
    for _d in (body.get('affected_devices') or [])[:50]:
        _d = str(_d).strip()
        if A._validate_id(_d) and _d in devices and _d not in affected:
            affected.append(_d)
    if device_id and device_id not in affected:
        affected.insert(0, device_id)
    # parent (master) ticket by #RP number
    parent_id = ''
    _pn = re.sub(r'\\D', '', str(body.get('parent_number', '')))
    if _pn:
        try:
            _pnum = int(_pn)
        except ValueError:
            _pnum = None
        if _pnum is not None:
            _pt = next((x for x in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or [])
                        if int(x.get('number') or 0) == _pnum), None)
            if _pt:
                parent_id = _pt['id']
    # #81: type-based auto-routing default group/assignee -- only fills in
    # what the operator didn't already specify; an explicit choice always wins.
    _route_group, _route_assignee = _ticket_auto_route(ttype)
    tid = 'tk_' + secrets.token_hex(5)
    # Seed the ticket with the FULL alert detail as an internal note — the alert
    # title (→ subject) only kept the first item + a "(+N more)" count; this
    # expands it from the live source so the ticket stands on its own.
    _seed_msgs = []
    if alert_internal and al:
        _detail = A._alert_ticket_detail(al, (devices or {}).get(device_id) if device_id else None)
        if _detail:
            _seed_msgs = [{'direction': 'note', 'author': 'alert', 'ts': now, 'body': _detail}]
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        tickets = store.setdefault('tickets', [])
        if len(tickets) >= A.MAX_TICKETS:
            A.respond(400, {'error': f'ticket limit reached (max {A.MAX_TICKETS})'})
        if number is None:
            seq = int(store.get('ticket_seq') or 0) + 1
            store['ticket_seq'] = seq
            number = A.TICKET_STANDALONE_BASE + seq
        tickets.append({
            'id': tid, 'number': number, 'subject': subject, 'type': ttype,
            'status': 'ongoing', 'device_id': device_id, 'device_name': dev_name,
            'alert_id': alert_internal, 'alertid': alertid,
            'to_email': A._sanitize_str(str(body.get('to_email', '')), 200),
            'affected_devices': affected, 'parent': parent_id, 'priority': priority,
            'assignee': A._sanitize_str(str(body.get('assignee') or _route_assignee or actor), 64),
            'group': A._sanitize_str(str(body.get('group') or _route_group), 64),
            'created_by': actor, 'created_at': now, 'updated_at': now,
            'messages': _seed_msgs,
        })
    # Link the ticket number back onto the source alert (collect-then-write, no nesting)
    if alert_internal:
        may_ack = A._may_touch_alert_state()   # strict-mode guard (no-op ack for viewers)
        try:
            with A._LockedUpdate(A.ALERTS_FILE) as astore:
                for a in (astore.get('alerts') or []):
                    if a.get('id') == alert_internal:
                        a['rp_ticket'] = number
                        a['rp_ticket_id'] = tid
                        # Opening a ticket = taking ownership -> auto-ack the alert
                        # (only if the caller is allowed to mutate alert state).
                        if may_ack and not a.get('resolved_at') and not a.get('acknowledged_at'):
                            a['acknowledged_by'] = actor
                            a['acknowledged_at'] = int(time.time())
                        break
        except Exception:
            pass
    A.audit_log(actor, 'ticket_create', f'#{number} type={ttype} dev={device_id}')
    A.fire_webhook('ticket_opened', {
        'number': number, 'ticket_id': tid, 'subject': subject,
        'priority': priority, 'type': ttype,
        'assignee': body.get('assignee') or _route_assignee or actor,
        'group': str(body.get('group') or _route_group)[:64], 'device_id': device_id,
        'device_name': dev_name, 'source': 'operator'})
    A.respond(200, {'ok': True, 'id': tid, 'number': number})


def handle_ticket_get(tid):
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    A.require_auth()
    all_t = (A.load(A.TICKETS_FILE) or {}).get('tickets') or []
    t = next((x for x in all_t if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'ticket not found'})
    # Opening the ticket clears the "new customer reply" badge (read receipt).
    # Only a write-capable operator clears it — a pure read-only role (viewer/
    # mcp/auditor/finance) peeking must not mutate the shared unread state.
    if t.get('new_reply') and A._caller_can_write():
        try:
            with A._LockedUpdate(A.TICKETS_FILE) as _st:
                _tk = next((x for x in (_st.get('tickets') or []) if x.get('id') == tid), None)
                if _tk:
                    _tk['new_reply'] = False
            t['new_reply'] = False
        except Exception:
            pass
    devs = A.load(A.DEVICES_FILE)
    resp = dict(t)
    resp['affected_devices_resolved'] = [
        {'id': d, 'name': (devs.get(d) or {}).get('name', d)} for d in (t.get('affected_devices') or [])]
    resp['parent_ticket'] = None
    if t.get('parent'):
        _p = next((x for x in all_t if x.get('id') == t['parent']), None)
        if _p:
            resp['parent_ticket'] = {'id': _p['id'], 'number': _p['number'], 'subject': _p.get('subject', '')}
    resp['children'] = [
        {'id': c['id'], 'number': c['number'], 'subject': c.get('subject', ''), 'status': c.get('status', '')}
        for c in all_t if c.get('parent') == t['id']]
    _due, _breached = A._ticket_sla(t)
    resp['sla_due'] = _due
    resp['sla_breached'] = _breached
    A.respond(200, {'ok': True, 'ticket': resp})


def _clean_sla_hours(raw, base_for_defaults=None):
    """Pure: coerce a {'1'..'4': hours} dict to validated floats (6 min..1yr),
    unset/invalid entries fall back to base_for_defaults (or the global
    TICKET_SLA_DEFAULT_HOURS)."""
    base = base_for_defaults or A.TICKET_SLA_DEFAULT_HOURS
    out = {}
    for k in (1, 2, 3, 4):
        try:
            v = float(raw.get(str(k), raw.get(k)))
        except (TypeError, ValueError):
            v = base[k]
        out[str(k)] = max(0.1, min(8760.0, v))   # 6 min .. 1 year
    return out


def handle_ticket_sla():
    """GET/POST /api/tickets/sla — per-priority SLA response targets (hours).

    docs/master-improvement-scoping-internal.md #81: also carries an OPTIONAL
    per-type override, `by_type: {'incident'|'request'|'change': {'1'..'4':
    hours}}`. A type's rule only needs to set the priorities it wants to
    diverge on -- unset priorities fall through to the flat policy above (see
    `_ticket_sla_policy`). Config keys: `ticket_sla` (flat, unchanged shape)
    + `ticket_sla_by_type` (new, additive)."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() == 'GET':
        A.require_auth()
        pol = A._ticket_sla_policy()
        by_type_raw = (A._config_ro().get('ticket_sla_by_type') or {})
        by_type = {}
        for ttype in A.TICKET_TYPES:
            rule = by_type_raw.get(ttype)
            if not isinstance(rule, dict):
                continue
            set_hours = {str(k): rule.get(str(k), rule.get(k)) for k in (1, 2, 3, 4)
                         if str(k) in rule or k in rule}
            if set_hours:
                by_type[ttype] = set_hours
        A.respond(200, {'ok': True, 'sla': {str(k): pol[k] for k in (1, 2, 3, 4)},
                        'by_type': by_type})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    body = A.get_json_obj()
    out = _clean_sla_hours(body)
    by_type_in = body.get('by_type')
    by_type_out = {}
    if isinstance(by_type_in, dict):
        for ttype, rule in by_type_in.items():
            if ttype not in A.TICKET_TYPES or not isinstance(rule, dict):
                continue
            # only PARTIAL overrides are meaningful here -- a priority the
            # caller didn't send stays unset (falls through to `out` at
            # resolve time), not silently pinned to the global default.
            cleaned = {}
            for k in (1, 2, 3, 4):
                if str(k) not in rule and k not in rule:
                    continue
                try:
                    v = float(rule.get(str(k), rule.get(k)))
                    cleaned[str(k)] = max(0.1, min(8760.0, v))
                except (TypeError, ValueError):
                    continue
            if cleaned:
                by_type_out[ttype] = cleaned
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['ticket_sla'] = out
        cfg['ticket_sla_by_type'] = by_type_out
    A.audit_log(actor, 'ticket_sla_save', detail=f'{out} by_type={by_type_out}')
    A.respond(200, {'ok': True, 'sla': out, 'by_type': by_type_out})


def handle_ticket_templates():
    """GET/POST /api/tickets/templates — canned replies (W1-26).

    Config key ``ticket_templates``: [{'name', 'body'}], ≤50 entries.
    GET is any authenticated user (operators insert them while composing);
    POST replaces the whole list, admin-only. The {ticket_id} / {customer} /
    {assignee} placeholders substitute CLIENT-side at insert time, so the
    stored body is plain text."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() == 'GET':
        A.require_auth()
        tpls = A._config_ro().get('ticket_templates') or []
        A.respond(200, {'ok': True, 'templates': tpls})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    body = A.get_json_obj()
    raw = body.get('templates')
    if not isinstance(raw, list):
        A.respond(400, {'error': 'templates must be a list'})
    tpls = []
    for t in raw[:50]:
        if not isinstance(t, dict):
            continue
        name = A._no_ctrl(A._sanitize_str(str(t.get('name', '')), 80)).strip()
        tbody = A._sanitize_str(str(t.get('body', '')), 4000)
        if name and tbody.strip():
            tpls.append({'name': name, 'body': tbody})
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['ticket_templates'] = tpls
    A.audit_log(actor, 'ticket_templates_save', detail=f'{len(tpls)} templates')
    A.respond(200, {'ok': True, 'templates': tpls})


def handle_ticket_schedules():
    """GET/POST /api/tickets/schedules — recurring scheduled tickets (W1-27).

    A schedule is {id, subject, body, type, priority, device_id?, assignee?,
    group?, cron, enabled}. The cadence sweep (run_ticket_schedules_if_due)
    opens a real ticket when the 5-field cron matches, deduped per (schedule,
    period). GET any authed user; POST replaces the whole list, admin-only."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() == 'GET':
        A.require_auth()
        scheds = (A.load(A.CONFIG_FILE) or {}).get('ticket_schedules') or []
        A.respond(200, {'ok': True, 'schedules': scheds})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    body = A.get_json_obj()
    raw = body.get('schedules')
    if not isinstance(raw, list):
        A.respond(400, {'error': 'schedules must be a list'})
    out = []
    for s in raw[:100]:
        if not isinstance(s, dict):
            continue
        subject = A._sanitize_str(str(s.get('subject', '')), 200).strip()
        cron = A._sanitize_str(str(s.get('cron', '')), 120).strip()
        if not subject or not cron:
            continue
        if not A._valid_cron(cron):
            A.respond(400, {'error': f'invalid cron in schedule "{subject[:40]}"'})
        ttype = str(s.get('type', 'request')).strip().lower()
        if ttype not in A.TICKET_TYPES:
            ttype = 'request'
        sched = {
            'id': A._sanitize_str(str(s.get('id') or ('ts_' + secrets.token_hex(4))), 32),
            'subject': subject, 'cron': cron, 'type': ttype,
            'priority': A._coerce_priority(s.get('priority', 4)),
            'body': A._sanitize_str(str(s.get('body', '')), 8000),
            'device_id': A._sanitize_str(str(s.get('device_id', '')), 64),
            'assignee': A._sanitize_str(str(s.get('assignee', '')), 64),
            'group': A._sanitize_str(str(s.get('group', '')), 64),
            'enabled': bool(s.get('enabled', True)),
        }
        out.append(sched)
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['ticket_schedules'] = out
    A.audit_log(actor, 'ticket_schedules_save', detail=f'{len(out)} schedules')
    A.respond(200, {'ok': True, 'schedules': out})


def _create_scheduled_ticket(sched):
    """Mint a ticket directly from a schedule (no request context). Returns the
    new ticket dict or None if the store is at capacity. Numbering + record
    shape mirror the standalone path in handle_tickets."""
    now = int(time.time())
    devices = A.load(A.DEVICES_FILE) or {}
    device_id = sched.get('device_id') or ''
    dev_name = (devices.get(device_id) or {}).get('name', '') if device_id else ''
    tid = 'tk_' + secrets.token_hex(5)
    rec = None
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        tickets = store.setdefault('tickets', [])
        if len(tickets) >= A.MAX_TICKETS:
            return None
        seq = int(store.get('ticket_seq') or 0) + 1
        store['ticket_seq'] = seq
        number = A.TICKET_STANDALONE_BASE + seq
        rec = {
            'id': tid, 'number': number, 'subject': sched.get('subject', ''),
            'type': sched.get('type', 'request'), 'status': 'ongoing',
            'device_id': device_id, 'device_name': dev_name,
            'alert_id': '', 'alertid': '', 'to_email': '',
            'affected_devices': [device_id] if device_id else [],
            'parent': '', 'priority': A._coerce_priority(sched.get('priority', 4)),
            'assignee': sched.get('assignee', ''), 'group': sched.get('group', ''),
            'created_by': 'schedule', 'created_at': now, 'updated_at': now,
            'scheduled_by': sched.get('id', ''),
            'messages': ([{'direction': 'note', 'author': 'schedule',
                           'ts': now, 'body': sched['body']}]
                         if sched.get('body') else []),
        }
        tickets.append(rec)
    return rec


def run_ticket_schedules_if_due():
    """W1-27: open recurring tickets when their cron matches. Cheap-when-not-due
    (_config_ro on the gate); dedups per (schedule id, cron-minute) so a schedule
    fires at most once per matching minute even across concurrent CGI processes.
    Ticket creation self-locks TICKETS_FILE; the dedup state has its own lock —
    neither nests the other."""
    if not A._tickets_enabled():
        return
    scheds = [s for s in (A._config_ro().get('ticket_schedules') or [])
              if isinstance(s, dict) and s.get('enabled', True) and s.get('cron')]
    if not scheds:
        return
    now = int(time.time())
    # period key = the matched minute, so a schedule fires once per minute max.
    minute_key = now // 60
    due = []
    for s in scheds:
        try:
            if A._cron_matches(s['cron'], now):
                due.append(s)
        except Exception:
            continue
    if not due:
        return
    # Dedup under the schedule-state lock BEFORE creating tickets (collect first).
    to_create = []
    with A._LockedUpdate(A.TICKET_SCHED_STATE_FILE) as st:
        fired = st.setdefault('fired', {})
        for s in due:
            if fired.get(s['id']) == minute_key:
                continue
            fired[s['id']] = minute_key
            to_create.append(s)
        # prune stale dedup markers (older than ~2 minutes) so the map stays small
        for sid in list(fired):
            if minute_key - int(fired.get(sid, 0)) > 2:
                fired.pop(sid, None)
    for s in to_create:
        try:
            _create_scheduled_ticket(s)
        except Exception as e:
            sys.stderr.write(f'[remotepower] scheduled ticket failed {s.get("id")}: {e}\n')


def handle_ticket_update(tid):
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() not in ('PATCH', 'POST'):
        A.respond(405, {'error': 'Method not allowed'})
    # v5.8.0 (SECURITY): updating a ticket (status/assignee/priority/messages/
    # re-parent) mutates shared state → write-capable role, not bare require_auth().
    actor = A.require_write_role('update a ticket')
    body = A.get_json_obj()
    now = int(time.time())
    ok = False
    resolve_alert_id = None     # set inside the lock; resolved AFTER it (no nested locks)
    resolve_ticket_no = None
    csat_target = None          # (to_email, ticket_snapshot) — CSAT sent AFTER the lock
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        t = next((x for x in (store.get('tickets') or []) if x.get('id') == tid), None)
        if t:
            ok = True
            if 'status' in body and str(body['status']).strip().lower() in A.TICKET_STATUSES:
                _prev_status = t.get('status')
                t['status'] = str(body['status']).strip().lower()
                # v5.6.x: fire ticket_resolved on the transition INTO
                # resolved/closed only (re-saving an already-resolved ticket
                # must not re-fire). Auto-deferred until the lock releases.
                if (t['status'] in ('resolved', 'closed')
                        and _prev_status not in ('resolved', 'closed')):
                    A.fire_webhook('ticket_resolved', {
                        'number': t.get('number'), 'ticket_id': t.get('id'),
                        'subject': t.get('subject', ''),
                        'priority': A._coerce_priority(t.get('priority', 4)),
                        'status': t['status'], 'resolved_by': actor,
                        'device_id': t.get('device_id', ''),
                        'device_name': t.get('device_name', '')})
                # Resolving/closing a ticket resolves its linked alert (captured
                # here, applied after this lock — ALERTS_FILE lock must not nest).
                # Suppressed for callers who may not mutate alert state (strict mode).
                if (t['status'] in ('resolved', 'closed') and t.get('alert_id')
                        and A._may_touch_alert_state()):
                    resolve_alert_id = t.get('alert_id')
                    resolve_ticket_no = t.get('number')
                # W1-31: one-time CSAT survey on the FIRST resolve, opt-in.
                if (t['status'] in ('resolved', 'closed')
                        and _prev_status not in ('resolved', 'closed')
                        and _csat_enabled() and not t.get('csat_sent')):
                    _to = (t.get('to_email') or ''
                           or _ticket_contact_email(t.get('device_id')))
                    if _to and '@' in _to:
                        t['csat_sent'] = True
                        csat_target = (_to, {'id': t.get('id'), 'number': t.get('number')})
            if 'type' in body and str(body['type']).strip().lower() in A.TICKET_TYPES:
                t['type'] = str(body['type']).strip().lower()
            if 'device_id' in body:
                did = str(body['device_id']).strip()
                t['device_id'] = did
                t['device_name'] = (A.load(A.DEVICES_FILE).get(did) or {}).get('name', '') if did else ''
            if 'to_email' in body:
                t['to_email'] = A._sanitize_str(str(body['to_email']), 200)
            if 'priority' in body:
                t['priority'] = A._coerce_priority(body['priority'], t.get('priority', 4))
            if 'assignee' in body:
                _asg = A._sanitize_str(str(body['assignee']), 64).strip()
                if _asg == '' or _asg in (A.load(A.USERS_FILE) or {}):
                    t['assignee'] = _asg
            if 'group' in body:
                t['group'] = A._sanitize_str(str(body['group']), 64)
            if 'affected_devices' in body and isinstance(body['affected_devices'], list):
                _devs = A.load(A.DEVICES_FILE)
                _aff = [str(x).strip() for x in body['affected_devices'][:50]
                        if A._validate_id(str(x).strip()) and str(x).strip() in _devs]
                t['affected_devices'] = _aff
                # keep the primary device_id/name in sync with the first affected device
                if _aff:
                    t['device_id'] = _aff[0]
                    t['device_name'] = (_devs.get(_aff[0]) or {}).get('name', '')
                else:
                    t['device_id'] = ''
                    t['device_name'] = ''
            if 'parent_number' in body:
                _pn = re.sub(r'\\D', '', str(body.get('parent_number', '')))
                if not _pn:
                    t['parent'] = ''
                else:
                    try:
                        _pnum = int(_pn)
                    except ValueError:
                        _pnum = None
                    if _pnum is not None:
                        _pt = next((x for x in (store.get('tickets') or [])
                                    if int(x.get('number') or 0) == _pnum), None)
                        if _pt and _pt.get('id') != tid:
                            t['parent'] = _pt['id']
            msg = A._sanitize_str(str(body.get('message', '')), 8000).strip()
            if msg:
                direction = str(body.get('direction', 'note'))
                if direction not in ('note', 'out', 'in'):
                    direction = 'note'
                t.setdefault('messages', []).append({
                    'ts': now, 'author': actor, 'body': msg,
                    'channel': 'web', 'direction': direction})
            t['updated_at'] = now
    if not ok:
        A.respond(404, {'error': 'ticket not found'})
    # Resolve the linked alert AFTER the tickets lock (collect-then-fire: a nested
    # ALERTS_FILE lock inside TICKETS_FILE would OperationalError under SQLite).
    alert_resolved = False
    if resolve_alert_id:
        try:
            with A._LockedUpdate(A.ALERTS_FILE) as astore:
                for a in (astore.get('alerts') or []):
                    if a.get('id') == resolve_alert_id and not a.get('resolved_at'):
                        a['resolved_by'] = actor
                        a['resolved_at'] = now
                        if not a.get('acknowledged_at'):
                            a['acknowledged_by'] = actor
                            a['acknowledged_at'] = now
                        a['resolve_note'] = f'Resolved via ticket #RP{int(resolve_ticket_no or 0):06d}'
                        alert_resolved = True
                        break
        except Exception:
            pass
    # W1-31: send the CSAT survey AFTER the tickets lock (SMTP + no nested lock).
    if csat_target:
        try:
            _base = A._request_base_url(A.os.environ)
            _send_ticket_csat(csat_target[0], csat_target[1], _base)
        except Exception as e:
            sys.stderr.write(f'[remotepower] CSAT dispatch failed: {e}\n')
    A.audit_log(actor, 'ticket_update', f'id={tid}')
    if alert_resolved:
        A.audit_log(actor, 'alert_resolve', f'id={resolve_alert_id} via ticket {tid}')
    A.respond(200, {'ok': True, 'alert_resolved': alert_resolved})


def handle_ticket_delete(tid):
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    actor = A.require_admin_auth()
    found = False
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        ts = store.get('tickets') or []
        kept = [x for x in ts if x.get('id') != tid]
        found = len(kept) != len(ts)
        store['tickets'] = kept
    if not found:
        A.respond(404, {'error': 'ticket not found'})
    A.audit_log(actor, 'ticket_delete', f'id={tid}')
    A.respond(200, {'ok': True})


def handle_ticket_hours(tid):
    """GET /api/tickets/{id}/hours — hours logged to a ticket; POST — add hours."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    t = next((x for x in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or [])
              if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'ticket not found'})
    if A.method() == 'GET':
        actor = A.require_auth()
        see_all = A._caller_billing_view()
        entries = (A.load(A.TIME_ENTRIES_FILE) or {}).get('entries') or []
        rows = [A._te_public(e) for e in entries
                if e.get('ticket_id') == tid and (see_all or e.get('user') == actor)]
        rows.sort(key=lambda x: x.get('created_at', 0), reverse=True)
        A.respond(200, {'ok': True, 'entries': rows,
                      'total_hours': round(sum(r['hours'] for r in rows), 2),
                      'billable_hours': round(sum(r['hours'] for r in rows if r['billable']), 2)})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # v5.8.0 (SECURITY): logging billable hours feeds invoices → write-capable
    # role, not bare require_auth() (billing-integrity: read-only roles must not
    # append time entries).
    actor = A.require_write_role('log ticket hours')
    body = A.get_json_obj()
    if 'billable' not in body:
        body['billable'] = True   # ticket work bills by default
    stored = A._te_store(A._te_validate_and_build(actor, body, ticket=t))
    A.audit_log(actor, 'time_entry_add', f"ticket #{t.get('number')} {stored['hours']}h")
    A.respond(200, {'ok': True, 'entry': A._te_public(stored)})


def handle_device_tickets(dev_id):
    """GET /api/devices/{id}/tickets — tickets attached to a device (open+closed)."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    A.require_auth()
    out = [A._ticket_public(t) for t in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or [])
           if t.get('device_id') == dev_id or dev_id in (t.get('affected_devices') or [])]
    out.sort(key=lambda x: x.get('updated_at', 0), reverse=True)
    A.respond(200, {'ok': True, 'tickets': out})


def handle_ticket_attachment(tid, aid):
    """GET /api/tickets/{id}/attachments/{aid}[?inline=1] — stream one attachment.
    Access is bound to the ticket: the caller must be authed AND the attachment id
    must appear on a message of THIS ticket (so ids aren't fetchable across
    tickets). Served as a download by default; ?inline=1 previews a small allowlist
    of safe types in-browser (always nosniff)."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    actor = A.require_auth()
    t = next((x for x in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or [])
              if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'ticket not found'})
    meta = None
    for m in (t.get('messages') or []):
        for a in (m.get('attachments') or []):
            if a.get('id') == aid:
                meta = a
                break
        if meta:
            break
    if not meta:
        A.respond(404, {'error': 'attachment not found'})
    path = A._attach_blob_path(aid)
    if not path or not path.exists():
        A.respond(404, {'error': 'attachment blob missing'})
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    ct = A._attach_safe_ct(meta.get('content_type'))
    inline = qs.get('inline', ['0'])[0] == '1' and ct in A.ATTACH_INLINE_TYPES
    fname = A._attach_safe_name(meta.get('filename'))
    try:
        data = path.read_bytes()
    except OSError:
        A.respond(404, {'error': 'attachment unreadable'})
    A.audit_log(actor, 'ticket_attachment', f'id={tid} aid={aid}')
    print("Status: 200 OK")
    print(f"Content-Type: {ct if inline else 'application/octet-stream'}")
    print(f'Content-Disposition: {"inline" if inline else "attachment"}; filename="{fname}"')
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_ticket_autoreply():
    """GET/POST /api/tickets/autoreply — the one-time acknowledgement auto-reply
    sent when a NEW ticket is auto-created from an inbound email. Loop-safe: it is
    stamped Auto-Submitted (so our own poller skips it), sent at most once per
    ticket (only on creation), and never sent to no-reply / mailer-daemon / bounce
    senders. Admin only."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() == 'GET':
        A.require_admin_auth()
        c = A._ticket_autoreply_cfg()
        A.respond(200, {'ok': True, 'enabled': bool(c.get('enabled')),
                      'subject': c.get('subject', ''),
                      'body': c.get('body', '') or A._TICKET_AUTOREPLY_DEFAULT})
    actor = A.require_admin_auth()
    body = A.get_json_obj()
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cfg['ticket_autoreply'] = {
            'enabled': bool(body.get('enabled')),
            'subject': A._no_ctrl(A._sanitize_str(body.get('subject', ''), 200)),
            'body': A._sanitize_str(str(body.get('body', '')), 4000),
        }
    A.audit_log(actor, 'ticket_autoreply_save', detail=f'enabled={bool(body.get("enabled"))}')
    A.respond(200, {'ok': True})


def handle_ticket_imap_get():
    A.require_admin_auth()
    c = A._ticket_imap_cfg()
    A.respond(200, {'ok': True, 'imap': {
        'enabled': bool(c.get('enabled')), 'host': c.get('host', ''), 'port': c.get('port', 993),
        'username': c.get('username', ''), 'folder': c.get('folder', 'INBOX'),
        'use_ssl': c.get('use_ssl', True) is not False,
        'verify_tls': c.get('verify_tls', True) is not False,
        'interval': c.get('interval', 300), 'password_set': bool(c.get('password')),
    }})


def handle_ticket_imap_save():
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    host = A._no_ctrl(A._sanitize_str(body.get('host', ''), 255)).strip()
    try:
        port = int(body.get('port') or 993)
    except (TypeError, ValueError):
        port = 993
    if not (1 <= port <= 65535):
        A.respond(400, {'error': 'port must be 1-65535'})
    try:
        interval = max(120, int(body.get('interval', 300) or 300))
    except (TypeError, ValueError):
        interval = 300
    with A._LockedUpdate(A.CONFIG_FILE) as cfg:
        cur = cfg.get('ticket_imap') if isinstance(cfg.get('ticket_imap'), dict) else {}
        new_pw = body.get('password')
        cfg['ticket_imap'] = {
            'enabled':  bool(body.get('enabled')),
            'host':     host, 'port': port,
            'username': A._no_ctrl(A._sanitize_str(body.get('username', ''), 255)),
            'folder':   A._no_ctrl(A._sanitize_str(body.get('folder', 'INBOX') or 'INBOX', 128)),
            'use_ssl':  body.get('use_ssl', True) is not False,
            'verify_tls': body.get('verify_tls', True) is not False,
            'interval': interval,
            'password': (str(new_pw)[:512] if new_pw else cur.get('password', '')),
        }
    A.audit_log(actor, 'ticket_imap_save', detail=f'host={host} enabled={bool(body.get("enabled"))}')
    A.respond(200, {'ok': True})


def handle_ticket_imap_test():
    """POST /api/tickets/imap/test — connect + login + select the folder using the
    posted form values (blank password falls back to the saved one). Read-only."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    saved = A._ticket_imap_cfg()
    host = (A._sanitize_str(str(body.get('host', saved.get('host', ''))), 255) or '').strip()
    if not host:
        A.respond(400, {'error': 'set the IMAP host first'})
    use_ssl = body.get('use_ssl', saved.get('use_ssl', True)) is not False
    verify_tls = body.get('verify_tls', saved.get('verify_tls', True)) is not False
    try:
        port = int(body.get('port') or saved.get('port') or (993 if use_ssl else 143))
    except (TypeError, ValueError):
        port = 993 if use_ssl else 143
    username = A._sanitize_str(str(body.get('username', saved.get('username', ''))), 255)
    password = body.get('password') or saved.get('password', '')
    folder = A._sanitize_str(str(body.get('folder', saved.get('folder', 'INBOX')) or 'INBOX'), 128)
    import imaplib
    import ssl as _ssl
    try:
        _ctx = _ssl.create_default_context()
        if not verify_tls:
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE
        M = (imaplib.IMAP4_SSL(host, port, ssl_context=_ctx, timeout=15)
             if use_ssl else imaplib.IMAP4(host, port, timeout=15))
        M.login(username, password)
        typ, _d = M.select(folder, readonly=True)
        try:
            M.logout()
        except Exception:
            pass
        if typ != 'OK':
            A.respond(200, {'ok': False, 'error': f'login ok but folder "{folder}" select failed'})
    except Exception as e:
        A.respond(200, {'ok': False, 'error': f'IMAP test failed: {str(e)[:200]}'})
    A.audit_log(actor, 'ticket_imap_test', f'host={host}')
    A.respond(200, {'ok': True, 'detail': f'login + select "{folder}" succeeded'})


def handle_ticket_send_email(tid):
    """POST /api/tickets/{id}/email {body, to?} — email the contact + log it.
    Loop-safe: stamps Auto-Submitted so the inbound poller skips our own mail."""
    if not A._tickets_enabled():
        A.respond(404, {'error': 'ticket system is disabled'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    # v5.7.0 (SECURITY): outbound SMTP relay must not be reachable by pure
    # read-only roles (viewer/mcp/auditor/finance). Bare require_auth() let any
    # token send arbitrary-body/attachment mail from the org mail server to any
    # address (phishing/exfil) and mutate the ticket. Gate on a write-capable
    # role, like every other state-mutating handler.
    actor = A.require_write_role('email a ticket contact')
    body = A.get_json_obj()
    text = A._sanitize_str(str(body.get('body', '')), 8000).strip()
    if not text:
        A.respond(400, {'error': 'message body required'})
    cfg = A.load(A.CONFIG_FILE) or {}
    if not cfg.get('smtp_host'):
        A.respond(400, {'error': 'SMTP is not configured (Settings -> Notifications)'})
    t = next((x for x in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or [])
              if x.get('id') == tid), None)
    if not t:
        A.respond(404, {'error': 'ticket not found'})
    to = (A._sanitize_str(str(body.get('to', '')), 200).strip()
          or t.get('to_email') or A._ticket_contact_email(t.get('device_id')))
    if '@' not in to:
        A.respond(400, {'error': 'no recipient — set a To: or add a contact email to the CMDB record'})
    # Per-user signature is stored as HTML (rich vCard-style block). The plain
    # part strips tags; an HTML alternative carries the rich signature.
    sig = (((A.load(A.USERS_FILE) or {}).get(actor) or {}).get('ui_prefs') or {}).get('signature', '')
    sig_text = re.sub(r'<[^>]+>', '', re.sub(r'<br\s*/?>', '\n', sig)).strip() if sig else ''
    out_body = text + (f"\n\n-- \n{sig_text}" if sig_text else '')
    html_body = None
    if sig:
        import html as _html_mod
        _esc_text = _html_mod.escape(text).replace('\n', '<br>')
        html_body = (f'<div style="font-family:sans-serif;font-size:14px">{_esc_text}</div>'
                     f'<br><div style="border-top:1px solid #ccc;margin-top:12px;padding-top:8px">{sig}</div>')
    # v5.4.1: optional outbound attachments — the client base64-encodes each file
    # and POSTs {filename, content_type, data_b64}. Decode, cap, store a blob, and
    # ride them along on the SMTP message; metadata is logged on the ticket message.
    send_atts = []   # (filename, content_type, bytes) for SMTP
    att_meta = []    # stored metadata for the message record
    raw_atts = body.get('attachments')
    if isinstance(raw_atts, list):
        import base64 as _b64
        for a in raw_atts[:A.MAX_ATTACH_PER_MSG]:
            if not isinstance(a, dict):
                continue
            try:
                blob = _b64.b64decode(str(a.get('data_b64') or ''), validate=True)
            except Exception:
                continue
            if not blob or len(blob) > A.MAX_ATTACH_BYTES:
                continue
            meta = A._ticket_store_attachment(blob, a.get('filename'), a.get('content_type'))
            if meta:
                send_atts.append((meta['filename'], meta['content_type'], blob))
                att_meta.append(meta)
    subject = f"#RP{int(t.get('number') or 0):06d} {t.get('subject', '')}"[:200]
    try:
        A.smtp_notifier.send_email(cfg, [to], subject, out_body, html_body=html_body,
            attachments=send_atts or None, extra_headers={
            'Auto-Submitted': 'auto-generated', 'X-RP-Ticket': str(t.get('number'))})
    except Exception as e:
        A.respond(200, {'ok': False, 'error': f'send failed: {str(e)[:200]}'})
    now = int(time.time())
    with A._LockedUpdate(A.TICKETS_FILE) as st:
        tk = next((x for x in (st.get('tickets') or []) if x.get('id') == tid), None)
        if tk:
            tk.setdefault('messages', []).append({'ts': now, 'author': actor, 'body': text,
                'channel': 'email', 'direction': 'out', 'to': to, 'attachments': att_meta})
            if not tk.get('to_email'):
                tk['to_email'] = to
            tk['updated_at'] = now
    A.audit_log(actor, 'ticket_email', f'id={tid} to={to}')
    A.respond(200, {'ok': True, 'to': to})


def _ticket_contact_email(device_id):
    """Best-effort recipient for a ticket: first email in the device's CMDB
    contacts, then its docs/documentation, then the device notes."""
    if not device_id:
        return ''
    rec = (A.load(A.CMDB_FILE) or {}).get(device_id) or {}
    for c in (rec.get('contacts') or []):
        vals = c.values() if isinstance(c, dict) else [c]
        for v in vals:
            m = A._TICKET_EMAIL_RE.search(str(v))
            if m:
                return m.group(0)
    blobs = [str(rec.get('documentation') or '')]
    for d in (rec.get('docs') or []):
        if isinstance(d, dict):
            blobs.append(str(d.get('body') or ''))
    dev = (A.load(A.DEVICES_FILE) or {}).get(device_id) or {}
    blobs.append(str(dev.get('notes') or ''))
    for b in blobs:
        m = A._TICKET_EMAIL_RE.search(b)
        if m:
            return m.group(0)
    return ''


def _ticket_autoreply_cfg():
    c = (A.load(A.CONFIG_FILE) or {}).get('ticket_autoreply')
    return c if isinstance(c, dict) else {}


def _send_ticket_autoreply(to_email, number, subject):
    """Best-effort: send the one-time acknowledgement to a new ticket's reporter.
    Caller has already confirmed the ticket was freshly auto-created. Returns
    quietly on any gate miss (disabled, no SMTP, automated sender, send error)."""
    c = A._ticket_autoreply_cfg()
    if not c.get('enabled'):
        return
    to = (to_email or '').strip()
    if '@' not in to or A._AUTOREPLY_SKIP_RE.search(to):
        return
    cfg = A.load(A.CONFIG_FILE) or {}
    if not cfg.get('smtp_host'):
        return
    ar_subject = A._no_ctrl(A._sanitize_str(c.get('subject', '') or f'Re: {subject}', 200))
    full_subject = f"#RP{int(number or 0):06d} {ar_subject}"[:200]
    ar_body = (c.get('body') or A._TICKET_AUTOREPLY_DEFAULT)
    try:
        A.smtp_notifier.send_email(cfg, [to], full_subject, ar_body, extra_headers={
            'Auto-Submitted': 'auto-replied', 'X-RP-Ticket': str(number)})
    except Exception as e:
        sys.stderr.write(f'[remotepower] ticket autoreply send failed: {e}\n')


_CSAT_SCORES = {'good': 5, 'ok': 3, 'bad': 1}
_CSAT_LABELS = {'good': 'Good', 'ok': 'Okay', 'bad': 'Bad'}


def _csat_enabled():
    return bool((A.load(A.CONFIG_FILE) or {}).get('ticket_csat_enabled'))


def _csat_sig(tid, rating):
    """HMAC tag binding a (ticket, rating) into an unguessable one-click link.
    Namespaced with a 'csat:' prefix so a tag can never be replayed as another
    signed artefact (export sig, etc.). Reuses the per-install export key."""
    msg = f'csat:{tid}:{rating}'.encode()
    return A.hmac.new(A._export_signing_key(), msg, A.hashlib.sha256).hexdigest()[:32]


def _send_ticket_csat(to_email, ticket, base_url):
    """Best-effort: email a one-click satisfaction survey when a ticket resolves.
    Loop-safe like the autoreply (skips automated senders). Returns quietly on
    any gate miss."""
    to = (to_email or '').strip()
    if '@' not in to or A._AUTOREPLY_SKIP_RE.search(to):
        return
    cfg = A.load(A.CONFIG_FILE) or {}
    if not cfg.get('smtp_host'):
        return
    tid = ticket.get('id')
    number = ticket.get('number')
    links = []
    for r in ('good', 'ok', 'bad'):
        url = (f'{base_url}/api/tickets/csat?t={urllib.parse.quote(str(tid))}'
               f'&r={r}&s={_csat_sig(tid, r)}')
        links.append(f'{_CSAT_LABELS[r]}: {url}')
    subject = f"#RP{int(number or 0):06d} How did we do?"[:200]
    body = ('Your ticket has been resolved. How was our support? '
            'Click the option that fits — it takes one click:\n\n'
            + '\n\n'.join(links)
            + '\n\nThank you.')
    try:
        A.smtp_notifier.send_email(cfg, [to], subject, body, extra_headers={
            'Auto-Submitted': 'auto-generated', 'X-RP-Ticket': str(number)},
            html_body=A.smtp_notifier.brand_html(cfg, subject, body))
    except Exception as e:
        sys.stderr.write(f'[remotepower] ticket CSAT send failed: {e}\n')


def _csat_page(title, message):
    """Emit a tiny self-contained HTML page for the public CSAT endpoint."""
    import html as _h
    doc = (
        '<!doctype html><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>' + _h.escape(title) + '</title>'
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;'
        'max-width:480px;margin:12vh auto;padding:24px;text-align:center;color:#16181d">'
        '<div style="font-size:20px;font-weight:700;margin-bottom:10px">'
        + _h.escape(title) + '</div>'
        '<div style="font-size:15px;line-height:1.6;color:#41474f">'
        + _h.escape(message) + '</div></div>'
    ).encode('utf-8')
    print("Status: 200 OK")
    print("Content-Type: text/html; charset=utf-8")
    print(f"Content-Length: {len(doc)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox;")
    print("X-Frame-Options: DENY")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(doc)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_ticket_csat():
    """GET /api/tickets/csat?t=&r=&s= — PUBLIC one-click satisfaction rating from
    a resolved-ticket email. No login; the HMAC signature is the capability.
    Single-use: the first valid click records the rating, later clicks just
    acknowledge it. Renders a tiny HTML page (never JSON — it's opened in a
    browser)."""
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    tid = (qs.get('t') or [''])[0]
    rating = (qs.get('r') or [''])[0]
    sig = (qs.get('s') or [''])[0]
    if rating not in _CSAT_SCORES or not tid:
        _csat_page('Invalid link', 'This survey link is not valid.')
    if not A.hmac.compare_digest(sig, _csat_sig(tid, rating)):
        _csat_page('Invalid link', 'This survey link is not valid or has expired.')
    now = int(time.time())
    already = False
    found = False
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        t = next((x for x in (store.get('tickets') or []) if x.get('id') == tid), None)
        if t:
            found = True
            if t.get('csat'):
                already = True
            else:
                t['csat'] = {'rating': rating, 'score': _CSAT_SCORES[rating], 'at': now}
    if not found:
        _csat_page('Not found', 'That ticket no longer exists.')
    if already:
        _csat_page('Already recorded', 'Thanks — we already have your feedback for this ticket.')
    _csat_page('Thank you!', f'Your rating ({_CSAT_LABELS[rating]}) has been recorded. We appreciate it.')


def _ticket_imap_cfg():
    c = (A.load(A.CONFIG_FILE) or {}).get('ticket_imap')
    return c if isinstance(c, dict) else {}


def _ticket_email_text(msg):
    """Plain-text body from an email.message.Message (first text/plain part)."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition') or ''):
                    return (part.get_payload(decode=True) or b'').decode('utf-8', 'replace').strip()
            return ''
        return (msg.get_payload(decode=True) or b'').decode('utf-8', 'replace').strip()
    except Exception:
        return ''


def _ticket_store_attachment(raw, filename, content_type):
    """Persist one attachment blob to TICKET_ATTACH_DIR under an opaque id and
    return its metadata dict, or None if it's empty / over the size cap. The blob
    filename on disk is the id only — never any caller-supplied string."""
    if not raw or len(raw) > A.MAX_ATTACH_BYTES:
        return None
    aid = secrets.token_hex(16)
    sub = A.TICKET_ATTACH_DIR / aid[:2]
    try:
        sub.mkdir(parents=True, exist_ok=True)
        with open(sub / aid, 'wb') as f:
            f.write(raw)
    except OSError as e:
        sys.stderr.write(f'[remotepower] attachment store failed: {e}\n')
        return None
    return {'id': aid, 'filename': A._attach_safe_name(filename),
            'content_type': A._attach_safe_ct(content_type), 'size': len(raw)}


def _fetch_ticket_replies():
    """Poll the dedicated ticket mailbox and append replies to their ticket by the
    #RP<number> subject token. LOOP-SAFE: skips auto-submitted / bulk / our own
    outbound (X-RP-Ticket) so nothing bounces back and forth."""
    import imaplib
    import email as _email
    import ssl as _ssl
    c = A._ticket_imap_cfg()
    host = (c.get('host') or '').strip()
    if not host:
        return
    try:
        port = int(c.get('port') or (993 if c.get('use_ssl', True) else 143))
    except (TypeError, ValueError):
        port = 993
    use_ssl = c.get('use_ssl', True) is not False
    verify_tls = c.get('verify_tls', True) is not False
    folder = (c.get('folder') or 'INBOX').strip() or 'INBOX'
    username = (c.get('username') or '').strip()
    password = c.get('password') or ''
    last_uid = int((A.load(A.TICKETS_FILE) or {}).get('imap_last_uid', 0) or 0)
    autoreply_jobs = []   # v5.4.1: (to_email, number, subject) for freshly auto-created tickets
    try:
        _ctx = _ssl.create_default_context()
        if not verify_tls:
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE
        M = (imaplib.IMAP4_SSL(host, port, ssl_context=_ctx, timeout=20)
             if use_ssl else imaplib.IMAP4(host, port, timeout=20))
        M.login(username, password)
        M.select(folder, readonly=False)
        typ, data = M.uid('search', None, 'ALL')
        uids = [int(x) for x in ((data[0].split() if data and data[0] else [])) if x.isdigit()]
        for uid in [u for u in sorted(uids) if u > last_uid][:200]:
            last_uid = max(last_uid, uid)
            typ, md = M.uid('fetch', str(uid), '(RFC822)')
            raw = next((it[1] for it in (md or []) if isinstance(it, tuple) and len(it) == 2), None)
            if not raw:
                continue
            msg = _email.message_from_bytes(raw)
            auto = (msg.get('Auto-Submitted') or '').lower()
            if auto and 'no' not in auto:
                continue
            if msg.get('X-RP-Ticket'):
                continue
            if (msg.get('Precedence') or '').lower() in ('bulk', 'auto_reply', 'list', 'junk'):
                continue
            mt = re.search(r'#RP0*(\d+)', str(msg.get('Subject') or ''))
            number = int(mt.group(1)) if mt else None
            frm = str(msg.get('From') or '')[:200]
            subj = (str(msg.get('Subject') or '').strip()[:200]) or '(no subject)'
            text = A._ticket_email_text(msg)[:8000]
            atts = A._email_attachments(msg)   # v5.4.1: store inbound attachments
            if not text and not atts:
                continue
            _fm = A._TICKET_EMAIL_RE.search(frm)
            frm_email = _fm.group(0) if _fm else ''
            now = int(time.time())
            with A._LockedUpdate(A.TICKETS_FILE) as st:
                tk = (next((x for x in (st.get('tickets') or []) if x.get('number') == number), None)
                      if number is not None else None)
                if tk:
                    tk.setdefault('messages', []).append({'ts': now, 'author': frm,
                        'body': text, 'channel': 'email', 'direction': 'in',
                        'attachments': atts})
                    if tk.get('status') == 'pending_customer':
                        tk['status'] = 'pending_internal'
                    tk['new_reply'] = True   # unread customer reply -> list badge
                    tk['updated_at'] = now
                else:
                    # No matching #RP ticket -> AUTO-CREATE a new ticket. Uses the
                    # standalone number band (TICKET_STANDALONE_BASE+seq) so it can
                    # never collide with an alert-derived ticket number. Loop-guard
                    # above already skipped auto-submitted/bulk/our own (X-RP-Ticket)
                    # mail, so we never create a ticket from our own outbound.
                    tickets = st.setdefault('tickets', [])
                    if len(tickets) < A.MAX_TICKETS:
                        seq = int(st.get('ticket_seq') or 0) + 1
                        st['ticket_seq'] = seq
                        tickets.append({
                            'id': 'tk_' + secrets.token_hex(5),
                            'number': A.TICKET_STANDALONE_BASE + seq,
                            'subject': re.sub(r'\s*#RP0*\d+\s*', ' ', subj).strip() or subj,
                            'type': 'request', 'status': 'ongoing',
                            'device_id': '', 'device_name': '',
                            'alert_id': '', 'alertid': '',
                            'to_email': frm_email, 'affected_devices': [], 'parent': '',
                            'priority': 4, 'assignee': '', 'group': '', 'new_reply': True,
                            'created_by': 'email', 'created_at': now, 'updated_at': now,
                            'messages': [{'ts': now, 'author': frm, 'body': text,
                                          'channel': 'email', 'direction': 'in',
                                          'attachments': atts}],
                        })
                        # v5.4.1: queue a one-time acknowledgement (sent post-lock).
                        autoreply_jobs.append((frm_email, A.TICKET_STANDALONE_BASE + seq,
                                               re.sub(r'\s*#RP0*\d+\s*', ' ', subj).strip() or subj))
                        # v5.6.x: lifecycle event (auto-deferred until the
                        # lock releases — recorders are nesting-safe now).
                        A.fire_webhook('ticket_opened', {
                            'number': A.TICKET_STANDALONE_BASE + seq,
                            'ticket_id': tickets[-1]['id'],
                            'subject': tickets[-1]['subject'], 'priority': 4,
                            'type': 'request', 'assignee': '', 'group': '',
                            'device_id': '', 'device_name': '',
                            'source': 'email'})
        try:
            M.logout()
        except Exception:
            pass
    except Exception as e:
        sys.stderr.write(f'[remotepower] ticket imap fetch failed: {e}\n')
    try:
        with A._LockedUpdate(A.TICKETS_FILE) as st:
            st['imap_last_uid'] = last_uid
            st['imap_last_fetch'] = int(time.time())
    except Exception:
        pass
    # v5.4.1: send the queued acknowledgement auto-replies AFTER the lock (SMTP is
    # I/O; never inside a _LockedUpdate). Loop-safe by construction — see
    # _send_ticket_autoreply (stamps Auto-Submitted, skips automated senders).
    for _to, _num, _subj in autoreply_jobs:
        A._send_ticket_autoreply(_to, _num, _subj)


def _open_ticket_device_ids():
    """device ids that currently have an OPEN (non-resolved/closed) ticket."""
    open_st = ('ongoing', 'pending_customer', 'pending_internal')
    ids = set()
    for t in ((A.load(A.TICKETS_FILE) or {}).get('tickets') or []):
        if t.get('status') in open_st:
            if t.get('device_id'):
                ids.add(t['device_id'])
            for d in (t.get('affected_devices') or []):
                ids.add(d)
    return sorted(ids)


def _dashboard_tickets(open_limit=5, acked_limit=5):
    """Open alerts (for quick-ack) + the most recently acknowledged alerts
    (with state + who) for the dashboard Tickets card. Scope-filtered."""
    al = A.load(A.ALERTS_FILE) or {}
    alerts = al.get('alerts') or []
    # v6.3.0 security fix: fold in BOTH role scope AND the tenant gate. The old
    # `if scope is not None` guard skipped filtering entirely for a tenant admin
    # (role scope None), leaking every tenant's alerts onto the dashboard card.
    # _filter_alerts_for_caller is the shared visibility filter (used by the
    # alerts list + summary) and gets tenant isolation right.
    alerts = A._filter_alerts_for_caller(alerts)

    def slim(a):
        return {'id': a.get('id'), 'alertid': a.get('alertid'),
                'title': a.get('title') or a.get('event') or '',
                'severity': a.get('severity') or 'medium',
                'device_name': a.get('device_name') or a.get('device_id') or '',
                'ts': a.get('ts'), 'acknowledged_by': a.get('acknowledged_by'),
                'acknowledged_at': a.get('acknowledged_at'),
                'resolved': bool(a.get('resolved_at'))}

    open_alerts = [a for a in alerts
                   if not a.get('acknowledged_at') and not a.get('resolved_at')]
    open_alerts.sort(key=lambda a: ({'critical': 0, 'high': 1, 'medium': 2,
                                     'low': 3}.get(a.get('severity'), 9),
                                    -(a.get('ts') or 0)))
    acked = [a for a in alerts if a.get('acknowledged_at')]
    acked.sort(key=lambda a: a.get('acknowledged_at') or 0, reverse=True)
    return {'open': [slim(a) for a in open_alerts[:open_limit]],
            'open_total': len(open_alerts),
            'acked': [slim(a) for a in acked[:acked_limit]]}


def run_ticket_imap_if_due():
    if not A._tickets_enabled():
        return
    c = A._ticket_imap_cfg()
    if not c.get('enabled') or not c.get('host'):
        return
    st = A.load(A.TICKETS_FILE) or {}
    try:
        interval = max(120, int(c.get('interval', 300) or 300))
    except (TypeError, ValueError):
        interval = 300
    if int(time.time()) - int(st.get('imap_last_fetch', 0) or 0) < interval:
        return
    A._fetch_ticket_replies()


def run_ticket_sla_if_due():
    """v5.3.0: edge-fire `ticket_sla_breached` once when an OPEN ticket passes its
    SLA target (priority-derived hours from creation). Cadence-gated; the
    `sla_breach_fired` flag de-dups so a breach pages once, and is cleared when the
    ticket closes. Collect-then-fire: webhooks go out AFTER the TICKETS_FILE lock."""
    if not A._tickets_enabled():
        return
    now = int(time.time())
    st0 = A.load(A.TICKETS_FILE) or {}
    try:
        if now - int(st0.get('sla_last_check', 0) or 0) < A.TICKET_SLA_CHECK_INTERVAL:
            return
    except (TypeError, ValueError):
        pass
    pending = []
    with A._LockedUpdate(A.TICKETS_FILE) as store:
        store['sla_last_check'] = now
        for t in (store.get('tickets') or []):
            # #81: no shared policy passed -- each ticket resolves its own
            # type-aware SLA (load() is request-cached, so this isn't a
            # repeated-I/O concern across the loop).
            _due, breached = A._ticket_sla(t)
            if breached and not t.get('sla_breach_fired'):
                t['sla_breach_fired'] = True
                pending.append({
                    'number': t.get('number'), 'ticket_id': t.get('id'),
                    'subject': t.get('subject', ''),
                    'priority': A._coerce_priority(t.get('priority', 4)),
                    'assignee': t.get('assignee', ''), 'group': t.get('group', ''),
                    'device_id': t.get('device_id', ''),
                    'device_name': t.get('device_name', ''), 'due': _due,
                })
            elif t.get('sla_breach_fired') and t.get('status') in ('resolved', 'closed'):
                t.pop('sla_breach_fired', None)   # allow a future re-open to re-page
    for pay in pending:
        A.fire_webhook('ticket_sla_breached', pay)
