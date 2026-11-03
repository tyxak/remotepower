"""RemotePower — One list of problems across Alerts, Needs attention and Checks (#56)

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


import time
import urllib.parse

import problems

A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ── handlers ─────────────────────────────────────────────────────────────────

# A check key -> the kind of the same problem: a Needs attention kind, or `alert:<event>` for a problem that has
# an alert and a check but no Needs attention item. Only the clear correspondences are listed: a wrong
# entry would join two things that are not one problem, while a missing one only leaves a check on a row of its
# own (`check:<key>`). tests/test_problems.py holds every key to a real check and every kind to a real kind.
# A key with a path after it (`disk:/var`, `script:12`) is looked up by what comes before the colon.
CHECK_FAMILY = {
    'reachability': 'offline',
    'cve': 'cve',
    'patches': 'patches',
    'reboot': 'reboot',
    'win_pending_reboot': 'reboot',
    'drift': 'drift',
    'exposure': 'new_port',
    'mounts': 'mount',
    'smart': 'hardware',
    'temperature': 'hardware',
    'cpu': 'cpu',
    'memory': 'memory',
    'swap': 'swap',
    'disk': 'disk',
    'script': 'custom_script_fail',
    'services': 'failed_units',
    # Problems that have a check and an alert but no Needs attention kind: the check joins the alerts of its event.
    'nic_errors': 'alert:nic_errors',
    'readonly_fs': 'alert:readonly_fs',
    'oom': 'alert:oom_detected',
    'clock': 'alert:clock_skew',
    'storage': 'alert:storage_degraded',
    'timers': 'alert:timer_failed',
    'mailq': 'alert:mailq_high',
}

# Kinds Needs attention builds from a metric alert's own state (cpu:, memory:, swap:, disk:), which have no row in
# the map of mutes because nothing else needed one.
METRIC_KINDS = frozenset(('cpu', 'memory', 'swap', 'disk', 'iowait', 'steal'))

DEFAULT_WINDOW_DAYS = 7


def _kind_of_event():
    """event -> the Needs attention kind of the problem it raises, from the map that decides which item a mute
    silences. An event in two kinds takes the first. Metric events are left out: their kind is in the alert."""
    out = {}
    for (kind, _severity), events in A._NA_MUTE_EVENTS.items():
        for ev in events:
            if ev not in problems.METRIC_EVENTS:
                out.setdefault(ev, kind)
    return out


def _failing_checks(allowed):
    """The failing checks of the hosts the caller may see, as the Checks page lists them: not the ones switched off
    on a host, and not the unmonitored hosts."""
    devices_all = A._load_ro(A.DEVICES_FILE) or {}
    cfg = A.load(A.CONFIG_FILE) or {}
    scripts = A._load_custom_scripts()
    rows = A._fleet_checks_rows(devices_all, cfg, scripts, A._fleet_checks_fp(cfg, scripts))
    out = []
    for host in rows:
        did = host.get('device_id')
        if did not in allowed or host.get('monitored') is False:
            continue
        for c in host.get('checks') or []:
            if not isinstance(c, dict) or c.get('enabled') is False or c.get('status') not in ('warning', 'critical'):
                continue
            key = str(c.get('key') or '')
            out.append({'device_id': did, 'device': host.get('name') or did, 'id': key.split(':', 1)[0], 'key': key,
                        'name': c.get('name') or key, 'status': c['status'], 'output': c.get('output')})
    return out


def _int_param(qs, name, default, lo, hi):
    try:
        return max(lo, min(hi, int(qs.get(name, [default])[0])))
    except (TypeError, ValueError, OverflowError):
        return default


def _fix_of_alert(a):
    """The Fix an alert offers, by the rule that tags the Alerts page's rows. That rule writes onto the alert it is
    given, so it gets a probe holding the four fields it reads and never the stored alert."""
    probe = {'resolved_at': a.get('resolved_at'), 'device_id': a.get('device_id'),
             'event': a.get('event'), 'payload': a.get('payload')}
    try:
        A._annotate_alert_mitigation([probe])
    except Exception:   # a stored row of a shape the rule does not read: a hint for a button never fails the list
        return None
    kind = probe.get('mitigation_kind')
    return (kind, probe.get('mitigation_target') or '') if kind else None


def _rows(days):
    """Every problem the caller may see, newest trouble first, and the time they were read at. The Alerts, Needs
    attention and Checks it joins are filtered to the caller's scope and tenant before they are joined."""
    devices_all = A._load_ro(A.DEVICES_FILE) or {}
    allowed = set(A._scope_filter_devices(devices_all).keys())
    now = int(time.time())
    alerts = A._filter_alerts_for_caller(A._readable_alerts((A._load_ro(A.ALERTS_FILE) or {}).get('alerts') or []))
    attention = (A._attention_for_caller() or {}).get('items') or []
    reports = {did: int(d.get('metrics_ts') or 0) for did, d in devices_all.items()
               if isinstance(d, dict) and did in allowed}
    kind_of_event = _kind_of_event()
    rows = problems.build(
        alerts=alerts, attention=attention, checks=_failing_checks(allowed),
        kind_of_event=kind_of_event, check_family=CHECK_FAMILY,
        shown_kinds=frozenset(kind_of_event.values()) | frozenset(CHECK_FAMILY.values()) | METRIC_KINDS,
        identity_fields=tuple(A._ALERT_IDENTITY_FIELDS), reports=reports, now=now, window_s=days * 86400,
        mute_map=A._NA_MUTE_EVENTS, fix_of_alert=_fix_of_alert)
    return rows, now


# The states the Alerts page marks an alert with, because the other views do not agree with it. A plain open alert
# that the host still reports is the normal case and gets nothing.
MARKED_STATES = frozenset((problems.HOST_CLEAR, problems.RESOLVED_BUT_FAILING, problems.WAITING))


def annotate_alerts_with_problem_state(page):
    """The Alerts page: an alert gets `problem_state` when the other views do not agree with it. An open alert that
    Needs attention and Checks no longer list is `host_clear`; an alert a person resolved is `resolved_but_failing`
    while the host still reports the problem and `waiting_for_report` until it has reported since. Only the alerts
    the problem's state is about are marked (`state_alert_ids`), not an older alert of the same host and kind. A
    failure here never fails the list: this is a decoration."""
    if not any(isinstance(a, dict) for a in page):
        return
    try:
        rows, _now = _rows(DEFAULT_WINDOW_DAYS)
    except Exception:
        return
    state_of = {}
    for r in rows:
        if r['state'] in MARKED_STATES:
            for aid in r['state_alert_ids']:
                state_of[aid] = r['state']
    for a in page:
        if isinstance(a, dict) and a.get('id') in state_of:
            a['problem_state'] = state_of[a['id']]


def _problem_index():
    """{(host, kind): row} for the problems that have a host, to tell the other pages what became of the alerts of
    the item or check they list."""
    rows, _now = _rows(DEFAULT_WINDOW_DAYS)
    return {(r['device_id'], r['family']): r for r in rows if r['device_id']}


def _problem_tag(row):
    """What the other pages say about a problem that has alerts: its state, how many are open and, when a person
    closed the alert it is about, who and when. None for a problem no alert ever raised."""
    if not row or not row['alert_total']:
        return None
    about = [e for e in row['alerts'] if e['id'] in set(row['state_alert_ids'])]
    hand = next((e for e in about if e['how'] == 'hand'), None)
    return {
        'state': row['state'],
        'alerts_open': len(row['open_ids']),
        'resolved_by': hand['resolved_by'] if hand else '',
        'resolved_at': hand['resolved_at'] if hand else 0,
    }


def annotate_attention_with_problems(payload):
    """GET /api/attention?problems=1: each item whose host and kind have alerts carries `problem` (see
    _problem_tag). A new payload, not an edit of the cached one."""
    if not isinstance(payload, dict) or not isinstance(payload.get('items'), list):
        return payload
    try:
        index = _problem_index()
    except Exception:
        return payload
    items = []
    for i in payload['items']:
        tag = _problem_tag(index.get((i.get('device_id') or '', i.get('kind') or ''))) if isinstance(i, dict) else None
        items.append(dict(i, problem=tag) if tag else i)
    return dict(payload, items=items)


def annotate_checks_with_problems(hosts):
    """GET /api/checks?problems=1: each failing check whose host and kind have alerts carries `problem`. The rows
    it is given are the shared cache of the Checks page, so it builds new ones and writes to none."""
    try:
        index = _problem_index()
    except Exception:
        return hosts
    out = []
    for h in hosts:
        did = h.get('device_id') if isinstance(h, dict) else None
        checks, changed = [], False
        for c in (h.get('checks') or []) if isinstance(h, dict) else []:
            tag = None
            if isinstance(c, dict) and c.get('status') in ('warning', 'critical') and c.get('enabled') is not False:
                cid = str(c.get('key') or '').split(':', 1)[0]
                tag = _problem_tag(index.get((did, CHECK_FAMILY.get(cid) or 'check:' + cid)))
            checks.append(dict(c, problem=tag) if tag else c)
            changed = changed or bool(tag)
        out.append(dict(h, checks=checks) if changed else h)
    return out


def handle_problems():
    """GET /api/problems?state=active|all|<state>&source=alert|attention|check&device_id=&q=&days=&limit=&offset=

    One list of what is wrong, each problem once, joined from Alerts, Needs attention and Checks (see problems.py).
    A problem is one kind of trouble on one host, with every alert, Needs attention item and failing check that
    belongs to it listed under it and a state that says where it stands: failing, host_clear (an alert is open and
    the host no longer reports it), resolved_but_failing (you resolved it and the host still reports it),
    waiting_for_report, resolved or recovered.

    `state` defaults to `active` (the first four). `days` is how far back a resolved alert still counts (default
    7, at most 30). `counts` covers everything the caller may see, before the filters, so the tabs of the page can
    show their numbers whatever is selected. Read-only, and filtered to the hosts the caller may see."""
    A.require_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    state = (qs.get('state', ['active'])[0] or 'active').lower()
    source = (qs.get('source', [''])[0] or '').lower()
    want_dev = A._sanitize_str(qs.get('device_id', [''])[0] or '', 64)
    q = (qs.get('q', [''])[0] or '').strip().lower()[:200]
    days = _int_param(qs, 'days', DEFAULT_WINDOW_DAYS, 1, 30)
    limit = _int_param(qs, 'limit', 200, 1, 1000)
    offset = _int_param(qs, 'offset', 0, 0, 10 ** 9)

    rows, now = _rows(days)
    shown = rows
    if state == 'active':
        shown = [r for r in shown if r['active']]
    elif state in problems.STATES:
        shown = [r for r in shown if r['state'] == state]
    if source in ('alert', 'attention', 'check'):
        shown = [r for r in shown if source in r['sources']]
    if want_dev:
        shown = [r for r in shown if r['device_id'] == want_dev]
    if q:
        shown = [r for r in shown if q in ' '.join(
            (r['device'], r['title'], r['family'], ' '.join(a['summary'] for a in r['attention']))).lower()]
    A.respond(200, {
        'problems': shown[offset:offset + limit],
        'total': len(shown),
        'offset': offset,
        'limit': limit,
        'days': days,
        'counts': problems.counts(rows),
        'generated_at': now,
    })


def handle_problems_history():
    """GET /api/problems/history?device_id=&family=[&detail=][&days=]

    Everything that happened to one problem, newest first: each alert of it was raised (with how often it came
    again), acknowledged and resolved, by whom and how, with the resolve note. A problem is a host and a kind (the
    `device_id` and `family` of a row of /api/problems); for a problem with no host, `detail` is the row's
    discriminator. `days` is how far back to read (default 90, at most 365).

    Read-only, and only the alerts the caller may see: a host outside the caller's scope or tenant answers with an
    empty history, the same as a host that has none, so the answer does not say whether it exists."""
    A.require_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    device_id = A._sanitize_str(qs.get('device_id', [''])[0] or '', 64)
    family = A._sanitize_str(qs.get('family', [''])[0] or '', 64)
    detail = A._sanitize_str(qs.get('detail', [''])[0] or '', 200)
    days = _int_param(qs, 'days', 90, 1, 365)
    alerts = A._filter_alerts_for_caller(A._readable_alerts((A._load_ro(A.ALERTS_FILE) or {}).get('alerts') or []))
    A.respond(200, problems.history(
        alerts=alerts, device_id=device_id, family=family, detail=detail, kind_of_event=_kind_of_event(),
        identity_fields=tuple(A._ALERT_IDENTITY_FIELDS), now=int(time.time()), window_s=days * 86400))
