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
METRIC_KINDS = frozenset(('cpu', 'memory', 'swap', 'disk'))

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
            out.append({'device_id': did, 'device': host.get('name') or did, 'id': key.split(':', 1)[0],
                        'name': c.get('name') or key, 'status': c['status'], 'output': c.get('output')})
    return out


def _int_param(qs, name, default, lo, hi):
    try:
        return max(lo, min(hi, int(qs.get(name, [default])[0])))
    except (TypeError, ValueError, OverflowError):
        return default


def _rows(days):
    """Every problem the caller may see, newest trouble first, and the time they were read at. The Alerts, Needs
    attention and Checks it joins are filtered to the caller's scope and tenant before they are joined."""
    devices_all = A._load_ro(A.DEVICES_FILE) or {}
    allowed = set(A._scope_filter_devices(devices_all).keys())
    now = int(time.time())
    alerts = A._filter_alerts_for_caller((A._load_ro(A.ALERTS_FILE) or {}).get('alerts') or [])
    attention = (A._attention_for_caller() or {}).get('items') or []
    reports = {did: int(d.get('metrics_ts') or 0) for did, d in devices_all.items()
               if isinstance(d, dict) and did in allowed}
    kind_of_event = _kind_of_event()
    rows = problems.build(
        alerts=alerts, attention=attention, checks=_failing_checks(allowed),
        kind_of_event=kind_of_event, check_family=CHECK_FAMILY,
        shown_kinds=frozenset(kind_of_event.values()) | frozenset(CHECK_FAMILY.values()) | METRIC_KINDS,
        identity_fields=tuple(A._ALERT_IDENTITY_FIELDS), reports=reports, now=now, window_s=days * 86400)
    return rows, now


def annotate_alerts_with_problem_state(page):
    """The Alerts page, resolved view: an alert a person resolved gets `still_failing` when the host still reports
    its problem (`resolved_but_failing`) or has not reported since (`waiting_for_report`), so "resolved by alice"
    does not read as "fixed". Nothing is built unless the page holds an alert resolved by hand, and a failure here
    never fails the list: this is a decoration."""
    wanted = [a for a in page if isinstance(a, dict) and problems.resolved_by_hand(a)]
    if not wanted:
        return
    try:
        rows, _now = _rows(DEFAULT_WINDOW_DAYS)
    except Exception:
        return
    state_of = {}
    for r in rows:
        if r['state'] in (problems.RESOLVED_BUT_FAILING, problems.WAITING):
            for aid in r['alert_ids']:
                state_of[aid] = r['state']
    for a in wanted:
        state = state_of.get(a.get('id'))
        if state:
            a['still_failing'] = state


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
