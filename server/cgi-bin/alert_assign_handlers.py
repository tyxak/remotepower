"""RemotePower — Assign an alert to a person, and tell them

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
def _assignee_may_see(target, rec, users, alert):
    """Whether this account could open this alert on its own. An alert that its assignee cannot see is a
    notice nobody can act on, and under tenancy it would also hand the alert's title to another tenant.

    The tests are the ones every path that has no signed-in caller makes (A._account_may_see): the tenant of the
    host, the role's device scope, and, for an alert that names no host, the organisation that runs the
    installation, with the hosts a business service's alert names added."""
    return A._account_may_see(target, users, alert.get('device_id'), alert.get('event'), alert.get('payload'))


def _notify_assignee(target, assigner, alert):
    """Tell the assignee, on the channels they set up under My Account, that an alert is theirs. Best effort:
    an assignment must not fail because a webhook is down. Nothing is sent to a person who assigns an alert
    to themselves, or to one with personal notifications switched off."""
    if target == assigner:
        return
    try:
        prefs = (A.load(A.USER_NOTIFY_FILE) or {}).get(target)
        if not isinstance(prefs, dict) or not prefs.get('enabled'):
            return
        cfg = A.load(A.CONFIG_FILE)
        title = 'Alert assigned to you'
        host = alert.get('device_name') or alert.get('device_id') or 'the fleet'
        message = f"{assigner} assigned you: {alert.get('title') or alert.get('event') or 'an alert'} ({host})"
        url = str(prefs.get('webhook_url') or '').strip()
        if url:
            dest = {'id': f'user:{target}', 'name': f'{target} (personal)', 'url': url,
                    'format': A._auto_detect_format(url), 'enabled': True}
            A._dispatch_one_webhook('alert_assigned', dest, {'alert_id': str(alert.get('id') or '')[:64],
                                                             'assigned_by': assigner[:64]},
                                    message, title, 3, allow_digest=False)
        email = str(prefs.get('email') or '').strip()
        if email and '@' in email and str(cfg.get('smtp_host') or '').strip():
            A.smtp_notifier.send_email(
                cfg, [email], title, message, html_body=A.smtp_notifier.brand_html(cfg, title, message),
                extra_headers={'Auto-Submitted': 'auto-generated'})
    except Exception as e:  # noqa: BLE001 — never let the notice break the assignment
        A.sys.stderr.write(f'[remotepower] alert assignment notice: {type(e).__name__}: {e}\n')


def handle_alert_assign(alert_id):
    """POST /api/alerts/<id>/assign — body {"user": "alice"} hands the alert to that account, {"user": ""} takes
    it back. The same people may do it as may acknowledge an alert (the viewers_can_ack_alerts switch), the
    assignee has to be an enabled account that can see the alert, and a resolved alert keeps whatever it had."""
    caller = A._check_alert_mutation_perm()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.AlertAssignRequest)
    # 7.5.0: a request that does not say who must not change the assignment. An empty body, a list, `null` or a misspelt key used to
    # take it back, by a viewer too. Taking it back is `{"user": ""}`, which the page sends.
    if not isinstance(body.get('user'), str):
        A.respond(400, {'error': 'user must be an account name, or an empty string to take the assignment back'})
    target = A._sanitize_str(body.get('user') or '', 64).strip()
    users = A.load(A.USERS_FILE) or {}
    rec = users.get(target) if target else None
    if target and (not isinstance(rec, dict) or rec.get('disabled') or not A._user_tenant_visible(target)):
        A.respond(404, {'error': 'User not found'})
    denied = None
    snapshot = None
    with A._LockedUpdate(A.ALERTS_FILE) as store:
        for a in store.get('alerts', []):
            if not isinstance(a, dict) or a.get('id') != alert_id:
                continue
            if not A._alert_mutable_by_caller(a):
                denied = (404, 'alert not found')
            elif a.get('resolved_at'):
                denied = (409, 'alert already resolved')
            elif target and not _assignee_may_see(target, rec, users, a):
                denied = (409, 'that user cannot see this alert')
            elif target:
                a['assigned_to'] = target
                a['assigned_by'] = caller
                a['assigned_at'] = int(A.time.time())
                snapshot = dict(a)
            else:
                for k in ('assigned_to', 'assigned_by', 'assigned_at'):
                    a.pop(k, None)
                snapshot = dict(a)
            break
        else:
            denied = (404, 'alert not found')
    if denied:
        A.respond(denied[0], {'error': denied[1]})
    if target:
        A.audit_log(caller, 'alert_assign', f'id={alert_id} to={target}')
        _notify_assignee(target, caller, snapshot)
    else:
        A.audit_log(caller, 'alert_unassign', f'id={alert_id}')
    A.respond(200, {'ok': True, 'assigned_to': target or None})
