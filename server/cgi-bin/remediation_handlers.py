"""RemotePower — guarded, verified auto-remediation on top of automation rules (v6.3.1)

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

# ── tuning (storage keys live in api.py) ─────────────────────────────────────
_LEDGER_MAX          = 500     # attempts kept in the ledger
_VERIFY_INTERVAL_S   = 60      # between verify-sweep passes
_BLAST_WINDOW_S      = 3600    # window for the max-hosts cap

# Per-rule defaults (overridable per rule via _validate_rule):
_DEF_HOST_COOLDOWN_S = 3600    # same rule + same host: at most once an hour
_DEF_MAX_HOSTS_HOUR  = 3       # same rule: at most N distinct hosts per hour
_DEF_VERIFY_S        = 0       # 0 = verification off (legacy behaviour)
_DEF_DISABLE_AFTER   = 3       # consecutive verify-failures before auto-disable


def _rule_guard_params(rule):
    """The remediation-guard knobs with defaults — one place, so the guard,
    the validator and the UI agree."""
    def _num(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(rule.get(key, default))))
        except (TypeError, ValueError):
            return default
    return {
        'host_cooldown_seconds': _num('host_cooldown_seconds', _DEF_HOST_COOLDOWN_S, 0, 7 * 86400),
        'max_hosts_per_hour':    _num('max_hosts_per_hour', _DEF_MAX_HOSTS_HOUR, 1, 100),
        'verify_seconds':        _num('verify_seconds', _DEF_VERIFY_S, 0, 86400),
        'disable_after_failures': _num('disable_after_failures', _DEF_DISABLE_AFTER, 0, 20),
    }


def _remediation_guard_ok(rule, dev_id, now):
    """Blast-radius guards for an automation run_script action.

    Returns (ok, reason). Two independent checks over the attempt ledger:
      - host cooldown: the same rule doesn't re-fix the same host within its
        window (a flapping alert must not turn into a restart loop);
      - blast cap: the same rule touches at most N distinct hosts per hour
        (an event storm — bad deploy, network split — must not become a
        fleet-wide script run).
    Suppressed attempts don't count toward either (they queued nothing)."""
    g = A._rule_guard_params(rule)
    attempts = (A.load(A.REMEDIATIONS_FILE) or {}).get('attempts') or []
    rid = rule.get('id')
    recent = [a for a in attempts
              if a.get('rule_id') == rid and a.get('status') != 'suppressed']
    cd = g['host_cooldown_seconds']
    if cd and any(a.get('device_id') == dev_id and now - int(a.get('ts') or 0) < cd
                  for a in recent):
        return False, 'host_cooldown'
    hosts_in_window = {a.get('device_id') for a in recent
                       if now - int(a.get('ts') or 0) < _BLAST_WINDOW_S}
    if dev_id not in hosts_in_window and len(hosts_in_window) >= g['max_hosts_per_hour']:
        return False, 'blast_cap'
    return True, ''


def _record_remediation_attempt(rule, dev_id, event, script_id, status,
                                reason=''):
    """Append one attempt to the ledger. status: 'queued' (script dispatched,
    verification pending or off) | 'suppressed' (a guard stopped it).
    Returns the attempt id."""
    import secrets as _secrets
    now = int(time.time())
    g = A._rule_guard_params(rule)
    verify_at = (now + g['verify_seconds']) if (status == 'queued' and g['verify_seconds']) else None
    dev_name = ((A.load(A.DEVICES_FILE) or {}).get(dev_id) or {}).get('name', dev_id)
    att = {
        'id':          'rem-' + _secrets.token_hex(5),
        'ts':          now,
        'rule_id':     rule.get('id'),
        'rule_name':   str(rule.get('name') or 'Rule')[:80],
        'device_id':   dev_id,
        'device_name': str(dev_name)[:80],
        'event':       str(event)[:64],
        'script_id':   str(script_id)[:64],
        'status':      status if verify_at else ('done' if status == 'queued' else status),
        'reason':      str(reason)[:40],
        'verify_at':   verify_at,
    }
    with A._LockedUpdate(A.REMEDIATIONS_FILE) as store:
        attempts = store.setdefault('attempts', [])
        attempts.append(att)
        del attempts[:-_LEDGER_MAX]
    return att['id']


def run_remediation_verify_if_due():
    """Cadence sweep: close the loop on queued auto-remediations.

    For every ledger attempt whose verify window has expired: if an OPEN alert
    with the same (event, device) still exists, the fix did NOT work →
    status 'failed', fire `remediation_failed` (inbox + webhooks), bump the
    rule's consecutive-failure counter and auto-DISABLE the rule once it hits
    its threshold (a fix that keeps not working must stop running). If no such
    alert remains open → 'verified' and the counter resets. Fired from the
    normal cadence (NEVER from inside fire_webhook — no recursion)."""
    now = int(time.time())
    # v6.4.0 PERF: read-only gate — _load_ro shares the cached dict (no full
    # deepcopy of the ledger every request); the mutation below re-reads under
    # _LockedUpdate.
    store_ro = A._load_ro(A.REMEDIATIONS_FILE) or {}
    if now - int(store_ro.get('last_verify') or 0) < _VERIFY_INTERVAL_S:
        return
    due = [a for a in (store_ro.get('attempts') or [])
           if a.get('status') == 'queued' and a.get('verify_at')
           and now >= int(a['verify_at'])]
    with A._LockedUpdate(A.REMEDIATIONS_FILE) as store:
        store['last_verify'] = now
    if not due:
        return
    open_alerts = {(a.get('event'), a.get('device_id'))
                   for a in (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
                   if not a.get('resolved_at')}
    verdicts = {}
    fired_payloads = []
    rules_delta = {}   # rule_id -> 'fail' | 'ok'
    for att in due:
        # v6.3.1 (BUGFIX): only judge a fix by "did the alert clear?" for events
        # that HAVE an auto-recover path. For events whose alert stays open until
        # a human resolves it (oom_detected, log_alert, disk_full, brute_force,
        # …), "still open" is NOT evidence the fix failed — treating it as such
        # would false-fail and eventually AUTO-DISABLE a working rule. Those
        # attempts are marked 'unverifiable' and skip the failure accounting.
        if att.get('event') not in A._AUTO_RESOLVABLE_EVENTS:
            verdicts[att['id']] = 'unverifiable'
            continue
        failed = (att.get('event'), att.get('device_id')) in open_alerts
        verdicts[att['id']] = 'failed' if failed else 'verified'
        rules_delta[att.get('rule_id')] = 'fail' if failed else \
            rules_delta.get(att.get('rule_id'), 'ok')
        if failed:
            fired_payloads.append(att)
    # Apply verdicts to the ledger.
    with A._LockedUpdate(A.REMEDIATIONS_FILE) as store:
        for a in (store.get('attempts') or []):
            v = verdicts.get(a.get('id'))
            if v:
                a['status'] = v
                a['verified_at'] = now
    # Failure accounting + auto-disable on the rules themselves.
    disabled_rules = set()
    with A._LockedUpdate(A.RULES_FILE) as st:
        for r in (st.get('rules') or []):
            delta = rules_delta.get(r.get('id'))
            if delta is None:
                continue
            if delta == 'ok':
                r['consecutive_failures'] = 0
                continue
            g = A._rule_guard_params(r)
            n = int(r.get('consecutive_failures') or 0) + 1
            r['consecutive_failures'] = n
            if g['disable_after_failures'] and n >= g['disable_after_failures'] \
                    and r.get('enabled'):
                r['enabled'] = False
                disabled_rules.add(r.get('id'))
    # Fire AFTER every lock is released (fire_webhook auto-defers anyway, but
    # keep the collect-then-fire shape the codebase standardises on).
    for att in fired_payloads:
        A.fire_webhook('remediation_failed', {
            'device_id':   att.get('device_id'),
            'device_name': att.get('device_name'),
            'event':       att.get('event'),
            'rule_name':   att.get('rule_name'),
            'rule_id':     att.get('rule_id'),
            'script_id':   att.get('script_id'),
            'rule_disabled': att.get('rule_id') in disabled_rules,
        })


def handle_remediation_log():
    """GET /api/automation/remediations — the auto-remediation attempt ledger,
    newest first, restricted to devices the caller may see (RBAC scope +
    tenant), plus summary counts for the Automations page."""
    A.require_auth()
    visible = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    attempts = [a for a in ((A.load(A.REMEDIATIONS_FILE) or {}).get('attempts') or [])
                if a.get('device_id') in visible]
    attempts = sorted(attempts, key=lambda a: -int(a.get('ts') or 0))[:200]
    counts = {}
    for a in attempts:
        counts[a.get('status', '?')] = counts.get(a.get('status', '?'), 0) + 1
    A.respond(200, {'attempts': attempts, 'counts': counts})
