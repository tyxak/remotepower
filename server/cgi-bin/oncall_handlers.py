"""RemotePower — on-call rotation + alert escalation.

An alert that nobody acknowledges should get louder, not sit silent. An
escalation policy is a list of tiers ({after_minutes}); a periodic tick
re-notifies the configured webhook destinations for any open, unacknowledged
alert that has aged past a tier it hasn't fired yet, naming the current on-call
person. The on-call schedule is a simple contact rotation (N days each), with
dated overrides + an anchored schedule. No new webhook event — escalation
re-fires the original alert's event through the existing channel fan-out.

A bound-module carve-out following the dmarc/netappliance pattern: api.py execs
a PRIVATE instance, binds its own ``globals()`` here (every api service reached
as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching
working), then re-imports the names back — INCLUDING the module-global
escalation-tick gate (_last_escalation_tick) + _ESCALATION_INTERVAL + the
_NoEscalationChange sentinel — so the home-page rollup caller of _oncall_now and
main()/scheduler's _escalation_tick_if_due cadence resolve unchanged. CONFIG_FILE
/ ALERTS_FILE + _send_webhook_to_url stay in api.py, read via A. The escalation
tick buffers its webhook sends and fires them AFTER the ALERTS_FILE lock releases
(the lock-nesting fix), through A._send_webhook_to_url.
"""
import sys
import time

_last_escalation_tick = [0.0]
_ESCALATION_INTERVAL = 60   # seconds


class _NoEscalationChange(Exception):
    """Sentinel to abort the _LockedUpdate write when nothing escalated."""


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


def _oncall_index(now, anchor, period_s, n):
    """Rotation index for `now` given the anchor (start) time and period. Before
    the anchor, the first person holds it (index 0)."""
    if now < anchor:
        return 0
    return int((now - anchor) // period_s) % n


def _oncall_at(cfg, now=None):
    """Resolve the on-call contact for `now`, honouring (in priority order):
      1. a dated OVERRIDE window (handoff / swap) that covers `now`;
      2. an anchored rotation SCHEDULE (who is on call THIS week — deterministic
         from an anchor date + rotation length, not wall-clock modulo);
      3. the legacy stateless modulo rotation (backwards compatible).
    Returns '' when on-call isn't configured/enabled."""
    oc = (cfg or {}).get('oncall') or {}
    if not oc.get('enabled'):
        return ''
    contacts = [c for c in (oc.get('contacts') or []) if c]
    now = int(now or time.time())

    # 1. Overrides win — a specific dated assignment.
    for ov in (oc.get('overrides') or []):
        if not isinstance(ov, dict):
            continue
        who = ov.get('contact')
        try:
            start = int(ov.get('start') or 0)
            end = int(ov.get('end') or 0)
        except (TypeError, ValueError):
            continue
        if who and start <= now < end:
            return who

    # 2. Anchored schedule.
    anchor = oc.get('anchor')
    if contacts and anchor:
        try:
            anchor = int(anchor)
            days = max(1, int(oc.get('rotation_days') or 7))
        except (TypeError, ValueError):
            anchor = None
        if anchor:
            return contacts[_oncall_index(now, anchor, days * 86400, len(contacts))]

    # 3. Legacy stateless modulo (unchanged).
    if not contacts:
        return ''
    try:
        days = max(1, int(oc.get('rotation_days') or 7))
    except (TypeError, ValueError):
        days = 7
    return contacts[(now // (days * 86400)) % len(contacts)]


def _oncall_upcoming(cfg, now=None, count=4):
    """The next `count` handoffs as [{start, contact}] from the anchored
    schedule (empty if no anchor/contacts). Overrides are listed separately by
    the handler; this is the base rotation timeline."""
    oc = (cfg or {}).get('oncall') or {}
    contacts = [c for c in (oc.get('contacts') or []) if c]
    anchor = oc.get('anchor')
    if not (oc.get('enabled') and contacts and anchor):
        return []
    try:
        anchor = int(anchor)
        days = max(1, int(oc.get('rotation_days') or 7))
    except (TypeError, ValueError):
        return []
    now = int(now or time.time())
    period = days * 86400
    # Start of the current rotation slot.
    slot = anchor if now < anchor else anchor + ((now - anchor) // period) * period
    out = []
    for k in range(count):
        start = slot + k * period
        idx = _oncall_index(start, anchor, period, len(contacts))
        out.append({'start': start, 'contact': contacts[idx]})
    return out


def _oncall_now(cfg, now=None):
    """Back-compat shim — the current on-call contact string. Delegates to the
    calendar-aware resolver (overrides → anchored schedule → legacy modulo)."""
    return _oncall_at(cfg, now)


def _escalation_tick(now=None):
    """Re-notify open, unacknowledged alerts that have aged past an escalation
    tier. Idempotent per (alert, tier) via the alert's `escalated_tiers` list.
    Best-effort; never raises into the caller."""
    now = int(now or time.time())
    try:
        cfg = A.load(A.CONFIG_FILE) or {}
        esc = cfg.get('escalation') or {}
        if not esc.get('enabled'):
            return
        tiers = sorted(
            [t for t in (esc.get('tiers') or []) if isinstance(t, dict)],
            key=lambda t: int(t.get('after_minutes') or 0))
        if not tiers:
            return
        sevs = esc.get('severities') or ['critical', 'high']
        oncall = _oncall_now(cfg, now)
        fired_any = False
        pending_sends = []   # (event, payload, msg) — fired AFTER the lock releases
        with A._LockedUpdate(A.ALERTS_FILE) as store:
            for a in store.get('alerts', []):
                if a.get('acknowledged_at') or a.get('resolved_at'):
                    continue
                if a.get('severity') not in sevs:
                    continue
                age_min = (now - int(a.get('ts') or now)) / 60.0
                done = set(a.get('escalated_tiers') or [])
                for i, tier in enumerate(tiers):
                    if i in done:
                        continue
                    try:
                        after = int(tier.get('after_minutes') or 0)
                    except (TypeError, ValueError):
                        after = 0
                    if age_min < after:
                        continue
                    msg = (f"ESCALATION tier {i + 1} — unacknowledged {int(age_min)}m: "
                           f"{a.get('title', a.get('event', 'alert'))}"
                           + (f" · on-call: {oncall}" if oncall else ""))
                    # v5.0.1 (lock-nesting fix): buffer the send; fire it AFTER
                    # the ALERTS_FILE lock releases. _send_webhook_to_url →
                    # _dlq_record opens WEBHOOK_DLQ_FILE's own _LockedUpdate; under
                    # SQLite a nested BEGIN IMMEDIATE errors and the failed-delivery
                    # DLQ row was silently dropped (un-retryable missed escalation).
                    pending_sends.append((a.get('event', 'alert_escalated'),
                                          dict(a.get('payload') or {}), msg,
                                          tier.get('target') or ''))   # v5.4.1 (G2)
                    done.add(i)
                    fired_any = True
                a['escalated_tiers'] = sorted(done)
            if not fired_any:
                # nothing changed — avoid an unnecessary write
                raise _NoEscalationChange()
    except _NoEscalationChange:
        pass
    except Exception as e:
        sys.stderr.write(f'[remotepower] escalation tick failed: {e}\n')
        return
    # Fire the buffered escalation webhooks OUTSIDE the ALERTS_FILE lock so a
    # delivery failure's DLQ write (its own _LockedUpdate) isn't nested. Empty
    # when nothing escalated.
    for _ev, _pl, _msg, _tgt in pending_sends:
        try:
            A._send_webhook_to_url(_ev, _pl, _msg, cfg,
                                   only_dest_ids=({_tgt} if _tgt else None))   # v5.4.1 (G2)
        except Exception:
            pass


def _escalation_tick_if_due():
    now = time.time()
    if now - _last_escalation_tick[0] < _ESCALATION_INTERVAL:
        return
    _last_escalation_tick[0] = now
    A._escalation_tick()


def handle_oncall():
    """GET /api/oncall — current on-call contact, the next handoffs, active/
    upcoming overrides, and the rotation + escalation cfg."""
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE) or {}
    now = int(time.time())
    oc = cfg.get('oncall') or {}
    A.respond(200, {
        'current':  _oncall_now(cfg, now),
        # v5.8.0 (B3.3): the next 4 rotation handoffs (empty unless an anchored
        # schedule is set) + any override windows still in effect / upcoming.
        'upcoming': _oncall_upcoming(cfg, now, count=4),
        'overrides': [o for o in (oc.get('overrides') or [])
                      if isinstance(o, dict) and (o.get('end') or 0) > now],
        'oncall': oc or {'enabled': False, 'contacts': [], 'rotation_days': 7},
        'escalation': cfg.get('escalation') or {'enabled': False, 'tiers': [], 'severities': ['critical', 'high']},
    })
