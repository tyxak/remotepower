"""RemotePower — Detection-chain self-test — verify the alert detection→routing chain is intact fleet-wide (no silent monitoring gaps)

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


# ── Detection-chain self-test ────────────────────────────────────────────────
# "Silence isn't clearance." A green dashboard proves the monitoring found
# nothing — NOT that the monitoring WOULD find something. This diagnostic
# verifies the detection→routing→delivery chain is intact for every alertable
# event type, and surfaces the silent gaps that no build-time test can catch
# because they live in the operator's LIVE config:
#
#   - an alert kind whose channels are ALL toggled off (fires → reaches nobody);
#   - `notifications_test_mode` left on (the whole fleet's external delivery is
#     sandboxed — the single most dangerous silent gap, and easy to forget);
#   - the `webhook` column on for a kind but ZERO external destinations
#     configured (routes out to nowhere);
#   - a recover event whose resolve target isn't alertable (alerts sit open
#     forever) — the "sub_match not whitelisted" class, verified at runtime.
#
# Read-only and side-effect free: it inspects the registry + the live config,
# never fires anything. The existing Settings "send a test" button covers ACTIVE
# delivery; this proves the ROUTING is wired before you rely on it.

# The routing columns that actually reach a human/inbox (recent_activity is a
# passive audit feed — landing ONLY there is effectively silent for alerting).
_ACTIONABLE_COLUMNS = ('alerts', 'needs_attention', 'webhook')


def _external_delivery_configured(cfg):
    """True if at least one OUTBOUND destination is configured (so the `webhook`
    routing column can actually deliver somewhere off-box)."""
    if cfg.get('smtp_enabled') and (cfg.get('smtp_recipients') or cfg.get('smtp_from')):
        return True
    if cfg.get('webpush_enabled'):
        return True
    dests = cfg.get('webhook_urls') or []
    if any(isinstance(d, dict) and d.get('url') for d in dests):
        return True
    if cfg.get('webhook_url'):        # legacy single destination
        return True
    return False


def _detection_selftest():
    """Pure analysis. Returns the coverage report for every alertable event
    kind, the fleet-level delivery state, and an actionable issue list."""
    cfg = A._config_ro()
    routing = A._channel_routing()
    sandbox = bool(cfg.get('notifications_test_mode'))
    external = _external_delivery_configured(cfg)

    # group alertable events by kind (an event is alertable when its registry
    # entry declares a severity, or defers severity to the payload via an
    # explicit severity=None — both land in the inbox; a kind with NO alertable
    # event is NA/informational only and isn't a delivery gap).
    reg = A.EVENT_REGISTRY
    kind_events = {}
    for ev, spec in reg.items():
        if spec.get('phantom'):
            continue                  # aliases aren't operator-facing
        if 'severity' not in spec and not spec.get('resolves'):
            continue                  # NA-only / decoration event
        kind_events.setdefault(spec.get('kind') or '(none)', []).append(ev)

    label_of = {k: l for (k, l, _g) in A.CHANNEL_KIND_DEFS}
    kinds, issues = [], []
    for kind, events in sorted(kind_events.items()):
        slot = routing.get(kind)
        slot = slot if isinstance(slot, dict) else {}
        cols = {c: bool(slot.get(c, True)) for c in
                ('alerts', 'needs_attention', 'webhook', 'recent_activity')}
        reachable = any(cols[c] for c in _ACTIONABLE_COLUMNS)
        # Some kinds ship deliberately quiet (agentlifecycle = expected upgrade
        # churn, new_port/usb/github_issue = opt-in). A kind that is silent
        # because that's its SHIPPED DEFAULT is not a misconfiguration — only a
        # kind the operator silenced that normally ships LOUD is an actionable
        # gap. Compare the live slot against _kind_default to tell them apart.
        dslot = A._kind_default(kind)
        default_reachable = any(dslot.get(c, True) for c in _ACTIONABLE_COLUMNS)
        status, note = 'ok', ''
        if not reachable:
            if default_reachable:
                status = 'silent'
                note = ('every actionable channel (Alerts inbox, Needs Attention, '
                        'webhook) is off for this kind — it fires but reaches nobody')
                issues.append({'level': 'critical', 'kind': kind,
                               'message': f'{label_of.get(kind, kind)}: {note}'})
            else:
                status = 'silent_by_default'
                note = 'ships intentionally quiet (routes to Recent Activity only)'
        elif cols['webhook'] and not any(cols[c] for c in ('alerts', 'needs_attention')) \
                and not external:
            status = 'webhook_no_destination'
            note = ('routed to webhook only, but no external destination is '
                    'configured — nothing is delivered off-box')
            issues.append({'level': 'warning', 'kind': kind,
                           'message': f'{label_of.get(kind, kind)}: {note}'})
        kinds.append({
            'kind': kind, 'label': label_of.get(kind, kind),
            'event_count': len(events), 'routes': cols,
            'reachable': reachable, 'status': status, 'note': note,
        })

    # recover-event integrity: a resolves-target that isn't alertable means the
    # open alert can never be auto-closed (it sits open forever).
    for ev, spec in reg.items():
        for tgt in (spec.get('resolves') or ()):
            tspec = reg.get(tgt)
            if not tspec or ('severity' not in tspec and not tspec.get('resolves')):
                issues.append({'level': 'warning', 'kind': spec.get('kind') or '',
                               'message': f'recover event {ev!r} resolves {tgt!r}, '
                               'which is not alertable — its alerts can never auto-close'})

    if sandbox:
        issues.insert(0, {'level': 'critical', 'kind': '(global)',
                          'message': 'notifications_test_mode is ON — ALL external '
                          'delivery is sandboxed; no webhook/email/push is actually sent'})
    if not external:
        issues.append({'level': 'info', 'kind': '(global)',
                       'message': 'no external destination configured (webhook/email/'
                       'push) — alerts land only in the in-app inbox'})

    silent = sum(1 for k in kinds if k['status'] == 'silent')
    return {
        'kinds': kinds,
        'delivery': {'external_configured': external, 'sandbox_mode': sandbox},
        'summary': {
            'total_kinds': len(kinds),
            'silent': silent,
            'webhook_no_destination': sum(
                1 for k in kinds if k['status'] == 'webhook_no_destination'),
            'ok': sum(1 for k in kinds if k['status'] == 'ok'),
        },
        'issues': issues,
    }


def handle_detection_selftest():
    """GET /api/detection-selftest — verify the alert detection→routing→delivery
    chain is intact fleet-wide and surface silent monitoring gaps. Admin-only
    (it reflects the full notification config). Read-only; fires nothing."""
    A.require_admin_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
        return
    A.respond(200, _detection_selftest())
