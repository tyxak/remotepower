"""Structural guardrail for the recurring tenant-isolation bug class.

Every request handler that reads a device id (`device_id`/`device_ids`) from the
request BODY must gate that id against the caller's tenant + role scope, or be
listed in EXEMPT with a reason. A new ungated body-device handler fails this test
— it cannot merge.

WHY THIS EXISTS. `handle_longpoll_exec` (POST /api/exec/wait) was a cross-tenant
RCE from v3.14.0 (when opt-in multi-tenancy shipped) until v6.2.3: it resolves
`device_id` from the body itself (not via the `_resolve_targets` chokepoint) and
sits OUTSIDE `/api/devices/<id>/…`, so `main()`'s pre-dispatch
`_enforce_device_scope` never covered it. A tenant admin (role scope None, but
tenant-confined) could queue an arbitrary command on another tenant's host. Four
prior "exhaustive" audits fixed the instances they found and generalised "class
closed"; none enumerated the full body-device-handler surface. This test does, so
the next sibling is a CI failure instead of an audit's lucky catch.

A handler is considered SAFE if it routes the body id through one of the canonical
scope helpers (each folds in tenant AND role scope, and is a no-op for an unscoped
single-tenant admin): `_scope_block_device`, `_resolve_targets`,
`_scope_filter_devices`. Anything else must be an explicit, reasoned EXEMPT entry.
"""
import ast
import re
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
# api.py + EVERY bound *_handlers.py module — auto-globbed so extracting a
# subsystem into a new module can never silently drop its handlers from this
# scope-gate enumeration (a hardcoded list did exactly that as modules were added).
HANDLER_FILES = ['api.py'] + sorted(p.name for p in CGI.glob('*_handlers.py'))

# Reads a device id (or a target set that contains device ids) from the body.
#
# THE KEY LIST IS THE POPULATION, and that is where this guard was weakest.
# It matched only `device_id`/`device_ids`, so nine handlers reading a device
# reference under a DIFFERENT body key were not in the enumeration at all --
# not failing, not EXEMPT, invisible. One of them (`assigned_devices` on a
# custom script) was a cross-tenant root RCE: the heartbeat hands every script
# assigned to a device to that device's agent, which runs the body as root.
#
# An EXEMPT list is visible and gets re-read. A population regex is read once,
# when the guard is written, and thereafter looks like an implementation
# detail -- so reviewing this file showed you the rule and the exemptions, and
# never the set they were applied to.
#
# Adding a key here is cheap; leaving one out is silent. When a new body field
# carries a device reference, add it.
_DEVICE_BODY_KEYS = (
    'device_ids?',          # the original pair
    'assigned_devices',     # custom scripts -- the agent RUNS these as root
    'endpoints',            # network-map tunnels
    'scope_device_id',      # inbound-webhook token pinning (attribution target)
    'affected_devices',     # tickets -- resolved to HOSTNAMES on read
    'linked_devices',       # KB articles
    'target_devices',       # not currently used; here so it cannot be missed
)
_READ = re.compile(
    r"""body\s*(\.get\(\s*['"](?:%s)['"]|\[\s*['"](?:%s)['"]\s*\])"""
    % ('|'.join(_DEVICE_BODY_KEYS), '|'.join(_DEVICE_BODY_KEYS))
    + r"""|_resolve_targets\s*\(""")

# The canonical, reviewed gating mechanisms.
_GATE = re.compile(
    r"(_scope_block_device\s*\(|_resolve_targets\s*\(|_scope_filter_devices\s*\()")

# Handlers that read a body device id but legitimately need no canonical gate.
# Adding an entry here is a REVIEWED decision — write the reason. Categories:
#   agent-self    — authenticates the posting AGENT by its device token, so the
#                   id is the caller's own device (or a not-yet-existing device
#                   being enrolled); a tenant boundary doesn't apply.
#   metadata      — the id is stored as free metadata (e.g. a ticket's affected
#                   host) and the device's data is never read/mutated/commanded.
#   gated-other   — it DOES tenant/scope-check, via a mechanism other than the
#                   three canonical helpers (name it).
EXEMPT = {
    # ---- agent-self: authenticates the posting AGENT by its device token
    #      (_device_token_ok), so the body id is the caller's OWN device (or a
    #      not-yet-existing device being enrolled). A tenant boundary can't apply.
    'handle_heartbeat':        'agent-self (device-token auth)',
    'handle_packages_submit':  'agent-self (device-token auth)',
    'handle_log_submit':       'agent-self (device-token auth)',
    'handle_scap_report':      'agent-self (device-token auth)',
    'handle_compose_fetch':    'agent-self (device-token auth; stack must match caller)',
    'handle_enroll_register':  'agent-self (one-time PIN / enroll token; re-enroll gated by device-token)',
    # ---- daemon shared-secret auth; id is only written to the audit log
    'handle_webterm_session_audit': 'daemon shared-secret (webterm_daemon_secret); id is audit metadata only',
    # ---- non-device / metadata: the id is stored as a free label and the
    #      device's data is never read / mutated / commanded through it.
    # v7.0.0: surfaced when the population regex was widened to include
    # `linked_devices`. Refuted on inspection: the ids are stored and
    # returned verbatim, never resolved to a name and never read back by
    # the frontend, so a caller learns only what they themselves typed.
    'handle_kb':             'metadata (KB article device links; stored verbatim, never resolved or read back)',
    'handle_kb_article':     'metadata (KB article device links; stored verbatim, never resolved or read back)',
    'handle_tickets':        'metadata (ticket affected-host label; now scope-filtered on write AND read)',
    # The reason here used to read "never reads/commands the device".
    # That stopped being true: handle_ticket_get resolves affected_devices
    # to HOSTNAMES, which was a working cross-tenant name oracle. Both the
    # write and the read are scope-filtered now; the exemption stands only
    # because the filtering is inline rather than via a canonical helper.
    'handle_ticket_update':  'metadata (ticket affected-host label; now scope-filtered on write AND read)',
    'handle_ignored_add':    'metadata (UI hide-list key; never reads/mutates/commands the device)',
    'handle_ignored_remove': 'metadata (UI hide-list key; never reads/mutates/commands the device)',
    # ---- gated by a custom mechanism (not the three canonical helpers): a
    #      per-(host,event) mute checks _tenant_visible + _device_in_scope and
    #      404-hides cross-scope existence (a 403 would confirm it).
    'handle_alert_mutes': 'gated-other (_tenant_visible + _device_in_scope, 404-hides)',
}


def _iter_handlers():
    for fn in HANDLER_FILES:
        src = (CGI / fn).read_text()
        tree = ast.parse(src)
        lines = src.split('\n')
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith('handle_'):
                seg = '\n'.join(lines[node.lineno - 1:node.end_lineno]).replace('A.', '')
                yield node.name, fn, seg


class TestBodyDeviceHandlersAreScopeGated(unittest.TestCase):
    def test_every_body_device_handler_is_gated_or_exempt(self):
        offenders = []
        for name, fn, seg in _iter_handlers():
            if not _READ.search(seg):
                continue
            if _GATE.search(seg):
                continue
            if name in EXEMPT:
                continue
            offenders.append(f'{name} [{fn}]')
        self.assertEqual(
            sorted(offenders), [],
            "Handler(s) read a device id from the body but neither route it "
            "through a canonical scope helper (_scope_block_device / "
            "_resolve_targets / _scope_filter_devices) nor appear in EXEMPT. "
            "A tenant admin could target another tenant's device. Add the gate, "
            "or add an EXEMPT entry with a reason:\n  " + "\n  ".join(sorted(offenders)))

    def test_exempt_entries_still_exist(self):
        """Keep EXEMPT from rotting: an entry for a deleted/renamed handler is a
        silent hole (a future handler could reuse the name)."""
        names = {n for n, _, _ in _iter_handlers()}
        stale = sorted(h for h in EXEMPT if h not in names)
        self.assertEqual(stale, [], f'EXEMPT names handlers that no longer exist: {stale}')

    def test_exempt_entries_have_a_reason(self):
        for h, reason in EXEMPT.items():
            self.assertTrue(reason and isinstance(reason, str),
                            f'EXEMPT[{h!r}] must carry a non-empty reason')


if __name__ == '__main__':
    unittest.main()
