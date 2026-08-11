"""Ratchet guardrail: new handler SUBSYSTEMS must land in a bound *_handlers.py
module, not be appended to the api.py monolith.

Why this exists: for years new handlers were tacked onto api.py because that was
the path of least resistance, and the file grew until a periodic "split api.py"
housekeeping task became necessary (the same treadmill the app.js → app-*.js page
split fought on the frontend). This test removes the treadmill by making the
monolith's inline-handler count a RATCHET that can only go DOWN:

  - Adding a new inline ``def handle_x(`` to api.py pushes the count over the
    ceiling and FAILS here — the nudge to scaffold a module instead
    (``tools/new-handler-module.py <name> "<desc>"``). A handler defined in a
    ``*_handlers.py`` bound module does NOT count (it isn't in api.py), so the
    module path is unblocked.
  - EXTRACTING a subsystem into a module lowers the real count; LOWER the
    ceiling to match in the same commit (that's the ratchet tightening).
  - The escape hatch is deliberate: if a handler genuinely belongs on the core
    spine (dispatch/config/device/heartbeat), you consciously raise CEILING by
    the exact number with a one-line justification here. Raising it should be
    rare and reviewed — the default answer to "where does this new subsystem go"
    is a module.

Companion: tests/apisrc.py auto-globs ``*_handlers.py`` so source-pin tests see
moved code unchanged; ``tools/new-handler-module.py`` scaffolds the boilerplate +
prints the api.py wiring block.
"""
import re
import unittest
from pathlib import Path

_API = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'

# The number of top-level ``def handle_*`` definitions inline in api.py.
# RATCHET: only ever lower this (when you extract a subsystem into a bound
# module). Do NOT raise it to make room for a new subsystem — scaffold a module
# with tools/new-handler-module.py instead. (Raise ONLY for a deliberate
# core-spine handler, with a justification comment.)
# 629→630 (v6.3.1): handle_alert_unresolve — core-spine alert lifecycle
# (sibling of the inline ack/unack/resolve family; the undo stack's inverse
# for a manual resolve).
# 630→633 (v6.4.0): handle_na_suppress_{list,add,remove} — class-level
# Needs-Attention suppression, justified at the time as "tightly coupled to
# _compute_attention … a bound module would just re-bind the whole attention
# internals".
# 633→627 (v6.4.1): that justification did not survive contact — carved into
# attention_handlers.py along with the ignored-items trio it sits next to. The
# coupling turned out to be exactly four helpers (_ignored_load/_ignored_keys/
# _na_suppress_rules/_na_item_suppressed), which moved with them; only the three
# CONSTANTS stay in api.py and are read via A., which is the normal pattern.
# _compute_attention keeps calling the moved helpers unchanged because api.py
# re-imports the names. Net −6, and the raise is paid back with interest.
# 627→628 (v6.4.2): handle_device_thermal_rollup was added inline on a
# "one handler, too coupled to the roll-up spine to carve" justification.
# 628→626 (v6.4.2): that justification did not survive contact either — the
# roll-up spine was 247 lines with 2-5 external references per symbol, so it
# carved cleanly into rollup_handlers.py and took BOTH readers with it
# (handle_device_metric_rollup as well as the thermal one), along with
# _rollup_merge / _rollup_prune / _rollup_read_shape / _raw_temp_samples and
# the two cadence sweeps. Only the tier/retention CONSTANTS stay in api.py and
# are read via A., which is the normal pattern. main()'s cadence, scheduler.py's
# CADENCE and the route table resolve unchanged because api.py re-imports the
# names. A debt-adding raise turned into a net −2.
# 626→627 (v6.4.2): handle_sessions_list — the fleet-wide active-session
# inventory for access review. Core spine, not a subsystem: it is the third
# member of the inline session family (handle_me_sessions /
# handle_me_session_revoke / handle_me_sessions_revoke_others) and reads the
# same TOKENS_FILE + auth helpers those do. Carving one read of the session
# store into a module would re-bind the whole auth spine to serve one endpoint.
# 627→625 (v6.4.2): the fleet-ops subsystem (bulk device attribute edit, group
# taxonomy rename/merge/delete, per-package patch approval, log-ring retention
# + export) landed in fleet_ops_handlers.py as a bound module — and it TOOK ITS
# TWO INLINE SIBLINGS WITH IT. handle_devices_bulk_delete /
# handle_devices_bulk_tags (+ _clean_tags) were the only two bulk device WRITES
# in api.py; the new handle_devices_bulk_attrs is the third member of that
# family, so leaving the first two inline would have split one subsystem across
# two files. Their route-table entries, the test suite's api.handle_devices_*
# calls and the source pins all resolve unchanged (api.py re-imports the names;
# tests/apisrc.py reads the COMBINED source). Nine new endpoints, net −2.
# 625→617 (v6.4.2): the REPORTING subsystem (fleet + per-site posture report,
# the HMAC-signed compliance evidence pack, the scheduled fleet-report cron and
# the saved custom report definitions) landed in reports_handlers.py. A textbook
# carve: eight handlers plus the pure logic they own (_build_fleet_report,
# _REPORT_SECTIONS/_filter_report_sections, _fleet_report_csv_bytes,
# _render_report_email, _clean_report_def/MAX_REPORT_DEFS) and the two cadence
# sweeps (_maybe_send_scheduled_report, _maybe_send_report_definitions). It only
# READS posture through helpers that stay on the spine and owns no state beyond
# report_schedule_state.json + two config keys, so nothing else moved. The route
# table, main()'s _safe(...) cadence and scheduler.py's CADENCE resolve unchanged
# (api.py re-imports the names); tests/apisrc.py reads the COMBINED source.
# api.py was AT the ceiling before this, which is why it went first.
# 617→605 (v6.4.3): PROXMOX VE guest lifecycle → proxmox_handlers.py. The
# ceiling had reached ZERO slack again, so the next core-spine handler would
# have failed the build. Proxmox was the cleanest remaining candidate on the
# measure that matters: its 13 functions (12 handlers + _refresh_snapshot_cache,
# which only handle_proxmox_list calls) reference just 20 distinct api globals,
# all of them ordinary bound-module fare — respond / load / CONFIG_FILE /
# require_admin_auth / audit_log / _read_valid — and none of the notify/event
# core the ratchet exists to protect. The pure protocol layer already lived in
# proxmox_client.py, so only the request-coupled half moved.
INLINE_HANDLER_CEILING = 605


class TestApiHandlerRatchet(unittest.TestCase):
    def _inline_handler_count(self) -> int:
        src = _API.read_text()
        return len(re.findall(r'^def handle_[A-Za-z0-9_]*\(', src, re.M))

    def test_inline_handler_count_does_not_exceed_ceiling(self):
        n = self._inline_handler_count()
        self.assertLessEqual(
            n, INLINE_HANDLER_CEILING,
            f'api.py has {n} inline handlers (ceiling {INLINE_HANDLER_CEILING}). '
            'A new handler SUBSYSTEM belongs in a bound *_handlers.py module, not '
            'inline in api.py — scaffold one with '
            'tools/new-handler-module.py <name> "<desc>". If a handler genuinely '
            'belongs on the core spine, raise INLINE_HANDLER_CEILING here by the '
            'exact count with a justification.')

    def test_ceiling_is_not_left_slack_after_an_extraction(self):
        # Keep the ratchet honest: the ceiling must track the real count within a
        # small buffer, so an extraction that lowers the count is matched by
        # lowering the ceiling (otherwise the ratchet silently loosens and stops
        # nudging). Buffer of 3 tolerates an in-progress core-spine addition.
        n = self._inline_handler_count()
        self.assertGreaterEqual(
            INLINE_HANDLER_CEILING, n,
            'ceiling below real count — raise not allowed without justification')
        self.assertLessEqual(
            INLINE_HANDLER_CEILING - n, 3,
            f'ceiling ({INLINE_HANDLER_CEILING}) is {INLINE_HANDLER_CEILING - n} '
            'above the real count — you extracted handlers but did not tighten '
            'the ratchet. Lower INLINE_HANDLER_CEILING to the new count.')


if __name__ == '__main__':
    unittest.main()
