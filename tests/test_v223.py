#!/usr/bin/env python3
"""
Tests for v2.2.3 — Home dashboard activity filter.

The webhook log carries SMTP-test and webhook-test entries (operator
diagnostics) alongside real fleet events. In 2.2.2 the Home dashboard
showed everything, drowning real events under a wall of repeated
"test (email) 1 recipient(s): smtp_host is empty" rows. v2.2.3 filters
the activity feed to canonical fleet events only.

This is a contract test on the JS source — verifies the filter list
matches the server-side WEBHOOK_EVENTS tuple and that 'test' is NOT in
the JS allowlist. If a new fleet event is added to the server tuple,
the JS allowlist needs the same addition; otherwise that event will
silently disappear from the dashboard.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v223", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestActivityFilter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()

    def _extract_fleet_events_set(self):
        """Pull the FLEET_EVENTS Set literal out of app.js so we can
        compare it against the server's WEBHOOK_EVENT_NAMES."""
        marker = 'const FLEET_EVENTS = new Set(['
        start = self.js.find(marker)
        self.assertGreater(start, 0, "FLEET_EVENTS Set not found in app.js")
        end = self.js.find(']);', start)
        body = self.js[start + len(marker):end]
        # Extract quoted strings — order doesn't matter for the comparison
        import re
        return set(re.findall(r"'([^']+)'", body))

    def test_filter_matches_server_canonical_events(self):
        """The dashboard's allowlist must contain every canonical
        WEBHOOK_EVENTS entry. If a future commit adds an event to the
        server tuple without updating the JS, this test fails — the
        event would silently disappear from the dashboard."""
        js_set     = self._extract_fleet_events_set()
        server_set = set(api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(js_set, server_set,
                         f"FLEET_EVENTS in app.js diverged from server\n"
                         f"  In server, missing in JS: {server_set - js_set}\n"
                         f"  In JS, missing in server: {js_set - server_set}")

    def test_test_event_excluded(self):
        """The 'test' event is what operator-triggered SMTP / webhook
        tests are logged as. It must NOT be in the activity allowlist —
        otherwise the dashboard fills up with test noise."""
        js_set = self._extract_fleet_events_set()
        self.assertNotIn('test', js_set,
                         "'test' should not be in FLEET_EVENTS — it's "
                         "operator test noise, not a fleet event")
        # And explicitly: 'test' is NOT in the canonical server list
        # either, so this is a stable invariant.
        self.assertNotIn('test', api.WEBHOOK_EVENT_NAMES)

    def test_filter_applied_before_slice(self):
        """Critical detail: slice the filtered list, not the raw one.
        Otherwise a wall of test entries shoves real events off the
        first-8 window. Verify the code reads filter().slice(), not
        slice().filter()."""
        # Find the activity function
        func_start = self.js.find('function _renderHomeActivity')
        self.assertGreater(func_start, 0)
        # Look for the filter + slice ordering in the next chunk.
        # v2.4.8: widened — the de-dup block lengthened the function.
        # v3.4.2: widened again — added image/health events to FLEET_EVENTS.
        # v3.12.0: widened again — added db_integrity_failed to FLEET_EVENTS.
        # v3.14.0: widened again — added process_alert/process_recovered + secret_exposed.
        # v4.7.0: widened again — added integration_down/integration_recovered.
        # v5.0.0: widened 4600→4800 — added vault_break_glass.
        # v5.1.0: widened 4800→5200 — added fail2ban_ban + av_infected.
        chunk = self.js[func_start:func_start + 5200]
        self.assertIn('.filter(', chunk)
        self.assertIn('.slice(', chunk)
        filter_pos = chunk.find('.filter(')
        slice_pos  = chunk.find('.slice(', filter_pos)
        # slice happens AFTER filter in source order
        self.assertGreater(slice_pos, filter_pos,
                           "filter() must run before slice() — otherwise "
                           "operator-test noise can crowd out real fleet "
                           "events from the first 8 entries")


if __name__ == '__main__':
    unittest.main(verbosity=2)
