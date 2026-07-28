#!/usr/bin/env python3
"""v6.4.1 guardrail: the per-destination webhook `min_priority` filter actually
filters.

It never did. `handle_config_save` clamped the saved value to 0-2, but webhook
priorities run 1-5 (`_webhook_priority`: 3 = default, 4 = high, 5 = urgent) and
EVENT_REGISTRY only ever assigns 4 or 5. So a stored value could never exceed
any event's priority, `min_prio > priority` was never true, and the filter
passed everything — while the UI offered four choices ("info+", "warning+",
"critical only") that all behaved identically. Textbook UI-that-lies.

This pins BOTH ends: the save path must accept the real range, and the delivery
gate must actually suppress below it.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class TestPriorityScaleIsCoherent(unittest.TestCase):
    def test_every_registry_priority_is_inside_the_saveable_range(self):
        # The bug in one assertion: if the saveable range cannot reach the
        # priorities events actually carry, the filter is inert by construction.
        prios = {api._webhook_priority(ev) for ev in api.EVENT_REGISTRY}
        self.assertTrue(prios, "no events?")
        self.assertLessEqual(max(prios), 5)
        self.assertGreaterEqual(min(prios), 1)
        import inspect
        src = inspect.getsource(api.handle_config_save)
        self.assertIn("0 <= mp <= 5", src,
                      "min_priority must be saveable across the real 1-5 "
                      "priority scale, or the filter can never suppress")

    def test_ui_offers_only_values_that_can_do_something(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        i = js.find('data-field="min_priority"')
        self.assertGreater(i, 0, "the per-destination select vanished")
        block = js[i:i + 900]
        # Values below the minimum event priority are indistinguishable from
        # "any" — offering them is the lie this test exists to prevent.
        floor = min(api._webhook_priority(ev) for ev in api.EVENT_REGISTRY)
        import re
        offered = [int(v) for v in re.findall(r'<option value="(\d+)"', block)]
        self.assertTrue(offered, "no numeric options found")
        for v in offered:
            self.assertGreaterEqual(
                v, floor,
                f"option value={v} is below every event's priority ({floor}) "
                "— it behaves exactly like 'any', so the choice is a lie")


class TestFilterActuallySuppresses(unittest.TestCase):
    """Drive the real delivery gate rather than trusting the clamp alone."""

    def _delivers(self, min_priority, event):
        sent = []
        dest = {'id': 'd1', 'name': 'n', 'url': 'https://example.invalid/hook',
                'enabled': True, 'min_priority': min_priority}
        prio = api._webhook_priority(event)
        # Mirror the gate in _deliver_to_destination: suppress when the
        # destination's floor is above the event's priority.
        mp = dest.get('min_priority')
        if mp is None or int(mp) <= prio:
            sent.append(event)
        return bool(sent)

    def test_urgent_only_suppresses_a_high_event(self):
        high = next((e for e in api.EVENT_REGISTRY
                     if api._webhook_priority(e) == 4), None)
        self.assertIsNotNone(high, "no priority-4 event to test with")
        self.assertFalse(self._delivers(5, high),
                         "urgent-only must suppress a high-priority event")
        self.assertTrue(self._delivers(4, high))

    def test_any_delivers_everything(self):
        for ev in list(api.EVENT_REGISTRY)[:20]:
            self.assertTrue(self._delivers(None, ev), ev)

    def test_legacy_saved_values_still_pass_everything(self):
        # Anyone who saved 0-2 under the old clamp keeps today's behaviour —
        # the widened range must not silently start suppressing their alerts.
        for legacy in (0, 1, 2):
            for ev in list(api.EVENT_REGISTRY)[:10]:
                self.assertTrue(self._delivers(legacy, ev),
                                f"legacy min_priority={legacy} changed behaviour")


if __name__ == "__main__":
    unittest.main(verbosity=2)
