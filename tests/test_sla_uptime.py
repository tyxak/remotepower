"""
SLA / uptime correctness:

  * pre-data time (before RemotePower had any record for a device — e.g. before
    enrollment) is reported as UNKNOWN, never as downtime, so a brand-new
    deployment is not shown as "N days down".
  * one-shot maintenance windows are excluded from both downtime and the covered
    window, so planned maintenance never burns the SLA.
  * SLA targets resolve most-specific-first: device → tag → group → default.

Pure stdlib unittest (runs under `python -m unittest discover` and pytest).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

WS, NOW = 1000, 2000   # window [1000, 2000] → 1000s wide


class TestUptimePct(unittest.TestCase):
    def test_no_data_is_unknown(self):
        pct, down, covered = api._uptime_pct([], WS, NOW)
        self.assertFalse(covered)
        self.assertIsNone(pct)

    def test_pre_enrollment_prefix_not_downtime(self):
        # Device first seen mid-window (online), nothing before → the prefix is
        # unknown, not down. Old bug reported ~50%; correct answer is 100%.
        events = [{"ts": 1500, "online": True}]
        pct, down, covered = api._uptime_pct(events, WS, NOW)
        self.assertTrue(covered)
        self.assertEqual(pct, 100.0)
        self.assertEqual(down, 0)

    def test_real_downtime_counted(self):
        events = [{"ts": 900, "online": True},     # known-up before window
                  {"ts": 1400, "online": False},
                  {"ts": 1600, "online": True}]
        pct, down, covered = api._uptime_pct(events, WS, NOW)
        self.assertTrue(covered)
        self.assertEqual(down, 200)                # 1400→1600 down
        self.assertEqual(pct, 80.0)                # 800/1000

    def test_maintenance_window_excluded(self):
        events = [{"ts": 900, "online": True},
                  {"ts": 1400, "online": False},
                  {"ts": 1600, "online": True}]
        # The whole outage falls inside a maintenance window → SLA not punished.
        pct, down, covered = api._uptime_pct(events, WS, NOW,
                                             maint_intervals=[(1400, 1600)])
        self.assertEqual(down, 0)
        self.assertEqual(pct, 100.0)

    def test_partial_maintenance_overlap(self):
        events = [{"ts": 900, "online": True},
                  {"ts": 1400, "online": False},
                  {"ts": 1800, "online": True}]   # 400s down
        # Maintenance covers half the outage (1400→1600); 200s counts.
        pct, down, covered = api._uptime_pct(events, WS, NOW,
                                             maint_intervals=[(1400, 1600)])
        self.assertEqual(down, 200)
        # covered window 1000s minus 200s maintenance = 800s effective
        self.assertEqual(pct, round(100.0 * (800 - 200) / 800, 3))


class TestSlaTargetResolution(unittest.TestCase):
    TARGETS = {"default": 99.0, "groups": {"g": 98.0},
               "tags": {"t": 97.0}, "devices": {"d1": 96.0}}

    def test_device_wins(self):
        dev = {"group": "g", "tags": ["t"]}
        self.assertEqual(api._resolve_sla_target(self.TARGETS, "d1", dev), 96.0)

    def test_tag_beats_group(self):
        dev = {"group": "g", "tags": ["t"]}
        self.assertEqual(api._resolve_sla_target(self.TARGETS, "other", dev), 97.0)

    def test_group_beats_default(self):
        dev = {"group": "g", "tags": []}
        self.assertEqual(api._resolve_sla_target(self.TARGETS, "other", dev), 98.0)

    def test_default_fallback(self):
        dev = {"group": "none", "tags": []}
        self.assertEqual(api._resolve_sla_target(self.TARGETS, "other", dev), 99.0)

    def test_none_when_unconfigured(self):
        dev = {"group": "g", "tags": ["t"]}
        self.assertIsNone(api._resolve_sla_target({}, "d1", dev))

    def test_out_of_range_rejected(self):
        self.assertIsNone(api._as_pct(0))
        self.assertIsNone(api._as_pct(150))
        self.assertEqual(api._as_pct("99.9"), 99.9)


if __name__ == "__main__":
    unittest.main()
