#!/usr/bin/env python3
"""7.4.6, issue #54 (the follow-up in the thread): the Thermal page and the risk score follow the drive lines.

The reporter, after trying 7.4.4: "yes, please make the Thermal page (and the risk score) follow the drive
lines. Today a host whose hottest sensor is a drive shows no threshold or headroom there, and the 75 C flag
doesn't match the lines set for that drive type."

A drive with temperature lines (its own, its host's or the fleet's, by type) is now held to them on the page and
in the score. Every other sensor, and a drive with no line at any level, is held to the fleet's hot and critical
lines as before. So an install that sets no drive line must read exactly as it did: that is the first control.

Held here through the real functions: the pure rule, the Thermal handler and the risk score.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))

import api  # noqa: E402
import drive_temp  # noqa: E402


class TestTheRule(unittest.TestCase):
    """drive_temp.level, as a table."""

    def lv(self, value, warn=None, crit=None):
        return drive_temp.level(value, warn, crit, 75.0, 85.0)

    def test_no_line_at_any_level_is_judged_by_the_fleets_lines(self):
        self.assertEqual([self.lv(v) for v in (40, 74.9, 75, 84.9, 85, 99)],
                         ["ok", "ok", "hot", "hot", "critical", "critical"])

    def test_a_drive_with_lines_is_judged_by_them_and_not_by_the_fleets(self):
        self.assertEqual([self.lv(v, 45, 50) for v in (44.9, 45, 49.9, 50, 80)],
                         ["ok", "hot", "hot", "critical", "critical"])

    def test_a_warning_line_on_its_own_is_never_critical(self):
        """As for the alerts: the critical line is out of reach, and the fleet's does not step in."""
        self.assertEqual([self.lv(v, 45, None) for v in (44, 45, 99)], ["ok", "hot", "hot"])

    def test_a_critical_line_on_its_own_is_critical_and_nothing_milder(self):
        self.assertEqual([self.lv(v, None, 50) for v in (49, 50)], ["ok", "critical"])

    def test_a_line_that_is_not_a_line_is_no_line(self):
        for junk in (0, -5, 151, float("nan"), float("inf"), True, "50", [], {}):
            self.assertEqual(self.lv(80, junk, junk), "hot", junk)

    def test_the_levels_are_in_order(self):
        self.assertEqual(drive_temp.LEVELS, ("ok", "hot", "critical"))


NOW = int(time.time())
HDD = {"device": "/dev/sda", "serial": "SER-HDD", "media": "hdd", "temperature_c": 52}
SSD = {"device": "/dev/sdb", "serial": "SER-SSD", "media": "ssd", "temperature_c": 60}


class _Fleet(unittest.TestCase):

    def setUp(self):
        self._orig = {k: getattr(api, k) for k in ("require_auth", "_caller_scope", "_tenant_gate")}
        api.require_auth = lambda require_admin=False: "tester"
        api._caller_scope = lambda: None
        api._tenant_gate = lambda: None
        self.config({})
        self.fleet({})

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {})
        api.save(api.HARDWARE_FILE, {})
        api._LOAD_CACHE.clear()

    def config(self, cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def fleet(self, hosts):
        """hosts: {id: (smart list, board temps, host metric thresholds)}"""
        devs, hw = {}, {}
        for dev_id, (smart, temps, lines) in hosts.items():
            dev = {"name": dev_id, "last_seen": NOW, "sysinfo": {}}
            if lines is not None:
                dev["metric_thresholds"] = lines
            devs[dev_id] = dev
            hw[dev_id] = {"ts": NOW, "smart": [dict(d) for d in smart],
                          "hardware": {"temps": [dict(t) for t in temps]}}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.HARDWARE_FILE, hw)
        api._LOAD_CACHE.clear()

    def page(self):
        try:
            api.handle_fleet_thermal()
        except api.HTTPError as e:
            return e.body
        self.fail("no answer")

    def row(self, dev_id="h1"):
        rows = [r for r in self.page()["hosts"] if r["device_id"] == dev_id]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def risk(self, dev_id="h1"):
        dev = api.load(api.DEVICES_FILE)[dev_id]
        hw = api.load(api.HARDWARE_FILE)[dev_id]
        out = api._device_risk(dev_id, dev, {}, {}, {}, NOW, 300, hw_rec=hw)
        return [f for f in out.get("factors") or [] if f.get("kind") == "overheating"]


class TestWithNoDriveLineNothingChanges(_Fleet):
    """The control. A drive no line is set for is held to the fleet's 75 and 85 like every other sensor."""

    def test_a_warm_drive_is_not_hot_and_has_no_threshold(self):
        self.fleet({"h1": ([HDD], [], None)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["warn_c"], r["headroom"]), (False, False, None, None, None))
        self.assertEqual(self.risk(), [])

    def test_a_drive_at_80_is_hot_by_the_fleets_line_and_not_critical(self):
        self.fleet({"h1": ([dict(HDD, temperature_c=80)], [], None)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["headroom"]), (True, False, None, None))
        self.assertEqual(self.page()["hot"], 1)
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("hottest sensor at 80", f[0]["detail"])

    def test_a_board_sensor_is_judged_as_it_was(self):
        self.fleet({"h1": ([], [{"label": "cpu", "current_c": 90, "crit_c": 100}], None)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["headroom"]), (True, True, 100.0, 10.0))

    def test_the_detail_of_a_drive_with_no_line_carries_no_level(self):
        self.fleet({"h1": ([HDD], [], None)})
        d = self.row()["detail"][0]
        self.assertEqual((d["type"], d["crit"]), ("disk", None))
        self.assertNotIn("level", d)
        self.assertNotIn("warn", d)


class TestADriveWithLinesOnThePage(_Fleet):

    LINES = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}

    def test_the_hottest_sensor_being_a_drive_shows_its_threshold_and_headroom(self):
        """The reporter's case."""
        self.fleet({"h1": ([HDD], [], self.LINES)})
        r = self.row()
        self.assertEqual((r["sensor_type"], r["crit_c"], r["warn_c"], r["headroom"]), ("disk", 50.0, 45.0, -2.0))

    def test_the_flag_follows_the_lines_and_not_the_75(self):
        self.fleet({"h1": ([HDD], [], self.LINES)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"]), (True, True))
        self.assertEqual(self.page()["hot"], 1)

    def test_a_cool_drive_has_its_headroom_and_is_not_flagged(self):
        self.fleet({"h1": ([dict(HDD, temperature_c=40)], [], self.LINES)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["headroom"]), (False, False, 50.0, 10.0))
        self.assertEqual(r["detail"][0]["level"], "ok")

    def test_between_the_lines_the_drive_is_hot_and_not_critical(self):
        self.fleet({"h1": ([dict(HDD, temperature_c=47)], [], self.LINES)})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["headroom"]), (True, False, 3.0))
        self.assertEqual(r["detail"][0]["level"], "hot")

    def test_a_warning_line_alone_has_no_threshold_and_is_never_critical(self):
        self.fleet({"h1": ([HDD], [], {"drivetemp_warn_c": 45})})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["headroom"]), (True, False, None, None))

    def test_a_host_over_a_drives_line_is_flagged_though_another_sensor_is_hotter(self):
        """The headline stays the hottest sensor, as it always was; the flag answers 'is anything over its line'."""
        self.fleet({"h1": ([HDD], [{"label": "cpu", "current_c": 60, "crit_c": 100}], self.LINES)})
        r = self.row()
        self.assertEqual((r["sensor_label"], r["sensor_type"], r["max_temp"]), ("cpu", "sensor", 60.0))
        self.assertEqual((r["hot"], r["critical"]), (True, True))
        self.assertEqual((r["crit_c"], r["headroom"]), (100.0, 40.0), "the headline sensor's own threshold")

    def test_the_fleets_line_for_the_type_applies_and_a_drives_own_line_beats_it(self):
        self.config({"drivetemp_ssd_warn_c": 55, "drivetemp_ssd_crit_c": 65})
        self.fleet({"h1": ([SSD], [], None)})
        self.assertEqual((self.row()["hot"], self.row()["critical"], self.row()["crit_c"]), (True, False, 65.0))
        self.fleet({"h1": ([SSD], [], {"drivetemp_per_serial": {"SER-SSD": {"warn": 70, "crit": 80}}})})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["warn_c"], r["crit_c"]), (False, False, 70.0, 80.0))

    def test_another_hosts_lines_do_not_leak(self):
        self.fleet({"h1": ([HDD], [], self.LINES), "h2": ([HDD], [], None)})
        self.assertEqual((self.row("h1")["hot"], self.row("h2")["hot"]), (True, False))
        self.assertEqual(self.page()["hot"], 1)

    def test_an_ignored_board_sensor_still_does_not_count(self):
        """A dead pin the operator ignored neither makes the host hot nor its headline, with drive lines set or not."""
        self.fleet({"h1": ([dict(HDD, temperature_c=40)], [{"label": "dead pin", "current_c": 120}], self.LINES)})
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {},
                                           "metric_thresholds": self.LINES, "sensor_ignores": ["dead pin"]}})
        api._LOAD_CACHE.clear()
        r = self.row()
        self.assertEqual((r["max_temp"], r["sensor_label"], r["hot"], r["critical"]), (40.0, "/dev/sda", False, False))
        self.assertEqual(self.risk(), [])


class TestADriveWithLinesInTheRiskScore(_Fleet):

    LINES = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}

    def test_a_drive_over_its_critical_line_is_a_critical_overheating(self):
        self.fleet({"h1": ([HDD], [], self.LINES)})
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("critical", f[0]["detail"])
        self.assertIn("52", f[0]["detail"])

    def test_a_drive_between_its_lines_scores_half(self):
        self.fleet({"h1": ([dict(HDD, temperature_c=47)], [], self.LINES)})
        crit = self.risk()
        self.fleet({"h1": ([HDD], [], self.LINES)})
        full = self.risk()
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["points"] * 2, full[0]["points"])
        self.assertIn("hot", crit[0]["detail"])

    def test_a_cool_drive_adds_nothing(self):
        self.fleet({"h1": ([dict(HDD, temperature_c=40)], [], self.LINES)})
        self.assertEqual(self.risk(), [])

    def test_the_score_names_a_drive_when_it_is_not_the_hottest_sensor(self):
        self.fleet({"h1": ([HDD], [{"label": "cpu", "current_c": 60, "crit_c": 100}], self.LINES)})
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("a drive over its own line at 52", f[0]["detail"])

    def test_the_score_and_the_page_agree_for_every_case(self):
        cases = [
            ([HDD], [], self.LINES),
            ([dict(HDD, temperature_c=47)], [], self.LINES),
            ([dict(HDD, temperature_c=40)], [], self.LINES),
            ([HDD], [], None),
            ([dict(HDD, temperature_c=80)], [], None),
            ([HDD], [], {"drivetemp_warn_c": 45}),
        ]
        for smart, temps, lines in cases:
            self.fleet({"h1": (smart, temps, lines)})
            r = self.row()
            self.assertEqual(bool(self.risk()), r["hot"], (smart, lines))
