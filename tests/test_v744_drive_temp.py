#!/usr/bin/env python3
"""v7.4.4, issue #54: temperature lines for each drive.

"Drive temperature alerts use one fleet-wide pair of lines for every drive. Different drives need very
different limits: my hard drives should warn at 45 and go critical at 50, my SATA SSDs at 65 and 70, and
NVMe drives at 70 and 80. With one fleet pair, a hard drive running at 60 degrees raises nothing, though
it is well past what it should run at. Temperature lines per drive, keyed on serial like the new disk
names, and also per host and per drive type, with the most specific line winning."

Before this a SMART drive temperature was judged only by the fleet's hot and critical pair, in the risk
score and on the Thermal page, and no alert ever fired from it. This adds the alert, and the lines.

Four layers, each driven for real: the pure rules (which line applies, what a report does to an alert),
the ingest and the alert ledger behind a real hardware report, the handlers that set the lines and hand
them to the page, and the Linux agent's reading of the drive type from smartctl.
"""
import json
import math
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Stdin, api  # noqa: E402
from test_v743_disk_io import _call  # noqa: E402

import drive_temp as dt  # noqa: E402


def drv(serial, temp=None, device="/dev/sda", **kw):
    """One SMART entry as the ingest keeps it."""
    d = {"device": device, "health": "PASSED", "model": "TestDrive", "serial": serial}
    if serial is None:
        del d["serial"]
    if temp is not None:
        d["temperature_c"] = temp
    d.update(kw)
    return d


def fixed(warn, crit):
    return lambda entry: (warn, crit)


# ── the rules, with no server in the way ───────────────────────────────────────────────────────────

class TestWhichLinesApply(unittest.TestCase):

    def test_a_line_is_a_number_of_degrees_from_one_to_150(self):
        for good, want in ((1, 1.0), (45, 45.0), (45.5, 45.5), (150, 150.0), (150.0, 150.0)):
            self.assertEqual(dt.as_line(good), want, good)
        for bad in (0, -5, 151, 1000, 10 ** 400, True, False, None, "45", "", [], {}, float("nan"),
                    float("inf"), float("-inf")):
            self.assertIsNone(dt.as_line(bad), repr(bad)[:20])

    def test_the_names_of_the_lines(self):
        self.assertEqual(dt.line_keys(), ("drivetemp_warn_c", "drivetemp_crit_c"))
        self.assertEqual(dt.line_keys("hdd"), ("drivetemp_hdd_warn_c", "drivetemp_hdd_crit_c"))
        self.assertEqual(len(dt.ALL_LINE_KEYS), 8)
        self.assertEqual(len(set(dt.ALL_LINE_KEYS)), 8)
        self.assertEqual(dt.MEDIA, ("hdd", "ssd", "nvme"))

    def test_each_level_wins_over_the_ones_below_it(self):
        own = {"S1": {"warn": 41, "crit": 42}}
        host = {"drivetemp_hdd_warn_c": 43, "drivetemp_hdd_crit_c": 44,
                "drivetemp_warn_c": 45, "drivetemp_crit_c": 46}
        fleet = {"drivetemp_hdd_warn_c": 47, "drivetemp_hdd_crit_c": 48,
                 "drivetemp_warn_c": 49, "drivetemp_crit_c": 50}
        self.assertEqual(dt.resolve("S1", "hdd", own, host, fleet), (41.0, 42.0), "the drive's own")
        self.assertEqual(dt.resolve("S9", "hdd", own, host, fleet), (43.0, 44.0), "the host's for the type")
        host.pop("drivetemp_hdd_warn_c"), host.pop("drivetemp_hdd_crit_c")
        self.assertEqual(dt.resolve("S9", "hdd", own, host, fleet), (45.0, 46.0), "the host's for any drive")
        host.pop("drivetemp_warn_c"), host.pop("drivetemp_crit_c")
        self.assertEqual(dt.resolve("S9", "hdd", own, host, fleet), (47.0, 48.0), "the fleet's for the type")
        fleet.pop("drivetemp_hdd_warn_c"), fleet.pop("drivetemp_hdd_crit_c")
        self.assertEqual(dt.resolve("S9", "hdd", own, host, fleet), (49.0, 50.0), "the fleet's for any drive")
        fleet.clear()
        self.assertEqual(dt.resolve("S9", "hdd", own, host, fleet), (None, None), "no line anywhere")

    def test_the_type_a_line_is_for_decides_nothing_for_another_type(self):
        fleet = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}
        self.assertEqual(dt.resolve("S1", "hdd", None, {}, fleet), (45.0, 50.0))
        self.assertEqual(dt.resolve("S1", "ssd", None, {}, fleet), (None, None))
        self.assertEqual(dt.resolve("S1", "", None, {}, fleet), (None, None), "an untyped drive")
        self.assertEqual(dt.resolve("S1", "floppy", None, {}, fleet), (None, None))

    def test_a_line_for_any_drive_catches_what_has_no_line_of_its_own_type(self):
        fleet = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50,
                 "drivetemp_warn_c": 70, "drivetemp_crit_c": 80}
        self.assertEqual(dt.resolve("S1", "nvme", None, {}, fleet), (70.0, 80.0))
        self.assertEqual(dt.resolve("S1", "", None, {}, fleet), (70.0, 80.0))
        self.assertEqual(dt.resolve("S1", "hdd", None, {}, fleet), (45.0, 50.0))

    def test_the_host_beats_the_fleet_whatever_the_type(self):
        """Scope first, then type: the host's line for any drive is more specific than the fleet's line for
        this type, because it was set for this host."""
        host = {"drivetemp_warn_c": 55, "drivetemp_crit_c": 60}
        fleet = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}
        self.assertEqual(dt.resolve("S1", "hdd", None, host, fleet), (55.0, 60.0))

    def test_the_two_numbers_are_looked_up_one_at_a_time(self):
        """A host that sets only a warning line keeps the fleet's critical line."""
        host = {"drivetemp_hdd_warn_c": 48}
        fleet = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 52}
        self.assertEqual(dt.resolve("S1", "hdd", None, host, fleet), (48.0, 52.0))
        own = {"S1": {"crit": 49}}
        self.assertEqual(dt.resolve("S1", "hdd", own, host, fleet), (48.0, 49.0))

    def test_a_warning_line_alone_leaves_the_critical_one_out_of_reach(self):
        w, c = dt.resolve("S1", "", None, {}, {"drivetemp_warn_c": 45})
        self.assertEqual(w, 45.0)
        self.assertEqual(c, math.inf)

    def test_a_critical_line_alone_is_also_the_warning(self):
        self.assertEqual(dt.resolve("S1", "", None, {}, {"drivetemp_crit_c": 50}), (50.0, 50.0))

    def test_a_warning_above_the_critical_is_brought_down_to_it(self):
        """Two levels can produce this between them: a host's warning of 60 over the fleet's critical of 50."""
        host = {"drivetemp_warn_c": 60}
        fleet = {"drivetemp_crit_c": 50}
        self.assertEqual(dt.resolve("S1", "", None, host, fleet), (50.0, 50.0))

    def test_junk_in_any_level_is_not_a_line_and_the_next_level_answers(self):
        junk = {"warn": "45", "crit": True}
        host = {"drivetemp_hdd_warn_c": float("nan"), "drivetemp_hdd_crit_c": 9999, "drivetemp_warn_c": None}
        fleet = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}
        self.assertEqual(dt.resolve("S1", "hdd", {"S1": junk}, host, fleet), (45.0, 50.0))
        for own in (None, "x", 5, [], {"S1": "x"}, {"S1": None}, {"S1": []}):
            self.assertEqual(dt.resolve("S1", "hdd", own, host, fleet), (45.0, 50.0), repr(own))
        for scope in (None, "x", 5, [], 3.5):
            self.assertEqual(dt.resolve("S1", "hdd", None, scope, scope), (None, None), repr(scope))

    def test_a_drive_without_a_serial_has_no_lines_of_its_own(self):
        own = {"": {"warn": 1, "crit": 2}, "S1": {"warn": 41, "crit": 42}}
        self.assertEqual(dt.resolve("", "", own, {}, {"drivetemp_warn_c": 70, "drivetemp_crit_c": 80}),
                         (70.0, 80.0))

    def test_without_its_own_lines_a_drive_gets_what_its_boxes_inherit(self):
        own = {"S1": {"warn": 41, "crit": 42}}
        host = {"drivetemp_ssd_warn_c": 60, "drivetemp_ssd_crit_c": 65}
        self.assertEqual(dt.resolve("S1", "ssd", own, host, {}), (41.0, 42.0))
        self.assertEqual(dt.resolve("S1", "ssd", None, host, {}), (60.0, 65.0))

    def test_the_type_comes_from_the_agent_or_the_device_name(self):
        for entry, want in (({"media": "hdd"}, "hdd"), ({"media": "SSD"}, "ssd"), ({"media": " nvme "}, "nvme"),
                            ({"media": "floppy"}, ""), ({"media": ""}, ""), ({}, ""),
                            ({"device": "/dev/nvme0n1"}, "nvme"), ({"device": "nvme1n1"}, "nvme"),
                            ({"device": "/dev/sda"}, ""), ({"device": "/dev/sda", "media": "ssd"}, "ssd"),
                            ({"device": "/dev/nvme0n1", "media": "hdd"}, "hdd"),
                            ("x", ""), (None, ""), ([], "")):
            self.assertEqual(dt.media_of(entry), want, entry)

    def test_a_pair_is_inverted_only_when_both_numbers_are_there(self):
        self.assertTrue(dt.inverted(50, 45))
        self.assertTrue(dt.inverted(45, 45))
        self.assertFalse(dt.inverted(45, 50))
        self.assertFalse(dt.inverted(None, 45))
        self.assertFalse(dt.inverted(50, None))
        self.assertFalse(dt.inverted("50", 45))

    def test_what_the_page_is_given(self):
        own = {"S1": {"warn": 41}}
        host = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}
        v = dt.view({"device": "/dev/sda", "serial": "S1", "media": "hdd"}, own, host, {})
        self.assertEqual(v["media"], "hdd")
        self.assertEqual((v["warn"], v["crit"]), (41.0, 50.0))
        self.assertEqual(v["inherit"], {"warn": 45.0, "crit": 50.0})
        self.assertEqual(v["own"], {"warn": 41.0, "crit": None})
        none = dt.view({"device": "/dev/sdb", "serial": "S2"}, own, {}, {})
        self.assertEqual((none["warn"], none["crit"]), (None, None))
        self.assertNotIn("own", none)
        only_warn = dt.view({"device": "/dev/sdc", "serial": "S3"}, None, {"drivetemp_warn_c": 45}, {})
        self.assertEqual((only_warn["warn"], only_warn["crit"]), (45.0, None))
        json.dumps([v, none, only_warn], allow_nan=False)           # no Infinity on the wire


class TestWhatAReportDoesToAnAlert(unittest.TestCase):

    def run_step(self, prev, drives, warn=45.0, crit=50.0, buffer=5):
        return dt.step(prev, drives, fixed(warn, crit), buffer)

    def names(self, events):
        return [(e["event"], e["key"], e["value"], e["threshold"]) for e in events]

    def test_a_drive_over_the_warning_line_warns_once(self):
        events, state = self.run_step({}, [drv("S1", 47)])
        self.assertEqual(self.names(events), [("metric_warning", "S1", 47.0, 45.0)])
        self.assertEqual(state, {"S1": {"l": "warning", "m": 0}})
        events, state = self.run_step(state, [drv("S1", 48)])
        self.assertEqual(events, [], "the same level again says nothing")
        self.assertEqual(state, {"S1": {"l": "warning", "m": 0}})

    def test_a_calm_drive_says_nothing_and_leaves_no_state(self):
        events, state = self.run_step({}, [drv("S1", 30), drv("S2", 44)])
        self.assertEqual((events, state), ([], {}))

    def test_the_line_itself_counts(self):
        events, _ = self.run_step({}, [drv("S1", 45)])
        self.assertEqual([e["event"] for e in events], ["metric_warning"])
        events, _ = self.run_step({}, [drv("S1", 50)])
        self.assertEqual([e["event"] for e in events], ["metric_critical"])

    def test_the_way_up_and_the_way_down(self):
        _e, state = self.run_step({}, [drv("S1", 47)])
        events, state = self.run_step(state, [drv("S1", 52)])
        self.assertEqual(self.names(events), [("metric_critical", "S1", 52.0, 50.0)])
        events, state = self.run_step(state, [drv("S1", 47)])
        self.assertEqual(self.names(events), [("metric_warning", "S1", 47.0, 45.0)], "down a level is said too")
        self.assertEqual(state, {"S1": {"l": "warning", "m": 0}})
        events, state = self.run_step(state, [drv("S1", 38)])
        self.assertEqual(self.names(events), [("metric_recovered", "S1", 38.0, 45.0)])
        self.assertEqual(state, {})

    def test_a_drive_hovering_at_the_line_does_not_bounce(self):
        """Under the warning line but inside the buffer, it stays where it was; 45 - 5 and a tenth under
        are the rule the other metrics use, so the recovery point here is 40.5."""
        _e, state = self.run_step({}, [drv("S1", 47)])
        for t in (44, 43, 41, 40.6):
            events, state = self.run_step(state, [drv("S1", t)])
            self.assertEqual(events, [], t)
            self.assertEqual(state, {"S1": {"l": "warning", "m": 0}}, t)
        events, state = self.run_step(state, [drv("S1", 40)])
        self.assertEqual([e["event"] for e in events], ["metric_recovered"])

    def test_the_recovery_point_is_the_nearer_of_the_buffer_and_a_tenth_of_the_line(self):
        """The rule the other metrics use. At 45 a tenth is 4.5 and the buffer 5, so the tenth is nearer:
        40.5. At 60 with a buffer of 2 the buffer is nearer: 58. A buffer of 0 lets go at the line."""
        self.assertTrue(dt.below_recovery(40.4, 45, 5))
        self.assertFalse(dt.below_recovery(40.6, 45, 5))
        self.assertTrue(dt.below_recovery(57.9, 60, 2))
        self.assertFalse(dt.below_recovery(58.1, 60, 2))
        self.assertTrue(dt.below_recovery(59.9, 60, 0))
        self.assertFalse(dt.below_recovery(60, 60, 0))
        self.assertFalse(dt.below_recovery(41, 45, 20), "a huge buffer cannot hold a drive for ever")
        self.assertTrue(dt.below_recovery(40, 45, 20))

    def test_a_critical_drive_that_cools_to_calm_inside_the_buffer_stays_critical(self):
        _e, state = self.run_step({}, [drv("S1", 52)])
        events, state = self.run_step(state, [drv("S1", 43)])
        self.assertEqual(events, [])
        self.assertEqual(state, {"S1": {"l": "critical", "m": 0}})

    def test_no_reading_holds_what_there_was(self):
        """A sleeping drive reports no temperature, and neither alerts nor closes anything."""
        _e, state = self.run_step({}, [drv("S1", 52)])
        for entry in (drv("S1"), drv("S1", standby=True)):
            events, kept = self.run_step(state, [entry])
            self.assertEqual(events, [])
            self.assertEqual(kept, {"S1": {"l": "critical", "m": 0}})

    def test_noise_is_not_a_reading(self):
        _e, state = self.run_step({}, [drv("S1", 52)])
        for noise in (0, -3, 151, 255, 10 ** 9, True, "52", None, float("nan"), float("inf")):
            events, kept = self.run_step(state, [dict(drv("S1"), temperature_c=noise)])
            self.assertEqual(events, [], repr(noise))
            self.assertEqual(kept, {"S1": {"l": "critical", "m": 0}}, repr(noise))
        events, kept = self.run_step({}, [dict(drv("S1"), temperature_c=255)])
        self.assertEqual((events, kept), ([], {}), "and it never opens an alert either")

    def test_a_drive_that_is_not_in_the_report_is_let_go_after_three_reports(self):
        _e, state = self.run_step({}, [drv("S1", 52)])
        events, state = self.run_step(state, [])
        self.assertEqual((events, state), ([], {"S1": {"l": "critical", "m": 1}}))
        events, state = self.run_step(state, [])
        self.assertEqual((events, state), ([], {"S1": {"l": "critical", "m": 2}}))
        events, state = self.run_step(state, [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "metric_recovered")
        self.assertEqual(events[0]["key"], "S1")
        self.assertIsNone(events[0]["drive"])
        self.assertEqual(state, {})
        self.assertEqual(dt.MISS_LIMIT, 3)

    def test_a_drive_that_comes_back_in_time_starts_its_count_again(self):
        _e, state = self.run_step({}, [drv("S1", 52)])
        _e, state = self.run_step(state, [])
        _e, state = self.run_step(state, [])
        events, state = self.run_step(state, [drv("S1", 53)])
        self.assertEqual((events, state), ([], {"S1": {"l": "critical", "m": 0}}))
        _e, state = self.run_step(state, [])
        self.assertEqual(state, {"S1": {"l": "critical", "m": 1}})

    def test_turning_the_lines_off_closes_the_alert(self):
        _e, state = self.run_step({}, [drv("S1", 52)])
        events, state = dt.step(state, [drv("S1", 52)], fixed(None, None), 5)
        self.assertEqual(self.names(events), [("metric_recovered", "S1", 52.0, 0.0)])
        self.assertEqual(state, {})
        events, state = dt.step({"S1": {"l": "warning", "m": 0}}, [drv("S1")], fixed(None, None), 5)
        self.assertEqual([e["event"] for e in events], ["metric_recovered"], "also when there is no reading")

    def test_a_warning_line_alone_never_goes_critical(self):
        events, _ = dt.step({}, [drv("S1", 99)], fixed(45.0, math.inf), 5)
        self.assertEqual(self.names(events), [("metric_warning", "S1", 99.0, 45.0)])

    def test_the_drives_are_separate(self):
        events, state = self.run_step({}, [drv("S1", 47), drv("S2", 30, device="/dev/sdb"),
                                          drv("S3", 53, device="/dev/sdc")])
        self.assertEqual(sorted((e["event"], e["key"]) for e in events),
                         [("metric_critical", "S3"), ("metric_warning", "S1")])
        events, state = self.run_step(state, [drv("S1", 30), drv("S2", 30, device="/dev/sdb"),
                                              drv("S3", 53, device="/dev/sdc")])
        self.assertEqual([(e["event"], e["key"]) for e in events], [("metric_recovered", "S1")])
        self.assertEqual(list(state), ["S3"])

    def test_the_alert_follows_the_serial_when_the_letter_changes(self):
        _e, state = self.run_step({}, [drv("S1", 52, device="/dev/sda")])
        events, state = self.run_step(state, [drv("S1", 53, device="/dev/sdd")])
        self.assertEqual((events, list(state)), ([], ["S1"]))

    def test_a_drive_without_a_serial_is_kept_under_its_device(self):
        events, state = self.run_step({}, [drv(None, 52, device="/dev/sdb")])
        self.assertEqual([e["key"] for e in events], ["/dev/sdb"])
        self.assertEqual(list(state), ["/dev/sdb"])

    def test_drives_that_share_a_serial_are_told_apart_by_where_they_are(self):
        report = [drv("0000", 52, device="/dev/sda"), drv("0000", 30, device="/dev/sdb")]
        events, state = self.run_step({}, report)
        self.assertEqual([e["key"] for e in events], ["0000@/dev/sda"])
        self.assertEqual(dt.drive_key(report[0], dt.serial_counts(report)), "0000@/dev/sda")
        self.assertEqual(dt.drive_key(report[0]), "0000", "alone it is just the serial")
        self.assertEqual(dt.drive_key({"serial": "S1"}, {"S1": 2}), "S1", "and with no device nothing to add")
        self.assertEqual(dt.drive_key({}), "")
        self.assertEqual(dt.drive_key("x"), "")

    def test_the_same_drive_listed_twice_is_judged_once(self):
        events, _ = self.run_step({}, [drv("S1", 52), drv("S1", 52)])
        self.assertEqual(len(events), 1, "the same serial on the same device is the same drive")

    def test_a_state_that_is_not_ours_is_ignored(self):
        for junk in ("x", 5, None, [], {"S1": "warning"}, {"S1": {"l": "ok", "m": 0}}, {"S1": {"l": "critical", "m": "x"}},
                     {5: {"l": "critical", "m": 0}}, {"S1": {"l": "critical", "m": True}}):
            events, state = self.run_step(junk, [drv("S1", 30)])
            self.assertEqual((events, state), ([], {}), repr(junk))

    def test_an_entry_that_is_not_a_drive_is_skipped(self):
        events, state = self.run_step({}, ["sda", None, 5, [], {"serial": "", "device": ""}, drv("S1", 47)])
        self.assertEqual([e["key"] for e in events], ["S1"])
        self.assertEqual(self.run_step({}, "not a list"), ([], {}))
        self.assertEqual(self.run_step({}, None), ([], {}))

    def test_the_event_carries_the_entry_it_is_about(self):
        entry = drv("S1", 47, model="WDC WD40EFRX")
        events, _ = self.run_step({}, [entry])
        self.assertIs(events[0]["drive"], entry)


# ── through a real hardware report and the real alert ledger ───────────────────────────────────────

class _Drives(_Base):
    """The real ingest, the real alert ledger and the real digest, with the drives' lines in the config."""

    def setUp(self):
        super().setUp()
        for f, empty in ((api.HARDWARE_FILE, {}), (api.DISK_NAMES_FILE, {}), (api.FLEET_EVENTS_FILE, {"events": []}),
                         (api.SMART_HIST_FILE, {}), (api.ROLES_FILE, {"roles": []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        """Leave the shared data directory as found. A neighbouring module that reads the first alert in
        the store without resetting it (test_api's channel routing does) fails after one that leaves an
        alert open, and only in the order a parallel run happens to give."""
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.HARDWARE_FILE, {}), (api.DISK_NAMES_FILE, {}),
                         (api.FLEET_EVENTS_FILE, {"events": []}), (api.CONFIG_FILE, {}), (api.DEVICES_FILE, {}),
                         (api.SMART_HIST_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        super().tearDown()

    def lines(self, **cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def host_lines(self, **thresholds):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["metric_thresholds"] = thresholds
        api._LOAD_CACHE.clear()

    def heartbeat(self, **body):
        """One heartbeat carrying this hardware body, through the real handler and the real post-lock path."""
        raw = json.dumps(dict({"device_id": DEV, "token": "tok"}, **body)).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except SystemExit as c:
            self.assertEqual(getattr(c, "status", None), 200, getattr(c, "body", None))
            return
        self.fail("the heartbeat did not answer")

    def report(self, *drives, **body):
        api._LOAD_CACHE.clear()
        api._ingest_hardware(DEV, "serverbox", dict({"smart": list(drives)}, **body), int(time.time()),
                             dev=api.device_get(DEV))
        api._LOAD_CACHE.clear()

    def record(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.HARDWARE_FILE) or {}).get(DEV) or {}

    def drive_events(self):
        return [(e, p.get("target"), p.get("value"), p.get("threshold")) for e, p in self.events
                if e.startswith("metric_") and p.get("kind") == "drivetemp"]

    def alert_rows(self):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if (a.get("payload") or {}).get("metric") == "drivetemp"]

    def open_alerts(self):
        return sorted(a["payload"]["target"] for a in self.alert_rows() if not a.get("resolved_at"))


class TestTheIngest(_Drives):

    def test_nothing_set_nothing_fires(self):
        """An upgrade alerts on nothing new, however hot the drives are."""
        for _ in range(3):
            self.report(drv("S1", 95), drv("S2", 80, device="/dev/nvme0n1"))
        self.assertEqual(self.drive_events(), [])
        self.assertEqual(self.record().get("_drive_temp"), {})

    def test_a_drive_over_the_fleet_line_alerts_once_and_the_alert_says_which(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("WD-1234", 52))
        self.assertEqual(self.drive_events(), [("metric_critical", "WD-1234", 52.0, 50.0)])
        p = [pl for e, pl in self.events if e == "metric_critical"][0]
        self.assertEqual((p["disk"], p["serial"], p["kind"], p["metric"], p["level"]),
                         ("/dev/sda", "WD-1234", "drivetemp", "drivetemp", "critical"))
        self.assertNotIn("disk_name", p, "an unnamed drive has no name to carry")
        self.report(drv("WD-1234", 53))
        self.assertEqual(len(self.drive_events()), 1, "the same level again is not another alert")
        self.assertEqual(self.open_alerts(), ["WD-1234"])
        self.assertEqual(self.record()["_drive_temp"], {"WD-1234": {"l": "critical", "m": 0}})

    def test_each_type_has_its_own_lines(self):
        self.lines(drivetemp_hdd_warn_c=45, drivetemp_hdd_crit_c=50, drivetemp_ssd_warn_c=65,
                   drivetemp_ssd_crit_c=70, drivetemp_nvme_warn_c=70, drivetemp_nvme_crit_c=80)
        self.report(drv("H1", 47, media="hdd"), drv("S1", 60, device="/dev/sdb", media="ssd"),
                    drv("N1", 75, device="/dev/nvme0n1"), drv("U1", 90, device="/dev/sdc"))
        self.assertEqual(sorted(self.drive_events()),
                         [("metric_warning", "H1", 47.0, 45.0), ("metric_warning", "N1", 75.0, 70.0)])

    def test_the_line_for_any_drive_catches_the_rest(self):
        self.lines(drivetemp_hdd_warn_c=45, drivetemp_hdd_crit_c=50, drivetemp_warn_c=70, drivetemp_crit_c=80)
        self.report(drv("H1", 47, media="hdd"), drv("U1", 75, device="/dev/sdc"))
        self.assertEqual(sorted(self.drive_events()),
                         [("metric_warning", "H1", 47.0, 45.0), ("metric_warning", "U1", 75.0, 70.0)])

    def test_the_hosts_line_beats_the_fleets(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.host_lines(drivetemp_warn_c=55, drivetemp_crit_c=60)
        self.report(drv("S1", 52))
        self.assertEqual(self.drive_events(), [], "52 is over the fleet's lines and under this host's")
        self.report(drv("S1", 57))
        self.assertEqual(self.drive_events(), [("metric_warning", "S1", 57.0, 55.0)])

    def test_the_drives_own_line_beats_the_hosts(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.host_lines(drivetemp_warn_c=55, drivetemp_crit_c=60,
                        drivetemp_per_serial={"S1": {"warn": 35, "crit": 38}, "S2": {"warn": 58}})
        self.report(drv("S1", 36), drv("S2", 59, device="/dev/sdb"), drv("S3", 52, device="/dev/sdc"))
        self.assertEqual(sorted(self.drive_events()),
                         [("metric_warning", "S1", 36.0, 35.0), ("metric_warning", "S2", 59.0, 58.0)],
                         "S2 has a warning of its own and borrows the host's critical 60, S3 is under 55")

    def test_the_hosts_line_reaches_the_real_heartbeat(self):
        """dev= is what hands the host's lines to the check; a heartbeat has to pass it."""
        self.host_lines(drivetemp_warn_c=40, drivetemp_crit_c=48)
        self.heartbeat(smart=[drv("S1", 44)])
        self.assertEqual(self.drive_events(), [("metric_warning", "S1", 44.0, 40.0)])

    def test_a_drives_own_line_reaches_the_real_heartbeat_too(self):
        self.host_lines(drivetemp_per_serial={"S1": {"warn": 35, "crit": 38}})
        self.heartbeat(smart=[drv("S1", 36)])
        self.assertEqual(self.drive_events(), [("metric_warning", "S1", 36.0, 35.0)])

    def test_it_closes_when_the_drive_cools_and_not_before(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        self.report(drv("S1", 43))
        self.assertEqual(self.open_alerts(), ["S1"], "under the line but inside the buffer")
        self.report(drv("S1", 38))
        self.assertEqual([e for e, *_ in self.drive_events()], ["metric_warning", "metric_recovered"])
        self.assertEqual(self.open_alerts(), [])
        self.assertEqual(self.record()["_drive_temp"], {})
        self.assertTrue(all(a.get("resolved_at") for a in self.alert_rows()))

    def test_warning_then_critical_then_back_down_adds_no_row_a_repeat_would_stack(self):
        """A row is kept for each event name, as for every metric: the warning and the critical one. The
        warning said again on the way down joins the one that is still open, and one recovery closes both."""
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        self.report(drv("S1", 52))
        self.report(drv("S1", 47))
        self.assertEqual([e for e, *_ in self.drive_events()], ["metric_warning", "metric_critical", "metric_warning"])
        self.assertEqual(sorted(a["event"] for a in self.alert_rows()), ["metric_critical", "metric_warning"])
        self.report(drv("S1", 30))
        self.assertEqual(self.open_alerts(), [])
        self.assertTrue(all(a.get("resolved_at") for a in self.alert_rows()))

    def test_two_hot_drives_are_two_alerts_and_one_can_close_alone(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47), drv("S2", 48, device="/dev/sdb"))
        self.assertEqual(self.open_alerts(), ["S1", "S2"])
        self.report(drv("S1", 30), drv("S2", 48, device="/dev/sdb"))
        self.assertEqual(self.open_alerts(), ["S2"])

    def test_a_new_letter_is_the_same_drive(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47, device="/dev/sda"))
        self.report(drv("S1", 47, device="/dev/sdd"))
        self.assertEqual(len(self.drive_events()), 1)
        self.assertEqual(self.open_alerts(), ["S1"])
        self.report(drv("S1", 30, device="/dev/sdd"))
        self.assertEqual(self.open_alerts(), [])

    def test_naming_the_drive_while_it_is_hot_does_not_strand_the_alert(self):
        """The name is not part of the alert's identity (label is), so a rename closes the same row."""
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        api.save(api.DISK_NAMES_FILE, {DEV: {"S1": "Pool disk 2"}})
        api._LOAD_CACHE.clear()
        self.report(drv("S1", 30))
        self.assertEqual(self.open_alerts(), [])
        recovered = [p for e, p in self.events if e == "metric_recovered"][0]
        self.assertEqual(recovered["disk_name"], "Pool disk 2")
        self.assertEqual(len(self.alert_rows()), 1)

    def test_a_named_drive_is_named_in_the_alert(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        api.save(api.DISK_NAMES_FILE, {DEV: {"WD-1234": "Pool disk 2"}})
        api._LOAD_CACHE.clear()
        self.report(drv("WD-1234", 52, device="/dev/sdd"))
        row = self.alert_rows()[0]
        self.assertEqual(row["title"], "Drive Pool disk 2 (/dev/sdd, sn WD-1234) CRITICAL on serverbox: 52°C")

    def test_an_unnamed_drive_is_the_device_in_the_title(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("WD-1234", 47, device="/dev/sdd"))
        self.assertEqual(self.alert_rows()[0]["title"], "Drive /dev/sdd WARNING on serverbox: 47°C")

    def test_a_sleeping_drive_keeps_its_alert(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        self.report(drv("S1", health="UNKNOWN", standby=True))
        self.report({"device": "/dev/sda", "health": "UNKNOWN", "standby": True})
        self.assertEqual(self.open_alerts(), ["S1"])
        self.assertEqual(len(self.drive_events()), 1)

    def test_a_drive_that_is_gone_for_three_reports_closes_its_alert(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47), drv("S2", 30, device="/dev/sdb"))
        self.report(drv("S2", 30, device="/dev/sdb"))
        self.report(drv("S2", 30, device="/dev/sdb"))
        self.assertEqual(self.open_alerts(), ["S1"], "two reports without it are not enough")
        self.report(drv("S2", 30, device="/dev/sdb"))
        self.assertEqual(self.open_alerts(), [])
        self.assertEqual(self.record()["_drive_temp"], {})

    def test_turning_the_lines_off_closes_what_is_open(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 52))
        self.lines()
        self.report(drv("S1", 52))
        self.assertEqual(self.open_alerts(), [])
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 52))
        self.assertEqual(self.open_alerts(), ["S1"], "and turning them back on alerts again")

    def test_a_report_without_a_smart_list_leaves_every_alert_as_it_was(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 52))
        before = list(self.events)
        for body in ({"kernel": {"running": "6.1.0"}}, {"gpus": []}, {"ups": []}):
            api._LOAD_CACHE.clear()
            api._ingest_hardware(DEV, "serverbox", body, int(time.time()), dev=api.device_get(DEV))
        self.assertEqual(self.events, before)
        self.assertEqual(self.open_alerts(), ["S1"])
        self.assertEqual(self.record()["_drive_temp"], {"S1": {"l": "critical", "m": 0}})

    def test_noise_from_a_drive_neither_alerts_nor_closes(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 255), drv("S2", 0, device="/dev/sdb"))
        self.assertEqual(self.drive_events(), [])
        self.report(drv("S1", 52))
        self.report(drv("S1", 0))
        self.report(drv("S1", 255))
        self.assertEqual(self.open_alerts(), ["S1"])

    def test_drives_that_share_a_serial_get_an_alert_each(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("0000", 47, device="/dev/sda"), drv("0000", 48, device="/dev/sdb"))
        self.assertEqual(self.open_alerts(), ["0000@/dev/sda", "0000@/dev/sdb"])

    def test_the_kind_of_drive_is_kept_only_as_one_of_three_words(self):
        self.report(drv("S1", media="SSD"), drv("S2", media="floppy", device="/dev/sdb"),
                    drv("S3", media="", device="/dev/sdc"), drv("S4", media=["hdd"], device="/dev/sdd"),
                    drv("S5", media="nvme", device="/dev/nvme0n1"))
        got = {d["serial"]: d.get("media") for d in self.record()["smart"]}
        self.assertEqual(got, {"S1": "ssd", "S2": None, "S3": None, "S4": None, "S5": "nvme"})

    def test_a_fault_in_the_check_cannot_cost_the_report_its_smart_record(self):
        real = api._drive_temp_events

        def boom(*a, **k):
            raise RuntimeError("boom")
        api._drive_temp_events = boom
        try:
            self.report(drv("S1", 52))
        finally:
            api._drive_temp_events = real
        self.assertEqual([d["serial"] for d in self.record()["smart"]], ["S1"])

    def test_the_internal_state_does_not_reach_the_hardware_answer(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 52))
        box = _call(api.handle_device_hardware, {}, DEV, verb="GET")
        self.assertEqual(box["status"], 200)
        self.assertNotIn("_drive_temp", box["body"])

    def test_a_deleted_host_takes_its_state_with_it(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 52))
        self.assertTrue(api._purge_device(DEV))
        api._LOAD_CACHE.clear()
        self.assertNotIn(DEV, api.load(api.HARDWARE_FILE) or {})


class TestASensorTheOperatorIgnoredStaysQuiet(_Drives):
    """Found on the way (6.4.2's per-sensor ignore). _ingest_hardware reads the ignore list off the device it is
    handed, and the heartbeat hands it saved_dev, a snapshot that did not carry sensor_ignores. So the
    ignore never reached temp_high through a heartbeat: the dead pin an operator had switched off went on
    raising the alert. The fix is the same row that carries the host's lines."""

    DEAD_PIN = {"hardware": {"temps": [{"label": "board temp3", "current_c": 104.0, "crit_c": 100.0}]}}

    def hot_events(self):
        return [e for e, p in self.events if e == "temp_high"]

    def test_the_control_an_unignored_sensor_over_the_line_fires(self):
        self.heartbeat(**self.DEAD_PIN)
        self.assertEqual(self.hot_events(), ["temp_high"], "the harness has to be able to see the alert")

    def test_an_ignored_sensor_does_not_fire_through_the_heartbeat(self):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["sensor_ignores"] = ["board temp3"]
        api._LOAD_CACHE.clear()
        self.heartbeat(**self.DEAD_PIN)
        self.assertEqual(self.hot_events(), [])

    def test_both_fields_are_in_the_contract_table(self):
        for field in ("metric_thresholds", "sensor_ignores"):
            self.assertIn(field, api._HEARTBEAT_PASSTHROUGH_FIELDS)


class TestTheWords(_Drives):

    def test_the_webhook_text(self):
        import notify
        p = {"kind": "drivetemp", "target": "WD-1234", "disk": "/dev/sdd", "serial": "WD-1234",
             "value": 52.0, "threshold": 50.0, "name": "nas01"}
        self.assertEqual(notify._webhook_message("metric_critical", p),
                         "nas01: CRITICAL — drive /dev/sdd at 52°C (threshold: 50°C)")
        self.assertEqual(notify._webhook_message("metric_warning", dict(p, threshold=45.5, value=47.0, disk_name="Pool disk 2")),
                         "nas01: WARNING — drive Pool disk 2 (/dev/sdd, sn WD-1234) at 47°C (threshold: 45.5°C)")
        self.assertEqual(notify._webhook_message("metric_recovered", dict(p, value=38.0)),
                         "nas01: drive /dev/sdd back to 38°C")

    def test_which_drive_falls_back_to_the_target(self):
        import notify
        self.assertEqual(notify.drive_phrase({"target": "WD-1234"}), "WD-1234")
        self.assertEqual(notify.drive_phrase({}), "?")
        self.assertEqual(notify.drive_phrase({"disk": "/dev/sda", "disk_name": "Backup"}), "Backup (/dev/sda)")

    def test_the_alert_row_keeps_what_the_inbox_shows(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        api.save(api.DISK_NAMES_FILE, {DEV: {"S1": "Pool disk 2"}})
        api._LOAD_CACHE.clear()
        self.report(drv("S1", 47, device="/dev/sdd"))
        p = self.alert_rows()[0]["payload"]
        for key, want in (("target", "S1"), ("metric", "drivetemp"), ("disk", "/dev/sdd"), ("serial", "S1"),
                          ("disk_name", "Pool disk 2"), ("value", 47.0), ("threshold", 45.0), ("level", "warning")):
            self.assertEqual(p.get(key), want, key)

    def na_items(self):
        import attention_isolation
        tmp = tempfile.mkdtemp(prefix="rp-v744-dt-")
        live = {"devices": dict(api.load(api.DEVICES_FILE)), "config": dict(api.load(api.CONFIG_FILE)),
                "hardware": dict(api.load(api.HARDWARE_FILE))}
        keep = {n: getattr(api, n) for n in ("DEVICES_FILE", "CONFIG_FILE", "ALERTS_FILE", "HARDWARE_FILE")}
        saved = attention_isolation.isolate(api, tmp)
        try:
            api.save(api.DEVICES_FILE, live["devices"])
            api.save(api.CONFIG_FILE, live["config"])
            api.save(api.HARDWARE_FILE, live["hardware"])
            api._LOAD_CACHE.clear()
            return [(i["kind"], i["severity"], i["summary"]) for i in api._compute_attention()
                    if "drive" in (i.get("summary") or "")]
        finally:
            attention_isolation.restore(api, saved)
            for n, v in keep.items():
                setattr(api, n, v)

    def test_needs_attention_names_the_drive_the_reading_and_the_line(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("WD-1234", 47, device="/dev/sdd"))
        self.assertEqual(self.na_items(), [("disk", "warning", "drive /dev/sdd at 47°C (warning ≥ 45°C)")])

    def test_needs_attention_gives_the_critical_line_when_it_is_critical_and_the_name(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        api.save(api.DISK_NAMES_FILE, {DEV: {"WD-1234": "Pool disk 2"}})
        api._LOAD_CACHE.clear()
        self.report(drv("WD-1234", 52, device="/dev/sdd"))
        self.assertEqual(self.na_items(),
                         [("disk", "critical", "drive Pool disk 2 (/dev/sdd, sn WD-1234) at 52°C (critical ≥ 50°C)")])

    def test_needs_attention_is_empty_once_the_drive_has_cooled(self):
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        self.report(drv("S1", 30))
        self.assertEqual(self.na_items(), [])

    def test_needs_attention_leaves_out_a_drive_whose_line_has_gone(self):
        """The state is settled by the next report; until then there is no line to quote."""
        self.lines(drivetemp_warn_c=45, drivetemp_crit_c=50)
        self.report(drv("S1", 47))
        self.lines()
        self.assertEqual(self.na_items(), [])

    def test_a_mute_of_the_disk_warning_mutes_it_like_the_other_disk_problems(self):
        """Kind 'disk', so the map that ties digest items to events already covers it."""
        self.assertEqual(api._NA_MUTE_EVENTS[("disk", "warning")], ("metric_warning",))
        self.assertIn("metric_critical", api._NA_MUTE_EVENTS[("disk", "critical")])


# ── the handlers that set the lines and hand them to the page ──────────────────────────────────────

class TestThePerHostHandler(_Drives):

    def patch(self, body, role="admin"):
        return _call(api.handle_device_metric_thresholds, body, DEV, role=role, verb="PATCH")

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(DEV, {}).get("metric_thresholds", {})

    def test_the_hosts_lines_are_saved(self):
        box = self.patch({"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50, "drivetemp_warn_c": 70.5})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.stored(), {"drivetemp_hdd_warn_c": 45.0, "drivetemp_hdd_crit_c": 50.0,
                                         "drivetemp_warn_c": 70.5})

    def test_every_one_of_the_eight_lines_persists(self):
        body = {k: 50 + i for i, k in enumerate(dt.ALL_LINE_KEYS)}
        # warn must sit below crit in each pair, so give the crit lines more
        for m in ("",) + dt.MEDIA:
            wk, ck = dt.line_keys(m)
            body[wk], body[ck] = 40.0, 60.0
        box = self.patch(body)
        self.assertEqual(box["status"], 200, box)
        got = self.stored()
        for k, v in body.items():
            self.assertEqual(got.get(k), v, f"{k} did not persist (the save-whitelist gotcha)")

    def test_a_null_removes_one_line_and_leaves_the_others(self):
        self.patch({"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50, "diskio_warn_percent": 80})
        self.patch({"drivetemp_hdd_warn_c": None})
        got = self.stored()
        self.assertNotIn("drivetemp_hdd_warn_c", got)
        self.assertEqual(got.get("drivetemp_hdd_crit_c"), 50.0)
        self.assertEqual(got.get("diskio_warn_percent"), 80.0)

    def test_what_is_not_a_line_is_refused_with_a_sentence_the_page_can_translate(self):
        for bad in (0, -1, 151, 9999, 10 ** 400, True, "hot", "50", "", [], {}, float("nan")):
            with self.subTest(value=repr(bad)[:20]):
                box = self.patch({"drivetemp_hdd_warn_c": bad})
                self.assertEqual(box["status"], 400, box)
                self.assertEqual(box["body"]["error"], "The drive temperature lines must be a number from 1 to 150")
                self.assertEqual(box["body"]["field"], "drivetemp_hdd_warn_c")
        self.assertNotIn("drivetemp_hdd_warn_c", self.stored())

    def test_a_warning_line_at_or_above_the_critical_one_is_refused(self):
        for warn, crit in ((50, 45), (50, 50)):
            box = self.patch({"drivetemp_ssd_warn_c": warn, "drivetemp_ssd_crit_c": crit})
            self.assertEqual(box["status"], 400, (warn, crit))
            self.assertEqual(box["body"]["error"], "A drive temperature warning line must be below its critical line")
        self.assertEqual(self.stored(), {})

    def test_the_order_is_judged_against_what_the_host_already_has(self):
        self.patch({"drivetemp_ssd_crit_c": 70})
        box = self.patch({"drivetemp_ssd_warn_c": 75})
        self.assertEqual(box["status"], 400)
        self.assertEqual(self.patch({"drivetemp_ssd_warn_c": 65})["status"], 200)

    def test_a_drives_own_lines_are_saved_against_its_serial(self):
        box = self.patch({"drivetemp_per_serial": {"WD-1234": {"warn": 45, "crit": 50}}})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(self.stored()["drivetemp_per_serial"], {"WD-1234": {"warn": 45.0, "crit": 50.0}})

    def test_the_body_names_the_drives_it_changes_and_the_rest_keep_what_they_have(self):
        self.patch({"drivetemp_per_serial": {"A": {"warn": 40, "crit": 45}, "B": {"warn": 50, "crit": 55}}})
        self.patch({"drivetemp_per_serial": {"A": {"crit": 48}}})
        mine = self.stored()["drivetemp_per_serial"]
        self.assertEqual(mine["A"], {"warn": 40.0, "crit": 48.0}, "one number changed, the other kept")
        self.assertEqual(mine["B"], {"warn": 50.0, "crit": 55.0}, "a drive the body did not name keeps its lines")

    def test_a_null_removes_a_number_or_the_whole_drive(self):
        self.patch({"drivetemp_per_serial": {"A": {"warn": 40, "crit": 45}, "B": {"warn": 50}}})
        self.patch({"drivetemp_per_serial": {"A": {"warn": None}, "B": None}})
        self.assertEqual(self.stored()["drivetemp_per_serial"], {"A": {"crit": 45.0}})
        self.patch({"drivetemp_per_serial": {"A": {"crit": None}}})
        self.assertNotIn("drivetemp_per_serial", self.stored(), "the last number gone, nothing left to keep")

    def test_an_empty_entry_keeps_nothing(self):
        self.patch({"drivetemp_per_serial": {"A": {"warn": 40}}})
        self.patch({"drivetemp_per_serial": {"A": {}, "": {"warn": 40}, "   ": {"warn": 40}}})
        self.assertEqual(self.stored()["drivetemp_per_serial"], {"A": {"warn": 40.0}}, "an empty entry changes nothing")

    def test_a_drives_lines_are_checked_like_the_hosts(self):
        for entry in ({"warn": 0}, {"crit": 200}, {"warn": True}, {"warn": "x"}, {"warn": [1]}):
            box = self.patch({"drivetemp_per_serial": {"A": entry}})
            self.assertEqual(box["status"], 400, entry)
            self.assertEqual(box["body"]["error"], "The drive temperature lines must be a number from 1 to 150")
        box = self.patch({"drivetemp_per_serial": {"A": {"warn": 50, "crit": 45}}})
        self.assertEqual(box["status"], 400)
        self.assertEqual(box["body"]["error"], "A drive temperature warning line must be below its critical line")
        self.assertNotIn("drivetemp_per_serial", self.stored())

    def test_the_wrong_shape_is_refused(self):
        for body in ({"drivetemp_per_serial": [1]}, {"drivetemp_per_serial": "x"}, {"drivetemp_per_serial": 5}):
            self.assertEqual(self.patch(body)["status"], 400, body)
        box = self.patch({"drivetemp_per_serial": {"A": 5}})
        self.assertEqual(box["status"], 400)
        self.assertEqual(box["body"]["error"], "The lines of a drive must be an object with a warn and a crit line")

    def test_a_host_keeps_at_most_128_drives(self):
        many = {f"S{i}": {"warn": 40} for i in range(dt.MAX_PER_HOST)}
        self.assertEqual(self.patch({"drivetemp_per_serial": many})["status"], 200)
        self.assertEqual(len(self.stored()["drivetemp_per_serial"]), 128)
        box = self.patch({"drivetemp_per_serial": {"one more": {"warn": 40}}})
        self.assertEqual(box["status"], 400)
        self.assertEqual(box["body"], {"error": "Too many drive lines for one host", "limit": 128})
        self.assertEqual(len(self.stored()["drivetemp_per_serial"]), 128)

    def test_a_serial_is_cleaned_and_cut(self):
        self.patch({"drivetemp_per_serial": {"  WD-1  ": {"warn": 40}, "x" * 200: {"warn": 41}}})
        keys = sorted(self.stored()["drivetemp_per_serial"])
        self.assertIn("WD-1", keys)
        self.assertEqual(max(len(k) for k in keys), 64)

    def test_other_saves_do_not_wipe_the_drives(self):
        """The form saves a field at a time; a save of the busy lines must leave the drive lines alone."""
        self.patch({"drivetemp_per_serial": {"A": {"warn": 40}}, "drivetemp_hdd_warn_c": 45})
        self.patch({"diskio_warn_percent": 80})
        got = self.stored()
        self.assertEqual(got["drivetemp_per_serial"], {"A": {"warn": 40.0}})
        self.assertEqual(got["drivetemp_hdd_warn_c"], 45.0)

    def test_only_an_administrator_may_set_them(self):
        """Through the real sign-in and role gate: only verify_token is stubbed, and it says viewer."""
        names = ("verify_token", "get_token_from_request", "method", "get_json_obj", "respond")
        keep = {n: getattr(api, n) for n in names}
        box = {}
        api.verify_token = lambda t: ("bob", "viewer")
        api.get_token_from_request = lambda: "t"
        api.method = lambda: "PATCH"
        api.get_json_obj = lambda: {"drivetemp_warn_c": 45}

        def _resp(status, data=None):
            box["status"] = status
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_device_metric_thresholds(DEV)
            except api.HTTPError:
                pass
        finally:
            for n, v in keep.items():
                setattr(api, n, v)
        self.assertIn(box.get("status"), (401, 403))
        self.assertNotIn("drivetemp_warn_c", self.stored())

    def test_the_get_answer_carries_the_fleets_lines_as_what_a_host_falls_back_to(self):
        self.lines(drivetemp_hdd_warn_c=45, drivetemp_hdd_crit_c=50)
        self.patch({"drivetemp_hdd_warn_c": 48})
        box = _call(api.handle_device_metric_thresholds, {}, DEV, verb="GET")
        self.assertEqual(box["status"], 200, box)
        body = box["body"]
        self.assertEqual(body["defaults"]["drivetemp_hdd_warn_c"], 45)
        self.assertEqual(body["defaults"]["drivetemp_hdd_crit_c"], 50)
        self.assertEqual(body["defaults"]["drivetemp_nvme_warn_c"], 0, "no fleet line shows as 0")
        self.assertEqual(body["effective"]["drivetemp_hdd_warn_c"], 48.0)
        self.assertEqual(body["effective"]["drivetemp_hdd_crit_c"], 50)
        self.assertEqual(body["overrides"]["drivetemp_hdd_warn_c"], 48.0)
        json.dumps(body, allow_nan=False)


class TestTheFleetsSettings(_Drives):

    def save(self, body):
        box = _call(api.handle_config_save, body)
        return box["status"], (api.load(api.CONFIG_FILE) or {})

    def test_the_eight_lines_are_saved(self):
        body = {k: str(40 + i) for i, k in enumerate(dt.ALL_LINE_KEYS)}
        for m in ("",) + dt.MEDIA:
            wk, ck = dt.line_keys(m)
            body[wk], body[ck] = "40", "60"
        status, cfg = self.save(body)
        self.assertEqual(status, 200)
        for k in dt.ALL_LINE_KEYS:
            self.assertIn(cfg.get(k), (40, 60), f"{k} did not persist (the save-whitelist gotcha)")

    def test_out_of_range_and_words_are_refused_as_every_other_alert_parameter_is(self):
        for body in ({"drivetemp_hdd_warn_c": 151}, {"drivetemp_hdd_warn_c": -1}, {"drivetemp_nvme_crit_c": "hot"}):
            with self.subTest(body=body):
                status, _cfg = self.save(body)
                self.assertEqual(status, 400)

    def test_a_warning_line_at_or_above_the_critical_one_is_refused(self):
        status, _ = self.save({"drivetemp_ssd_warn_c": 70, "drivetemp_ssd_crit_c": 65})
        self.assertEqual(status, 400)
        box = _call(api.handle_config_save, {"drivetemp_ssd_warn_c": 70, "drivetemp_ssd_crit_c": 70})
        self.assertEqual(box["body"]["error"], "A drive temperature warning line must be below its critical line")
        self.assertEqual(box["body"]["field"], "drivetemp_ssd_warn_c")

    def test_zero_is_a_line_that_is_off_and_not_an_inverted_pair(self):
        status, cfg = self.save({"drivetemp_ssd_warn_c": 65, "drivetemp_ssd_crit_c": 0})
        self.assertEqual(status, 200)
        self.assertEqual(cfg["drivetemp_ssd_crit_c"], 0)
        self.assertEqual(dt.resolve("S1", "ssd", None, {}, cfg), (65.0, math.inf), "0 is no line")

    def test_blank_puts_a_line_back_to_nothing(self):
        self.save({"drivetemp_hdd_warn_c": 45})
        _s, cfg = self.save({"drivetemp_hdd_warn_c": ""})
        self.assertNotIn("drivetemp_hdd_warn_c", cfg)

    def test_the_defaults_are_off(self):
        box = _call(api.handle_config_get, {}, verb="GET")
        self.assertEqual(box["status"], 200)
        for k in dt.ALL_LINE_KEYS:
            self.assertEqual(box["body"].get(k), 0, k)

    def test_the_model_accepts_every_line_and_an_empty_body(self):
        import request_models as rm
        for k in dt.ALL_LINE_KEYS:
            ok, err = rm.validate(rm.ConfigSaveRequest, {k: "5"})
            self.assertTrue(ok, f"{k}: {err}")
        ok, err = rm.validate(rm.ConfigSaveRequest, {})
        self.assertTrue(ok, err)

    def test_what_a_save_sets_is_what_the_next_report_is_held_to(self):
        """The Settings pane to the alert, with nothing in between faked."""
        self.save({"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50})
        self.report(drv("H1", 47, media="hdd"))
        self.assertEqual(self.drive_events(), [("metric_warning", "H1", 47.0, 45.0)])


class TestWhatTheHardwareTabIsGiven(_Drives):

    def hardware(self):
        box = _call(api.handle_device_hardware, {}, DEV, verb="GET")
        self.assertEqual(box["status"], 200, box)
        return {d["serial"]: d for d in box["body"]["smart"]}

    def test_each_drive_carries_its_type_its_lines_and_what_its_boxes_inherit(self):
        self.lines(drivetemp_hdd_warn_c=45, drivetemp_hdd_crit_c=50, drivetemp_nvme_warn_c=70)
        self.host_lines(drivetemp_per_serial={"H2": {"warn": 41}})
        self.report(drv("H1", 40, media="hdd"), drv("H2", 40, device="/dev/sdb", media="hdd"),
                    drv("N1", 40, device="/dev/nvme0n1"), drv("U1", 40, device="/dev/sdc"))
        got = self.hardware()
        self.assertEqual(got["H1"]["lines"]["media"], "hdd")
        self.assertEqual((got["H1"]["lines"]["warn"], got["H1"]["lines"]["crit"]), (45.0, 50.0))
        self.assertNotIn("own", got["H1"]["lines"])
        self.assertEqual((got["H2"]["lines"]["warn"], got["H2"]["lines"]["crit"]), (41.0, 50.0))
        self.assertEqual(got["H2"]["lines"]["own"], {"warn": 41.0, "crit": None})
        self.assertEqual(got["H2"]["lines"]["inherit"], {"warn": 45.0, "crit": 50.0})
        self.assertEqual(got["N1"]["lines"]["media"], "nvme", "from the device name")
        self.assertEqual((got["N1"]["lines"]["warn"], got["N1"]["lines"]["crit"]), (70.0, None))
        self.assertEqual((got["U1"]["lines"]["warn"], got["U1"]["lines"]["crit"]), (None, None))

    def test_the_answer_has_no_infinity(self):
        self.lines(drivetemp_warn_c=45)
        self.report(drv("S1", 30))
        box = _call(api.handle_device_hardware, {}, DEV, verb="GET")
        json.dumps(box["body"], allow_nan=False)


# ── the Linux agent's reading of the kind of drive ─────────────────────────────────────────────────

_ATA_HDD = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux] (local build)
=== START OF INFORMATION SECTION ===
Device Model:     WDC WD40EFRX-68N32N0
Serial Number:    WD-WCC7K1234567
Rotation Rate:    5400 rpm
Form Factor:      3.5 inches
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
194 Temperature_Celsius     0x0022   115   100   000    Old_age   Always       -       35
"""

_ATA_SSD = _ATA_HDD.replace("WDC WD40EFRX-68N32N0", "Samsung SSD 870 EVO").replace(
    "5400 rpm", "Solid State Device").replace("WD-WCC7K1234567", "S5Y1NX0T123456")

_NO_RATE = "\n".join(ln for ln in _ATA_HDD.splitlines() if not ln.startswith("Rotation Rate"))

_NVME = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux] (local build)
=== START OF INFORMATION SECTION ===
Model Number:                       Samsung SSD 980 1TB
Serial Number:                      S64ANS0T123456
=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED
Temperature:                        41 Celsius
"""


class TestTheAgentReadsTheKindOfDrive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from test_v643_smart_standby import _agent
        cls.ag = _agent()

    def collect(self, per_device):
        from test_v643_smart_standby import _FakeRun
        ag = self.ag
        saved = (ag.subprocess.run, ag._which, ag._list_block_devices)
        ag.subprocess.run = _FakeRun(per_device)
        ag._which = lambda n: "/usr/sbin/smartctl" if n == "smartctl" else None
        ag._list_block_devices = lambda: list(per_device)
        try:
            return {d["device"]: d for d in ag.get_smart_status()}
        finally:
            (ag.subprocess.run, ag._which, ag._list_block_devices) = saved

    def test_a_spinning_disk_is_a_hdd_and_a_solid_state_one_is_an_ssd(self):
        got = self.collect({"/dev/sda": _ATA_HDD, "/dev/sdb": _ATA_SSD})
        self.assertEqual(got["/dev/sda"]["media"], "hdd")
        self.assertEqual(got["/dev/sdb"]["media"], "ssd")
        self.assertEqual(got["/dev/sda"]["serial"], "WD-WCC7K1234567", "and the rest is read as before")

    def test_an_nvme_drive_is_known_by_its_name(self):
        got = self.collect({"/dev/nvme0n1": _NVME})
        self.assertEqual(got["/dev/nvme0n1"]["media"], "nvme")
        self.assertEqual(got["/dev/nvme0n1"]["temperature_c"], 41)

    def test_a_drive_that_does_not_say_is_left_untyped(self):
        got = self.collect({"/dev/sdc": _NO_RATE})
        self.assertNotIn("media", got["/dev/sdc"])
        self.assertEqual(got["/dev/sdc"]["health"], "PASSED")

    def test_a_rate_it_cannot_read_is_left_untyped_and_not_guessed(self):
        odd = _ATA_HDD.replace("5400 rpm", "Unknown")
        self.assertNotIn("media", self.collect({"/dev/sdd": odd})["/dev/sdd"])

    def test_the_two_copies_of_the_agent_agree(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(),
                         (ROOT / "client" / "remotepower-agent.py").read_bytes())

    def test_the_other_agents_are_not_claimed_to_send_it(self):
        """Windows reports its drives without a type; they are 'any drive' to the lines. If that agent
        starts to send one this test says so, and the docs need a sentence."""
        win = (ROOT / "client" / "remotepower-agent-win.py").read_text(encoding="utf-8")
        self.assertNotIn("'media'", win)


class TestTheModuleIsRegistered(unittest.TestCase):
    """A new module goes in the lint and type lists the day it is made (the Makefile says so)."""

    def test_it_is_in_both_lists(self):
        mk = (ROOT / "Makefile").read_text()
        self.assertEqual(mk.count("server/cgi-bin/drive_temp.py"), 2)

    def test_it_imports_nothing_of_the_server(self):
        import ast
        tree = ast.parse((_CGI / "drive_temp.py").read_text())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertTrue(names <= {"__future__", "math", "typing"}, names)


if __name__ == "__main__":
    unittest.main()
