#!/usr/bin/env python3
"""7.4.9: a host profile carries every numeric line a single host can be given.

A host profile is a named bundle of per-host settings that **Apply** stamps onto the hosts you pick. Its metric thresholds were
checked by a table of their own, written when the profile feature was, and the per-host editor went on getting lines the table never
heard of: how busy a disk may be (7.4.3), the drive temperatures (7.4.4), the mail queue, and the I/O wait and steal lines of
7.4.9. A profile that named one of those had it dropped without a word, because the validator skipped keys it did not know.

The population is read from the code: every name the per-host handler checks. For each, the profile has to keep the number, refuse
a bad one with a 400, and refuse a warning line that sits on or above its critical line.
"""
import inspect
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v741_nic_per_host import _Base  # noqa: E402
from test_v622_alert_params import ROOT, api  # noqa: E402

sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import drive_temp  # noqa: E402

# a value inside the range of each kind of line. A host's own warning line is checked against the default critical line and the other
# way round, so a warning line is a low number and a critical line a high one.
LOW = {"percent": 10, "ratio": 0.5, "celsius": 20, "count": 5, "min": 5, "c": 20}
HIGH = {"percent": 98, "ratio": 50.0, "celsius": 150, "count": 900000, "min": 5, "c": 140}


def good(name):
    return (HIGH if "_crit_" in name or name.endswith("_crit_c") else LOW)[kind(name)]


def candidates():
    """The names the per-host handler's source mentions that look like a line, plus the ones it takes from constants. Some of them
    are only read back for the editor (the recovery buffer), so this is a list to try, not the population."""
    src = inspect.getsource(api.handle_device_metric_thresholds)
    names = set(re.findall(r"'([a-z0-9_]+_(?:percent|ratio|celsius|count|min|c))'", src))
    return sorted(names | set(api._CPU_TIME_LINE_KEYS) | set(drive_temp.ALL_LINE_KEYS))


def kind(name):
    return name.rsplit("_", 1)[1]


def validate(mt):
    try:
        return api._validate_device_profile({"name": "p", "metric_thresholds": mt})
    except api.HTTPError as e:
        return e


class _Population(_Base):
    """The lines a host can be given: the ones the real per-host handler stores when it is sent one."""

    def population(self):
        out = []
        for name in candidates():
            api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "h", "token": "t", "sysinfo": {}, "metric_thresholds": {}}})
            api._invalidate_load_cache(api.DEVICES_FILE)
            status, _body = self.call("PATCH", {name: good(name)})
            if status == 200 and name in self.stored():
                out.append(name)
        return out


class TestEveryLineAHostCanHave(_Population):

    def test_the_population_is_the_one_the_handler_stores(self):
        names = self.population()
        self.assertEqual(len(names), 30, names)
        for known in ("mem_warn_percent", "diskio_warn_percent", "iowait_crit_percent", "steal_warn_percent", "mailq_crit_count",
                      "nic_drop_alert_min", "drivetemp_hdd_crit_c", "cpu_warn_load_ratio", "temp_crit_celsius"):
            self.assertIn(known, names)
        self.assertIn("recovery_buffer_percent", candidates(), "the handler mentions it")
        self.assertNotIn("recovery_buffer_percent", names, "and does not take it: it is only shown to the editor")

    def test_a_profile_keeps_the_number_of_each(self):
        kept = {}
        for name in self.population():
            out = validate({name: good(name)})
            self.assertIsInstance(out, dict, f"{name}: {getattr(out, 'body', out)}")
            kept[name] = out["metric_thresholds"].get(name)
            self.assertEqual(kept[name], good(name), name)
        self.assertEqual(len(kept), len(self.population()))

    def test_a_count_stays_whole_and_the_rest_are_numbers(self):
        out = validate({"mailq_warn_count": 100.0, "nic_err_alert_min": 5.0, "diskio_warn_percent": 40})["metric_thresholds"]
        self.assertIs(type(out["mailq_warn_count"]), int)
        self.assertIs(type(out["nic_err_alert_min"]), int)
        self.assertIs(type(out["diskio_warn_percent"]), float)

    def test_a_bad_number_is_a_400_for_each_not_a_line_that_goes_missing(self):
        for name in self.population():
            for bad in (True, "x", None, [], {}, -1, 10 ** 9, float("nan"), float("inf")):
                if kind(name) == "min" and bad is None:
                    continue
                with self.subTest(name=name, bad=repr(bad)[:12]):
                    out = validate({name: bad})
                    self.assertIsInstance(out, api.HTTPError, f"{name}={bad!r} was accepted: {out}")
                    self.assertEqual(out.status, 400)

    def test_a_line_outside_its_range_is_refused_at_both_ends(self):
        for name, low, high in (("diskio_warn_percent", 0, 100), ("iowait_crit_percent", 0, 100), ("steal_warn_percent", 0, 100),
                                ("mailq_warn_count", 0, 1000001), ("drivetemp_crit_c", 0, 151)):
            for bad in (low, high):
                self.assertIsInstance(validate({name: bad}), api.HTTPError, (name, bad))
        for name, edge in (("diskio_warn_percent", 1), ("diskio_crit_percent", 99), ("iowait_warn_percent", 1), ("steal_crit_percent", 99),
                           ("mailq_warn_count", 1), ("mailq_crit_count", 1000000), ("drivetemp_warn_c", 1), ("drivetemp_crit_c", 150)):
            self.assertIsInstance(validate({name: edge}), dict, (name, edge))

    def test_a_warning_line_has_to_sit_below_its_critical_line(self):
        for warn, crit in (("diskio_warn_percent", "diskio_crit_percent"), ("iowait_warn_percent", "iowait_crit_percent"),
                           ("steal_warn_percent", "steal_crit_percent"), ("mailq_warn_count", "mailq_crit_count"),
                           ("drivetemp_warn_c", "drivetemp_crit_c"), ("drivetemp_nvme_warn_c", "drivetemp_nvme_crit_c")):
            hi, lo = (80, 30) if kind(warn) != "count" else (800, 300)
            with self.subTest(pair=warn):
                self.assertIsInstance(validate({warn: hi, crit: lo}), api.HTTPError)
                self.assertIsInstance(validate({warn: lo, crit: lo}), api.HTTPError, "on the line is not below it")
                self.assertIsInstance(validate({warn: lo, crit: hi}), dict)
                self.assertIsInstance(validate({warn: hi}), dict, "one line alone has nothing to be above")

    def test_the_per_host_maps_are_not_carried(self):
        out = validate({"disk_per_mount": {"/var": {"warn": 60, "crit": 70}}, "drivetemp_per_serial": {"WD1": {"warn": 40, "crit": 50}},
                        "mem_warn_percent": 80})
        self.assertEqual(out["metric_thresholds"], {"mem_warn_percent": 80.0})

    def test_a_name_nobody_knows_is_still_left_out(self):
        self.assertEqual(validate({"iowait_warning": 20, "nonsense": 1})["metric_thresholds"], {})


class TestAppliedToAHost(unittest.TestCase):

    def test_the_lines_land_beside_the_hosts_own_and_replace_only_their_own(self):
        dev = {"metric_thresholds": {"disk_per_mount": {"/var": {"warn": 60.0, "crit": 70.0}}, "iowait_warn_percent": 10.0, "mem_warn_percent": 70.0}}
        prof = validate({"iowait_warn_percent": 25, "iowait_crit_percent": 40, "diskio_warn_percent": 60, "steal_warn_percent": 5})
        out = api._apply_profile_to_device(dev, prof)["metric_thresholds"]
        self.assertEqual((out["iowait_warn_percent"], out["iowait_crit_percent"], out["diskio_warn_percent"], out["steal_warn_percent"]),
                         (25.0, 40.0, 60.0, 5.0))
        self.assertEqual(out["mem_warn_percent"], 70.0, "a line the profile does not define is the host's own")
        self.assertEqual(out["disk_per_mount"], {"/var": {"warn": 60.0, "crit": 70.0}})

    def test_the_evaluation_reads_the_stamped_lines(self):
        """A line only counts if the check that judges the report reads it from where the profile put it."""
        prof = validate({"iowait_warn_percent": 25, "iowait_crit_percent": 40, "steal_warn_percent": 5, "steal_crit_percent": 15,
                         "diskio_warn_percent": 60, "diskio_crit_percent": 90})
        dev = api._apply_profile_to_device({"metric_thresholds": {}}, prof)
        self.assertEqual(api._resolve_metric_thresholds(dev, "iowait"), (25.0, 40.0))
        self.assertEqual(api._resolve_metric_thresholds(dev, "steal"), (5.0, 15.0))
        self.assertEqual(api._resolve_metric_thresholds(dev, "diskio"), (60.0, 90.0))
        self.assertEqual(api._resolve_metric_thresholds({"metric_thresholds": {}}, "iowait"), (None, None),
                         "a host with no line of its own and no fleet line is not judged")


if __name__ == "__main__":
    unittest.main()
