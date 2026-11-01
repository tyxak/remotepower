#!/usr/bin/env python3
"""Issue #54, the reporter's last comment: a drive's own sensors on the Thermal page.

Reported on 7.4.6: "the raw NVMe sensors (nvme-pci-xxxx "Sensor 1" and "Sensor 2") report a critical value of 65261.8,
which the page takes as real. On one host that sensor is the hottest, so the host's row reads "threshold 65261.8 C,
headroom 65215.9". The raw drivetemp sensors report a critical value of 0. Could crit values like these be ignored, and the
raw NVMe and drivetemp sensors fall under the drive's lines?"

Two changes are held here, through the real functions:

  1. A limit that is not a temperature is no limit. An NVMe drive that sets no threshold reports 65535 K, which is
     65261.85 C, and a drivetemp sensor with no limit reports 0. The agent took a sensor's `_crit` and fell back to its
     `_max`, so both went to the page as the sensor's critical value. The agent stops sending them, the server drops them
     on the way in, and the Thermal page ignores one that is already stored.
  2. The sensors of a drive's own chip follow the drive lines on the Thermal page and in the risk score: `nvme-*` the NVMe
     lines, `drivetemp-*` the lines for any drive (the chip name does not say hard disk or SSD). The temp_high alert and
     the reliability grade still judge them by the fleet's settings.

The lm-sensors output below is a shape built from the two numbers in the report, not a capture from their host.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))

import api  # noqa: E402
import drive_temp  # noqa: E402

NOW = int(time.time())
NVME_UNSET = 65261.85      # 65535 K in C: what an NVMe drive reports for a threshold it does not set


class TestWhichSensorsAreADrives(unittest.TestCase):

    def test_the_chip_name_in_front_of_the_label_says_so(self):
        for label, media in (("nvme-pci-0100/Composite", "nvme"), ("nvme-pci-0100/Sensor 1", "nvme"),
                             ("NVME-pci-0100/Sensor 2", "nvme"), ("drivetemp-scsi-0-0/temp1", ""),
                             ("drivetemp-scsi-4-0/temp1", "")):
            self.assertEqual(drive_temp.sensor_media(label), media, label)

    def test_a_board_sensor_and_anything_else_is_not_a_drive(self):
        for label in ("coretemp-isa-0000/Package id 0", "nct6798-isa-0290/AUXTIN2", "k10temp-pci-00c3/Tctl",
                      "acpitz-acpi-0/temp1", "cpu", "nvmefoo/x", "drivetempfoo/x", "x/nvme-pci-0100", "", None, 5, {}, []):
            self.assertIsNone(drive_temp.sensor_media(label), label)


def _load_agent():
    spec = importlib.util.spec_from_file_location("rp_agent_raw_drive_sensors", ROOT / "client" / "remotepower-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sensors(chips):
    """What the agent's own reader makes of `sensors -A -j` printing `chips`, with nothing else on the host answering."""
    agent = _load_agent()

    def run(cmd, *a, **k):
        if list(cmd) == ["sensors", "-A", "-j"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(chips), stderr="")
        raise FileNotFoundError(cmd[0] if cmd else "")

    with mock.patch.object(agent, "_which", lambda prog, *a, **k: "/usr/bin/sensors" if prog == "sensors" else None), \
            mock.patch.object(subprocess, "run", run):
        return {t["label"]: t for t in agent.get_hardware_inventory().get("temps", [])}


CHIPS = {
    "nvme-pci-0100": {
        "Adapter": "PCI adapter",
        "Composite": {"temp1_input": 38.85, "temp1_max": 83.85, "temp1_min": -273.15, "temp1_crit": 87.85, "temp1_alarm": 0.0},
        "Sensor 1": {"temp2_input": 45.9, "temp2_max": NVME_UNSET, "temp2_min": -273.15},
        "Sensor 2": {"temp3_input": 41.9, "temp3_max": NVME_UNSET, "temp3_min": -273.15},
    },
    "drivetemp-scsi-0-0": {
        "Adapter": "SCSI adapter",
        "temp1": {"temp1_input": 37.0, "temp1_max": 0.0, "temp1_min": 0.0, "temp1_crit": 0.0, "temp1_lcrit": 0.0},
    },
    "coretemp-isa-0000": {
        "Adapter": "ISA adapter",
        "Package id 0": {"temp1_input": 52.0, "temp1_max": 100.0, "temp1_crit": 100.0, "temp1_crit_alarm": 0.0},
    },
    "foo-isa-0000": {"Adapter": "ISA adapter", "temp1": {"temp1_input": 40.0, "temp1_max": 90.0}},
    "bar-isa-0000": {"Adapter": "ISA adapter", "temp1": {"temp1_input": 41.0, "temp1_crit": 0.0, "temp1_max": 60.0}},
}


class TestTheAgentStopsSendingAFalseLimit(unittest.TestCase):
    """The agent's own reader, run on the output shape of the report."""

    @classmethod
    def setUpClass(cls):
        cls.temps = _sensors(CHIPS)

    def test_an_unset_nvme_threshold_is_not_sent_as_a_limit(self):
        for label in ("nvme-pci-0100/Sensor 1", "nvme-pci-0100/Sensor 2"):
            self.assertNotIn("crit_c", self.temps[label], self.temps[label])

    def test_a_limit_of_zero_is_not_sent(self):
        self.assertNotIn("crit_c", self.temps["drivetemp-scsi-0-0/temp1"])

    def test_the_composite_sensor_and_a_board_sensor_keep_theirs(self):
        self.assertEqual(self.temps["nvme-pci-0100/Composite"]["crit_c"], 87.8)
        self.assertEqual(self.temps["coretemp-isa-0000/Package id 0"]["crit_c"], 100.0)

    def test_a_sensor_with_only_a_max_still_uses_it_and_a_false_crit_falls_through_to_a_real_max(self):
        self.assertEqual(self.temps["foo-isa-0000/temp1"]["crit_c"], 90.0)
        self.assertEqual(self.temps["bar-isa-0000/temp1"]["crit_c"], 60.0)

    def test_every_sensor_is_still_reported(self):
        self.assertEqual(len(self.temps), 7, sorted(self.temps))


class _Fleet(unittest.TestCase):

    def setUp(self):
        self._orig = {k: getattr(api, k) for k in ("require_auth", "_caller_scope", "_tenant_gate")}
        api.require_auth = lambda require_admin=False: "tester"
        api._caller_scope = lambda: None
        api._tenant_gate = lambda: None
        self.config({})
        api.save(api.DEVICES_FILE, {})
        api.save(api.HARDWARE_FILE, {})

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)
        for f in (api.CONFIG_FILE, api.DEVICES_FILE, api.HARDWARE_FILE, api.THERMAL_HIST_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()

    def config(self, cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def stored(self, temps, smart=(), host=None, ignores=None):
        """One host whose stored hardware record holds `temps` as they are (an older agent's report, say)."""
        dev = {"name": "h1", "last_seen": NOW, "sysinfo": {}}
        if host is not None:
            dev["metric_thresholds"] = host
        if ignores:
            dev["sensor_ignores"] = list(ignores)
        api.save(api.DEVICES_FILE, {"h1": dev})
        api.save(api.HARDWARE_FILE, {"h1": {"ts": NOW, "smart": [dict(s) for s in smart],
                                            "hardware": {"temps": [dict(t) for t in temps]}}})
        api._LOAD_CACHE.clear()

    def page(self):
        try:
            api.handle_fleet_thermal()
        except api.HTTPError as e:
            return e.body
        self.fail("no answer")

    def row(self):
        rows = [r for r in self.page()["hosts"] if r["device_id"] == "h1"]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def risk(self):
        dev = api.load(api.DEVICES_FILE)["h1"]
        hw = api.load(api.HARDWARE_FILE)["h1"]
        out = api._device_risk("h1", dev, {}, {}, {}, NOW, 300, hw_rec=hw)
        return [f for f in out.get("factors") or [] if f.get("kind") == "overheating"]


def sensor(label, temp, crit=None):
    return dict({"label": label, "current_c": temp}, **({} if crit is None else {"crit_c": crit}))


NVME1 = "nvme-pci-0100/Sensor 1"
DRIVE = "drivetemp-scsi-0-0/temp1"
BOARD = "coretemp-isa-0000/Package id 0"


class TestTheServerDropsAFalseLimit(_Fleet):

    def ingest(self, temps):
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        api._ingest_hardware("h1", "h1", {"hardware": {"temps": temps}, "smart": []}, NOW,
                             dev=api.load(api.DEVICES_FILE)["h1"])
        api._LOAD_CACHE.clear()
        return {t["label"]: t for t in api.load(api.HARDWARE_FILE)["h1"]["hardware"]["temps"]}

    def test_an_older_agent_sending_one_is_not_stored_with_it(self):
        got = self.ingest([sensor(NVME1, 45.9, 65261.8), sensor(DRIVE, 37.0, 0.0), sensor(BOARD, 52.0, 100.0),
                           sensor("a/low", 40.0, 0.9), sensor("a/edge", 40.0, 150.0), sensor("a/over", 40.0, 150.1)])
        for label in (NVME1, DRIVE, "a/low", "a/over"):
            self.assertNotIn("crit_c", got[label], got[label])
        self.assertEqual(got[BOARD]["crit_c"], 100.0)
        self.assertEqual(got["a/edge"]["crit_c"], 150.0)

    def test_the_readings_themselves_are_kept(self):
        got = self.ingest([sensor(NVME1, 45.9, 65261.8)])
        self.assertEqual(got[NVME1]["current_c"], 45.9)


class TestAStoredFalseLimitIsNotShown(_Fleet):
    """Rows an older agent already stored are read through the same rule."""

    def test_the_report_of_the_issue_has_no_threshold_and_no_headroom(self):
        self.stored([sensor(NVME1, 45.9, 65261.8)])
        r = self.row()
        self.assertEqual((r["sensor_label"], r["max_temp"], r["crit_c"], r["headroom"]), (NVME1, 45.9, None, None))
        self.assertEqual((r["hot"], r["critical"]), (False, False))
        self.assertIsNone(r["detail"][0]["crit"])

    def test_a_limit_of_zero_has_no_threshold_and_no_negative_headroom(self):
        self.stored([sensor(DRIVE, 37.0, 0.0)])
        r = self.row()
        self.assertEqual((r["crit_c"], r["headroom"]), (None, None))

    def test_a_real_limit_is_shown_as_it_was(self):
        self.stored([sensor(BOARD, 60.0, 100.0)])
        r = self.row()
        self.assertEqual((r["crit_c"], r["headroom"]), (100.0, 40.0))


class TestTheLinesApplyToADrivesOwnSensors(_Fleet):

    def test_with_no_line_set_nothing_changes(self):
        """The control: an install that sets no drive line reads as it did. A raw sensor is held to the fleet's 75 and 85."""
        self.stored([sensor(NVME1, 80.0), sensor(DRIVE, 40.0)])
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["warn_c"]), (True, False, None, None))

    def test_an_nvme_sensor_is_held_to_the_nvme_lines(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor(NVME1, 45.9, 65261.8)])
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["warn_c"], r["crit_c"], r["headroom"]), (True, False, 45.0, 50.0, 4.1))
        self.assertEqual((r["detail"][0]["level"], r["detail"][0]["warn"], r["detail"][0]["crit"]), ("hot", 45.0, 50.0))
        self.assertEqual(self.page()["hot"], 1)

    def test_the_line_is_the_edge_and_below_it_is_fine(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        for temp, hot, critical in ((44.9, False, False), (45.0, True, False), (49.9, True, False), (50.0, True, True)):
            self.stored([sensor(NVME1, temp)])
            r = self.row()
            self.assertEqual((r["hot"], r["critical"]), (hot, critical), temp)
        self.stored([sensor(NVME1, 44.0)])
        r = self.row()
        self.assertEqual((r["crit_c"], r["warn_c"], r["headroom"]), (50.0, 45.0, 6.0))
        self.assertEqual(r["detail"][0]["level"], "ok")

    def test_a_drivetemp_sensor_is_held_to_the_lines_for_any_drive_and_not_to_the_nvme_ones(self):
        self.config({"drivetemp_nvme_warn_c": 20, "drivetemp_nvme_crit_c": 30})
        self.stored([sensor(DRIVE, 37.0)])
        self.assertEqual((self.row()["hot"], self.row()["crit_c"]), (False, None))
        self.config({"drivetemp_warn_c": 35, "drivetemp_crit_c": 45})
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["warn_c"], r["crit_c"]), (True, False, 35.0, 45.0))

    def test_an_nvme_sensor_falls_back_to_the_lines_for_any_drive(self):
        self.config({"drivetemp_warn_c": 35, "drivetemp_crit_c": 45})
        self.stored([sensor(NVME1, 40.0)])
        r = self.row()
        self.assertEqual((r["hot"], r["warn_c"], r["crit_c"]), (True, 35.0, 45.0))

    def test_a_board_sensor_is_never_held_to_a_drive_line(self):
        self.config({"drivetemp_nvme_warn_c": 30, "drivetemp_nvme_crit_c": 40, "drivetemp_warn_c": 30, "drivetemp_crit_c": 40})
        self.stored([sensor(BOARD, 50.0, 100.0)])
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["warn_c"]), (False, False, 100.0, None))

    def test_the_hosts_line_beats_the_fleets(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor(NVME1, 46.5)], host={"drivetemp_nvme_crit_c": 46})
        r = self.row()
        self.assertEqual((r["critical"], r["crit_c"]), (True, 46.0))

    def test_a_warning_line_on_its_own_is_never_critical(self):
        self.config({"drivetemp_nvme_warn_c": 40})
        self.stored([sensor(NVME1, 90.0)])
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"]), (True, False, None))

    def test_the_line_kept_against_a_serial_number_is_for_the_drives_own_reading_and_not_its_sensors(self):
        smart = {"device": "/dev/nvme0n1", "serial": "SER-1", "media": "nvme", "temperature_c": 18}
        self.stored([sensor(NVME1, 45.9)], smart=[smart], host={"drivetemp_per_serial": {"SER-1": {"warn": 20, "crit": 25}}})
        r = self.row()
        self.assertEqual((r["sensor_label"], r["hot"], r["critical"], r["crit_c"]), (NVME1, False, False, None),
                         "the sensor has no serial number to match a line to; the drive itself is under its line")

    def test_an_ignored_sensor_is_still_not_counted(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor(NVME1, 90.0), sensor(BOARD, 40.0, 100.0)], ignores=[NVME1])
        r = self.row()
        self.assertEqual((r["sensor_label"], r["hot"], r["critical"]), (BOARD, False, False))
        self.assertTrue(next(d for d in r["detail"] if d["label"] == NVME1)["ignored"])


class TestTheRiskScoreFollowsToo(_Fleet):

    def test_with_no_line_set_a_raw_drive_sensor_is_judged_as_it_was(self):
        self.stored([sensor(NVME1, 45.9)])
        self.assertEqual(self.risk(), [])
        self.stored([sensor(NVME1, 80.0)])
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("hottest sensor at 80", f[0]["detail"])

    def test_a_raw_nvme_sensor_over_its_line_counts(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor(NVME1, 45.9)])
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("45.9", f[0]["detail"])
        self.assertIn("hot", f[0]["detail"])
        self.stored([sensor(NVME1, 51.0)])
        full = self.risk()
        self.assertIn("critical", full[0]["detail"])
        self.assertGreater(full[0]["points"], f[0]["points"])

    def test_below_the_line_it_does_not(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor(NVME1, 44.0)])
        self.assertEqual(self.risk(), [])

    def test_a_board_sensor_is_not_held_to_a_drive_line(self):
        self.config({"drivetemp_nvme_warn_c": 30, "drivetemp_nvme_crit_c": 40})
        self.stored([sensor(BOARD, 50.0, 100.0)])
        self.assertEqual(self.risk(), [])


if __name__ == "__main__":
    unittest.main()
