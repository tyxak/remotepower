#!/usr/bin/env python3
"""Issue #54, the reporter's reply on 7.4.8: a drivetemp sensor is held to the lines of the disk it reads.

Reported on 7.4.8: "One host has hard disks and SATA SSDs on the same controllers, so the drivetemp sensors need two
different pairs. Could each drivetemp-scsi sensor take the type and lines of the disk at that SCSI address (its sysfs
device links to the block device), and fall back to the "any other drive" pair only when that can't be found?"

Held here, through the real functions:

  1. The agent finds the disk behind each drivetemp chip from sysfs. lm-sensors names the chip from the SCSI address,
     `drivetemp-scsi-<host>-<(channel << 8) + (target << 4) + lun in hex>` (libsensors lib/sysfs.c and lib/data.c), a
     packing that loses information, so the agent builds that name from each device and matches it. It never decodes one,
     and two devices that build the same name are both left out.
  2. The server keeps the disk's name at ingest (a block device name, nothing else) and joins it to the SMART entry of
     the same report. The sensor is then held to that disk's lines on the Thermal page and in the risk score, exactly as
     the disk's own SMART reading is, and the row says which disk it is.
  3. A sensor whose disk is not known keeps the lines for any other drive, as before.

The sysfs tree below is built to the layout the kernel makes (checked against this host's own nvme and coretemp hwmon
links), not captured from a host with a drivetemp chip: the machine the tests were written on has none.
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


# ── the agent ────────────────────────────────────────────────────────────────────────────────────────────────────

def _load_agent():
    spec = importlib.util.spec_from_file_location("rp_agent_drivetemp_disk", ROOT / "client" / "remotepower-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build_sysfs(root, devices, other=()):
    """A sysfs tree as the kernel lays it out. `devices` is a list of (hwmon name, "H:C:T:L", [block names]); `other` is
    a list of (hwmon name, chip name, device dir name) for hwmon devices that are not drivetemp.

    Each drivetemp hwmon directory lives inside its SCSI device, which holds `block/<disk>`; the directory holds `name`
    and a relative `device` link back to the SCSI device, spelled the way the kernel spells it (up to the device's parent, then down); /sys/class/hwmon/<hwmon> links to the directory."""
    cls = root / "sys" / "class" / "hwmon"
    cls.mkdir(parents=True, exist_ok=True)
    for i, (hw, addr, blocks) in enumerate(devices):
        host, chan, tgt, _ = addr.split(":")
        scsi = (root / "sys" / "devices" / "pci0000:00" / "0000:00:17.0" / f"ata{i + 1}" / f"host{host}"
                / f"target{host}:{chan}:{tgt}" / addr)
        for b in blocks:
            (scsi / "block" / b).mkdir(parents=True, exist_ok=True)
        hwdir = scsi / "hwmon" / hw
        hwdir.mkdir(parents=True, exist_ok=True)
        (hwdir / "name").write_text("drivetemp\n")
        os.symlink(f"../../../{addr}", hwdir / "device")
        os.symlink(os.path.relpath(hwdir, cls), cls / hw)
    for hw, chip, dev in other:
        d = root / "sys" / "devices" / "platform" / dev / "hwmon" / hw
        d.mkdir(parents=True, exist_ok=True)
        (d / "name").write_text(chip + "\n")
        os.symlink(f"../../../{dev}", d / "device")
        os.symlink(os.path.relpath(d, cls), cls / hw)


def _under(root):
    """The agent's host_path with the tree at `root` standing in for the host's /sys."""
    def hp(p):
        s = os.fspath(p)
        out = str(root) + s if s.startswith("/") else s
        return Path(out) if isinstance(p, Path) else out
    return hp


class _Sysfs(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.agent = _load_agent()
        self._hp = mock.patch.object(self.agent, "host_path", _under(self.root))
        self._hp.start()

    def tearDown(self):
        self._hp.stop()
        self._tmp.cleanup()


class TestTheAgentFindsTheDiskBehindEachChip(_Sysfs):

    def test_the_two_disks_of_the_report_get_their_own_chip(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"]), ("hwmon4", "1:0:0:0", ["sdb"])])
        self.assertEqual(self.agent._drivetemp_disks(), {"drivetemp-scsi-0-0": "sda", "drivetemp-scsi-1-0": "sdb"})

    def test_the_chip_name_packs_channel_target_and_lun_as_libsensors_does(self):
        _build_sysfs(self.root, [("hwmon1", "2:0:1:0", ["sdc"]),     # target 1  -> 0x10
                                 ("hwmon2", "3:1:0:0", ["sdd"]),     # channel 1 -> 0x100
                                 ("hwmon3", "4:0:0:2", ["sde"]),     # lun 2     -> 0x2
                                 ("hwmon4", "5:2:3:1", ["sdf"])])    # 0x200 + 0x30 + 0x1 -> 0x231
        self.assertEqual(self.agent._drivetemp_disks(),
                         {"drivetemp-scsi-2-10": "sdc", "drivetemp-scsi-3-100": "sdd",
                          "drivetemp-scsi-4-2": "sde", "drivetemp-scsi-5-231": "sdf"})

    def test_two_devices_that_pack_to_one_name_are_both_left_out(self):
        """Target 1 and lun 0x10 both pack to 0x10 on host 6, so libsensors names two chips alike. Neither is the other's."""
        _build_sysfs(self.root, [("hwmon1", "6:0:1:0", ["sdg"]), ("hwmon2", "6:0:0:10", ["sdh"]),
                                 ("hwmon3", "7:0:0:0", ["sdi"])])
        self.assertEqual(self.agent._drivetemp_disks(), {"drivetemp-scsi-7-0": "sdi"})

    def test_a_device_with_no_disk_or_with_two_is_left_out(self):
        _build_sysfs(self.root, [("hwmon1", "0:0:0:0", []), ("hwmon2", "1:0:0:0", ["sda", "sdb"]),
                                 ("hwmon3", "2:0:0:0", ["sdc"])])
        self.assertEqual(self.agent._drivetemp_disks(), {"drivetemp-scsi-2-0": "sdc"})

    def test_a_block_name_that_is_not_one_is_left_out(self):
        _build_sysfs(self.root, [("hwmon1", "0:0:0:0", ["bad name"]), ("hwmon2", "1:0:0:0", [".hidden"]),
                                 ("hwmon3", "2:0:0:0", ["sdz"])])
        self.assertEqual(self.agent._drivetemp_disks(), {"drivetemp-scsi-2-0": "sdz"})

    def test_a_hwmon_device_that_is_not_drivetemp_is_ignored(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"])],
                     other=[("hwmon9", "coretemp", "coretemp.0"), ("hwmon8", "nvme", "nvme0")])
        self.assertEqual(self.agent._drivetemp_disks(), {"drivetemp-scsi-0-0": "sda"})

    def test_a_drivetemp_device_that_is_not_on_a_scsi_address_is_ignored(self):
        _build_sysfs(self.root, [], other=[("hwmon5", "drivetemp", "weird.0")])
        self.assertEqual(self.agent._drivetemp_disks(), {})

    def test_a_host_with_no_hwmon_at_all_answers_nothing_and_does_not_raise(self):
        self.assertEqual(self.agent._drivetemp_disks(), {})


def _sensors_json():
    return {
        "drivetemp-scsi-0-0": {"Adapter": "SCSI adapter", "temp1": {"temp1_input": 41.0, "temp1_max": 0.0, "temp1_crit": 0.0}},
        "drivetemp-scsi-1-0": {"Adapter": "SCSI adapter", "temp1": {"temp1_input": 52.0, "temp1_max": 0.0, "temp1_crit": 0.0}},
        "drivetemp-scsi-9-0": {"Adapter": "SCSI adapter", "temp1": {"temp1_input": 39.0, "temp1_max": 0.0, "temp1_crit": 0.0}},
        "coretemp-isa-0000": {"Adapter": "ISA adapter", "Package id 0": {"temp1_input": 52.0, "temp1_crit": 100.0}},
        "nvme-pci-0100": {"Adapter": "PCI adapter", "Composite": {"temp1_input": 38.0, "temp1_crit": 87.8}},
    }


class TestTheInventoryNamesTheDisk(_Sysfs):

    def inventory(self, chips=None):
        chips = _sensors_json() if chips is None else chips

        def run(cmd, *a, **k):
            if list(cmd) == ["sensors", "-A", "-j"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(chips), stderr="")
            raise FileNotFoundError(cmd[0] if cmd else "")

        with mock.patch.object(self.agent, "_which", lambda prog, *a, **k: "/usr/bin/sensors" if prog == "sensors" else None), \
                mock.patch.object(subprocess, "run", run):
            return {t["label"]: t for t in self.agent.get_hardware_inventory().get("temps", [])}

    def test_each_drivetemp_sensor_carries_its_disk(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"]), ("hwmon4", "1:0:0:0", ["sdb"])])
        temps = self.inventory()
        self.assertEqual(temps["drivetemp-scsi-0-0/temp1"]["drive"], "sda")
        self.assertEqual(temps["drivetemp-scsi-1-0/temp1"]["drive"], "sdb")

    def test_a_chip_the_agent_cannot_place_has_no_drive_field(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"])])
        self.assertNotIn("drive", self.inventory()["drivetemp-scsi-9-0/temp1"])

    def test_no_other_sensor_gets_one(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"])])
        temps = self.inventory()
        for label in ("coretemp-isa-0000/Package id 0", "nvme-pci-0100/Composite"):
            self.assertNotIn("drive", temps[label], label)

    def test_every_sensor_is_still_reported_with_its_reading_and_limit(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"]), ("hwmon4", "1:0:0:0", ["sdb"])])
        temps = self.inventory()
        self.assertEqual(len(temps), 5, sorted(temps))
        self.assertEqual(temps["coretemp-isa-0000/Package id 0"]["crit_c"], 100.0)
        self.assertEqual(temps["drivetemp-scsi-0-0/temp1"]["current_c"], 41.0)
        self.assertNotIn("crit_c", temps["drivetemp-scsi-0-0/temp1"])

    def test_a_host_with_no_drivetemp_chip_never_reads_sysfs_for_it(self):
        chips = {"coretemp-isa-0000": _sensors_json()["coretemp-isa-0000"]}
        with mock.patch.object(self.agent, "_drivetemp_disks", side_effect=AssertionError("read sysfs")):
            temps = self.inventory(chips)
        self.assertEqual(list(temps), ["coretemp-isa-0000/Package id 0"])

    def test_a_failure_in_the_walk_does_not_lose_the_temperature_list(self):
        with mock.patch.object(self.agent.os, "listdir", side_effect=RuntimeError("boom")):
            temps = self.inventory()
        self.assertEqual(len(temps), 5)
        self.assertNotIn("drive", temps["drivetemp-scsi-0-0/temp1"])


# ── the pure join ────────────────────────────────────────────────────────────────────────────────────────────────

SMART = [
    {"device": "/dev/sda", "serial": "HDD-A", "media": "hdd", "temperature_c": 41},
    {"device": "/dev/sdb", "serial": "SSD-B", "media": "ssd", "temperature_c": 52},
    {"device": "/dev/nvme0n1", "serial": "NVME-C", "media": "nvme", "temperature_c": 38},
]


class TestTheJoin(unittest.TestCase):

    def test_a_disk_name_is_a_block_device_name_and_nothing_else(self):
        for good in ("sda", "sdaa", "vdb", "nvme0n1", "dm-0", "mmcblk0", "a", "x.y_z-9", "s" * 32):
            self.assertEqual(drive_temp.as_drive_name(good), good, good)
        for bad in ("", " ", "sda ", "sda\n", "s da", "../etc", "/dev/sda", ".sda", "-sda", "s" * 33, "sd;a",
                    "sda\x00", "é", None, 5, 5.0, True, [], {}, ["sda"]):
            self.assertIsNone(drive_temp.as_drive_name(bad), repr(bad))

    def test_the_entry_is_found_by_the_end_of_its_device_path(self):
        self.assertIs(drive_temp.disk_of("sda", SMART), SMART[0])
        self.assertIs(drive_temp.disk_of("sdb", SMART), SMART[1])
        self.assertIs(drive_temp.disk_of("nvme0n1", SMART), SMART[2])

    def test_no_entry_for_a_name_that_is_not_in_the_report(self):
        self.assertIsNone(drive_temp.disk_of("sdc", SMART))
        self.assertIsNone(drive_temp.disk_of("sd", SMART))      # a prefix is not the disk
        self.assertIsNone(drive_temp.disk_of("sda", [{"device": "/dev/sdaa"}]))

    def test_two_entries_that_claim_a_disk_are_no_answer(self):
        twice = SMART + [{"device": "/dev/sda", "serial": "OTHER", "media": "ssd"}]
        self.assertIsNone(drive_temp.disk_of("sda", twice))

    def test_nothing_usable_is_no_answer_and_never_raises(self):
        for smart in (None, {}, "x", 5, [], [None, 5, "x", {}], [{"device": None}], [{"device": 5}]):
            self.assertIsNone(drive_temp.disk_of("sda", smart), repr(smart))
        for drive in (None, "", 5, [], "../x"):
            self.assertIsNone(drive_temp.disk_of(drive, SMART), repr(drive))

    def test_only_a_drivetemp_sensor_reads_a_disk(self):
        self.assertIs(drive_temp.sensor_disk("drivetemp-scsi-0-0/temp1", "sda", SMART), SMART[0])
        self.assertIsNone(drive_temp.sensor_disk("nvme-pci-0100/Composite", "nvme0n1", SMART))
        self.assertIsNone(drive_temp.sensor_disk("coretemp-isa-0000/Package id 0", "sda", SMART))
        self.assertIsNone(drive_temp.sensor_disk(None, "sda", SMART))


FLEET = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50,
         "drivetemp_ssd_warn_c": 65, "drivetemp_ssd_crit_c": 70,
         "drivetemp_warn_c": 55, "drivetemp_crit_c": 60}
HDD_SENSOR = "drivetemp-scsi-0-0/temp1"
SSD_SENSOR = "drivetemp-scsi-1-0/temp1"


class TestTheLinesOfTheDisk(unittest.TestCase):

    def lines(self, label, drive, host=None, fleet=FLEET, smart=SMART):
        return drive_temp.sensor_lines(label, host or {}, fleet, drive, smart)

    def test_a_hard_disk_and_a_ssd_on_one_controller_get_their_own_pairs(self):
        self.assertEqual(self.lines(HDD_SENSOR, "sda"), (45.0, 50.0))
        self.assertEqual(self.lines(SSD_SENSOR, "sdb"), (65.0, 70.0))

    def test_the_sensor_of_the_report_gets_the_lines_of_its_own_disk_not_the_other_one(self):
        self.assertNotEqual(self.lines(HDD_SENSOR, "sdb"), self.lines(HDD_SENSOR, "sda"))

    def test_a_sensor_with_no_disk_keeps_the_lines_for_any_other_drive(self):
        self.assertEqual(self.lines(HDD_SENSOR, None), (55.0, 60.0))
        self.assertEqual(self.lines(SSD_SENSOR, None), (55.0, 60.0))

    def test_a_disk_that_is_not_in_the_report_keeps_the_lines_for_any_other_drive(self):
        self.assertEqual(self.lines(HDD_SENSOR, "sdq"), (55.0, 60.0))
        self.assertEqual(self.lines(HDD_SENSOR, "sda", smart=[]), (55.0, 60.0))
        self.assertEqual(self.lines(HDD_SENSOR, "sda", smart=None), (55.0, 60.0))

    def test_a_disk_the_agent_could_not_type_is_held_to_the_lines_for_any_drive(self):
        smart = [{"device": "/dev/sda", "serial": "X"}]
        self.assertEqual(self.lines(HDD_SENSOR, "sda", smart=smart), (55.0, 60.0))

    def test_the_hosts_own_lines_beat_the_fleets_for_the_disks_type(self):
        self.assertEqual(self.lines(SSD_SENSOR, "sdb", host={"drivetemp_ssd_crit_c": 68}), (65.0, 68.0))

    def test_the_line_kept_against_the_disks_serial_number_beats_them_all(self):
        host = {"drivetemp_per_serial": {"SSD-B": {"warn": 40, "crit": 45}}}
        self.assertEqual(self.lines(SSD_SENSOR, "sdb", host=host), (40.0, 45.0))
        self.assertEqual(self.lines(HDD_SENSOR, "sda", host=host), (45.0, 50.0), "the other disk's lines are not touched")

    def test_a_line_kept_against_a_serial_does_not_reach_a_sensor_with_no_disk(self):
        host = {"drivetemp_per_serial": {"SSD-B": {"warn": 40, "crit": 45}}}
        self.assertEqual(self.lines(SSD_SENSOR, None, host=host), (55.0, 60.0))

    def test_nothing_set_anywhere_is_no_line(self):
        self.assertEqual(self.lines(HDD_SENSOR, "sda", fleet={}), (None, None))

    def test_an_nvme_sensor_and_a_board_sensor_are_as_they_were(self):
        self.assertEqual(self.lines("nvme-pci-0100/Sensor 1", "nvme0n1", fleet={"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50}),
                         (45.0, 50.0))
        self.assertEqual(self.lines("nvme-pci-0100/Sensor 1", "nvme0n1",
                                    host={"drivetemp_per_serial": {"NVME-C": {"warn": 20, "crit": 25}}},
                                    fleet={"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50}), (45.0, 50.0))
        self.assertEqual(self.lines("coretemp-isa-0000/Package id 0", "sda"), (None, None))

    def test_the_old_three_argument_call_still_works(self):
        self.assertEqual(drive_temp.sensor_lines(HDD_SENSOR, {}, FLEET), (55.0, 60.0))


# ── the server ──────────────────────────────────────────────────────────────────────────────────────────────────

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

    def stored(self, temps, smart=(), host=None):
        dev = {"name": "h1", "last_seen": NOW, "sysinfo": {}}
        if host is not None:
            dev["metric_thresholds"] = host
        api.save(api.DEVICES_FILE, {"h1": dev})
        api.save(api.HARDWARE_FILE, {"h1": {"ts": NOW, "smart": [dict(s) for s in smart],
                                            "hardware": {"temps": [dict(t) for t in temps]}}})
        api._LOAD_CACHE.clear()

    def row(self):
        try:
            api.handle_fleet_thermal()
        except api.HTTPError as e:
            rows = [r for r in e.body["hosts"] if r["device_id"] == "h1"]
            self.assertEqual(len(rows), 1)
            return rows[0]
        self.fail("no answer")

    def detail(self, label):
        return next(d for d in self.row()["detail"] if d["label"] == label)

    def risk(self):
        dev = api.load(api.DEVICES_FILE)["h1"]
        hw = api.load(api.HARDWARE_FILE)["h1"]
        out = api._device_risk("h1", dev, {}, {}, {}, NOW, 300, hw_rec=hw)
        return [f for f in out.get("factors") or [] if f.get("kind") == "overheating"]


def sensor(label, temp, drive=None):
    return dict({"label": label, "current_c": temp}, **({} if drive is None else {"drive": drive}))


class TestTheServerKeepsTheDisk(_Fleet):

    def ingest(self, temps):
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        api._ingest_hardware("h1", "h1", {"hardware": {"temps": temps}, "smart": SMART}, NOW,
                             dev=api.load(api.DEVICES_FILE)["h1"])
        api._LOAD_CACHE.clear()
        return {t["label"]: t for t in api.load(api.HARDWARE_FILE)["h1"]["hardware"]["temps"]}

    def test_the_name_is_stored_with_the_sensor(self):
        got = self.ingest([sensor(HDD_SENSOR, 41.0, "sda"), sensor("coretemp-isa-0000/Package id 0", 50.0)])
        self.assertEqual(got[HDD_SENSOR]["drive"], "sda")
        self.assertNotIn("drive", got["coretemp-isa-0000/Package id 0"])

    def test_a_name_that_is_not_a_block_device_name_is_not_stored(self):
        bad = ["../../etc/passwd", "/dev/sda", "sda; rm -rf /", "s" * 33, "", "sda\n", 5, ["sda"], {"a": 1}, True]
        got = self.ingest([sensor(f"x{i}-isa-0000/temp1", 40.0, v) for i, v in enumerate(bad)])
        for label, t in got.items():
            self.assertNotIn("drive", t, (label, t))
        self.assertEqual(len(got), len(bad), "the readings themselves are kept")


class TestTheThermalPageUsesTheDisksLines(_Fleet):
    """The report of the issue: a hard disk and a SATA SSD on the same controllers."""

    TEMPS = [sensor(HDD_SENSOR, 44.0, "sda"), sensor(SSD_SENSOR, 66.0, "sdb")]

    def test_each_sensor_is_judged_by_its_own_disks_pair(self):
        self.config(FLEET)
        self.stored(self.TEMPS, smart=SMART)
        hdd, ssd = self.detail(HDD_SENSOR), self.detail(SSD_SENSOR)
        self.assertEqual((hdd["warn"], hdd["crit"], hdd["level"]), (45.0, 50.0, "ok"))
        self.assertEqual((ssd["warn"], ssd["crit"], ssd["level"]), (65.0, 70.0, "hot"))

    def test_the_row_says_which_disk_the_lines_are_from(self):
        self.config(FLEET)
        self.stored(self.TEMPS, smart=SMART)
        hdd, ssd = self.detail(HDD_SENSOR), self.detail(SSD_SENSOR)
        self.assertEqual((hdd["disk"], hdd["media"]), ("sda", "hdd"))
        self.assertEqual((ssd["disk"], ssd["media"]), ("sdb", "ssd"))

    def test_the_hosts_hot_and_headroom_come_from_the_hottest_sensors_disk(self):
        self.config(FLEET)
        self.stored(self.TEMPS, smart=SMART)
        r = self.row()
        self.assertEqual((r["sensor_label"], r["hot"], r["critical"], r["warn_c"], r["crit_c"], r["headroom"]),
                         (SSD_SENSOR, True, False, 65.0, 70.0, 4.0))

    def test_a_hard_disk_over_its_critical_line_is_critical_at_a_temperature_a_ssd_may_run_at(self):
        self.config(FLEET)
        self.stored([sensor(HDD_SENSOR, 51.0, "sda"), sensor(SSD_SENSOR, 51.0, "sdb")], smart=SMART)
        self.assertEqual(self.detail(HDD_SENSOR)["level"], "critical")
        self.assertEqual(self.detail(SSD_SENSOR)["level"], "ok")

    def test_the_old_reading_of_the_same_report_judged_both_by_the_one_pair(self):
        """What 7.4.8 did, kept as the control: with no disk named, both sensors take the pair for any other drive."""
        self.config(FLEET)
        self.stored([sensor(HDD_SENSOR, 44.0), sensor(SSD_SENSOR, 66.0)], smart=SMART)
        hdd, ssd = self.detail(HDD_SENSOR), self.detail(SSD_SENSOR)
        self.assertEqual((hdd["warn"], hdd["crit"], hdd["level"]), (55.0, 60.0, "ok"))
        self.assertEqual((ssd["warn"], ssd["crit"], ssd["level"]), (55.0, 60.0, "critical"))
        self.assertNotIn("disk", ssd)

    def test_a_disk_that_is_not_in_the_smart_list_falls_back_without_a_disk_field(self):
        self.config(FLEET)
        self.stored(self.TEMPS, smart=[])
        ssd = self.detail(SSD_SENSOR)
        self.assertEqual((ssd["warn"], ssd["crit"]), (55.0, 60.0))
        self.assertNotIn("disk", ssd)

    def test_the_hosts_line_against_a_serial_number_now_reaches_the_sensor_of_that_disk(self):
        self.config(FLEET)
        self.stored(self.TEMPS, smart=SMART, host={"drivetemp_per_serial": {"SSD-B": {"warn": 60, "crit": 64}}})
        ssd = self.detail(SSD_SENSOR)
        self.assertEqual((ssd["warn"], ssd["crit"], ssd["level"]), (60.0, 64.0, "critical"))
        self.assertEqual(self.detail(HDD_SENSOR)["crit"], 50.0)

    def test_with_no_line_set_nothing_changes(self):
        self.stored(self.TEMPS, smart=SMART)
        r = self.row()
        self.assertEqual((r["hot"], r["critical"], r["crit_c"], r["warn_c"]), (False, False, None, None))
        self.assertNotIn("level", self.detail(SSD_SENSOR))

    def test_an_nvme_sensor_is_not_given_a_disk(self):
        self.config({"drivetemp_nvme_warn_c": 45, "drivetemp_nvme_crit_c": 50})
        self.stored([sensor("nvme-pci-0100/Sensor 1", 46.0, "nvme0n1")], smart=SMART)
        d = self.detail("nvme-pci-0100/Sensor 1")
        self.assertEqual((d["warn"], d["crit"]), (45.0, 50.0))
        self.assertNotIn("disk", d)


class TestTheRiskScoreFollowsToo(_Fleet):

    def test_a_ssd_sensor_over_the_ssd_line_counts_and_under_it_does_not(self):
        self.config(FLEET)
        self.stored([sensor(SSD_SENSOR, 64.0, "sdb")], smart=SMART)
        self.assertEqual(self.risk(), [])
        self.stored([sensor(SSD_SENSOR, 66.0, "sdb")], smart=SMART)
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("hot", f[0]["detail"])

    def test_the_same_reading_on_a_hard_disk_is_over_its_critical_line(self):
        self.config(FLEET)
        self.stored([sensor(HDD_SENSOR, 51.0, "hda")], smart=[dict(SMART[0], device="/dev/hda")])
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("critical", f[0]["detail"])

    def test_with_no_disk_named_the_reading_is_judged_by_the_pair_for_any_drive(self):
        self.config(FLEET)
        self.stored([sensor(SSD_SENSOR, 56.0)], smart=SMART)
        f = self.risk()
        self.assertEqual(len(f), 1)
        self.assertIn("hot", f[0]["detail"])


class TestFromTheAgentToThePage(_Sysfs, _Fleet):
    """The runnable reproduction: the agent's own reader, a heartbeat's ingest, and the page, on one host."""

    def setUp(self):
        _Sysfs.setUp(self)
        _Fleet.setUp(self)

    def tearDown(self):
        _Fleet.tearDown(self)
        _Sysfs.tearDown(self)

    def test_one_host_with_a_hard_disk_and_a_ssd_on_the_same_controllers(self):
        _build_sysfs(self.root, [("hwmon3", "0:0:0:0", ["sda"]), ("hwmon4", "1:0:0:0", ["sdb"])])
        chips = {k: v for k, v in _sensors_json().items() if k.startswith("drivetemp-scsi-") and k != "drivetemp-scsi-9-0"}
        chips["drivetemp-scsi-1-0"]["temp1"]["temp1_input"] = 66.0

        def run(cmd, *a, **k):
            if list(cmd) == ["sensors", "-A", "-j"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(chips), stderr="")
            raise FileNotFoundError(cmd[0] if cmd else "")

        with mock.patch.object(self.agent, "_which", lambda prog, *a, **k: "/usr/bin/sensors" if prog == "sensors" else None), \
                mock.patch.object(subprocess, "run", run):
            hw = self.agent.get_hardware_inventory()
        self.config(FLEET)
        api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "last_seen": NOW, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        api._ingest_hardware("h1", "h1", {"hardware": hw, "smart": SMART}, NOW, dev=api.load(api.DEVICES_FILE)["h1"])
        api._LOAD_CACHE.clear()
        hdd, ssd = self.detail(HDD_SENSOR), self.detail(SSD_SENSOR)
        self.assertEqual((hdd["disk"], hdd["warn"], hdd["crit"], hdd["level"]), ("sda", 45.0, 50.0, "ok"))
        self.assertEqual((ssd["disk"], ssd["warn"], ssd["crit"], ssd["level"]), ("sdb", 65.0, 70.0, "hot"))


class TestTheTwoAgentCopiesAreTheSame(unittest.TestCase):

    def test_extensionless_matches_py(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(),
                         (ROOT / "client" / "remotepower-agent.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
