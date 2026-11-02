#!/usr/bin/env python3
"""The demo seeder carries what 7.4.9 added, in the shapes the agents send.

The demo seeder is a producer under contract: the accessibility, box-overflow and icon-gap gates and every screenshot measure
the seeded instance, so a feature the seeder never fills shows its empty state to all of them and to anyone who tries the demo.
7.4.9 added three signals, and a fourth was found missing while adding them:

  * a host in the Extended upgrade mode, and hosts whose apt keeps a package back (Discussion #30);
  * drivetemp sensors that name their disk, one of them not identified (#54);
  * the package manager each demo host's agent reports. It was left out, so every Patch Report row said "unknown".

The records are read back through the server's own helpers (`drive_temp`, `upgrade_mode`, `_device_os_family`), not through a
copy of their rules, so a change in how the server reads them fails here.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))

import drive_temp  # noqa: E402
import upgrade_mode  # noqa: E402


def _load_seeder():
    spec = importlib.util.spec_from_file_location("seed_v749", ROOT / "packaging" / "seed-demo-data.py")
    if spec is None or spec.loader is None:
        raise unittest.SkipTest("demo seeder not in this tree")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSeederCarriesTheNewSignals(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.seed = _load_seeder()
        cls.devices = cls.seed.build_devices()
        cls.hardware = cls.seed.build_hardware()
        import api  # noqa: E402  (after RP_DATA_DIR is pinned)
        cls.api = api

    def agented(self):
        return {i: d for i, d in self.devices.items() if not d.get("agentless")}

    # ── Discussion #30 ────────────────────────────────────────────────────────────
    def test_exactly_one_demo_host_runs_the_extended_mode_and_it_is_an_apt_host(self):
        modes = {i: d["upgrade_mode"] for i, d in self.devices.items() if "upgrade_mode" in d}
        self.assertEqual(modes, {"nc01": "extended"})
        d = self.devices["nc01"]
        pkg = d["sysinfo"]["packages"]
        self.assertIsNone(upgrade_mode.not_applicable(self.api._device_os_family(d), pkg["manager"]))
        self.assertEqual(upgrade_mode.mode_of(d), "extended")

    def test_a_standard_host_with_a_package_kept_back_sits_beside_it(self):
        d = self.devices["jf01"]
        self.assertNotIn("upgrade_mode", d)
        self.assertEqual(upgrade_mode.mode_of(d), "standard")
        self.assertEqual(d["sysinfo"]["packages"]["kept_back"], ["linux-image-generic"])

    def test_kept_back_names_are_pending_and_counted(self):
        for i in ("jf01", "nc01"):
            with self.subTest(host=i):
                pkg = self.devices[i]["sysinfo"]["packages"]
                self.assertTrue(set(pkg["kept_back"]) <= set(pkg["upgradable_names"]), pkg)
                self.assertEqual(pkg["upgradable"], len(pkg["upgradable_names"]), pkg)

    def test_no_other_host_reports_a_kept_back_package(self):
        others = {i for i, d in self.agented().items() if (d.get("sysinfo", {}).get("packages") or {}).get("kept_back")}
        self.assertEqual(others, {"jf01", "nc01"})

    # ── the package manager ───────────────────────────────────────────────────────
    def test_every_agented_host_reports_the_manager_its_agent_sends(self):
        want = {"windows": "windows-update", "macos": "brew", "alpine": "apk"}
        seen = set()
        for i, d in self.agented().items():
            os_name = d["os"].lower()
            expect = next((m for k, m in want.items() if k in os_name), "apt")
            mgr = d["sysinfo"]["packages"]["manager"]
            seen.add(mgr)
            with self.subTest(host=i, os=d["os"]):
                self.assertEqual(mgr, expect)
        self.assertEqual(seen, {"apt", "apk", "brew", "windows-update"}, "the demo shows all four")

    def test_the_mode_applies_to_the_apt_hosts_and_to_no_others(self):
        for i, d in self.agented().items():
            applies = upgrade_mode.not_applicable(self.api._device_os_family(d), d["sysinfo"]["packages"]["manager"]) is None
            with self.subTest(host=i, os=d["os"]):
                self.assertEqual(applies, d["sysinfo"]["packages"]["manager"] == "apt")

    # ── #54 ───────────────────────────────────────────────────────────────────────
    def sensors(self, host):
        rec = self.hardware[host]
        return rec["smart"], [t for t in rec["hardware"]["temps"] if str(t["label"]).startswith("drivetemp-scsi-")]

    def test_drivetemp_sensors_name_their_disks(self):
        for host, total, unnamed in (("tnas", 4, 1), ("bk01", 2, 1), ("nc01", 1, 0)):
            with self.subTest(host=host):
                _, sensors = self.sensors(host)
                self.assertEqual(len(sensors), total)
                self.assertEqual(len([t for t in sensors if "drive" not in t]), unnamed)

    def test_a_named_sensor_resolves_to_the_disk_it_reads_through_the_servers_own_helper(self):
        for host in ("tnas", "bk01", "nc01"):
            smart, sensors = self.sensors(host)
            for t in sensors:
                with self.subTest(host=host, sensor=t["label"]):
                    disk = drive_temp.sensor_disk(t["label"], t.get("drive"), smart)
                    if "drive" in t:
                        self.assertIsNotNone(disk)
                        self.assertEqual(disk["temperature_c"], t["current_c"], "a sensor reads what its disk's SMART row reads")
                    else:
                        self.assertIsNone(disk, "an unnamed sensor has no disk")

    def test_the_nas_hot_disk_has_a_hot_sensor_and_both_land_on_the_same_lines(self):
        smart, sensors = self.sensors("tnas")
        hot = next(t for t in sensors if t.get("drive") == "sdb")
        self.assertEqual(hot["current_c"], 47.0)
        warn, crit = drive_temp.sensor_lines(hot["label"], {}, {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50}, "sdb", smart)
        self.assertEqual((warn, crit), (45.0, 50.0))
        self.assertGreaterEqual(hot["current_c"], warn)

    def test_the_ssd_in_the_demo_is_held_to_the_ssd_lines(self):
        smart, sensors = self.sensors("nc01")
        t = sensors[0]
        warn, _ = drive_temp.sensor_lines(t["label"], {}, {"drivetemp_hdd_warn_c": 45, "drivetemp_ssd_warn_c": 65}, t["drive"], smart)
        self.assertEqual(warn, 65.0)

    def test_control_a_name_no_disk_has_is_not_resolved(self):
        smart, sensors = self.sensors("tnas")
        self.assertIsNone(drive_temp.sensor_disk(sensors[0]["label"], "sdz", smart))

    def test_the_board_sensors_are_still_there(self):
        labels = [t["label"] for t in self.hardware["tnas"]["hardware"]["temps"]]
        self.assertIn("CPU", labels)
        self.assertIn("Mainboard", labels)


if __name__ == "__main__":
    unittest.main()
