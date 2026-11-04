#!/usr/bin/env python3
"""v7.5.0 (data binding): the health signals the Checks page reads are Data Explorer fields.

The Checks page, the alerts, the risk score and the Hardware roll-up all read ten facts about a host that the Data Explorer
could not be asked about: how much of the CPU time went to waiting for storage, how much was taken by the hypervisor, whether a
storage pool or array is degraded, whether the default gateway answers, when the kernel last killed a process for lack of memory,
how many uncorrectable memory errors were counted, and the four flags the hardware report sets (a failing disk, a hot sensor, a UPS
on battery, a newer kernel waiting for a reboot). "Which hosts have a failing disk" is the first question of a storage review.

What this holds:

* The projection and the tuple of exposed names agree, and the guide lists every exposed name.
* Each field is tri-state. `None` means the host never reported the thing, so a silent host is not read as a healthy one, and a
  value of the wrong kind is no value (`True` is not a number, a string is not a flag).
* The hardware flags come from the real `_ingest_hardware`, not from a hand-written record: a fixture is the consumer's idea of
  the producer. A record that reports only SMART has no thermal, UPS or kernel flag.
* A real predicate runs over the rows the Data Explorer builds from the stored fleet.
* The demo seeder writes the flags the ingest writes. It wrote the lists and not the flags, so the Hardware roll-up counted
  no failing disk and no UPS on battery on the demo, and these fields were empty there.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-qhf-"))

_spec = importlib.util.spec_from_file_location("api_v750_qhf", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import query_engine  # noqa: E402

NEW_FIELDS = ("cpu_iowait_pct", "cpu_steal_pct", "storage_degraded", "gateway_reachable", "last_oom_ts",
              "ecc_uncorrectable", "smart_failed", "temp_high", "ups_on_battery", "kernel_reboot")
HARDWARE_FIELDS = ("smart_failed", "temp_high", "ups_on_battery", "kernel_reboot")
NOW = int(time.time())


def _pool(name, state, kind="zfs"):
    """A pool as safe_si stores it (name, kind, state)."""
    return {"name": name, "kind": kind, "state": state}


# Sysinfo in the shapes safe_si persists: shares are floats, the gateway is {ip, reachable}, ecc is {ce, ue, controllers}.
SICK = {"cpu_iowait": 38.5, "cpu_steal": 12.0,
        "storage_health": [_pool("tank", "ONLINE"), _pool("md0", "DEGRADED", "mdadm")],
        "gateway": {"ip": "192.0.2.1", "reachable": False},
        "last_oom_ts": NOW - 600, "ecc": {"ce": 4, "ue": 2, "controllers": 1}}
WELL = {"cpu_iowait": 1.2, "cpu_steal": 0.0,
        "storage_health": [_pool("tank", "ONLINE")],
        "gateway": {"ip": "192.0.2.1", "reachable": True},
        "ecc": {"ce": 0, "ue": 0, "controllers": 1}}


class TestTheProjection(unittest.TestCase):

    def test_a_sick_host_reads_as_one(self):
        r = api._qe_device_posture(SICK)
        self.assertEqual(r["cpu_iowait_pct"], 38.5)
        self.assertEqual(r["cpu_steal_pct"], 12.0)
        self.assertIs(r["storage_degraded"], True)
        self.assertIs(r["gateway_reachable"], False)
        self.assertEqual(r["last_oom_ts"], NOW - 600)
        self.assertEqual(r["ecc_uncorrectable"], 2)           # the uncorrectable count, not the correctable one (4)

    def test_a_well_host_reads_as_one(self):
        r = api._qe_device_posture(WELL)
        self.assertEqual(r["cpu_iowait_pct"], 1.2)
        self.assertEqual(r["cpu_steal_pct"], 0.0)             # zero is a value: the agent measured it
        self.assertIs(r["storage_degraded"], False)
        self.assertIs(r["gateway_reachable"], True)
        self.assertIsNone(r["last_oom_ts"])                   # the agent sends it only after a kill
        self.assertEqual(r["ecc_uncorrectable"], 0)

    def test_a_silent_host_has_none_of_them(self):
        r = api._qe_device_posture({})
        for f in ("cpu_iowait_pct", "cpu_steal_pct", "storage_degraded", "gateway_reachable", "last_oom_ts",
                  "ecc_uncorrectable"):
            self.assertIn(f, r)
            self.assertIsNone(r[f], f)

    def test_a_value_of_the_wrong_kind_is_no_value(self):
        r = api._qe_device_posture({"cpu_iowait": "high", "cpu_steal": True, "storage_health": "degraded",
                                    "gateway": "down", "last_oom_ts": True, "ecc": [1, 2]})
        for f in ("cpu_iowait_pct", "cpu_steal_pct", "storage_degraded", "gateway_reachable", "last_oom_ts",
                  "ecc_uncorrectable"):
            self.assertIsNone(r[f], f)

    def test_a_gateway_without_a_verdict_is_none_not_unreachable(self):
        self.assertIsNone(api._qe_device_posture({"gateway": {"ip": "192.0.2.1"}})["gateway_reachable"])
        self.assertIsNone(api._qe_device_posture({"gateway": {"reachable": "no"}})["gateway_reachable"])

    def test_an_ecc_record_without_the_uncorrectable_count_is_none(self):
        self.assertIsNone(api._qe_device_posture({"ecc": {"ce": 9}})["ecc_uncorrectable"])


class TestStorageDegraded(unittest.TestCase):
    """The rule is posture_signals.pool_unhealthy, the one the Checks row, the Fleet Query facet and the report use."""

    def test_one_bad_pool_among_good_ones_is_degraded(self):
        self.assertIs(api._qe_storage_degraded([_pool("a", "ONLINE"), _pool("b", "DEGRADED"), _pool("c", "ONLINE")]), True)

    def test_all_pools_healthy_is_false(self):
        for state in ("ONLINE", "active", "clean", "Healthy", "ok"):
            self.assertIs(api._qe_storage_degraded([_pool("a", state)]), False, state)

    def test_the_states_that_are_not_healthy(self):
        for state in ("DEGRADED", "FAULTED", "inactive", "unknown", "resyncing", "UNAVAIL"):
            self.assertIs(api._qe_storage_degraded([_pool("a", state)]), True, state)

    def test_a_pool_with_no_state_is_read_like_the_checks_row_reads_it(self):
        """checks.py asks `pool_unhealthy(state or 'unknown')`: a pool nobody can read is not healthy."""
        self.assertIs(api._qe_storage_degraded([_pool("a", "")]), True)

    def test_no_pools_is_none_not_false(self):
        for v in (None, [], "", {}, ["x", 3], [None]):
            self.assertIsNone(api._qe_storage_degraded(v), repr(v))

    def test_it_agrees_with_the_checks_row_on_every_state(self):
        """Two readers of one rule: the Checks row builds its finding from the same pool list."""
        import checks
        for state in ("ONLINE", "DEGRADED", "unknown", "", "clean", "FAULTED", "inactive"):
            si = {"storage_health": [_pool("p", state)]}
            rows = [r for r in checks._host_checks("d", {"name": "h", "last_seen": NOW, "sysinfo": si}, now=NOW)
                    if r.get("id") == "storage_health" or r.get("check") == "storage_health"]
            if rows:                                                  # the row exists on the Checks page
                self.assertEqual(rows[0].get("status") != "ok", api._qe_storage_degraded(si["storage_health"]), state)


class TestTheHardwareFlags(unittest.TestCase):

    def test_a_record_with_the_flags(self):
        r = api._qe_hardware_flags({"_smart_failed": True, "_temp_high": False, "_ups_on_battery": True,
                                    "kernel": {"reboot_for_kernel": True}})
        self.assertEqual(r, {"smart_failed": True, "temp_high": False, "ups_on_battery": True, "kernel_reboot": True})

    def test_no_record_is_four_nones(self):
        for rec in (None, {}, "x", [], 0):
            self.assertEqual(api._qe_hardware_flags(rec), {f: None for f in HARDWARE_FIELDS}, repr(rec))

    def test_a_flag_of_the_wrong_kind_is_none(self):
        r = api._qe_hardware_flags({"_smart_failed": "yes", "_temp_high": 1, "_ups_on_battery": [True],
                                    "kernel": {"reboot_for_kernel": "true"}})
        self.assertEqual(r, {f: None for f in HARDWARE_FIELDS})

    def test_a_kernel_section_that_is_not_a_record_is_none(self):
        self.assertIsNone(api._qe_hardware_flags({"kernel": "6.1"})["kernel_reboot"])
        self.assertIsNone(api._qe_hardware_flags({"kernel": None})["kernel_reboot"])


class TestTheTupleAndTheGuide(unittest.TestCase):

    def test_the_ten_are_exposed(self):
        for f in NEW_FIELDS:
            self.assertIn(f, api._QE_DEVICE_FIELDS, f)

    def test_every_exposed_host_field_is_in_the_guide(self):
        """The guide is the only place besides the code that lists the fields, and nothing read it."""
        doc = (ROOT / "docs" / "data-explorer.md").read_text(encoding="utf-8")
        missing = sorted(f for f in api._QE_DEVICE_FIELDS if "`%s`" % f not in doc)
        self.assertEqual(missing, [], "fields a query accepts that the guide does not list")

    def test_the_guide_says_the_health_fields_are_empty_for_a_host_that_never_reported(self):
        doc = (ROOT / "docs" / "data-explorer.md").read_text(encoding="utf-8")
        start = doc.index("### Hardware and storage health")
        section = doc[start:doc.index("### ", start + 5)]
        self.assertIn("never reported", section)
        for f in NEW_FIELDS:
            self.assertIn("`%s`" % f, section, f)


class _Fleet(unittest.TestCase):
    """Stored hosts, with hardware records written by the real ingest."""

    @classmethod
    def setUpClass(cls):
        cls.ids = {k: "qhf-" + k for k in ("sick", "well", "partial", "silent", "nohw")}
        real_fire = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None                  # the ingest raises alerts; this test is not about them
        try:
            api._ingest_hardware(cls.ids["sick"], "sick", {
                "smart": [{"device": "/dev/sda", "health": "PASSED"}, {"device": "/dev/sdb", "health": "FAILED"}],
                "hardware": {"temps": [{"label": "CPU", "current_c": 91.0, "crit_c": 100.0}]},
                "ups": [{"name": "Back-UPS", "status": "OB DISCHRG", "battery_pct": 60}],
                "kernel": {"running": "6.1.0-21", "latest_installed": "6.1.0-27", "reboot_for_kernel": True}}, NOW)
            api._ingest_hardware(cls.ids["well"], "well", {
                "smart": [{"device": "/dev/sda", "health": "PASSED"}],
                "hardware": {"temps": [{"label": "CPU", "current_c": 40.0, "crit_c": 100.0}]},
                "ups": [{"name": "Back-UPS", "status": "OL", "battery_pct": 100}],
                "kernel": {"running": "6.1.0-27", "latest_installed": "6.1.0-27", "reboot_for_kernel": False}}, NOW)
            # reports its disks and nothing else: no sensor, no UPS, no kernel section
            api._ingest_hardware(cls.ids["partial"], "partial", {"smart": [{"device": "/dev/sda", "health": "PASSED"}]}, NOW)
        finally:
            api.fire_webhook = real_fire

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-qhf-fleet-"))
        self._df = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        host = lambda key, si: {"name": key, "last_seen": NOW, "monitored": True, "sysinfo": si}   # noqa: E731
        api.save(api.DEVICES_FILE, {
            self.ids["sick"]: host("sick", dict(SICK)),
            self.ids["well"]: host("well", dict(WELL)),
            self.ids["partial"]: host("partial", {}),
            self.ids["silent"]: host("silent", {}),
            self.ids["nohw"]: host("nohw", dict(WELL)),
        })
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.HARDWARE_FILE)

    def tearDown(self):
        api.DEVICES_FILE = self._df
        api._invalidate_load_cache(api.DEVICES_FILE)

    def rows(self):
        return {r["device_id"]: r for r in api._qe_devices_rows()}

    def names(self, pred):
        query_engine.validate_predicate(pred, api._QE_DEVICE_FIELDS)
        return {r["name"] for r in query_engine.run(list(self.rows().values()), pred, api._QE_DEVICE_FIELDS)}


class TestTheIngestFlagsReachTheRows(_Fleet):

    def test_the_population_is_not_empty(self):
        """Control: every planted host is in the rows, so an empty answer below cannot be a fixture that never loaded."""
        self.assertEqual(set(self.rows()), set(self.ids.values()))

    def test_the_real_ingest_wrote_the_flags_the_projection_reads(self):
        """Control on the producer: if the ingest stopped writing these keys, every assertion below would read None."""
        hw = api.load(api.HARDWARE_FILE)
        self.assertIs(hw[self.ids["sick"]]["_smart_failed"], True)
        self.assertIs(hw[self.ids["sick"]]["_temp_high"], True)
        self.assertIs(hw[self.ids["sick"]]["_ups_on_battery"], True)
        self.assertIs(hw[self.ids["well"]]["_smart_failed"], False)

    def test_a_sick_host(self):
        r = self.rows()[self.ids["sick"]]
        self.assertEqual({f: r[f] for f in HARDWARE_FIELDS},
                         {"smart_failed": True, "temp_high": True, "ups_on_battery": True, "kernel_reboot": True})

    def test_a_well_host(self):
        r = self.rows()[self.ids["well"]]
        self.assertEqual({f: r[f] for f in HARDWARE_FIELDS},
                         {"smart_failed": False, "temp_high": False, "ups_on_battery": False, "kernel_reboot": False})

    def test_a_host_that_reported_only_its_disks_has_one_flag(self):
        r = self.rows()[self.ids["partial"]]
        self.assertIs(r["smart_failed"], False)
        for f in ("temp_high", "ups_on_battery", "kernel_reboot"):
            self.assertIsNone(r[f], f)

    def test_a_host_without_a_hardware_record_has_four_nones(self):
        for key in ("silent", "nohw"):
            r = self.rows()[self.ids[key]]
            for f in HARDWARE_FIELDS:
                self.assertIsNone(r[f], "%s %s" % (key, f))

    def test_the_sysinfo_fields_travel_with_the_row(self):
        r = self.rows()[self.ids["sick"]]
        self.assertEqual((r["storage_degraded"], r["gateway_reachable"], r["ecc_uncorrectable"]), (True, False, 2))


class TestAQueryRunsOverThem(_Fleet):

    def test_a_failing_disk(self):
        self.assertEqual(self.names({"field": "smart_failed", "op": "eq", "value": True}), {"sick"})

    def test_the_hosts_that_never_reported_smart_are_not_in_either_answer(self):
        on = self.names({"field": "smart_failed", "op": "eq", "value": True})
        off = self.names({"field": "smart_failed", "op": "eq", "value": False})
        self.assertEqual(off, {"well", "partial"})
        for silent in ("silent", "nohw"):
            self.assertNotIn(silent, on | off)

    def test_the_hosts_that_never_reported_are_found_by_exists(self):
        self.assertEqual(self.names({"not": {"field": "smart_failed", "op": "exists"}}), {"silent", "nohw"})

    def test_a_hot_sensor_and_a_ups_on_battery_together(self):
        pred = {"and": [{"field": "temp_high", "op": "eq", "value": True},
                        {"field": "ups_on_battery", "op": "eq", "value": True}]}
        self.assertEqual(self.names(pred), {"sick"})

    def test_a_kernel_waiting_for_a_reboot(self):
        self.assertEqual(self.names({"field": "kernel_reboot", "op": "eq", "value": True}), {"sick"})

    def test_a_degraded_pool(self):
        self.assertEqual(self.names({"field": "storage_degraded", "op": "eq", "value": True}), {"sick"})

    def test_a_gateway_that_does_not_answer(self):
        self.assertEqual(self.names({"field": "gateway_reachable", "op": "eq", "value": False}), {"sick"})

    def test_cpu_time_spent_waiting_for_storage(self):
        self.assertEqual(self.names({"field": "cpu_iowait_pct", "op": "gt", "value": 20}), {"sick"})
        self.assertEqual(self.names({"field": "cpu_steal_pct", "op": "gte", "value": 10}), {"sick"})

    def test_a_recent_out_of_memory_kill(self):
        self.assertEqual(self.names({"field": "last_oom_ts", "op": "gt", "value": NOW - 3600}), {"sick"})

    def test_uncorrectable_memory_errors(self):
        self.assertEqual(self.names({"field": "ecc_uncorrectable", "op": "gt", "value": 0}), {"sick"})
        self.assertEqual(self.names({"field": "ecc_uncorrectable", "op": "eq", "value": 0}), {"well", "nohw"})


class TestTenantScope(_Fleet):
    """The hardware store is read for the hosts the caller may see, and only for those."""

    def test_a_host_the_caller_cannot_see_is_not_in_the_rows(self):
        real = api._scope_filter_devices
        keep = self.ids["well"]
        api._scope_filter_devices = lambda d, scope=None: {k: v for k, v in d.items() if k == keep}
        try:
            rows = api._qe_devices_rows()
        finally:
            api._scope_filter_devices = real
        self.assertEqual([r["device_id"] for r in rows], [keep])
        self.assertIs(rows[0]["smart_failed"], False)
        self.assertNotIn("sick", {r["name"] for r in rows})


class TestTheDemoSeederWritesTheFlags(unittest.TestCase):
    """seed-demo-data.py writes JSON straight into the stores, so it has to write what the ingest keeps beside a report."""

    @classmethod
    def setUpClass(cls):
        seeder = ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.is_file():
            raise unittest.SkipTest("demo seeder excluded from this tree")
        spec = importlib.util.spec_from_file_location("seed_demo_v750_qhf", seeder)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.mod = mod
        cls.hw = mod.build_hardware()

    def test_there_are_records_to_measure(self):
        self.assertGreaterEqual(len(self.hw), 6)

    def test_every_flag_agrees_with_the_list_it_summarises(self):
        """Re-derived here from the lists, by a different route than the seeder's own helper."""
        checked = 0
        for dev_id, rec in self.hw.items():
            if isinstance(rec.get("smart"), list):
                failed = sorted(d["device"] for d in rec["smart"] if d["failed"])
                self.assertEqual(rec.get("_smart_failed_devs"), failed, dev_id)
                self.assertIs(rec.get("_smart_failed"), bool(failed), dev_id)
                checked += 1
            self.assertIs(rec.get("_kernel_old"), bool(rec["kernel"]["reboot_for_kernel"]), dev_id)
            if isinstance(rec.get("ups"), list):
                self.assertIs(rec.get("_ups_on_battery"), any("OB" in u["status"] for u in rec["ups"]), dev_id)
            else:
                self.assertNotIn("_ups_on_battery", rec, dev_id)
            if isinstance(rec.get("hardware"), dict):
                hot = [t["current_c"] for t in rec["hardware"].get("temps") or []] + [g["temp_c"] for g in rec.get("gpus") or []]
                self.assertIs(rec.get("_temp_high"), any(v >= 85 for v in hot), dev_id)
            else:
                self.assertNotIn("_temp_high", rec, dev_id)
        self.assertGreaterEqual(checked, 5, "the SMART records the check walks")

    def test_the_demo_shows_a_failing_disk_a_ups_on_battery_a_hot_host_and_a_kernel_waiting(self):
        self.assertIs(self.hw["tnas"]["_smart_failed"], True)
        self.assertEqual(self.hw["tnas"]["_smart_failed_devs"], ["/dev/sdc"])
        self.assertIs(self.hw["pmx01"]["_ups_on_battery"], True)
        self.assertIs(self.hw["pmx01"]["_kernel_old"], True)
        self.assertIs(self.hw["gt01"]["_temp_high"], True)
        self.assertIs(self.hw["nc01"]["_temp_high"], False)         # a record with sensors under the line is not hot

    def test_the_seeder_and_the_ingest_agree_on_which_disks_have_failed(self):
        """The seeder decides `failed` itself; the flag is only right if the product would decide the same."""
        n = 0
        for dev_id, rec in self.hw.items():
            for d in rec.get("smart") or []:
                self.assertIs(api._smart_disk_failed(d), d["failed"], "%s %s" % (dev_id, d["device"]))
                n += 1
        self.assertGreaterEqual(n, 8)

    def test_a_flag_is_set_only_for_a_part_the_record_reports(self):
        """The ingest sets `_smart_failed` only when the report carries a SMART list, and so on."""
        from_a_gpu_only = {"gpus": [{"name": "x", "temp_c": 90.0}], "ts": 1}
        self.mod._hardware_flags(from_a_gpu_only)
        self.assertEqual({k for k in from_a_gpu_only if k.startswith("_")}, set())

    def test_the_heat_line_is_the_one_the_ingest_uses(self):
        """The seeder repeats the ingest's rule for `_temp_high`. The real ingest is the oracle, at the line and either side of
        it, for a board sensor and for a GPU (the demo's own hot host also has a dead pin at 104, which hides a wrong line)."""
        real_fire = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None
        try:
            for i, v in enumerate((30.0, 84.9, 85.0, 85.1, 110.0)):
                for kind in ("sensor", "gpu"):
                    body = ({"hardware": {"temps": [{"label": "CPU", "current_c": v}]}} if kind == "sensor"
                            else {"hardware": {"temps": []}, "gpus": [{"name": "g", "temp_c": v}]})
                    dev = "qhf-heat-%s-%d" % (kind, i)
                    api._ingest_hardware(dev, "heat", body, NOW)
                    real = api.load(api.HARDWARE_FILE)[dev]["_temp_high"]
                    rec = {k: (list(x) if isinstance(x, list) else dict(x)) for k, x in body.items()}
                    self.mod._hardware_flags(rec)
                    self.assertIs(rec["_temp_high"], real, "%s at %s" % (kind, v))
                    self.assertIs(real, v >= 85, "the ingest's own line moved: %s at %s" % (kind, v))
        finally:
            api.fire_webhook = real_fire


if __name__ == "__main__":
    unittest.main()
