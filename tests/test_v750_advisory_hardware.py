#!/usr/bin/env python3
"""The Security Advisory reads the hardware, storage and malware-scanner stores.

`advisory.build` was handed neither the hardware store nor the AV store, so a host with uncorrectable ECC errors, a degraded
pool, a failing disk, a kernel waiting for a reboot or an active malware detection produced the same findings as a healthy
host. Each of these already pages the operator, sits on a Checks row and scores in Risk or reliability.

The records here are stored by the real ingests (`_ingest_hardware`, `_ingest_av`), and the advisory is built the way the
Security page builds it. "Is this pool unhealthy" now comes from one helper, shared with the Checks row, the Fleet Query
facet, the fleet report and the dashboard count; `TestOnePoolRule` holds that.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-advhw-"))

import advisory  # noqa: E402
import posture_signals as ps  # noqa: E402


def _fresh_api():
    import importlib.util
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-advhw-api-")
    spec = importlib.util.spec_from_file_location("api_v750_advhw", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _on(f, dev):
    """The built advisory groups a finding across hosts: it lists them in `devices`."""
    return any(d.get("device_id") == dev for d in f.get("devices") or [])


def _ids(adv, dev=None):
    return {f["id"] for f in adv["findings"] if dev is None or _on(f, dev)}


class TestThroughTheRealStores(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "sick": {"name": "nas01", "last_seen": now, "monitored": True, "sysinfo": {
                "ecc": {"ue": 4, "ce": 12},
                "storage_health": [{"name": "tank", "kind": "zfs", "state": "DEGRADED"},
                                   {"name": "md0", "kind": "md", "state": "unknown"}]}},
            "well": {"name": "web01", "last_seen": now, "monitored": True, "sysinfo": {
                "ecc": {"ue": 0, "ce": 0},
                "storage_health": [{"name": "tank", "kind": "zfs", "state": "ONLINE"},
                                   {"name": "md0", "kind": "md", "state": "clean"}]}}})
        real = api.fire_webhook
        api.fire_webhook = lambda *a, **k: None
        try:
            api._ingest_hardware("sick", "nas01", {
                "smart": [{"device": "/dev/sdb", "serial": "SN-SECRET-1", "model": "ST4000", "health": "FAILED",
                           "temperature_c": 40}],
                "kernel": {"running": "6.1.0", "latest_installed": "6.1.9", "reboot_for_kernel": True}}, now)
            api._ingest_hardware("well", "web01", {
                "smart": [{"device": "/dev/sda", "serial": "SN-OK", "model": "ST4000", "health": "PASSED",
                           "temperature_c": 38}],
                "kernel": {"running": "6.1.9", "latest_installed": "6.1.9", "reboot_for_kernel": False}}, now)
            api._ingest_av("sick", {"clamav": {"infected": 2, "installed": True}}, now, "nas01")
            api._ingest_av("well", {"clamav": {"infected": 0, "installed": True}}, now, "web01")
        finally:
            api.fire_webhook = real
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        cls.adv = api._build_advisory(devs)

    def test_the_sick_host_has_every_finding(self):
        self.assertTrue({"int.av_infected", "os.kernel", "data.smart", "data.pool", "data.ecc"} <= _ids(self.adv, "sick"),
                        _ids(self.adv, "sick"))

    def test_the_healthy_host_has_none_of_them(self):
        got = _ids(self.adv, "well")
        for fid in ("int.av_infected", "int.av_realtime", "os.kernel", "data.smart", "data.pool", "data.ecc"):
            self.assertNotIn(fid, got, fid)

    def test_severities(self):
        sev = {f["id"]: f["severity"] for f in self.adv["findings"] if _on(f, "sick")}
        self.assertEqual(sev["int.av_infected"], "critical")
        self.assertEqual(sev["data.smart"], "high")
        self.assertEqual(sev["data.pool"], "high")
        self.assertEqual(sev["os.kernel"], "medium")

    def test_the_pool_finding_counts_both_the_degraded_and_the_unreadable_one(self):
        f = [x for x in self.adv["findings"] if x["id"] == "data.pool" and _on(x, "sick")][0]
        self.assertIn("2 storage pools or arrays", f["title"])
        self.assertIn("tank: DEGRADED", " ".join(f["evidence"]))

    def test_the_ai_brief_carries_no_disk_serial_or_pool_name(self):
        brief = advisory.summarize_for_ai(self.adv, "the fleet")
        for secret in ("SN-SECRET-1", "ST4000", "tank", "md0", "nas01", "/dev/sdb"):
            self.assertNotIn(secret, brief)
        self.assertIn("malware", brief)

    def test_the_serial_is_not_in_any_finding_at_all(self):
        import json
        self.assertNotIn("SN-SECRET-1", json.dumps(self.adv))


class TestRealtimeOff(unittest.TestCase):

    def test_defender_realtime_off_is_a_high_finding_not_critical(self):
        dev = {"name": "w", "sysinfo": {}}
        out = advisory.build({"w": dev}, av_by_dev={"w": {"defender": {"installed": True, "realtime_enabled": False, "infected": 0}}},
                             av_tools=("clamav", "rkhunter", "defender"), now=1)
        got = {f["id"]: f["severity"] for f in out["findings"]}
        self.assertEqual(got.get("int.av_realtime"), "high")
        self.assertNotIn("int.av_infected", got)

    def test_an_infection_outranks_it_and_only_one_of_the_two_is_raised(self):
        dev = {"name": "w", "sysinfo": {}}
        out = advisory.build({"w": dev}, av_by_dev={"w": {"defender": {"realtime_enabled": False, "infected": 1}}},
                             av_tools=("defender",), now=1)
        ids = {f["id"] for f in out["findings"]}
        self.assertIn("int.av_infected", ids)
        self.assertNotIn("int.av_realtime", ids)

    def test_without_the_tool_list_nothing_is_read(self):
        dev = {"name": "w", "sysinfo": {}}
        out = advisory.build({"w": dev}, av_by_dev={"w": {"clamav": {"infected": 5}}}, now=1)
        self.assertNotIn("int.av_infected", {f["id"] for f in out["findings"]})


class TestEcc(unittest.TestCase):

    def _ids(self, ecc):
        out = advisory.build({"d": {"name": "d", "sysinfo": {"ecc": ecc}}}, now=1)
        return {f["id"] for f in out["findings"]}

    def test_correctable_errors_alone_are_not_a_finding(self):
        """Corrected bit errors are normal; the reliability score weighs them. The advisory speaks for the uncorrectable ones."""
        self.assertNotIn("data.ecc", self._ids({"ue": 0, "ce": 50}))

    def test_one_uncorrectable_error_is_one_and_singular(self):
        out = advisory.build({"d": {"name": "d", "sysinfo": {"ecc": {"ue": 1, "ce": 0}}}}, now=1)
        f = [x for x in out["findings"] if x["id"] == "data.ecc"][0]
        self.assertEqual(f["title"], "1 uncorrectable memory error")

    def test_the_wrong_kinds_are_nothing(self):
        for ue in (True, "4", None, -1, 2.5):
            self.assertNotIn("data.ecc", self._ids({"ue": ue}), ue)
        for ecc in (None, "x", [], 5):
            self.assertNotIn("data.ecc", self._ids(ecc), ecc)


class TestOnePoolRule(unittest.TestCase):

    def test_the_states(self):
        for s in ("ONLINE", "online", "active", "clean", "healthy", "ok", " Online "):
            self.assertFalse(ps.pool_unhealthy(s), s)
        for s in ("DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SUSPENDED", "degraded", "unknown", "inactive", "rebuilding"):
            self.assertTrue(ps.pool_unhealthy(s), s)

    def test_an_empty_state_says_nothing(self):
        for s in ("", None, "   "):
            self.assertFalse(ps.pool_unhealthy(s), repr(s))

    def test_the_four_readers_take_the_set_from_one_place(self):
        api_src = (_CGI / "api.py").read_text()
        for needle in ("'online', 'active', 'clean', 'healthy', 'ok'", '"online", "active", "clean", "healthy", "ok"'):
            self.assertNotIn(needle, api_src)
            self.assertNotIn(needle, (_CGI / "checks.py").read_text())
            self.assertNotIn(needle, (_CGI / "reports_handlers.py").read_text())
        self.assertIn("posture_signals.POOL_OK", (_CGI / "reports_handlers.py").read_text())
        self.assertIn("posture_signals.pool_unhealthy", (_CGI / "checks.py").read_text())

    def test_the_checks_row_judges_an_unreadable_array_the_way_the_advisory_does(self):
        import checks
        dev = {"name": "h", "last_seen": int(time.time()), "monitored": True,
               "sysinfo": {"storage_health": [{"name": "md0", "state": "unknown"}]}}
        rows = {r["key"]: r for r in checks._host_checks("d", dev, {}, now=int(time.time()))}
        self.assertEqual(rows["storage"]["status"], "critical")
        out = advisory.build({"d": dev}, now=1)
        self.assertIn("data.pool", {f["id"] for f in out["findings"]})


if __name__ == "__main__":
    unittest.main()
