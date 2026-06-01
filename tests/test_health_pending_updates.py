"""
Regression test: pending package updates must dent the fleet health score.

The per-device health score is 100 minus the severity weight of each Needs
Attention item for that device. The pending-patch NA item read a non-existent
top-level `dev['upgradable']` field instead of the real count at
`dev['sysinfo']['packages']['upgradable']` (what the agent reports and the
heatmap renders), so a device with pending updates kept a perfect 100.

Pure stdlib unittest (runs under `python -m unittest discover` and pytest).
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class TestHealthPendingUpdates(unittest.TestCase):
    # Isolate every flat file _compute_attention reads, so stale state written by
    # an earlier test in the same process (a failed service, SMART warning, etc.)
    # can't leak an extra attention item into the absolute health score.
    _FILES = ("DEVICES_FILE", "CVE_FINDINGS_FILE", "CVE_IGNORE_FILE",
              "FLEET_EVENTS_FILE", "IGNORED_ITEMS_FILE", "CONFIG_FILE",
              "ACME_STATE_FILE", "AFTER_HOURS_FILE", "BRUTE_FORCE_FILE",
              "CONTAINERS_FILE", "HARDWARE_FILE", "METRICS_HIST_FILE",
              "MON_HIST_FILE", "PACKAGES_FILE", "PROXMOX_SNAPSHOT_CACHE",
              "SERVICES_FILE", "TLS_RESULTS_FILE", "TLS_TARGETS_FILE",
              "DRIFT_STATE_FILE", "UPTIME_FILE")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a, None) for a in self._FILES}
        for a in self._FILES:
            if hasattr(api, a):
                setattr(api, a, self.tmp / (a.lower().replace("_file", "") + ".json"))
        # Isolate the 10s NA cache file so a stale cache can't mask the compute.
        self._saved_acf = api._attention_cache_file
        api._attention_cache_file = lambda: self.tmp / "attn_cache.json"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api._attention_cache_file = self._saved_acf
        api._LOAD_CACHE.clear()

    def _seed(self, upgradable):
        api.save(api.DEVICES_FILE, {"d1": {
            "name": "d1", "group": "g", "monitored": True,
            "last_seen": int(time.time()),   # recent → not flagged offline
            "sysinfo": {"packages": {"upgradable": upgradable}},
        }})
        api._LOAD_CACHE.clear()

    def test_pending_updates_create_patches_item(self):
        self._seed(5)
        items = api._compute_attention()
        patch = [i for i in items if i.get("kind") == "patches" and i.get("device") == "d1"]
        self.assertTrue(patch, "pending updates should create a 'patches' attention item")
        self.assertEqual(patch[0]["severity"], "info")   # 5 < 20

    def test_pending_updates_lower_health_score(self):
        self._seed(5)
        h = api._fleet_health(use_cache=False)
        row = [d for d in h["devices"] if d["device_id"] == "d1"]
        self.assertTrue(row)
        self.assertEqual(row[0]["score"], 98)            # 100 − info(2)

    def test_no_pending_updates_stays_100(self):
        self._seed(0)
        h = api._fleet_health(use_cache=False)
        row = [d for d in h["devices"] if d["device_id"] == "d1"]
        self.assertEqual(row[0]["score"], 100)

    def test_large_pileup_is_warning(self):
        self._seed(25)
        items = api._compute_attention()
        patch = [i for i in items if i.get("kind") == "patches" and i.get("device") == "d1"]
        self.assertTrue(patch)
        self.assertEqual(patch[0]["severity"], "warning")  # ≥ 20

    def test_cve_item_shows_fixable_count(self):
        # The CVE attention item surfaces how many findings carry a known fixed
        # version (i.e. a package upgrade would clear them).
        api.save(api.DEVICES_FILE, {"d1": {
            "name": "d1", "group": "g", "monitored": True,
            "last_seen": int(time.time()), "sysinfo": {}}})
        api.save(api.CVE_FINDINGS_FILE, {"d1": {"findings": [
            {"id": "CVE-1", "severity": "high", "fixed_version": "1.2.3"},
            {"id": "CVE-2", "severity": "high", "fixed_version": ""},
            {"id": "CVE-3", "severity": "high"},
            # medium with a fix must NOT count — fixable is crit/high only, to
            # match the Patches page's "fixable" number.
            {"id": "CVE-4", "severity": "medium", "fixed_version": "9.9.9"},
        ]}})
        api._LOAD_CACHE.clear()
        items = api._compute_attention()
        cve = [i for i in items if i.get("kind") == "cve" and i.get("device") == "d1"]
        self.assertTrue(cve, "a device with high CVEs should get a 'cve' attention item")
        self.assertIn("3 high", cve[0]["summary"])
        self.assertIn("1 fixable", cve[0]["summary"])   # only the high one, not the medium


if __name__ == "__main__":
    unittest.main()
