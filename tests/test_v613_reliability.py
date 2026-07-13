"""v6.1.3 — device reliability prediction (competitive-gap item #23).

"How likely is this host to BREAK?" — deliberately SEPARATE from the risk score,
which answers "how EXPOSED is this host?" (CVEs, ports, policy, EOL). A fully
patched server with a dying disk is low-risk and low-reliability; an operator
needs to see exactly that, and merging them would hide it.

No new collection: every input is already stored. The tests below pin the three
things that are easy to get silently wrong:

  1. The RAW SMART dict uses long field names (wear_pct/pending_sectors/
     reallocated_sectors); only the HISTORY samples use the short ones
     (wear/pending/realloc). Reading the wrong ones scores every disk at zero,
     forever, and looks perfectly correct in review.
  2. The cache must fingerprint on OPERATOR inputs, never DEVICES_FILE mtime —
     every heartbeat rewrites devices.json, so an mtime-keyed cache never hits
     on a real fleet (the v6.1.2 _attention_payload bug).
  3. Unit flapping is deliberately NOT scored: services.json keeps only the
     CUMULATIVE NRestarts counter, and the flap DELTA is never persisted.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-rel-"))
_spec = importlib.util.spec_from_file_location("api_v613_rel", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

NOW = int(time.time())


def _score(hw=None, smart_hist=None, health=None, uptime=None, sysinfo=None):
    return api._device_reliability(
        "d1", {"name": "nas", "sysinfo": sysinfo or {}}, hw, smart_hist,
        health, uptime, None, None, NOW)


class TestHealthyHostScoresZero(unittest.TestCase):
    def test_a_healthy_host_has_no_factors(self):
        r = _score(hw={"smart": [{"device": "/dev/sda", "serial": "S1",
                                  "health": "PASSED", "reallocated_sectors": 0,
                                  "pending_sectors": 0, "wear_pct": 3}]})
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["level"], "low")
        self.assertEqual(r["factors"], [])

    def test_no_data_at_all_is_not_a_failure_prediction(self):
        """A host that has never reported hardware must not read as 'about to
        die' — absence of evidence is not evidence."""
        r = _score()
        self.assertEqual(r["score"], 0)


class TestDiskSignals(unittest.TestCase):
    def test_raw_smart_field_names_are_read_correctly(self):
        """THE bug this test exists for: reading d['wear'] instead of
        d['wear_pct'] silently scores every disk at zero."""
        r = _score(hw={"smart": [{"device": "/dev/sda", "serial": "S1",
                                  "health": "PASSED", "wear_pct": 95,
                                  "pending_sectors": 4}]})
        kinds = {f["kind"] for f in r["factors"]}
        self.assertIn("wear_high", kinds)
        self.assertIn("pending_sectors", kinds)

    def test_growing_reallocated_sectors_is_predictive_not_reactive(self):
        """A disk with 4 reallocated sectors that has had 4 for a year is fine.
        One that went 0 -> 4 this month is on its way out. Only the second scores."""
        stable = {"S1": {"samples": [{"ts": NOW - 86400 * i, "realloc": 4}
                                     for i in range(10, 0, -1)]}}
        growing = {"S1": {"samples": [{"ts": NOW - 86400 * i, "realloc": 12 - i}
                                      for i in range(10, 0, -1)]}}
        hw = {"smart": [{"device": "/dev/sda", "serial": "S1", "health": "PASSED",
                         "reallocated_sectors": 4}]}
        flat = {f["kind"] for f in _score(hw=hw, smart_hist=stable)["factors"]}
        rising = {f["kind"] for f in _score(hw=hw, smart_hist=growing)["factors"]}
        self.assertNotIn("realloc_growing", flat)
        self.assertIn("realloc_growing", rising)

    def test_a_failing_disk_dominates_the_score(self):
        r = _score(hw={"smart": [{"device": "/dev/sda", "serial": "S1",
                                  "health": "FAILED"}]})
        self.assertGreaterEqual(r["score"], 40)
        self.assertEqual(r["factors"][0]["kind"], "smart_failing")


class TestOtherSignals(unittest.TestCase):
    def test_uncorrectable_ecc_outweighs_correctable(self):
        """An uncorrectable error means the DIMM could NOT fix it — a different
        universe from a corrected one."""
        ue = _score(sysinfo={"ecc": {"ue": 1, "ce": 0}})["score"]
        ce = _score(sysinfo={"ecc": {"ue": 0, "ce": 1}})["score"]
        self.assertGreater(ue, ce)

    def test_reboot_churn_needs_repeated_returns(self):
        """One reboot is a reboot. Five in a week is a symptom."""
        one = {"events": [{"ts": NOW - 3600, "online": False},
                          {"ts": NOW - 1800, "online": True}]}
        many = {"events": [{"ts": NOW - 3600 * i, "online": i % 2 == 0}
                           for i in range(12, 0, -1)]}
        self.assertNotIn("reboot_churn", {f["kind"] for f in _score(uptime=one)["factors"]})
        self.assertIn("reboot_churn", {f["kind"] for f in _score(uptime=many)["factors"]})

    def test_declining_health_trajectory_scores(self):
        falling = [{"ts": NOW - 86400 * i, "score": 60 + i * 2} for i in range(10, 0, -1)]
        steady = [{"ts": NOW - 86400 * i, "score": 90} for i in range(10, 0, -1)]
        self.assertIn("health_declining",
                      {f["kind"] for f in _score(health=falling)["factors"]})
        self.assertNotIn("health_declining",
                         {f["kind"] for f in _score(health=steady)["factors"]})

    def test_factors_are_explainable_and_sorted_worst_first(self):
        r = _score(hw={"smart": [{"device": "/dev/sda", "serial": "S1",
                                  "health": "FAILED", "wear_pct": 99}]})
        self.assertGreater(len(r["factors"]), 1)
        pts = [f["points"] for f in r["factors"]]
        self.assertEqual(pts, sorted(pts, reverse=True))
        for f in r["factors"]:
            self.assertTrue(f["detail"], "every factor must explain itself")


class TestUnitFlappingIsDeliberatelyNotScored(unittest.TestCase):
    def test_cumulative_restarts_do_not_score(self):
        """services.json keeps only the CUMULATIVE NRestarts counter; the flap
        DELTA is computed in-flight and never persisted. Scoring restarts>0 would
        mark every host that ever deployed a service as failing."""
        src = (_CGI / "api.py").read_text()
        i = src.index("_RELIABILITY_WEIGHTS = {")
        self.assertNotIn("unit_flapping", src[i:i + 900])


class TestCachingAndScoping(unittest.TestCase):
    def test_fingerprint_busts_on_membership_not_on_telemetry(self):
        """The distinction that makes a short-TTL fleet cache both correct AND
        useful:

          * devices.json is rewritten by EVERY heartbeat, so keying the cache on
            its MTIME means the cache never hits on a real fleet (the v6.1.2
            _attention_payload bug).
          * But an operator adding or removing a device expects to see it
            immediately — and that changes the device KEY SET, which a heartbeat
            does not.

        So: fingerprint the SET, tolerate <=TTL-stale telemetry.
        """
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def _reliability_fingerprint"):
                 src.index("def _fleet_reliability_cached")]
        body = fn[fn.index("parts = ["):]
        self.assertIn("_device_set_fingerprint()", body)
        self.assertNotIn("backend_mtime(DEVICES_FILE)", body)
        self.assertNotIn("HARDWARE_FILE", body)

    def test_adding_a_device_changes_the_fingerprint(self):
        api.save(api.DEVICES_FILE, {"a": {"name": "a"}})
        fp1 = api._device_set_fingerprint()
        api.save(api.DEVICES_FILE, {"a": {"name": "a"}, "b": {"name": "b"}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertNotEqual(fp1, api._device_set_fingerprint())

    def test_a_heartbeat_does_not_change_the_fingerprint(self):
        """The whole point: telemetry churn must NOT bust the cache."""
        api.save(api.DEVICES_FILE, {"a": {"name": "a", "last_seen": 1}})
        fp1 = api._device_set_fingerprint()
        api.save(api.DEVICES_FILE, {"a": {"name": "a", "last_seen": 999}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(fp1, api._device_set_fingerprint())

    def test_risk_cache_was_fixed_the_same_way(self):
        """The pre-existing _fleet_risk_cached had the same never-hits bug."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def _fleet_risk_cached"):src.index("def _compute_fleet_risk")]
        self.assertIn("_risk_fingerprint()", fn)
        self.assertNotIn("backend_mtime(src) > cache_mtime", fn)

    def test_overview_folds_in_tenant_isolation(self):
        """A tenant admin resolves to scope=None but must NOT see another
        tenant's hosts — the v6.1.1 fleet-aggregate leak class. The fix is to
        route the device set through _scope_filter_devices."""
        src = (_CGI / "api.py").read_text()
        fn = src[src.index("def handle_reliability_overview"):
                 src.index("def _risk_fingerprint")]
        self.assertIn("_scope_filter_devices", fn)
        self.assertIn("_tenant_gate()", fn)


class TestNeedsAttentionWiring(unittest.TestCase):
    def test_kind_is_registered_in_the_routing_matrix(self):
        """An NA kind missing from CHANNEL_KIND_DEFS is silently dropped by the
        routing gate in _compute_attention."""
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn("reliability", kinds)

    def test_kind_is_muteable(self):
        """An NA kind with no _NA_MUTE_EVENTS row is UNMUTEABLE — and an
        unmuteable item permanently depresses the host's and the fleet's health
        score with no operator recourse."""
        keys = {k for k, _ in api._NA_MUTE_EVENTS}
        self.assertIn("reliability", keys)
        for ev in api._NA_MUTE_EVENTS[("reliability", "critical")]:
            self.assertIn(ev, api.EVENT_REGISTRY, f"{ev} is not a real event")

    def test_route_registered(self):
        self.assertIn("'/api/reliability'", (_CGI / "api.py").read_text())


if __name__ == "__main__":
    unittest.main()
