"""v6.4.0 — the last five auto-heal gaps get real recovery observers.

_AUTOHEAL_GAPS is empty now: every stateful alert auto-resolves.
  cve_found   → cve_cleared   (scan reports no filtered findings left)
  patch_alert → patch_ok      (upgradable count back under the threshold)
  tls_expiry  → tls_renewed   (probe crosses back above the warn window)
  ecc_errors  → ecc_stable    (24 quiet hours after the last counter rise)
  secret_exposed → secret_cleared (rescan finds no unmuted findings)
Each observer is DRIVEN here (not just registry-pinned), and the tls match
keys are exercised through the real _record_alert → _auto_resolve path (the
hand-built-payload false-green trap from v4.9.0).
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-heal-"))
_spec = importlib.util.spec_from_file_location("api_v640_heal", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    _FILES = ("CONFIG_FILE", "DEVICES_FILE", "ALERTS_FILE", "POSTURE_STATE_FILE",
              "SECRETS_FILE", "CVE_IGNORE_FILE", "FLEET_EVENTS_FILE",
              "UPTIME_FILE")

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in self._FILES:
            if hasattr(api, attr):
                self._files[attr] = getattr(api, attr)
                setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.fire_webhook = self._orig_fire
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def events(self):
        return [e for e, _ in self.fired]


class TestGapListIsEmpty(unittest.TestCase):
    def test_no_gaps_remain(self):
        self.assertEqual(set(api._AUTOHEAL_GAPS), set(),
                         "every stateful alert must auto-resolve — build the "
                         "observer, don't grow the gap list")

    def test_all_five_resolvers_registered(self):
        for ev, target in (("cve_cleared", "cve_found"),
                           ("patch_ok", "patch_alert"),
                           ("tls_renewed", "tls_expiry"),
                           ("ecc_stable", "ecc_errors"),
                           ("secret_cleared", "secret_exposed")):
            self.assertIn(target, api.EVENT_REGISTRY[ev].get("resolves", ()),
                          ev)


class TestCveCleared(_Base):
    def test_clears_when_no_filtered_findings_remain(self):
        prev = [{"vuln_id": "CVE-1", "package": "a", "severity": "critical"}]
        api._detect_new_cve_and_fire_webhook(
            "d1", {"d1": {"name": "h"}}, prev, [])
        self.assertIn("cve_cleared", self.events())

    def test_still_bad_does_not_clear(self):
        prev = [{"vuln_id": "CVE-1", "package": "a", "severity": "critical"}]
        cur = [{"vuln_id": "CVE-2", "package": "b", "severity": "high"}]
        api._detect_new_cve_and_fire_webhook(
            "d1", {"d1": {"name": "h"}}, prev, cur)
        self.assertNotIn("cve_cleared", self.events())


class TestPatchOk(_Base):
    def _sweep(self, upgradable, alerted):
        now = int(time.time())
        api.save(api.CONFIG_FILE, {
            api.PATCH_ALERT_KEY: 5,
            "patch_alerted": {"d1": alerted},
        })
        api.save(api.DEVICES_FILE, {"d1": {
            "name": "h", "last_seen": now, "token": "t",
            "sysinfo": {"packages": {"upgradable": upgradable}}}})
        api._LOAD_CACHE.clear()
        api.check_offline_webhooks()

    def test_recovery_fires_patch_ok(self):
        self._sweep(upgradable=0, alerted=True)
        self.assertIn("patch_ok", self.events())

    def test_no_prior_alert_stays_silent(self):
        self._sweep(upgradable=0, alerted=False)
        self.assertNotIn("patch_ok", self.events())


class TestTlsRenewed(_Base):
    def test_crossing_back_above_warn_emits(self):
        T = api.tls_ct_handlers_mod   # the BOUND instance (A -> api globals)
        now = int(time.time())
        tgt = {"host": "web.example.com", "port": 443, "warn_days": 14}
        prev = {"expires_at": now + 5 * 86400}
        cur = {"expires_at": now + 80 * 86400}
        out = T._tls_renewal_crossings(tgt, prev, cur)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "web.example.com")
        # no prior probe = baseline, healthy->healthy = no event
        self.assertEqual(T._tls_renewal_crossings(tgt, None, cur), [])
        self.assertEqual(T._tls_renewal_crossings(tgt, cur, cur), [])

    def test_resolves_only_the_matching_host_and_port(self):
        # REAL alert path (a hand-built payload dict bypasses the whitelist).
        a1 = api._record_alert("tls_expiry",
                               {"host": "a.example.com", "port": 443,
                                "days_left": 3, "severity": "critical"})
        a2 = api._record_alert("tls_expiry",
                               {"host": "a.example.com", "port": 8443,
                                "days_left": 3, "severity": "critical"})
        self.assertTrue(a1 and a2, "alerts must record for this test to mean anything")
        api._auto_resolve_alerts("tls_renewed",
                                 {"host": "a.example.com", "port": 443,
                                  "days_left": 80})
        alerts = (api.load(api.ALERTS_FILE) or {}).get("alerts") or []
        by_port = {(a.get("payload") or {}).get("port"): a for a in alerts}
        self.assertTrue(by_port[443].get("resolved_at"),
                        ":443 renewal must resolve the :443 alert")
        self.assertFalse(by_port[8443].get("resolved_at"),
                         ":8443 is still expiring — must stay open")


class TestEccStable(_Base):
    def _ingest(self, ce, ue):
        api._ingest_posture_v3110("d1", "h", {"ecc": {"ce": ce, "ue": ue}})

    def test_quiet_24h_after_rise_fires_once(self):
        self._ingest(0, 0)                    # baseline (first_seen)
        self._ingest(5, 0)                    # rise -> ecc_errors
        self.assertIn("ecc_errors", self.events())
        # rewind the stored last_rise past the 24h window
        st = api._entity_read_one(api.POSTURE_STATE_FILE, "d1", None) or {}
        st["ecc"]["last_rise"] = int(time.time()) - 25 * 3600
        api._entity_write_one(api.POSTURE_STATE_FILE, "d1", st)
        api._LOAD_CACHE.clear()
        self._ingest(5, 0)                    # flat -> stable
        self.assertIn("ecc_stable", self.events())
        n = self.events().count("ecc_stable")
        self._ingest(5, 0)                    # still flat -> latched, no re-fire
        self.assertEqual(self.events().count("ecc_stable"), n)

    def test_new_rise_rearms(self):
        self.test_quiet_24h_after_rise_fires_once()
        self._ingest(9, 0)                    # rises again
        self.assertEqual(self.events().count("ecc_errors"), 2)


class TestSecretCleared(_Base):
    def _ingest(self, findings):
        api._ingest_secret_findings("d1", "h", findings)

    def test_rescan_with_no_findings_clears(self):
        f = [{"rule": "aws_key", "path": "/home/x/.env",
              "fingerprint": "fp1", "preview": "AKIA..."}]
        self._ingest(f)
        self.assertIn("secret_exposed", self.events())
        self._ingest([])
        self.assertIn("secret_cleared", self.events())

    def test_never_had_findings_stays_silent(self):
        self._ingest([])
        self.assertNotIn("secret_cleared", self.events())


if __name__ == "__main__":
    unittest.main()
