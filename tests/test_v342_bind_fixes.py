"""
v3.4.2 — "bind it together" data-binding + bughunt fixes.

Covers the fixes made in the v3.4.2 sweep:

  * normalize_container preserves the agent's container health / cpu / mem
    fields (they used to be dropped at the server boundary).            [D1]
  * cve_scanner.apply_ignore_list never mutates its input findings.      [B8]
  * metric_recovered auto-resolves the matching metric_warning/critical
    alert for that exact metric+target — not unrelated metric alerts.   [B2]
  * GET /api/config never returns oidc_client_secret / status_token as a
    value (only *_set booleans); webhook_url is admin-only.             [S1]
  * the fleet posture report excludes ignored CVEs, matching the live page. [B5]
  * GET /api/devices/<id>/backups joins backup_state + monitor config.  [D4]

Pure stdlib unittest.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api          # noqa: E402
import cve_scanner  # noqa: E402
import containers as containers_mod  # noqa: E402


# ─── D1: container live fields survive normalization ─────────────────────────

class TestContainerNormalizePreservesLiveFields(unittest.TestCase):
    def test_health_cpu_mem_preserved(self):
        n = containers_mod.normalize_container({
            "name": "nginx", "image": "nginx", "status": "Up 3 hours",
            "health": "healthy", "cpu_percent": 12.5, "mem_percent": 30.0,
            "mem_usage": "120MiB / 2GiB",
        })
        self.assertEqual(n["health"], "healthy")
        self.assertEqual(n["cpu_percent"], 12.5)
        self.assertEqual(n["mem_percent"], 30.0)
        self.assertEqual(n["mem_usage"], "120MiB / 2GiB")

    def test_missing_stats_become_none_not_zero(self):
        n = containers_mod.normalize_container({"name": "x"})
        self.assertIsNone(n["cpu_percent"])
        self.assertIsNone(n["mem_percent"])
        self.assertEqual(n["health"], "")

    def test_pct_clamped(self):
        n = containers_mod.normalize_container(
            {"name": "x", "cpu_percent": 250, "mem_percent": -5})
        self.assertEqual(n["cpu_percent"], 100.0)
        self.assertEqual(n["mem_percent"], 0.0)


# ─── B8: apply_ignore_list must not mutate the caller's input ────────────────

class TestApplyIgnoreNoMutate(unittest.TestCase):
    def test_input_not_mutated(self):
        findings = [{"vuln_id": "CVE-1", "severity": "high"}]
        out = cve_scanner.apply_ignore_list(findings, {}, "dev1")
        self.assertNotIn("ignored", findings[0])      # input untouched
        self.assertFalse(out[0]["ignored"])           # output flagged
        self.assertIsNot(out[0], findings[0])         # distinct object

    def test_ignored_branch_also_copies(self):
        findings = [{"vuln_id": "CVE-2", "severity": "high"}]
        ig = {"CVE-2": {"scope": "global", "reason": "false positive"}}
        out = cve_scanner.apply_ignore_list(findings, ig, "dev1")
        self.assertNotIn("ignored", findings[0])
        self.assertTrue(out[0]["ignored"])
        self.assertEqual(out[0]["ignore_reason"], "false positive")


# ─── api-backed tests share this harness ─────────────────────────────────────

class _ApiBase(unittest.TestCase):
    _FILES = ("DEVICES_FILE", "CONFIG_FILE", "ALERTS_FILE",
              "CVE_FINDINGS_FILE", "CVE_IGNORE_FILE")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a, None) for a in self._FILES}
        for a in self._FILES:
            setattr(api, a, self.tmp / (a.lower().replace("_file", "") + ".json"))
        self._dd = api.DATA_DIR
        api.DATA_DIR = self.tmp
        self._fns = {f: getattr(api, f, None)
                     for f in ("get_token_from_request", "verify_token",
                               "respond", "require_auth", "fire_webhook")}
        api.respond = lambda s, b=None: (_ for _ in ()).throw(api.HTTPError(s, b))
        api.require_auth = lambda *a, **k: "admin"
        api.fire_webhook = lambda *a, **k: None
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api.DATA_DIR = self._dd
        for f, v in self._fns.items():
            if v is not None:
                setattr(api, f, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        return None, None


# ─── B2: metric_recovered auto-resolves the right metric alert ───────────────

class TestMetricRecoveredAutoResolve(_ApiBase):
    def _seed_alerts(self, alerts):
        api.save(api.ALERTS_FILE, {"alerts": alerts})
        api._LOAD_CACHE.clear()

    def test_resolves_matching_metric_only(self):
        self._seed_alerts([
            {"event": "metric_warning", "device_id": "d1",
             "payload": {"metric": "disk", "target": "/var"}, "resolved_at": None},
            {"event": "metric_critical", "device_id": "d1",
             "payload": {"metric": "memory", "target": ""}, "resolved_at": None},
        ])
        api._auto_resolve_alerts("metric_recovered", {
            "device_id": "d1", "metric": "disk", "target": "/var"})
        store = api.load(api.ALERTS_FILE)
        by_metric = {a["payload"]["metric"]: a for a in store["alerts"]}
        self.assertTrue(by_metric["disk"]["resolved_at"])      # recovered → resolved
        self.assertIsNone(by_metric["memory"]["resolved_at"])  # untouched

    def test_resolves_both_severities_for_same_metric(self):
        self._seed_alerts([
            {"event": "metric_warning", "device_id": "d1",
             "payload": {"metric": "memory", "target": ""}, "resolved_at": None},
            {"event": "metric_critical", "device_id": "d1",
             "payload": {"metric": "memory", "target": ""}, "resolved_at": None},
        ])
        api._auto_resolve_alerts("metric_recovered", {
            "device_id": "d1", "metric": "memory", "target": ""})
        store = api.load(api.ALERTS_FILE)
        self.assertTrue(all(a["resolved_at"] for a in store["alerts"]))


# ─── S1: config-get never leaks oidc_client_secret / status_token ────────────

class TestConfigGetRedactsSecrets(_ApiBase):
    def _seed_cfg(self):
        api.save(api.CONFIG_FILE, {
            "oidc_client_secret": "super-secret",
            "status_token": "stok-123",
            "webhook_url": "https://hooks.slack.com/services/T/B/secretpath",
        })
        api._LOAD_CACHE.clear()

    def test_admin_redacts_oidc_and_status_keeps_webhook(self):
        self._seed_cfg()
        api.verify_token = lambda t: ("admin", "admin")
        st, body = self.call(api.handle_config_get)
        self.assertEqual(st, 200)
        self.assertNotIn("oidc_client_secret", body)
        self.assertNotIn("status_token", body)
        self.assertTrue(body["oidc_client_secret_set"])
        self.assertTrue(body["status_token_set"])
        # admin still sees the webhook URL value (they can edit it)
        self.assertEqual(body.get("webhook_url"),
                         "https://hooks.slack.com/services/T/B/secretpath")

    def test_viewer_also_redacts_webhook_url(self):
        self._seed_cfg()
        api.verify_token = lambda t: ("bob", "viewer")
        st, body = self.call(api.handle_config_get)
        self.assertEqual(st, 200)
        self.assertNotIn("oidc_client_secret", body)
        self.assertNotIn("status_token", body)
        self.assertNotIn("webhook_url", body)
        self.assertTrue(body["webhook_configured"])  # boolean still tells them


# ─── D4: device backups endpoint joins state + monitor config ────────────────

class TestDeviceBackupsEndpoint(_ApiBase):
    def test_joins_state_and_config(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "host1"}})
        api.save(api.CONFIG_FILE, {"backup_monitors": [
            {"path": "/srv/dump.sql", "label": "DB dump", "max_age_hours": 24},
        ]})
        api.save(self.tmp / "backup_state.json", {
            "d1:/srv/dump.sql": {"ok": False, "age_h": 50.0},
            "d1:/other": {"ok": True, "age_h": 1.0},
            "d2:/srv/dump.sql": {"ok": True, "age_h": 2.0},  # other device
        })
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "GET"
        st, body = self.call(api.handle_device_backups, "d1")
        self.assertEqual(st, 200)
        paths = {b["path"] for b in body["backups"]}
        self.assertEqual(paths, {"/srv/dump.sql", "/other"})  # only d1's
        db = next(b for b in body["backups"] if b["path"] == "/srv/dump.sql")
        self.assertEqual(db["label"], "DB dump")        # joined from config
        self.assertFalse(db["ok"])
        self.assertEqual(db["max_age_hours"], 24.0)
        # stale rows sort first
        self.assertFalse(body["backups"][0]["ok"])


if __name__ == "__main__":
    unittest.main()
