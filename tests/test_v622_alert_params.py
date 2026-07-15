"""v6.2.2 — Settings → "Alert parameters" page.

A dedicated Settings tab consolidating the global alert-firing thresholds. Two
of them (`nic_err_alert_min`, `snmp_dead_threshold`) were hardcoded module
constants; three (`temp_alert_threshold_c`, `clock_skew_threshold_ms`,
`proxmox_snapshot_warn_days`) were config-backed but had no UI, so an operator
had to hand-edit config.json.

Guards the known "toggle silently doesn't persist" gotcha: a new config key must
be (1) declared in the ConfigSaveRequest model, (2) written by a `handle_config_save`
block, (3) defaulted in `handle_config_get` — or it round-trips as a no-op. This
drives the REAL save/get handlers so a missing wiring layer fails here.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-ap-"))
_spec = importlib.util.spec_from_file_location("api_v622_ap", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_NEW_KEYS = {
    "nic_err_alert_min": 12,
    "snmp_dead_threshold": 48,
    "temp_alert_threshold_c": 90,
    "clock_skew_threshold_ms": 2500,
    "proxmox_snapshot_warn_days": 14,
}
_DEFAULTS = {
    "nic_err_alert_min": api._NIC_ERR_ALERT_MIN,
    "snmp_dead_threshold": api._SNMP_DEAD_THRESHOLD,
    "temp_alert_threshold_c": 85,
    "clock_skew_threshold_ms": 1000,
    "proxmox_snapshot_warn_days": 7,
}


class _SaveBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("USERS_FILE", "CONFIG_FILE", "ROLES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            self.cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def _save(self, body):
        api.get_json_obj = lambda: body
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}


class TestAlertParamPersist(_SaveBase):
    def test_all_five_new_keys_persist(self):
        cfg = self._save(dict(_NEW_KEYS))
        for k, v in _NEW_KEYS.items():
            self.assertEqual(cfg.get(k), v, f"{k} did not persist (save-whitelist gotcha)")

    def test_blank_clears_override(self):
        self._save(dict(_NEW_KEYS))
        cfg = self._save({"nic_err_alert_min": ""})
        self.assertNotIn("nic_err_alert_min", cfg)

    def test_out_of_range_rejected(self):
        self._save({"temp_alert_threshold_c": "5000"})  # > 200 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"snmp_dead_threshold": "abc"})
        self.assertEqual(self.cap.get("s"), 400)


class TestAlertParamDefaultsExposed(unittest.TestCase):
    def test_config_get_setdefaults_present(self):
        """handle_config_get must setdefault each key so the UI renders the
        effective default on an unconfigured server."""
        src = (_CGI / "api.py").read_text()
        get_src = src[src.index("def handle_config_get"):src.index("def handle_config_save")]
        for k in _DEFAULTS:
            self.assertIn(f"setdefault('{k}'", get_src, f"{k} missing from config_get defaults")


class TestAlertParamModel(unittest.TestCase):
    def test_model_accepts_new_keys(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {k: str(v) for k, v in _NEW_KEYS.items()})
        self.assertTrue(ok, err)


class TestAlertParamFrontendWiring(unittest.TestCase):
    def test_tab_pane_loader_saver_present(self):
        html = (ROOT / "server/html/index.html").read_text()
        app = (ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn('data-tab="alertparams"', html)
        self.assertIn('id="settings-pane-alertparams"', html)
        self.assertIn("loadAlertParams", html)
        self.assertIn("loadAlertParams", app)
        self.assertIn("saveAlertParams", app)

    def test_new_inputs_present_once(self):
        html = (ROOT / "server/html/index.html").read_text()
        for _id in ("ap-nic-err-min", "ap-snmp-dead", "ap-temp-c",
                    "ap-clock-skew-ms", "ap-pmox-snap-days"):
            self.assertEqual(html.count(f'id="{_id}"'), 1, f"{_id} not present exactly once")

    def test_moved_inputs_still_present_once(self):
        html = (ROOT / "server/html/index.html").read_text()
        for _id in ("cfg-disk-watchdog-pct", "cfg-ups-critical-battery-pct",
                    "cfg-ups-critical-runtime-s", "cfg-scrub-overdue-days",
                    "cfg-snapshot-stale-days", "cfg-incident-device-threshold",
                    "health-alert-threshold", "cfg-patch-threshold"):
            self.assertEqual(html.count(f'id="{_id}"'), 1, f"{_id} not present exactly once (lost/dup by the move)")


if __name__ == "__main__":
    unittest.main()
