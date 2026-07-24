"""v6.4.0 — alert-parameters coverage + per-instance recover-clearing fixes.

Two audits of the alerting stack found:
1. Four recover events over-cleared: disk_predict_cleared / policy_compliant /
   backup_verified / port_closed fell through to device_id-only matching and
   cleared EVERY sibling alert on the host (a fixed disk cleared a still-failing
   one). Fixed with sub_match branches PLUS coalesce-identity entries for
   `disk` / `rule` (port/proto/path were already discriminators).
2. One truly un-tunable threshold: the Windows/macOS CPU-percent band was
   hardcoded 85/95 in checks.py. Now cpu_pct_warn/cpu_pct_crit are on the
   Alert-parameters page.
These drive the REAL _record_alert → _auto_resolve path (a hand-built payload
would bypass the coalesce identity and give a false green).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-cov-"))
_spec = importlib.util.spec_from_file_location("api_v640_cov", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import checks as checks_mod  # noqa: E402


class TestPerInstanceRecoverClearing(unittest.TestCase):
    """A recover on ONE instance must clear only that instance's alert."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._af = api.ALERTS_FILE
        api.ALERTS_FILE = self.d / "alerts.json"
        api.save(api.ALERTS_FILE, {"alerts": []})
        self._orig = {n: getattr(api, n) for n in
                      ("_module_on", "_channel_allowed", "device_get")}
        api._module_on = lambda n: True
        api._channel_allowed = lambda e, c: True
        api.device_get = lambda i: {"monitored": True}
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.ALERTS_FILE = self._af
        api._LOAD_CACHE.clear()

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if not a.get("resolved_at")]

    def _case(self, ev_fail, ev_ok, disc, vals, extra=None):
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._LOAD_CACHE.clear()
        for v in vals:
            pl = {"device_id": "h1", "name": "h", disc: v}
            if extra:
                pl.update(extra)
            api._record_alert(ev_fail, pl)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self._open()), 2,
                         f"{ev_fail}: two instances must be TWO alerts "
                         "(coalesce-identity discriminator missing?)")
        rec = {"device_id": "h1", disc: vals[0]}
        if extra:
            rec.update(extra)
        api._auto_resolve_alerts(ev_ok, rec)
        api._LOAD_CACHE.clear()
        rem = self._open()
        self.assertEqual(len(rem), 1, f"{ev_ok}: cleared too many")
        self.assertEqual(rem[0]["payload"].get(disc), vals[1],
                         f"{ev_ok}: cleared the WRONG instance")

    def test_disk_predict_per_disk(self):
        self._case("disk_predict_fail", "disk_predict_cleared", "disk",
                   ["sda", "sdb"], extra={"eta_days": 30})

    def test_software_policy_per_rule(self):
        self._case("software_policy_violation", "policy_compliant", "rule",
                   ["r1", "r2"], extra={"package": "p"})

    def test_backup_verify_per_path(self):
        self._case("backup_verify_failed", "backup_verified", "path",
                   ["/a", "/b"], extra={"label": "x"})

    def test_new_port_per_socket(self):
        self._case("new_port_detected", "port_closed", "port",
                   [8080, 9090], extra={"proto": "tcp"})

    def test_disc_and_rule_in_coalesce_identity(self):
        # the structural half — the discriminators the four fixes depend on
        for f in ("disk", "rule", "port", "proto", "path"):
            self.assertIn(f, api._ALERT_IDENTITY_FIELDS, f)


class TestCpuBandTunable(unittest.TestCase):
    def test_checks_honours_the_configurable_band(self):
        dev = {"sysinfo": {"cpu_percent": 88}}
        warn = checks_mod._host_checks("h", dev, cpu_pct_warn=85, cpu_pct_crit=95)
        ok = checks_mod._host_checks("h", dev, cpu_pct_warn=90, cpu_pct_crit=95)
        cpu_w = next(c for c in warn if c["key"] == "cpu")["status"]
        cpu_o = next(c for c in ok if c["key"] == "cpu")["status"]
        self.assertEqual(cpu_w, "warning")
        self.assertEqual(cpu_o, "ok")

    def test_inverted_band_clamps(self):
        dev = {"sysinfo": {"cpu_percent": 100}}
        # crit <= warn must not break the ladder
        r = checks_mod._host_checks("h", dev, cpu_pct_warn=95, cpu_pct_crit=90)
        self.assertEqual(next(c for c in r if c["key"] == "cpu")["status"],
                         "critical")

    def test_page_wiring_present(self):
        html = (ROOT / "server" / "html" / "index.html").read_text()
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        for needle in ('id="ap-cpu-pct-warn"', 'id="ap-cpu-pct-crit"'):
            self.assertIn(needle, html, needle)
        self.assertIn("'cpu_pct_warn'", js)
        self.assertIn("'cpu_pct_crit'", js)


class TestCpuBandConfigRoundTrip(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {a: getattr(api, a) for a in
                       ("CONFIG_FILE", "USERS_FILE", "ROLES_FILE")}
        for a in self._files:
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "t"
        api.verify_token = lambda t: ("t", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def test_save_and_default(self):
        api.get_json_obj = lambda: {"cpu_pct_warn": 70, "cpu_pct_crit": 92}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg.get("cpu_pct_warn"), 70)
        self.assertEqual(cfg.get("cpu_pct_crit"), 92)
        # threshold kwargs helper feeds them to _host_checks
        kw = api._checks_threshold_kwargs(cfg)
        self.assertEqual(kw["cpu_pct_warn"], 70)
        self.assertEqual(kw["cpu_pct_crit"], 92)


if __name__ == "__main__":
    unittest.main()
