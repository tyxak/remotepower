"""Response-shape contracts for the endpoints the UI binds hardest.

The recurring data-binding bug class: a server-side field rename ships, the UI
silently renders blanks, and a finalize sweep finds it weeks later. These
tests drive the REAL handlers over a seeded store and pin the keys (and value
kinds) the frontend actually reads — a rename now fails a test instead of a
release sweep.

Deliberately a FLOOR, not a snapshot: only load-bearing keys are pinned (the
ones a grep of app.js shows the UI reading), so adding fields never breaks
this file; removing or renaming one does.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-contracts-"))
_spec = importlib.util.spec_from_file_location("api_contracts", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _assert_keys(tc, obj, spec, where):
    for key, kinds in spec.items():
        tc.assertIn(key, obj, f"{where}: missing key {key!r}")
        if kinds is not None:
            tc.assertIsInstance(obj[key], kinds,
                                f"{where}: {key!r} is {type(obj[key]).__name__}")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls._files = {}
        for attr in [a for a in dir(api) if a.endswith("_FILE")]:
            v = getattr(api, attr)
            if isinstance(v, Path):
                cls._files[attr] = v
                setattr(api, attr, cls.d / v.name)
        cls._orig = {n: getattr(api, n) for n in
                     ("require_auth", "require_admin_auth", "verify_token",
                      "get_token_from_request")}
        api.require_auth = lambda *a, **k: "admin"
        api.require_admin_auth = lambda: "admin"
        api.verify_token = lambda t: ("admin", "admin")
        api.get_token_from_request = lambda *a, **k: "x"
        now = int(time.time())
        api.save(api.DEVICES_FILE, {"dev1": {
            "name": "host1", "ip": "10.0.0.1", "group": "lab",
            "last_seen": now, "token": "t",
            "sysinfo": {"cpu_percent": 5, "mem_percent": 40,
                        "disk_percent": 50, "os": "Arch Linux",
                        "kernel": "6.1"}}})
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["monitors"] = [{"label": "web", "type": "http",
                            "target": "https://example.com/",
                            "slo_ids": ["slo-web"]}]
        cfg["slo_objects"] = [{"id": "slo-web", "name": "Web",
                               "target_pct": 99.9, "window_days": 30}]
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.MON_HIST_FILE,
                 {"web": [{"ts": now - 60, "ok": True, "ms": 12}]})
        api._LOAD_CACHE.clear()

    @classmethod
    def tearDownClass(cls):
        for n, v in cls._orig.items():
            setattr(api, n, v)
        for attr, v in cls._files.items():
            setattr(api, attr, v)
        api._LOAD_CACHE.clear()

    def _call(self, handler, method="GET"):
        api._RCTX.environ = {"REQUEST_METHOD": method}
        api._LOAD_CACHE.clear()
        try:
            handler()
        except api.HTTPError as e:      # respond() AND _respond_with_etag
            return e.status, e.body
        self.fail(f"{handler.__name__} returned without responding")


class TestHomeContract(_Base):
    def test_home_shape(self):
        st, b = self._call(api.handle_home)
        self.assertEqual(st, 200)
        _assert_keys(self, b, {
            "devices": list, "health": dict, "attention": dict,
            "fleet_events": list, "widgets": (list, dict), "modules": dict,
            "config": dict, "tickets_open": int, "show_homelab": bool,
        }, "/api/home")
        row = b["devices"][0]
        _assert_keys(self, row, {
            "id": str, "name": str, "online": bool, "group": str,
            "last_seen": int, "missed_polls": int, "monitored": bool,
            "os": str, "sysinfo": dict, "tags": (list, type(None)),
            "metric_state": (dict, type(None)),
        }, "/api/home devices[0]")

    def test_devices_list_is_a_list_of_rows(self):
        st, b = self._call(api.handle_devices_list)
        self.assertEqual(st, 200)
        self.assertIsInstance(b, list)
        _assert_keys(self, b[0], {"id": str, "name": str, "online": bool},
                     "/api/devices [0]")


class TestNavCountsContract(_Base):
    def test_nav_counts_shape(self):
        st, b = self._call(api.handle_nav_counts)
        self.assertEqual(st, 200)
        _assert_keys(self, b, {
            "alerts": dict, "fleet": int, "monitoring": int,
            "security": int, "site_health": dict, "tickets_open": int,
            "commands_pending": int, "confirmations_pending": int,
            "quiet_hours_active": bool,
        }, "/api/nav-counts")
        _assert_keys(self, b["site_health"],
                     {"healthy": bool}, "site_health")


class TestSloContract(_Base):
    def test_slo_shape(self):
        st, b = self._call(api.handle_slo)
        self.assertEqual(st, 200)
        _assert_keys(self, b, {"target": float, "monitors": list,
                               "objects": list}, "/api/slo")
        obj = b["objects"][0]
        _assert_keys(self, obj, {
            "id": str, "name": str, "target": float, "window_days": int,
            "monitors": list, "checks": int, "availability": (float, int),
            "budget_remaining_pct": (float, int),
            "meeting_slo": bool,
        }, "/api/slo objects[0]")


class TestMonitorContract(_Base):
    def test_monitor_rows_shape(self):
        # no real probes — stub the executor, keep the response assembly real
        orig = api._execute_monitor_checks
        origp = api._persist_monitor_results
        api._execute_monitor_checks = lambda monitors: [
            {"label": "web", "type": "http", "target": "https://example.com/",
             "ok": True, "detail": "200 · 12ms", "checked": int(time.time()),
             "ms": 12}]
        api._persist_monitor_results = lambda results: None
        try:
            st, b = self._call(api.handle_monitor_run)
        finally:
            api._execute_monitor_checks = orig
            api._persist_monitor_results = origp
        self.assertEqual(st, 200)
        row = b["monitors"][0]
        _assert_keys(self, row, {
            "label": str, "type": str, "target": str, "ok": bool,
            "detail": str, "checked": int, "origin": str,
        }, "/api/monitor rows[0]")


class TestSelfStatusContract(_Base):
    def test_self_status_shape(self):
        st, b = self._call(api.handle_self_status)
        self.assertEqual(st, 200)
        _assert_keys(self, b, {
            "server_version": str, "storage_backend": dict, "devices": dict,
            "webhooks": dict, "audit_log": dict, "backup": dict,
            "cadence_jobs": (list, dict), "now": int,
        }, "/api/self/status")


class TestConfigContract(_Base):
    def test_config_get_shape(self):
        st, b = self._call(api.handle_config_get)
        self.assertEqual(st, 200)
        _assert_keys(self, b, {
            "monitors": list, "slo_objects": list, "monitor_interval": int,
            "webhook_configured": bool, "default_poll_interval": int,
            "online_ttl": int,
        }, "/api/config")


if __name__ == "__main__":
    unittest.main()
