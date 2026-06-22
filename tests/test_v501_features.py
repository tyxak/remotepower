"""v5.0.1 "TemperMatters" feature + fix tests:
  - API keys can be edited in place (name/role/expiry/rate) without touching the secret
  - the SQLite-blind .exists() class is fixed on the host_config_current / proxmox paths
"""
import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v501-")
_spec = importlib.util.spec_from_file_location("api_v501feat", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

API_SRC = (_CGI / "api.py").read_text()


class _Stop(Exception):
    pass


def _capture_respond():
    box = {}

    def _cap(status, body=None):
        box["status"], box["body"] = status, body
        raise _Stop()

    api.respond = _cap
    return box


class TestApiKeyUpdate(unittest.TestCase):
    """PATCH /api/apikeys/{id} edits metadata; the key secret is immutable."""

    def setUp(self):
        api.save(api.APIKEYS_FILE, {
            "k1": {"name": "old", "key": "SECRET-VALUE", "user": "api",
                   "role": "viewer", "created": 1000, "active": True,
                   "rate_limit": 0, "expires_at": None},
        })
        self._orig = (api.require_admin_auth, api.method, api.get_json_body, api.respond)
        api.require_admin_auth = lambda: "tester"

    def tearDown(self):
        (api.require_admin_auth, api.method, api.get_json_body, api.respond) = self._orig

    def _run(self, body):
        api.method = lambda: "PATCH"
        api.get_json_body = lambda: body
        box = _capture_respond()
        try:
            api.handle_apikeys_update("k1")
        except _Stop:
            pass
        return box

    def test_updates_metadata_not_secret(self):
        future = int(time.time()) + 86400
        box = self._run({"name": "new", "role": "admin",
                         "rate_limit": 120, "expires_at": future})
        self.assertEqual(box["status"], 200)
        rec = api.load(api.APIKEYS_FILE)["k1"]
        self.assertEqual(rec["name"], "new")
        self.assertEqual(rec["role"], "admin")
        self.assertEqual(rec["rate_limit"], 120)
        self.assertEqual(rec["expires_at"], future)
        self.assertEqual(rec["key"], "SECRET-VALUE", "the key secret must never change on edit")

    def test_partial_update_only_touches_given_fields(self):
        box = self._run({"name": "renamed"})
        self.assertEqual(box["status"], 200)
        rec = api.load(api.APIKEYS_FILE)["k1"]
        self.assertEqual(rec["name"], "renamed")
        self.assertEqual(rec["role"], "viewer", "untouched fields stay put")

    def test_clear_expiry(self):
        api.save(api.APIKEYS_FILE, {"k1": {**api.load(api.APIKEYS_FILE)["k1"],
                                           "expires_at": int(time.time()) + 99999}})
        box = self._run({"expires_at": None})
        self.assertEqual(box["status"], 200)
        self.assertIsNone(api.load(api.APIKEYS_FILE)["k1"]["expires_at"])

    def test_rejects_bad_role(self):
        box = self._run({"role": "superuser"})
        self.assertEqual(box["status"], 400)

    def test_rejects_past_expiry(self):
        box = self._run({"expires_at": 1000})
        self.assertEqual(box["status"], 400)


class TestSqliteBlindExistsFixed(unittest.TestCase):
    """The host_config_current / proxmox-snapshot reads must use backend_exists,
    not Path.exists — otherwise they silently read empty under the DB backend
    (same class as the v5.0.0 backup-runaway bug)."""

    def test_host_config_current_reads_use_backend_exists(self):
        # No `<something>.exists()` guard immediately around a HOST_CONFIG_CURRENT
        # read should remain; they must be backend_exists(...).
        for var in ("_hcc_path", "current_path", "cpath", "_hcc"):
            self.assertNotIn(f"if {var}.exists():", API_SRC,
                             f"{var}.exists() is SQLite-blind — use backend_exists()")
        self.assertIn("backend_exists(_hcc_path)", API_SRC)
        self.assertIn("backend_exists(current_path)", API_SRC)
        self.assertIn("backend_exists(cpath)", API_SRC)

    def test_proxmox_snapshot_cache_uses_backend_exists(self):
        self.assertNotIn("if PROXMOX_SNAPSHOT_CACHE.exists():", API_SRC)
        self.assertIn("backend_exists(PROXMOX_SNAPSHOT_CACHE)", API_SRC)


class TestLongSessionPerf(unittest.TestCase):
    """The device grid must not rebuild its DOM on the 60s tick while hidden,
    and page-scoped pollers stop on navigation — to keep a long-lived PWA from
    degrading. Source-level guards (the behaviour is browser-side)."""

    APP_JS = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()

    def test_loaddevices_gates_render_on_visibility(self):
        self.assertIn("_devicesRenderPending", self.APP_JS)
        self.assertIn("page-devices')?.classList.contains('active')", self.APP_JS)

    def test_showpage_renders_devices_on_entry(self):
        self.assertIn("if (name === 'devices')  loadDevices();", self.APP_JS)

    def test_showpage_stops_page_pollers(self):
        self.assertIn("_stopPagePollers();", self.APP_JS)
        self.assertIn("function _stopPagePollers()", self.APP_JS)

    def test_perf_hud_present_and_off_by_default(self):
        self.assertIn("window.rpPerfHud", self.APP_JS)
        # gated on a localStorage flag → off unless explicitly enabled
        self.assertIn("localStorage.getItem('rp_perfhud')", self.APP_JS)


class TestEpssFeedUrl(unittest.TestCase):
    """EPSS moved from epss.cyentia.com to epss.empiricalsecurity.com, and the
    `-current` URL serves the scores via a same-host relative redirect — so the
    fetch must point at the new host AND follow the redirect, or EPSS scores
    never load (the no-redirect opener failed with HTTP 302/301)."""

    def test_feed_url_is_current_host(self):
        self.assertEqual(api.EPSS_FEED_URL,
                         "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
        self.assertNotIn("cyentia", api.EPSS_FEED_URL)

    def test_epss_fetch_allows_redirect(self):
        # The EPSS fetch must pass allow_redirect=True (the KEV fetch must not).
        self.assertIn("_fetch_feed_bytes(EPSS_FEED_URL, allow_redirect=True)", API_SRC)
        self.assertIn("def _fetch_feed_bytes(url, timeout=30, allow_redirect=False)", API_SRC)


if __name__ == "__main__":
    unittest.main()
