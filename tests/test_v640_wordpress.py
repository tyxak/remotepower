"""v6.4.0 — WordPress integration connector + recent-logins widget.

The `wordpress` connector monitors a WordPress site's REST reachability and,
with an Application password, reports the last 5 successful logins (user, IP,
timestamp) via the Simple History plugin's REST API. api.py geo-enriches the
IPs at poll time (offline MMDB, empty when unconfigured) and exposes the list
to the UI through the `last_recent_logins` read whitelist in
handle_integrations_list.

Connector tests use the canned FakeClient (no network); the api wiring tests
drive the real handlers with only identity stubbed.
"""

import calendar
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-wp-"))

import integrations as I  # noqa: E402

from test_connectors_wave_g import FakeClient  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v640_wp", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _gmt(s):
    return int(calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S")))


def _events():
    return {"data": [
        {"logger": "SimpleUserLogger", "message": "Logged in",
         "context": {"_message_key": "user_logged_in"},
         "date_gmt": "2026-07-23 09:15:00",
         "initiator_data": {"user_login": "admin"},
         "ip_addresses": {"_server_remote_addr": "203.0.113.7"}},
        {"logger": "SimpleUserLogger", "message": "Logged in",
         "context": {"_message_key": "user_logged_in",
                     "_server_remote_addr": "198.51.100.9",
                     "user_login": "editor"},
         "date_gmt": "2026-07-22 08:00:00"},
        # non-login events must be filtered out
        {"logger": "SimpleUserLogger", "message": "Failed to log in",
         "context": {"_message_key": "user_login_failed"},
         "date_gmt": "2026-07-22 07:00:00"},
        {"logger": "SimplePluginLogger", "message": "Plugin updated",
         "context": {"_message_key": "plugin_updated"},
         "date_gmt": "2026-07-21 07:00:00"},
    ]}


class TestWordpressConnector(unittest.TestCase):
    def test_registered_with_stats_chip(self):
        self.assertIn("wordpress", I.CONNECTORS)
        self.assertTrue(I._STATS.get("wordpress"))

    def test_happy_path_with_simple_history(self):
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (200, {"id": 1}),
            "/wp-json/simple-history/v1/events": (200, _events()),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "admin", "secret": "app pass"}, c)
        self.assertEqual(r["status"], I.OK)
        self.assertIn("2 recent login(s)", r["detail"])
        self.assertEqual(r["recent_logins"], [
            {"user": "admin", "ip": "203.0.113.7",
             "ts": _gmt("2026-07-23 09:15:00")},
            {"user": "editor", "ip": "198.51.100.9",
             "ts": _gmt("2026-07-22 08:00:00")},
        ])
        # Application password rides as Basic auth on the authed calls.
        self.assertTrue(any(
            h.get("Authorization", "").startswith("Basic ")
            for _m, p, h in c.calls if p == "/wp-json/wp/v2/users/me"))

    def test_no_simple_history_still_monitors_the_site(self):
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (200, {"id": 1}),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "b"}, c)
        self.assertEqual(r["status"], I.OK)
        self.assertIn("Simple History", r["detail"])
        self.assertEqual(r["recent_logins"], [])

    def test_rejected_credentials_are_warning_not_critical(self):
        c = FakeClient(routes={"/wp-json/": (200, {"name": "My Blog"})})
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "wrong"}, c)
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("credentials rejected", r["detail"])

    def test_credential_less_reachability_check(self):
        c = FakeClient(routes={"/wp-json/": (200, {"name": "My Blog"})})
        r = I.poll_instance({"type": "wordpress"}, c)
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(r["recent_logins"], [])

    def test_unreachable_is_critical(self):
        r = I.poll_instance({"type": "wordpress"}, FakeClient(routes={}))
        self.assertEqual(r["status"], I.CRIT)

    def test_login_list_caps_at_five(self):
        ev = {"data": [dict(_events()["data"][0]) for _ in range(9)]}
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "b"}),
            "/wp-json/wp/v2/users/me": (200, {"id": 1}),
            "/wp-json/simple-history/v1/events": (200, ev),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "b"}, c)
        self.assertEqual(len(r["recent_logins"]), 5)

    def test_unparseable_date_becomes_zero(self):
        self.assertEqual(I._wp_ts("not a date"), 0)
        self.assertEqual(I._wp_ts(None), 0)


class TestApiWiring(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("CONFIG_FILE", "INTEG_STATE_FILE", "USERS_FILE",
                     "ROLES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self._orig = {n: getattr(api, n) for n in
                      ("require_auth", "verify_token", "get_token_from_request",
                       "geo_enrich", "respond")}
        api.require_auth = lambda *a, **k: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.get_token_from_request = lambda *a, **k: "tok"
        self.cap = {}

        def _resp(s, b=None):
            self.cap["s"] = s
            self.cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        api._LOAD_CACHE.clear()

    def test_poll_geo_enriches_recent_logins(self):
        orig_poll = api.integrations_mod.poll_instance
        api.integrations_mod.poll_instance = lambda inst, c: {
            "status": "ok", "detail": "", "metrics": {},
            "recent_logins": [{"user": "admin", "ip": "203.0.113.7", "ts": 5},
                              {"user": "x", "ip": "", "ts": 6}]}
        api.geo_enrich = lambda ip: (
            {"country": "Denmark", "country_code": "DK"}
            if ip == "203.0.113.7" else {})
        try:
            r = api._poll_one_integration(
                {"id": "wp1", "type": "wordpress", "label": "Blog",
                 "url": "https://blog.example.com"})
        finally:
            api.integrations_mod.poll_instance = orig_poll
        self.assertEqual(r["recent_logins"][0]["country"], "Denmark")
        self.assertEqual(r["recent_logins"][0]["country_code"], "DK")
        self.assertNotIn("country", r["recent_logins"][1])

    def test_list_whitelists_and_sanitizes_recent_logins(self):
        api.save(api.CONFIG_FILE, {"integrations": [
            {"id": "wp1", "type": "wordpress", "label": "Blog",
             "url": "https://blog.example.com", "enabled": True}]})
        api.save(api.INTEG_STATE_FILE, {"latest": {"wp1": {
            "status": "ok", "detail": "d", "checked": 1, "metrics": {},
            "recent_logins": (
                [{"user": "admin" + "x" * 200,
                  "ip": "203.0.113.7; rm -rf /", "ts": "9",
                  "country": "Denmark", "country_code": "DK",
                  "evil": "dropped"}] +
                [{"user": f"u{i}", "ip": "1.2.3.4", "ts": i}
                 for i in range(9)]),
        }}})
        api._LOAD_CACHE.clear()
        try:
            api.handle_integrations_list()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap["s"], 200)
        inst = self.cap["b"]["integrations"][0]
        logins = inst["last_recent_logins"]
        self.assertEqual(len(logins), 5, "widget shows the last 5 logins only")
        first = logins[0]
        self.assertNotIn("evil", first, "read whitelist must drop unknown keys")
        self.assertLessEqual(len(first["user"]), 64, "user field must be capped")
        self.assertEqual(first["ip"], "",
                         "a non-IP-shaped ip must be rejected, not echoed")
        self.assertEqual(logins[1]["ip"], "1.2.3.4")
        self.assertEqual(first["ts"], 9)
        self.assertEqual(first["country_code"], "DK")
        # the catalog now offers the connector to the Settings UI
        self.assertIn("wordpress",
                      [c["type"] for c in self.cap["b"]["catalog"]])


class TestFrontendWiring(unittest.TestCase):
    def test_panel_shipped_and_wired(self):
        html = (ROOT / "server" / "html" / "index.html").read_text()
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        self.assertIn('id="wp-login-panels"', html)
        self.assertIn("function _renderWpLoginPanels", js)
        self.assertIn("_renderWpLoginPanels(items)", js)
        self.assertIn("last_recent_logins", js)
        # untrusted remote strings must go through textContent, not innerHTML
        i = js.index("function _renderWpLoginPanels")
        block = js[i:js.index("\nfunction ", i + 10)]
        self.assertNotIn(".innerHTML = `", block)


if __name__ == "__main__":
    unittest.main()
