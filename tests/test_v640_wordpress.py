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

import base64
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
        # v6.4.2: a real rejection is a 401 carrying WordPress's own error code.
        # The original fixture returned 404 (route simply absent) and still
        # asserted "credentials rejected" — so the connector was free to blame
        # the password for ANY failure of that request, which is what it did.
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (401, {"code": "incorrect_password"}),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "wrong"}, c)
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("credentials rejected", r["detail"])

    def test_a_stripped_authorization_header_is_not_blamed_on_the_password(self):
        # Plenty of CGI/FastCGI hosts drop the Authorization header before PHP
        # sees it. WordPress then says "not logged in" — the password is fine
        # and telling the operator to check it sends them to the wrong place.
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (401, {"code": "rest_not_logged_in"}),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "right"}, c)
        self.assertEqual(r["status"], I.WARN)
        self.assertNotIn("credentials rejected", r["detail"])
        self.assertIn("Authorization header", r["detail"])

    def test_application_password_spaces_are_stripped(self):
        # WordPress prints Application passwords in space-separated groups and
        # strips the spaces on comparison; an operator pasting it verbatim was
        # told their correct password was wrong.
        seen = {}

        class _C(FakeClient):
            def request(self, method, path, headers=None, params=None, body=None):
                if path.endswith("/users/me"):
                    seen["auth"] = (headers or {}).get("Authorization", "")
                return super().request(method, path, headers, params, body)

        c = _C(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (200, {"id": 3}),
        })
        I.poll_instance({"type": "wordpress", "username": "a",
                         "secret": "abcd EFGH ijkl MNOP qrst UVWX"}, c)
        raw = base64.b64decode(seen["auth"].split(" ", 1)[1]).decode()
        self.assertEqual(raw, "a:abcdEFGHijklMNOPqrstUVWX")

    def test_the_rejected_path_still_carries_recent_logins(self):
        # _persist_integration_results and the UI both read this key; an
        # asymmetric early return is the documented way to lose a whole batch.
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "My Blog"}),
            "/wp-json/wp/v2/users/me": (401, {"code": "incorrect_password"}),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "wrong"}, c)
        self.assertEqual(r["recent_logins"], [])

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

    def test_iso8601_dates_parse(self):
        # v6.4.2: WP core's REST layer serialises dates with a 'T'. Parsing only
        # the MySQL-style space form silently zeroed EVERY timestamp — the table
        # showed '—' for all of them and logins_24h was permanently 0, which is
        # indistinguishable from a quiet site.
        want = _gmt("2026-07-23 09:15:00")
        for form in ("2026-07-23 09:15:00", "2026-07-23T09:15:00",
                     "2026-07-23T09:15:00Z", "2026-07-23T09:15:00.000"):
            self.assertEqual(I._wp_ts(form), want, form)


class TestWordpressResponseShapes(unittest.TestCase):
    """The reported symptom was "json errors". Every case here produced one, on
    a site that was actually healthy."""

    def _poll(self, body, status=200, headers=None, inst=None):
        c = FakeClient(routes={"/wp-json/": (status, body, headers or {})})
        return I.poll_instance(inst or {"type": "wordpress"}, c)

    def test_a_non_dict_json_body_does_not_raise_attributeerror(self):
        # `x = get_json(...) or {}` does NOT coerce a truthy non-dict, so a bare
        # list/string/number reached `.get` and the operator was shown
        # "AttributeError: 'list' object has no attribute 'get'".
        for body in ("[1,2,3]", '"hello"', "42", "true"):
            r = self._poll(body)
            self.assertNotIn("AttributeError", r["detail"], body)
            self.assertEqual(r["status"], I.WARN, body)

    def test_a_null_body_is_not_reported_healthy(self):
        # `null or {}` -> {} -> site='' -> detail 'site up' -> OK. A green tile
        # for something we never actually reached.
        r = self._poll("null")
        self.assertEqual(r["status"], I.WARN)

    def test_html_is_named_as_html_not_as_invalid_json(self):
        r = self._poll("<!DOCTYPE html><h1>Just a moment…</h1>",
                       headers={"Content-Type": "text/html"})
        self.assertIn("HTML", r["detail"])
        self.assertNotIn("invalid JSON", r["detail"])

    def test_a_php_notice_before_the_json_is_survivable(self):
        # A theme or plugin emitting a warning prepends it to every REST
        # response. The JSON after it is valid and the site is healthy; failing
        # here turns somebody else's cosmetic notice into "monitoring broken".
        r = self._poll('<br /><b>Warning</b>: x in /f.php on line 3\n'
                       '{"name":"Noisy Site","namespaces":["wp/v2"]}')
        self.assertEqual(r["status"], I.OK)
        self.assertIn("Noisy Site", r["detail"])

    def test_a_bom_before_the_json_is_survivable(self):
        r = self._poll('﻿{"name":"BOM Site","namespaces":["wp/v2"]}')
        self.assertEqual(r["status"], I.OK)

    def test_plain_permalinks_fall_back_to_rest_route(self):
        # With permalinks set to Plain there is no /wp-json/ path at all.
        c = FakeClient(routes={
            "/wp-json/": (404, "<html>404</html>"),
            "/": (200, {"name": "Plain Perms", "namespaces": ["wp/v2"]}),
        })
        r = I.poll_instance({"type": "wordpress"}, c)
        self.assertEqual(r["status"], I.OK)
        self.assertIn("Plain Perms", r["detail"])

    def test_the_index_is_requested_with_fields(self):
        # THE fix for the reported error: the unfiltered REST index enumerates
        # every route with its schema and runs to megabytes on a real site,
        # past the transport's read budget — so it arrived truncated and
        # unparseable. We read four keys, so we ask for four keys.
        seen = []

        class _C(FakeClient):
            def request(self, method, path, headers=None, params=None, body=None):
                seen.append(self._full(path, params))
                return super().request(method, path, headers, params, body)

        c = _C(routes={"/wp-json/": (200, {"name": "x", "namespaces": []})})
        I.poll_instance({"type": "wordpress"}, c)
        self.assertTrue(seen, "no request was made")
        self.assertIn("_fields=", seen[0])
        self.assertIn("name", seen[0])

    def test_logins_24h_counts_past_the_display_cap(self):
        # The scan used to break out once it had five rows to SHOW, so the
        # metric was structurally incapable of exceeding 5. A metric that
        # saturates at the display cap is a constant, not a measurement.
        import time as _t
        now = _t.strftime("%Y-%m-%d %H:%M:%S", _t.gmtime(_t.time() - 600))
        ev = {"data": [
            {"logger": "SimpleUserLogger", "message": "Logged in",
             "context": {"_message_key": "user_logged_in", "user_login": f"u{i}",
                         "_server_remote_addr": "203.0.113.7"},
             "date_gmt": now}
            for i in range(12)
        ]}
        c = FakeClient(routes={
            "/wp-json/": (200, {"name": "Busy"}),
            "/wp-json/wp/v2/users/me": (200, {"id": 1}),
            "/wp-json/simple-history/v1/events": (200, ev),
        })
        r = I.poll_instance(
            {"type": "wordpress", "username": "a", "secret": "b"}, c)
        self.assertEqual(len(r["recent_logins"]), 5, "display still caps at 5")
        self.assertEqual(r["metrics"]["logins_24h"], 12, "but the count does not")

    def test_ipv6_login_ips_survive_sanitisation(self):
        # _sanitize_ip's regex matched only fully-expanded IPv6, so every real
        # address was blanked — the Source IP column read '—' while the Location
        # column still named a country, which reads as data corruption.
        import sanitize
        for ip in ("2001:db8::1", "::1", "2a02:1810:1234:5678::1f",
                   "::ffff:192.0.2.1", "203.0.113.7"):
            self.assertEqual(sanitize._sanitize_ip(ip), ip, ip)
        self.assertEqual(sanitize._sanitize_ip("fe80::1%eth0"), "fe80::1",
                         "a zone id is interface-local metadata, not the address")
        for bad in ("not-an-ip", "1.2.3.4.5", "999.1.1.1", "203.0.113.7, 10.0.0.1"):
            self.assertEqual(sanitize._sanitize_ip(bad), "", bad)

    def test_a_truncated_response_says_so_instead_of_invalid_json(self):
        # The transport reads a bounded number of bytes. When it cut the body,
        # the operator was told the site's JSON was invalid — it was not; ours
        # was. Resp carries the flag now.
        r = I.Resp(200, '{"name":"Big","routes":{"a":{"b"', truncated=True)
        with self.assertRaises(I.IntegrationError) as cm:
            r.json()
        self.assertIn("too large", str(cm.exception))
        self.assertNotIn("invalid JSON", str(cm.exception))


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
