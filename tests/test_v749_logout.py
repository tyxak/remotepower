#!/usr/bin/env python3
"""Sign out ends the session on the server (7.4.9).

`doLogout()` threw away the browser's copy of the token and nothing else. `POST /api/logout` was documented and allow-listed in the
setup and portal gates and answered 404 (the authorization matrix and the web client audit both found it), so a session token kept
working for 24 hours, or 30 days with "remember me", for anyone who had a copy. There is a route now, the page calls it, and the
page also drops what it kept of the fleet for the next person on the browser.

Driven through the real handler and the real `verify_token`: the session is built the way login builds it, and only the response
function is replaced.
"""
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-logout-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v749_logout", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class TestTheRoute(unittest.TestCase):

    def setUp(self):
        self._saved_respond = api.respond
        self._env = dict(os.environ)
        now = int(time.time())
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x"}, "bob": {"role": "viewer", "password_hash": "x"}})
        api.save(api.TOKENS_FILE, {api._token_hash(t): {"user": u, "created": now, "ttl": 86400, "last_seen": now}
                                   for t, u in (("tok-alice-1", "alice"), ("tok-alice-2", "alice"), ("tok-bob", "bob"))})
        api._LOAD_CACHE.clear()

        def fake(status, data, *a, **k):
            raise _Captured(status, data)
        setattr(api, "respond", fake)

    def tearDown(self):
        setattr(api, "respond", self._saved_respond)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def post(self, token, verb="POST"):
        os.environ.update({"REQUEST_METHOD": verb, "PATH_INFO": "/api/logout", "QUERY_STRING": "", "CONTENT_LENGTH": "0"})
        os.environ.pop("HTTP_X_TOKEN", None)
        if token:
            os.environ["HTTP_X_TOKEN"] = token
        api.sys.stdin = type("S", (), {"buffer": io.BytesIO(b"")})()
        api._LOAD_CACHE.clear()
        try:
            api.handle_logout()
        except _Captured as c:
            return c.status, c.body
        self.fail("no response")

    def alive(self, token):
        api._LOAD_CACHE.clear()
        return bool(api.verify_token(token)[0])

    def test_the_session_stops_working(self):
        self.assertTrue(self.alive("tok-alice-1"))
        self.assertEqual(self.post("tok-alice-1"), (200, {"ok": True}))
        self.assertFalse(self.alive("tok-alice-1"), "the token no longer authenticates")

    def test_only_that_session_ends(self):
        self.post("tok-alice-1")
        self.assertTrue(self.alive("tok-alice-2"), "the same user's other session stays")
        self.assertTrue(self.alive("tok-bob"), "another user's session stays")

    def test_a_second_sign_out_with_the_same_token_is_a_401(self):
        self.post("tok-alice-1")
        self.assertEqual(self.post("tok-alice-1")[0], 401)

    def test_no_token_and_an_unknown_token_are_401_and_change_nothing(self):
        for token in (None, "", "not-a-session"):
            with self.subTest(token=token):
                self.assertEqual(self.post(token)[0], 401)
        self.assertTrue(self.alive("tok-alice-1") and self.alive("tok-bob"))

    def test_only_post_is_a_route(self):
        self.assertEqual(self.post("tok-alice-1", verb="GET")[0], 405)
        self.assertTrue(self.alive("tok-alice-1"))

    def test_the_route_is_registered(self):
        self.assertIn(("POST", "/api/logout"), api._build_exact_routes())

    def test_it_is_audited_with_the_name_of_who_signed_out(self):
        seen = []
        real = api.audit_log
        setattr(api, "audit_log", lambda actor, action, *a, **k: seen.append((actor, action)))
        try:
            self.post("tok-alice-1")
        finally:
            setattr(api, "audit_log", real)
        self.assertEqual(seen, [("alice", "logout")])


class TestThePageCallsIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        cls.body = srcpin.js_function(js, "doLogout")

    def test_sign_out_calls_the_route_with_the_token_it_read_first(self):
        self.assertIn("fetch('/api/logout'", self.body)
        self.assertLess(self.body.index("const _tok = getToken();"), self.body.index("sessionStorage.removeItem('rp_token')"),
                        "the token is read before the stores are cleared")
        self.assertIn("keepalive: true", self.body)

    def test_the_request_waits_for_the_preference_save(self):
        self.assertLess(self.body.index("flushUiPrefs()"), self.body.index("fetch('/api/logout'"))
        self.assertIn(".finally(", self.body)

    def test_what_the_browser_kept_of_the_fleet_is_dropped(self):
        for key in ("rp_stat_hist", "rp_recent_devices", "rp_favorites", "rp_fleet_queries", "rp_draft_", "rp.ai.conv",
                    "rp_iac_last_device", "rp_iac_instructions", "rp_metric_explorer_v1", "rp_activity_cleared"):
            with self.subTest(key=key):
                self.assertIn(key, self.body)


if __name__ == "__main__":
    unittest.main()
