"""v6.4.0 — the frontend error beacon's ring is finally VISIBLE.

The v5.4.1 (F4) beacon collected uncaught browser errors into
CLIENT_ERRORS_FILE "for Server Status" — but no UI ever consumed the GET list,
so errors were collected and shown nowhere (the dead-feature class: complete
on one side, unconsumed on the other). v6.4.0 renders the ring on the
Server-status page and adds an admin DELETE to clear it after a fix ships.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-ce-"))
_spec = importlib.util.spec_from_file_location("api_v640_ce", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("CLIENT_ERRORS_FILE", "USERS_FILE", "ROLES_FILE",
                     "CONFIG_FILE", "AUDIT_FILE"):
            if hasattr(api, attr):
                self._files[attr] = getattr(api, attr)
                setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self.audits = []
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "require_auth", "audit_log",
                       "respond", "method", "get_json_obj", "_get_client_ip",
                       "_ip_ratelimit")}
        api.require_admin_auth = lambda: "jakob"
        api.require_auth = lambda *a, **k: "jakob"
        api.audit_log = lambda actor, action, detail=None, **k: \
            self.audits.append((actor, action, detail))
        api._get_client_ip = lambda: "203.0.113.5"
        api._ip_ratelimit = lambda *a, **k: True

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

    def _call(self, method, body=None):
        self.cap.clear()
        api.method = lambda: method
        if body is not None:
            api.get_json_obj = lambda: body
        try:
            api.handle_client_error()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get("s"), self.cap.get("b")


class TestBeaconRoundTrip(_Base):
    def test_post_then_get_then_delete(self):
        s, b = self._call("POST", {"message": "boom", "source": "app.js",
                                   "line": 42, "col": 7, "stack": "trace",
                                   "url": "https://x/#monitor"})
        self.assertEqual(s, 200)
        s, b = self._call("GET")
        self.assertEqual(s, 200)
        self.assertEqual(len(b["errors"]), 1)
        self.assertEqual(b["errors"][0]["message"], "boom")
        self.assertEqual(b["errors"][0]["line"], 42)
        s, b = self._call("DELETE")
        self.assertEqual(s, 200)
        self.assertEqual(b["cleared"], 1)
        self.assertEqual(self.audits[-1][1], "client_errors_clear")
        s, b = self._call("GET")
        self.assertEqual(b["errors"], [])

    def test_delete_route_registered(self):
        self.assertIn(("DELETE", "/api/client-error"),
                      api._build_exact_routes())

    def test_ring_stays_bounded(self):
        for i in range(api.MAX_CLIENT_ERRORS + 25):
            self._call("POST", {"message": f"e{i}"})
        store = api.load(api.CLIENT_ERRORS_FILE)
        self.assertEqual(len(store["errors"]), api.MAX_CLIENT_ERRORS)
        # ring semantics: oldest evicted, newest kept
        self.assertEqual(store["errors"][-1]["message"],
                         f"e{api.MAX_CLIENT_ERRORS + 24}")


class TestUiConsumesTheRing(unittest.TestCase):
    """The gap this release closes: the list endpoint must have a UI consumer."""

    def test_self_page_renders_and_clears(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        html = (ROOT / "server" / "html" / "index.html").read_text()
        self.assertIn('id="client-errors-card"', html)
        self.assertIn('id="client-errors-body"', html)
        self.assertIn('data-action="clearClientErrors"', html)
        self.assertIn("function _loadClientErrors", js)
        self.assertIn("async function clearClientErrors", js)
        # loadSelfStatus actually calls the loader (not just defines it)
        i = js.index("async function loadSelfStatus")
        self.assertIn("_loadClientErrors();", js[i:i + 800])
        # the GET consumer exists now — this grep going to zero again means
        # the ring went back to being collected-but-invisible
        self.assertIn("api('GET', '/client-error')", js)


if __name__ == "__main__":
    unittest.main()
