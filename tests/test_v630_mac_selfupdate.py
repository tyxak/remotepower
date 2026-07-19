"""v6.3.0: macOS agent self-update — the last agent that couldn't heal itself.

Server side: /api/agent/mac/{version,signature,download} reuse the three
Windows handlers, parametrized by request path (keeps the inline-handler
ratchet count unchanged). Agent side: a real _self_update() replaces the
honest-but-useless rc:1 stub (which itself replaced the v6.2.0 rc:0 lie).
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

MAC_AGENT = (_ROOT / "client/remotepower-agent-mac.py").read_text()


def _fresh_api():
    d = tempfile.mkdtemp(prefix="rp-v630-mac-")
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_v630_mac", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMacUpdateEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def setUp(self):
        self.captured = {}

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise self.api.HTTPError(status, data)

        self.api.respond = _respond
        self.api.require_auth = lambda *a, **k: "agent"
        os.environ.pop("PATH_INFO", None)

    def tearDown(self):
        os.environ.pop("PATH_INFO", None)

    def _call(self, fn):
        self.captured = {}
        try:
            fn()
        except self.api.HTTPError:
            pass
        return self.captured

    def test_mac_path_serves_the_mac_file(self):
        tmp = Path(tempfile.mkdtemp())
        mac = tmp / "remotepower-agent-mac.py"
        mac.write_text("VERSION = '6.3.0'\n# mac agent\n")
        win = tmp / "remotepower-agent-win.py"
        win.write_text("VERSION = '6.3.0'\n# win agent — different bytes\n")
        om, ow = self.api._AGENT_MAC_PATH, self.api._AGENT_WIN_PATH
        self.api._AGENT_MAC_PATH, self.api._AGENT_WIN_PATH = mac, win
        try:
            os.environ["PATH_INFO"] = "/api/agent/mac/version"
            r_mac = self._call(self.api.handle_win_agent_version)
            os.environ["PATH_INFO"] = "/api/agent/win/version"
            r_win = self._call(self.api.handle_win_agent_version)
            self.assertEqual(r_mac["status"], 200)
            self.assertEqual(r_win["status"], 200)
            self.assertTrue(r_mac["data"]["sha256"])
            # the two OS agents are distinct files with distinct hashes
            self.assertNotEqual(r_mac["data"]["sha256"], r_win["data"]["sha256"])
        finally:
            self.api._AGENT_MAC_PATH, self.api._AGENT_WIN_PATH = om, ow

    def test_default_path_is_windows_back_compat(self):
        # No PATH_INFO (or a win path) → the pre-v6.3.0 behavior exactly.
        p, sig, fn, label = self.api._os_agent_dist()
        self.assertEqual(fn, "remotepower-agent-win.py")
        self.assertEqual(label, "windows")

    def test_mac_routes_registered(self):
        routes = self.api._build_exact_routes()
        for ep in ("version", "signature", "download"):
            self.assertIn(("GET", f"/api/agent/mac/{ep}"), routes, ep)

    def test_mac_endpoints_ip_allowlist_exempt(self):
        for p in ("/api/agent/mac/version", "/api/agent/mac/download"):
            self.assertIn(p, self.api._IP_ALLOWLIST_EXEMPT_PATHS, p)

    def test_mac_signature_404s_when_unsigned(self):
        os.environ["PATH_INFO"] = "/api/agent/mac/signature"
        r = self._call(self.api.handle_win_agent_signature)
        self.assertEqual(r["status"], 404)
        self.assertIn("macOS", r["data"]["error"])


class TestMacAgentSelfUpdate(unittest.TestCase):
    """Source pins on the mac agent's updater (not unit-drivable headlessly)."""

    def test_stub_is_gone_real_updater_exists(self):
        self.assertNotIn("not yet implemented on the macOS agent", MAC_AGENT)
        self.assertIn("def _self_update", MAC_AGENT)
        self.assertIn("return _self_update()", MAC_AGENT)

    def test_verifies_sha_with_constant_time_compare(self):
        i = MAC_AGENT.index("def _self_update")
        body = MAC_AGENT[i:i + 4000]
        self.assertIn("compare_digest", body)
        self.assertIn("/api/agent/mac/version", body)
        self.assertIn("/api/agent/mac/download", body)
        # atomic install
        self.assertIn("os.replace", body)

    def test_update_refused_in_audit_mode(self):
        i = MAC_AGENT.index("def _self_update")
        self.assertIn("_audit_mode()", MAC_AGENT[i:i + 1200])

    def test_http_helpers_refuse_plain_http(self):
        for fn in ("def _http_get_json", "def _http_get_bytes"):
            i = MAC_AGENT.index(fn)
            self.assertIn("https://", MAC_AGENT[i:i + 400], fn)

    def test_restart_only_after_report(self):
        # the re-exec happens in the run loop AFTER the update result was sent,
        # so the server always receives the outcome before the process swaps.
        self.assertIn("_RESTART_AFTER_REPORT", MAC_AGENT)
        i = MAC_AGENT.index("sent and sent.get('cmd') == 'update'")
        self.assertIn("os.execv", MAC_AGENT[i:i + 300])


if __name__ == "__main__":
    unittest.main()
