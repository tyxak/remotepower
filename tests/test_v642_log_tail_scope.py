"""v6.4.2 (audit): handle_log_tail leaked cross-scope/cross-tenant log content.

handle_log_search scope-filters (v6.2.2 SECURITY); its sibling handle_log_tail
did the identical fleet-wide log read with a bare load(DEVICES_FILE), so a
scoped viewer or tenant admin could tail every device's log lines. Driven
through the real handler, not a source grep.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-logtail-"))

_spec = importlib.util.spec_from_file_location("api_logtail", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestLogTailRespectsScope(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {}
        for a in ("DEVICES_FILE", "LOG_WATCH_FILE"):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / pathlib.Path(getattr(api, a)).name)
        api.save(api.DEVICES_FILE, {
            "mine": {"name": "mine", "group": "team-a"},
            "theirs": {"name": "theirs", "group": "team-b"}})
        api.save(api.LOG_WATCH_FILE, {
            "mine":   {"units": {"sshd": [{"ts": 10, "line": "MINE-secret"}]}},
            "theirs": {"units": {"sshd": [{"ts": 10, "line": "THEIRS-secret"}]}}})
        for f in (api.DEVICES_FILE, api.LOG_WATCH_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "require_auth", "_env", "_scope_filter_devices")}
        api.require_auth = lambda **k: "viewer1"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def _tail(self, qs=""):
        api._env = lambda k, dv="": (qs if k == "QUERY_STRING" else dv)
        try:
            api.handle_log_tail()
        except api.HTTPError:
            pass
        return self.cap.get("b") or {}

    def test_a_scoped_caller_only_sees_its_own_devices_lines(self):
        # scope resolves to only 'mine'
        api._scope_filter_devices = lambda devs: {"mine": devs["mine"]}
        body = self._tail("")
        lines = str(body)
        self.assertIn("MINE-secret", lines)
        self.assertNotIn("THEIRS-secret", lines)

    def test_an_out_of_scope_device_query_returns_nothing(self):
        api._scope_filter_devices = lambda devs: {"mine": devs["mine"]}
        body = self._tail("device=theirs")
        self.assertNotIn("THEIRS-secret", str(body))

    def test_a_full_scope_admin_still_sees_all(self):
        api._scope_filter_devices = lambda devs: devs   # single-org admin: no-op
        body = self._tail("")
        s = str(body)
        self.assertIn("MINE-secret", s)
        self.assertIn("THEIRS-secret", s)

    def test_the_handler_uses_the_scope_filter(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        self.assertIn("_scope_filter_devices(load(DEVICES_FILE))",
                      py_function(src, "handle_log_tail"))


if __name__ == "__main__":
    unittest.main()
