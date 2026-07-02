#!/usr/bin/env python3
"""v5.6.x: the Server-status "Serving & runtime" panel.

/api/self/status must report HOW the server is actually being served — storage
backend (json/sqlite/postgres), request tier (cgi/scgi/wsgi), and whether the
out-of-band scheduler is configured AND alive — so an operator can verify at a
glance (the exact "am I really on WSGI / the scheduler?" question).
"""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v560serve", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP_JS = (_ROOT / "server/html/static/js/app.js").read_text()
_SCALING = (_ROOT / "docs/scaling.md").read_text()


class TestRuntimeHelper(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._sf = api.SCHEDULER_STATE_FILE
        self._tier = api._SERVER_TIER
        api.SCHEDULER_STATE_FILE = self.d / "scheduler_state.json"
        os.environ.pop("RP_EXTERNAL_SCHEDULER", None)

    def tearDown(self):
        api.SCHEDULER_STATE_FILE = self._sf
        api._SERVER_TIER = self._tier
        os.environ.pop("RP_EXTERNAL_SCHEDULER", None)

    def test_default_shape(self):
        info = api._runtime_serving_info()
        for k in ("storage_backend", "server_tier", "scheduler_configured",
                  "scheduler_running", "cadence_in_request"):
            self.assertIn(k, info)
        # default install: no scheduler → cadence runs in-request
        self.assertFalse(info["scheduler_configured"])
        self.assertFalse(info["scheduler_running"])
        self.assertTrue(info["cadence_in_request"])

    def test_server_tier_default_cgi(self):
        self.assertEqual(api._SERVER_TIER, "cgi")   # fresh module default

    def test_scheduler_running_with_fresh_heartbeat(self):
        os.environ["RP_EXTERNAL_SCHEDULER"] = "1"
        api.save(api.SCHEDULER_STATE_FILE,
                 {"ts": int(time.time()), "pid": 1, "interval": 60})
        info = api._runtime_serving_info()
        self.assertTrue(info["scheduler_configured"])
        self.assertTrue(info["scheduler_running"])
        # scheduler owns the cadence → request path skips it
        self.assertFalse(info["cadence_in_request"])
        self.assertLess(info["scheduler_last_beat_s"], 5)

    def test_scheduler_configured_but_dead(self):
        os.environ["RP_EXTERNAL_SCHEDULER"] = "1"
        api.save(api.SCHEDULER_STATE_FILE,
                 {"ts": int(time.time()) - 9999, "pid": 1, "interval": 60})
        info = api._runtime_serving_info()
        self.assertTrue(info["scheduler_configured"])   # flag set…
        self.assertFalse(info["scheduler_running"])     # …but no live heartbeat

    def test_self_status_includes_runtime(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("out['runtime'] = _runtime_serving_info()", src)


class TestWiring(unittest.TestCase):
    def _sets_tier(self, path, tier):
        # quote-agnostic: api_worker.py is black-checked (double quotes), wsgi.py
        # is not — accept either.
        t = (_CGI / path).read_text()
        return f"_SERVER_TIER = '{tier}'" in t or f'_SERVER_TIER = "{tier}"' in t

    def test_entry_points_set_tier(self):
        self.assertTrue(self._sets_tier("wsgi.py", "wsgi"))
        self.assertTrue(self._sets_tier("api_worker.py", "scgi"))

    def test_scheduler_writes_heartbeat(self):
        self.assertIn("SCHEDULER_STATE_FILE", (_CGI / "scheduler.py").read_text())

    def test_frontend_renders_panel_and_links_scaling(self):
        self.assertIn("s.runtime", _APP_JS)
        self.assertIn("Serving &amp; runtime", _APP_JS)
        self.assertIn("docs/scaling.md", _APP_JS)

    def test_scaling_doc_documents_panel(self):
        self.assertIn("Serving & runtime", _SCALING)
        self.assertIn("api.env", _SCALING)


if __name__ == "__main__":
    unittest.main()
