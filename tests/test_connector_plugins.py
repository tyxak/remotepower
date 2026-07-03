"""v5.8.0 (B5.1): connectors.d plugin loader — third-party connector files
self-register via @_register when imported from the plugins directory."""
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402


class TestPluginLoader(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        # snapshot so we can assert what the plugin added and clean up
        self._before = set(I.CONNECTORS)

    def tearDown(self):
        for t in set(I.CONNECTORS) - self._before:
            I.CONNECTORS.pop(t, None)
            I._STATS.pop(t, None)
            I.PLUGIN_CONNECTORS.discard(t)

    def _write(self, name, body):
        (Path(self.dir) / name).write_text(textwrap.dedent(body))

    def test_loads_and_registers(self):
        self._write("mything.py", '''
            from integrations import _register, _field, PASSWORD, OK, _STATS
            @_register("plugintest_mything", "My Thing", "apps",
                       [_field("secret", "Token", PASSWORD)],
                       notes="test plugin")
            def _mything(inst, c):
                return {"status": OK, "detail": "ok", "metrics": {"q": 1}}
            _STATS["plugintest_mything"] = [("q", "Queue", "int")]
        ''')
        loaded = I.load_plugins(self.dir)
        self.assertIn("mything.py", loaded)
        self.assertIn("plugintest_mything", I.CONNECTORS)
        self.assertIn("plugintest_mything", I.PLUGIN_CONNECTORS)
        self.assertIn("plugintest_mything", I._STATS)

    def test_registered_plugin_polls(self):
        self._write("p2.py", '''
            from integrations import _register, OK, _STATS
            @_register("plugintest_p2", "P2", "apps", [], notes="x")
            def _p2(inst, c):
                d = c.get_json("/h")
                return {"status": OK, "detail": "up", "metrics": {"n": d.get("n", 0)}}
            _STATS["plugintest_p2"] = [("n", "N", "int")]
        ''')
        I.load_plugins(self.dir)

        import json

        class FakeClient(I.HTTPClient):
            def __init__(self):
                super().__init__("http://x")
            def request(self, method, path, headers=None, params=None, body=None):
                return I.Resp(200, json.dumps({"n": 7}))

        res = I.poll_instance({"type": "plugintest_p2"}, FakeClient())
        self.assertEqual(res["status"], I.OK)
        self.assertEqual(res["metrics"]["n"], 7)

    def test_bad_plugin_skipped_not_fatal(self):
        self._write("good.py", '''
            from integrations import _register, OK, _STATS
            @_register("plugintest_good", "Good", "apps", [], notes="x")
            def _g(inst, c): return {"status": OK}
            _STATS["plugintest_good"] = [("a", "A", "int")]
        ''')
        self._write("bad.py", "raise RuntimeError('boom on import')\n")
        loaded = I.load_plugins(self.dir)   # must not raise
        self.assertIn("good.py", loaded)
        self.assertNotIn("bad.py", loaded)
        self.assertIn("plugintest_good", I.CONNECTORS)

    def test_missing_dir_is_empty(self):
        self.assertEqual(I.load_plugins("/no/such/dir/xyz"), [])

    def test_readme_ignored(self):
        (Path(self.dir) / "README.md").write_text("not python")
        self.assertEqual(I.load_plugins(self.dir), [])


class TestWiring(unittest.TestCase):
    def test_api_calls_load_plugins(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("integrations_mod.load_plugins()", src)

    def test_dir_and_docs_exist(self):
        self.assertTrue((_CGI / "connectors.d" / "README.md").exists())
        self.assertTrue((_ROOT / "docs" / "writing-a-connector.md").exists())


if __name__ == "__main__":
    unittest.main()
