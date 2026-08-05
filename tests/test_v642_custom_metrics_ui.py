"""v6.4.2: custom metrics were collected in full and shown almost not at all.

The server keeps 720 rolling samples per metric per device, evaluates operator
thresholds against them and fires `custom_metric_alert`. The drawer rendered a
flat name/value pair out of the last heartbeat — no history, no threshold, no
alert state — and `GET /devices/{id}/custom-metrics`, which returns all three,
had NO caller anywhere in the SPA.

Run: python3 -m pytest tests/test_v642_custom_metrics_ui.py -q
"""
import os
import re
import sys
import time
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_cm", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP = (_ROOT / "server/html/static/js/app.js").read_text()


class TestTheEndpointIsReachable(unittest.TestCase):
    def test_the_drawer_offers_it(self):
        self.assertIn('data-action="loadCustomMetrics"', _APP)

    def test_the_handler_exists(self):
        self.assertRegex(_APP, r"async function loadCustomMetrics\(")

    def test_the_route_is_registered(self):
        served = {r[1] for r in api._build_exact_routes()} | {
            r[1] for r in api._dispatcher_routes()}
        self.assertIn("/api/devices/{device_id}/custom-metrics", served)


class TestRendererReadsTheRealShape(unittest.TestCase):
    """A renderer reading keys no producer writes is this codebase's documented
    dead-signal class — so the field names are taken from a real response."""

    @classmethod
    def setUpClass(cls):
        now = int(time.time())
        api.require_auth = lambda *a, **k: "op"
        api._caller_scope = lambda: None
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "token": "t", "monitored": True}})
        api.save(api.CUSTOM_METRICS_HIST_FILE, {"d1": {
            "queue_depth": {"alerted": True,
                            "samples": [{"ts": now - i * 300, "val": 40 + i} for i in range(10)][::-1]},
            "cache_hit": {"alerted": False,
                          "samples": [{"ts": now - i * 300, "val": 0.9} for i in range(5)][::-1]}}})
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["custom_metric_thresholds"] = {"queue_depth": {"op": "gt", "value": 30,
                                                           "severity": "high"}}
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api._RCTX.environ = {"REQUEST_METHOD": "GET", "QUERY_STRING": "",
                             "PATH_INFO": "/api/devices/d1/custom-metrics"}
        try:
            api.handle_device_custom_metrics("d1")
            cls.body = {}
        except (SystemExit, api.HTTPError) as e:
            cls.body = getattr(e, "body", None) or {}

    def test_the_endpoint_returns_history_threshold_and_alert_state(self):
        rows = {m["name"]: m for m in self.body.get("metrics", [])}
        self.assertIn("queue_depth", rows)
        self.assertTrue(rows["queue_depth"]["alerted"])
        self.assertEqual(rows["queue_depth"]["threshold"]["value"], 30)
        self.assertEqual(len(rows["queue_depth"]["samples"]), 10)
        self.assertIsNone(rows["cache_hit"]["threshold"])

    def test_every_key_the_renderer_reads_is_returned(self):
        fn = re.search(r"async function loadCustomMetrics\(.*?\n\}", _APP, re.S).group(0)
        returned = set(self.body["metrics"][0].keys())
        for key in ("name", "current", "alerted", "threshold", "samples"):
            with self.subTest(key):
                self.assertIn("m." + key, fn, f"renderer never reads {key}")
                self.assertIn(key, returned, f"endpoint does not return {key}")

    def test_the_threshold_is_rendered_as_words_not_an_object(self):
        """`threshold` is {op,value,severity}; printing it raw gives
        [object Object] in the cell."""
        fn = re.search(r"async function loadCustomMetrics\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("t.value", fn)
        self.assertNotRegex(fn, r"\$\{escHtml\(String\(m\.threshold\)\)\}")


class TestSparkline(unittest.TestCase):
    def test_it_is_csp_clean(self):
        """Presentation attributes only — an inline style= in a JS innerHTML
        string dies under the shipped CSP just as it does in static HTML."""
        fn = re.search(r"function _sparkline\(.*?\n\}", _APP, re.S).group(0)
        self.assertNotIn('style="', fn)
        self.assertNotIn("onclick", fn)

    def test_a_single_point_does_not_draw_a_broken_path(self):
        fn = re.search(r"function _sparkline\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("pts.length < 2", fn)

    def test_a_flat_series_does_not_divide_by_zero(self):
        fn = re.search(r"function _sparkline\(.*?\n\}", _APP, re.S).group(0)
        self.assertIn("|| 1", fn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
