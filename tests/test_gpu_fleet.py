#!/usr/bin/env python3
"""v4.7.0 fleet GPU page — agent collection (NVIDIA + AMD), the /api/fleet/gpus
aggregation, sanitizer persistence, and the page/nav/i18n wiring."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))


def _load_api():
    spec = importlib.util.spec_from_file_location("api_gpu", _CGI / "api.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestAgentCollection(unittest.TestCase):
    SRC = (_ROOT / "client" / "remotepower-agent.py").read_text()

    def test_nvidia_queries_fan(self):
        self.assertIn("fan.speed", self.SRC)        # NVIDIA fan added
        self.assertIn("'fan_pct'", self.SRC)

    def test_amd_enriched_and_sysfs_fallback(self):
        self.assertIn("--showmeminfo", self.SRC)    # rocm-smi VRAM/power/fan
        self.assertIn("--showpower", self.SRC)
        self.assertIn("gpu_busy_percent", self.SRC)  # tooling-free amdgpu sysfs fallback
        self.assertIn("mem_info_vram_total", self.SRC)

    def test_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())


class TestFleetGpuEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    def test_route_registered(self):
        self.assertIn(('GET', '/api/fleet/gpus'), self.api._build_exact_routes())

    def test_sanitizer_persists_fan(self):
        # The heartbeat sanitizer must keep fan_pct or it never reaches the page.
        src = (_CGI / "api.py").read_text()
        self.assertIn("'power_w', 'fan_pct'", src)

    def test_aggregation_and_summary(self):
        api = self.api
        import time
        now = int(time.time())
        tmp = Path(tempfile.mkdtemp())
        api.DEVICES_FILE = tmp / "devices.json"
        api.HARDWARE_FILE = tmp / "hardware.json"
        api.CONFIG_FILE = tmp / "config.json"
        api.save(api.CONFIG_FILE, {})                       # default online TTL (300s)
        api.require_auth = lambda *a, **k: "tester"        # bypass auth for the unit test
        # `online` is COMPUTED from last_seen, NOT a stored field — fresh hosts
        # read online, a stale one reads offline (regression: it used to read the
        # nonexistent d['online'] and every host showed offline).
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "workstation", "last_seen": now, "monitored": True},
            "d2": {"name": "render01", "last_seen": now, "monitored": True},
            "d3": {"name": "muted", "last_seen": now - 10000, "monitored": False},
        })
        api.save(api.HARDWARE_FILE, {
            # name carries the vendor word — the handler must strip it so the card
            # doesn't read "NVIDIA NVIDIA GeForce …".
            "d1": {"gpus": [{"vendor": "nvidia", "name": "NVIDIA GeForce RTX 4070",
                             "util_pct": 23,
                             "mem_used_mb": 1084, "mem_total_mb": 16376, "temp_c": 35,
                             "power_w": 18, "fan_pct": 0}]},
            "d2": {"gpus": [{"vendor": "amd", "name": "RX 7900", "util_pct": 90,
                             "mem_used_mb": 8000, "mem_total_mb": 24000, "temp_c": 88}]},
            "d3": {"gpus": [{"vendor": "nvidia", "name": "GT 1030"}]},  # unmonitored host
        })
        with self.assertRaises(api.HTTPError) as ctx:
            api.handle_fleet_gpus()
        body = ctx.exception.body
        # GPU inventory is a telemetry view, not an alerting view — the unmonitored
        # host's GPU is INCLUDED (just flagged monitored:false), not hidden.
        self.assertEqual(body["summary"]["gpus"], 3)
        self.assertEqual(body["summary"]["nvidia"], 2)
        self.assertEqual(body["summary"]["amd"], 1)
        self.assertEqual(body["summary"]["hot"], 1)         # the 88°C AMD
        self.assertEqual(body["summary"]["total_power_w"], 18)
        # hottest first
        self.assertEqual(body["gpus"][0]["device"], "render01")
        self.assertEqual(body["gpus"][0]["mem_pct"], round(100 * 8000 / 24000, 1))
        # the unmonitored host is present and flagged
        muted = [r for r in body["gpus"] if r["device"] == "muted"]
        self.assertEqual(len(muted), 1)
        self.assertFalse(muted[0]["monitored"])
        # monitored hosts carry the flag too
        self.assertTrue(body["gpus"][0]["monitored"])
        # online is computed from last_seen: fresh hosts online, stale one offline
        by_dev = {r["device"]: r for r in body["gpus"]}
        self.assertTrue(by_dev["workstation"]["online"])
        self.assertTrue(by_dev["render01"]["online"])
        self.assertFalse(by_dev["muted"]["online"])
        # the redundant leading vendor word is stripped from the display name
        self.assertEqual(by_dev["workstation"]["name"], "GeForce RTX 4070")

    def test_display_name_strips_vendor(self):
        api = self.api
        f = api._gpu_display_name
        self.assertEqual(f({"name": "NVIDIA GeForce RTX 4070 Ti SUPER"}),
                         "GeForce RTX 4070 Ti SUPER")
        self.assertEqual(f({"name": "AMD Radeon RX 7900 XT"}), "Radeon RX 7900 XT")
        self.assertEqual(f({"name": "Quadro P2000"}), "Quadro P2000")  # no prefix
        self.assertEqual(f({}), "GPU")                                 # fallback

    def test_gpu_temp_feeds_thermal_alert(self):
        # A hot GPU must participate in the existing temp_high thermal alert
        # (folded into the hardware-ingest hot-sensor list, labelled "GPU: …").
        src = (_CGI / "api.py").read_text()
        self.assertIn("body.get('gpus')", src)
        self.assertIn("'GPU: '", src)


class TestGpuPageWiring(unittest.TestCase):
    HTML = (_ROOT / "server/html/index.html").read_text()
    JS = (_ROOT / "server/html/static/js/app.js").read_text()
    I18N = (_ROOT / "server/html/static/js/i18n.js").read_text()
    CSS = (_ROOT / "server/html/static/css/styles.css").read_text()

    def test_nav_and_page(self):
        self.assertIn('data-page="gpus"', self.HTML)
        self.assertIn('id="page-gpus"', self.HTML)
        self.assertIn('id="gpus-grid"', self.HTML)

    def test_loader_wired(self):
        self.assertIn("function loadGpus(", self.JS)
        self.assertIn("function _gpuCard(", self.JS)
        self.assertIn("if (name === 'gpus')", self.JS)
        self.assertIn("'/fleet/gpus'", self.JS)

    def test_csp_safe_bar_widths(self):
        # Meter widths are set via .style in JS, never inline style= attrs.
        self.assertIn("el.style.width = (el.dataset.w", self.JS)

    def test_i18n_entry(self):
        self.assertIn("'GPUs':", self.I18N)         # nav label + page title (i18n gate)

    def test_css_present(self):
        for c in (".gpu-grid", ".gpu-card", ".gpu-vendor-nvidia", ".gpu-vendor-amd", ".gpu-bar-fill"):
            self.assertIn(c, self.CSS)


if __name__ == "__main__":
    unittest.main()
