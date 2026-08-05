"""v6.4.2: per-device uptime/SLA and framework compliance reach /api/metrics.

The product computed both for its own screens and exported neither, so an
operator could see their SLA on a page but never chart or alert on it.

Every assertion here DRIVES `generate_metrics(_build_metrics_ctx())`. A metric
block that is gated on a context key its builder never supplies emits nothing
while every source assertion passes — the documented "feature that can never
fire" shape, which this exporter has hit before.

Run: python3 -m pytest tests/test_v642_metrics_posture.py -q
"""
import os
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
_spec = importlib.util.spec_from_file_location("api_v642_metrics", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import prometheus_export  # noqa: E402


class TestPostureMetrics(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        n = self.now
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "web01", "group": "prod", "token": "t",
                   "monitored": True, "last_seen": n},
            "d2": {"name": "nas1", "group": "lab", "token": "t",
                   "monitored": True, "last_seen": n},
            "d3": {"name": "new", "group": "lab", "token": "t",
                   "monitored": True, "last_seen": n},
        })
        # NB the transition key is `online`, not `up`.
        api.save(api.UPTIME_FILE, {
            "d1": {"events": [{"ts": n - 40 * 86400, "online": True}]},
            "d2": {"events": [{"ts": n - 40 * 86400, "online": True},
                              {"ts": n - 5 * 86400, "online": False},
                              {"ts": n - 4 * 86400, "online": True}]},
        })
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["sla_targets"] = {"default": 99.0}
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.txt = prometheus_export.generate_metrics(api._build_metrics_ctx())

    def _samples(self, family):
        return [l for l in self.txt.splitlines() if l.startswith(family + "{")]

    def test_uptime_family_fires(self):
        self.assertTrue(self._samples("remotepower_device_uptime_percent"),
                        "the uptime block emitted nothing on a real scrape")

    def test_the_numbers_are_right(self):
        rows = {l.split('name="')[1].split('"')[0]: float(l.rsplit(" ", 1)[1])
                for l in self._samples("remotepower_device_uptime_percent")}
        self.assertAlmostEqual(rows["web01"], 100.0, places=2)
        # one day down in a thirty-day window
        self.assertAlmostEqual(rows["nas1"], 96.667, places=2)

    def test_a_device_with_no_history_is_omitted_not_zero(self):
        """Time before enrollment is unknown, not downtime — a 0 here would
        read as a total outage on a dashboard."""
        self.assertNotIn("new", "".join(self._samples("remotepower_device_uptime_percent")))

    def test_sla_met_resolves_against_the_target(self):
        rows = {l.split('name="')[1].split('"')[0]: int(l.rsplit(" ", 1)[1])
                for l in self._samples("remotepower_device_sla_met")}
        self.assertEqual(rows["web01"], 1)     # 100% >= 99%
        self.assertEqual(rows["nas1"], 0)      # 96.7% < 99%

    def test_framework_compliance_fires(self):
        self.assertTrue(self._samples("remotepower_compliance_framework_score"))
        self.assertTrue(self._samples("remotepower_compliance_framework_controls"))

    def test_no_hostname_leaks_into_framework_rows(self):
        """`compliance.build_report` embeds offending HOSTNAMES in each
        control's evidence string, and a scrape is routinely wider-read than
        the compliance page. Scores and counts only — never control rows."""
        fw = [l for l in self.txt.splitlines() if "framework" in l]
        for host in ("web01", "nas1", "new"):
            self.assertFalse(any(host in l for l in fw),
                             f"{host} leaked into a framework metric")

    def test_a_broken_block_does_not_500_the_scrape(self):
        """A scrape must degrade, not fail, if one posture block throws."""
        real = api._compliance_facts

        def _boom(*a, **k):
            raise RuntimeError("synthetic")
        api._compliance_facts = _boom
        try:
            txt = prometheus_export.generate_metrics(api._build_metrics_ctx())
        finally:
            api._compliance_facts = real
        self.assertIn("remotepower_devices_total", txt,
                      "the whole scrape died with one block")


if __name__ == "__main__":
    unittest.main(verbosity=2)
