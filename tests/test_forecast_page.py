"""v3.4.0 Forecast page: chartable forecast series + the fleet /api/forecast
endpoint that backs the Monitoring -> Forecast page."""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import api          # noqa: E402
import forecast     # noqa: E402
from routing_harness import routes_to  # noqa: E402

DAY = 86400


def _rising(n=12, slope=2.0, start=20.0, total=100.0, path="/"):
    now = int(time.time())
    return [{"ts": now - (n - 1 - i) * DAY, "date": "x",
             "mounts": [{"path": path, "used_gb": start + i * slope, "total_gb": total}]}
            for i in range(n)]


class TestForecastSeries(unittest.TestCase):
    def test_mount_carries_chartable_series_and_fit(self):
        out = forecast.forecast_mounts(_rising())
        self.assertTrue(out)
        row = out[0]
        # the chart needs raw points + the fitted line + a time origin
        self.assertIn("series", row)
        self.assertEqual(len(row["series"]), 12)
        self.assertTrue(all(len(p) == 2 for p in row["series"]))   # [ts, used_gb]
        self.assertIn("slope", row)
        self.assertIn("intercept", row)
        self.assertIn("t0_ts", row)
        self.assertAlmostEqual(row["slope"], 2.0, places=2)


class TestFleetForecastEndpoint(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        os.environ["RP_DATA_DIR"] = d
        for name in ("DEVICES_FILE", "METRICS_HIST_FILE"):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01"}, "d2": {"name": "db01"}})
        api.save(api.METRICS_HIST_FILE, {
            "d1": {"samples": _rising(slope=3.0, start=40.0)},   # fills sooner
            "d2": {"samples": _rising(slope=0.0, start=10.0)},   # flat -> no fill
        })

    def test_route_resolves(self):
        self.assertEqual(routes_to("GET", "/api/forecast"), "handle_forecast")

    def test_endpoint_aggregates_and_sorts(self):
        cap = {}

        def fake(status, body):
            cap["status"] = status
            cap["body"] = body
            raise api.HTTPError(status, body)
        orig = api.respond
        api.respond = fake
        api.require_auth = lambda **k: "admin"
        os.environ["REQUEST_METHOD"] = "GET"
        try:
            api.handle_forecast()
        except api.HTTPError:
            pass
        finally:
            api.respond = orig
        self.assertEqual(cap["status"], 200)
        rows = cap["body"]["mounts"]
        self.assertEqual(cap["body"]["devices"], 2)
        self.assertEqual(len(rows), 2)
        # rows carry the device name and the chartable series
        self.assertEqual(rows[0]["device_name"], "web01")   # rising one sorts first
        self.assertIn("series", rows[0])
        # flat mount sinks to the bottom with no fill
        self.assertIsNone(rows[-1]["days_to_full"])


if __name__ == "__main__":
    unittest.main()
