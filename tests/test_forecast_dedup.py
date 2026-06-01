"""
Forecast: collapse same-filesystem mounts and cap the projection horizon.

  * btrfs subvolumes / bind mounts report identical used_gb/total_gb at every
    sample, so they must collapse into one row per filesystem (not one per
    mountpoint), preferring '/' as the representative and listing the rest in
    `shared_mounts`.
  * a mount that only fills >2 years out is not an actionable "risk": the row is
    kept (current usage is useful) but days_to_full is dropped and
    beyond_horizon is set.

Pure stdlib unittest (runs under `python -m unittest discover` and pytest).
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import forecast  # noqa: E402

DAY = 86400


def _samples(mountsets, n=12):
    """mountsets: list of (path, start_gb, slope_gb_per_day, total_gb)."""
    now = int(time.time())
    out = []
    for i in range(n):
        mounts = [{"path": p, "used_gb": start + i * slope, "total_gb": total}
                  for (p, start, slope, total) in mountsets]
        out.append({"ts": now - (n - 1 - i) * DAY, "mounts": mounts})
    return out


class TestForecastDedup(unittest.TestCase):
    def test_same_filesystem_mounts_collapse_to_one_row(self):
        # / and /home are the same btrfs pool (identical series); /data is its
        # own disk.
        rows = forecast.forecast_mounts(_samples([
            ("/", 20.0, 2.0, 100.0),
            ("/home", 20.0, 2.0, 100.0),
            ("/data", 50.0, 1.0, 200.0),
        ]))
        paths = {r["path"] for r in rows}
        self.assertEqual(paths, {"/", "/data"})       # /home folded into /
        root = next(r for r in rows if r["path"] == "/")
        self.assertEqual(root["shared_mounts"], ["/", "/home"])

    def test_prefers_root_as_representative(self):
        rows = forecast.forecast_mounts(_samples([
            ("/var/log", 30.0, 1.0, 100.0),
            ("/", 30.0, 1.0, 100.0),
            ("/srv", 30.0, 1.0, 100.0),
        ]))
        self.assertEqual([r["path"] for r in rows], ["/"])
        self.assertEqual(rows[0]["shared_mounts"], ["/", "/srv", "/var/log"])

    def test_distinct_filesystems_not_collapsed(self):
        rows = forecast.forecast_mounts(_samples([
            ("/", 20.0, 1.0, 100.0),
            ("/data", 20.0, 1.0, 200.0),   # same used, different total → different FS
        ]))
        self.assertEqual({r["path"] for r in rows}, {"/", "/data"})


class TestForecastHorizon(unittest.TestCase):
    def test_far_future_fill_is_not_a_dated_risk(self):
        # ~0.255 GB/day on a half-full 1 TB disk → ~5.5 years to fill.
        rows = forecast.forecast_mounts(_samples([("/slow", 486.0, 0.255, 1000.0)]))
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["days_to_full"])
        self.assertIsNone(rows[0]["fill_date_ts"])
        self.assertTrue(rows[0]["beyond_horizon"])
        # row is kept — current usage is still informative
        self.assertGreater(rows[0]["current_percent"], 0)

    def test_near_term_fill_keeps_its_date(self):
        rows = forecast.forecast_mounts(_samples([("/fast", 20.0, 2.0, 100.0)]))
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0]["days_to_full"])
        self.assertFalse(rows[0]["beyond_horizon"])
        self.assertIsNotNone(rows[0]["fill_date_ts"])


if __name__ == "__main__":
    unittest.main()
