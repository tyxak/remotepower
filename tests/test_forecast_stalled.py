"""
Forecast: "has the growth actually stopped?" guard (v3.8.0).

A one-off spike inside the trend window (a big restore, a log burst) leaves the
full-window least-squares slope pointing up long after growth is over, so the
page kept projecting an alarming fill date that never arrives. forecast_mounts
now re-fits over the recent window; if growth has flattened/reversed while the
long-run trend is still up, the mount is flagged `stalled` and no date is
projected. A genuinely-growing mount is unaffected.

Pure stdlib unittest.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import forecast  # noqa: E402

DAY = 86400
NOW = 1_780_000_000


def _series(fn, lo=-28, hi=0, total=40.0):
    """Build samples for a single '/' mount; fn(day)->used_gb."""
    return [{"ts": NOW + d * DAY,
             "mounts": [{"path": "/", "used_gb": round(fn(d), 3), "total_gb": total}]}
            for d in range(lo, hi + 1)]


class TestForecastStalled(unittest.TestCase):
    def test_growth_that_stopped_is_flagged_and_not_projected(self):
        # rose 1 GB/day until 8 days ago, flat since
        def fn(d):
            return 30.0 if d >= -8 else 30.0 + (d + 8) * 1.0
        row = forecast.forecast_mounts(_series(fn))[0]
        self.assertTrue(row["stalled"])
        self.assertIsNone(row["days_to_full"])
        self.assertIsNone(row["fill_date_ts"])
        self.assertEqual(row["recent_gb_per_day"], 0.0)
        # the long-run trend is still reported (transparency)
        self.assertGreater(row["trend_gb_per_day"], 0.1)

    def test_steady_growth_still_projects_a_date(self):
        row = forecast.forecast_mounts(_series(lambda d: 30.0 + d * 1.0, lo=-9))[0]
        self.assertFalse(row["stalled"])
        self.assertIsNotNone(row["days_to_full"])
        self.assertAlmostEqual(row["recent_gb_per_day"], 1.0, places=1)

    def test_decelerating_growth_uses_the_gentler_recent_rate(self):
        # fast early (2 GB/day), slow recently (0.25 GB/day) — projection should
        # use the slower recent rate, giving a longer (less alarmist) horizon.
        def fn(d):
            return (28.0 + 0.25 * (d + 8)) if d >= -8 else (28.0 + 2.0 * (d + 8))
        row = forecast.forecast_mounts(_series(fn))[0]
        self.assertFalse(row["stalled"])
        self.assertIsNotNone(row["days_to_full"])
        # recent rate ~0.25 → horizon should be far longer than the full-window
        # rate would give.
        full_rate_days = (row["total_gb"] - row["current_gb"]) / row["trend_gb_per_day"]
        self.assertGreater(row["days_to_full"], full_rate_days)


if __name__ == "__main__":
    unittest.main(verbosity=2)
