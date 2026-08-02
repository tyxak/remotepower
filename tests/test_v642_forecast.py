"""Forecast: memory / swap / CPU-load headroom projection (v6.4.2).

The daily metric samples have carried mem_percent, swap_percent and
loadavg_1m + cpu_count since v3.9.0, but only disk was ever projected.
`forecast.forecast_resources` fits those series with the same least-squares
fit + R² gate as forecast_mounts, so a noisy series can't produce a
confident-looking wrong saturation date.

Pure stdlib unittest (the Hypothesis class skips cleanly without it).
Run: python3 -m pytest tests/test_v642_forecast.py -q
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

# Optional deep pass — hypothesis is NOT in the CI dep list, so a module-level
# hard import would be an instant ImportError under `unittest discover` on CI.
try:
    from hypothesis import given, settings, strategies as st
    _HAS_HYPOTHESIS = True
except ImportError:                     # pragma: no cover
    _HAS_HYPOTHESIS = False
    import functools

    def given(*a, **k):                 # no-op decorators so the class body parses
        def _wrap(fn):
            @functools.wraps(fn)
            def _skip(self, *aa, **kk):
                self.skipTest('hypothesis not installed (pip install hypothesis)')
            return _skip
        return _wrap

    def settings(*a, **k):
        return lambda fn: fn

    class _Dummy:
        def __call__(self, *a, **k):
            return self

        def __or__(self, other):
            return self

        def __getattr__(self, _n):
            return self

    st = _Dummy()

DAY = 86400
NOW = 1_780_000_000


def mem_series(fn, lo=-29, hi=0, **extra):
    """One sample per day; fn(day_offset) -> mem_percent."""
    out = []
    for d in range(lo, hi + 1):
        s = {'ts': NOW + d * DAY, 'mem_percent': round(fn(d), 3)}
        s.update(extra)
        out.append(s)
    return out


def row(samples, metric='memory', **kw):
    rows = forecast.forecast_resources(samples, **kw)
    got = [r for r in rows if r['metric'] == metric]
    return got[0] if got else None


class TestCleanTrend(unittest.TestCase):
    def test_clean_upward_trend_projects_a_date(self):
        # 59% → 88% over 30 days, dead straight: 2 points of headroom left at
        # 1 point/day.
        r = row(mem_series(lambda d: 59.0 + (d + 29) * 1.0))
        self.assertIsNotNone(r)
        self.assertEqual(r['current'], 88.0)
        self.assertEqual(r['ceiling'], 90.0)
        self.assertEqual(r['headroom'], 2.0)
        self.assertAlmostEqual(r['days_to_saturation'], 2.0, places=1)
        self.assertEqual(r['r2'], 1.0)
        self.assertFalse(r['noisy'])
        self.assertFalse(r['stalled'])
        self.assertFalse(r['below_floor'])
        self.assertFalse(r['saturated'])
        self.assertFalse(r['beyond_horizon'])
        # the date is the last sample + the projected days
        self.assertEqual(r['saturation_date_ts'],
                         int(NOW + r['days_to_saturation'] * DAY))
        self.assertEqual(r['points'], 30)
        self.assertEqual(len(r['series']), 30)
        self.assertEqual(r['series'][0][0], NOW - 29 * DAY)
        self.assertEqual(r['unit'], '%')
        self.assertEqual(r['label'], 'Memory')

    def test_series_and_fitted_line_reconstruct_the_current_value(self):
        r = row(mem_series(lambda d: 59.0 + (d + 29) * 1.0))
        days = (r['series'][-1][0] - r['t0_ts']) / DAY
        self.assertAlmostEqual(r['slope'] * days + r['intercept'],
                               r['current'], places=1)


class TestFlatSeries(unittest.TestCase):
    def test_flat_series_is_not_projected(self):
        r = row(mem_series(lambda d: 75.0))
        self.assertIsNotNone(r)
        self.assertEqual(r['current'], 75.0)
        self.assertEqual(r['trend_per_day'], 0.0)
        self.assertIsNone(r['days_to_saturation'])
        self.assertIsNone(r['saturation_date_ts'])
        self.assertFalse(r['noisy'])       # flat is not noise, it's just flat
        self.assertFalse(r['stalled'])     # never grew, so nothing stalled

    def test_flat_series_below_the_floor_is_flagged(self):
        r = row(mem_series(lambda d: 12.0))
        self.assertTrue(r['below_floor'])
        self.assertIsNone(r['days_to_saturation'])


class TestNoisyRejectedByR2Gate(unittest.TestCase):
    # A deterministic sawtooth: the mean creeps up ~0.2%/day but each day swings
    # ±15 points, so the least-squares fit explains almost nothing.
    OFFSETS = [0, 14, -13, 9, -15, 12, -9, 15, -14, 8]

    def _saw(self):
        return mem_series(
            lambda d: 70.0 + 0.2 * (d + 29) + self.OFFSETS[(d + 29) % 10])

    def test_noisy_series_keeps_the_row_but_no_date(self):
        r = row(self._saw())
        self.assertIsNotNone(r)
        self.assertLess(r['r2'], 0.5)
        self.assertGreater(r['trend_per_day'], 0.01)   # the fit does point up…
        self.assertTrue(r['noisy'])                    # …but we refuse a date
        self.assertIsNone(r['days_to_saturation'])
        self.assertIsNone(r['saturation_date_ts'])

    def test_lowering_the_r2_gate_lets_the_same_series_through(self):
        # The gate is the only thing blocking it — proves noisy isn't a
        # side-effect of some other guard.
        r = row(self._saw(), min_r2=0.0)
        self.assertFalse(r['noisy'])
        self.assertIsNotNone(r['days_to_saturation'])


class TestTooFewPoints(unittest.TestCase):
    def test_two_points_produce_no_row(self):
        self.assertIsNone(row(mem_series(lambda d: 70.0 + d, lo=-1)))

    def test_min_points_is_honoured(self):
        s = mem_series(lambda d: 60.0 + (d + 4) * 5.0, lo=-4)
        self.assertIsNone(row(s, min_points=10))
        self.assertIsNotNone(row(s, min_points=5))

    def test_empty_and_none_samples(self):
        self.assertEqual(forecast.forecast_resources([]), [])
        self.assertEqual(forecast.forecast_resources(None), [])


class TestHoleInTheSeries(unittest.TestCase):
    def test_missing_days_are_skipped_not_zero_filled(self):
        # A ten-day gap in the middle. Zero-filling would invent a crash to 0%
        # and wreck the slope; skipping keeps the straight line intact.
        s = mem_series(lambda d: 59.0 + (d + 29) * 1.0)
        for smp in s:
            if -20 <= (smp['ts'] - NOW) // DAY <= -11:
                del smp['mem_percent']
        r = row(s)
        self.assertEqual(r['points'], 20)
        self.assertEqual(len(r['series']), 20)
        self.assertAlmostEqual(r['trend_per_day'], 1.0, places=2)
        self.assertAlmostEqual(r['days_to_saturation'], 2.0, places=1)

    def test_explicit_null_metric_is_a_hole_too(self):
        s = mem_series(lambda d: 70.0)
        for smp in s[:5]:
            smp['mem_percent'] = None
        r = row(s)
        self.assertEqual(r['points'], len(s) - 5)

    def test_all_holes_means_no_row(self):
        s = mem_series(lambda d: 70.0)
        for smp in s:
            smp['mem_percent'] = None
        self.assertIsNone(row(s))


class TestDownwardTrend(unittest.TestCase):
    def test_falling_memory_is_never_projected(self):
        r = row(mem_series(lambda d: 88.0 - (d + 29) * 0.5))
        self.assertIsNotNone(r)
        self.assertLess(r['trend_per_day'], 0)
        self.assertIsNone(r['days_to_saturation'])
        self.assertIsNone(r['saturation_date_ts'])
        self.assertFalse(r['noisy'])
        self.assertFalse(r['saturated'])


class TestGatesThatDeclineADate(unittest.TestCase):
    def test_below_floor_blocks_an_otherwise_clean_projection(self):
        # 5% → 34%, perfectly straight and climbing 1%/day, but nowhere near
        # the 60% floor: projecting "saturates in 56 days" from here is noise.
        r = row(mem_series(lambda d: 5.0 + (d + 29) * 1.0))
        self.assertTrue(r['below_floor'])
        self.assertIsNone(r['days_to_saturation'])
        self.assertGreater(r['trend_per_day'], 0.9)   # trend still reported

    def test_lowering_the_floor_lets_it_through(self):
        r = row(mem_series(lambda d: 5.0 + (d + 29) * 1.0), floors={'memory': 0})
        self.assertFalse(r['below_floor'])
        self.assertIsNotNone(r['days_to_saturation'])

    def test_beyond_horizon_keeps_the_row_and_drops_the_date(self):
        # 61% creeping 0.02%/day → ~1400 days to 90%. Real, but not actionable.
        r = row(mem_series(lambda d: 61.0 + (d + 29) * 0.02))
        self.assertTrue(r['beyond_horizon'])
        self.assertIsNone(r['days_to_saturation'])
        self.assertFalse(r['noisy'])
        # a caller willing to look further out can widen the horizon
        r2 = row(mem_series(lambda d: 61.0 + (d + 29) * 0.02), horizon_days=3650)
        self.assertFalse(r2['beyond_horizon'])
        self.assertGreater(r2['days_to_saturation'], 180)

    def test_growth_that_stopped_is_flagged_stalled(self):
        # climbed 1%/day until 8 days ago, flat since — the full-window slope
        # still points up, but the pressure is over.
        def fn(d):
            return 82.0 if d >= -8 else 82.0 + (d + 8) * 1.0
        r = row(mem_series(fn))
        self.assertTrue(r['stalled'])
        self.assertIsNone(r['days_to_saturation'])
        self.assertEqual(r['recent_per_day'], 0.0)
        self.assertGreater(r['trend_per_day'], 0.1)

    def test_decelerating_growth_uses_the_gentler_recent_rate(self):
        # fast early (2%/day), slow recently (0.05%/day): the projection should
        # use the current rate, not the alarmist full-window one.
        def fn(d):
            return (70.0 + 0.3 * (d + 8)) if d >= -8 else (70.0 + 2.0 * (d + 8))
        r = row(mem_series(fn))
        self.assertFalse(r['stalled'])
        self.assertIsNotNone(r['days_to_saturation'])
        full_rate_days = (r['ceiling'] - r['current']) / r['trend_per_day']
        self.assertGreater(r['days_to_saturation'], full_rate_days)

    def test_already_over_the_ceiling_is_a_present_tense_problem(self):
        r = row(mem_series(lambda d: 94.0))
        self.assertTrue(r['saturated'])
        self.assertEqual(r['days_to_saturation'], 0.0)
        self.assertEqual(r['saturation_date_ts'], NOW)
        self.assertEqual(r['headroom'], 0.0)


class TestLoadNormalisation(unittest.TestCase):
    def _load_series(self, la_fn, cores=4, lo=-29):
        return [{'ts': NOW + d * DAY, 'loadavg_1m': la_fn(d), 'cpu_count': cores}
                for d in range(lo, 1)]

    def test_load_is_percent_of_cores(self):
        r = row(self._load_series(lambda d: 2.0), metric='load')
        self.assertEqual(r['current'], 50.0)          # 2.0 on 4 cores
        self.assertEqual(r['ceiling'], 100.0)
        self.assertEqual(r['label'], 'CPU load')

    def test_rising_load_projects_a_date(self):
        # 2.0 → 3.45 on 4 cores = 50% → 86.25%, climbing 1.25 pts/day
        r = row(self._load_series(lambda d: 2.0 + (d + 29) * 0.05), metric='load')
        self.assertIsNotNone(r['days_to_saturation'])
        self.assertAlmostEqual(r['days_to_saturation'], (100.0 - r['current']) / 1.25,
                               places=0)

    def test_load_without_a_core_count_is_dropped(self):
        # A load average with no scale is meaningless — better no row than a
        # row projected against a ceiling that means nothing.
        s = [{'ts': NOW + d * DAY, 'loadavg_1m': 2.0} for d in range(-29, 1)]
        self.assertIsNone(row(s, metric='load'))
        for smp in s:
            smp['cpu_count'] = 0
        self.assertIsNone(row(s, metric='load'))

    def test_load_over_the_core_count_saturates(self):
        r = row(self._load_series(lambda d: 6.0), metric='load')   # 150% of 4 cores
        self.assertTrue(r['saturated'])
        self.assertEqual(r['current'], 150.0)


class TestSwapAndSelection(unittest.TestCase):
    def _full(self):
        return [{'ts': NOW + d * DAY,
                 'mem_percent': 70.0,
                 'swap_percent': 10.0 + (d + 29) * 2.0,
                 'loadavg_1m': 1.0, 'cpu_count': 4}
                for d in range(-29, 1)]

    def test_all_three_metrics_are_returned(self):
        rows = forecast.forecast_resources(self._full())
        self.assertEqual({r['metric'] for r in rows}, {'memory', 'swap', 'load'})

    def test_metrics_argument_selects(self):
        rows = forecast.forecast_resources(self._full(), metrics=('swap',))
        self.assertEqual([r['metric'] for r in rows], ['swap'])

    def test_unknown_metric_name_is_ignored_not_raised(self):
        rows = forecast.forecast_resources(self._full(), metrics=('nope', 'swap'))
        self.assertEqual([r['metric'] for r in rows], ['swap'])

    def test_rising_swap_saturates(self):
        # 10% → 68% at 2 pts/day, ceiling 80 → 6 days of headroom.
        r = row(self._full(), metric='swap')
        self.assertAlmostEqual(r['days_to_saturation'], 6.0, places=1)

    def test_soonest_to_saturate_sorts_first_and_never_sinks(self):
        rows = forecast.forecast_resources(self._full())
        self.assertEqual(rows[0]['metric'], 'swap')     # only one with a date
        self.assertIsNone(rows[-1]['days_to_saturation'])
        dated = [r['days_to_saturation'] for r in rows
                 if r['days_to_saturation'] is not None]
        self.assertEqual(dated, sorted(dated))

    def test_ceiling_override_shortens_the_projection(self):
        base = row(self._full(), metric='swap')
        tight = row(self._full(), metric='swap', ceilings={'swap': 70.0})
        self.assertLess(tight['days_to_saturation'], base['days_to_saturation'])
        self.assertEqual(tight['ceiling'], 70.0)

    def test_bogus_override_falls_back_to_the_default(self):
        for bad in ({'swap': None}, {'swap': 'lots'}, {'swap': -5}, {'swap': 0}):
            r = row(self._full(), metric='swap', ceilings=bad)
            self.assertEqual(r['ceiling'], forecast.RESOURCE_DEFS['swap']['ceiling'],
                             f'override {bad!r} should have fallen back')


class TestGarbageInput(unittest.TestCase):
    def test_junk_samples_are_skipped_not_fatal(self):
        good = mem_series(lambda d: 59.0 + (d + 29) * 1.0)
        junk = [None, 'nope', 42, [], {}, {'ts': None, 'mem_percent': 70},
                {'ts': 'yesterday', 'mem_percent': 70},
                {'ts': True, 'mem_percent': 70}]
        r = row(junk + good)
        self.assertEqual(r['points'], len(good))
        self.assertAlmostEqual(r['days_to_saturation'], 2.0, places=1)

    def test_non_numeric_metric_values_are_holes(self):
        s = mem_series(lambda d: 70.0)
        for smp, bad in zip(s, ['80', True, False, [], {}, float('nan'),
                                float('inf'), float('-inf'), -3.0]):
            smp['mem_percent'] = bad
        r = row(s)
        self.assertEqual(r['points'], len(s) - 9)
        self.assertEqual(r['current'], 70.0)

    def test_identical_timestamps_do_not_divide_by_zero(self):
        s = [{'ts': NOW, 'mem_percent': 70.0 + i} for i in range(5)]
        r = row(s)
        self.assertEqual(r['trend_per_day'], 0.0)
        self.assertIsNone(r['days_to_saturation'])

    def test_out_of_order_samples_are_sorted(self):
        s = mem_series(lambda d: 59.0 + (d + 29) * 1.0)
        shuffled = s[15:] + s[:15]
        self.assertEqual(row(shuffled)['series'], row(s)['series'])


class TestRegistryShape(unittest.TestCase):
    def test_metrics_tuple_matches_the_definitions(self):
        self.assertEqual(set(forecast.RESOURCE_METRICS),
                         set(forecast.RESOURCE_DEFS))
        for name, d in forecast.RESOURCE_DEFS.items():
            self.assertTrue(d['label'], name)
            self.assertGreater(d['ceiling'], d['floor'], name)


class TestProperties(unittest.TestCase):
    """Invariants that must hold for ANY series (Hypothesis)."""

    @settings(max_examples=250, deadline=None)
    @given(st.lists(st.floats(min_value=0, max_value=100,
                              allow_nan=False, allow_infinity=False),
                    min_size=0, max_size=40))
    def test_invariants_hold_for_any_memory_series(self, vals):
        samples = [{'ts': NOW + i * DAY, 'mem_percent': v}
                   for i, v in enumerate(vals)]
        rows = forecast.forecast_resources(samples)
        self.assertLessEqual(len(rows), 1)             # only memory is present
        for r in rows:
            self.assertEqual(r['points'], len(r['series']))
            self.assertGreaterEqual(r['points'], 3)
            self.assertEqual(r['current'], round(vals[-1], 1))
            self.assertTrue(0.0 <= r['r2'] <= 1.0)
            d = r['days_to_saturation']
            # A date is produced only with a clean fit or an already-saturated
            # resource — never from noise.
            if d is None:
                self.assertIsNone(r['saturation_date_ts'])
            else:
                self.assertGreaterEqual(d, 0.0)
                self.assertLessEqual(d, forecast._RESOURCE_HORIZON_DAYS)
                self.assertIsNotNone(r['saturation_date_ts'])
                self.assertGreaterEqual(r['saturation_date_ts'], r['series'][-1][0])
                self.assertTrue(r['saturated'] or r['r2'] >= forecast._MIN_R2)
                self.assertFalse(r['noisy'])
                self.assertFalse(r['below_floor'])
                self.assertFalse(r['beyond_horizon'])
            # the mutually-exclusive "why there's no date" flags
            self.assertFalse(r['noisy'] and r['stalled'])

    @settings(max_examples=200, deadline=None)
    @given(st.lists(st.tuples(st.integers(min_value=0, max_value=400),
                              st.floats(min_value=0, max_value=100,
                                        allow_nan=False, allow_infinity=False)),
                    min_size=0, max_size=30))
    def test_ragged_timestamps_never_raise(self, pts):
        samples = [{'ts': NOW + d * DAY, 'mem_percent': v} for d, v in pts]
        for r in forecast.forecast_resources(samples):
            ts = [p[0] for p in r['series']]
            self.assertEqual(ts, sorted(ts))           # always time-ordered
            self.assertGreaterEqual(r['headroom'], 0.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
