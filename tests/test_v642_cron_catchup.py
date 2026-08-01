"""Cron-scheduled sweeps must catch up, not require an exact-minute hit.

Six CADENCE members — scheduled commands, backup jobs, auto-patch, both report
senders and recurring tickets — fired only if the cadence happened to execute
during the very minute `_cron_matches(cron, now)` was true. Every other sweep
uses a persisted `now - last_run >= interval` test, which a late tick still
satisfies; these six had no catch-up at all.

Under the out-of-band scheduler (the default deployment since v6.1.0)
`main()` runs the cadence then sleeps a fixed interval, so ticks are a
fixed-PERIOD sequence rather than a per-minute sample:

  * at the shipped 60 s interval any non-zero cadence duration pushes the period
    past 60 s and minutes get skipped — the shipped per-run wall-clock budgets
    alone sum to 67 s, which dropped ~60 % of a daily job's runs;
  * at any interval > 60 s the phase relative to a day is CONSTANT (86400 is
    divisible by 120/300/600), so a given cron minute is either always sampled
    or NEVER sampled — a daily job silently never fired again.

Nothing surfaced it: no alert, no log line, the policy still read enabled with a
stale last_run. Both `scheduler.py`'s docstring and docs/wsgi.md state as fact
that the sweeps are `_if_due`-gated and the interval only controls how often
"what's due" is checked; for these six that was false.
"""

import importlib.util
import os
import sys
import tempfile
import time as _rt
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-cron-"))

_spec = importlib.util.spec_from_file_location("api_v642_cron", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules["api_v642_cron"] = api
_spec.loader.exec_module(api)

CRON = '30 3 * * *'          # an ordinary "auto-patch at 03:30" policy
DAYS = 30


class _FakeClock:
    def __init__(self, mod):
        self._m, self.now = mod, 0.0

    def time(self):
        return self.now

    def __getattr__(self, name):
        return getattr(self._m, name)


class TestCronSweepsCatchUp(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-cron-run-"))
        self._af = api.AUTOPATCH_FILE
        api.AUTOPATCH_FILE = self.d / "autopatch.json"
        self._time = api.time
        self.clock = _FakeClock(_rt)
        api.time = self.clock

    def tearDown(self):
        api.time = self._time
        api.AUTOPATCH_FILE = self._af

    def _simulate(self, interval, cadence_seconds, start_offset, seed_minute=None):
        """Replay scheduler.main(): run the cadence, then sleep(interval).

        Returns how many of DAYS days the policy actually fired on.
        """
        api.save(api.AUTOPATCH_FILE, {'policies': [{
            'id': 'p1', 'name': 'nightly', 'enabled': True, 'cron': CRON,
            'created_by': 'admin', 'targets': [],
            'last_fired_minute': seed_minute,
        }]})
        t0 = _rt.mktime((2026, 8, 2, 0, 0, 0, 0, 0, -1)) + start_offset
        self.clock.now = t0
        end, fires = t0 + DAYS * 86400, 0
        while self.clock.now < end:
            api._invalidate_load_cache(api.AUTOPATCH_FILE)
            before = api.load(api.AUTOPATCH_FILE)['policies'][0].get('last_run')
            api.process_autopatch()
            api._invalidate_load_cache(api.AUTOPATCH_FILE)
            if api.load(api.AUTOPATCH_FILE)['policies'][0].get('last_run') != before:
                fires += 1
            self.clock.now += interval + cadence_seconds
        return fires

    def test_fires_once_a_day_at_the_shipped_interval(self):
        self.assertEqual(self._simulate(60, 0, 0), DAYS)

    def test_a_slow_cadence_does_not_drop_runs(self):
        # 67 s is the sum of the shipped per-run wall-clock budgets alone
        # (IP_REP 20 + RESOLVER 20 + TLS 15 + CT 12), against a 60 s interval.
        self.assertEqual(self._simulate(60, 67, 0), DAYS)

    def test_a_longer_interval_does_not_kill_the_job(self):
        # 86400 % interval == 0 for all three, so the tick phase is constant and
        # the cron minute was NEVER sampled before the catch-up.
        for interval in (120, 300, 600):
            with self.subTest(interval=interval):
                self.assertEqual(self._simulate(interval, 0, 70), DAYS)

    def test_it_still_fires_exactly_once_per_day(self):
        self.assertEqual(self._simulate(60, 2, 0), DAYS,
                         'the catch-up must not fire a job twice in one day')

    def test_a_new_schedule_does_not_fire_for_a_window_that_predates_it(self):
        """A job created at 03:45 must not immediately run for 03:30. Creation
        stamps `last_fired_minute`, so the catch-up window starts at creation —
        without that, the bounded look-back would reach backwards over an hour
        the schedule did not exist for."""
        t = _rt.mktime((2026, 8, 2, 3, 45, 0, 0, 0, -1))
        self.clock.now = t
        api.save(api.AUTOPATCH_FILE, {'policies': [{
            'id': 'p1', 'name': 'nightly', 'enabled': True, 'cron': CRON,
            'created_by': 'admin', 'targets': [],
            'last_fired_minute': int(t) // 60 - 1,    # what the create path stamps
        }]})
        api.process_autopatch()
        api._invalidate_load_cache(api.AUTOPATCH_FILE)
        self.assertIsNone(
            api.load(api.AUTOPATCH_FILE)['policies'][0].get('last_run'),
            'a freshly created schedule fired for a window that closed before it '
            'existed')

    def test_a_legacy_record_catches_up_at_most_one_window(self):
        """An upgrade finds `last_fired_minute` absent. It must catch up (that is
        the whole point) but only over the bounded look-back, not since epoch."""
        t = _rt.mktime((2026, 8, 2, 3, 45, 0, 0, 0, -1))   # 15 min after 03:30
        self.clock.now = t
        api.save(api.AUTOPATCH_FILE, {'policies': [{
            'id': 'p1', 'name': 'nightly', 'enabled': True, 'cron': CRON,
            'created_by': 'admin', 'targets': [], 'last_fired_minute': None,
        }]})
        api.process_autopatch()
        api._invalidate_load_cache(api.AUTOPATCH_FILE)
        self.assertIsNotNone(
            api.load(api.AUTOPATCH_FILE)['policies'][0].get('last_run'),
            'a legacy record must catch up its missed window on the first tick')


class TestCronDueSince(unittest.TestCase):
    """The helper itself, without the sweep around it."""

    def _m(self, *tm):
        return int(_rt.mktime(tm + (0, 0, -1)))

    def test_matches_a_minute_inside_the_window(self):
        now = self._m(2026, 8, 2, 3, 45, 0)
        self.assertTrue(api._cron_due_since(CRON, now, now // 60 - 20))

    def test_ignores_a_minute_before_the_window(self):
        now = self._m(2026, 8, 2, 3, 45, 0)
        self.assertFalse(api._cron_due_since(CRON, now, now // 60 - 5))

    def test_the_lookback_is_bounded(self):
        """A day-long outage must not walk 1440 minutes, nor fire for every
        matched minute since the process died."""
        now = self._m(2026, 8, 3, 12, 0, 0)
        self.assertFalse(api._cron_due_since(CRON, now, now // 60 - 5000))
        self.assertLessEqual(api.CRON_CATCHUP_MINUTES, 60 * 6)

    def test_already_claimed_this_minute_still_evaluates_it(self):
        """The caller's own same-minute dedup is what stops a double fire; the
        helper must still report the current minute as due, or seeding the claim
        would block the first legitimate run."""
        now = self._m(2026, 8, 2, 3, 30, 0)
        self.assertTrue(api._cron_due_since(CRON, now, now // 60))

    def test_a_bad_expression_never_raises(self):
        now = self._m(2026, 8, 2, 3, 30, 0)
        for junk in ('', 'not a cron', '* * *', '99 99 99 99 99'):
            self.assertIn(api._cron_due_since(junk, now, now // 60 - 10),
                          (True, False), junk)


class TestSchedulerTickDoesNotDrift(unittest.TestCase):
    """The loop slept a full `interval` AFTER the cadence ran, so the real
    period was `interval + however long the sweeps took` — which also stretches
    every due-time sweep's effective period, not just the cron ones."""

    def test_the_sleep_subtracts_the_cadence_duration(self):
        import ast
        tree = ast.parse((_CGI / "scheduler.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "main")
        src = ast.unparse(fn)
        self.assertIn("_tick_started", src)
        self.assertNotIn("time.sleep(interval)\n", src.split("_tick_started")[-1],
                         "the post-cadence sleep must subtract the elapsed time")


if __name__ == '__main__':
    unittest.main()
