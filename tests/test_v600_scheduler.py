"""Phase-5 "keystone" Stage D — out-of-band maintenance scheduler.

Verifies the standalone scheduler runs the SAME cadence main() does (a parity
guardrail so a newly-added sweep can't silently be missed), that its leader lock is
exclusive, and that the request-path guard (_external_scheduler_active) is opt-in
and default-off.
"""
import os
import time
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sched-test-"))

from srcpin import py_function  # noqa: E402

import scheduler  # noqa: E402  (imports api)
api = scheduler.api


class TestSchedulerCadenceParity(unittest.TestCase):
    def test_cadence_matches_main_safe_wrapped_set(self):
        src = (_CGI / "api.py").read_text()
        # main() wraps EVERY maintenance sweep in _safe(<fn>, 'label', …). Parse the
        # CALL sites; exclude the helper's own `def _safe(fn, …)` signature token.
        wrapped = set(re.findall(r'_safe\((\w+),', src)) - {'fn'}
        self.assertEqual(set(scheduler.CADENCE), wrapped,
                         f"scheduler CADENCE out of sync with main(): "
                         f"missing={wrapped - set(scheduler.CADENCE)}, "
                         f"extra={set(scheduler.CADENCE) - wrapped}")

    def test_every_cadence_fn_exists_and_is_zero_arg_callable(self):
        import inspect
        for name in scheduler.CADENCE:
            fn = getattr(api, name, None)
            self.assertTrue(callable(fn), f"{name} missing/not callable")
            # every sweep must be callable with no args (all required params default)
            sig = inspect.signature(fn)
            required = [p for p in sig.parameters.values()
                        if p.default is p.empty
                        and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            self.assertEqual(required, [], f"{name} needs args: {required}")


class TestRunCadenceOnce(unittest.TestCase):
    def test_runs_each_sweep_guarded(self):
        saved = {n: getattr(api, n) for n in scheduler.CADENCE}
        called = []
        try:
            for n in scheduler.CADENCE:
                setattr(api, n, (lambda nm: (lambda *a, **k: called.append(nm)))(n))
            # one stub raises — the rest must still run (guarded like main()'s _safe)
            boom = scheduler.CADENCE[3]
            setattr(api, boom, lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
            ran = scheduler.run_cadence_once()
            self.assertEqual(set(called), set(scheduler.CADENCE) - {boom})
            self.assertEqual(ran, len(scheduler.CADENCE) - 1)
        finally:
            for n, fn in saved.items():
                setattr(api, n, fn)


class TestLeaderLock(unittest.TestCase):
    def test_host_leader_lock_is_exclusive(self):
        first = scheduler.acquire_host_leader_lock()
        self.assertIsNotNone(first, "first acquirer should become leader")
        try:
            second = scheduler.acquire_host_leader_lock()
            self.assertIsNone(second, "a second acquirer must NOT also get the lock")
        finally:
            first.close()      # releasing lets a later acquirer win
        third = scheduler.acquire_host_leader_lock()
        self.assertIsNotNone(third, "after release the lock is acquirable again")
        third.close()

    def test_pg_advisory_lock_is_na_without_pg(self):
        saved = os.environ.get('RP_STORAGE_BACKEND')
        try:
            os.environ.pop('RP_STORAGE_BACKEND', None)   # not PG → no cross-node lock needed
            self.assertEqual(scheduler.acquire_pg_leader_lock(), 'n/a')
        finally:
            if saved is None:
                os.environ.pop('RP_STORAGE_BACKEND', None)
            else:
                os.environ['RP_STORAGE_BACKEND'] = saved


class TestRequestPathGuard(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get('RP_EXTERNAL_SCHEDULER')

    def tearDown(self):
        if self._saved is None:
            os.environ.pop('RP_EXTERNAL_SCHEDULER', None)
        else:
            os.environ['RP_EXTERNAL_SCHEDULER'] = self._saved

    def test_default_off(self):
        os.environ.pop('RP_EXTERNAL_SCHEDULER', None)
        # no env + (test config has no external_scheduler) → request path keeps the cadence
        self.assertFalse(api._external_scheduler_active())

    def _beat(self, age_s):
        """Write a scheduler heartbeat `age_s` seconds old."""
        api.save(api.SCHEDULER_STATE_FILE,
                 {'ts': int(time.time()) - age_s, 'interval': 60})
        api._invalidate_load_cache(api.SCHEDULER_STATE_FILE)

    def test_env_enables_when_the_scheduler_is_actually_alive(self):
        """v6.4.2: the flag says WHO SHOULD own the cadence. It never asked
        whether that owner is alive — so when remotepower-scheduler OOMed, the
        request path REFUSED to pick up all ~33 sweeps (offline detection,
        monitors, integrations, ticket SLA, the daily backup) because the flag
        was still set, and the fleet looked perfectly healthy. The flag alone is
        no longer sufficient; a recent heartbeat is required too."""
        self._beat(10)
        for v in ('1', 'true', 'YES', 'on'):
            os.environ['RP_EXTERNAL_SCHEDULER'] = v
            self.assertTrue(api._external_scheduler_active(), v)
        os.environ['RP_EXTERNAL_SCHEDULER'] = 'no'
        self.assertFalse(api._external_scheduler_active())

    def test_a_stalled_scheduler_hands_the_cadence_back(self):
        os.environ['RP_EXTERNAL_SCHEDULER'] = '1'
        try:
            self._beat(10)
            self.assertTrue(api._external_scheduler_active())
            self._beat(3600)
            self.assertFalse(api._external_scheduler_active(),
                             'a scheduler silent for an hour still owned the '
                             'cadence, so nothing ran it')
        finally:
            os.environ['RP_EXTERNAL_SCHEDULER'] = 'no'

    def test_a_scheduler_that_never_beat_hands_it_back(self):
        """Either it has not started on a fresh install or it is not running at
        all; in both cases the request path taking the cadence is the safe
        answer, and the sweeps claim their slots so nothing double-runs."""
        os.environ['RP_EXTERNAL_SCHEDULER'] = '1'
        try:
            api.save(api.SCHEDULER_STATE_FILE, {})
            api._invalidate_load_cache(api.SCHEDULER_STATE_FILE)
            self.assertFalse(api._external_scheduler_active())
        finally:
            os.environ['RP_EXTERNAL_SCHEDULER'] = 'no'

    def test_the_grace_is_far_wider_than_the_liveness_indicator(self):
        """A slow sweep or a restart must never make BOTH run — the sweeps are
        idempotent and claim their slot, but double-running is still waste."""
        os.environ['RP_EXTERNAL_SCHEDULER'] = '1'
        try:
            self._beat(400)   # well past _runtime_serving_info's ~180s window
            self.assertTrue(api._external_scheduler_active())
        finally:
            os.environ['RP_EXTERNAL_SCHEDULER'] = 'no' 

    def test_main_safe_guarded_by_flag(self):
        src = (_CGI / "api.py").read_text()
        body = py_function(src, 'main')
        self.assertIn('_ext_sched = _external_scheduler_active()', body)
        self.assertIn('if _ext_sched:', body)

    def test_self_test_nudges_scheduler_on_postgres(self):
        src = (_CGI / "api.py").read_text()
        block = py_function(src, 'handle_self_test')
        self.assertIn("_storage_backend() == 'postgres' and not _external_scheduler_active()", block)
        self.assertIn("'Maintenance scheduler'", block)


class TestSchedulerSystemdUnit(unittest.TestCase):
    """The out-of-band scheduler ships a ready-made systemd unit."""

    def test_unit_present_and_wired(self):
        unit = _ROOT / "server" / "conf" / "remotepower-scheduler.service"
        self.assertTrue(unit.exists(), "remotepower-scheduler.service missing")
        txt = unit.read_text()
        self.assertIn("scheduler.py", txt)                 # runs the scheduler
        self.assertIn("RP_EXTERNAL_SCHEDULER=1", txt)       # owns the cadence
        self.assertIn("EnvironmentFile=-/etc/remotepower/api.env", txt)  # same secrets as worker
        self.assertIn("[Install]", txt)


if __name__ == '__main__':
    unittest.main()
