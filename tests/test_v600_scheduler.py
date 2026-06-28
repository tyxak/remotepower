"""Phase-5 "keystone" Stage D — out-of-band maintenance scheduler.

Verifies the standalone scheduler runs the SAME cadence main() does (a parity
guardrail so a newly-added sweep can't silently be missed), that its leader lock is
exclusive, and that the request-path guard (_external_scheduler_active) is opt-in
and default-off.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sched-test-"))

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

    def test_env_enables(self):
        for v in ('1', 'true', 'YES', 'on'):
            os.environ['RP_EXTERNAL_SCHEDULER'] = v
            self.assertTrue(api._external_scheduler_active(), v)
        os.environ['RP_EXTERNAL_SCHEDULER'] = 'no'
        self.assertFalse(api._external_scheduler_active())

    def test_main_safe_guarded_by_flag(self):
        src = (_CGI / "api.py").read_text()
        i = src.index('def main():')
        self.assertIn('_ext_sched = _external_scheduler_active()', src[i:i + 4000])
        self.assertIn('if _ext_sched:', src[i:i + 4000])


if __name__ == '__main__':
    unittest.main()
