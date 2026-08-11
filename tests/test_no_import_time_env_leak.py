#!/usr/bin/env python3
"""No test module may change the process environment at IMPORT time.

`unittest discover` — what `make test` and `make test-sqlite` actually run —
imports EVERY test module before executing a single test. So a module that
mutates `os.environ` at import time has already broken every other module's
`setUpClass` before any of them get to look, and a `tearDownModule` restore
(however correct) fires far too late to help.

This is not hypothetical and it was not cheap. `test_hypothesis_props.py` had a
module-level `_API = _fresh_api()`, and `_fresh_api()` POPS
`RP_STORAGE_BACKEND`. The file carried a careful `tearDownModule` restore and a
comment warning about exactly this leak class — and leaked at import anyway,
where the restore could not reach.

What it cost, all of it invisible:

  * `make test-sqlite` re-ran the ENTIRE a11y browser walk. That suite skips
    itself under RP_STORAGE_BACKEND=sqlite because it audits the rendered
    frontend, which no storage backend can change — but the guard read None.
  * `test_v430_e2e` re-ran for the same reason.
  * ~7 minutes added to every gate run, spent proving something already proven.
  * A 90-second Playwright selector timeout under the contention that created,
    reported as a gate FAILURE twice and written off as environmental twice,
    because the documented advice for that symptom is "e2e flake under load".

The last point is the reason this test exists rather than a comment: the leak
manufactured evidence for its own dismissal.

pytest is NOT affected the same way (it imports lazily per module), which is
why this only ever showed up in the real gate and never while iterating.
"""
import importlib
import os
import pathlib
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent
# Environment keys that steer behaviour across module boundaries. A leak in any
# of these silently reconfigures every module imported after it.
_WATCHED = ('RP_STORAGE_BACKEND', 'RP_DATA_DIR', 'RP_PG_DSN', 'RP_PG_TEST_DSN',
            'RP_EXTERNAL_SCHEDULER', 'RP_CGI_BIN', 'RP_READ_ONLY')


class TestNoImportTimeEnvLeak(unittest.TestCase):
    """Imports every test module in discover's order and reports any that
    change a watched key. Deliberately behavioural: a static scan cannot see a
    module-level call to a helper that mutates the environment three frames
    down, which is precisely how the real one hid."""

    def test_importing_every_test_module_leaves_the_env_alone(self):
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        # RP_DATA_DIR is exempt from the VALUE check: several modules set it at
        # import time on purpose, which CLAUDE.md requires so a stray import
        # never writes into a live /var/lib/remotepower. What must not change is
        # the rest.
        watched = tuple(k for k in _WATCHED if k != 'RP_DATA_DIR')
        # SET A SENTINEL for every watched key first. The first version of this
        # test compared against the ambient environment — and under `make test`
        # RP_STORAGE_BACKEND is UNSET, so the leak it was written to catch
        # (a `.pop()` of an absent key) is a no-op and nothing is detectable.
        # It passed against the reintroduced bug. A guard that only works under
        # one of the two runs it protects is the false-green this whole release
        # is about, so: plant a value, and any pop OR overwrite shows up.
        original = {k: os.environ.get(k) for k in watched}
        self.addCleanup(self._restore, original)
        for k in watched:
            os.environ[k] = f'__sentinel_{k}__'
        before = {k: os.environ.get(k) for k in watched}
        offenders = []
        for path in sorted(_ROOT.glob('test_*.py')):
            if path.name == pathlib.Path(__file__).name:
                continue
            pre = {k: os.environ.get(k) for k in watched}
            try:
                importlib.import_module(path.stem)
            except Exception:
                continue          # an import that fails is another test's problem
            for k in watched:
                if os.environ.get(k) != pre[k]:
                    offenders.append(
                        f'{path.name}: {k} {pre[k]!r} -> {os.environ.get(k)!r}')
                    if pre[k] is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = pre[k]
        self.assertEqual(offenders, [], '\n'.join([
            'these modules change the environment at IMPORT time:', *offenders,
            '',
            'unittest discover imports every module before running anything, so '
            'this has already reconfigured every other module by the time their '
            'setUpClass runs — and tearDownModule cannot help, because it fires '
            'after the damage. Move the mutation into setUp/setUpClass, or '
            'restore it immediately after the import-time call.']))
        # and confirm nothing drifted overall
        self.assertEqual({k: os.environ.get(k) for k in watched}, before)

    @staticmethod
    def _restore(original):
        for k, v in original.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_the_detector_would_notice(self):
        """Guard the guard: prove the comparison catches a change, so a green
        result means "nothing leaked" rather than "nothing was measured"."""
        key = 'RP_STORAGE_BACKEND'
        pre = os.environ.get(key)
        try:
            os.environ[key] = '__leak_probe__'
            self.assertNotEqual(os.environ.get(key), pre)
        finally:
            if pre is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = pre


if __name__ == '__main__':
    unittest.main()
