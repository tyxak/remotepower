#!/usr/bin/env python3
"""The off-host backup posture row must grade the outcome, not the setting.

`Backups mirrored off-host` graded `bool(offsite_dir)` — so it turned green the
moment a destination was configured, and STAYED green while every mirror since
had failed. The real result is recorded as `offsite_ok` in
self_backup_state.json by the run that just failed, two files away from the row
that reports on it.

A posture row that answers "is it configured?" while appearing to answer "is it
working?" is the UI-that-lies class the repo treats as zero tolerance — and
this is the one row an operator reads before trusting their disaster recovery,
which is the worst possible place for it. The failure is also silent by
construction: a mirror failing does not raise, it records `offsite_ok: False`
and moves on.

Three states now, because two of them used to be indistinguishable from a pass:
configured-and-working, configured-and-FAILING, and configured-but-never-run.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643offs-'))

_spec = importlib.util.spec_from_file_location('api_v643_offs', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    STATE = api.DATA_DIR / 'self_backup_state.json'

    def _row(self, offsite_dir, offsite_ok='__absent__'):
        api.save(api.CONFIG_FILE, {'backup': {'offsite_dir': offsite_dir}})
        state = {} if offsite_ok == '__absent__' else {'offsite_ok': offsite_ok}
        api.save(self.STATE, state)
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._invalidate_load_cache(self.STATE)
        # There is no _security_posture_rows() — I invented that name, and all
        # six tests SKIPPED with a plausible reason, which is a file that
        # measures nothing while reporting green. The rows are built inline in
        # handle_security_posture, so drive the real handler.
        cap = {}
        orig = (api.require_admin_or_auditor_auth, api.method, api.respond)
        api.require_admin_or_auditor_auth = lambda *a, **k: 'root'
        api.method = lambda: 'GET'

        def _r(status, data=None, *a, **k):
            cap['s'], cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r
        try:
            api.handle_security_posture()
        except (SystemExit, api.HTTPError):
            pass
        finally:
            (api.require_admin_or_auditor_auth, api.method, api.respond) = orig
        rows = (cap.get('d') or {}).get('checks') or []
        self.assertTrue(rows, 'the posture handler returned no rows at all')
        return next(r for r in rows if r.get('key') == 'backup_offsite')


class TestTheRowReflectsReality(_Base):
    def test_a_failing_mirror_is_not_a_pass(self):
        """The bug: configured + last attempt FAILED used to read as ok."""
        r = self._row('/mnt/offsite', offsite_ok=False)
        self.assertEqual(r['status'], 'warn',
                         'the row reports a pass while the last mirror failed')
        self.assertIn('FAILED', r['detail'])

    def test_a_working_mirror_passes(self):
        """Positive control — a row that always failed would satisfy the test
        above while being just as useless."""
        r = self._row('/mnt/offsite', offsite_ok=True)
        self.assertEqual(r['status'], 'ok', r['detail'])
        self.assertIn('/mnt/offsite', r['detail'])

    def test_configured_but_never_run_is_not_a_pass_either(self):
        """`offsite_ok` is None until a backup has actually run. Reporting that
        as working is the same lie one step earlier."""
        r = self._row('/mnt/offsite', offsite_ok=None)
        self.assertEqual(r['status'], 'warn')
        self.assertIn('no backup has run', r['detail'])

    def test_absent_state_is_treated_as_never_run(self):
        r = self._row('/mnt/offsite')
        self.assertEqual(r['status'], 'warn')

    def test_unconfigured_is_still_unconfigured(self):
        r = self._row('')
        self.assertEqual(r['status'], 'warn')
        self.assertIn('local-host only', r['detail'])

    def test_the_remediation_points_at_the_right_thing(self):
        """A failing mirror needs "check the last run", not "set a
        destination" — the destination is already set."""
        r = self._row('/mnt/offsite', offsite_ok=False)
        self.assertIn('mirror step reports its own success', r['hint'])


if __name__ == '__main__':
    unittest.main()
