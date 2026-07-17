"""v6.2.3 self-observability: the ~33 maintenance sweeps run inside a swallow-all
wrapper, so a sweep that silently stops or starts failing used to be invisible.
_self_obs_mark records each sweep's last-ok / last-error (+ a small error ring),
surfaced via GET /api/self/observability so 'why did X stop firing?' is answerable.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-obs-'))
_spec = importlib.util.spec_from_file_location('api_v623_obs', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestSelfObservability(unittest.TestCase):
    def setUp(self):
        api._SELF_OBS = None
        try:
            api.save(api.SELF_OBS_FILE, {'sweeps': {}, 'errors': []})
        except Exception:
            pass
        api._invalidate_load_cache(api.SELF_OBS_FILE)
        api._SELF_OBS = None
        self.cap = {}
        self._r, self._a = api.respond, api.require_admin_auth

        def resp(s, d=None):
            self.cap['s'], self.cap['d'] = s, d
            raise SystemExit
        api.respond = resp
        api.require_admin_auth = lambda: 'admin'

    def tearDown(self):
        api.respond, api.require_admin_auth = self._r, self._a

    def _obs(self):
        try:
            api.handle_self_observability()
        except SystemExit:
            pass
        return self.cap['d']

    def test_marks_ok_and_failure(self):
        api._self_obs_mark('run_monitors_if_due', True)
        api._self_obs_mark('run_dmarc_imap_if_due', False, ValueError('IMAP down'))
        d = self._obs()
        self.assertEqual(d['tracked'], 2)
        self.assertEqual(d['failing'], 1)
        by = {r['name']: r for r in d['sweeps']}
        self.assertFalse(by['run_monitors_if_due']['failing'])
        self.assertTrue(by['run_monitors_if_due']['last_ok'] > 0)
        self.assertTrue(by['run_dmarc_imap_if_due']['failing'])
        self.assertIn('IMAP down', by['run_dmarc_imap_if_due']['err'])

    def test_error_ring_records_recent_swallowed_errors(self):
        for i in range(3):
            api._self_obs_mark('sweep_x', False, RuntimeError(f'boom{i}'))
        d = self._obs()
        self.assertGreaterEqual(len(d['errors']), 3)
        self.assertIn('boom2', d['errors'][-1]['err'])

    def test_error_ring_is_capped(self):
        for i in range(api._SELF_OBS_MAX_ERRORS + 20):
            api._self_obs_mark('sweep_y', False, RuntimeError(str(i)))
        d = self._obs()
        self.assertLessEqual(len(d['errors']), api._SELF_OBS_MAX_ERRORS)

    def test_recovering_clears_failing(self):
        api._self_obs_mark('sweep_z', False, ValueError('x'))
        api._self_obs_mark('sweep_z', True)          # next run succeeds
        d = self._obs()
        z = next(r for r in d['sweeps'] if r['name'] == 'sweep_z')
        self.assertFalse(z['failing'], 'a later OK clears the failing flag')

    def test_mark_never_raises(self):
        # self-observability must never break the thing it observes
        try:
            api._self_obs_mark(None, False, None)
            api._record_self_error('ctx', ValueError('y'))
        except Exception as e:
            self.fail(f'_self_obs_mark raised: {e}')

    def test_endpoint_requires_admin(self):
        called = {}
        api.require_admin_auth = lambda: called.setdefault('a', True) or 'admin'
        self._obs()
        self.assertTrue(called.get('a'), 'observability must be admin-gated')

    def test_safe_wrapper_and_scheduler_are_instrumented(self):
        src = (CGI / 'api.py').read_text()
        i = src.index('def _safe(fn, label')
        self.assertIn('_self_obs_mark(label, True)', src[i:i + 500])
        self.assertIn('_self_obs_mark(label, False', src[i:i + 500])
        sched = (CGI / 'scheduler.py').read_text()
        self.assertIn('_self_obs_mark', sched)


if __name__ == '__main__':
    unittest.main()
