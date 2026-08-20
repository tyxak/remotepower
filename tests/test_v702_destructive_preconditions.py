#!/usr/bin/env python3
"""Three operations reported success for work that did not happen.

All three sit on paths where being wrong is expensive: the audit trail, the
disaster-recovery restore, and offline detection.

1. **Clearing the audit log destroyed it when the archive failed.** The pre-wipe
   gzip exists, in the code's own words, "so a clear can never silently destroy
   evidence". Its `except` logged to the server log and fell straight through to
   the wipe — so a full disk or a read-only volume erased the log, returned 200,
   and left one entry reading "audit log cleared (pre-wipe archived)". The single
   record an auditor would read asserted an archive that was never written.

2. **A partial restore reported ok:true.** The extract loop swallowed every
   member it could not write — an existing directory at the name, a read-only
   file, ENOSPC part-way through — and counted only successes, against no
   baseline. The result is a data directory that is half backup and half broken
   install, on the DR path, reported as clean.

3. **The anti-flap FLOOR could exceed the ceiling it floors.** `online_ttl` is
   hard-rejected above 7200s; `min_online_ttl` accepted 100000, and
   `get_online_ttl()` returns max(floor, ttl) — so offline detection stretched
   to 27.8 hours and a dead host stayed green for over a day.
"""
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702dp-'))
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702dp', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api_v702dp'] = api
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix='rp-dp-'))
        self._saved = {n: getattr(api, n) for n in
                       ('CONFIG_FILE', 'AUDIT_LOG_FILE', 'USERS_FILE', 'DATA_DIR')}
        for n in ('CONFIG_FILE', 'AUDIT_LOG_FILE', 'USERS_FILE'):
            setattr(api, n, self.d / self._saved[n].name)
        api.DATA_DIR = self.d
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'get_json_obj', 'get_json_body',
                      'require_admin_auth', 'audit_log', 'verify_password',
                      '_tenancy_enforced', '_caller_is_superadmin',
                      '_fire_control_plane_change', 'log_json')}
        self.cap, self.audits = {}, []

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: 'DELETE'
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.audit_log = lambda who, act, detail='', **k: self.audits.append((act, detail))
        api.verify_password = lambda *a, **k: True
        api._tenancy_enforced = lambda: False
        api._caller_is_superadmin = lambda: True
        api._fire_control_plane_change = lambda *a, **k: None
        api.log_json = lambda *a, **k: None
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in list(self._saved.items()) + list(self._fns.items()):
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, *a):
        self.cap.clear()
        try:
            return 200, fn(*a)
        except api.HTTPError:
            return self.cap.get('status'), self.cap.get('data')


class TestClearingTheAuditLogNeedsItsArchive(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.USERS_FILE, {'admin': {'password_hash': '$2b$12$' + 'x' * 53}})
        api.save(api.AUDIT_LOG_FILE,
                 {'entries': [{'ts': 1, 'actor': 'a', 'action': 'login'},
                              {'ts': 2, 'actor': 'b', 'action': 'exec'}]})
        api._LOAD_CACHE.clear()
        api.get_json_obj = api.get_json_body = lambda: {'password': 'right'}

    def test_a_healthy_clear_still_works(self):
        """The control, first — a guard that refused every clear would satisfy
        the test below and break the feature."""
        st, _d = self._call(api.handle_audit_log_clear)
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.AUDIT_LOG_FILE) or {}).get('entries'), [])
        self.assertTrue(list(self.d.glob('audit_log_prewipe_*.jsonl.gz')),
                        'no archive was written')

    def test_the_entry_names_the_archive_it_wrote(self):
        self._call(api.handle_audit_log_clear)
        acts = dict(self.audits)
        self.assertIn('clear_audit_log', acts)
        self.assertIn('audit_log_prewipe_', acts['clear_audit_log'],
                      'the entry must name the archive, not assert one exists')
        self.assertIn('2 entries', acts['clear_audit_log'])

    def test_an_archive_failure_refuses_the_wipe(self):
        """The bug. Made to fail the way it fails in the field: the archive
        cannot be written."""
        api.DATA_DIR = self.d / 'does' / 'not' / 'exist'
        st, data = self._call(api.handle_audit_log_clear)
        self.assertEqual(st, 500, 'the wipe went ahead without an archive')
        self.assertIn('NOT cleared', str(data))
        api._LOAD_CACHE.clear()
        self.assertEqual(
            len((api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []), 2,
            'the audit log was destroyed with no archive to fall back on')

    def test_the_refusal_is_itself_audited(self):
        api.DATA_DIR = self.d / 'nope'
        self._call(api.handle_audit_log_clear)
        self.assertIn('clear_audit_log_refused', dict(self.audits))


class TestTheOnlineTtlFloorCannotExceedItsCeiling(_Base):

    def setUp(self):
        super().setUp()
        api.method = lambda: 'POST'

    def _save(self, body):
        api.get_json_obj = api.get_json_body = lambda: body
        api._LOAD_CACHE.clear()
        return self._call(api.handle_config_save)

    def test_a_floor_above_the_ceiling_is_refused(self):
        st, data = self._save({'min_online_ttl': 100000})
        self.assertEqual(st, 400, 'a 27.8-hour offline threshold was accepted')
        self.assertIn('7200', str(data), 'the refusal must say the bound')

    def test_the_bound_matches_online_ttl_own_ceiling(self):
        """They are the same quantity; two different maxima is how this
        happened."""
        st, _d = self._save({'min_online_ttl': 7200})
        self.assertEqual(st, 200)
        st, _d = self._save({'online_ttl': 7200})
        self.assertEqual(st, 200)
        st, _d = self._save({'online_ttl': 7201})
        self.assertEqual(st, 400)

    def test_an_ordinary_floor_still_saves(self):
        st, _d = self._save({'min_online_ttl': 300})
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get('min_online_ttl'), 300)


class TestAPartialRestoreSaysSo(unittest.TestCase):
    """Source-level: driving a real restore needs a tarball, a snapshot and a
    backend import. What matters is that the failures are collected and change
    the answer, which is visible in the handler."""

    def test_the_extract_loop_records_what_it_could_not_write(self):
        sys.path.insert(0, str(pathlib.Path(__file__).parent))
        import srcpin
        body = srcpin.py_function(
            (_CGI / 'backups_handlers.py').read_text(), 'handle_backup_restore')
        code = '\n'.join(l for l in body.splitlines()
                         if not l.lstrip().startswith('#'))
        self.assertIn('failed.append(', code,
                      'extraction failures are swallowed again')
        self.assertNotIn('except Exception:\n            pass', code)

    def test_a_partial_restore_is_not_reported_as_ok(self):
        sys.path.insert(0, str(pathlib.Path(__file__).parent))
        import srcpin
        body = srcpin.py_function(
            (_CGI / 'backups_handlers.py').read_text(), 'handle_backup_restore')
        code = '\n'.join(l for l in body.splitlines()
                         if not l.lstrip().startswith('#'))
        self.assertIn("'ok': False", code,
                      'a restore that dropped files still answers ok:true')
        self.assertIn('expected', code,
                      'the count has no baseline to be judged against')


if __name__ == '__main__':
    unittest.main()
