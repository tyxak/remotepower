#!/usr/bin/env python3
"""A force renew that produces no log must say so.

Reported from the field: an operator forced a renewal of gmc.tvipper.com, the
certificate WAS renewed, and the Logs tab stayed empty with no error anywhere.

The server reserves a log file at queue time so the action appears as `pending`
before the agent has even collected the command. Three separate places could
lose that and every one of them was silent:

  * the mkdir, under `except Exception: pass`
  * the reservation write, under the same
  * the whole log listing on the read side, under one more

So a filesystem problem produced a renewal that happened, a certificate that
changed, and a UI that said nothing at all — while the sibling mitigation path
has always reported the same failure. Half-applied, one file apart.

None of them should fail the ACTION: a renewal without a log beats no renewal.
They just have to be visible.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-acmelog-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_acmelog', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-acme-'))
        self._saved = {}
        for n in ('DEVICES_FILE', 'CMDS_FILE', 'ACME_STATE_FILE', 'HISTORY_FILE',
                  'AUDIT_LOG_FILE'):
            self._saved[n] = getattr(api, n)
        # The BASENAME is the storage key. Under SQLite/Postgres the backend
        # selects its table from it, so a synthesised name like
        # 'devices_file.json' is not the devices store — every heartbeat 403'd
        # on the JSON-backend-only spelling. Keep the product's own filename.
            setattr(api, n, self.d / self._saved[n].name)
        self._saved_dir = api.ACME_LOGS_DIR
        api.ACME_LOGS_DIR = self.d / 'acme_logs'
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'require_admin_auth', 'require_auth',
                      'audit_log', 'log_command', '_scope_block_device')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: 'POST'
        api.require_admin_auth = lambda *a, **k: 'alice'
        api.require_auth = lambda *a, **k: 'alice'
        self.audit = []
        api.audit_log = lambda *a, **k: self.audit.append((a, k))
        api.log_command = lambda *a, **k: None
        api._scope_block_device = lambda *a, **k: None
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {'w1': {'name': 'tviweb01.tvipper.com'}})
        api.save(api.ACME_STATE_FILE, {'w1': {'home': '/root/.acme.sh', 'certs': [
            {'domain': 'gmc.tvipper.com', 'alt_names': ['www.gmc.tvipper.com']}]}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api.ACME_LOGS_DIR = self._saved_dir
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
            return 200, self.cap.get('data')
        except api.HTTPError:
            return self.cap.get('status'), self.cap.get('data')


class TestTheHappyPathStillWorks(_Base):
    """Control. Every assertion below is about a FAILURE being reported, and a
    queue path that had stopped working entirely would satisfy those too."""

    def test_the_action_queues_and_the_log_appears_as_pending(self):
        st, data = self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        self.assertEqual(st, 200)
        self.assertTrue(data['ok'])
        self.assertNotIn('log_error', data)
        queued = (api.load(api.CMDS_FILE) or {}).get('w1') or []
        self.assertEqual(len(queued), 1)
        self.assertIn('#acme:', queued[0])
        api.method = lambda: 'GET'
        st, detail = self._call(api.handle_acme_detail, 'w1', 'gmc.tvipper.com')
        self.assertEqual(st, 200)
        self.assertEqual(len(detail['logs']), 1, detail)
        self.assertIsNone(detail['logs'][0]['rc'], 'a queued run reads as pending')
        self.assertNotIn('logs_error', detail)


class TestAReservationFailureIsReported(_Base):

    def _break_the_log_dir(self):
        """A file where the directory should be — mkdir and write both fail."""
        api.ACME_LOGS_DIR.parent.mkdir(parents=True, exist_ok=True)
        api.ACME_LOGS_DIR.write_text('not a directory')

    def test_the_renewal_still_queues(self):
        """A renewal that happens without a log beats one that does not
        happen."""
        self._break_the_log_dir()
        st, data = self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        self.assertEqual(st, 200)
        self.assertTrue(data['ok'])
        self.assertEqual(len((api.load(api.CMDS_FILE) or {}).get('w1') or []), 1,
                         'the command must still reach the queue')

    def test_but_the_response_says_the_log_is_missing(self):
        self._break_the_log_dir()
        _st, data = self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        self.assertIn('log_error', data,
                      'the operator gets a success toast promising output in a '
                      'tab that will stay empty')
        self.assertTrue(data['log_error'])

    def test_and_the_audit_entry_records_it(self):
        self._break_the_log_dir()
        self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        self.assertIn('log_error', str(self.audit[-1]))

    def test_the_page_tells_the_operator(self):
        js = (_ROOT / 'server/html/static/js/app-dns.js').read_text()
        self.assertIn('log_error', js)
        self.assertIn('logs_error', js)


class TestAnUnreadableLogDirIsReported(_Base):

    def test_the_listing_says_why_instead_of_no_logs_yet(self):
        api.ACME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        real_is_dir = Path.is_dir

        def boom(self_):
            if str(self_) == str(api.ACME_LOGS_DIR):
                raise PermissionError('permission denied')
            return real_is_dir(self_)
        api.method = lambda: 'GET'
        Path.is_dir = boom
        try:
            st, detail = self._call(api.handle_acme_detail, 'w1', 'gmc.tvipper.com')
        finally:
            Path.is_dir = real_is_dir
        self.assertEqual(st, 200, 'the cert detail must still render')
        self.assertEqual(detail['logs'], [])
        self.assertIn('logs_error', detail,
                      'an empty list renders as "No logs yet. Trigger a force '
                      'renew to capture one." — advice that cannot work')
        self.assertIn('PermissionError', detail['logs_error'])

    def test_one_unreadable_row_does_not_empty_the_list(self):
        """The per-file stat used to sit under the outer handler, so a file
        removed between the listing and its stat lost every OTHER row too."""
        self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        self._call(api.handle_acme_force_renew, 'w1', 'gmc.tvipper.com')
        junk = api.ACME_LOGS_DIR / 'w1__zzzzzzzzzzzz.log'
        junk.write_text('x')
        junk.with_suffix('.meta.json').write_text('{ this is not json')
        api.method = lambda: 'GET'
        _st, detail = self._call(api.handle_acme_detail, 'w1', 'gmc.tvipper.com')
        self.assertEqual(len(detail['logs']), 2,
                         f"the two real runs were lost with the bad row: {detail}")


if __name__ == '__main__':
    unittest.main()
