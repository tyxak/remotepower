#!/usr/bin/env python3
"""Tests for the v4.2.0 "5ecur1tyM4tter5" hardening bundle (A-series)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v420h", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('AUDIT_LOG_FILE', 'USERS_FILE', 'CONFIG_FILE'):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'get_json_body', 'require_admin_auth')}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_admin_auth = lambda: 'alice'
        api.method = lambda: 'GET'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestAuditTamperEvidence(_Base):
    def test_entries_are_chained(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        api.audit_log('alice', 'login', 'ok')
        api.audit_log('bob', 'reboot', 'dev1')
        entries = api.load(api.AUDIT_LOG_FILE)['entries']
        self.assertEqual(len(entries), 2)
        self.assertTrue(all('_hash' in e for e in entries))
        self.assertEqual(entries[1]['_hash'],
                         api._audit_entry_hash(entries[0]['_hash'], entries[1]))

    def test_verify_clean(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        for i in range(3):
            api.audit_log('u', 'act', str(i))
        r = self.call(api.handle_audit_log_verify)
        self.assertTrue(r['ok'])
        self.assertIsNone(r['broken_at'])
        self.assertGreaterEqual(r['verified'], 1)

    def test_verify_detects_tamper(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        for i in range(3):
            api.audit_log('u', 'act', str(i))
        al = api.load(api.AUDIT_LOG_FILE)
        al['entries'][1]['detail'] = 'TAMPERED'   # edit content, leave _hash
        api.save(api.AUDIT_LOG_FILE, al)
        r = self.call(api.handle_audit_log_verify)
        self.assertFalse(r['ok'])
        self.assertEqual(r['broken_at'], 1)

    def test_clear_requires_password(self):
        api.save(api.USERS_FILE, {'alice': {'role': 'admin',
                                            'password_hash': api.hash_password('s3cret')}})
        api.save(api.AUDIT_LOG_FILE, {'entries': [{'ts': 1, 'actor': 'x'}]})
        api.method = lambda: 'DELETE'
        # no password → 403
        api.get_json_body = lambda: {}
        self.call(api.handle_audit_log_clear)
        self.assertEqual(self.cap['s'], 403)
        # wrong password → 403
        api.get_json_body = lambda: {'password': 'nope'}
        self.call(api.handle_audit_log_clear)
        self.assertEqual(self.cap['s'], 403)
        # correct → cleared + a pre-wipe archive exists
        api.get_json_body = lambda: {'password': 's3cret'}
        r = self.call(api.handle_audit_log_clear)
        self.assertTrue(r['ok'])
        self.assertTrue(any(p.name.startswith('audit_log_prewipe_')
                            for p in api.DATA_DIR.glob('audit_log_prewipe_*')))


if __name__ == '__main__':
    unittest.main()
