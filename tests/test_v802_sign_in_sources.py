#!/usr/bin/env python3
"""8.0.2 review (threat-flow R3): where people signed in from is kept in a store of its own, not read out of the audit log.

Threat Intel never blocks or reports an address someone signed in from in the last 30 days. It read that from the audit log, which holds 500 entries whatever their age, and
Threat Intel writes lines of its own (one for each report and each block): a busy hour pushed every sign-in out of the log, and an administrator's own address was a public
address nothing protected, so a fail2ban ban of it was blocked on the host, banned at the edge and reported in public.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-signin-src-'))
sys.path.insert(0, str(CGI))

OFFICE = '185.15.56.1'


def _api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-signin-src-')
    spec = importlib.util.spec_from_file_location('api_signin_src', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSignInSources(unittest.TestCase):

    def setUp(self):
        self.api = _api()
        self.api._LOAD_CACHE.clear()

    def protected(self):
        self.api._LOAD_CACHE.clear()
        import ip_intel
        nets = self.api.ip_intel_handlers_mod._protected_networks({'never_block': []}, {})
        return ip_intel.in_any(OFFICE, nets)

    def flood(self, n=600):
        for i in range(n):
            self.api.audit_log('threat-intel', 'ip_intel_report', f'ip=203.0.113.{i % 250}', source_ip='127.0.0.1')

    def test_a_sign_in_protects_its_address_after_the_audit_log_has_rolled_over(self):
        self.api.audit_log('alice', 'login', 'ok', source_ip=OFFICE)
        self.assertTrue(self.protected(), 'control: protected right after the sign-in')
        self.flood()
        self.api._LOAD_CACHE.clear()
        entries = self.api.load(self.api.AUDIT_LOG_FILE).get('entries') or []
        self.assertFalse(any(e.get('action') == 'login' for e in entries), 'control: the sign-in is no longer among the 500 lines of the audit log')
        self.assertTrue(self.protected())

    def test_every_kind_of_sign_in_is_noted(self):
        for i, action in enumerate(('login', 'login_webauthn', 'login_saml', 'login_oidc')):
            self.api.audit_log('u', action, 'ok', source_ip=f'185.15.57.{i + 1}')
        self.api._LOAD_CACHE.clear()
        self.assertEqual(sorted(self.api.load(self.api.SIGNIN_SOURCES_FILE)), ['185.15.57.1', '185.15.57.2', '185.15.57.3', '185.15.57.4'])

    def test_the_names_agree_with_the_handler_that_reads_them(self):
        self.assertEqual(set(self.api._SIGN_IN_AUDIT_ACTIONS), set(self.api.ip_intel_handlers_mod.SIGN_IN_ACTIONS))

    def test_other_lines_note_nothing_and_an_old_entry_is_dropped(self):
        self.api.audit_log('a', 'ip_intel_report', 'x', source_ip='185.15.58.1')
        self.api._LOAD_CACHE.clear()
        self.assertFalse(self.api.backend_exists(self.api.SIGNIN_SOURCES_FILE) and self.api.load(self.api.SIGNIN_SOURCES_FILE))
        self.api.save(self.api.SIGNIN_SOURCES_FILE, {'198.51.100.9': int(time.time()) - 40 * 86400})
        self.api._LOAD_CACHE.clear()
        self.api.audit_log('bob', 'login', 'ok', source_ip='185.15.58.2')
        self.api._LOAD_CACHE.clear()
        self.assertEqual(sorted(self.api.load(self.api.SIGNIN_SOURCES_FILE)), ['185.15.58.2'], 'a source older than 30 days is not kept')

    def test_the_store_is_bounded(self):
        self.api.save(self.api.SIGNIN_SOURCES_FILE, {f'10.{i // 250}.{i % 250}.1': int(time.time()) - 100 + (i % 50) for i in range(2100)})
        self.api._LOAD_CACHE.clear()
        self.api.audit_log('bob', 'login', 'ok', source_ip='185.15.58.3')
        self.api._LOAD_CACHE.clear()
        self.assertLessEqual(len(self.api.load(self.api.SIGNIN_SOURCES_FILE)), 2000)
        self.assertIn('185.15.58.3', self.api.load(self.api.SIGNIN_SOURCES_FILE))


if __name__ == '__main__':
    unittest.main()
