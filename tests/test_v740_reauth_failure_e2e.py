#!/usr/bin/env python3
"""7.4.0: a wrong password typed into a re-authentication prompt must not sign you out.

`api()` in app.js treats every 401 as "your session is gone" and calls doLogout(). Four prompts
that ask a signed-in person for their own password or code answered 401 when it was wrong: the
step-up dialog, turning 2FA off, making new recovery codes, and changing your password. A typo in
any of them threw the person back to the login page and showed nothing about why.

A refused credential inside a valid session is a 403, as it already was for the SSH gateway, the
web terminal, the vault and agent-release signing. This drives the real page against the real
server, because the two halves are each correct on their own: the server's 401 means "wrong
credentials" and the client's 401 handling means "no session". Only the pair is wrong.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import base64
import hashlib
import hmac
import json
import os as _os
import struct
import sys as _sys
import time
import unittest
import urllib.error
import urllib.request

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
import browser_required  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright

NEW_PASSWORD = 'Zx9!correct-horse-battery-staple'
ADMIN_PASSWORD = 'Qw7!another-long-passphrase-here'
CAROL_PASSWORD = 'Hk3!yet-another-long-passphrase'


def _totp(secret, at=None):
    """RFC 6238, SHA-1, 6 digits, 30 s: what an authenticator app shows."""
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    counter = int((at or time.time()) // 30)
    mac = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAWrongPasswordDoesNotSignYouOut(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            browser_required.skip_or_fail(f'app stack not available: {exc}')
        # A fresh install makes the admin change the default password before anything else works.
        req = urllib.request.Request(
            cls.base + '/api/login', method='POST',
            data=json.dumps({'username': 'admin', 'password': 'remotepower'}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as r:
            tok = json.loads(r.read())['token']
        req = urllib.request.Request(
            cls.base + '/api/users/passwd', method='POST',
            data=json.dumps({'old_password': 'remotepower', 'new_password': ADMIN_PASSWORD}).encode(),
            headers={'Content-Type': 'application/json', 'X-Token': tok})
        urllib.request.urlopen(req, timeout=20).read()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _call(self, method, path, body, token):
        req = urllib.request.Request(
            self.base + '/api' + path, method=method, data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json', 'X-Token': token})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def _open_app(self, user='admin', password=ADMIN_PASSWORD):
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.goto(self.base + '/index.html')
        page.fill('#login-user', user)
        page.fill('#login-pass', password)
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=15000)
        return page

    def _still_signed_in(self, page):
        return page.evaluate("""() => document.getElementById('app').style.display !== 'none'
                                      && document.getElementById('login-page').style.display !== 'flex'""")

    def _wrong_password(self, page, path, body):
        """Send the wrong password through the page's own api(), as the dialogs do."""
        res = page.evaluate(
            """async ([path, body]) => {
                const r = await api('POST', path, body);
                return {answered: r !== null, error: r && r.error};
            }""", [path, body])
        self.assertTrue(res['answered'], f'{path}: api() returned null, the signal for a 401 and a logout')
        self.assertTrue(res['error'], f'{path}: no reason came back to show the person')
        self.assertTrue(self._still_signed_in(page), f'{path}: a wrong password signed the person out')

    def test_the_step_up_dialog(self):
        self._wrong_password(self._open_app(), '/auth/step-up', {'password': 'not-the-password'})

    def test_turning_2fa_off(self):
        self._wrong_password(self._open_app(), '/totp/disable', {'password': 'not-the-password'})

    def test_changing_your_password(self):
        self._wrong_password(self._open_app(), '/users/passwd',
                             {'old_password': 'not-the-password', 'new_password': NEW_PASSWORD})

    def test_making_new_recovery_codes(self):
        """Needs 2FA on, so it has its own person: turning it on for the admin would make every
        other sign-in in this class ask for a code."""
        admin = self._open_app()
        tok = admin.evaluate('getToken()')
        st, made = self._call('POST', '/users', {'username': 'carol', 'password': NEW_PASSWORD, 'role': 'viewer'}, tok)
        self.assertIn(st, (200, 201), made)
        # an account an admin made must choose its own password before anything else works
        req = urllib.request.Request(
            self.base + '/api/login', method='POST',
            data=json.dumps({'username': 'carol', 'password': NEW_PASSWORD}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as r:
            first = json.loads(r.read())['token']
        st, changed = self._call('POST', '/users/passwd',
                                 {'old_password': NEW_PASSWORD, 'new_password': CAROL_PASSWORD}, first)
        self.assertEqual(st, 200, changed)
        carol = self._open_app('carol', CAROL_PASSWORD)
        ctok = carol.evaluate('getToken()')
        st, setup = self._call('POST', '/totp/setup', {}, ctok)
        self.assertEqual(st, 200, setup)
        st, done = self._call('POST', '/totp/confirm', {'code': _totp(setup['secret'])}, ctok)
        self.assertEqual(st, 200, done)
        self._wrong_password(carol, '/totp/recovery-codes', {'password': 'not-the-password'})

    def test_a_session_that_is_gone_still_signs_out(self):
        """Control: a real 401 (no valid session) must keep working, or the fix is a hole."""
        page = self._open_app()
        page.evaluate("sessionStorage.setItem('rp_token', 'not-a-session'); localStorage.setItem('rp_token', 'not-a-session')")
        res = page.evaluate("""async () => {
            const r = await api('GET', '/devices');
            return {answered: r !== null};
        }""")
        self.assertFalse(res['answered'])
        self.assertFalse(self._still_signed_in(page))


if __name__ == '__main__':
    unittest.main()
