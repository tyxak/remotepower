#!/usr/bin/env python3
"""
Tests for v2.3.2 — security hardening.

  - Password hashing: the bcrypt-less fallback is now salted PBKDF2,
    not bare unsalted SHA-256. Legacy SHA-256 hashes still verify
    (backward compatibility). PBKDF2 hashes are self-describing and
    salted (two hashes of the same password differ).
  - The seeded default admin carries `must_change_password`, surfaced
    in the login response and cleared when the password is changed.
"""

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')
_spec = importlib.util.spec_from_file_location("api_v232", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestPasswordHashing(unittest.TestCase):

    def test_pbkdf2_round_trip(self):
        h = api._pbkdf2_hash('correct horse')
        self.assertTrue(h.startswith('pbkdf2$'))
        self.assertTrue(api.verify_password('correct horse', h))
        self.assertFalse(api.verify_password('wrong horse', h))

    def test_pbkdf2_is_salted(self):
        # Two hashes of the same password must differ — proves a
        # per-hash random salt (the whole point vs. bare sha256).
        h1 = api._pbkdf2_hash('samepw')
        h2 = api._pbkdf2_hash('samepw')
        self.assertNotEqual(h1, h2)
        # ...yet both verify
        self.assertTrue(api.verify_password('samepw', h1))
        self.assertTrue(api.verify_password('samepw', h2))

    def test_pbkdf2_iteration_count(self):
        # OWASP floor — don't let this silently regress
        self.assertGreaterEqual(api._PBKDF2_ITERATIONS, 600_000)
        h = api._pbkdf2_hash('x')
        self.assertEqual(h.split('$')[1], str(api._PBKDF2_ITERATIONS))

    def test_legacy_sha256_still_verifies(self):
        # Pre-2.3.2 hashes are bare hex sha256 — must still work so an
        # upgrade doesn't lock existing users out.
        legacy = hashlib.sha256(b'oldpassword').hexdigest()
        self.assertTrue(api.verify_password('oldpassword', legacy))
        self.assertFalse(api.verify_password('nope', legacy))

    def test_hash_password_no_bare_sha256(self):
        # hash_password must never emit a bare 64-hex sha256 — that was
        # the weak pre-2.3.2 fallback. Output is bcrypt ($2) or pbkdf2$.
        h = api.hash_password('whatever')
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'),
                        f'unexpected hash format: {h[:12]}')
        # specifically: not a bare hex digest
        self.assertFalse(len(h) == 64 and all(c in '0123456789abcdef' for c in h))

    def test_verify_rejects_garbage(self):
        for junk in ('', 'x', 'pbkdf2$bad', 'pbkdf2$1$2', '$2bad'):
            self.assertFalse(api.verify_password('pw', junk))

    def test_corrupt_pbkdf2_does_not_crash(self):
        # A malformed pbkdf2 string must return False, not raise
        self.assertFalse(api.verify_password('pw', 'pbkdf2$notanint$ab$cd'))


class TestDefaultUserHardening(unittest.TestCase):

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.USERS_FILE = self._tmp / 'users.json'

    def test_default_user_not_bare_sha256(self):
        # Re-seed a fresh users.json and check the hash format.
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        h = users['admin']['password_hash']
        # Must be bcrypt or pbkdf2 — never the old bare sha256 of
        # b'remotepower'
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'))
        self.assertNotEqual(h, hashlib.sha256(b'remotepower').hexdigest())
        # The documented default password still works
        self.assertTrue(api.verify_password('remotepower', h))

    def test_default_user_flagged_must_change(self):
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        self.assertTrue(users['admin'].get('must_change_password'))


class TestSecurityAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.docker_nginx = (_ROOT / 'docker/nginx-docker.conf').read_text()
        cls.bare_nginx = (_ROOT / 'server/conf/remotepower.conf').read_text()

    def test_default_pw_banner_in_js(self):
        self.assertIn('_mustChangePassword', self.js)
        self.assertIn('default-pw-banner', self.js)

    def test_nginx_configs_have_security_headers(self):
        # Both nginx configs ship the hardening headers — regression
        # guard so a future edit doesn't silently drop them.
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            self.assertIn('X-Frame-Options', conf, f'{name} missing X-Frame-Options')
            self.assertIn('Content-Security-Policy', conf, f'{name} missing CSP')
            self.assertIn('X-Content-Type-Options', conf, f'{name} missing nosniff')


if __name__ == '__main__':
    unittest.main(verbosity=2)
