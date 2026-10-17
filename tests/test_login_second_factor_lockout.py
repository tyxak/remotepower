"""Two ways the login path was weaker than documented.

1. A correct password cleared the failure counter *before* the second factor was
   checked, so a caller holding the password could guess TOTP codes for ever: each
   attempt reset the count that the next wrong code would have added to. The
   counter now clears only once the whole login has passed.

2. A name that does not exist was "verified" against a bare SHA-256 hex string,
   which `verify_password` rejects without hashing anything, while a real account
   with a wrong password cost a full bcrypt. The difference in response time told
   an attacker which user names exist. The stand-in is now a real password hash.

Each is shown red by restoring the line it replaced.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-login2f-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _login(body, ip='203.0.113.77'):
    api._begin_request()
    os.environ['REQUEST_METHOD'] = 'POST'
    os.environ['PATH_INFO'] = '/api/login'
    os.environ['REMOTE_ADDR'] = ip
    raw = json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    os.environ.pop('HTTP_X_TOKEN', None)

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        with mock.patch('time.sleep'):
            api.handle_login()
        return None, None
    except _Captured as c:
        return c.status, c.body
    finally:
        api.respond = orig


class TestLogin(unittest.TestCase):
    PASSWORD = 'correct horse battery staple 42'

    def setUp(self):
        d = tempfile.mkdtemp(prefix='rp-login2f-')
        os.environ['RP_DATA_DIR'] = d
        for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                     'RATELIMIT_FILE'):
            if hasattr(api, name):
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()
        self.secret = api._generate_totp_secret() if hasattr(api, '_generate_totp_secret') else 'JBSWY3DPEHPK3PXP'
        users = api.load(api.USERS_FILE)
        users['alice'] = {'password_hash': api.hash_password(self.PASSWORD), 'role': 'admin',
                          'created': int(time.time()), 'totp_secret': self.secret}
        api.save(api.USERS_FILE, users)

    def _wrong_code(self):
        good = set(api._totp(self.secret))
        for n in range(1000000):
            c = f'{n:06d}'
            if c not in good:
                return c

    # ── the second factor cannot be guessed past the lockout ──
    def test_a_known_password_does_not_buy_unlimited_code_guesses(self):
        code = self._wrong_code()
        statuses = []
        for i in range(api.LOGIN_FAIL_MAX + 3):
            # a fresh address each time: the per-address limiter is not what is under test
            status, body = _login({'username': 'alice', 'password': self.PASSWORD,
                                   'totp_code': code}, ip=f'203.0.113.{i + 1}')
            statuses.append(status)
        self.assertIn(429, statuses, statuses)
        # and it holds: the right code is refused while the account is locked
        status, _ = _login({'username': 'alice', 'password': self.PASSWORD,
                            'totp_code': api._totp(self.secret)[0]}, ip='203.0.113.200')
        self.assertEqual(status, 429)

    def test_a_correct_login_still_works_and_clears_the_count(self):
        code = self._wrong_code()
        for i in range(3):
            _login({'username': 'alice', 'password': self.PASSWORD, 'totp_code': code},
                   ip=f'203.0.113.{i + 1}')
        status, body = _login({'username': 'alice', 'password': self.PASSWORD,
                               'totp_code': api._totp(self.secret)[0]}, ip='203.0.113.50')
        self.assertEqual(status, 200)
        self.assertTrue(body.get('ok'), body)
        self.assertNotIn('login:alice', api.load(api.RATELIMIT_FILE) or {})

    def test_a_password_without_a_code_does_not_reset_the_count(self):
        code = self._wrong_code()
        for i in range(4):
            _login({'username': 'alice', 'password': self.PASSWORD, 'totp_code': code},
                   ip=f'203.0.113.{i + 1}')
        before = len((api.load(api.RATELIMIT_FILE) or {}).get('login:alice', {}).get('failures', []))
        status, body = _login({'username': 'alice', 'password': self.PASSWORD}, ip='203.0.113.60')
        self.assertTrue(body.get('totp_required'), body)
        after = len((api.load(api.RATELIMIT_FILE) or {}).get('login:alice', {}).get('failures', []))
        self.assertEqual(after, before)
        self.assertGreater(before, 0)

    # ── a name that does not exist costs what a real one costs ──
    def test_unknown_name_is_checked_against_a_real_hash(self):
        seen = []
        real = api.verify_password

        def spy(plain, stored):
            seen.append(stored)
            return real(plain, stored)
        with mock.patch.object(api, 'verify_password', spy):
            _login({'username': 'nobody-here', 'password': 'whatever'})
            _login({'username': 'alice', 'password': 'wrong password'}, ip='203.0.113.9')
        self.assertEqual(len(seen), 2)
        for stored in seen:
            self.assertTrue(stored.startswith(('$2', 'pbkdf2$')), stored[:12])

    def test_the_stand_in_hash_is_not_a_password_anyone_has(self):
        h = api._dummy_password_hash()
        self.assertIs(h, api._dummy_password_hash())          # made once
        self.assertFalse(api.verify_password('dummy', h))
        self.assertFalse(api.verify_password('', h))


def _post(fn, body, token, ip='203.0.113.77', method='POST'):
    api._begin_request()
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = '/api/x'
    os.environ['REMOTE_ADDR'] = ip
    raw = json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    os.environ['HTTP_X_TOKEN'] = token

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        with mock.patch('time.sleep'):
            fn()
        return None, None
    except _Captured as c:
        return c.status, c.body
    finally:
        api.respond = orig
        os.environ.pop('HTTP_X_TOKEN', None)


class TestReauthPromptsAreThrottled(unittest.TestCase):
    """The "type your password to confirm" prompts exist so that a stolen session is
    not enough. They were guessable without limit by whoever held the session."""
    PASSWORD = 'correct horse battery staple 42'

    def setUp(self):
        d = tempfile.mkdtemp(prefix='rp-reauth-')
        os.environ['RP_DATA_DIR'] = d
        for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                     'RATELIMIT_FILE'):
            if hasattr(api, name):
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()
        self.secret = api._generate_totp_secret()
        users = api.load(api.USERS_FILE)
        users['alice'] = {'password_hash': api.hash_password(self.PASSWORD), 'role': 'admin',
                          'created': int(time.time()), 'totp_secret': self.secret}
        api.save(api.USERS_FILE, users)
        api._begin_request()
        self.token = api._mint_session('alice')
        api._begin_request()

    def _wrong_code(self):
        good = set(api._totp(self.secret))
        return next(f'{n:06d}' for n in range(1000000) if f'{n:06d}' not in good)

    def test_step_up_totp_cannot_be_guessed_without_limit(self):
        code = self._wrong_code()
        seen = [_post(api.handle_step_up_verify, {'totp_code': code}, self.token)[0]
                for _ in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertEqual(seen[0], 403)
        self.assertIn(429, seen, seen)
        # and a correct code is refused while locked out, so guessing buys nothing
        st, _ = _post(api.handle_step_up_verify, {'totp_code': api._totp(self.secret)[1]}, self.token)
        self.assertEqual(st, 429)

    def test_step_up_password_cannot_be_guessed_without_limit(self):
        seen = [_post(api.handle_step_up_verify, {'password': f'guess-{i}'}, self.token)[0]
                for i in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertIn(429, seen, seen)

    def test_a_correct_answer_still_works_and_resets(self):
        for i in range(3):
            _post(api.handle_step_up_verify, {'password': f'guess-{i}'}, self.token)
        st, body = _post(api.handle_step_up_verify, {'password': self.PASSWORD}, self.token)
        self.assertEqual(st, 200, body)
        self.assertNotIn('reauth:alice', api.load(api.RATELIMIT_FILE) or {})

    def test_a_locked_prompt_does_not_lock_the_sign_in(self):
        for i in range(api.LOGIN_FAIL_MAX + 1):
            _post(api.handle_step_up_verify, {'password': f'guess-{i}'}, self.token)
        self.assertFalse(api._check_login_ratelimit('alice', 'reauth'))
        self.assertTrue(api._check_login_ratelimit('alice', 'login'))
        st, body = _login({'username': 'alice', 'password': self.PASSWORD,
                           'totp_code': api._totp(self.secret)[1]}, ip='203.0.113.88')
        self.assertTrue((body or {}).get('ok'), (st, body))

    def test_turning_off_2fa_needs_a_password_that_can_not_be_guessed_at(self):
        seen = [_post(api.handle_totp_disable, {'password': f'guess-{i}'}, self.token)[0]
                for i in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertEqual(seen[0], 403)
        self.assertIn(429, seen, seen)
        self.assertTrue(api.load(api.USERS_FILE)['alice'].get('totp_secret'))      # still on

    def test_recovery_codes_cannot_be_regenerated_by_guessing(self):
        seen = [_post(api.handle_totp_regenerate_codes, {'password': f'guess-{i}'}, self.token)[0]
                for i in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertIn(429, seen, seen)

    def test_changing_the_password_needs_an_old_one_that_can_not_be_guessed_at(self):
        body = lambda i: {'old_password': f'guess-{i}', 'new_password': 'A-new-strong-pass-phrase-9'}
        seen = [_post(api.handle_user_passwd, body(i), self.token)[0]
                for i in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertEqual(seen[0], 403)
        self.assertIn(429, seen, seen)
        self.assertTrue(api.verify_password(self.PASSWORD, api.load(api.USERS_FILE)['alice']['password_hash']))

    def test_the_right_old_password_still_changes_it(self):
        st, resp = _post(api.handle_user_passwd,
                         {'old_password': self.PASSWORD, 'new_password': 'A-new-strong-pass-phrase-9'},
                         self.token)
        self.assertEqual(st, 200, resp)
        self.assertTrue(api.verify_password('A-new-strong-pass-phrase-9',
                                            api.load(api.USERS_FILE)['alice']['password_hash']))

    def test_the_web_terminal_prompt_is_throttled(self):
        api.save(api.DEVICES_FILE, {'dev0000000000001': {'name': 'h', 'hostname': 'h'}})
        seen = [_post(api.handle_webterm_auth,
                      {'device_id': 'dev0000000000001', 'admin_password': f'guess-{i}'}, self.token)[0]
                for i in range(api.LOGIN_FAIL_MAX + 3)]
        self.assertEqual(seen[0], 403)
        self.assertIn(429, seen, seen)

    def test_nothing_typed_is_not_an_attempt(self):
        for _ in range(api.LOGIN_FAIL_MAX + 3):
            _post(api.handle_step_up_verify, {}, self.token)
        self.assertTrue(api._check_login_ratelimit('alice', 'reauth'))


if __name__ == '__main__':
    unittest.main()
