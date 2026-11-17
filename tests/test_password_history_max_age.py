#!/usr/bin/env python3
"""Password history and a maximum password age: two instance-wide settings, both off until an administrator sets them.

`password_history` (0 to 24, default 0): a new password may not equal any of the user's last N passwords, the current one included. At
N=3 the user can change P1 to P2, P3 and P4, and the fourth change, back to P1, is accepted. `password_max_age_days` (0 to 3650, default
0): once a local password is older than that, the next sign-in with it has to change it before anything else (the existing "must change
password" gate), and the change clears it.

Everything runs through the real routes, with a real session: sign in, change a password, an administrator's reset, the first-login
change of an account an administrator made, and the Settings save. A failed change leaves the whole user record as it was. Only a hash
is kept (the scheme the account's own password uses), at most N-1 earlier ones and never more than 24, and no answer, no export and no
audit line carries one. Accounts that sign in through LDAP, OIDC or SAML, and API keys, have no local password to age.

bcrypt runs at its lowest cost here so that dozens of changes take seconds; one test runs the real cost.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-pwpolicy-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import wsgi  # noqa: E402  (imports api)

api = wsgi.api

PW = ['Alpha-Passw0rd!1', 'Bravo-Passw0rd!2', 'Charlie-Passw0rd!3', 'Delta-Passw0rd!4', 'Echo-Passw0rd!5', 'Foxtrot-Passw0rd!6',
      'Golf-Passw0rd!7', 'Hotel-Passw0rd!8']
ROOT_PW = 'Root-Passw0rd!x1'
DAY = 86400

_STATE = {}


def setUpModule():
    # every store of api in a directory of this module's own: the data dir may be the one the whole suite shares
    data_dir = api.DATA_DIR
    moved = {n: v for n, v in vars(api).items() if n.isupper() and isinstance(v, Path) and v.parent == data_dir}
    tmp = Path(tempfile.mkdtemp(prefix='rp-pwpolicy-run-'))
    for n, v in moved.items():
        setattr(api, n, tmp / v.name)
    api.DATA_DIR = tmp
    saved = {n: getattr(api, n) for n in ('_run_detached', '_ip_ratelimit', 'hash_password')}
    api._run_detached = lambda *a, **k: None
    api._ip_ratelimit = lambda *a, **k: True                     # twenty sign-ins a minute is for people; these are tests
    real_hash = api.hash_password
    if api._BCRYPT:
        import bcrypt
        api.hash_password = lambda plain: bcrypt.hashpw(plain.encode(), bcrypt.gensalt(4)).decode()      # the scheme as it is, at the lowest cost
    _STATE.update(tmp=tmp, moved=moved, data_dir=data_dir, saved=saved, real_hash=real_hash)


def tearDownModule():
    for n, v in _STATE['moved'].items():
        setattr(api, n, v)
    api.DATA_DIR = _STATE['data_dir']
    for n, v in _STATE['saved'].items():
        setattr(api, n, v)
    api._LOAD_CACHE.clear()
    api._RCTX.environ = None
    shutil.rmtree(_STATE['tmp'], ignore_errors=True)


def _environ(method, path, body=b'', headers=None):
    env = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': '', 'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
           'SERVER_PROTOCOL': 'HTTP/1.1', 'REMOTE_ADDR': '127.0.0.1', 'wsgi.input': io.BytesIO(body), 'wsgi.errors': io.BytesIO(),
           'wsgi.version': (1, 0), 'wsgi.url_scheme': 'http', 'wsgi.multithread': True, 'wsgi.multiprocess': False, 'wsgi.run_once': False}
    if body:
        env['CONTENT_LENGTH'] = str(len(body))
        env['CONTENT_TYPE'] = 'application/json'
    for k, v in (headers or {}).items():
        env['HTTP_' + k.upper().replace('-', '_')] = v
    return env


class _Policy(unittest.TestCase):
    """A directory of users, a config and the routes, driven the way a browser drives them."""

    def setUp(self):
        for f in (api.USERS_FILE, api.TOKENS_FILE, api.CONFIG_FILE, api.AUDIT_LOG_FILE, api.RATELIMIT_FILE, api.TENANTS_FILE,
                  api.DEVICES_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'backup': {'enabled': False}})
        api._LOAD_CACHE.clear()
        self.now = int(time.time())
        self.add_user('root', 'admin', ROOT_PW)
        self.add_user('alice', 'viewer', PW[0])
        self.add_user('bob', 'viewer', PW[0])
        self.root_token = self.sign_in('root', ROOT_PW)['token']

    # ── fixtures ────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def add_user(self, name, role, password, **extra):
        rec = {'password_hash': api.hash_password(password), 'role': role, 'created': self.now, 'password_changed_at': self.now,
               'tenant_id': 'default'}
        rec.update(extra)
        users = api.load(api.USERS_FILE) or {}
        users[name] = rec
        api.save(api.USERS_FILE, users)
        api._LOAD_CACHE.clear()

    def set_cfg(self, **kw):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update(kw)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def rec(self, name):
        api._LOAD_CACHE.clear()
        return (api.load(api.USERS_FILE) or {}).get(name) or {}

    def set_rec(self, name, **kw):
        users = api.load(api.USERS_FILE)
        for k, v in kw.items():
            if v is None:
                users[name].pop(k, None)
            else:
                users[name][k] = v
        api.save(api.USERS_FILE, users)
        api._LOAD_CACHE.clear()

    # ── the routes ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def call(self, verb, path, body=None, token=None, raw=False):
        payload = json.dumps(body).encode() if body is not None else b''
        env = _environ(verb, path, payload, {'X-Token': token} if token else None)
        cap = {}

        def start(status, headers):
            cap['status'] = int(status.split()[0])

        out = b''.join(wsgi.application(env, start))
        api._LOAD_CACHE.clear()
        if raw:
            return cap['status'], out
        try:
            return cap['status'], (json.loads(out) if out else None)
        except ValueError:
            return cap['status'], out

    def sign_in(self, name, password):
        st, d = self.call('POST', '/api/login', {'username': name, 'password': password})
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get('ok'), (name, d))
        return d

    def change(self, name, old, new, token=None):
        """The user changes their own password, signed in."""
        token = token or self.sign_in(name, old)['token']
        return self.call('POST', '/api/users/passwd', {'username': name, 'old_password': old, 'new_password': new}, token)

    def reset(self, name, new):
        """An administrator sets someone else's password."""
        return self.call('POST', '/api/users/passwd', {'username': name, 'new_password': new}, self.root_token)

    def settings(self, **kw):
        return self.call('POST', '/api/config', kw, self.root_token)

    def history(self, name):
        return self.rec(name).get('password_history')


class TestBothAreOffByDefault(_Policy):

    def test_a_fresh_instance_remembers_nothing_and_never_expires_a_password(self):
        st, cfg = self.call('GET', '/api/config', token=self.root_token)
        self.assertEqual(st, 200)
        self.assertEqual((cfg['password_history'], cfg['password_max_age_days']), (0, 0))
        for i in range(4):                                      # change forward, then back to a password it had two changes ago
            old, new = PW[i % 2], PW[(i + 1) % 2]
            st, d = self.change('alice', old, new)
            self.assertEqual(st, 200, d)
        self.assertNotIn('password_history', self.rec('alice'), 'a store that is off keeps no history')
        self.assertTrue(self.rec('alice').get('password_changed_at'))

    def test_the_same_password_again_is_accepted_when_it_is_off(self):
        st, d = self.change('alice', PW[0], PW[0])
        self.assertEqual(st, 200, d)

    def test_an_old_password_does_not_expire_when_it_is_off(self):
        self.set_rec('alice', password_changed_at=self.now - 4000 * DAY)
        d = self.sign_in('alice', PW[0])
        self.assertFalse(d['must_change_password'])
        self.assertFalse(d.get('password_expired'))
        self.assertEqual(self.rec('alice')['password_changed_at'], self.now - 4000 * DAY, 'a sign-in must not touch the date when the age is off')

    def test_an_account_without_a_date_is_not_stamped_while_the_age_is_off(self):
        """The clock starts at the first sign-in after the setting is turned on, not before."""
        self.set_rec('alice', password_changed_at=None)
        self.sign_in('alice', PW[0])
        self.assertNotIn('password_changed_at', self.rec('alice'))


class TestHistory(_Policy):

    def setUp(self):
        super().setUp()
        self.set_cfg(password_history=3)

    def test_at_three_the_fourth_change_back_to_the_first_is_accepted(self):
        for n in range(3):                                     # P1 -> P2 -> P3 -> P4
            st, d = self.change('alice', PW[n], PW[n + 1])
            self.assertEqual(st, 200, (n, d))
        st, d = self.change('alice', PW[3], PW[0])
        self.assertEqual(st, 200, d)
        self.assertTrue(api.verify_password(PW[0], self.rec('alice')['password_hash']))

    def test_a_reused_password_is_refused_within_the_last_three_the_current_one_included(self):
        self.change('alice', PW[0], PW[1])
        self.change('alice', PW[1], PW[2])                    # now P3, with P2 and P1 before it
        for reused in (PW[2], PW[1], PW[0]):
            st, d = self.change('alice', PW[2], reused)
            self.assertEqual(st, 400, (reused, d))
            self.assertIn('used', d['error'])
        self.assertTrue(api.verify_password(PW[2], self.rec('alice')['password_hash']), 'a refused change must not have changed it')

    def test_a_password_older_than_the_last_three_is_free_again(self):
        self.change('alice', PW[0], PW[1])
        self.change('alice', PW[1], PW[2])
        self.change('alice', PW[2], PW[3])                    # now P4, with P3 and P2 before it: P1 has gone
        st, d = self.change('alice', PW[3], PW[1])
        self.assertEqual(st, 400, 'P2 is still one of the last three')
        st, d = self.change('alice', PW[3], PW[0])
        self.assertEqual(st, 200, d)

    def test_depth_one_forbids_the_current_password_only(self):
        self.set_cfg(password_history=1)
        self.assertEqual(self.change('alice', PW[0], PW[0])[0], 400)
        self.assertEqual(self.change('alice', PW[0], PW[1])[0], 200)
        self.assertEqual(self.change('alice', PW[1], PW[0])[0], 200, 'at depth one only the current password counts')
        self.assertFalse(self.history('alice'), 'depth one keeps no earlier password')

    def test_what_is_kept_is_a_hash_in_the_scheme_the_account_uses_never_the_password(self):
        self.change('alice', PW[0], PW[1])
        hist = self.history('alice')
        self.assertEqual(len(hist), 1)
        self.assertTrue(hist[0].startswith('$2') or hist[0].startswith('pbkdf2$'), hist[0][:12])
        self.assertTrue(api.verify_password(PW[0], hist[0]))
        for p in PW:
            self.assertNotIn(p, json.dumps(self.rec('alice')), 'a password was stored in the clear')

    def test_the_list_is_cut_to_what_still_counts_and_never_past_twenty_four(self):
        self.set_cfg(password_history=3)
        cur = PW[0]
        for n in range(8):
            nxt = 'Rolling-Passw0rd!%d' % n
            self.assertEqual(self.change('alice', cur, nxt)[0], 200)
            cur = nxt
        self.assertEqual(len(self.history('alice')), 2, 'at depth three the current password and two earlier ones count')
        self.set_cfg(password_history=24)
        for n in range(30):
            nxt = 'Deep-Passw0rd!%d' % n
            self.assertEqual(self.change('alice', cur, nxt)[0], 200)
            cur = nxt
        self.assertEqual(len(self.history('alice')), 23, 'at the largest depth, the current password and 23 earlier ones: 24 in all')

    def test_a_list_longer_than_the_depth_counts_only_as_far_as_the_depth_reaches(self):
        """The depth was lowered by editing the settings document directly, so nothing trimmed the stored list: the check still reads
        only the last N."""
        self.set_cfg(password_history=5)
        order = [PW[0]]
        for n in range(4):
            self.assertEqual(self.change('alice', order[-1], PW[n + 1])[0], 200)
            order.append(PW[n + 1])
        self.assertEqual(len(self.history('alice')), 4)
        self.set_cfg(password_history=2)                       # a person's last two: the current password (P5) and P4
        self.assertEqual(self.change('alice', PW[4], PW[3])[0], 400, 'P4 is one of the last two')
        self.assertEqual(self.change('alice', PW[4], PW[2])[0], 200, 'P3 is the first one past the last two: stored, and not counted')

    def test_the_history_helper_holds_the_cap_whatever_the_setting_says(self):
        rec = {'password_history': ['$2b$04$' + 'x' * 53] * 40}
        api._remember_password(rec, '$2b$04$' + 'y' * 53, 99)
        self.assertLessEqual(len(rec['password_history']), 24)
        rec = {'password_history': ['a$'] * 5}
        api._remember_password(rec, '$2b$04$' + 'y' * 53, 0)
        self.assertNotIn('password_history', rec, 'off: nothing is kept, and what was kept goes')

    def test_a_placeholder_hash_is_not_put_into_the_list(self):
        self.add_user('sso', 'viewer', PW[0], password_hash='!' + 'a' * 64)
        rec = self.rec('sso')
        api._remember_password(rec, rec['password_hash'], 3)
        self.assertNotIn('password_history', rec)


class TestAFailedChangeWritesNothing(_Policy):

    def setUp(self):
        super().setUp()
        self.set_cfg(password_history=3, password_min_length=12)
        self.change('alice', PW[0], PW[1])                    # one real change, so there is a history to leave alone

    def snapshot(self):
        return json.dumps(self.rec('alice'), sort_keys=True)

    def test_every_way_a_change_can_fail_leaves_the_whole_record_as_it_was(self):
        token = self.sign_in('alice', PW[1])['token']
        before = self.snapshot()
        for label, body in (('reused', {'old_password': PW[1], 'new_password': PW[0]}),
                            ('the current one', {'old_password': PW[1], 'new_password': PW[1]}),
                            ('too short', {'old_password': PW[1], 'new_password': 'Sh0rt!'}),
                            ('wrong old password', {'old_password': 'not-the-password', 'new_password': PW[3]}),
                            ('no new password', {'old_password': PW[1], 'new_password': ''}),
                            ('not text', {'old_password': PW[1], 'new_password': 12345})):
            with self.subTest(label):
                st, d = self.call('POST', '/api/users/passwd', dict(body, username='alice'), token)
                self.assertIn(st, (400, 403), (label, st, d))
                self.assertEqual(self.snapshot(), before, 'a refused change touched the record: ' + label)

    def test_a_failed_reset_by_an_administrator_leaves_it_too(self):
        before = self.snapshot()
        for new in (PW[1], PW[0], 'Sh0rt!'):
            st, d = self.reset('alice', new)
            self.assertEqual(st, 400, (new, d))
        self.assertEqual(self.snapshot(), before)


class TestAnAdministratorsResetAndTheFirstLoginChange(_Policy):

    def setUp(self):
        super().setUp()
        self.set_cfg(password_history=3)

    def test_a_reset_writes_the_old_password_into_the_history_and_flags_the_account(self):
        st, d = self.reset('alice', PW[2])
        self.assertEqual(st, 200, d)
        rec = self.rec('alice')
        self.assertTrue(rec['must_change_password'])
        self.assertEqual(len(rec['password_history']), 1)
        self.assertTrue(api.verify_password(PW[0], rec['password_history'][0]))
        # the user cannot go back to what they had before the reset, or keep the one the administrator chose
        token = self.sign_in('alice', PW[2])['token']
        self.assertEqual(self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': PW[2], 'new_password': PW[0]}, token)[0], 400)
        self.assertEqual(self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': PW[2], 'new_password': PW[2]}, token)[0], 400)
        self.assertEqual(self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': PW[2], 'new_password': PW[3]}, token)[0], 200)
        self.assertFalse(self.rec('alice').get('must_change_password'))

    def test_a_reset_to_a_recent_password_is_refused(self):
        self.change('alice', PW[0], PW[1])
        st, d = self.reset('alice', PW[0])
        self.assertEqual(st, 400, d)
        self.assertEqual(self.reset('alice', PW[4])[0], 200)

    def test_the_first_login_change_of_an_account_an_administrator_made_writes_history(self):
        st, d = self.call('POST', '/api/users', {'username': 'carol', 'password': PW[5], 'role': 'viewer'}, self.root_token)
        self.assertEqual(st, 201, d)
        self.assertNotIn('password_history', self.rec('carol'), 'a new account has no earlier password')
        d = self.sign_in('carol', PW[5])
        self.assertTrue(d['must_change_password'])
        st, body = self.call('GET', '/api/devices', token=d['token'])
        self.assertEqual(st, 403, 'the gate holds until the password is changed')
        self.assertTrue((body or {}).get('must_change_password'))
        st, body = self.call('POST', '/api/users/passwd', {'username': 'carol', 'old_password': PW[5], 'new_password': PW[6]}, d['token'])
        self.assertEqual(st, 200, body)
        rec = self.rec('carol')
        self.assertFalse(rec.get('must_change_password'))
        self.assertEqual(len(rec['password_history']), 1)
        self.assertTrue(api.verify_password(PW[5], rec['password_history'][0]))
        self.assertEqual(self.change('carol', PW[6], PW[5])[0], 400, 'the password the administrator chose cannot come back')

    def test_the_seeded_default_admin_changes_through_the_same_path(self):
        self.add_user('admin', 'admin', 'remotepower', must_change_password=True)
        d = self.sign_in('admin', 'remotepower')
        self.assertTrue(d['must_change_password'])
        st, body = self.call('POST', '/api/users/passwd', {'username': 'admin', 'old_password': 'remotepower', 'new_password': PW[7]}, d['token'])
        self.assertEqual(st, 200, body)
        self.assertEqual(len(self.history('admin')), 1)


class TestARaceBetweenTheCheckAndTheWrite(_Policy):

    def test_a_password_changed_while_the_slow_check_ran_is_not_written_over(self):
        """The check hashes against several old passwords outside the lock; if the account changed in the meantime the write refuses."""
        self.set_cfg(password_history=3)
        token = self.sign_in('alice', PW[0])['token']
        real = api.hash_password

        def meanwhile(plain):
            # another request lands between the check and the write
            users = api.load(api.USERS_FILE)
            users['alice']['password_hash'] = real(PW[5])
            api.save(api.USERS_FILE, users)
            return real(plain)

        api.hash_password = meanwhile
        try:
            st, d = self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': PW[0], 'new_password': PW[1]}, token)
        finally:
            api.hash_password = real
        self.assertEqual(st, 409, d)
        self.assertTrue(api.verify_password(PW[5], self.rec('alice')['password_hash']), 'the other change was overwritten')
        self.assertNotIn('password_history', self.rec('alice'))


class TestMaxAge(_Policy):

    def setUp(self):
        super().setUp()
        self.set_cfg(password_max_age_days=30)

    def test_a_password_older_than_the_limit_has_to_be_changed_at_sign_in_and_the_change_clears_it(self):
        self.set_rec('alice', password_changed_at=self.now - 31 * DAY)
        d = self.sign_in('alice', PW[0])
        self.assertTrue(d['must_change_password'])
        self.assertTrue(d['password_expired'])
        self.assertTrue(self.rec('alice')['must_change_password'])
        # nothing else works: the existing gate
        for path in ('/api/devices', '/api/me'):
            st, body = self.call('GET', path, token=d['token'])
            self.assertEqual(st, 403, path)
            self.assertTrue(body.get('must_change_password'), path)
            self.assertTrue(body.get('password_expired'), 'the page says why: ' + path)
        st, body = self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': PW[0], 'new_password': PW[1]}, d['token'])
        self.assertEqual(st, 200, body)
        rec = self.rec('alice')
        self.assertFalse(rec.get('must_change_password'))
        self.assertFalse(rec.get('password_expired'))
        self.assertGreaterEqual(rec['password_changed_at'], self.now)
        d2 = self.sign_in('alice', PW[1])
        self.assertFalse(d2['must_change_password'])
        self.assertEqual(self.call('GET', '/api/devices', token=d2['token'])[0], 200)

    def test_a_password_younger_than_the_limit_is_left_alone(self):
        self.set_rec('alice', password_changed_at=self.now - 29 * DAY)
        d = self.sign_in('alice', PW[0])
        self.assertFalse(d['must_change_password'])
        self.assertFalse(d.get('password_expired'))
        self.assertEqual(self.rec('alice')['password_changed_at'], self.now - 29 * DAY)

    def test_the_edge_is_the_day_count_a_minute_either_side_of_it(self):
        for age, expired in ((30 * DAY - 60, False), (30 * DAY + 60, True)):
            self.set_rec('alice', password_changed_at=int(time.time()) - age, must_change_password=None, password_expired=None)
            self.assertEqual(self.sign_in('alice', PW[0])['must_change_password'], expired, age)

    def test_an_account_without_a_date_starts_its_clock_at_its_own_first_sign_in_and_no_other_account_is_touched(self):
        self.set_rec('alice', password_changed_at=None)
        self.set_rec('bob', password_changed_at=None)
        d = self.sign_in('alice', PW[0])
        self.assertFalse(d['must_change_password'], 'an account with no date is not expired by that')
        stamped = self.rec('alice')['password_changed_at']
        self.assertTrue(abs(stamped - int(time.time())) < 30)
        self.assertNotIn('password_changed_at', self.rec('bob'), 'one sign-in started everybody\'s clock')
        # and the clock it started runs: a year on, it has expired
        self.set_rec('alice', password_changed_at=stamped - 400 * DAY)
        self.assertTrue(self.sign_in('alice', PW[0])['must_change_password'])

    def test_an_admin_reset_account_that_is_expired_keeps_one_reason_not_two(self):
        self.set_rec('alice', password_changed_at=self.now - 90 * DAY, must_change_password=True)
        d = self.sign_in('alice', PW[0])
        self.assertTrue(d['must_change_password'])
        self.assertFalse(d.get('password_expired'), 'the account was already flagged for another reason; the page keeps that reason')

    def test_a_password_changed_by_an_administrator_starts_a_new_clock(self):
        self.set_rec('alice', password_changed_at=self.now - 90 * DAY)
        self.assertEqual(self.reset('alice', PW[1])[0], 200)
        self.assertGreaterEqual(self.rec('alice')['password_changed_at'], self.now)
        self.assertFalse(self.rec('alice').get('password_expired'))

    def test_the_gate_lets_the_account_reach_the_change_and_the_sign_out_and_nothing_else(self):
        self.set_rec('alice', password_changed_at=self.now - 99 * DAY)
        token = self.sign_in('alice', PW[0])['token']
        self.assertEqual(self.call('GET', '/api/public-info')[0], 200)
        st, _b = self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': 'wrong', 'new_password': PW[2]}, token)
        self.assertEqual(st, 403)                              # reaches the handler (refused for the old password), not the gate
        self.assertEqual(self.call('GET', '/api/users', token=token)[0], 403)

    def test_expiry_is_written_to_the_audit_log_without_a_secret(self):
        self.set_rec('alice', password_changed_at=self.now - 90 * DAY)
        self.sign_in('alice', PW[0])
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []
        mine = [e for e in entries if e.get('action') == 'password_expired' or 'password_expired' in json.dumps(e)]
        self.assertTrue(mine, 'no audit line says the password expired')
        self.assertNotIn(self.rec('alice')['password_hash'], json.dumps(entries))


class TestWhoIsNotAffected(_Policy):

    def setUp(self):
        super().setUp()
        self.set_cfg(password_max_age_days=1, password_history=5)

    def test_an_ldap_sign_in_is_not_aged_and_the_account_is_not_flagged(self):
        self.add_user('lena', 'viewer', 'unused', password_hash='!' + 'b' * 64, password_changed_at=self.now - 500 * DAY, ldap_dn='cn=lena')
        self.set_cfg(ldap_enabled=True)

        class Info:
            dn, full_name, email, role, groups = 'cn=lena', 'Lena', '', 'viewer', []

        real = api.ldap_auth.authenticate
        api.ldap_auth.authenticate = lambda cfg, u, p: Info()
        try:
            d = self.sign_in('lena', 'directory-password')
        finally:
            api.ldap_auth.authenticate = real
        self.assertFalse(d['must_change_password'])
        self.assertFalse(d.get('password_expired'))
        self.assertFalse(self.rec('lena').get('must_change_password'))

    def test_an_account_with_no_local_password_cannot_sign_in_with_one_and_is_never_flagged(self):
        self.add_user('oidc', 'viewer', 'unused', password_hash='!' + 'c' * 64, password_changed_at=self.now - 500 * DAY, oidc_subject='sub-1')
        st, d = self.call('POST', '/api/login', {'username': 'oidc', 'password': '!' + 'c' * 64})
        self.assertFalse(d.get('ok'))
        self.assertFalse(self.rec('oidc').get('must_change_password'))

    def test_an_api_key_is_not_gated_by_the_account_it_names(self):
        """A key has no password and is not a session: the gate that follows a flagged account applies to sessions only."""
        st, d = self.call('POST', '/api/apikeys', {'name': 'ci', 'role': 'viewer', 'user': 'alice'}, self.root_token)
        self.assertEqual(st, 201, d)
        key = d['key']
        self.set_rec('alice', password_changed_at=self.now - 500 * DAY)
        session = self.sign_in('alice', PW[0])['token']
        self.assertTrue(self.rec('alice')['must_change_password'], 'control: the account is flagged')
        self.assertEqual(self.call('GET', '/api/devices', token=session)[0], 403, 'control: its session is gated')
        self.assertEqual(self.call('GET', '/api/devices', token=key)[0], 200)

    def test_a_viewer_session_made_before_the_limit_is_not_cut_off_by_it(self):
        """The age is checked when a local password is used to sign in, not on every request."""
        self.set_cfg(password_max_age_days=0)
        token = self.sign_in('alice', PW[0])['token']
        self.set_cfg(password_max_age_days=1)
        self.set_rec('alice', password_changed_at=self.now - 50 * DAY)
        self.assertEqual(self.call('GET', '/api/devices', token=token)[0], 200)


class TestAResetByATenantAdministratorWritesHistory(_Policy):
    """A tenant administrator resets an account of its own tenant, and the history is written the same way. (Which accounts it may reset
    is held in test_tenant_password_reset_and_export.)"""

    def setUp(self):
        super().setUp()
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True},
                                    'tenantB': {'name': 'B', 'status': 'active'}})
        self.add_user('tadmin', 'admin', PW[2], tenant_id='tenantB')
        self.add_user('tuser', 'viewer', PW[3], tenant_id='tenantB')
        self.set_cfg(tenancy_enforced=True, password_history=3)
        self.tadmin = self.sign_in('tadmin', PW[2])['token']

    def test_the_history_is_written_and_a_repeat_of_the_old_password_is_refused(self):
        st, d = self.call('POST', '/api/users/passwd', {'username': 'tuser', 'new_password': PW[5]}, self.tadmin)
        self.assertEqual(st, 200, d)
        self.assertTrue(api.verify_password(PW[5], self.rec('tuser')['password_hash']))
        self.assertEqual(len(self.history('tuser')), 1)
        self.assertTrue(api.verify_password(PW[3], self.history('tuser')[0]))
        st, d = self.call('POST', '/api/users/passwd', {'username': 'tuser', 'new_password': PW[3]}, self.tadmin)
        self.assertEqual(st, 400, 'the password the account had before the reset was chosen again')


class TestAPasskeySignInOfAnAccountThatIsFlagged(_Policy):
    """A passkey is not a local password, so the maximum age does not look at a passkey sign-in. An account that a password sign-in has
    already flagged stays gated, though, and the page says why it is: "expired" for an expiry, the default-password words for the rest."""

    def passkey_sign_in(self, name):
        class WA:
            @staticmethod
            def authentication_verify(cred, challenge, origin, rp_id, public_key, sign_count):
                return {'new_sign_count': sign_count + 1}

        names = ('_webauthn_guard', '_webauthn_take_challenge', '_webauthn_rp')
        real = {n: getattr(api, n) for n in names}
        api._webauthn_guard = lambda: WA
        api._webauthn_take_challenge = lambda user, kind: b'challenge'
        api._webauthn_rp = lambda: ('localhost', 'http://localhost')
        try:
            return self.call('POST', '/api/webauthn/login/complete', {'username': name, 'credential': {'id': 'cred-1'}})
        finally:
            for n, f in real.items():
                setattr(api, n, f)

    def give_a_passkey(self, name):
        self.set_rec(name, webauthn_credentials=[{'id': 'cred-1', 'public_key': 'k', 'sign_count': 0}])

    def test_an_account_flagged_by_the_age_is_told_the_password_expired(self):
        self.set_cfg(password_max_age_days=30)
        self.set_rec('alice', password_changed_at=self.now - 45 * DAY)
        self.sign_in('alice', PW[0])                           # the password sign-in is what flags it
        self.give_a_passkey('alice')
        st, d = self.passkey_sign_in('alice')
        self.assertEqual(st, 200, d)
        self.assertTrue(d['ok'])
        self.assertTrue(d['must_change_password'])
        self.assertTrue(d['password_expired'])

    def test_a_passkey_sign_in_does_not_age_anything(self):
        self.set_cfg(password_max_age_days=30)
        self.set_rec('alice', password_changed_at=self.now - 400 * DAY)
        self.give_a_passkey('alice')
        st, d = self.passkey_sign_in('alice')
        self.assertEqual(st, 200, d)
        self.assertEqual((d['must_change_password'], d['password_expired']), (False, False))
        self.assertFalse(self.rec('alice').get('must_change_password'))

    def test_an_account_flagged_by_a_reset_is_told_what_it_always_was(self):
        self.assertEqual(self.reset('alice', PW[3])[0], 200)
        self.give_a_passkey('alice')
        st, d = self.passkey_sign_in('alice')
        self.assertEqual(st, 200, d)
        self.assertEqual((d['must_change_password'], d['password_expired']), (True, False))


class TestOnlyAPasswordSignInIsAged(unittest.TestCase):
    """The sign-ins that never meet a local password (OIDC, SAML, a passkey, an LDAP bind) are not aged because the age is checked in one
    place only: the handler that has just accepted a local password. A new sign-in route that called it would be a new reader."""

    def test_the_age_gate_is_called_from_the_password_sign_in_and_nowhere_else(self):
        import ast
        callers = []
        for f in sorted((_ROOT / 'server' / 'cgi-bin').glob('*.py')):
            tree = ast.parse(f.read_text())
            for fn in ast.walk(tree):
                if isinstance(fn, ast.FunctionDef):
                    for node in ast.walk(fn):
                        if isinstance(node, ast.Call):
                            name = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
                            if name == '_password_age_gate':
                                callers.append((f.name, fn.name))
        self.assertEqual(callers, [('api.py', 'handle_login')], 'the maximum age is applied outside the local password sign-in')

    def test_in_that_handler_it_sits_inside_the_branch_that_only_a_local_password_reaches(self):
        import ast
        tree = ast.parse((_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text())
        login = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'handle_login')
        inside = []
        for node in ast.walk(login):
            if isinstance(node, ast.If) and ast.unparse(node.test) == 'ldap_user_info is None':
                for stmt in node.body:
                    inside += [c for c in ast.walk(stmt) if isinstance(c, ast.Call) and getattr(c.func, 'id', '') == '_password_age_gate']
        self.assertEqual(len(inside), 1, 'the call is not inside the branch that a bind through LDAP skips')


class TestSettings(_Policy):

    def test_an_administrator_sets_both_and_reads_them_back_and_it_is_audited_by_key_name(self):
        st, d = self.settings(password_history=7, password_max_age_days=90)
        self.assertEqual(st, 200, d)
        st, cfg = self.call('GET', '/api/config', token=self.root_token)
        self.assertEqual((cfg['password_history'], cfg['password_max_age_days']), (7, 90))
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []
        lines = [e for e in entries if 'password_history' in json.dumps(e)]
        self.assertTrue(lines, 'the change is not on the audit trail')
        self.assertIn('password_max_age_days', json.dumps(lines))

    def test_the_whole_range_is_accepted_and_zero_turns_each_off(self):
        for key, top in (('password_history', 24), ('password_max_age_days', 3650)):
            for v in (0, 1, top):
                with self.subTest(key=key, v=v):
                    self.assertEqual(self.settings(**{key: v})[0], 200)
                    self.assertEqual((api.load(api.CONFIG_FILE) or {}).get(key, 0), v)

    def test_a_value_outside_the_range_or_of_the_wrong_kind_is_a_400_and_changes_nothing(self):
        self.settings(password_history=4, password_max_age_days=60)
        for key in ('password_history', 'password_max_age_days'):
            for bad in (-1, 25 if key == 'password_history' else 3651, 10 ** 9, 'x', '5', 2.5, True, [3], {'n': 3}):
                with self.subTest(key=key, bad=repr(bad)[:20]):
                    st, d = self.settings(**{key: bad})
                    self.assertEqual(st, 400, (key, bad, d))
                    self.assertEqual((d['field'], d['min'], d['max']), (key, 0, 24 if key == 'password_history' else 3650))
                    cfg = api.load(api.CONFIG_FILE)
                    self.assertEqual((cfg['password_history'], cfg['password_max_age_days']), (4, 60))

    def test_an_out_of_range_value_in_a_save_with_other_keys_saves_none_of_them(self):
        st, d = self.settings(password_history=99, password_min_length=14)
        self.assertEqual(st, 400)
        self.assertNotIn('password_min_length', api.load(api.CONFIG_FILE))

    def test_blank_turns_it_off(self):
        self.settings(password_history=4, password_max_age_days=60)
        self.assertEqual(self.settings(password_history=None, password_max_age_days='')[0], 200)
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual((cfg.get('password_history', 0), cfg.get('password_max_age_days', 0)), (0, 0))

    def test_a_value_written_into_the_document_by_hand_is_read_inside_the_range(self):
        """The save refuses a number outside the range, but the settings document can be edited on disk or restored from an older file."""
        for raw, depth, days in ((10 ** 9, 24, 3650), (-5, 0, 0), ('x', 0, 0), (None, 0, 0), (7, 7, 7)):
            with self.subTest(raw=repr(raw)):
                self.set_cfg(password_history=raw, password_max_age_days=raw)
                self.assertEqual((api._password_history_depth(), api._config_count('password_max_age_days', api.PASSWORD_MAX_AGE_DAYS_MAX)),
                                 (depth, days))

    def test_a_tenant_administrator_cannot_change_either_and_neither_can_a_viewer(self):
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True},
                                    'tenantB': {'name': 'B', 'status': 'active'}})
        self.add_user('tadmin', 'admin', PW[2], tenant_id='tenantB')
        self.set_cfg(tenancy_enforced=True)
        token = self.sign_in('tadmin', PW[2])['token']
        for body in ({'password_history': 3}, {'password_max_age_days': 30}, {'password_history': 0}):
            st, d = self.call('POST', '/api/config', body, token)
            self.assertEqual(st, 403, (body, d))
            self.assertIn('platform operator', d['error'])
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual((cfg.get('password_history', 0), cfg.get('password_max_age_days', 0)), (0, 0))
        viewer = self.sign_in('alice', PW[0])['token']
        self.assertEqual(self.call('POST', '/api/config', {'password_history': 3}, viewer)[0], 403)
        # the platform operator still can
        self.assertEqual(self.settings(password_history=3)[0], 200)

    def test_lowering_the_depth_cuts_what_is_stored_and_turning_it_off_deletes_it(self):
        self.settings(password_history=5)
        cur = PW[0]
        for n in range(5):
            nxt = 'Stored-Passw0rd!%d' % n
            self.assertEqual(self.change('alice', cur, nxt)[0], 200)
            cur = nxt
        self.assertEqual(len(self.history('alice')), 4)
        self.settings(password_history=2)
        self.assertEqual(len(self.history('alice')), 1, 'depth two keeps one earlier password')
        self.settings(password_history=0)
        self.assertNotIn('password_history', self.rec('alice'), 'off deletes the stored hashes')
        self.assertNotIn('password_history', self.rec('bob'))

    def test_restoring_an_older_revision_of_the_settings_trims_the_history_the_same_way(self):
        """A revision is the settings as they were before a save. Restoring one that remembers fewer passwords (here none) deletes what no
        longer counts, as the save of the setting does."""
        self.assertEqual(self.settings(password_history=5)[0], 200)             # the revision of the settings with the history off
        cur = PW[0]
        for n in range(4):
            nxt = 'Revision-Passw0rd!%d' % n
            self.assertEqual(self.change('alice', cur, nxt)[0], 200)
            cur = nxt
        self.assertEqual(len(self.history('alice')), 4, 'control: at five, the history keeps the four earlier passwords')
        st, d = self.call('GET', '/api/config/revisions', token=self.root_token)
        self.assertEqual(st, 200, d)
        rid = d['revisions'][0]['id']
        st, d = self.call('POST', '/api/config/revisions/restore', {'id': rid}, self.root_token)
        self.assertEqual(st, 200, d)
        self.assertEqual(self.call('GET', '/api/config', token=self.root_token)[1]['password_history'], 0, 'control: the revision was restored')
        self.assertNotIn('password_history', self.rec('alice'), 'the history outlived the setting that kept it')
        self.assertNotIn('password_history', self.rec('bob'))

    def test_restoring_a_revision_that_remembers_as_many_or_more_keeps_what_is_stored(self):
        self.assertEqual(self.settings(password_history=2)[0], 200)
        self.assertEqual(self.change('alice', PW[0], PW[1])[0], 200)
        self.assertEqual(self.settings(password_history=5)[0], 200)
        before = self.history('alice')
        self.assertEqual(len(before), 1)
        st, d = self.call('GET', '/api/config/revisions', token=self.root_token)
        rid = d['revisions'][0]['id']                                             # the settings as they were before the second save: history 2
        self.assertEqual(self.call('POST', '/api/config/revisions/restore', {'id': rid}, self.root_token)[0], 200)
        self.assertEqual(self.call('GET', '/api/config', token=self.root_token)[1]['password_history'], 2)
        self.assertEqual(self.history('alice'), before, 'a depth that is still 2 or more keeps the one earlier password it needs')

    def test_raising_the_depth_does_not_touch_what_is_stored(self):
        self.settings(password_history=2)
        self.change('alice', PW[0], PW[1])
        before = self.history('alice')
        self.settings(password_history=9)
        self.assertEqual(self.history('alice'), before)


class TestTheHistoryStaysPrivate(_Policy):

    def test_no_answer_export_or_audit_line_carries_a_stored_hash_or_the_field(self):
        self.settings(password_history=5)
        cur = PW[0]
        for n in range(4):
            nxt = 'Private-Passw0rd!%d' % n
            self.assertEqual(self.change('alice', cur, nxt)[0], 200)
            cur = nxt
        self.assertEqual(self.reset('bob', PW[3])[0], 200)
        hashes = list(self.history('alice')) + list(self.history('bob'))
        self.assertGreaterEqual(len(hashes), 4)
        alice = self.sign_in('alice', cur)['token']
        answers = {}
        for what, path, token in (('users list', '/api/users', self.root_token), ('config', '/api/config', self.root_token),
                                  ('me (alice)', '/api/me', alice), ('audit log', '/api/audit-log', self.root_token),
                                  ('sessions', '/api/sessions', self.root_token), ('my sessions', '/api/me/sessions', alice),
                                  ('tenants', '/api/tenants', self.root_token), ('security posture', '/api/security-posture', self.root_token),
                                  ('home', '/api/home', self.root_token)):
            st, body = self.call('GET', path, token=token, raw=True)
            self.assertEqual(st, 200, 'control: %s answered %s, so it measures nothing' % (what, st))
            self.assertTrue(body, 'control: %s answered with nothing' % what)
            answers[what] = body
        st, blob = self.call('GET', '/api/export', token=self.root_token, raw=True)
        self.assertEqual(st, 200)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                answers['export/' + name] = zf.read(name)
            exported_users = json.loads(zf.read('users.json'))
        for what, body in answers.items():
            text = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)
            # the settings answer has a key of the same name (the number of passwords remembered); an account's list of hashes is a list
            self.assertIsNone(re.search(r'"password_history"\s*:\s*\[', text), what)
            for h in hashes:
                self.assertNotIn(h, text, 'a stored hash is in: ' + what)
        self.assertTrue(all('password_history' not in rec for rec in exported_users.values()), 'an account in the export carries the field')
        self.assertEqual(exported_users['alice']['role'], 'viewer', 'control: the accounts are in the export')

    def test_no_log_line_carries_one(self):
        import contextlib
        self.settings(password_history=5)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.change('alice', PW[0], PW[1])
            self.change('alice', PW[1], PW[0])                # refused
            self.reset('bob', PW[2])
        for h in (self.history('alice') or []) + (self.history('bob') or []):
            self.assertNotIn(h, err.getvalue())


class TestTheSecurityPostureRow(_Policy):
    """The Security posture row "Password policy enforced" says what is set. With the passwords remembered or the maximum age on and no
    minimum length, it used to read "off" above rules that were on."""

    def row(self):
        st, d = self.call('GET', '/api/security-posture', token=self.root_token)
        self.assertEqual(st, 200, d)
        return next(r for r in d['checks'] if r['key'] == 'password_policy')

    def test_nothing_set_reads_off_as_before(self):
        r = self.row()
        self.assertEqual((r['status'], r['detail']), ('warn', 'off'))

    def test_a_minimum_length_reads_as_before(self):
        self.set_cfg(password_min_length=12, password_require_classes=True, password_breach_check=True)
        r = self.row()
        self.assertEqual((r['status'], r['detail']), ('ok', 'min length 12, classes, breach-check'))

    def test_the_two_new_rules_are_named_when_they_are_on(self):
        self.set_cfg(password_history=5)
        r = self.row()
        self.assertEqual((r['status'], r['detail']), ('warn', 'no minimum length, remembers 5'))
        self.set_cfg(password_max_age_days=90)
        self.assertEqual(self.row()['detail'], 'no minimum length, remembers 5, expires after 90d')
        self.set_cfg(password_history=0)
        self.assertEqual(self.row()['detail'], 'no minimum length, expires after 90d')
        self.set_cfg(password_min_length=12, password_history=5)
        r = self.row()
        self.assertEqual((r['status'], r['detail']), ('ok', 'min length 12, remembers 5, expires after 90d'))


class TestTheAuditTrail(_Policy):
    """A password change, an administrator's reset (the step that takes an account over) and a change refused for a repeat are on the audit
    log with whose password and who asked, and never the password or a hash. A reset used to leave no line at all."""

    def test_a_change_a_reset_and_a_refusal_each_leave_one_line_without_a_secret(self):
        self.set_cfg(password_history=3)
        self.assertEqual(self.change('alice', PW[0], PW[1])[0], 200)
        self.assertEqual(self.reset('bob', PW[2])[0], 200)
        self.assertEqual(self.change('alice', PW[1], PW[0])[0], 400)
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []
        got = [(e.get('actor'), e.get('action'), e.get('detail')) for e in entries if str(e.get('action')).startswith('password_')]
        self.assertEqual(got, [('alice', 'password_change', 'username=alice'), ('root', 'password_reset', 'username=bob'),
                               ('alice', 'password_change_refused', 'username=alice reason=used_recently')])
        text = json.dumps(entries)
        secrets_ = PW[:3] + [self.rec('alice')['password_hash'], self.rec('bob')['password_hash']] + (self.history('alice') or []) + (self.history('bob') or [])
        self.assertGreaterEqual(len(secrets_), 6)
        for s in secrets_:
            self.assertNotIn(s, text, 'a password or a hash is on the audit log')

    def test_a_change_that_fails_for_the_old_password_or_the_rules_leaves_none(self):
        self.set_cfg(password_history=3, password_min_length=12)
        self.assertEqual(self.change('alice', 'not-the-password', PW[1], token=self.sign_in('alice', PW[0])['token'])[0], 403)
        self.assertEqual(self.change('alice', PW[0], 'Sh0rt!')[0], 400)
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []
        self.assertEqual([e for e in entries if str(e.get('action')).startswith('password_')], [])


class TestTheCostOfTheComparison(_Policy):
    """Checking a new password against the history costs one password check for each password kept: at the largest setting, 24 bcrypt
    checks, several seconds of one worker. Only a caller who knows the account's current password gets that far, and a caller can ask ten
    times a minute, so nobody can tie up the workers with it. With the history off there is no comparison and no limit."""

    def setUp(self):
        super().setUp()
        self.real_limit = _STATE['saved']['_ip_ratelimit']
        api.save(api.RATELIMIT_FILE, {})

    def tearDown(self):
        api._ip_ratelimit = lambda *a, **k: True               # the module's own stand-in for the sign-in limiter, as setUpModule left it
        api.save(api.RATELIMIT_FILE, {})

    def passwd(self, token, name, old, new):
        return self.call('POST', '/api/users/passwd', {'username': name, 'old_password': old, 'new_password': new}, token)

    def test_the_eleventh_comparison_in_a_minute_is_refused_before_any_old_password_is_checked(self):
        self.set_cfg(password_history=24)
        token = self.sign_in('alice', PW[0])['token']
        before = json.dumps(self.rec('alice'), sort_keys=True)
        api._ip_ratelimit = self.real_limit
        for n in range(api.PASSWORD_HISTORY_CHECKS_PER_MINUTE):
            st, d = self.passwd(token, 'alice', PW[0], PW[0])
            self.assertEqual(st, 400, (n, d))                  # refused as a repeat: the comparison ran
        checks = []
        real_verify = api.verify_password
        api.verify_password = lambda plain, stored: (checks.append(1), real_verify(plain, stored))[1]
        try:
            st, d = self.passwd(token, 'alice', PW[0], PW[0])
        finally:
            api.verify_password = real_verify
        self.assertEqual(st, 429, d)
        self.assertEqual(len(checks), 1, 'the refusal cost more than the check of the old password: %d checks' % len(checks))
        self.assertEqual(json.dumps(self.rec('alice'), sort_keys=True), before, 'a refused change touched the record')

    def test_the_limit_is_the_caller_s_own(self):
        self.set_cfg(password_history=5)
        alice = self.sign_in('alice', PW[0])['token']
        bob = self.sign_in('bob', PW[0])['token']
        api._ip_ratelimit = self.real_limit
        for _ in range(api.PASSWORD_HISTORY_CHECKS_PER_MINUTE):
            self.assertEqual(self.passwd(alice, 'alice', PW[0], PW[0])[0], 400)
        self.assertEqual(self.passwd(alice, 'alice', PW[0], PW[1])[0], 429, 'control: alice is at her limit')
        self.assertEqual(self.passwd(bob, 'bob', PW[0], PW[1])[0], 200, 'bob was stopped by what alice did')

    def test_a_change_that_is_accepted_counts_as_one_too(self):
        self.set_cfg(password_history=24)
        token = self.sign_in('alice', PW[0])['token']
        api._ip_ratelimit = self.real_limit
        current = PW[0]
        for n in range(api.PASSWORD_HISTORY_CHECKS_PER_MINUTE):
            nxt = 'Accepted-Passw0rd!%d' % n
            self.assertEqual(self.passwd(token, 'alice', current, nxt)[0], 200, n)
            current = nxt
        self.assertEqual(self.passwd(token, 'alice', current, 'Accepted-Passw0rd!x')[0], 429)

    def test_nothing_is_limited_while_the_history_is_off(self):
        token = self.sign_in('alice', PW[0])['token']
        api._ip_ratelimit = self.real_limit
        current = PW[0]
        for n in range(api.PASSWORD_HISTORY_CHECKS_PER_MINUTE + 5):
            nxt = 'Plain-Passw0rd!%d' % n
            self.assertEqual(self.passwd(token, 'alice', current, nxt)[0], 200, n)
            current = nxt


class TestADamagedRecord(_Policy):
    """The account records are a file. A change date or a history that is not what the code writes is read as absent, never as a date far
    enough ahead that the account does not expire, and never as something that fails the sign-in or the change."""

    def test_a_date_that_cannot_be_a_date_is_no_date_and_the_clock_starts_over(self):
        now = 1_800_000_000
        for bad in ('yesterday', '1700000000', True, False, 0, -5, float('nan'), float('inf'), -float('inf'), 10 ** 30, now + 90 * DAY,
                    None, [1], {'t': 1}):
            self.assertEqual(api._password_age_action({'password_changed_at': bad}, 30, now), 'stamp', repr(bad))
        self.assertEqual(api._password_age_action({}, 30, now), 'stamp')

    def test_a_real_date_is_judged_by_the_limit(self):
        now = 1_800_000_000
        act = api._password_age_action
        self.assertEqual(act({'password_changed_at': now - 31 * DAY}, 30, now), 'expire')
        self.assertEqual(act({'password_changed_at': now - 31 * DAY, 'must_change_password': True}, 30, now), '', 'already flagged')
        self.assertEqual(act({'password_changed_at': now - 29 * DAY}, 30, now), '')
        self.assertEqual(act({'password_changed_at': now - 30 * DAY}, 30, now), '', 'the day itself is not past the limit')
        self.assertEqual(act({'password_changed_at': float(now - 31 * DAY)}, 30, now), 'expire', 'a date stored as a float')
        self.assertEqual(act({'password_changed_at': now + 3600}, 30, now), '', 'an hour of clock skew is not a damaged date')

    def test_a_damaged_date_and_history_do_not_fail_the_sign_in_or_the_change(self):
        self.set_cfg(password_max_age_days=30, password_history=3)
        for damaged in ({'password_changed_at': 'junk', 'password_history': 'junk'},
                        {'password_changed_at': True, 'password_history': [None, 5, '', 'junk', {'a': 1}]},
                        {'password_changed_at': -1, 'password_history': {'0': 'x'}}):
            with self.subTest(damaged=repr(damaged)[:40]):
                self.add_user('carol', 'viewer', PW[0], **damaged)
                d = self.sign_in('carol', PW[0])
                self.assertFalse(d['must_change_password'], 'a damaged date expired the account instead of starting its clock')
                self.assertGreater(self.rec('carol').get('password_changed_at') or 0, self.now - 60)
                st, body = self.call('POST', '/api/users/passwd', {'username': 'carol', 'old_password': PW[0], 'new_password': PW[1]}, d['token'])
                self.assertEqual(st, 200, body)
                for h in self.history('carol') or []:
                    self.assertIsInstance(h, str)
                self.assertEqual(self.call('POST', '/api/users/passwd', {'username': 'carol', 'old_password': PW[1], 'new_password': PW[0]},
                                           d['token'])[0], 400, 'the password before this change is in the history')

    def test_a_history_that_is_not_a_list_reads_as_empty(self):
        for raw in ('junk', 7, {'a': 'b'}, None, [None, 3, '', 'x', 'y']):
            got = api._stored_password_history({'password_history': raw})
            self.assertIsInstance(got, list, repr(raw))
            self.assertTrue(all(isinstance(h, str) and h for h in got), repr(raw))
        self.assertEqual(api._stored_password_history('not a record'), [])


class TestTheShapeRegistryKnowsTheNewFields(unittest.TestCase):
    """The stored-shape registry repairs what a reader would trip on. The change date is subtracted from the clock and the history is read
    as a list, so both are in it, and so are the two settings (read through int())."""

    def test_the_change_date_and_the_history_of_an_account(self):
        import copy
        import store_shapes
        doc = {'a': {'role': 'viewer', 'password_changed_at': 'junk', 'password_history': ['h1', None, 'h2']},
               'b': {'password_changed_at': True, 'password_history': 'junk'},
               'c': {'password_changed_at': 1700000000, 'password_history': ['x']},
               'd': {'password_changed_at': float('nan'), 'password_history': None},
               'e': {'password_changed_at': '1700000000'}}
        out = store_shapes.normalize('users.json', copy.deepcopy(doc))
        self.assertEqual(out['a'], {'role': 'viewer', 'password_history': ['h1', 'h2']}, 'text for a date is left out, a null in the list too')
        self.assertEqual(out['b'], {'password_history': []}, 'a boolean is not a date; a history that is not a list is empty')
        self.assertEqual(out['c'], doc['c'], 'a good record is left alone')
        self.assertEqual(out['d'], {'password_history': []}, 'NaN is not a date')
        self.assertEqual(out['e'], {'password_changed_at': 1700000000}, 'a number written as text is read as the number')

    def test_the_two_settings_are_read_as_numbers_or_not_at_all(self):
        import store_shapes
        out = store_shapes.normalize('config.json', {'password_history': 'x', 'password_max_age_days': [1], 'password_min_length': 8})
        self.assertEqual(out, {'password_min_length': 8}, 'a value that is not a number is left out, so the setting reads as off')
        out = store_shapes.normalize('config.json', {'password_history': '5', 'password_max_age_days': 90.0})
        self.assertEqual(out, {'password_history': 5, 'password_max_age_days': 90.0})


class TestTheSignInTakesNoLockWhenThereIsNothingToWrite(_Policy):
    """Most sign-ins have nothing for the maximum age to write. A write takes the users store's lock and rewrites the whole store, so the
    age looks first and locks only for an account that needs a change."""

    def count_locks(self, name):
        taken = []
        real = api._LockedUpdate

        def counting(path, non_blocking=False):
            if path == api.USERS_FILE:
                taken.append(1)
            return real(path, non_blocking)

        api._LockedUpdate = counting
        try:
            flags = api._password_age_gate(name)
        finally:
            api._LockedUpdate = real
        return len(taken), flags

    def test_a_password_inside_the_limit_is_judged_without_the_lock(self):
        self.set_cfg(password_max_age_days=30)
        self.set_rec('alice', password_changed_at=self.now - 5 * DAY)
        n, flags = self.count_locks('alice')
        self.assertEqual((n, flags), (0, {'must_change_password': False, 'password_expired': False}))

    def test_an_account_that_needs_a_write_takes_it_once(self):
        self.set_cfg(password_max_age_days=30)
        self.set_rec('alice', password_changed_at=self.now - 45 * DAY)
        n, flags = self.count_locks('alice')
        self.assertEqual((n, flags['must_change_password'], flags['password_expired']), (1, True, True))
        self.set_rec('bob', password_changed_at=None)
        n, flags = self.count_locks('bob')
        self.assertEqual((n, flags['must_change_password']), (1, False))
        self.assertTrue(self.rec('bob').get('password_changed_at'))

    def test_an_account_that_is_already_flagged_is_judged_without_the_lock(self):
        self.set_cfg(password_max_age_days=30)
        self.set_rec('alice', password_changed_at=self.now - 45 * DAY, must_change_password=True)
        n, flags = self.count_locks('alice')
        self.assertEqual((n, flags['must_change_password'], flags['password_expired']), (0, True, False))

    def test_the_age_off_takes_no_lock_and_reads_nothing(self):
        n, flags = self.count_locks('alice')
        self.assertEqual((n, flags), (0, None))

    def test_a_name_that_is_not_an_account_gets_no_flags(self):
        self.set_cfg(password_max_age_days=30)
        self.assertEqual(self.count_locks('nobody'), (0, None))


class TestTheRedactedExportCarriesNoCredential(_Policy):
    """The export that the docs call safe to share leaves every credential out of users.json: the password hash, the history, the TOTP secret
    (and the one waiting to be confirmed) and the recovery codes. It had carried all of them for every account."""

    SECRETS = {'totp_secret': 'JBSWY3DPEHPK3PXP', 'totp_pending': 'KRSXG5CTMVRXEZLU', 'recovery_codes': ['recoveryhash-one', 'recoveryhash-two']}

    def exported_users(self):
        import zipfile
        st, blob = self.call('GET', '/api/export', token=self.root_token, raw=True)
        self.assertEqual(st, 200)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return json.loads(zf.read('users.json'))

    def test_no_account_in_the_export_carries_a_credential(self):
        self.settings(password_history=3)
        self.change('alice', PW[0], PW[1])
        self.set_rec('alice', **self.SECRETS)
        before = self.rec('alice')
        for key in api._EXPORT_ACCOUNT_CREDENTIALS:
            self.assertIn(key, before, 'control: the record holds ' + key)
        users = self.exported_users()
        for name, rec in users.items():
            for key in api._EXPORT_ACCOUNT_CREDENTIALS:
                self.assertNotIn(key, rec, (name, key))
        text = json.dumps(users)
        for secret in ([before['password_hash'], self.SECRETS['totp_secret'], self.SECRETS['totp_pending']] + self.SECRETS['recovery_codes']
                       + before['password_history']):
            self.assertNotIn(secret, text, 'a credential is in the export')

    def test_the_accounts_themselves_and_what_is_not_a_credential_are_still_there(self):
        self.set_rec('alice', totp_secret='JBSWY3DPEHPK3PXP', lang='de')
        users = self.exported_users()
        self.assertEqual(sorted(users), ['alice', 'bob', 'root'])
        self.assertEqual((users['alice']['role'], users['alice']['tenant_id'], users['alice'].get('lang')), ('viewer', 'default', 'de'))
        self.assertEqual(users['root']['role'], 'admin')

    def test_the_full_backup_keeps_every_credential_because_it_restores_accounts(self):
        import tarfile
        self.settings(password_history=3)
        self.change('alice', PW[0], PW[1])
        self.set_rec('alice', **self.SECRETS)
        st, blob = self.call('GET', '/api/backup/download', token=self.root_token, raw=True)
        self.assertEqual(st, 200)
        with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as tar:
            member = next(m for m in tar.getmembers() if m.name.split('/')[-1] == 'users.json')
            users = json.loads(tar.extractfile(member).read())
        alice = users['alice']
        for key in api._EXPORT_ACCOUNT_CREDENTIALS:
            self.assertIn(key, alice, 'the full backup lost ' + key + ': a restore would lose it too')
        self.assertTrue(api.verify_password(PW[1], alice['password_hash']))


class TestTheRealCost(_Policy):

    def test_it_works_with_bcrypt_at_its_real_cost(self):
        if not api._BCRYPT:
            self.skipTest('bcrypt is not installed; the PBKDF2 scheme is covered by the tests above')
        api.hash_password = _STATE['real_hash']
        try:
            self.set_cfg(password_history=2)
            self.add_user('real', 'viewer', PW[0])
            self.assertEqual(self.change('real', PW[0], PW[1])[0], 200)
            self.assertEqual(self.change('real', PW[1], PW[0])[0], 400)
            self.assertTrue(self.history('real')[0].startswith('$2b$12$'), 'the real cost')
        finally:
            api.hash_password = lambda plain: __import__('bcrypt').hashpw(plain.encode(), __import__('bcrypt').gensalt(4)).decode()


if __name__ == '__main__':
    unittest.main()
