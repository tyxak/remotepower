#!/usr/bin/env python3
"""Two routes that a tenant administrator could use on every tenant's data: the password reset and the export.

With tenancy on, a tenant administrator passes `require_admin_auth()` and has no tenant dimension of its own in these two handlers:

* `POST /api/users/passwd` set the password of ANY account when an administrator asked: the platform operator's, or another tenant's. The
  other account routes (`handle_user_update`, `handle_user_delete`) already answer 404 for an account of another tenant; this one did not.
  A tenant administrator could set the operator's password and sign in as it.
* `GET /api/export` is the ZIP of every store: the hosts and the accounts (with their password hashes) of every tenant, and the settings.
  It is the platform operator's now, like the full backup beside it. `/api/export/monitors` stays open to the operator organisation's own
  users.

Both are driven through the real routes with real sessions. A tenant administrator is refused, the account it aimed at is left exactly as
it was, and the platform operator, an administrator of the tenant itself and an install with tenancy off still can.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-tenantpw-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import wsgi  # noqa: E402  (imports api)

api = wsgi.api

ROOT_PW = 'Root-Passw0rd!x1'
PW = ['Alpha-Passw0rd!1', 'Bravo-Passw0rd!2', 'Charlie-Passw0rd!3', 'Delta-Passw0rd!4', 'Echo-Passw0rd!5', 'Foxtrot-Passw0rd!6']

_STATE = {}


def setUpModule():
    # every store of api in a directory of this module's own: the data dir may be the one the whole suite shares
    data_dir = api.DATA_DIR
    moved = {n: v for n, v in vars(api).items() if n.isupper() and isinstance(v, Path) and v.parent == data_dir}
    tmp = Path(tempfile.mkdtemp(prefix='rp-tenantpw-run-'))
    for n, v in moved.items():
        setattr(api, n, tmp / v.name)
    api.DATA_DIR = tmp
    saved = {n: getattr(api, n) for n in ('_run_detached', '_ip_ratelimit', 'hash_password')}
    api._run_detached = lambda *a, **k: None
    api._ip_ratelimit = lambda *a, **k: True                     # twenty sign-ins a minute is for people; these are tests
    if api._BCRYPT:
        import bcrypt
        api.hash_password = lambda plain: bcrypt.hashpw(plain.encode(), bcrypt.gensalt(4)).decode()      # the scheme as it is, at the lowest cost
    _STATE.update(tmp=tmp, moved=moved, data_dir=data_dir, saved=saved)


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


class TestWhoMayResetWhom(unittest.TestCase):
    """The platform operator is `root` (an administrator of the default tenant); `tadmin` and `tuser` belong to tenant B; `alice` and `bob`
    are viewers of the default tenant."""

    def setUp(self):
        for f in (api.USERS_FILE, api.TOKENS_FILE, api.CONFIG_FILE, api.AUDIT_LOG_FILE, api.RATELIMIT_FILE, api.TENANTS_FILE, api.DEVICES_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'backup': {'enabled': False}})
        api._LOAD_CACHE.clear()
        self.now = int(time.time())
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True},
                                    'tenantB': {'name': 'B', 'status': 'active'}})
        self.add_user('root', 'admin', ROOT_PW)
        self.add_user('alice', 'viewer', PW[0])
        self.add_user('bob', 'viewer', PW[0])
        self.add_user('tadmin', 'admin', PW[2], tenant_id='tenantB')
        self.add_user('tuser', 'viewer', PW[3], tenant_id='tenantB')
        self.set_cfg(tenancy_enforced=True)
        self.root_token = self.sign_in('root', ROOT_PW)
        self.tadmin = self.sign_in('tadmin', PW[2])

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

    def call(self, verb, path, body=None, token=None, raw=False):
        payload = json.dumps(body).encode() if body is not None else b''
        cap = {}

        def start(status, headers):
            cap['status'] = int(status.split()[0])

        out = b''.join(wsgi.application(_environ(verb, path, payload, {'X-Token': token} if token else None), start))
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
        return d['token']

    def reset_as(self, token, name, new):
        return self.call('POST', '/api/users/passwd', {'username': name, 'new_password': new}, token)

    def step_up(self, token, password):
        """Setting somebody else's password asks for a fresh sign-in check: the administrator types their own password first."""
        st, d = self.call('POST', '/api/auth/step-up', {'password': password}, token)
        self.assertEqual(st, 200, d)

    def snapshot(self, name):
        return json.dumps(self.rec(name), sort_keys=True)

    # ── the reset ───────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_tenant_administrator_cannot_set_the_password_of_the_platform_operator_or_of_another_tenants_account(self):
        for victim in ('root', 'alice', 'bob'):
            before = self.snapshot(victim)
            st, d = self.reset_as(self.tadmin, victim, PW[5])
            self.assertEqual(st, 404, (victim, d))
            self.assertEqual(self.snapshot(victim), before, 'the account of another tenant was changed: ' + victim)
        self.assertTrue(api.verify_password(ROOT_PW, self.rec('root')['password_hash']))
        self.assertEqual(self.call('GET', '/api/devices', token=self.root_token)[0], 200, 'the platform operator was signed out')
        st, d = self.call('POST', '/api/login', {'username': 'root', 'password': PW[5]})
        self.assertFalse((d or {}).get('ok'), 'the password the tenant administrator chose signs in as the platform operator')

    def test_the_answer_for_an_account_of_another_tenant_is_the_answer_for_one_that_does_not_exist(self):
        """So that the refusal does not say which account names exist."""
        self.assertEqual(self.reset_as(self.tadmin, 'root', PW[5]), self.reset_as(self.tadmin, 'no-such-account', PW[5]))

    def test_it_can_set_the_password_of_an_account_of_its_own_tenant(self):
        self.step_up(self.tadmin, PW[2])
        st, d = self.reset_as(self.tadmin, 'tuser', PW[5])
        self.assertEqual(st, 200, d)
        self.assertTrue(api.verify_password(PW[5], self.rec('tuser')['password_hash']))
        self.assertTrue(self.rec('tuser')['must_change_password'], 'an administrator chose it, so the person changes it at the first sign-in')

    def test_the_platform_operator_can_set_the_password_of_an_account_of_any_tenant(self):
        self.step_up(self.root_token, ROOT_PW)
        self.assertEqual(self.reset_as(self.root_token, 'tuser', PW[5])[0], 200)
        self.assertEqual(self.reset_as(self.root_token, 'alice', PW[5])[0], 200)

    def test_a_viewer_cannot_set_the_password_of_anybody_but_themselves(self):
        viewer = self.sign_in('alice', PW[0])
        before = self.snapshot('bob')
        self.assertEqual(self.reset_as(viewer, 'bob', PW[5])[0], 403)
        self.assertEqual(self.snapshot('bob'), before)

    def test_a_tenant_administrator_still_changes_its_own_password(self):
        st, d = self.call('POST', '/api/users/passwd', {'username': 'tadmin', 'old_password': PW[2], 'new_password': PW[5]}, self.tadmin)
        self.assertEqual(st, 200, d)
        self.assertTrue(api.verify_password(PW[5], self.rec('tadmin')['password_hash']))

    def test_with_tenancy_off_every_administrator_sets_every_password_as_before(self):
        self.set_cfg(tenancy_enforced=False)
        self.step_up(self.tadmin, PW[2])
        self.assertEqual(self.reset_as(self.tadmin, 'alice', PW[5])[0], 200)

    # ── the export ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_tenant_administrator_cannot_download_the_export_that_holds_every_tenants_accounts(self):
        st, blob = self.call('GET', '/api/export', token=self.tadmin, raw=True)
        self.assertEqual(st, 403)
        self.assertNotIn(b'users.json', blob)
        self.assertNotIn(self.rec('root')['password_hash'].encode(), blob, 'a hash of the platform operator went out in the answer')

    def test_the_platform_operator_still_downloads_it(self):
        import zipfile
        st, blob = self.call('GET', '/api/export', token=self.root_token, raw=True)
        self.assertEqual(st, 200)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            self.assertIn('users.json', zf.namelist())

    def test_the_monitors_list_under_the_same_prefix_is_not_closed_to_the_operator_organisations_own_users(self):
        viewer = self.sign_in('alice', PW[0])
        self.assertEqual(self.call('GET', '/api/export/monitors', token=viewer)[0], 200)

    def test_with_tenancy_off_a_tenant_administrator_still_downloads_it(self):
        self.set_cfg(tenancy_enforced=False)
        self.assertEqual(self.call('GET', '/api/export', token=self.tadmin, raw=True)[0], 200)


if __name__ == '__main__':
    unittest.main()
