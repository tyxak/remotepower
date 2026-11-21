#!/usr/bin/env python3
"""Every gate that holds a session behind a step lets the session end.

A person whose password has passed its maximum age (or who still has the default one, or whose role requires a second factor they have not
set up) holds a valid session that the pre-dispatch gates answer 403 for every route but a few. Signing out is one of those few: the route
that ends the session on the server (7.4.9) has to be reachable from inside the gate, or the page signs out in the browser and the token
stays alive on the server for as long as it lasts. The password-change gate was the one that left it out; the MFA enrolment gate and the
read-only gate listed it.

The population is derived from api.py by syntax tree: every `_enforce_*` gate and the lists of `/api/` paths it reads. A gate lets the
sign-out through when `/api/logout` is in one of its lists or one of its prefix lists covers it; a gate that does not is named in EXEMPT
with the reason it does not need to. An exemption that stops being needed fails the test too, so the list only shrinks. The two gates that
hold a real session are then driven through the routes: sign in, be refused, sign out, and the same token is a 401 afterwards.
"""
import ast
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-gates-logout-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import wsgi  # noqa: E402  (imports api)

api = wsgi.api
LOGOUT = '/api/logout'
PW = 'Alpha-Passw0rd!1'
_STATE = {}

# Gates that do not let the sign-out through, with the reason each does not need to.
EXEMPT = {
    '_enforce_ip_allowlist':
        'it refuses an address, not a session, and its lists are what an address that is not on the allowlist may still reach (the agent '
        'routes): there is no session to end from it',
    '_enforce_platform_routes':
        'it refuses a tenant user a request that is on the list of the routes of the platform (a deny list, which does not hold /api/logout, and none of the routes a held session may '
        'use: the next test holds that), and it does not refuse a request with no signed-in user',
}


def setUpModule():
    # every store of api in a directory of this module's own: the data dir may be the one the whole suite shares
    data_dir = api.DATA_DIR
    moved = {n: v for n, v in vars(api).items() if n.isupper() and isinstance(v, Path) and v.parent == data_dir}
    tmp = Path(tempfile.mkdtemp(prefix='rp-gates-logout-run-'))
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


def _gates():
    """{gate: {list name: the strings in it}} for every `_enforce_*` function of api.py and every module-level collection of `/api/` path
    strings (frozenset, set, tuple or list) that the function reads."""
    tree = ast.parse((_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text())
    lists = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            continue
        v = node.value
        elts = None
        if isinstance(v, ast.Call) and getattr(v.func, 'id', '') in ('frozenset', 'set', 'tuple', 'list') and v.args \
                and isinstance(v.args[0], (ast.Set, ast.List, ast.Tuple)):
            elts = v.args[0].elts
        elif isinstance(v, (ast.Set, ast.List, ast.Tuple)):
            elts = v.elts
        if elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts) \
                and any(e.value.startswith('/api/') for e in elts):
            lists[node.targets[0].id] = {e.value for e in elts}
    out = {}
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef) and fn.name.startswith('_enforce_'):
            names = sorted({x.id for x in ast.walk(fn) if isinstance(x, ast.Name) and x.id in lists})
            if names:
                out[fn.name] = {n: lists[n] for n in names}
    return out


def _lets_through(gate_lists, route):
    """True when the gate lets `route` through: it is in one of the gate's lists, or one of its prefix lists (entries that end in a slash)
    covers it."""
    return any(route in strings or any(route.startswith(s) for s in strings if s.endswith('/')) for strings in gate_lists.values())


class TestEveryGateLetsTheSignOutThrough(unittest.TestCase):

    def test_the_population_is_the_gates_a_session_can_sit_behind(self):
        found = _gates()
        # the control: the derivation has to see the three gates that hold a session, or the test below would pass over nothing
        for gate, name in (('_enforce_read_only', '_READ_ONLY_ALLOWED'), ('_enforce_password_change', '_PWCHG_ALLOWED_PATHS'),
                           ('_enforce_mfa_enrollment', '_MFA_ENROLL_ALLOWED_PATHS')):
            self.assertIn(gate, found, 'the derivation does not see %s: it measures nothing' % gate)
            self.assertIn(name, found[gate], 'the derivation does not see %s in %s' % (name, gate))
        self.assertGreaterEqual(len(found), 4, sorted(found))

    def test_every_gate_lets_it_through_or_is_exempt_with_a_reason(self):
        found = _gates()
        through = sorted(g for g, lists in found.items() if _lets_through(lists, LOGOUT))
        missing = sorted(g for g, lists in found.items() if not _lets_through(lists, LOGOUT) and g not in EXEMPT)
        self.assertEqual(missing, [], '%d of %d gates leave a held session no way to end: %s (gates that let it through: %s)'
                         % (len(missing), len(found), missing, through))

    def test_an_exemption_is_still_needed(self):
        found = _gates()
        for gate, reason in EXEMPT.items():
            self.assertTrue(reason.strip(), 'an exemption without a reason: %s' % gate)
            self.assertIn(gate, found, 'the exemption names a gate that reads no list of paths any more: remove it: %s' % gate)
            self.assertFalse(_lets_through(found[gate], LOGOUT), 'the gate lets the sign-out through now: remove the exemption: %s' % gate)

    def test_the_platform_routes_hold_nothing_a_held_session_needs(self):
        """The reason of the exemption above. _enforce_platform_routes is not a list of what a session may still reach but of what a tenant may not, so the test above cannot read it.
        What it can be asked is whether any route that a held session is let through to (the sign-out, its account, the password change, the enrolment of a second factor) is on that list."""
        needed = set(api._PWCHG_ALLOWED_PATHS) | set(api._MFA_ENROLL_ALLOWED_PATHS) | {LOGOUT}
        self.assertIn(LOGOUT, needed)
        self.assertGreaterEqual(len(needed), 3, 'the lists of the held sessions were not read')
        for path in sorted(needed):
            for method in ('GET', 'POST'):
                self.assertIsNone(api._platform_route(path, method), '%s %s is a route of the platform: a tenant user whose password has expired could not use it' % (method, path))
        self.assertEqual(api._platform_route('/api/backup/download', 'GET'), '/api/backup', 'control: a route of the platform is found')

    def test_the_route_that_the_lists_name_is_a_real_route(self):
        self.assertIn(('POST', LOGOUT), api._build_exact_routes())

    def test_the_helper_reads_exact_lists_and_prefix_lists_and_nothing_looser(self):
        # no gate lets the sign-out through by a prefix today, so the prefix branch is held here with lists of its own
        self.assertTrue(_lets_through({'a': {'/api/logout'}}, LOGOUT))
        self.assertTrue(_lets_through({'a': {'/api/x'}, 'b': {'/api/'}}, LOGOUT), 'a prefix that covers the route is a way through')
        self.assertFalse(_lets_through({'a': {'/api/x'}, 'b': {'/api/webhook/in/'}}, LOGOUT))
        self.assertFalse(_lets_through({'a': {'/api/logout/other'}}, LOGOUT), 'a longer path is not the route and has no slash to be a prefix')
        self.assertFalse(_lets_through({'a': {'/api/log'}}, LOGOUT), 'a shorter path without a trailing slash is not a prefix')


class _Sessions(unittest.TestCase):
    """Accounts, a settings document and the routes, driven the way a browser drives them."""

    def setUp(self):
        for f in (api.USERS_FILE, api.TOKENS_FILE, api.CONFIG_FILE, api.AUDIT_LOG_FILE, api.RATELIMIT_FILE, api.TENANTS_FILE,
                  api.DEVICES_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'backup': {'enabled': False}})
        api._LOAD_CACHE.clear()

    def add_user(self, name, role, **extra):
        rec = {'password_hash': api.hash_password(PW), 'role': role, 'created': int(time.time()), 'password_changed_at': int(time.time()),
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

    def call(self, verb, path, body=None, token=None):
        payload = json.dumps(body).encode() if body is not None else b''
        env = _environ(verb, path, payload, {'X-Token': token} if token else None)
        cap = {}

        def start(status, headers):
            cap['status'] = int(status.split()[0])

        out = b''.join(wsgi.application(env, start))
        api._LOAD_CACHE.clear()
        try:
            return cap['status'], (json.loads(out) if out else None)
        except ValueError:
            return cap['status'], out

    def sign_in(self, name):
        st, d = self.call('POST', '/api/login', {'username': name, 'password': PW})
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get('ok'), (name, d))
        return d

    def sessions_of(self, name):
        api._LOAD_CACHE.clear()
        return [e for e in (api.load(api.TOKENS_FILE) or {}).values() if isinstance(e, dict) and e.get('user') == name]

    def assert_held_then_signed_out(self, name, held_route, expect=None):
        """The session is real, the gate refuses a route, the sign-out is answered, and the session is gone on the server."""
        answer = self.sign_in(name)
        for key, value in (expect or {}).items():
            self.assertEqual(answer.get(key), value, 'control: the sign-in answer says %s = %r' % (key, value))
        token = answer['token']
        self.assertEqual(len(self.sessions_of(name)), 1, 'control: the sign-in made a session')
        st, d = self.call('GET', held_route, token=token)
        self.assertEqual(st, 403, 'control: the gate holds this session (%s -> %s %s)' % (held_route, st, d))
        st, d = self.call('POST', LOGOUT, token=token)
        self.assertEqual((st, d), (200, {'ok': True}), 'the sign-out of a session behind the gate was refused: %s %s' % (st, d))
        self.assertEqual(self.sessions_of(name), [], 'the session is still stored on the server after the sign-out')
        self.assertEqual(self.call('GET', held_route, token=token)[0], 401, 'the token still works after the sign-out')
        return token


class TestAPasswordThatHasToBeChanged(_Sessions):

    def test_the_default_or_reset_password_gate_lets_the_session_sign_out(self):
        self.add_user('alice', 'viewer', must_change_password=True)
        self.assert_held_then_signed_out('alice', '/api/devices', expect={'must_change_password': True})

    def test_the_maximum_age_gate_lets_the_session_sign_out(self):
        self.set_cfg(password_max_age_days=30)
        self.add_user('alice', 'viewer', password_changed_at=int(time.time()) - 99 * 86400)
        self.assert_held_then_signed_out('alice', '/api/devices', expect={'must_change_password': True, 'password_expired': True})

    def test_the_other_routes_stay_shut_and_the_change_stays_open(self):
        self.add_user('alice', 'viewer', must_change_password=True)
        token = self.sign_in('alice')['token']
        self.assertEqual(self.call('GET', '/api/users', token=token)[0], 403)
        self.assertEqual(self.call('GET', '/api/config', token=token)[0], 403)
        st, d = self.call('POST', '/api/users/passwd', {'username': 'alice', 'old_password': 'wrong', 'new_password': PW + 'x'}, token)
        self.assertEqual(st, 403, 'the change itself reaches its handler: it is refused for the old password, not by the gate')
        self.assertNotIn('must_change_password', d or {}, 'the gate answered the change route')
        self.assertEqual(self.call('GET', '/api/public-info')[0], 200)


class TestARoleThatHasToSetUpASecondFactor(_Sessions):

    def test_the_mfa_enrolment_gate_lets_the_session_sign_out(self):
        self.set_cfg(mfa_required_roles=['viewer'])
        self.add_user('bob', 'viewer')
        self.assert_held_then_signed_out('bob', '/api/devices')


if __name__ == '__main__':
    unittest.main()
