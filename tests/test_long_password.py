#!/usr/bin/env python3
"""A password that bcrypt cannot hash whole is refused with a message, and no place that hashes one can fail on it.

bcrypt reads the first 72 BYTES of a password. bcrypt 5 refuses a longer one with a ValueError, and the new-password forms accept up to
1024 characters, so a new password of 73 to 1024 bytes answered HTTP 500 (after the rate-limit slot of the change had been spent). The unit
is the byte, not the character: 25 euro signs are 75 bytes. The rules this module holds:

* a new password over 72 bytes is refused by the shared policy check with a 400 and a message that says so, on every route that sets one
  (the change, an administrator's reset, creating an account), before any lock, comparison or rate-limit slot is spent; 72 bytes is
  accepted. Where bcrypt is not the scheme there is nothing to refuse;
* hash_password() never raises: a password bcrypt cannot take whole gets the PBKDF2 hash the server verifies for any account, and a
  password is never cut (the same password with one more character does not verify);
* signing in with a long password into a PBKDF2 hash does not fail and does not rewrite the hash on every sign-in, and the upgrade to bcrypt
  of a short password still happens;
* every other place in the product that hashes a password with bcrypt (the offline tool and the three installers) follows the same rule,
  run here with real passwords, and a new place that does not is found by a walk of the repository.

bcrypt runs at its lowest cost in the route tests so that dozens of changes take seconds; its real cost is used for the tools.
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-longpw-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(_ROOT / 'tests'))

import srcpin  # noqa: E402
import wsgi  # noqa: E402  (imports api)
from i18n_engine import LANGS, dict_rows, unchanged_by_engine  # noqa: E402

api = wsgi.api
HAVE_BCRYPT = bool(api._BCRYPT)
OLD = 'Alpha-Passw0rd!1'
ROOT_PW = 'Root-Passw0rd!x1'
MESSAGE = 'Password must be at most 72 bytes (72 letters or digits; fewer characters if it uses accents, symbols or other scripts)'
OLDER_MESSAGE = 'new_password required (max 1024 chars)'
_STATE = {}


class _CheapBcrypt:
    """The bcrypt module with its work factor lowered. Everything else, hashpw and checkpw with their 72-byte rule, is the real thing."""

    def __init__(self, real):
        self._real = real

    def gensalt(self, rounds=12, prefix=b'2b'):
        return self._real.gensalt(4)

    def __getattr__(self, name):
        return getattr(self._real, name)


def setUpModule():
    # every store of api in a directory of this module's own: the data dir may be the one the whole suite shares
    data_dir = api.DATA_DIR
    moved = {n: v for n, v in vars(api).items() if n.isupper() and isinstance(v, Path) and v.parent == data_dir}
    tmp = Path(tempfile.mkdtemp(prefix='rp-longpw-run-'))
    for n, v in moved.items():
        setattr(api, n, tmp / v.name)
    api.DATA_DIR = tmp
    saved = {n: getattr(api, n) for n in ('_run_detached', '_ip_ratelimit', '_bcrypt')}
    api._run_detached = lambda *a, **k: None
    api._ip_ratelimit = lambda *a, **k: True                     # twenty sign-ins a minute is for people; these are tests
    if HAVE_BCRYPT:
        api._bcrypt = _CheapBcrypt(saved['_bcrypt'])
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


def _pw(n_bytes):
    """A password of exactly n ASCII bytes."""
    return ('Zz9!' + 'a' * n_bytes)[:n_bytes]


class _Base(unittest.TestCase):

    def setUp(self):
        for f in (api.USERS_FILE, api.TOKENS_FILE, api.CONFIG_FILE, api.AUDIT_LOG_FILE, api.RATELIMIT_FILE, api.TENANTS_FILE, api.DEVICES_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'backup': {'enabled': False}})
        api._LOAD_CACHE.clear()
        self.add_user('root', 'admin', ROOT_PW)
        self.add_user('alice', 'viewer', OLD)
        self.root_token = self.sign_in('root', ROOT_PW)['token']

    def add_user(self, name, role, password=None, password_hash=None, **extra):
        rec = {'password_hash': password_hash or api.hash_password(password), 'role': role, 'created': int(time.time()),
               'password_changed_at': int(time.time()), 'tenant_id': 'default'}
        rec.update(extra)
        users = api.load(api.USERS_FILE) or {}
        users[name] = rec
        api.save(api.USERS_FILE, users)
        api._LOAD_CACHE.clear()

    def rec(self, name):
        api._LOAD_CACHE.clear()
        return (api.load(api.USERS_FILE) or {}).get(name) or {}

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

    def try_sign_in(self, name, password):
        return self.call('POST', '/api/login', {'username': name, 'password': password})

    def sign_in(self, name, password):
        st, d = self.try_sign_in(name, password)
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get('ok'), (name, d))
        return d

    def change(self, token, old, new, name='alice'):
        return self.call('POST', '/api/users/passwd', {'username': name, 'old_password': old, 'new_password': new}, token)


@unittest.skipUnless(HAVE_BCRYPT, 'bcrypt is not installed: nothing here is limited to 72 bytes')
class TestANewPasswordOverTheLimitIsRefusedWithAMessage(_Base):

    def test_72_bytes_are_accepted_and_73_are_refused_with_the_message_and_change_nothing(self):
        token = self.sign_in('alice', OLD)['token']
        before = json.dumps(self.rec('alice'), sort_keys=True)
        st, d = self.change(token, OLD, _pw(73))
        self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), 'a password of 73 bytes was not refused with the message: %s %s' % (st, d))
        self.assertEqual(json.dumps(self.rec('alice'), sort_keys=True), before, 'a refused change touched the record')
        self.assertEqual(self.try_sign_in('alice', OLD)[1].get('ok'), True, 'the old password stopped working')
        st, d = self.change(token, OLD, _pw(72))
        self.assertEqual(st, 200, d)
        self.assertTrue(self.sign_in('alice', _pw(72))['ok'], 'a password of exactly 72 bytes does not sign in')

    def test_the_limit_is_in_bytes_not_characters(self):
        token = self.sign_in('alice', OLD)['token']
        cases = (('€', 24, 25), ('é', 36, 37), ('a', 72, 73), ('\U0001F511', 18, 19))      # euro sign 3 bytes, e acute 2, ASCII 1, key 4
        current = OLD
        for ch, fits, over in cases:
            with self.subTest(character=ch):
                self.assertEqual(len((ch * fits).encode()), 72)
                st, d = self.change(token, current, ch * over)
                self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), (ch, over, st, d))
                st, d = self.change(token, current, ch * fits)
                self.assertEqual(st, 200, (ch, fits, d))
                current = ch * fits
                self.assertTrue(self.sign_in('alice', current)['ok'])

    def test_every_length_up_to_the_form_limit_is_a_refusal_and_never_a_500(self):
        token = self.sign_in('alice', OLD)['token']
        for n in (73, 74, 100, 500, 1023, 1024):
            with self.subTest(length=n):
                st, d = self.change(token, OLD, _pw(n))
                self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), (n, st, d))
        st, d = self.change(token, OLD, _pw(1025))
        self.assertEqual((st, (d or {}).get('error')), (400, OLDER_MESSAGE), 'the length limit of the form is still its own message')

    def test_creating_an_account_is_held_to_the_same_rule(self):
        st, d = self.call('POST', '/api/users', {'username': 'carol', 'password': _pw(73), 'role': 'viewer'}, self.root_token)
        self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), (st, d))
        self.assertNotIn('carol', api.load(api.USERS_FILE) or {}, 'a refused account was stored')
        st, d = self.call('POST', '/api/users', {'username': 'carol', 'password': _pw(72), 'role': 'viewer'}, self.root_token)
        self.assertEqual(st, 201, d)
        self.assertTrue(self.sign_in('carol', _pw(72))['ok'])

    def test_an_administrators_reset_is_held_to_it_too(self):
        st, d = self.call('POST', '/api/users/passwd', {'username': 'alice', 'new_password': _pw(73)}, self.root_token)
        self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), (st, d))
        # setting somebody else's password asks for a fresh sign-in check, as creating an administrator does
        st, d = self.call('POST', '/api/auth/step-up', {'password': ROOT_PW}, self.root_token)
        self.assertEqual(st, 200, d)
        st, d = self.call('POST', '/api/users/passwd', {'username': 'alice', 'new_password': _pw(72)}, self.root_token)
        self.assertEqual(st, 200, d)

    def test_the_refusal_comes_before_any_comparison_lock_or_rate_limit_slot(self):
        self.set_cfg(password_history=5)
        token = self.sign_in('alice', OLD)['token']
        real_limit = _STATE['saved']['_ip_ratelimit']
        checks = []
        real_verify = api.verify_password
        api._ip_ratelimit = real_limit
        api.verify_password = lambda plain, stored: (checks.append(1), real_verify(plain, stored))[1]
        try:
            for n in range(api.PASSWORD_HISTORY_CHECKS_PER_MINUTE + 5):
                st, d = self.change(token, OLD, _pw(100))
                self.assertEqual((st, (d or {}).get('error')), (400, MESSAGE), (n, st, d))
            self.assertEqual(checks, [], 'a refusal for the length checked %d password hashes first' % len(checks))
            st, d = self.change(token, OLD, 'Bravo-Passw0rd!2')
            self.assertEqual(st, 200, 'the refusals used up the caller\'s rate-limit slots: %s %s' % (st, d))
        finally:
            api.verify_password = real_verify
            api._ip_ratelimit = lambda *a, **k: True

    def test_a_refusal_leaves_no_audit_line_of_a_password_change(self):
        token = self.sign_in('alice', OLD)['token']
        self.change(token, OLD, _pw(100))
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get('entries') or []
        self.assertEqual([e for e in entries if str(e.get('action')).startswith('password_')], [], 'a refused change was written down as a change')


class TestTheMessageIsTranslated(unittest.TestCase):

    def test_the_text_the_server_sends_is_a_dictionary_key_with_all_six_languages(self):
        if not HAVE_BCRYPT:
            self.skipTest('bcrypt is not installed: the server does not send the message')
        ok, sent = api._validate_password_policy(_pw(73))
        self.assertFalse(ok)
        self.assertEqual(sent, MESSAGE, 'the message of the server changed: the test, the dictionary and the guides name it')
        rows = dict_rows()
        self.assertEqual(sorted(set(LANGS) - rows.get(sent, set())), [], 'the message is not translated into every language')
        if shutil.which('node'):
            left = unchanged_by_engine([sent])
            self.assertEqual({k: v for k, v in left.items() if v}, {}, 'the engine hands the message back in English')


class TestHashPasswordNeverRaises(_Base):

    def test_every_length_gives_a_hash_the_server_verifies_and_a_password_is_never_cut(self):
        for label, plain in (('empty-ish', 'x'), ('72 bytes', _pw(72)), ('73 bytes', _pw(73)), ('100 chars', _pw(100)),
                             ('1024 chars', _pw(1024)), ('25 euro signs', '€' * 25), ('4-byte characters', '\U0001F511' * 40)):
            with self.subTest(password=label):
                h = api.hash_password(plain)
                over = len(plain.encode()) > 72
                want = 'pbkdf2$' if (over or not HAVE_BCRYPT) else '$2'
                self.assertTrue(h.startswith(want), (label, h[:12]))
                self.assertTrue(api.verify_password(plain, h), 'the hash does not verify its own password')
                self.assertFalse(api.verify_password(plain + 'x', h), 'a password one character longer verifies: the tail was cut')
                self.assertFalse(api.verify_password(plain[:-1] or 'y', h))

    def test_without_bcrypt_every_password_is_pbkdf2_and_nothing_is_limited(self):
        real = api._BCRYPT
        api._BCRYPT = False
        try:
            h = api.hash_password(_pw(100))
            self.assertTrue(h.startswith('pbkdf2$'))
            self.assertTrue(api.verify_password(_pw(100), h))
            self.assertEqual(api._validate_password_policy(_pw(100)), (True, ''), 'the limit is bcrypt\'s: without bcrypt there is none')
            self.assertEqual(api._validate_password_policy(_pw(1024)), (True, ''))
        finally:
            api._BCRYPT = real

    def test_the_policy_check_is_the_one_place_the_web_refuses_and_it_is_not_a_setting(self):
        if not HAVE_BCRYPT:
            self.skipTest('bcrypt is not installed')
        self.set_cfg(password_min_length=0, password_require_classes=False, password_breach_check=False)
        self.assertEqual(api._validate_password_policy(_pw(72)), (True, ''))
        self.assertEqual(api._validate_password_policy(_pw(73)), (False, MESSAGE))


class TestSigningInWithALongPassword(_Base):
    """An account whose password is over 72 bytes can exist: it was made before bcrypt was installed, or by an installer or the offline
    tool. Signing in with it must work, and the upgrade to bcrypt that happens at sign-in must leave it alone."""

    def test_a_long_password_in_a_pbkdf2_hash_signs_in_and_the_hash_is_not_rewritten(self):
        if not HAVE_BCRYPT:
            self.skipTest('bcrypt is not installed: nothing would be upgraded')
        long_pw = _pw(100)
        stored = api._pbkdf2_hash(long_pw)
        self.add_user('dora', 'viewer', password_hash=stored)
        for n in range(3):
            st, d = self.try_sign_in('dora', long_pw)
            self.assertEqual(st, 200, 'a sign-in with a long password failed (%d): %s' % (n, d))
            self.assertTrue(d.get('ok'), d)
            self.assertEqual(self.rec('dora')['password_hash'], stored, 'the PBKDF2 hash was rewritten at sign-in %d' % n)

    def test_a_short_password_in_a_pbkdf2_hash_is_still_upgraded_to_bcrypt(self):
        if not HAVE_BCRYPT:
            self.skipTest('bcrypt is not installed: nothing would be upgraded')
        self.add_user('erik', 'viewer', password_hash=api._pbkdf2_hash(OLD))
        self.assertTrue(self.sign_in('erik', OLD)['ok'])
        self.assertTrue(self.rec('erik')['password_hash'].startswith('$2'), 'the control: a short password is upgraded as it always was')
        self.assertTrue(self.sign_in('erik', OLD)['ok'])

    def test_the_account_with_a_long_password_can_change_it_to_one_the_form_accepts(self):
        if not HAVE_BCRYPT:
            self.skipTest('bcrypt is not installed')
        self.add_user('dora', 'viewer', password_hash=api._pbkdf2_hash(_pw(100)))
        token = self.sign_in('dora', _pw(100))['token']
        st, d = self.change(token, _pw(100), _pw(60), name='dora')
        self.assertEqual(st, 200, d)
        self.assertTrue(self.rec('dora')['password_hash'].startswith('$2'))
        self.assertTrue(self.sign_in('dora', _pw(60))['ok'])


# ── the other places that hash a password with bcrypt ─────────────────────────────────────────────────────────────────────────
# Each is a script, run here with real passwords: 100 characters, exactly 72 bytes, a short one, and with bcrypt missing.

_PY_ENV = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'PYTHONPATH', 'TMPDIR')}
_SAFE_WRITE = "def safe_write(path, data):\n    open(path, 'w').write(data)\n"
_NO_BCRYPT = "import sys\nsys.modules['bcrypt'] = None\n"        # `import bcrypt` then raises ImportError, as on a host without it
_ABSENT = object()


def _heredoc(path, needle):
    """The body of the here-document of a shell script that contains `needle`."""
    text = (_ROOT / path).read_text()
    for m in re.finditer(r"<<'(\w+)'[^\n]*\n(.*?)\n\1\n", text, re.S):
        if needle in m.group(2):
            return m.group(2)
    raise AssertionError('no here-document with %r in %s' % (needle, path))


def _run_admin_snippet(code, env, no_bcrypt=False):
    src = (_NO_BCRYPT if no_bcrypt else '') + code
    # not isolated mode: that drops the user site, where a developer's bcrypt may live, and the script would then take its no-bcrypt branch
    out = subprocess.run([sys.executable, '-c', src], env=dict(_PY_ENV, **env), capture_output=True, text=True, timeout=120, cwd=tempfile.gettempdir())
    if out.returncode != 0:
        raise AssertionError('the installer script failed:\n' + out.stderr[-1500:])


class _Installers(unittest.TestCase):
    """Name, here-document marker, how its users file is found, and the text of the script's own path to rewrite (if any)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-longpw-inst-'))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def snippets(self):
        users = self.tmp / 'users.json'
        install_server = _heredoc('install-server.sh', 'RP_ADMIN_PASS')
        self.assertEqual(install_server.count("'/var/lib/remotepower/users.json'"), 1, 'the users file of install-server.sh moved')
        entry = _heredoc('docker/entrypoint.sh', 'RP_ADMIN_PASS')
        return {
            'install.sh': (_heredoc('install.sh', 'RP_ADMIN_PASS'), {'RP_USERS': str(users)}, users),
            'install-server.sh': (install_server.replace("'/var/lib/remotepower/users.json'", repr(str(users))), {}, users),
            'docker/entrypoint.sh': (_SAFE_WRITE + entry, {'USERS_FILE': str(users)}, users),
        }

    def make(self, name, password, no_bcrypt=False):
        code, env, users = self.snippets()[name]
        if users.exists():
            users.unlink()
        _run_admin_snippet(code, dict(env, RP_ADMIN_USER='admin', RP_ADMIN_PASS=password), no_bcrypt=no_bcrypt)
        return json.loads(users.read_text())['admin']['password_hash']

    def test_each_installer_makes_a_hash_the_server_verifies_for_every_length(self):
        for name in self.snippets():
            for label, password in (('100 characters', _pw(100)), ('1024 characters', _pw(1024)), ('exactly 72 bytes', _pw(72)),
                                    ('a short one', 'Short-Passw0rd!'), ('25 euro signs', '€' * 25)):
                with self.subTest(installer=name, password=label):
                    h = self.make(name, password)
                    over = len(password.encode()) > 72
                    want = 'pbkdf2$' if (over or not HAVE_BCRYPT) else '$2'
                    self.assertTrue(h.startswith(want), (name, label, h[:12]))
                    self.assertTrue(api.verify_password(password, h), '%s: the account cannot sign in with its own password (%s)' % (name, label))
                    self.assertFalse(api.verify_password(password + 'x', h), '%s: the password was cut (%s)' % (name, label))

    def test_without_bcrypt_each_installer_makes_pbkdf2_the_server_reads(self):
        # the Docker entrypoint's fallback was a bare SHA-256, which the server does not accept: nobody could sign in
        for name in self.snippets():
            for password in ('Short-Passw0rd!', _pw(100)):
                with self.subTest(installer=name, length=len(password)):
                    h = self.make(name, password, no_bcrypt=True)
                    self.assertTrue(h.startswith('pbkdf2$'), (name, h[:12]))
                    self.assertTrue(api.verify_password(password, h), '%s: the hash it makes without bcrypt is not one the server reads' % name)


class TestTheOfflineTool(unittest.TestCase):

    def namespace(self, no_bcrypt=False):
        src = (_ROOT / 'server' / 'remotepower-passwd').read_text()
        start = src.index('try:\n    import bcrypt as _bcrypt')
        end = src.index('def hash_type(')
        code = (_NO_BCRYPT if no_bcrypt else '') + 'import hashlib, secrets\n' + src[start:end]
        ns = {}
        # _NO_BCRYPT sets sys.modules['bcrypt'] to None, and this runs in the test process: left that way, every module that imports bcrypt after this one fails
        # ("import of bcrypt halted; None in sys.modules": test_session_gates_allow_logout did, in a shared run). It is put back as it was, or removed if it was not there.
        had = sys.modules.get('bcrypt', _ABSENT)
        try:
            exec(compile(code, 'remotepower-passwd', 'exec'), ns)        # the tool's own hash_password and what it needs, nothing else of it
        finally:
            if had is _ABSENT:
                sys.modules.pop('bcrypt', None)
            else:
                sys.modules['bcrypt'] = had
        return ns

    def test_simulating_a_host_without_bcrypt_does_not_leave_it_blocked_for_the_rest_of_the_process(self):
        before = sys.modules.get('bcrypt', _ABSENT)
        ns = self.namespace(no_bcrypt=True)
        self.assertFalse(ns['_BCRYPT'], 'control: the namespace really saw no bcrypt')
        self.assertIs(sys.modules.get('bcrypt', _ABSENT), before, "sys.modules['bcrypt'] was left as the snippet set it")

    def test_the_tool_hashes_every_length_the_way_the_server_does_and_never_cuts_a_password(self):
        ns = self.namespace()
        for label, password in (('100 characters', _pw(100)), ('exactly 72 bytes', _pw(72)), ('short', 'Short-Passw0rd!'), ('euro signs', '€' * 25)):
            with self.subTest(password=label):
                said = io.StringIO()
                with contextlib.redirect_stdout(said):
                    h = ns['hash_password'](password)
                over = len(password.encode()) > 72
                if over:
                    self.assertIn('longer than 72 bytes', said.getvalue(), 'the tool does not say why it is not using bcrypt')
                else:
                    self.assertEqual(said.getvalue(), '')
                want = 'pbkdf2$' if (over or not ns['_BCRYPT']) else '$2'
                self.assertTrue(h.startswith(want), (label, h[:12]))
                self.assertTrue(api.verify_password(password, h))
                self.assertFalse(api.verify_password(password + 'x', h))

    def test_without_bcrypt_it_is_pbkdf2_for_all(self):
        ns = self.namespace(no_bcrypt=True)
        self.assertFalse(ns['_BCRYPT'])
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            h = ns['hash_password']('Short-Passw0rd!')
        self.assertTrue(h.startswith('pbkdf2$'))
        self.assertIn('bcrypt not installed', said.getvalue())


class TestEveryPlaceThatHashesWithBcryptIsListedAndGuarded(unittest.TestCase):
    """A walk of the repository, not a list that someone has to remember: a file that calls bcrypt.hashpw is a place, and a new place fails
    this until it is added below and follows the rule (a 72-byte test just before the call)."""

    SITES = {'server/cgi-bin/api.py', 'server/remotepower-passwd', 'install.sh', 'install-server.sh', 'docker/entrypoint.sh'}
    SKIP_DIRS = {'.git', 'tests', 'docs', '.ruff_cache', '__pycache__', 'node_modules', 'dist', '.codeql-cache'}
    GUARD = re.compile(r'<=\s*72|>\s*72|_over_bcrypt_limit\(|_BCRYPT_MAX_BYTES')

    def _paths(self):
        """The tracked files of the repository, which leaves out what a build leaves in a directory git ignores (a makepkg tree under packaging/aur holds a
        symlink that points at a path of the install, and a walk of the disk fell over it). A tree with no .git is walked, and its symlinks are left alone."""
        try:
            out = subprocess.run(['git', 'ls-files', '-z'], cwd=_ROOT, capture_output=True, timeout=60, check=True).stdout.decode().split('\0')
            paths = [_ROOT / rel for rel in out if rel]
        except (OSError, subprocess.SubprocessError):
            paths = []
            for dirpath, dirs, files in os.walk(_ROOT):
                dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
                paths.extend(Path(dirpath) / name for name in files)
        return [p for p in paths if p.is_file() and not p.is_symlink() and not (set(p.relative_to(_ROOT).parts) & self.SKIP_DIRS)]

    def walk(self):
        found = {}
        for p in self._paths():
            if p.suffix not in ('.py', '.sh', '') or p.stat().st_size > 6_000_000:
                continue
            try:
                text = p.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if 'hashpw(' in text:
                found[str(p.relative_to(_ROOT))] = text
        return found

    def test_the_places_are_the_five_and_a_new_one_has_to_be_added_here(self):
        found = self.walk()
        self.assertEqual(set(found), self.SITES, 'a place that hashes a password with bcrypt appeared or went: add it here once it follows the rule')

    def test_each_call_has_the_72_byte_rule_just_before_it(self):
        for rel, text in self.walk().items():
            lines = text.splitlines()
            calls = [i for i, ln in enumerate(lines) if 'hashpw(' in ln and not ln.lstrip().startswith(('#', '"""'))]
            self.assertTrue(calls, rel)
            for i in calls:
                near = '\n'.join(lines[max(0, i - 12):i + 1])
                self.assertTrue(self.GUARD.search(near), '%s:%d calls hashpw with no 72-byte rule in the 12 lines before it' % (rel, i + 1))

    def test_the_walk_sees_the_repository(self):
        # the control: a walk that found nothing would pass the two tests above for the wrong reason
        found = self.walk()
        self.assertGreaterEqual(len(found), 5, sorted(found))
        self.assertIn('server/cgi-bin/api.py', found)
        self.assertTrue(srcpin.py_function(found['server/cgi-bin/api.py'], 'hash_password'))


if __name__ == '__main__':
    unittest.main()
