#!/usr/bin/env python3
"""Setting somebody else's password takes their account over, so it asks for a step-up like creating an administrator does.

Creating an administrator account and promoting one both ask the caller to have re-entered their own password in the last ten minutes. An
API key has no person at the keyboard, so it can never do either. `POST /api/users/passwd` reached the same end without asking: an
administrator key set the password of the platform operator's account, signed in as it with the password it had just chosen, stepped up
with that password and then did everything the key had been refused (a new administrator, the governance switches).

What this holds, with real sessions and real keys through the real route table and the real token check (a process of its own on a data
directory of its own, so that nothing is stubbed):

* an administrator key sets nobody's password: not the operator's, not a viewer's, not an account with a custom role. It gets the answer
  the other two routes give (403, `step_up_required`), the stored hash of the account is unchanged, nothing signs in with the password it
  tried, and no session is touched;
* an administrator's session is refused the same way until it has stepped up, and then it works as before: the account is flagged to
  change the password, signed out of its sessions, and the administrator keeps theirs;
* a tenant administrator reaches an account of another tenant with a 404 that is the answer for a name that does not exist (the step-up
  question is not asked first, so the refusal does not say which names exist), and an account of its own tenant after a step-up;
* a person changing their own password is not asked for a step-up (the old password is the proof), and a viewer still cannot set
  anybody else's password and is told so in the old words;
* the page asks for the step-up and sends the request again (the real functions, run under node);
* the class: the functions that write a user's password hash or role are listed by syntax tree, and each either asks for the step-up or
  is on the list of the ones that are somebody's own sign-in, the identity provider's answer or the first start.
"""
import ast
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import real_stack  # noqa: E402
import srcpin  # noqa: E402

_ROOT = real_stack.ROOT
_CGI = real_stack.CGI
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_NODE = shutil.which('node')

_DRIVER = r'''
ATTACK = 'Attacker-Passw0rd!77'
NEW = 'Fresh-Passw0rd!x91'
add_key('CI-KEY', 'ci')                                    # an administrator key of the platform operator's tenant
add_key('ACME-KEY', 'acme-ci', tenant='acme')              # an administrator key of the tenant acme
passwd = lambda token, who, pw=NEW, **more: call('POST', '/api/users/passwd', token, dict({'username': who, 'new_password': pw}, **more))
hashes = lambda: {u: r['password_hash'] for u, r in get('USERS_FILE').items()}
before = hashes()
sessions_before = sorted(get('TOKENS_FILE'))

# an administrator key
out['key_admin'] = passwd('CI-KEY', 'admin', ATTACK)
out['key_viewer'] = passwd('CI-KEY', 'vera', ATTACK)
out['key_custom_role'] = passwd('CI-KEY', 'olga', ATTACK)
out['key_login'] = call('POST', '/api/login', None, {'username': 'admin', 'password': ATTACK})
out['key_controls'] = [call('POST', '/api/users', 'CI-KEY', {'username': 'mallory', 'password': ATTACK, 'role': 'admin'})[1],
                       call('PATCH', '/api/users/vera', 'CI-KEY', {'role': 'admin'})[1]]
# an administrator key of a tenant
out['acme_key_same_tenant_viewer'] = passwd('ACME-KEY', 'vic', ATTACK)
out['acme_key_same_tenant_admin'] = passwd('ACME-KEY', 'alice', ATTACK)
out['acme_key_other_tenant'] = passwd('ACME-KEY', 'admin', ATTACK)
out['after_keys'] = {'hashes_unchanged': hashes() == before, 'sessions_kept': sorted(get('TOKENS_FILE')) == sessions_before}

# a viewer
out['viewer_sets_admin'] = passwd(SESS['vera'], 'admin')
out['viewer_sets_viewer'] = passwd(SESS['vera'], 'vic')

# a tenant administrator, who has not stepped up
out['tenant_admin_other_tenant'] = passwd(SESS['alice'], 'admin')
out['tenant_admin_unknown_name'] = passwd(SESS['alice'], 'no-such-account')
out['tenant_admin_own_tenant_no_step_up'] = passwd(SESS['alice'], 'vic')
out['tenant_admin_unchanged'] = hashes() == before
out['tenant_admin_step_up'] = call('POST', '/api/auth/step-up', SESS['alice'], {'password': PW['alice']})
out['tenant_admin_own_tenant'] = passwd(SESS['alice'], 'vic')
out['tenant_admin_other_tenant_after'] = passwd(SESS['alice'], 'admin')

# the operator's administrator session
out['admin_no_step_up'] = passwd(SESS['admin'], 'olga')
out['olga_unchanged'] = hashes()['olga'] == before['olga']
out['admin_step_up'] = call('POST', '/api/auth/step-up', SESS['admin'], {'password': PW['admin']})
olga_sessions = lambda: len([r for r in get('TOKENS_FILE').values() if r.get('user') == 'olga'])
out['olga_sessions_before'] = olga_sessions()
out['admin_after_step_up'] = passwd(SESS['admin'], 'olga')
rec = get('USERS_FILE')['olga']
out['olga_after'] = {'changed': rec['password_hash'] != before['olga'], 'flagged': rec.get('must_change_password'), 'sessions': olga_sessions()}
out['olga_signs_in'] = call('POST', '/api/login', None, {'username': 'olga', 'password': NEW})
out['admin_keeps_the_session'] = call('GET', '/api/users', SESS['admin'])[0]

# a person changing their own password: the old password is the proof, no step-up
out['own_wrong_old_password'] = passwd(SESS['rita'], 'rita', old_password='not-the-password')
out['own_change'] = passwd(SESS['rita'], 'rita', old_password=PW['rita'])
out['own_change_as_administrator'] = passwd(SESS['bob'], 'bob', old_password=PW['bob'])
out['admin_sets_another_admin'] = passwd(SESS['admin'], 'bob')       # last: it signs bob out
'''


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def asks_for_a_step_up(self, name):
        st, body = self.out[name]
        self.assertEqual(st, 403, (name, body))
        self.assertEqual((body or {}).get('code'), 'step_up_required', (name, body))

    def test_an_administrator_key_sets_nobodys_password(self):
        for name in ('key_admin', 'key_viewer', 'key_custom_role'):
            with self.subTest(target=name):
                self.asks_for_a_step_up(name)

    def test_the_password_the_key_tried_signs_nobody_in(self):
        st, body = self.out['key_login']          # a refused sign-in is a 200 with ok false, the same answer whatever the reason
        self.assertFalse((body or {}).get('ok'), 'the key signed in as the operator with the password it chose')
        self.assertNotIn('token', body or {})

    def test_the_other_two_routes_the_key_is_refused_on_still_refuse_it(self):
        """The control: the refusal on these two is the one the password route has to match."""
        for body in self.out['key_controls']:
            self.assertEqual((body or {}).get('code'), 'step_up_required', body)

    def test_a_tenant_administrators_key_is_refused_for_its_own_tenants_accounts_too(self):
        self.asks_for_a_step_up('acme_key_same_tenant_viewer')
        self.asks_for_a_step_up('acme_key_same_tenant_admin')

    def test_a_tenant_key_reaching_for_another_tenant_gets_the_answer_for_a_name_that_does_not_exist(self):
        self.assertEqual(self.out['acme_key_other_tenant'][0], 404)

    def test_a_refused_attempt_changes_nothing(self):
        self.assertEqual(self.out['after_keys'], {'hashes_unchanged': True, 'sessions_kept': True})
        self.assertTrue(self.out['tenant_admin_unchanged'])
        self.assertTrue(self.out['olga_unchanged'])

    def test_an_administrators_session_asks_until_it_has_stepped_up(self):
        self.asks_for_a_step_up('admin_no_step_up')
        self.asks_for_a_step_up('tenant_admin_own_tenant_no_step_up')

    def test_after_the_step_up_it_works_as_it_did(self):
        self.assertEqual(self.out['admin_step_up'][0], 200, self.out['admin_step_up'])
        self.assertEqual(self.out['admin_after_step_up'], [200, {'ok': True}])
        after = self.out['olga_after']
        self.assertTrue(after['changed'])
        self.assertTrue(after['flagged'], 'an administrator chose it, so the person changes it at the first sign-in')
        self.assertEqual((self.out['olga_sessions_before'], after['sessions']), (1, 0), 'the account is signed out of its sessions')
        self.assertEqual(self.out['olga_signs_in'][0], 200)
        self.assertEqual(self.out['admin_keeps_the_session'], 200, 'the administrator keeps their own session')
        self.assertEqual(self.out['admin_sets_another_admin'], [200, {'ok': True}], 'an administrator account is reachable after a step-up too')

    def test_a_tenant_administrator_can_after_the_step_up_for_its_own_tenant_only(self):
        self.assertEqual(self.out['tenant_admin_step_up'][0], 200)
        self.assertEqual(self.out['tenant_admin_own_tenant'], [200, {'ok': True}])
        self.assertEqual(self.out['tenant_admin_other_tenant_after'][0], 404, 'the step-up does not open another tenant')

    def test_another_tenants_account_is_answered_like_a_name_that_does_not_exist(self):
        """Before the step-up the answer for the operator's account and for a name nobody has is one answer: the question of the step-up is
        not asked first, so it cannot say which names exist."""
        self.assertEqual(self.out['tenant_admin_other_tenant'], self.out['tenant_admin_unknown_name'])
        self.assertEqual(self.out['tenant_admin_other_tenant'][0], 404)

    def test_a_viewer_is_told_what_it_always_was(self):
        for name in ('viewer_sets_admin', 'viewer_sets_viewer'):
            st, body = self.out[name]
            self.assertEqual((st, (body or {}).get('error')), (403, "Cannot change another user's password"), name)

    def test_your_own_password_is_not_a_step_up_and_still_wants_the_old_one(self):
        st, body = self.out['own_wrong_old_password']
        self.assertEqual((st, (body or {}).get('error')), (403, 'Old password incorrect'))
        self.assertEqual(self.out['own_change'], [200, {'ok': True}])
        self.assertEqual(self.out['own_change_as_administrator'], [200, {'ok': True}])


# ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────

_STUBS = r"""
const out = {apiCalls: [], toasts: [], closed: [], changed: 0, modal: 0};
const queue = [];
const DECISION = __DECISION__;
const values = {'passwd-username': '__USER__', 'passwd-old': '', 'passwd-new': 'Fresh-Passw0rd!x91'};
const document = {getElementById(id) { return id in values ? {value: values[id]} : null; }};
function toast(m, t) { out.toasts.push([String(m), t || '']); }
function failToast(r) { out.toasts.push(['FAIL', (r && (r.code || r.error)) || '']); }
function closeModal(id) { out.closed.push(id); }
function getMe() { return 'admin'; }
function _passwordChangedHere() { out.changed++; }
async function _openStepUpModal() { out.modal++; return DECISION; }
async function api(method, path, body) { out.apiCalls.push(method + ' ' + path); return queue.shift(); }
"""
_STEP = {'error': 'step-up re-authentication required', 'code': 'step_up_required'}


@unittest.skipUnless(_NODE, 'node is needed to run the client functions')
class TestThePageAsksAndSendsAgain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app = (_JS / 'app.js').read_text()
        cls.funcs = ['async ' + srcpin.js_function(app, 'withStepUp'), 'async ' + srcpin.js_function(app, 'submitPasswd')]
        assert 'async function withStepUp(' in app and 'async function submitPasswd(' in app

    def run_js(self, responses, user='vera', decision='true'):
        script = (_STUBS.replace('__DECISION__', decision).replace('__USER__', user) + '\n'.join(self.funcs) + '\n'
                  + 'queue.push(' + ', '.join(json.dumps(r) for r in responses) + ');\n'
                  + '(async () => { await submitPasswd(); console.log(JSON.stringify(out)); })();')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'run.js'
            path.write_text(script)
            proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_resetting_someone_elses_asks_for_the_password_and_sends_again(self):
        out = self.run_js([_STEP, {'ok': True}])
        self.assertEqual(out['modal'], 1)
        self.assertEqual(out['apiCalls'], ['POST /users/passwd'] * 2)
        self.assertEqual(out['toasts'], [['Password updated', 'success']])
        self.assertEqual(out['closed'], ['passwd-modal'])

    def test_declining_the_prompt_sends_nothing_more_and_shows_no_error(self):
        """The prompt is the answer, and a person who closes it has not met an error."""
        out = self.run_js([_STEP], decision='false')
        self.assertEqual(out['modal'], 1)
        self.assertEqual(out['apiCalls'], ['POST /users/passwd'])
        self.assertEqual(out['toasts'], [])
        self.assertEqual(out['closed'], [])

    def test_another_refusal_is_shown(self):
        out = self.run_js([{'error': 'User not found'}])
        self.assertEqual(out['modal'], 0)
        self.assertEqual(out['toasts'], [['FAIL', 'User not found']])

    def test_your_own_password_does_not_ask(self):
        out = self.run_js([{'ok': True}], user='admin')
        self.assertEqual(out['modal'], 0)
        self.assertEqual(out['apiCalls'], ['POST /users/passwd'])
        self.assertEqual(out['changed'], 1)


# ── the class ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# The functions that write a user's password hash or role and do not ask for a step-up, each with the reason it is not a caller taking an
# account over. A function that is not here and does not ask fails the build; so does an entry that no longer matches.
_NOT_AN_ADMINISTRATORS_REQUEST = {
    '_provision_or_promote_user': "sign-in through the identity provider: the provider's answer decides the role, and no administrator request is involved",
    '_scim_set_user_role': 'reached only with the SCIM bearer token, which switching SCIM on or changing its token asks a step-up for',
    'ensure_default_user': 'the first start, before any caller exists',
    'handle_login': "the account's own sign-in: it stores a stronger hash of the password it has just checked, and provisions a directory account",
    'maybe_rehash': "the account's own sign-in: a stronger hash of the password it has just checked",
}
_ASKS = ('handle_user_create', 'handle_user_passwd', 'handle_user_update')


def _name(node):
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def _names(node, wanted):
    return any(_name(n) == wanted for n in ast.walk(node))


def users_store_writers_of_credentials():
    """{function: calls it makes} for every function of api.py and the handler modules that writes the users store and sets a user's
    password hash or role: a subscript store (`rec['role'] = ...`), a user record written out as a dict that holds a password hash, or a
    call of `_set_password`. A dict with a `role` key alone is not one (the sign-in answers with one)."""
    found = {}
    for path in [_CGI / 'api.py'] + sorted(_CGI.glob('*_handlers.py')):
        for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = {_name(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)}
            writes_store = any(isinstance(n, ast.Call) and _name(n.func) in ('_LockedUpdate', 'save', 'locked_update')
                               and any(_names(a, 'USERS_FILE') for a in n.args) for n in ast.walk(fn))
            if not writes_store:
                continue
            sets = '_set_password' in calls
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign):
                    sets = sets or any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                       and t.slice.value in ('role', 'password_hash') for t in n.targets)
                if isinstance(n, ast.Dict):
                    sets = sets or any(isinstance(k, ast.Constant) and k.value == 'password_hash' for k in n.keys)
            if sets:
                found[fn.name] = calls
    return found


class TestEveryWriterOfAPasswordOrARoleAsksOrIsNotARequest(unittest.TestCase):

    def test_the_population_is_the_one_known_and_every_member_is_accounted_for(self):
        found = users_store_writers_of_credentials()
        self.assertGreaterEqual(len(found), 8, 'the scan sees nothing: %s' % sorted(found))
        for name in _ASKS:
            self.assertIn(name, found, 'the scan no longer sees %s, which it must (the control of this scan)' % name)
        unaccounted = sorted(n for n in found if n not in _ASKS and n not in _NOT_AN_ADMINISTRATORS_REQUEST)
        self.assertEqual(unaccounted, [], 'a function now writes a password hash or a role and neither asks for a step-up nor is listed: %s' % unaccounted)
        stale = sorted(n for n in _NOT_AN_ADMINISTRATORS_REQUEST if n not in found)
        self.assertEqual(stale, [], 'listed, but no longer writes a password hash or a role: %s' % stale)

    def test_the_three_that_take_an_account_over_ask(self):
        found = users_store_writers_of_credentials()
        for name in _ASKS:
            with self.subTest(handler=name):
                self.assertIn('require_step_up', found[name])

    def test_the_listed_ones_do_not_ask_and_are_not_routes_that_an_administrator_calls(self):
        """The list is not a way round the rule: none of its entries is a handler of an administrator's request."""
        found = users_store_writers_of_credentials()
        for name in _NOT_AN_ADMINISTRATORS_REQUEST:
            with self.subTest(function=name):
                self.assertFalse({'require_admin_auth', 'require_auth'} & found[name], '%s checks a caller, so it answers a request' % name)


if __name__ == '__main__':
    unittest.main()
