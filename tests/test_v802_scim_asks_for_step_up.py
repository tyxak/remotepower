#!/usr/bin/env python3
"""The SCIM token puts any account in the admin group, so switching SCIM on or setting its token asks for a step-up.

`PATCH /api/users/<name>` asks the caller to have re-entered their own password before it promotes an account to administrator, and an API
key can never do that. The SCIM routes do the same promotion for whoever holds the SCIM bearer token (adding an account to the `admin`
group sets its role), and the token and the switch were ordinary settings: an administrator key could create a viewer with a password it
chose, switch SCIM on with a token it chose, add the account to the admin group over SCIM, sign in as it, step up with its own password and
do what the key had been refused.

What this holds, with real sessions and keys through the real route table and the real token check (a process of its own on a data
directory of its own, so that nothing is stubbed):

* the whole chain stops at the second step: a key that tries to switch SCIM on, or to set its token, in any of the forms the save reads
  (`true`, `1`, `"true"`) is refused with `step_up_required`, nothing is stored, and the token it chose opens nothing;
* once SCIM is on, a key cannot take the token over either: clearing it while SCIM stays on (the save mints a new one and sends it back
  to the caller), replacing it, or sending ` __clear__` with a space (the save stores that text as the token) are all refused, and the
  stored token is the one it was;
* a person who has stepped up can switch it on, gets the token once, and the identity provider then works as before;
* the gate asks only where it must: an ordinary settings save, a save that repeats the state, switching SCIM off, and clearing the token
  while SCIM is off all go through without a step-up;
* restoring a saved configuration that switches SCIM on, or swaps its token, asks as well, since a restore swaps the whole document;
* both settings are named in the list of switches that ask, so the audit trail names them;
* the page asks for the step-up and sends the save again, and says nothing when the prompt is declined (the real functions, under node).
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

_CGI = real_stack.CGI
_JS = real_stack.ROOT / 'server' / 'html' / 'static' / 'js'
_NODE = shutil.which('node')

_DRIVER = r'''
CHOSEN = 'chosen-scim-token-0123456789abcdef'
PATCH_ADMIN_GROUP = {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                     'Operations': [{'op': 'add', 'path': 'members', 'value': [{'value': 'mal'}]}]}
bearer = lambda t: {'Authorization': 'Bearer ' + t}
scim = lambda t: call('PATCH', '/api/scim/v2/Groups/admin', None, PATCH_ADMIN_GROUP, headers=bearer(t))
cfg = lambda: get('CONFIG_FILE')
state = lambda: {'enabled': bool(cfg().get('scim_enabled')), 'token': cfg().get('scim_token') or ''}
audit = lambda: [r for r in (lambda a: a.get('entries', a) if isinstance(a, dict) else a)(get('AUDIT_LOG_FILE')) if isinstance(r, dict)]

add_key('CI-KEY', 'ci')                                       # an administrator key of the platform operator's tenant
add_user('admin2', 'admin'); session('admin2')                # operator administrators, none of which has stepped up yet
add_user('admin3', 'admin'); session('admin3')
add_user('mal', 'viewer')                                     # the account the chain wants as an administrator

# the chain, as a key walks it
out['promote_directly'] = call('PATCH', '/api/users/mal', 'CI-KEY', {'role': 'admin'})
forms = {'true': True, 'one': 1, 'string': 'true'}
out['key_switches_it_on'] = {name: call('POST', '/api/config', 'CI-KEY', {'scim_enabled': v}) for name, v in forms.items()}     # the save mints a token and sends it back
out['key_switches_it_on_with_its_own_token'] = call('POST', '/api/config', 'CI-KEY', {'scim_enabled': True, 'scim_token': CHOSEN})
out['key_sets_a_token_while_it_is_off'] = call('POST', '/api/config', 'CI-KEY', {'scim_token': CHOSEN})
out['stored_after_the_key'] = state()
out['the_chosen_token_opens'] = scim(CHOSEN)
out['mal_role'] = get('USERS_FILE')['mal']['role']

# a person
out['admin_without_a_step_up'] = call('POST', '/api/config', SESS['admin2'], {'scim_enabled': True})
out['step_up'] = call('POST', '/api/auth/step-up', SESS['admin2'], {'password': PW['admin2']})
out['admin_switches_it_on'] = call('POST', '/api/config', SESS['admin2'], {'scim_enabled': True})
minted = (out['admin_switches_it_on'][1] or {}).get('scim_token') or ''
out['minted_token_length'] = len(minted)
out['stored_after_the_person'] = {'enabled': state()['enabled'], 'token_is_the_minted_one': state()['token'] == minted and bool(minted)}
out['the_identity_provider_works'] = scim(minted)
out['mal_role_after_the_provider'] = get('USERS_FILE')['mal']['role']
out['named_in_the_audit_trail'] = [r['detail'] for r in audit() if r.get('action') == 'governance_config_change']

# once it is on, a key cannot take the token over
out['key_clears_the_token'] = call('POST', '/api/config', 'CI-KEY', {'scim_token': '__clear__'})
out['key_replaces_the_token'] = call('POST', '/api/config', 'CI-KEY', {'scim_token': CHOSEN})
out['key_sends_a_spaced_clear'] = call('POST', '/api/config', 'CI-KEY', {'scim_token': ' __clear__'})
out['key_clears_and_keeps_it_on'] = call('POST', '/api/config', 'CI-KEY', {'scim_enabled': True, 'scim_token': '__clear__'})
out['token_is_still_the_minted_one'] = state()['token'] == minted
out['the_chosen_token_still_opens_nothing'] = scim(CHOSEN)[0]

# the gate asks only where it must
out['key_saves_something_else'] = call('POST', '/api/config', 'CI-KEY', {'brand_name': 'Acme Operations'})
out['key_repeats_the_state'] = call('POST', '/api/config', 'CI-KEY', {'scim_enabled': True})
out['key_switches_it_off'] = call('POST', '/api/config', 'CI-KEY', {'scim_enabled': False})
out['stored_after_off'] = state()['enabled']
out['the_token_after_off_opens_nothing'] = scim(minted)[0]
out['key_clears_the_token_while_off'] = call('POST', '/api/config', 'CI-KEY', {'scim_token': '__clear__'})
out['stored_after_clear'] = state()

# a restore swaps the whole document
revision = dict(cfg(), scim_enabled=True, scim_token='old-token-of-an-earlier-revision')
put('CONFIG_REVS_FILE', {'revisions': [{'id': 'rev-scim1', 'ts': now, 'user': 'someone', 'changed_keys': ['scim_enabled'], 'config': revision}]})
out['key_restores_it'] = call('POST', '/api/config/revisions/restore', 'CI-KEY', {'id': 'rev-scim1'})
out['admin_without_a_step_up_restores_it'] = call('POST', '/api/config/revisions/restore', SESS['admin3'], {'id': 'rev-scim1'})
out['stored_after_refused_restores'] = state()
out['admin_with_a_step_up_restores_it'] = call('POST', '/api/config/revisions/restore', SESS['admin2'], {'id': 'rev-scim1'})
out['stored_after_the_restore'] = state()
# SCIM stays on, and a revision carries another token: which secret is live changes, so that asks as well
revision2 = dict(cfg(), scim_enabled=True, scim_token='another-token-of-an-earlier-revision')
put('CONFIG_REVS_FILE', {'revisions': [{'id': 'rev-scim2', 'ts': now, 'user': 'someone', 'changed_keys': ['scim_token'], 'config': revision2}]})
out['key_swaps_the_token_by_a_restore'] = call('POST', '/api/config/revisions/restore', 'CI-KEY', {'id': 'rev-scim2'})
out['admin_without_a_step_up_swaps_the_token'] = call('POST', '/api/config/revisions/restore', SESS['admin3'], {'id': 'rev-scim2'})
out['stored_after_the_refused_swaps'] = state()
'''

_STEP_UP = 'step_up_required'


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('flask is not installed')
        cls.out = real_stack.run(_DRIVER)

    def asks(self, answer, what):
        st, body = answer
        self.assertEqual((st, (body or {}).get('code')), (403, _STEP_UP), (what, st, body))

    def test_the_control_the_key_is_refused_on_is_still_refused(self):
        self.asks(self.out['promote_directly'], 'PATCH /api/users')

    def test_a_key_cannot_switch_scim_on_in_any_form_the_save_reads(self):
        for name, answer in self.out['key_switches_it_on'].items():
            with self.subTest(form=name):
                self.asks(answer, 'scim_enabled=' + name)
        self.asks(self.out['key_switches_it_on_with_its_own_token'], 'scim_enabled with a token of its own')

    def test_a_key_cannot_set_a_token_while_scim_is_off_either(self):
        """It would be live on the day somebody else switches SCIM on and keeps the token that is there."""
        self.asks(self.out['key_sets_a_token_while_it_is_off'], 'scim_token while off')

    def test_nothing_was_stored_and_the_token_it_chose_opens_nothing(self):
        self.assertEqual(self.out['stored_after_the_key'], {'enabled': False, 'token': ''})
        self.assertEqual(self.out['the_chosen_token_opens'][0], 404, 'SCIM answers 404 while it is off')
        self.assertEqual(self.out['mal_role'], 'viewer')

    def test_an_administrator_session_asks_until_it_has_stepped_up_and_then_switches_it_on(self):
        self.asks(self.out['admin_without_a_step_up'], 'a session that has not stepped up')
        self.assertEqual(self.out['step_up'][0], 200)
        st, body = self.out['admin_switches_it_on']
        self.assertEqual(st, 200, body)
        self.assertGreaterEqual(self.out['minted_token_length'], 30, 'the token is sent once, in the answer')
        self.assertEqual(self.out['stored_after_the_person'], {'enabled': True, 'token_is_the_minted_one': True})

    def test_the_identity_provider_works_for_the_person_who_switched_it_on(self):
        self.assertEqual(self.out['the_identity_provider_works'][0], 200)
        self.assertEqual(self.out['mal_role_after_the_provider'], 'admin', 'SCIM still sets roles; who may switch it on is what changed')

    def test_the_switch_is_named_in_the_audit_trail(self):
        details = self.out['named_in_the_audit_trail']
        self.assertTrue(any('scim_enabled' in d for d in details), details)

    def test_once_it_is_on_a_key_cannot_take_the_token_over(self):
        for name in ('key_clears_the_token', 'key_replaces_the_token', 'key_sends_a_spaced_clear', 'key_clears_and_keeps_it_on'):
            with self.subTest(attempt=name):
                self.asks(self.out[name], name)
        self.assertTrue(self.out['token_is_still_the_minted_one'])
        self.assertEqual(self.out['the_chosen_token_still_opens_nothing'], 401, 'a token that is not the stored one is a 401')

    def test_it_asks_only_where_it_must(self):
        self.assertEqual(self.out['key_saves_something_else'][0], 200, 'an ordinary settings save is not a step-up')
        self.assertEqual(self.out['key_repeats_the_state'][0], 200, 'repeating the state is not a change')
        self.assertEqual(self.out['key_switches_it_off'][0], 200, 'switching it off takes the power back and does not ask')
        self.assertFalse(self.out['stored_after_off'])
        self.assertEqual(self.out['the_token_after_off_opens_nothing'], 404)
        self.assertEqual(self.out['key_clears_the_token_while_off'][0], 200, 'with SCIM off nothing is minted, so clearing does not ask')
        self.assertEqual(self.out['stored_after_clear'], {'enabled': False, 'token': ''})

    def test_a_restore_that_switches_it_on_asks_too(self):
        self.asks(self.out['key_restores_it'], 'a key restoring a revision')
        self.asks(self.out['admin_without_a_step_up_restores_it'], 'a session that has not stepped up restoring a revision')
        self.assertEqual(self.out['stored_after_refused_restores'], {'enabled': False, 'token': ''})
        self.assertEqual(self.out['admin_with_a_step_up_restores_it'][0], 200)
        self.assertEqual(self.out['stored_after_the_restore'], {'enabled': True, 'token': 'old-token-of-an-earlier-revision'})

    def test_a_restore_that_swaps_the_token_of_a_scim_that_stays_on_asks_too(self):
        self.asks(self.out['key_swaps_the_token_by_a_restore'], 'a key restoring a revision with another token')
        self.asks(self.out['admin_without_a_step_up_swaps_the_token'], 'a session that has not stepped up, another token')
        self.assertEqual(self.out['stored_after_the_refused_swaps'], {'enabled': True, 'token': 'old-token-of-an-earlier-revision'})


_STUBS = r"""
const out = {apiCalls: [], toasts: [], modal: 0, reveal: null, settingsLoaded: 0};
const queue = [];
const DECISION = __DECISION__;
const reveal = {hidden: true, textContent: ''};
const fields = {'cfg-scim-enabled': {checked: __ENABLED__}, 'cfg-scim-token': {value: ''}, 'scim-token-reveal': reveal};
const document = {getElementById(id) { return fields[id] || null; }};
function toast(m, t) { out.toasts.push([String(m), t || '']); }
function failToast(r) { out.toasts.push(['FAIL', (r && (r.code || r.error)) || '']); }
function loadSettings() { out.settingsLoaded++; }
async function _openStepUpModal() { out.modal++; return DECISION; }
async function api(method, path, body) {
  out.apiCalls.push(method + ' ' + path + ' ' + JSON.stringify(body));
  const r = queue.shift();
  if (r && r.__reject) throw new Error('network');
  return r;
}
"""
_STEP = {'error': 'step-up re-authentication required', 'code': 'step_up_required'}


@unittest.skipUnless(_NODE, 'node is needed to run the client functions')
class TestThePageAsksAndSendsAgain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app = (_JS / 'app.js').read_text()
        assert 'async function withStepUp(' in app and 'async function saveScim(' in app
        cls.funcs = ['async ' + srcpin.js_function(app, 'withStepUp'), 'async ' + srcpin.js_function(app, 'saveScim')]

    def run_js(self, responses, enabled='true', decision='true'):
        script = (_STUBS.replace('__DECISION__', decision).replace('__ENABLED__', enabled) + '\n'.join(self.funcs) + '\n'
                  + 'queue.push(' + ', '.join(json.dumps(r) for r in responses) + ');\n'
                  + '(async () => { await saveScim(); out.reveal = reveal.textContent; console.log(JSON.stringify(out)); })();')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'run.js'
            path.write_text(script)
            proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_switching_it_on_asks_for_the_password_and_sends_the_same_save_again(self):
        out = self.run_js([_STEP, {'ok': True, 'scim_token': 'minted-token-xyz'}])
        self.assertEqual(out['modal'], 1)
        self.assertEqual(len(out['apiCalls']), 2)
        self.assertEqual(out['apiCalls'][0], out['apiCalls'][1])
        self.assertIn('POST /config', out['apiCalls'][0])
        self.assertIn('minted-token-xyz', out['reveal'], 'the token is shown once, after the save that went through')
        self.assertEqual(out['toasts'], [['SCIM enabled', 'success']])

    def test_declining_the_prompt_saves_nothing_and_shows_no_error(self):
        out = self.run_js([_STEP], decision='false')
        self.assertEqual((out['modal'], len(out['apiCalls'])), (1, 1))
        self.assertEqual(out['toasts'], [])
        self.assertEqual(out['reveal'], '')

    def test_switching_it_off_does_not_ask(self):
        out = self.run_js([{'ok': True}], enabled='false')
        self.assertEqual(out['modal'], 0)
        self.assertEqual(out['toasts'], [['SCIM disabled', 'success']])

    def test_another_refusal_and_a_lost_connection_are_still_shown(self):
        out = self.run_js([{'error': 'Instance settings are managed by the platform operator.'}])
        self.assertEqual(out['toasts'], [['FAIL', 'Instance settings are managed by the platform operator.']])
        out = self.run_js([{'__reject': True}])
        self.assertEqual(out['toasts'], [['FAIL', '']])


def _governance_keys():
    """The tuple `_GOVERNANCE_CONFIG_KEYS` of api.py, read from the syntax tree."""
    for node in ast.parse((_CGI / 'api.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_GOVERNANCE_CONFIG_KEYS' for t in node.targets):
            return [e.value for e in node.value.elts]
    return []


class TestTheListThatAsks(unittest.TestCase):

    def test_both_settings_are_in_the_list_of_switches_that_ask(self):
        keys = _governance_keys()
        self.assertGreaterEqual(len(keys), 12, 'the list was not read: %s' % keys)
        self.assertIn('change_approval_enabled', keys, 'control: the list is the one of the governance switches')
        for key in ('scim_enabled', 'scim_token'):
            self.assertIn(key, keys)

    def test_the_only_place_that_writes_them_is_the_settings_save(self):
        """The class: a function that sets either key in the settings document has to be a place that asks. Today that is the settings save
        (which asks through the list above); the restores of a revision and of a backup replace the whole document and ask for the step-up
        themselves, and nothing else names the keys."""
        def mentions(node, name):
            return any((isinstance(n, ast.Name) and n.id == name) or (isinstance(n, ast.Attribute) and n.attr == name) for n in ast.walk(node))

        writers = []
        for path in [_CGI / 'api.py'] + sorted(_CGI.glob('*_handlers.py')):
            for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # the names this function binds to the settings document: cfg = load(CONFIG_FILE) and `with _LockedUpdate(CONFIG_FILE) as cfg`
                doc = set()
                for n in ast.walk(fn):
                    if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and any(mentions(a, 'CONFIG_FILE') for a in n.value.args):
                        doc |= {t.id for t in n.targets if isinstance(t, ast.Name)}
                    if isinstance(n, ast.With):
                        for item in n.items:
                            c = item.context_expr
                            if isinstance(c, ast.Call) and any(mentions(a, 'CONFIG_FILE') for a in c.args) and isinstance(item.optional_vars, ast.Name):
                                doc.add(item.optional_vars.id)
                sets = any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in doc
                                                             and isinstance(t.slice, ast.Constant) and t.slice.value in ('scim_enabled', 'scim_token')
                                                             for t in n.targets) for n in ast.walk(fn))
                if sets:
                    writers.append(fn.name)
        self.assertEqual(sorted(writers), ['handle_config_save'], 'another function sets a SCIM key: it has to ask for a step-up too')


if __name__ == '__main__':
    unittest.main()
