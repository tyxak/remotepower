#!/usr/bin/env python3
"""Pointing sign-in at an identity provider, or changing whom it is believed about and which of its groups are administrators, asks for a step-up.

An identity provider promotes any account whose group it names to administrator, which is promoting it without the step-up that
`PATCH /api/users/<name>` asks for, and an API key can never give one. The settings that say who the provider is were ordinary settings, so
an administrator key could create a viewer with a password it chose, point sign-in at a provider of its own with its own admin group,
let the provider's answer promote that account, sign in with the password it had chosen, step up with it and do what the key had been refused
(a new administrator, the governance switches).

What this holds, with real sessions and keys through the real route table and the real token check (a process of its own on a data directory
of its own, so that nothing is stubbed):

* the chain stops at the settings: a key that turns OpenID Connect or SAML on (in each of the forms the save reads), or sets who the provider
  is, whom it is believed about, which of its groups are administrators, the map of groups to roles or the tenant that new accounts land in,
  is refused with `step_up_required`, nothing is stored, and the provider's answer for the account it made changes nothing: it stays a viewer;
* a change is a change when it differs from what is stored, read as the save reads it, so the page that posts the whole form again with the same
  values asks nothing, and neither does a blank secret (the save keeps the one it has);
* taking the power back does not ask: turning a provider off, clearing a value, lowering the SAML switch that accepts unsolicited answers;
* a change that is made while a provider is off asks too, since it would be live on the day somebody else turns the provider on;
* a person who has stepped up sets it up, and the provider then maps its admin group to administrator as before;
* restoring a saved configuration that differs in any of these asks as well, since a restore swaps the whole document;
* the settings are named in the list of switches that ask, so the audit trail names them;
* the page asks for the step-up and sends the save again, and says nothing when the prompt is declined (the real functions, under node);
* the class: the functions that set these settings in the settings document are listed by syntax tree, and only the settings save does.
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

_KEYS = ('oidc_enabled', 'oidc_issuer', 'oidc_client_id', 'oidc_client_secret', 'oidc_admin_group',
         'saml_enabled', 'saml_idp_entity_id', 'saml_idp_sso_url', 'saml_idp_x509_cert', 'saml_attr_username', 'saml_attr_groups',
         'saml_admin_group', 'saml_allow_unsolicited', 'sso_group_roles', 'sso_default_tenant')

_DRIVER = r'''
KEYS = %(keys)r
OIDC = {'oidc_issuer': 'https://idp.attacker.example', 'oidc_client_id': 'rp', 'oidc_client_secret': 'chosen-secret', 'oidc_admin_group': 'owners'}
SAML = {'saml_idp_entity_id': 'https://idp.attacker.example/meta', 'saml_idp_sso_url': 'https://idp.attacker.example/sso',
        'saml_idp_x509_cert': 'MIIB-the-attackers-certificate', 'saml_attr_username': 'uid', 'saml_attr_groups': 'groups', 'saml_admin_group': 'owners'}
step = lambda r: [r[0], (r[1] or {}).get('code')]
cfg = lambda: get('CONFIG_FILE')
stored = lambda: {k: cfg().get(k) for k in KEYS if cfg().get(k) not in (None, '', False, {})}
audit = lambda: [r for r in (lambda a: a.get('entries', a) if isinstance(a, dict) else a)(get('AUDIT_LOG_FILE')) if isinstance(r, dict)]
post = lambda token, body: call('POST', '/api/config', token, body)

put('CONFIG_FILE', {})                                          # the common install: tenancy is off
add_key('CI-KEY', 'ci')                                         # an administrator key of the platform operator's tenant
add_user('admin2', 'admin'); session('admin2')                  # administrators that have not stepped up yet
add_user('admin3', 'admin'); session('admin3')
add_user('mal', 'viewer')                                       # the account the chain wants as an administrator (its password is PW['mal'])

# ---- the chain, as a key walks it
out['promote_directly'] = step(call('PATCH', '/api/users/mal', 'CI-KEY', {'role': 'admin'}))
forms = {'true': True, 'one': 1, 'string': 'yes', 'string_false': 'false'}      # the save reads bool(...): any text is on
out['key_turns_oidc_on'] = {name: step(post('CI-KEY', dict(OIDC, oidc_enabled=v))) for name, v in forms.items()}
out['key_turns_saml_on'] = {name: step(post('CI-KEY', dict(SAML, saml_enabled=v))) for name, v in forms.items()}
out['key_turns_the_switch_on_alone'] = {p + ':' + name: step(post('CI-KEY', {p + '_enabled': v})) for p in ('oidc', 'saml') for name, v in forms.items()}
out['stored_after_the_key'] = stored()
# the provider's answer for the account the key made: what the sign-in does after the provider has spoken
role = api._oidc_role_for({'groups': ['owners']}, api._config_ro())
api._provision_or_promote_user('mal', role, {}, 'oidc')
out['provider_answer_role'] = role
out['mal_role'] = get('USERS_FILE')['mal']['role']

# ---- the settings one at a time, while the provider is off and on a key's own
out['key_sets'] = {k: step(post('CI-KEY', {k: v})) for k, v in dict(OIDC, **SAML, sso_group_roles={'owners': 'admin'}, sso_default_tenant='acme',
                                                                   saml_allow_unsolicited=True).items()}
out['stored_after_the_single_settings'] = stored()

# ---- a person
out['admin_without_a_step_up'] = step(post(SESS['admin2'], dict(OIDC, oidc_enabled=True)))
out['step_up'] = call('POST', '/api/auth/step-up', SESS['admin2'], {'password': PW['admin2']})[0]
out['admin_sets_it_up'] = step(post(SESS['admin2'], dict(OIDC, oidc_enabled=True, sso_group_roles={'owners': 'admin'})))
out['stored_after_the_person'] = stored()
role = api._oidc_role_for({'groups': ['owners']}, api._config_ro())
out['provider_answer_after_the_person'] = role
api._provision_or_promote_user('mal', role, {}, 'oidc')
out['mal_role_after_the_person'] = get('USERS_FILE')['mal']['role']
out['named_in_the_audit_trail'] = sorted({d for r in audit() if r.get('action') == 'governance_config_change' for d in [r.get('detail', '')]})

# ---- once it is on, a key cannot take it over
others = {'oidc_issuer': 'https://other.example', 'oidc_client_id': 'other', 'oidc_client_secret': 'other-secret', 'oidc_admin_group': 'others',
          'saml_idp_entity_id': 'https://other.example/meta', 'saml_idp_sso_url': 'https://other.example/sso', 'saml_idp_x509_cert': 'MIIB-other',
          'saml_attr_username': 'mail', 'saml_attr_groups': 'memberOf', 'saml_admin_group': 'others', 'saml_allow_unsolicited': True,
          'sso_group_roles': {'others': 'admin'}, 'sso_default_tenant': 'acme'}
before = stored()
out['key_changes_each_setting'] = {k: step(post('CI-KEY', {k: v})) for k, v in others.items()}
out['stored_after_the_changes'] = stored() == before

# ---- it asks only where it must
body_again = {k: cfg().get(k) for k in KEYS if k != 'oidc_client_secret'}
out['key_saves_something_else'] = step(post('CI-KEY', {'brand_name': 'Acme Operations'}))
out['key_posts_the_whole_form_again'] = step(post('CI-KEY', dict(body_again, oidc_client_secret='')))
out['key_posts_the_same_secret'] = step(post('CI-KEY', {'oidc_client_secret': cfg().get('oidc_client_secret')}))
out['key_sends_a_blank_secret'] = step(post('CI-KEY', {'oidc_client_secret': ''}))
issuer = cfg().get('oidc_issuer')
out['key_posts_the_same_issuer_with_spaces'] = step(post('CI-KEY', {'oidc_issuer': '  ' + issuer + '  '}))       # the save trims it, so it is the same value
out['key_posts_the_same_map_with_spaces'] = step(post('CI-KEY', {'sso_group_roles': {' owners ': ' admin '}}))
out['key_clears_the_admin_group'] = step(post('CI-KEY', {'oidc_admin_group': ''}))
out['key_clears_the_map'] = step(post('CI-KEY', {'sso_group_roles': {}}))
out['key_turns_oidc_off'] = step(post('CI-KEY', {'oidc_enabled': False}))
out['oidc_after_off'] = [bool(cfg().get('oidc_enabled')), cfg().get('oidc_admin_group') or '', cfg().get('sso_group_roles') or {}]
out['key_turns_saml_off'] = step(post('CI-KEY', {'saml_enabled': False}))

# ---- a restore swaps the whole document
revision = dict(cfg(), oidc_enabled=True, oidc_issuer='https://idp.old.example', oidc_admin_group='old-admins')
put('CONFIG_REVS_FILE', {'revisions': [{'id': 'rev-sso1', 'ts': now, 'user': 'someone', 'changed_keys': ['oidc_issuer'], 'config': revision}]})
out['key_restores_it'] = step(call('POST', '/api/config/revisions/restore', 'CI-KEY', {'id': 'rev-sso1'}))
out['admin_without_a_step_up_restores_it'] = step(call('POST', '/api/config/revisions/restore', SESS['admin3'], {'id': 'rev-sso1'}))
out['issuer_after_refused_restores'] = cfg().get('oidc_issuer')
out['admin_with_a_step_up_restores_it'] = step(call('POST', '/api/config/revisions/restore', SESS['admin2'], {'id': 'rev-sso1'}))
out['issuer_after_the_restore'] = cfg().get('oidc_issuer')
# one stored issuer for another: both are set, so only the value tells them apart
revision2 = dict(cfg(), oidc_issuer='https://idp.second.example')
put('CONFIG_REVS_FILE', {'revisions': [{'id': 'rev-sso2', 'ts': now, 'user': 'someone', 'changed_keys': ['oidc_issuer'], 'config': revision2}]})
out['key_swaps_the_issuer_by_a_restore'] = step(call('POST', '/api/config/revisions/restore', 'CI-KEY', {'id': 'rev-sso2'}))
out['admin_without_a_step_up_swaps_the_issuer'] = step(call('POST', '/api/config/revisions/restore', SESS['admin3'], {'id': 'rev-sso2'}))
out['issuer_after_the_refused_swaps'] = cfg().get('oidc_issuer')
''' % {'keys': _KEYS}

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
        self.assertEqual(answer, [403, _STEP_UP], (what, answer))

    def test_the_control_the_key_is_refused_on_is_still_refused(self):
        self.asks(self.out['promote_directly'], 'PATCH /api/users')

    def test_a_key_cannot_turn_either_provider_on_in_any_form_the_save_reads(self):
        for provider in ('key_turns_oidc_on', 'key_turns_saml_on'):
            for name, answer in self.out[provider].items():
                with self.subTest(provider=provider, form=name):
                    self.asks(answer, provider + ' ' + name)
        for name, answer in self.out['key_turns_the_switch_on_alone'].items():
            with self.subTest(switch_alone=name):
                self.asks(answer, 'the switch alone ' + name)

    def test_nothing_was_stored_and_the_answer_of_the_provider_changes_nothing(self):
        self.assertEqual(self.out['stored_after_the_key'], {})
        self.assertEqual(self.out['provider_answer_role'], 'viewer', 'with nothing stored the provider names no administrators')
        self.assertEqual(self.out['mal_role'], 'viewer')

    def test_a_key_cannot_set_any_of_the_settings_one_at_a_time_either(self):
        """With both providers off. A setting changed now would be live on the day somebody else turns a provider on."""
        self.assertEqual(sorted(self.out['key_sets']), sorted(k for k in _KEYS if k not in ('oidc_enabled', 'saml_enabled')))
        for key, answer in self.out['key_sets'].items():
            with self.subTest(setting=key):
                self.asks(answer, key)
        self.assertEqual(self.out['stored_after_the_single_settings'], {})

    def test_an_administrator_asks_until_it_has_stepped_up_and_then_sets_it_up(self):
        self.asks(self.out['admin_without_a_step_up'], 'a session that has not stepped up')
        self.assertEqual(self.out['step_up'], 200)
        self.assertEqual(self.out['admin_sets_it_up'], [200, None])
        stored = self.out['stored_after_the_person']
        self.assertEqual((stored['oidc_enabled'], stored['oidc_issuer'], stored['oidc_admin_group']), (True, 'https://idp.attacker.example', 'owners'))
        self.assertEqual(stored['sso_group_roles'], {'owners': 'admin'})

    def test_the_provider_works_for_the_person_who_set_it_up(self):
        self.assertEqual(self.out['provider_answer_after_the_person'], 'admin')
        self.assertEqual(self.out['mal_role_after_the_person'], 'admin', 'the provider still sets roles; who may set it up is what changed')

    def test_the_settings_are_named_in_the_audit_trail(self):
        details = ' '.join(self.out['named_in_the_audit_trail'])
        for key in ('oidc_enabled', 'oidc_issuer', 'oidc_client_secret', 'oidc_admin_group', 'sso_group_roles'):
            self.assertIn(key, details)

    def test_once_it_is_on_a_key_cannot_change_any_of_the_settings(self):
        self.assertEqual(sorted(self.out['key_changes_each_setting']), sorted(k for k in _KEYS if k not in ('oidc_enabled', 'saml_enabled')))
        for key, answer in self.out['key_changes_each_setting'].items():
            with self.subTest(setting=key):
                self.asks(answer, key)
        self.assertTrue(self.out['stored_after_the_changes'], 'a refused change was written')

    def test_it_asks_only_where_it_must(self):
        for name in ('key_saves_something_else', 'key_posts_the_whole_form_again', 'key_posts_the_same_secret', 'key_sends_a_blank_secret',
                     'key_posts_the_same_issuer_with_spaces', 'key_posts_the_same_map_with_spaces'):
            with self.subTest(save=name):
                self.assertEqual(self.out[name], [200, None], 'a save that changes nothing is not a step-up')

    def test_taking_the_power_back_does_not_ask(self):
        for name in ('key_clears_the_admin_group', 'key_clears_the_map', 'key_turns_oidc_off', 'key_turns_saml_off'):
            with self.subTest(save=name):
                self.assertEqual(self.out[name], [200, None])
        self.assertEqual(self.out['oidc_after_off'], [False, '', {}])

    def test_a_restore_that_changes_any_of_them_asks_too(self):
        self.asks(self.out['key_restores_it'], 'a key restoring a revision')
        self.asks(self.out['admin_without_a_step_up_restores_it'], 'a session that has not stepped up restoring a revision')
        self.assertEqual(self.out['issuer_after_refused_restores'], 'https://idp.attacker.example', 'a refused restore changed the document')
        self.assertEqual(self.out['admin_with_a_step_up_restores_it'], [200, None])
        self.assertEqual(self.out['issuer_after_the_restore'], 'https://idp.old.example')

    def test_a_restore_that_swaps_one_stored_value_for_another_asks_too(self):
        """Both documents have an issuer, so a check that only asks whether there is one would not see the swap."""
        self.asks(self.out['key_swaps_the_issuer_by_a_restore'], 'a key restoring a revision with another issuer')
        self.asks(self.out['admin_without_a_step_up_swaps_the_issuer'], 'a session that has not stepped up, another issuer')
        self.assertEqual(self.out['issuer_after_the_refused_swaps'], 'https://idp.old.example')


_STUBS = r"""
const out = {apiCalls: [], toasts: [], modal: 0, cleared: null, msgs: [], synced: 0};
const queue = [];
const DECISION = __DECISION__;
const _WIZ_OIDC_SCOPES = 'openid profile email groups';
const fields = {
  'oidc-enabled': {checked: true}, 'oidc-issuer': {value: ' https://idp.example '}, 'oidc-client-id': {value: 'rp'}, 'oidc-scopes': {value: ''},
  'oidc-admin-group': {value: 'owners'}, 'oidc-client-secret': {value: 's3cret'}, 'sso-group-roles': {value: 'owners=admin'},
  'saml-enabled': {checked: true}, 'saml-idp-entity-id': {value: 'https://idp.example/meta'}, 'saml-sp-entity-id': {value: ''},
  'saml-idp-sso-url': {value: 'https://idp.example/sso'}, 'saml-idp-cert': {value: 'MIIB'}, 'saml-attr-username': {value: 'uid'},
  'saml-attr-groups': {value: 'groups'}, 'saml-admin-group': {value: 'owners'}, 'saml-allow-unsolicited': {checked: false},
};
const document = {getElementById(id) { return fields[id] || null; }};
function toast(m, t) { out.toasts.push([String(m), t || '']); }
function failToast(r) { out.toasts.push(['FAIL', (r && (r.code || r.error)) || '']); }
function _wizMsg(text) { out.msgs.push(String(text)); }
function _wizOidcSync() { out.synced++; }
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
        wiz = (_JS / 'app-wizard.js').read_text()
        for name in ('withStepUp', 'saveOidcConfig', 'saveSamlConfig'):
            assert 'function %s(' % name in app, name
        assert 'async function _wizOidcOn(' in wiz
        cls.common = ['async ' + srcpin.js_function(app, 'withStepUp'), srcpin.js_function(app, '_parseGroupRoleMap')]
        cls.oidc = 'async ' + srcpin.js_function(app, 'saveOidcConfig')
        cls.saml = 'async ' + srcpin.js_function(app, 'saveSamlConfig')
        cls.wizard = 'async ' + srcpin.js_function(wiz, '_wizOidcOn')

    def run_js(self, call, responses, decision='true'):
        script = (_STUBS.replace('__DECISION__', decision) + '\n'.join(self.common) + '\n' + self.oidc + '\n' + self.saml + '\n' + self.wizard + '\n'
                  + 'queue.push(' + ', '.join(json.dumps(r) for r in responses) + ');\n'
                  + '(async () => { out.result = ' + call + '; out.cleared = fields["oidc-client-secret"].value; console.log(JSON.stringify(out)); })();')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'run.js'
            path.write_text(script)
            proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_the_oidc_card_asks_for_the_password_and_sends_the_same_save_again(self):
        out = self.run_js('await saveOidcConfig()', [_STEP, {'ok': True}])
        self.assertEqual(out['modal'], 1)
        self.assertEqual(len(out['apiCalls']), 2)
        self.assertEqual(out['apiCalls'][0], out['apiCalls'][1])
        self.assertIn('POST /config', out['apiCalls'][0])
        self.assertEqual(out['toasts'], [['OIDC config saved', 'success']])
        self.assertEqual(out['cleared'], '', 'the secret is cleared from the form after the save that went through')

    def test_declining_the_prompt_saves_nothing_and_says_nothing(self):
        out = self.run_js('await saveOidcConfig()', [_STEP], decision='false')
        self.assertEqual((out['modal'], len(out['apiCalls'])), (1, 1))
        self.assertEqual(out['toasts'], [], 'a declined prompt is not a saved card and not an error')
        self.assertEqual(out['cleared'], 's3cret', 'the secret stays in the form: nothing was saved')

    def test_a_save_that_needs_no_step_up_does_not_ask(self):
        out = self.run_js('await saveOidcConfig()', [{'ok': True}])
        self.assertEqual((out['modal'], len(out['apiCalls'])), (0, 1))
        self.assertEqual(out['toasts'], [['OIDC config saved', 'success']])

    def test_another_refusal_is_shown_and_not_reported_as_a_save(self):
        out = self.run_js('await saveOidcConfig()', [{'error': 'OIDC enabled but missing: oidc_client_secret'}])
        self.assertEqual(out['toasts'], [['FAIL', 'OIDC enabled but missing: oidc_client_secret']])
        self.assertEqual(out['cleared'], 's3cret')

    def test_the_saml_card_asks_and_sends_again_and_a_decline_says_nothing(self):
        out = self.run_js('await saveSamlConfig()', [_STEP, {'ok': True}])
        self.assertEqual((out['modal'], len(out['apiCalls'])), (1, 2))
        self.assertEqual(out['apiCalls'][0], out['apiCalls'][1])
        self.assertEqual(out['toasts'], [['SAML config saved', 'success']])
        out = self.run_js('await saveSamlConfig()', [_STEP], decision='false')
        self.assertEqual((out['modal'], len(out['apiCalls']), out['toasts']), (1, 1, []))
        out = self.run_js('await saveSamlConfig()', [{'error': 'SAML enabled but missing: saml_idp_x509_cert'}])
        self.assertEqual(out['toasts'], [['FAIL', 'SAML enabled but missing: saml_idp_x509_cert']])

    def test_the_guide_asks_and_sends_again_and_the_card_takes_what_was_saved(self):
        st = {'issuer': 'https://idp.example', 'cid': 'rp', 'scopes': '', 'admin': 'owners', 'map': 'owners=admin', 'secret': 'x'}
        out = self.run_js('await _wizOidcOn(%s, {})' % json.dumps(st), [_STEP, {'ok': True}])
        self.assertEqual((out['modal'], len(out['apiCalls']), out['result']), (1, 2, True))
        self.assertEqual(out['apiCalls'][0], out['apiCalls'][1])
        self.assertEqual((out['synced'], out['toasts']), (1, [['Single sign-on turned on', 'success']]))
        self.assertEqual(out['msgs'], [])

    def test_declining_the_prompt_leaves_the_guide_where_it_is_with_nothing_said(self):
        st = {'issuer': 'https://idp.example', 'cid': 'rp', 'scopes': '', 'admin': 'owners', 'map': '', 'secret': 'x'}
        out = self.run_js('await _wizOidcOn(%s, {})' % json.dumps(st), [_STEP], decision='false')
        self.assertEqual((out['modal'], len(out['apiCalls']), out['result']), (1, 1, False))
        self.assertEqual((out['msgs'], out['toasts'], out['synced']), ([], [], 0))

    def test_the_guide_still_says_what_the_server_refused(self):
        st = {'issuer': 'https://idp.example', 'cid': 'rp', 'scopes': '', 'admin': '', 'map': '', 'secret': 'x'}
        out = self.run_js('await _wizOidcOn(%s, {})' % json.dumps(st), [{'error': 'oidc_issuer must be http:// or https://'}])
        self.assertEqual((out['result'], out['msgs']), (False, ['oidc_issuer must be http:// or https://']))


def _governance_keys():
    """The tuple `_GOVERNANCE_CONFIG_KEYS` of api.py, read from the syntax tree."""
    for node in ast.parse((_CGI / 'api.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_GOVERNANCE_CONFIG_KEYS' for t in node.targets):
            return [e.value for e in node.value.elts]
    return []


class TestTheListThatAsks(unittest.TestCase):

    def test_every_setting_is_in_the_list_of_switches_that_ask(self):
        keys = _governance_keys()
        self.assertGreaterEqual(len(keys), 12, 'the list was not read: %s' % keys)
        self.assertIn('change_approval_enabled', keys, 'control: the list is the one of the governance switches')
        for key in _KEYS:
            self.assertIn(key, keys)

    def test_the_only_place_that_writes_them_is_the_settings_save(self):
        """The class: a function that sets one of these settings in the settings document has to be a place that asks. Today that is the
        settings save (which asks through the list above); the restores replace the whole document and ask for the step-up themselves, and
        nothing else names the settings."""
        def mentions(node, name):
            return any((isinstance(n, ast.Name) and n.id == name) or (isinstance(n, ast.Attribute) and n.attr == name) for n in ast.walk(node))

        writers = []
        for path in [_CGI / 'api.py'] + sorted(_CGI.glob('*_handlers.py')):
            for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
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
                                                             and isinstance(t.slice, ast.Constant) and t.slice.value in _KEYS
                                                             for t in n.targets) for n in ast.walk(fn))
                if sets:
                    writers.append(fn.name)
        self.assertEqual(sorted(writers), ['handle_config_save'], 'another function sets one of these settings: it has to ask for a step-up too')


if __name__ == '__main__':
    unittest.main()
