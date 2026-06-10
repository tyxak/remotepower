#!/usr/bin/env python3
"""Tests for the v4.2.0 "5ecur1tyM4tter5" hardening bundle (A-series)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v420h", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('AUDIT_LOG_FILE', 'USERS_FILE', 'CONFIG_FILE',
                  'TOKENS_FILE', 'APIKEYS_FILE'):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'get_json_body', 'require_admin_auth')}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_admin_auth = lambda: 'alice'
        api.method = lambda: 'GET'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestAuditTamperEvidence(_Base):
    def test_entries_are_chained(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        api.audit_log('alice', 'login', 'ok')
        api.audit_log('bob', 'reboot', 'dev1')
        entries = api.load(api.AUDIT_LOG_FILE)['entries']
        self.assertEqual(len(entries), 2)
        self.assertTrue(all('_hash' in e for e in entries))
        self.assertEqual(entries[1]['_hash'],
                         api._audit_entry_hash(entries[0]['_hash'], entries[1]))

    def test_verify_clean(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        for i in range(3):
            api.audit_log('u', 'act', str(i))
        r = self.call(api.handle_audit_log_verify)
        self.assertTrue(r['ok'])
        self.assertIsNone(r['broken_at'])
        self.assertGreaterEqual(r['verified'], 1)

    def test_verify_detects_tamper(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        for i in range(3):
            api.audit_log('u', 'act', str(i))
        al = api.load(api.AUDIT_LOG_FILE)
        al['entries'][1]['detail'] = 'TAMPERED'   # edit content, leave _hash
        api.save(api.AUDIT_LOG_FILE, al)
        r = self.call(api.handle_audit_log_verify)
        self.assertFalse(r['ok'])
        self.assertEqual(r['broken_at'], 1)

    def test_clear_requires_password(self):
        api.save(api.USERS_FILE, {'alice': {'role': 'admin',
                                            'password_hash': api.hash_password('s3cret')}})
        api.save(api.AUDIT_LOG_FILE, {'entries': [{'ts': 1, 'actor': 'x'}]})
        api.method = lambda: 'DELETE'
        # no password → 403
        api.get_json_body = lambda: {}
        self.call(api.handle_audit_log_clear)
        self.assertEqual(self.cap['s'], 403)
        # wrong password → 403
        api.get_json_body = lambda: {'password': 'nope'}
        self.call(api.handle_audit_log_clear)
        self.assertEqual(self.cap['s'], 403)
        # correct → cleared + a pre-wipe archive exists
        api.get_json_body = lambda: {'password': 's3cret'}
        r = self.call(api.handle_audit_log_clear)
        self.assertTrue(r['ok'])
        self.assertTrue(any(p.name.startswith('audit_log_prewipe_')
                            for p in api.DATA_DIR.glob('audit_log_prewipe_*')))


class TestSessionCap(_Base):
    def test_cap_evicts_oldest(self):
        api.save(api.CONFIG_FILE, {'max_sessions_per_user': 2})
        api.save(api.TOKENS_FILE, {})
        for _ in range(3):
            api._mint_session('alice')
        toks = api.load(api.TOKENS_FILE)
        alice = [v for v in toks.values() if v.get('user') == 'alice']
        self.assertEqual(len(alice), 2)   # oldest evicted, only 2 remain

    def test_unlimited_when_zero(self):
        api.save(api.CONFIG_FILE, {'max_sessions_per_user': 0})
        api.save(api.TOKENS_FILE, {})
        for _ in range(4):
            api._mint_session('bob')
        self.assertEqual(len(api.load(api.TOKENS_FILE)), 4)


class TestApiKeyDefaultExpiry(_Base):
    def test_default_expiry_applied(self):
        api.save(api.CONFIG_FILE, {'apikey_default_expiry_days': 30})
        api.save(api.APIKEYS_FILE, {})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'k', 'role': 'admin'}
        r = self.call(api.handle_apikeys_create)
        kid = r['id']
        exp = api.load(api.APIKEYS_FILE)[kid]['expires_at']
        self.assertIsNotNone(exp)
        self.assertGreater(exp, int(__import__('time').time()) + 29 * 86400)

    def test_no_policy_no_expiry(self):
        api.save(api.CONFIG_FILE, {})
        api.save(api.APIKEYS_FILE, {})
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': 'k', 'role': 'admin'}
        r = self.call(api.handle_apikeys_create)
        self.assertIsNone(api.load(api.APIKEYS_FILE)[r['id']]['expires_at'])


class TestMfaEnrollmentGate(_Base):
    def test_required_predicate(self):
        api.save(api.CONFIG_FILE, {'mfa_required_roles': ['admin']})
        self.assertTrue(api._mfa_enrollment_required({'role': 'admin'}))
        self.assertFalse(api._mfa_enrollment_required({'role': 'admin', 'totp_secret': 'X'}))
        self.assertFalse(api._mfa_enrollment_required({'role': 'viewer'}))

    def test_interceptor_blocks_then_allows_enrollment(self):
        api.save(api.CONFIG_FILE, {'mfa_required_roles': ['admin']})
        api.save(api.USERS_FILE, {'alice': {'role': 'admin'}})   # no totp
        tok = 'rawtok'
        api.save(api.TOKENS_FILE, {api._token_hash(tok): {'user': 'alice', 'created': 1}})
        orig = (api.path_info, api.get_token_from_request)
        api.get_token_from_request = lambda: tok
        try:
            api.path_info = lambda: '/api/devices'      # a normal endpoint → blocked
            self.call(api._enforce_mfa_enrollment)
            self.assertEqual(self.cap.get('s'), 403)
            self.assertTrue(self.cap['b'].get('must_enroll_mfa'))
            self.cap.clear()
            api.path_info = lambda: '/api/totp/setup'    # enrollment path → allowed
            self.call(api._enforce_mfa_enrollment)
            self.assertEqual(self.cap, {})               # no respond → passes through
        finally:
            api.path_info, api.get_token_from_request = orig


class TestSecurityPosture(_Base):
    def test_posture_grades_config(self):
        api.save(api.CONFIG_FILE, {'mfa_required_roles': ['admin'], 'max_sessions_per_user': 5})
        api.save(api.USERS_FILE, {'a': {'role': 'admin', 'totp_secret': 'X'}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_security_posture)
        by = {c['key']: c for c in r['checks']}
        self.assertEqual(by['mfa_enforced']['status'], 'ok')
        self.assertEqual(by['session_cap']['status'], 'ok')
        self.assertEqual(by['admin_mfa']['status'], 'ok')
        self.assertEqual(by['apikey_expiry']['status'], 'warn')   # not configured
        self.assertGreater(r['total'], 5)
        self.assertLessEqual(r['score'], r['total'])


class TestWebAuthn(_Base):
    def setUp(self):
        super().setUp()
        self._wf = api.WEBAUTHN_CHALLENGES_FILE
        api.WEBAUTHN_CHALLENGES_FILE = self.d / 'wa_chal.json'
        self._ra = api.require_auth
        api.require_auth = lambda require_admin=False: 'alice'
        os.environ['HTTP_HOST'] = 'rp.example.com'

    def tearDown(self):
        api.require_auth = self._ra
        api.WEBAUTHN_CHALLENGES_FILE = self._wf
        os.environ.pop('HTTP_HOST', None)
        super().tearDown()

    def test_available(self):
        api.save(api.CONFIG_FILE, {})
        r = self.call(api.handle_webauthn_available)
        self.assertIn('available', r)

    def test_passkey_satisfies_mfa(self):
        api.save(api.CONFIG_FILE, {'mfa_required_roles': ['admin']})
        self.assertFalse(api._mfa_enrollment_required(
            {'role': 'admin', 'webauthn_credentials': [{'id': 'x'}]}))

    def test_register_begin_returns_options(self):
        if not (api._webauthn() and api._webauthn().available()):
            self.skipTest('py_webauthn not installed')
        api.save(api.USERS_FILE, {'alice': {'role': 'admin'}})
        api.method = lambda: 'POST'
        r = self.call(api.handle_webauthn_register_begin)
        self.assertIn('challenge', r)
        self.assertIn('rp', r)
        self.assertTrue(any(k.startswith('reg:')
                            for k in api.load(api.WEBAUTHN_CHALLENGES_FILE)))

    def test_credentials_list_hides_key_and_delete(self):
        api.save(api.USERS_FILE, {'alice': {'role': 'admin', 'webauthn_credentials': [
            {'id': 'cred1', 'name': 'key', 'public_key': 'pk', 'sign_count': 0}]}})
        api.method = lambda: 'GET'
        r = self.call(api.handle_webauthn_credentials_list)
        self.assertEqual(len(r['credentials']), 1)
        self.assertNotIn('public_key', r['credentials'][0])   # never expose the key
        api.method = lambda: 'DELETE'
        d = self.call(api.handle_webauthn_credential_delete, 'cred1')
        self.assertTrue(d['removed'])
        self.assertEqual(api.load(api.USERS_FILE)['alice'].get('webauthn_credentials'), [])

    def test_unavailable_returns_503(self):
        orig = api._webauthn
        api._WEBAUTHN_MOD = False   # simulate lib absent
        try:
            api.method = lambda: 'POST'
            self.call(api.handle_webauthn_login_begin)
            self.assertEqual(self.cap['s'], 503)
        finally:
            api._WEBAUTHN_MOD = None


class TestSamlSso(_Base):
    """v4.2.0 (B1): SAML SP SSO. The signature-verify path needs pysaml2 + the
    xmlsec1 binary (often absent in CI), so these cover the wiring, config
    validation, identity mapping, replay store and graceful-degradation paths —
    the crypto path is exercised at deploy + the mandatory security review."""

    _FULL = {'saml_enabled': True,
             'saml_idp_entity_id': 'https://idp.example.com/meta',
             'saml_idp_sso_url': 'https://idp.example.com/sso',
             'saml_idp_x509_cert': 'MIIBfakecert'}

    def setUp(self):
        super().setUp()
        self._sr = api.SAML_REQUESTS_FILE
        api.SAML_REQUESTS_FILE = self.d / 'saml_req.json'
        self._ra = api.require_auth
        api.require_auth = lambda require_admin=False: 'alice'
        os.environ['HTTP_HOST'] = 'rp.example.com'

    def tearDown(self):
        api.require_auth = self._ra
        api.SAML_REQUESTS_FILE = self._sr
        os.environ.pop('HTTP_HOST', None)
        super().tearDown()

    def test_available_shape(self):
        api.save(api.CONFIG_FILE, {})
        r = self.call(api.handle_saml_available)
        self.assertIn('available', r)
        self.assertIn('enabled', r)
        self.assertFalse(r['enabled'])      # not configured

    def test_cfg_requires_all_fields(self):
        api.save(api.CONFIG_FILE, {})
        self.assertIsNone(api._saml_cfg())          # disabled
        api.save(api.CONFIG_FILE, {'saml_enabled': True,
                                   'saml_idp_entity_id': 'x'})
        self.assertIsNone(api._saml_cfg())          # incomplete
        api.save(api.CONFIG_FILE, dict(self._FULL))
        self.assertIsNotNone(api._saml_cfg())       # complete

    def test_username_attr_then_nameid(self):
        cfg = {'saml_attr_username': 'uid'}
        self.assertEqual(api._saml_username_for('nid', {'uid': 'bob'}, cfg), 'bob')
        self.assertEqual(api._saml_username_for('nid', {'uid': ['carol']}, cfg), 'carol')
        self.assertEqual(api._saml_username_for('nid@x', {}, cfg), 'nid@x')   # fallback
        self.assertEqual(api._saml_username_for('nid', {}, {}), 'nid')

    def test_role_mapping(self):
        cfg = {'saml_admin_group': 'admins', 'saml_attr_groups': 'grp'}
        self.assertEqual(api._saml_role_for({'grp': ['admins', 'x']}, cfg), 'admin')
        self.assertEqual(api._saml_role_for({'grp': 'admins'}, cfg), 'admin')
        self.assertEqual(api._saml_role_for({'grp': ['x']}, cfg), 'viewer')
        self.assertEqual(api._saml_role_for({'grp': ['admins']}, {}), 'viewer')  # no mapping

    def test_outstanding_request_store(self):
        api._saml_put_request('req-123')
        self.assertIn('req-123', api._saml_outstanding())
        api._saml_consume_request('req-123')             # one-time-use
        self.assertNotIn('req-123', api._saml_outstanding())

    def test_outstanding_prunes_expired(self):
        # write an already-expired entry directly
        api.save(api.SAML_REQUESTS_FILE, {'old': {'ts': 1}})
        self.assertEqual(api._saml_outstanding(), {})

    def test_config_save_validates(self):
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'POST'
        # enabling without the required fields → 400
        api.get_json_body = lambda: {'saml_enabled': True}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)
        # a bogus SSO URL → 400
        api.get_json_body = lambda: {'saml_idp_sso_url': 'not-a-url'}
        self.call(api.handle_config_save)
        self.assertEqual(self.cap['s'], 400)
        # full valid config saves
        api.get_json_body = lambda: dict(self._FULL)
        self.call(api.handle_config_save)
        self.assertTrue(api.load(api.CONFIG_FILE).get('saml_enabled'))

    def test_acs_unavailable_returns_503(self):
        api._SAML_MOD = False         # simulate library/binary absent
        try:
            api.method = lambda: 'POST'
            self.call(api.handle_saml_acs)
            self.assertEqual(self.cap['s'], 503)
        finally:
            api._SAML_MOD = None

    def test_handlers_exist(self):
        for fn in ('handle_saml_available', 'handle_saml_metadata',
                   'handle_saml_login', 'handle_saml_acs'):
            self.assertTrue(callable(getattr(api, fn)))

    def test_public_info_exposes_saml_flag(self):
        api.save(api.CONFIG_FILE, dict(self._FULL))
        api.method = lambda: 'GET'
        r = self.call(api.handle_public_info)
        self.assertTrue(r.get('saml_enabled'))


class TestFinalizeSweep(_Base):
    """v4.2.0 finalize sweep regressions."""

    def test_custom_check_results_persisted_by_sanitizer(self):
        # Regression: the heartbeat sanitizer must keep si['custom_check_results']
        # (the Checks engine's agent-side file/job/log checks read it). Guard the
        # persistence so it can't silently get dropped again (proc_names class).
        src = (Path(api.__file__).read_text())
        self.assertIn("safe_si['custom_check_results']", src)

    def test_eval_agent_check_reads_reported_result(self):
        # an agent-side custom check returns the status the agent reported
        cdef = {'id': 'c1', 'type': list(api.AGENT_CHECK_TYPES)[0], 'param': 'x'}
        dev = {'sysinfo': {'custom_check_results': {'c1': {'status': 'critical',
                                                           'output': 'missing'}}}}
        status, out = api._eval_custom_check(cdef, dev)
        self.assertEqual(status, 'critical')
        self.assertIn('missing', out)
        # no reported result → unknown (not a crash)
        self.assertEqual(api._eval_custom_check(cdef, {'sysinfo': {}})[0], 'unknown')

    def test_scan_schedule_scope_helper(self):
        api.save(api.DEVICES_FILE, {'d1': {'group': 'prod'}, 'd2': {'group': 'dev'}})
        prod = {'type': 'groups', 'values': ['prod']}
        # all-scope (None) sees everything
        self.assertTrue(api._scan_sched_in_scope({'device_id': 'd2'}, None))
        # scoped caller: in-scope device ok, out-of-scope refused
        self.assertTrue(api._scan_sched_in_scope({'device_id': 'd1'}, prod))
        self.assertFalse(api._scan_sched_in_scope({'device_id': 'd2'}, prod))
        # target-only schedule is all-scope only
        self.assertFalse(api._scan_sched_in_scope({'scan_target_id': 't1'}, prod))


if __name__ == '__main__':
    unittest.main()
