#!/usr/bin/env python3
"""A tenant admin must not be able to read another tenant's credentials.

`/api/cmdb/{device_id}/credentials/{cred_id}/reveal` returns a decrypted
password. It gated on `require_admin_auth()` and nothing else — and
`/api/cmdb/` is NOT covered by main()'s pre-dispatch `_enforce_device_scope`,
which only matches `/api/devices/<id>/`. So a tenant-scoped admin could reveal
the plaintext credential of ANY device in the fleet.

Reproduced before the fix: tenant `acme` admin, device in tenant `default`,
HTTP 200, `{'password': 'PLATFORM-DB-ROOT-PASSWORD'}`.

WHY THE VAULT DOES NOT SAVE YOU. Reveal requires the vault to be unlocked, so
the caller must know the passphrase — but the vault is INSTANCE-WIDE, one
passphrase for the whole deployment. Any admin entitled to unlock it for their
own credentials could therefore read everyone's. The vault protects the data at
rest, not between tenants.

Seven of the eleven device-taking CMDB handlers already called
`_scope_block_device`. These four — add, update, delete, reveal — were the
exceptions, which is the shape this class always has: a subsystem gated
almost everywhere, and the gap in the handlers added later.

Found by auditing `GET /api/tenancy/readiness`, which told superadmins the CMDB
was "not tenant-partitioned at any layer". It was partitioned at seven sites
out of eleven — the note was wrong in the reassuring direction about the four
that mattered most.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643cmdb-'))

_spec = importlib.util.spec_from_file_location('api_v643_cmdb', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import cmdb_vault  # noqa: E402

VAULT_PW = 'shared-vault-pass-1234'
SECRET = 'PLATFORM-DB-ROOT-PASSWORD'


class _Base(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        try:
            meta = cmdb_vault.setup_vault(VAULT_PW)
        except cmdb_vault.VaultNotInstalledError:
            self.skipTest('cryptography not installed')
        self.meta = meta
        self.key = cmdb_vault.derive_key_from_meta(VAULT_PW, meta)
        api.save(api.CMDB_VAULT_FILE, meta)
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api.save(api.TENANTS_FILE, {'default': {'name': 'P'}, 'acme': {'name': 'A'}})
        api.save(api.USERS_FILE, {'root': {'role': 'admin', 'tenant_id': 'default'},
                                  'tadmin': {'role': 'admin', 'tenant_id': 'acme'}})
        api.save(api.DEVICES_FILE, {
            'victim': {'name': 'platform-db', 'tenant': 'default'},
            'mine':   {'name': 'acme-web',    'tenant': 'acme'}})
        api.save(api.CMDB_FILE, {
            'victim': {'credentials': [dict(id='cred_abc123', label='root password',
                                            **cmdb_vault.encrypt(self.key, SECRET))]},
            'mine':   {'credentials': [dict(id='cred_def456', label='app password',
                                            **cmdb_vault.encrypt(self.key, 'acme-secret'))]}})
        for f in (api.CMDB_VAULT_FILE, api.CONFIG_FILE, api.TENANTS_FILE,
                  api.USERS_FILE, api.DEVICES_FILE, api.CMDB_FILE):
            api._invalidate_load_cache(f)

        self._orig = {k: getattr(api, k) for k in (
            'require_admin_auth', 'method', 'get_json_obj', 'get_json_body',
            'respond', 'audit_log', 'verify_token', 'get_token_from_request',
            '_cmdb_require_unlocked', '_get_client_ip')}
        api.audit_log = lambda *a, **k: None
        api._get_client_ip = lambda *a, **k: '10.0.0.1'
        api._cmdb_require_unlocked = lambda *a, **k: (self.key, self.meta)

        def _r(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _as(self, actor):
        api.require_admin_auth = lambda *a, **k: actor
        api.verify_token = lambda *a, **k: (actor, 'admin')
        api.get_token_from_request = lambda *a, **k: 'tok-' + actor

    def _call(self, fn, *args, body=None, m='POST'):
        api.method = lambda: m
        api.get_json_obj = lambda: (body or {})
        api.get_json_body = lambda *a, **k: (body or {})
        try:
            fn(*args)
        except (SystemExit, api.HTTPError):
            pass
        api._invalidate_load_cache(api.CMDB_FILE)
        return self.cap


class TestCrossTenantRevealIsRefused(_Base):
    def test_a_tenant_admin_cannot_reveal_another_tenants_password(self):
        self._as('tadmin')
        r = self._call(api.handle_cmdb_credentials_reveal, 'victim', 'cred_abc123')
        self.assertNotEqual(r.get('s'), 200,
                            'plaintext credential returned across tenants')
        self.assertNotIn(SECRET, str(r.get('d')),
                         'the secret leaked in the response body')

    def test_it_CAN_reveal_its_own(self):
        """Positive control. A gate that refused everything would satisfy the
        test above while breaking the feature entirely."""
        self._as('tadmin')
        r = self._call(api.handle_cmdb_credentials_reveal, 'mine', 'cred_def456')
        self.assertEqual(r.get('s'), 200, r.get('d'))
        self.assertEqual(r['d'].get('password'), 'acme-secret')

    def test_a_superadmin_can_reveal_anything(self):
        self._as('root')
        r = self._call(api.handle_cmdb_credentials_reveal, 'victim', 'cred_abc123')
        self.assertEqual(r.get('s'), 200, r.get('d'))
        self.assertEqual(r['d'].get('password'), SECRET)


class TestTheOtherThreeAreGatedToo(_Base):
    """add / update / delete shared the same gap. Delete is the destructive
    one: a tenant admin could remove another tenant's stored credentials."""

    def test_add_is_refused(self):
        self._as('tadmin')
        r = self._call(api.handle_cmdb_credentials_add, 'victim',
                       body={'label': 'x', 'password': 'y'})
        self.assertNotEqual(r.get('s'), 200)

    def test_delete_is_refused_and_nothing_is_removed(self):
        self._as('tadmin')
        self._call(api.handle_cmdb_credentials_delete, 'victim', 'cred_abc123',
                   m='DELETE')
        creds = (api.load(api.CMDB_FILE)['victim'] or {}).get('credentials') or []
        self.assertEqual(len(creds), 1,
                         "another tenant's credential was deleted")

    def test_update_is_refused(self):
        self._as('tadmin')
        r = self._call(api.handle_cmdb_credentials_update, 'victim', 'cred_abc123',
                       body={'label': 'pwned'}, m='PATCH')
        self.assertNotEqual(r.get('s'), 200)


class TestEveryDeviceTakingCmdbHandlerIsGated(unittest.TestCase):
    """The enumeration, so the NEXT credential handler cannot land ungated.

    `/api/cmdb/` gets no cover from main()'s pre-dispatch `_enforce_device_scope`
    — that gate matches `/api/devices/<id>/` only — so each handler must gate
    itself, and there is nothing structural to notice when one does not.
    """

    def test_no_ungated_device_handler_remains(self):
        import ast
        src = (_CGI / 'cmdb_handlers.py').read_text()
        lines = src.splitlines()
        ungated = []
        for n in ast.walk(ast.parse(src)):
            if not (isinstance(n, ast.FunctionDef) and n.name.startswith('handle_')):
                continue
            if 'dev_id' not in [a.arg for a in n.args.args]:
                continue
            body = '\n'.join(lines[n.lineno - 1:n.end_lineno])
            if '_scope_block_device' not in body:
                ungated.append(n.name)
        self.assertEqual(ungated, [], '\n'.join([
            'these CMDB handlers take a device id and never check whether the '
            'caller may see that device:', *ungated, '',
            '/api/cmdb/ is NOT covered by _enforce_device_scope. Add '
            'A._scope_block_device(dev_id) after the id validation.']))

    def test_the_detector_would_notice(self):
        """Guard the guard — an enumeration that found no handlers at all would
        report success forever."""
        import ast
        src = (_CGI / 'cmdb_handlers.py').read_text()
        n = sum(1 for x in ast.walk(ast.parse(src))
                if isinstance(x, ast.FunctionDef) and x.name.startswith('handle_')
                and 'dev_id' in [a.arg for a in x.args.args])
        self.assertGreaterEqual(n, 8, f'only {n} device-taking handlers found — '
                                      'the scan has stopped measuring')


if __name__ == '__main__':
    unittest.main()


class TestScopedCredentialsAreTenantIsolatedToo(_Base):
    """The same plaintext-reveal hole, one endpoint over.

    Scoped credentials (group/tag/site-scoped passwords) are gated by RBAC
    SCOPE via `_caller_scope_covers_credential` — and a tenant admin resolves
    to scope None, so that check passes for EVERYTHING. They carried no tenant
    at all, so a tenant admin could reveal any other tenant's scoped
    credential in plaintext, and delete them.
    """

    def _seed(self):
        api.save(api.SCOPED_VAULT_FILE, {'creds': [
            dict(id='scred_aaa', scope_type='group', scope_value='db',
                 label='platform db', tenant='default',
                 **cmdb_vault.encrypt(self.key, 'PLATFORM-SCOPED-SECRET')),
            dict(id='scred_bbb', scope_type='group', scope_value='web',
                 label='acme web', tenant='acme',
                 **cmdb_vault.encrypt(self.key, 'acme-scoped-secret')),
        ]})
        api._invalidate_load_cache(api.SCOPED_VAULT_FILE)

    def test_a_tenant_admin_cannot_reveal_another_tenants(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_scoped_credentials_reveal, 'scred_aaa')
        self.assertNotEqual(r.get('s'), 200)
        self.assertNotIn('PLATFORM-SCOPED-SECRET', str(r.get('d')))

    def test_it_CAN_reveal_its_own(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_scoped_credentials_reveal, 'scred_bbb')
        self.assertEqual(r.get('s'), 200, r.get('d'))
        self.assertEqual(r['d'].get('password'), 'acme-scoped-secret')

    def test_the_list_is_filtered(self):
        self._seed(); self._as('tadmin')
        r = self._call(api.handle_scoped_credentials_list, m='GET')
        ids = {c['id'] for c in (r['d'] or {}).get('credentials', [])}
        self.assertEqual(ids, {'scred_bbb'}, str(ids))

    def test_delete_cannot_reach_another_tenant(self):
        self._seed(); self._as('tadmin')
        self._call(api.handle_scoped_credentials_delete, 'scred_aaa', m='DELETE')
        api._invalidate_load_cache(api.SCOPED_VAULT_FILE)
        ids = {c['id'] for c in
               (api.load(api.SCOPED_VAULT_FILE) or {}).get('creds', [])}
        self.assertIn('scred_aaa', ids, "another tenant's credential was deleted")

    def test_a_new_scoped_credential_is_stamped(self):
        self._seed(); self._as('tadmin')
        self._call(api.handle_scoped_credentials_add,
                   body={'scope_type': 'group', 'scope_value': 'x',
                         'label': 'mine', 'password': 'pw'})
        api._invalidate_load_cache(api.SCOPED_VAULT_FILE)
        made = [c for c in (api.load(api.SCOPED_VAULT_FILE) or {}).get('creds', [])
                if c.get('label') == 'mine']
        self.assertTrue(made, 'the credential was not created')
        self.assertEqual(made[0].get('tenant'), 'acme')
