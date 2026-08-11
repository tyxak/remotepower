#!/usr/bin/env python3
"""A tenant admin must not be able to mint, promote or delete its way out.

THE ESCALATION, reproduced before it was fixed:

    handle_user_create gates on require_admin_auth()   — a TENANT admin passes
    the created record carried no tenant_id
    _user_tenant() resolves an unstamped account to DEFAULT_TENANT
    _caller_is_superadmin() IS `role == 'admin' and tenant == DEFAULT_TENANT`

so a tenant admin confined to `acme` created an account that was a PLATFORM
SUPERADMIN, logged in as it, and could then `POST /api/tenants/default/users`
itself into the default tenant — permanently. That is the exact attack
`require_superadmin_auth()`'s own docstring says the v5.7.0 gate exists to
prevent; `POST /api/users` was an unguarded detour to the identical outcome,
laundered through one throwaway account.

The decisive evidence that this was an oversight rather than a decision is that
THE IDENTICAL HAZARD WAS FIXED FOR API KEYS in v6.1.1, with this same
one-liner and a comment spelling out the failure mode. So a tenant admin could
not mint a cross-tenant API key, but could mint a cross-tenant human login —
strictly more powerful.

Three siblings shared the root cause (all four handlers considered tenancy
nowhere):
  * PATCH /api/users/<u>  — promote any default-tenant user to admin
  * DELETE /api/users/<u> — delete the platform superadmin
  * GET   /api/users      — `require_auth()`, so ANY authenticated caller,
                            including a viewer, received every tenant's roster

SCOPE, stated honestly: all of this requires `tenancy_enforced`, which is
opt-in and defaults False. On a single-tenant install every admin is already a
superadmin, so there is no boundary to cross and no impact — which is why the
"unaffected" class below is as important as the escalation class.

Two published claims were false as shipped, and are corrected in the same
change: docs/scaling.md said "A tenant admin cannot promote itself", and
docs/threat-model.md listed tenant-admin→superadmin as mitigated.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643usr-'))

_spec = importlib.util.spec_from_file_location('api_v643_usr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    """Seeds a genuinely multi-tenant install: a platform superadmin in
    `default` and a tenant admin confined to `acme`."""

    TENANCY = True

    def setUp(self):
        self.cap = {}
        api.save(api.CONFIG_FILE, {'tenancy_enforced': self.TENANCY})
        # TENANTS_FILE is a dict KEYED BY TENANT ID — a list shape would leave
        # 'acme' unknown, every id would fall back to default, and these tests
        # would pass for the wrong reason.
        api.save(api.TENANTS_FILE, {'default': {'name': 'Platform'},
                                    'acme': {'name': 'Acme Corp'}})
        api.save(api.USERS_FILE, {
            'root':   {'role': 'admin',  'tenant_id': 'default', 'password_hash': 'x'},
            'other':  {'role': 'viewer', 'tenant_id': 'default', 'password_hash': 'x'},
            'tadmin': {'role': 'admin',  'tenant_id': 'acme',    'password_hash': 'x'},
            'tuser':  {'role': 'viewer', 'tenant_id': 'acme',    'password_hash': 'x'},
        })
        for f in (api.CONFIG_FILE, api.TENANTS_FILE, api.USERS_FILE):
            api._invalidate_load_cache(f)
        self._orig = {k: getattr(api, k) for k in (
            'require_admin_auth', 'require_auth', 'method', 'get_json_obj',
            'respond', 'audit_log', 'require_step_up', 'verify_token',
            'get_token_from_request')}

        def _respond(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: None
        api.require_step_up = lambda *a, **k: None

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _as(self, actor):
        """Authenticate as `actor`.

        Stubs verify_token — NOT the require_* gates. Stubbing those would let a
        handler with no gate at all pass, which is the documented way to write a
        permission test that proves nothing.
        """
        role = (api.load(api.USERS_FILE) or {}).get(actor, {}).get('role', 'admin')
        api.verify_token = lambda *a, **k: (actor, role)
        api.get_token_from_request = lambda *a, **k: 'tok-' + actor

    def _call(self, fn, *args, body=None, m='POST'):
        api.method = lambda: m
        api.get_json_obj = lambda: (body or {})
        api.get_json_body = lambda *a, **k: (body or {})
        try:
            fn(*args)
        except (SystemExit, api.HTTPError):
            pass
        api._invalidate_load_cache(api.USERS_FILE)
        return self.cap

    def _users(self):
        return api.load(api.USERS_FILE) or {}


class TestATenantAdminCannotMintASuperadmin(_Base):
    def test_the_created_account_belongs_to_the_creators_tenant(self):
        self._as('tadmin')
        r = self._call(api.handle_user_create,
                       body={'username': 'pwn', 'password': 'Sup3rSecret!pass',
                             'role': 'admin'})
        self.assertIn(r.get('s'), (200, 201), r.get('d'))
        rec = self._users().get('pwn')
        self.assertIsNotNone(rec, 'the account was not created at all')
        self.assertEqual(rec.get('tenant_id'), 'acme',
                         'an unstamped account resolves to the default tenant, '
                         'where admin == platform superadmin')

    def test_and_is_therefore_not_a_superadmin(self):
        """Recomputed the way the product decides it, not asserted directly."""
        self._as('tadmin')
        self._call(api.handle_user_create,
                   body={'username': 'pwn', 'password': 'Sup3rSecret!pass',
                         'role': 'admin'})
        self.assertEqual(api._user_tenant('pwn'), 'acme')
        self.assertNotEqual(api._user_tenant('pwn'), api.DEFAULT_TENANT,
                            'a tenant admin minted a platform superadmin')

    def test_a_superadmin_still_creates_into_the_default_tenant(self):
        """The positive control. A fix that stamped every account into some
        other tenant would satisfy the tests above and break the product."""
        self._as('root')
        self._call(api.handle_user_create,
                   body={'username': 'newop', 'password': 'Sup3rSecret!pass',
                         'role': 'admin'})
        self.assertEqual(self._users()['newop'].get('tenant_id'),
                         api.DEFAULT_TENANT)


class TestATenantAdminCannotReachAnotherTenantsAccounts(_Base):
    def test_it_cannot_promote_a_default_tenant_user(self):
        """Without a tenant check this needed no new account at all — PATCH any
        existing default-tenant user to admin and it is a superadmin."""
        self._as('tadmin')
        r = self._call(api.handle_user_update, 'other',
                       body={'role': 'admin'}, m='PATCH')
        self.assertEqual(r.get('s'), 404,
                         '404 rather than 403 — a tenant admin must not be able '
                         'to probe for another tenant\'s account names')
        self.assertEqual(self._users()['other']['role'], 'viewer',
                         'the promotion went through')

    def test_it_cannot_delete_the_platform_superadmin(self):
        self._as('tadmin')
        r = self._call(api.handle_user_delete, 'root', m='DELETE')
        self.assertEqual(r.get('s'), 404)
        self.assertIn('root', self._users(), 'the superadmin was deleted')

    def test_it_CAN_still_manage_its_own_tenants_users(self):
        """The positive control that keeps the feature usable. A fix that
        refused everything would pass both tests above."""
        self._as('tadmin')
        r = self._call(api.handle_user_update, 'tuser',
                       body={'role': 'admin'}, m='PATCH')
        self.assertIn(r.get('s'), (200, 201), r.get('d'))
        self.assertEqual(self._users()['tuser']['role'], 'admin')

    def test_the_roster_is_filtered(self):
        """handle_users_list is require_auth(), so this leaked to ANY
        authenticated caller — a viewer, an mcp token — not just admins."""
        self._as('tadmin')
        r = self._call(api.handle_users_list, m='GET')
        names = {row['username'] for row in (r.get('d') or [])}
        self.assertEqual(names, {'tadmin', 'tuser'},
                         'the roster exposed another tenant: ' + str(names))

    def test_a_superadmin_still_sees_everyone(self):
        self._as('root')
        r = self._call(api.handle_users_list, m='GET')
        names = {row['username'] for row in (r.get('d') or [])}
        self.assertEqual(names, {'root', 'other', 'tadmin', 'tuser'})


class TestSingleTenantInstallsAreUnaffected(_Base):
    """Nearly every install. Asserted rather than assumed: a security fix that
    quietly broke ordinary user management would be worse than the bug."""

    TENANCY = False

    def test_an_admin_still_creates_admins(self):
        self._as('root')
        r = self._call(api.handle_user_create,
                       body={'username': 'newop', 'password': 'Sup3rSecret!pass',
                             'role': 'admin'})
        self.assertIn(r.get('s'), (200, 201), r.get('d'))
        self.assertEqual(self._users()['newop']['role'], 'admin')

    def test_everyone_still_sees_the_whole_roster(self):
        self._as('tadmin')          # not a superadmin, but tenancy is OFF
        r = self._call(api.handle_users_list, m='GET')
        names = {row['username'] for row in (r.get('d') or [])}
        self.assertEqual(names, {'root', 'other', 'tadmin', 'tuser'})

    def test_any_admin_can_still_manage_any_account(self):
        self._as('tadmin')
        r = self._call(api.handle_user_update, 'other',
                       body={'role': 'admin'}, m='PATCH')
        self.assertIn(r.get('s'), (200, 201), r.get('d'))


class TestTheApiKeyPrecedent(unittest.TestCase):
    """The same one-liner already guards API-key creation (v6.1.1). Pin it, so
    a future refactor cannot quietly reopen the weaker of the two paths while
    leaving the stronger one looking guarded."""

    def test_api_keys_stamp_the_creators_tenant(self):
        import inspect
        src = inspect.getsource(api)
        self.assertIn("'tenant_id': _caller_effective_tenant(actor)", src,
                      'the API-key tenant stamp is gone — it is the precedent '
                      'the user-create fix is modelled on')

    def test_user_create_uses_the_same_accessor(self):
        """_caller_effective_tenant, not _user_tenant: an API-key caller
        carries its own tenant, and resolving through the key's free-text
        `user` field was itself a cross-tenant bypass in v6.1.1."""
        import inspect
        src = inspect.getsource(api.handle_user_create)
        self.assertIn('_caller_effective_tenant', src)


if __name__ == '__main__':
    unittest.main()
