#!/usr/bin/env python3
"""An SSO group mapping must not promote a default-tenant account to superadmin.

v6.4.3 added a fail-closed check to `_provision_or_promote_user`: when tenancy
is enforced and an IdP group maps to `admin` in the default tenant, provision a
viewer instead, because an admin in the default tenant is a platform operator
who sees every tenant.

It asked the question about the wrong account. The check reads
`_sso_provision_tenant()` — the tenant a NEW user would be created in — while
the promote branch acts on an account that already exists and carries its own
`tenant_id`. Set `sso_default_tenant` to a real tenant and the check compares
against that tenant, never fires, and an existing default-tenant viewer is
promoted straight to `admin`. A record with no `tenant_id` — the ordinary
pre-tenancy shape — resolves to the default as well.

Both directions matter, so both are asserted here: the refusal, AND that a real
tenant admin can still be promoted by their IdP group, that a non-admin role
still maps through, and that a single-tenant install with tenancy off is
untouched. A fix that simply stopped promoting anyone would pass a one-sided
test.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v703-sso-'))
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')
_spec = importlib.util.spec_from_file_location('api_v703_sso', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Case(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-sso-case-'))
        self._saved = {}
        for name in ('USERS_FILE', 'CONFIG_FILE', 'TENANTS_FILE',
                     'AUDIT_LOG_FILE'):
            self._saved[name] = getattr(api, name)
            # The basename IS the storage key on SQLite/Postgres — take it from
            # the attribute being replaced, never from the attribute's NAME.
            setattr(api, name, self.tmp / Path(str(self._saved[name])).name)
        api._invalidate_load_cache(None)
        api.save(api.TENANTS_FILE, {'t2': {'id': 't2', 'name': 'Customer Two'}})

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)
        api._invalidate_load_cache(None)

    def _config(self, **cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(None)

    def _user(self, **rec):
        rec.setdefault('password_hash', 'x')
        api.save(api.USERS_FILE, {'alice': rec})
        api._invalidate_load_cache(None)

    def _promote(self, role='admin'):
        api._provision_or_promote_user('alice', role, {}, 'oidc')
        return (api.load(api.USERS_FILE) or {})['alice']

    def _is_superadmin(self, rec):
        tid = rec.get('tenant_id') or api.DEFAULT_TENANT
        if tid not in api._load_tenants():
            tid = api.DEFAULT_TENANT
        return rec.get('role') == 'admin' and tid == api.DEFAULT_TENANT


class TestPromotionCannotMintASuperadmin(_Case):

    def test_default_tenant_viewer_is_not_promoted_to_admin(self):
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer', tenant_id='default')
        rec = self._promote()
        self.assertEqual(rec['role'], 'viewer')
        self.assertFalse(self._is_superadmin(rec))

    def test_a_record_with_no_tenant_id_is_treated_as_the_default_tenant(self):
        """The pre-tenancy shape. It resolves to the default on read, so it is
        superadmin territory even though nothing says `default` anywhere."""
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer')
        rec = self._promote()
        self.assertEqual(rec['role'], 'viewer')
        self.assertFalse(self._is_superadmin(rec))

    def test_an_unknown_tenant_id_falls_back_to_default_and_is_refused(self):
        """`_user_tenant` maps an unknown tenant to the default, so a stale
        `tenant_id` must not become a way through."""
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer', tenant_id='deleted-tenant')
        self.assertEqual(self._promote()['role'], 'viewer')

    def test_the_refusal_is_audited(self):
        """Silence reads as "the group mapping is broken". Say what happened."""
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer', tenant_id='default')
        self._promote()
        log = api.load(api.AUDIT_LOG_FILE) or {}
        entries = log.get('entries', []) if isinstance(log, dict) else log
        actions = [e.get('action') for e in entries]
        self.assertIn('oidc_role_promotion_refused', actions, log)


class TestLegitimatePromotionsStillWork(_Case):
    """The other direction. Refusing everyone would pass the class above."""

    def test_a_real_tenant_admin_is_still_promoted(self):
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer', tenant_id='t2')
        rec = self._promote()
        self.assertEqual(rec['role'], 'admin')
        self.assertFalse(self._is_superadmin(rec), 't2 admin is not platform')

    def test_a_non_admin_role_still_maps_through_in_the_default_tenant(self):
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='viewer', tenant_id='default')
        self.assertEqual(self._promote('auditor')['role'], 'auditor')

    def test_tenancy_off_is_untouched(self):
        """The common single-tenant install must not change behaviour."""
        self._config()
        self._user(role='viewer', tenant_id='default')
        self.assertEqual(self._promote()['role'], 'admin')

    def test_an_existing_admin_stays_an_admin(self):
        """This function never demotes. It must not start."""
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        self._user(role='admin', tenant_id='default')
        self.assertEqual(self._promote()['role'], 'admin')


class TestTheProvisionPathStillFailsClosed(_Case):
    """The v6.4.3 behaviour this builds on, so a later edit cannot trade one
    for the other."""

    def test_new_user_admin_in_default_tenant_is_demoted(self):
        self._config(tenancy_enforced=True)
        api.save(api.USERS_FILE, {})
        api._invalidate_load_cache(None)
        rec = self._promote()
        self.assertEqual(rec['role'], 'viewer')

    def test_new_user_lands_in_the_configured_sso_tenant(self):
        self._config(tenancy_enforced=True, sso_default_tenant='t2')
        api.save(api.USERS_FILE, {})
        api._invalidate_load_cache(None)
        rec = self._promote()
        self.assertEqual(rec['tenant_id'], 't2')
        self.assertEqual(rec['role'], 'admin', 'a tenant admin is legitimate')


if __name__ == '__main__':
    unittest.main()
