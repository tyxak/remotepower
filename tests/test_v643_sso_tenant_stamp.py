#!/usr/bin/env python3
"""An SSO login must not become a cross-tenant platform operator by omission.

THE BUG, reproduced before it was fixed:

    _user_tenant()          → u.get('tenant_id') or DEFAULT_TENANT
    _caller_is_superadmin() → role == 'admin' and tenant == DEFAULT_TENANT

and NO SSO path stamped `tenant_id`. So on a `tenancy_enforced` install, any
user whose IdP group mapped to admin was JIT-provisioned with no tenant,
resolved to `default`, and was therefore a SUPERADMIN with visibility into
every tenant — including tenants they have no relationship with. There was also
no way anywhere in the SSO configuration to express "admin OF tenant X", so a
multi-tenant operator could not have avoided this even knowing about it.

It is the same single fact behind the cross-tenant findings in v6.1.1 through
v6.4.0, arriving from a fourth direction: an absent tenant means `default`, and
admin-in-default means superadmin. Every previous fix hardened a READ path.
This one is a WRITE path — the account is created wrong, and every read is then
behaving correctly.

THE FIX HAS TWO HALVES and only the second changes existing behaviour:

  1. `tenant_id` is stamped on create from `sso_default_tenant`. With tenancy
     off that is DEFAULT_TENANT, which is what every user already resolves to,
     so single-tenant installs — nearly all of them — see nothing change.

  2. It FAILS CLOSED on the dangerous combination: tenancy enforced + resolved
     tenant is the default + mapped role is admin + the operator has not said
     where SSO users belong. The account is created as a viewer and the
     demotion is audited by name. A viewer can be promoted by a real superadmin
     in one click; the opposite mistake is invisible until it is a breach.

Every test drives the real `_provision_or_promote_user`, which all four SSO
paths (OIDC, SAML, SCIM, LDAP-adjacent) funnel through.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643sso-'))

_spec = importlib.util.spec_from_file_location('api_v643_sso', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def _setup(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        # TENANTS_FILE is a dict KEYED BY TENANT ID, not {'tenants': [...]}.
        # The first version of this fixture used the list shape, so 'acme' was
        # not in _load_tenants() and every tenant id fell back to default —
        # which made the fail-closed tests pass for the wrong reason and the
        # scoped-admin test fail. An invented fixture shape agrees with
        # whatever you assert.
        api.save(api.TENANTS_FILE, {
            'default': {'name': 'Platform', 'status': 'active'},
            'acme': {'name': 'Acme Corp', 'status': 'active'},
        })
        api.save(api.USERS_FILE, {})
        for f in (api.CONFIG_FILE, api.TENANTS_FILE, api.USERS_FILE):
            api._invalidate_load_cache(f)

    def _provision(self, username, role, source='oidc'):
        rec = api._provision_or_promote_user(username, role, {}, source)
        api._invalidate_load_cache(api.USERS_FILE)
        return rec

    def _stored(self, username):
        return (api.load(api.USERS_FILE) or {}).get(username) or {}

    def _is_superadmin(self, username):
        """Recomputed the way the product does, not asserted about directly."""
        return (self._stored(username).get('role') == 'admin'
                and api._user_tenant(username) == api.DEFAULT_TENANT)


class TestTheSuperadminByOmission(_Base):
    def test_an_sso_admin_is_not_silently_a_platform_operator(self):
        """The finding. Tenancy on, an IdP group maps to admin, nothing says
        which tenant — this used to produce a superadmin."""
        self._setup(tenancy_enforced=True)
        self._provision('alice@acme.example', 'admin')
        self.assertFalse(self._is_superadmin('alice@acme.example'),
                         'an SSO login became a cross-tenant platform operator '
                         'because no tenant was stamped')
        self.assertEqual(self._stored('alice@acme.example')['role'], 'viewer')

    def test_the_demotion_is_recorded_not_silent(self):
        """A security-relevant downgrade the operator did not ask for must be
        explainable afterwards, or it reads as a bug in the IdP mapping."""
        self._setup(tenancy_enforced=True)
        seen = []
        orig = api.audit_log
        api.audit_log = lambda actor, action, detail='', *a, **k: seen.append(
            (action, detail))
        try:
            self._provision('bob@acme.example', 'admin')
        finally:
            api.audit_log = orig
        joined = ' '.join(d for _a, d in seen)
        self.assertIn('DEMOTED', joined)
        self.assertIn('sso_default_tenant', joined,
                      'the audit line must name the setting that restores the '
                      'intended role, or the operator cannot act on it')

    def test_naming_a_tenant_gives_the_admin_that_tenant(self):
        """The intended multi-tenant setup, which was previously unreachable:
        an SSO admin scoped to ONE tenant."""
        self._setup(tenancy_enforced=True, sso_default_tenant='acme')
        rec = self._provision('carol@acme.example', 'admin')
        self.assertEqual(rec['role'], 'admin', 'a scoped admin keeps its role')
        self.assertEqual(api._user_tenant('carol@acme.example'), 'acme')
        self.assertFalse(self._is_superadmin('carol@acme.example'))

    def test_an_operator_can_still_choose_a_superadmin_explicitly(self):
        """Fail-closed must not mean impossible. Setting the default tenant to
        `default` on purpose is a deliberate, auditable choice."""
        self._setup(tenancy_enforced=True, sso_default_tenant='default')
        rec = self._provision('root@corp.example', 'admin')
        self.assertEqual(rec['role'], 'admin')
        self.assertTrue(self._is_superadmin('root@corp.example'))

    def test_a_non_admin_role_is_never_touched(self):
        self._setup(tenancy_enforced=True)
        rec = self._provision('dave@acme.example', 'auditor')
        self.assertEqual(rec['role'], 'auditor')


class TestSingleTenantInstallsAreUnaffected(_Base):
    """Nearly every install. The stamped value equals what these users already
    resolved to, so nothing observable changes — asserted rather than assumed,
    because a security fix that quietly demotes admins on ordinary installs
    would be worse than the bug."""

    def test_tenancy_off_keeps_the_admin_role(self):
        self._setup()                      # tenancy_enforced absent
        rec = self._provision('admin@corp.example', 'admin')
        self.assertEqual(rec['role'], 'admin')
        self.assertTrue(self._is_superadmin('admin@corp.example'))

    def test_tenancy_off_stamps_the_default_tenant(self):
        self._setup()
        self._provision('admin@corp.example', 'admin')
        self.assertEqual(self._stored('admin@corp.example')['tenant_id'],
                         api.DEFAULT_TENANT)

    def test_the_stamp_matches_what_an_unstamped_user_resolved_to(self):
        """The compatibility argument, made executable: the new explicit value
        is identical to the old implicit one."""
        self._setup()
        api.save(api.USERS_FILE, {'legacy': {'role': 'admin'}})   # no tenant_id
        api._invalidate_load_cache(api.USERS_FILE)
        implicit = api._user_tenant('legacy')
        self._provision('fresh@corp.example', 'admin')
        self.assertEqual(self._stored('fresh@corp.example')['tenant_id'],
                         implicit)


class TestTheTenantResolver(_Base):
    def test_an_unknown_tenant_id_falls_back_rather_than_stranding(self):
        """_user_tenant() applies the same rule on READ (an id not in the
        tenant list reads as default), so provisioning into a nonexistent
        tenant would create a user whose stored and resolved tenants disagree."""
        self._setup(tenancy_enforced=True, sso_default_tenant='ghost')
        self.assertEqual(api._sso_provision_tenant(), api.DEFAULT_TENANT)

    def test_a_known_tenant_is_used(self):
        self._setup(sso_default_tenant='acme')
        self.assertEqual(api._sso_provision_tenant(), 'acme')

    def test_blank_is_the_default_tenant(self):
        self._setup(sso_default_tenant='')
        self.assertEqual(api._sso_provision_tenant(), api.DEFAULT_TENANT)


class TestEverySsoPathGoesThroughTheHelper(unittest.TestCase):
    """The fix lives in one function on purpose. If a future SSO path builds a
    user record itself, it re-opens the hole — and this is what would notice."""

    def test_no_sso_handler_writes_a_user_record_directly(self):
        import ast
        src = (_CGI / 'api.py').read_text()
        tree = ast.parse(src)
        # AST, not a fixed-size lookback for the nearest `^def `. The first
        # version searched 3000 characters backwards to name the enclosing
        # function — and adding a comment to the code under test pushed the
        # `def` out of that window, so the owner resolved to '?' and the
        # allowlist could not match it. A fixed character window is the same
        # bug class the srcpin ratchet exists to remove, and I reintroduced it
        # in the detector rather than in the pin.
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Assign):
                    continue
                if not isinstance(sub.value, ast.Dict):
                    continue
                for tgt in sub.targets:
                    if (isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == 'users'):
                        offenders.append((node.name, sub.lineno))
        # handle_login holds the LDAP JIT-provision block; handle_user_create is
        # an admin creating a local account by hand (which takes an explicit
        # tenant). Both are reviewed, and the LDAP one is asserted DIRECTLY by
        # the next test rather than merely exempted — an allowlist entry that
        # checks nothing is exactly how the LDAP hole survived until this file
        # was written.
        allowed = {'handle_user_create', 'handle_login', 'ensure_default_user',
                   '_provision_or_promote_user'}
        unexpected = [f'{fn} (line {ln})' for fn, ln in offenders
                      if fn not in allowed]
        self.assertEqual(unexpected, [], '\n'.join([
            'these build a user record without going through '
            '_provision_or_promote_user, so they do not stamp a tenant:',
            *unexpected,
            '',
            'An unstamped user resolves to the default tenant, and an admin in '
            'the default tenant is a cross-tenant superadmin.']))
        self.assertTrue(offenders, 'the detector found no user-record writes at '
                                   'all — it has stopped measuring')

    def test_the_ldap_path_stamps_a_tenant_too(self):
        """LDAP auto-provision builds its own record (it carries ldap_dn and
        friends). It is in the allowlist above, so assert the stamp directly
        rather than letting the exemption hide it."""
        import re
        src = (_CGI / 'api.py').read_text()
        m = re.search(r"audit_log\(username, 'ldap_auto_provision'", src)
        self.assertIsNotNone(m, 'the LDAP auto-provision path moved')
        block = src[max(0, m.start() - 1500):m.start()]
        self.assertIn('tenant_id', block,
                      'the LDAP JIT-provision path does not stamp a tenant, so '
                      'an LDAP group mapped to admin still mints a superadmin')


if __name__ == '__main__':
    unittest.main()
