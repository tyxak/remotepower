"""v6.2.3: LDAP honours the shared sso_group_roles matrix.

Before this, `_role_from_groups` was only called from the SAML and OIDC login
paths — an LDAP user could only ever be admin (ldap_admin_group DN match) or
viewer, even though the Settings "Group → role map" matrix suggested otherwise.
The fix: ldap_auth returns the raw memberOf DNs (LdapResult.groups) and the
login path resolves them through `_role_from_groups(..., casefold=True)` —
case-insensitive, matching the legacy lowercased ldap_admin_group comparison.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-ldap-'))

spec = importlib.util.spec_from_file_location('api_v623_ldap', CGI / 'api.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

import ldap_auth


class TestRoleFromGroupsCasefold(unittest.TestCase):
    """The casefold=True path (LDAP): matrix keys, groups and the admin group
    all match case-insensitively; the default path stays case-sensitive."""

    CFG = {
        'sso_group_roles': {'CN=Ops,OU=Groups,DC=example,DC=com': 'auditor'},
        'ldap_admin_group': 'cn=admins,dc=example,dc=com',
    }

    def test_matrix_key_matches_case_insensitively(self):
        role = api._role_from_groups(
            ['cn=ops,ou=groups,dc=example,dc=com'], self.CFG,
            'ldap_admin_group', casefold=True)
        self.assertEqual(role, 'auditor')

    def test_admin_group_matches_case_insensitively(self):
        role = api._role_from_groups(
            ['CN=Admins,DC=example,DC=com'], self.CFG,
            'ldap_admin_group', casefold=True)
        self.assertEqual(role, 'admin')

    def test_admin_wins_over_matrix(self):
        role = api._role_from_groups(
            ['cn=ops,ou=groups,dc=example,dc=com',
             'cn=admins,dc=example,dc=com'], self.CFG,
            'ldap_admin_group', casefold=True)
        self.assertEqual(role, 'admin')

    def test_no_match_is_viewer(self):
        role = api._role_from_groups(
            ['cn=nobody,dc=example,dc=com'], self.CFG,
            'ldap_admin_group', casefold=True)
        self.assertEqual(role, 'viewer')

    def test_default_path_stays_case_sensitive(self):
        # SAML/OIDC behaviour must be unchanged: without casefold a
        # case-mismatched group name does NOT match the matrix.
        role = api._role_from_groups(
            ['cn=ops,ou=groups,dc=example,dc=com'], self.CFG,
            'saml_admin_group')
        self.assertEqual(role, 'viewer')


class TestLdapResultCarriesGroups(unittest.TestCase):
    def test_groups_kwarg_and_default(self):
        r = ldap_auth.LdapResult('u', 'viewer', 'cn=u,dc=x',
                                 groups=['cn=g,dc=x'])
        self.assertEqual(r.groups, ['cn=g,dc=x'])
        r2 = ldap_auth.LdapResult('u', 'viewer', 'cn=u,dc=x')
        self.assertEqual(r2.groups, [])

    def test_authenticate_returns_member_of(self):
        # Source-level pin: authenticate() must hand the memberOf list to
        # LdapResult so the login path can resolve the matrix.
        src = (CGI / 'ldap_auth.py').read_text()
        self.assertIn('groups=member_of', src)


class TestLoginPathUsesMatrix(unittest.TestCase):
    def test_login_resolves_matrix_casefolded(self):
        # Source-level pin on the login block: it must call _role_from_groups
        # with the ldap_admin_group key and casefold=True.
        src = (CGI / 'api.py').read_text()
        self.assertIn("'ldap_admin_group', casefold=True", src)


if __name__ == '__main__':
    unittest.main()
