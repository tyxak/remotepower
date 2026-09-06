#!/usr/bin/env python3
"""The SP metadata advertised an ACS URL that does not exist.

`GET /api/saml/metadata` renders the Assertion Consumer Service endpoint the
IdP will post its assertion to, and docs/sso.md tells the operator to hand that
metadata to their IdP. It advertised `/api/saml/acs`. The handler is routed at
`/api/auth/saml/acs`, and nothing answers the other path — so a SAML login set
up by following the documentation posted the assertion into a 404.

Three surfaces named the endpoint and two of them agreed with each other: the
in-app hint beside the setting has always shown `/api/auth/saml/acs`, so a
reader comparing the UI and the code would have concluded it was fine. The one
that was wrong is the one the IdP actually reads.

The rule this file holds is not "the string is correct" — it is that the
advertised path must resolve to a route the dispatcher answers. A future rename
of either half breaks the test rather than the login.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_API = _CGI / 'api.py'
_SAML = _CGI / 'saml_auth.py'


def _routed_paths():
    """Every exact ('METHOD', '/api/...') pair in the dispatcher table."""
    src = _API.read_text(encoding='utf-8')
    return {(m.group(1), m.group(2))
            for m in re.finditer(r"\(\s*'([A-Z]+)'\s*,\s*'(/api/[^']+)'\s*\)\s*:",
                                 src)}


def _advertised_acs_path():
    """The ACS path saml_auth.py appends to the base URL."""
    src = _SAML.read_text(encoding='utf-8')
    tree = ast.parse(src)
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'ACS_PATH'
                        for t in node.targets)
                and isinstance(node.value, ast.Constant)):
            return node.value.value
    raise AssertionError('ACS_PATH is no longer a module-level constant in '
                         'saml_auth.py — the path is written somewhere this '
                         'check cannot see')


class TestTheAdvertisedAcsIsRouted(unittest.TestCase):

    def test_the_acs_path_resolves_to_a_post_route(self):
        acs = _advertised_acs_path()
        routes = _routed_paths()
        self.assertIn(
            ('POST', acs), routes,
            f'the SP metadata advertises {acs}, which the dispatcher does not '
            'answer. That metadata is what the operator hands their IdP, so '
            'every SAML assertion lands in a 404.')

    def test_only_one_place_writes_the_path(self):
        """It was written in three places and one disagreed. Keep it to one in
        the code; the doc and the UI hint are checked against it below."""
        src = _SAML.read_text(encoding='utf-8')
        literals = re.findall(r"'(/api/[a-z/]*saml/acs)'", src)
        code = [l for l in src.splitlines() if not l.lstrip().startswith('#')]
        in_code = re.findall(r"'(/api/[a-z/]*saml/acs)'", '\n'.join(code))
        self.assertEqual(len(in_code), 1,
                         f'the ACS path appears {len(in_code)} times in code: '
                         f'{in_code}')
        self.assertTrue(literals)

    def test_the_in_app_hint_agrees(self):
        acs = _advertised_acs_path()
        js = (_ROOT / 'server/html/static/js/app.js').read_text(encoding='utf-8')
        self.assertIn(acs, js,
                      'the Settings hint tells the operator which URL to give '
                      'the IdP and no longer matches the metadata')

    def test_the_documentation_agrees(self):
        acs = _advertised_acs_path()
        doc = (_ROOT / 'docs' / 'sso.md').read_text(encoding='utf-8')
        self.assertIn(acs, doc)
        self.assertNotIn('/api/saml/acs`', doc,
                         'docs/sso.md still names the unrouted path')


class TestTheRouteDerivationWorks(unittest.TestCase):
    """Both assertions above lean on `_routed_paths`. If it returns nothing,
    the first one fails loudly rather than passing — but the second-order risk
    is a derivation that returns a WRONG set, so pin known-good members."""

    def test_it_finds_routes_we_know_exist(self):
        routes = _routed_paths()
        self.assertGreater(len(routes), 100, len(routes))
        for known in (('GET', '/api/saml/metadata'),
                      ('POST', '/api/auth/saml/acs')):
            self.assertIn(known, routes)

    def test_it_does_not_invent_the_old_path(self):
        self.assertNotIn(('POST', '/api/saml/acs'), _routed_paths(),
                         'if this ever passes, the route was added rather than '
                         'the advertisement corrected — decide which one is '
                         'canonical and keep only that')


if __name__ == '__main__':
    unittest.main()
