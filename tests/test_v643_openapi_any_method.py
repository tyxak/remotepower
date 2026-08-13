#!/usr/bin/env python3
"""A dispatcher row with no method in its condition was silently undocumented.

`_dispatcher_routes()` reconstructs the API surface by parsing each dispatch
row's condition text for `m == 'GET'` and friends. Rows that branch on
`method()` *inside* the handler have no verb in the condition, so the parser
could not infer one — and its response was `continue`.

That is the quiet kind of gap. The spec reported 860 routes, which reads as
complete, while fifteen rows were missing from it: `POST /api/login`, the three
inbound ingest endpoints, two device sub-resources, every WireGuard tunnel and
client route, and the **entire SCIM 2.0 surface**. SCIM is the one an enterprise
customer is most likely to go looking for, because they are wiring an identity
provider against it and the published spec is where they look first.

Nothing was broken at runtime — the endpoints all worked. They were just
invisible to anyone reading the documentation, which for an integration surface
amounts to the same thing.

The fix is a declaration table (`_ANY_METHOD_ROUTES`) rather than cleverer
parsing, because the verbs genuinely are not knowable from outside the handler:
`/api/vpn-tunnels/` alone re-splits its path and fans out to nine routes across
four methods. Declaring them is honest; inferring them would be a guess that
looks like a fact.

This test holds the undeclared count at ZERO. It is a hard zero rather than a
shrink-only ceiling because, unlike a heuristic scan, the question it asks is
exact: a row's condition either contains a method or it does not.

The verbs in the table were each read off the handler, and two absences are
deliberate: `POST /api/scim/v2/Groups` answers 501 and `DELETE` on a group
answers 405, because roles are defined in RemotePower rather than created by the
IdP. Those are a designed contract, so the table must NOT list them — and the
test below asserts that, so a future "completeness" pass cannot add them back
without noticing they are refusals.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-anym-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_anym', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import openapi_spec  # noqa: E402

_HAS_METHOD = re.compile(r"m == '[A-Z]+'|m in \(")


def _flat(cond):
    return ' '.join(str(cond).split())


def _rows_without_a_method():
    """Dispatch rows whose condition names no HTTP verb."""
    return [_flat(r[5]) for r in api._PATTERN_ROUTE_DEFS
            if not _HAS_METHOD.search(str(r[5]))]


class TestTheScanWorks(unittest.TestCase):
    """The assertion below is a count-is-zero, which is exactly what a scan
    that matches nothing also produces."""

    def test_there_are_dispatch_rows_at_all(self):
        self.assertGreater(len(api._PATTERN_ROUTE_DEFS), 300,
                           'no dispatch rows found — the parse is broken and '
                           'every other assertion here is vacuous')

    def test_it_recognises_a_condition_that_names_a_method(self):
        self.assertTrue(_HAS_METHOD.search("pi == '/api/x' and m == 'GET'"))
        self.assertTrue(_HAS_METHOD.search("pi == '/api/x' and m in ('GET','POST')"))

    def test_it_recognises_one_that_does_not(self):
        self.assertFalse(_HAS_METHOD.search("pi == '/api/login'"))

    def test_the_rows_it_finds_are_the_ones_declared(self):
        """If this drops to zero the guard passes trivially forever."""
        self.assertGreater(len(_rows_without_a_method()), 10)


class TestEveryAnyMethodRowIsDeclared(unittest.TestCase):

    def test_none_are_undeclared(self):
        undeclared = [c for c in _rows_without_a_method()
                      if c not in api._ANY_METHOD_ROUTES]
        self.assertEqual(
            undeclared, [],
            'these dispatch rows carry no method in their condition, so '
            '_dispatcher_routes() cannot infer their verbs and drops them from '
            'the OpenAPI spec without saying so. Read the handler and add an '
            '_ANY_METHOD_ROUTES entry:\n' + '\n'.join('  ' + c for c in undeclared))

    def test_no_declaration_is_stale(self):
        """A condition that was edited stops matching its row, and the entry
        then documents a route that no longer dispatches that way."""
        live = set(_flat(r[5]) for r in api._PATTERN_ROUTE_DEFS)
        stale = [c for c in api._ANY_METHOD_ROUTES if c not in live]
        self.assertEqual(stale, [],
                         'declared conditions that match no dispatch row:\n'
                         + '\n'.join('  ' + c for c in stale))

    def test_declarations_are_well_formed(self):
        for cond, routes in api._ANY_METHOD_ROUTES.items():
            self.assertTrue(routes, f'{cond} declares no routes')
            for me, path in routes:
                self.assertIn(me, ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'), cond)
                self.assertTrue(path.startswith('/api/'), path)


class TestTheRoutesReachTheServedSpec(unittest.TestCase):
    """The table existing is not the point; the published document is."""

    @classmethod
    def setUpClass(cls):
        routes = (list(api._build_exact_routes().keys())
                  + list(api._dispatcher_routes()))
        cls.spec = openapi_spec.build_spec(api.SERVER_VERSION, routes=routes)
        cls.paths = cls.spec['paths']

    def test_a_known_good_route_is_present(self):
        """Control: if ordinary routes were missing too, the assertions below
        would be measuring a broken builder rather than this fix."""
        self.assertTrue('/devices' in self.paths, 'control failed: even /devices is absent')

    def test_login_is_documented(self):
        self.assertTrue('/login' in self.paths, '/login missing from the spec')
        self.assertTrue('post' in self.paths['/login'], 'POST /login missing')

    def test_the_whole_scim_surface_is_documented(self):
        for p in ('/scim/v2/Users', '/scim/v2/Users/{id}', '/scim/v2/Groups',
                  '/scim/v2/Groups/{id}', '/scim/v2/ServiceProviderConfig',
                  '/scim/v2/ResourceTypes', '/scim/v2/Schemas'):
            self.assertTrue(p in self.paths, f'{p} missing from the spec')
        self.assertEqual(
            sorted(k for k in self.paths['/scim/v2/Users/{id}']
                   if k in ('get', 'put', 'patch', 'delete', 'post')),
            ['delete', 'get', 'patch', 'put'])

    def test_scim_refusals_are_not_documented_as_capabilities(self):
        """POST /Groups answers 501 and DELETE on a group 405, by design. A
        spec that lists them would send an IdP integrator down a path the
        server refuses."""
        self.assertNotIn('post', self.paths.get('/scim/v2/Groups', {}))
        self.assertNotIn('delete', self.paths.get('/scim/v2/Groups/{id}', {}))

    def test_ingest_endpoints_are_documented(self):
        for p in ('/webhook/in/{token}', '/syslog/in/{token}',
                  '/snmp/trap/{token}'):
            self.assertTrue(p in self.paths, f'{p} missing from the spec')
            self.assertTrue('post' in self.paths[p], f'POST {p} missing')

    def test_the_nine_vpn_tunnel_routes_are_documented(self):
        for p in ('/vpn-tunnels/{id}', '/vpn-tunnels/{id}/stats',
                  '/vpn-tunnels/{id}/clients',
                  '/vpn-tunnels/{id}/clients/{client_id}',
                  '/vpn-tunnels/{id}/clients/{client_id}/stats',
                  '/vpn-tunnels/{id}/clients/{client_id}/history'):
            self.assertTrue(p in self.paths, f'{p} missing from the spec')

    def test_templated_paths_declare_their_parameters(self):
        """A path with {id} in it and no parameter block is not usable by a
        generated client."""
        for p in ('/scim/v2/Users/{id}',
                  '/vpn-tunnels/{id}/clients/{client_id}'):
            names = set()
            for key, op in self.paths[p].items():
                if key == 'parameters':
                    names |= {q.get('name') for q in op}
                elif isinstance(op, dict):
                    names |= {q.get('name') for q in op.get('parameters', [])}
            for want in re.findall(r'\{([a-z_]+)\}', p):
                self.assertTrue(want in names, f'{p} does not declare path param {want}')

    def test_device_subresources_are_documented(self):
        for p in ('/devices/{device_id}/allowlist',
                  '/devices/{device_id}/services/config'):
            self.assertTrue(p in self.paths, f'{p} missing from the spec')
            self.assertTrue('get' in self.paths[p], f'GET {p} missing')
            self.assertTrue('post' in self.paths[p], f'POST {p} missing')


if __name__ == '__main__':
    unittest.main()
