#!/usr/bin/env python3
"""8.0.2: a tenant user cannot tell a host of another tenant from an id that no host has.

docs/api.md has said since 6.1.2 that a host id of another tenant answers 404, "not 403: a 403 would confirm the id exists". The gates answered 403 "Host belongs to another tenant" from
3.14.0, and an id that no host has fell through to the handler, which answered 404 on 43 routes, 200 with nothing in it on 21 and something else on the rest. Run through the real gate
and dispatcher for all 69 routes of /api/devices/<id>... that need no body, none of them answered the two alike. The ids of hosts that came from a cloud account are the provider's own
(`hetzner-<number>`, `digitalocean-<number>`) and can be guessed, so the difference was a way to learn which of them another tenant has.

Now `_enforce_device_scope` answers 404 {"error": "Host not found"} for both, on every route under /api/devices/<id>/ and before the handler reads a body, to a caller that is
confined to a tenant. `_scope_block_device`, which the routes outside that prefix call, answers it for a host of another tenant. What stays as it was: a caller that sees every tenant (the
platform operator, and an install with tenancy off) gets the handler's own answers; the routes that are a path of their own (`/api/devices/agentless`, `/api/devices/bulk-tags`) are not read
as host ids; and a host of the caller's own tenant that its role may not reach still answers 403 "Host outside your role scope".
"""
import ast
import inspect
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-notfound-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

NOT_FOUND = (404, {'error': 'Host not found'})
METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')

# the routes of /api/devices/<id>... that the table does not list one by one (they are matched by code in _dispatch)
CODE_ROUTES = (
    ('DELETE', '/api/devices/{id}'),
    ('POST', '/api/devices/{id}'),
    ('PATCH', '/api/devices/{id}/require_confirmation'),
    ('GET', '/api/devices/{id}/allowlist'),
    ('GET', '/api/devices/{id}/netconfig/rev1'),
    ('POST', '/api/devices/{id}/ssh-exec'),
    ('POST', '/api/devices/{id}/ssh-poll'),
    ('GET', '/api/devices/{id}/services/config'),
)


def setUpModule():
    __import__("sys").path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    import api_guard
    api_guard.save(__name__)


def tearDownModule():
    import api_guard
    api_guard.restore(__name__)


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        a = self.api
        a.respond = lambda status, body=None: (_ for _ in ()).throw(a.HTTPError(status, body))
        a.audit_log = lambda *x, **k: None
        a.save(a.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'created': 0, 'builtin': True},
                                'tenantA': {'name': 'A', 'status': 'active', 'created': 0},
                                'tenantB': {'name': 'B', 'status': 'active', 'created': 0}})
        a.save(a.USERS_FILE, {'aadmin': {'role': 'admin', 'tenant_id': 'tenantA'}, 'root': {'role': 'admin', 'tenant_id': 'default'}})
        a.save(a.CONFIG_FILE, {'tenancy_enforced': True})
        a.save(a.DEVICES_FILE, {'devA': {'name': 'A1', 'tenant': 'tenantA', 'last_seen': 1}, 'devB': {'name': 'B1', 'tenant': 'tenantB', 'last_seen': 1},
                                'hetzner-12345678': {'name': 'cloud', 'tenant': 'tenantB', 'last_seen': 1}})
        a.get_token_from_request = lambda: 'tok'
        a.current_username = lambda: 'aadmin'
        self.as_user('aadmin')

    def tearDown(self):
        self.api._RCTX.environ = None

    def as_user(self, user, role='admin'):
        self.api.verify_token = lambda tok: (user, role)
        self.api.current_username = lambda: user
        self.api._LOAD_CACHE.clear()

    def gate(self, method, path):
        """What the gate before the dispatcher answers: (status, body), or None when it lets the request through."""
        a = self.api
        a._LOAD_CACHE.clear()
        a._RCTX.environ = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': '', 'REMOTE_ADDR': '203.0.113.9'}
        try:
            a._enforce_device_scope()
        except a.HTTPError as e:
            return (e.status, e.body)
        return None

    def routes(self):
        """(method, path template) of every route under /api/devices/<id>: the table's, and the ones matched by code."""
        out = []
        for kind, methods, prefix, suffix, _handler, _expr in (d for d in self.api._PATTERN_ROUTE_DEFS if d[0] == 'pat'):
            if prefix == '/api/devices/':
                out += [(m, prefix + '{id}' + suffix) for m in methods]
        return out + list(CODE_ROUTES)


class TestTheGateAnswersAlike(_Base):

    def test_the_population_is_the_routes_of_a_host(self):
        routes = self.routes()
        self.assertGreater(len(routes), 130, 'the table of routes under /api/devices/<id> was read (138 at 8.0.2)')
        self.assertGreater(len({m for m, _ in routes}), 3, 'more than one method')

    def test_a_host_of_another_tenant_and_an_id_no_host_has_are_answered_alike_on_every_route_and_method(self):
        routes = self.routes()
        measured = 0
        for method, template in routes:
            for foreign in ('devB', 'hetzner-12345678'):
                with self.subTest(method=method, route=template, id=foreign):
                    answer_foreign = self.gate(method, template.format(id=foreign))
                    answer_unknown = self.gate(method, template.format(id='hetzner-87654321'))
                    self.assertEqual(answer_foreign, NOT_FOUND)
                    self.assertEqual(answer_unknown, NOT_FOUND)
                    measured += 1
        self.assertGreaterEqual(measured, 2 * len(routes))

    def test_a_host_of_the_callers_own_tenant_is_let_through(self):
        for method, template in self.routes():
            with self.subTest(method=method, route=template):
                self.assertIsNone(self.gate(method, template.format(id='devA')), 'a host of the caller\'s own tenant was refused')

    def test_the_routes_that_are_a_path_of_their_own_are_not_read_as_a_host_id(self):
        exact = [(m, p) for (m, p) in self.api._build_exact_routes() if m and p.startswith('/api/devices/') and p.count('/') == 3]
        self.assertGreaterEqual(len(exact), 4, 'control: the table has routes such as /api/devices/bulk-tags (5 at 8.0.2)')
        for method, path in exact:
            with self.subTest(method=method, path=path):
                self.assertIsNone(self.gate(method, path), '%s %s is a route of its own and was answered as a host that does not exist' % (method, path))

    def test_the_answer_is_the_one_the_handlers_give_for_an_unknown_id(self):
        # the text a tenant user already got from a handler when no host had the id: 239 of the 251 not-found answers about a host in the handlers are exactly this
        self.assertEqual(NOT_FOUND, (404, {'error': 'Host not found'}))
        a = self.api
        a._RCTX.environ = {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/api/devices/zzz/checks', 'QUERY_STRING': ''}
        self.as_user('root')
        try:
            a.handle_device_checks('zzz')
        except a.HTTPError as e:
            self.assertEqual((e.status, e.body), NOT_FOUND, 'a handler answers a host that does not exist as the gate now does for a tenant user')
        else:
            self.fail('the handler did not answer')


class TestRoutesWithTheHostIdInThePathOutsideThePrefix(_Base):
    """/api/cmdb/<id>..., /api/scap/<id>/...: the id is in the path, the handler checks it with `_scope_block_device`, and an id that no host has has to be answered as a host of
    another tenant is, or the handler's own words for it ("no report on file for this host") tell the two apart."""

    def population(self):
        out = []
        for kind, methods, prefix, suffix, handler, _expr in (d for d in self.api._PATTERN_ROUTE_DEFS if d[0] == 'pat'):
            if prefix.startswith('/api/devices/'):
                continue
            fn = getattr(self.api, handler, None)
            if fn is None:
                continue
            try:
                params = list(inspect.signature(fn).parameters)
                tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
            except (TypeError, ValueError, OSError, SyntaxError):
                continue
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func).endswith('_scope_block_device')]
            if calls and params and params[0] in ('dev_id', 'device_id', 'did'):
                out.append((methods, prefix, suffix, handler, calls))
        return out

    def test_the_population_is_found(self):
        pop = self.population()
        self.assertGreaterEqual(len(pop), 5, 'control: the routes with a host id in the path that check it with _scope_block_device were found (cmdb and scap: 7 at 8.0.2)')
        self.assertTrue(any(h == 'handle_scap_report_download' for _m, _p, _s, h, _c in pop), 'control: the scap report is in it')

    def test_every_one_of_them_asks_for_the_strict_answer(self):
        for methods, prefix, suffix, handler, calls in self.population():
            for call in calls:
                with self.subTest(handler=handler, line=call.lineno):
                    self.assertTrue(any(k.arg == 'strict' and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords),
                                    '%s checks a host id from the path without strict=True: an id that no host has is answered in the handler\'s own words' % handler)

    def test_a_host_of_another_tenant_and_an_id_no_host_has_are_answered_alike_by_the_handler_too(self):
        a = self.api
        for methods, prefix, suffix, handler, _calls in self.population():
            if 'GET' not in methods:
                continue
            answers = {}
            for label, dev in (('foreign', 'devB'), ('unknown', 'nobody')):
                a._LOAD_CACHE.clear()
                path = prefix + dev + suffix
                a._RCTX.environ = {'REQUEST_METHOD': 'GET', 'PATH_INFO': path, 'QUERY_STRING': '', 'REMOTE_ADDR': '203.0.113.9'}
                try:
                    a._dispatch(path, 'GET')
                    answers[label] = None
                except a.HTTPError as e:
                    answers[label] = (e.status, e.body)
            with self.subTest(route=prefix + '<id>' + suffix):
                self.assertEqual(answers['foreign'], NOT_FOUND)
                self.assertEqual(answers['unknown'], NOT_FOUND)


class TestWhatDoesNotChange(_Base):

    def test_the_platform_operator_gets_the_handlers_own_answers(self):
        self.as_user('root')
        for method, template in self.routes():
            with self.subTest(method=method, route=template):
                self.assertIsNone(self.gate(method, template.format(id='devB')), 'the operator sees every tenant: the gate lets a host of tenantB through')
                self.assertIsNone(self.gate(method, template.format(id='nobody')), 'an id that no host has falls through to the handler for the operator')

    def test_with_tenancy_off_nothing_is_answered_by_the_gate(self):
        a = self.api
        a.save(a.CONFIG_FILE, {})
        a._LOAD_CACHE.clear()
        for method, template in self.routes()[:40]:
            self.assertIsNone(self.gate(method, template.format(id='devB')))
            self.assertIsNone(self.gate(method, template.format(id='nobody')))

    def test_a_host_of_the_callers_tenant_outside_its_role_scope_is_still_403(self):
        a = self.api
        a.save(a.ROLES_FILE, {'roles': [{'name': 'site-ops', 'permissions': [], 'scope': {'type': 'sites', 'values': ['hq']}}]})
        a.save(a.USERS_FILE, {'aadmin': {'role': 'site-ops', 'tenant_id': 'tenantA'}})
        devices = a.load(a.DEVICES_FILE)
        devices['devA']['site'] = 'branch'
        a.save(a.DEVICES_FILE, devices)
        self.as_user('aadmin', 'site-ops')
        answer = self.gate('GET', '/api/devices/devA/checks')
        self.assertEqual(answer, (403, {'error': 'Host outside your role scope'}), 'a host of the same tenant is a role question and keeps its own answer')
        devices['devA']['site'] = 'hq'
        a.save(a.DEVICES_FILE, devices)
        a._LOAD_CACHE.clear()
        self.assertIsNone(self.gate('GET', '/api/devices/devA/checks'), 'control: the same role reaches a host inside its scope')

    def test_the_gate_for_routes_outside_the_prefix_answers_a_foreign_host_as_not_found(self):
        a = self.api
        a._LOAD_CACHE.clear()
        for dev in ('devB', 'hetzner-12345678'):
            with self.assertRaises(a.HTTPError) as cm:
                a._scope_block_device(dev)
            self.assertEqual((cm.exception.status, cm.exception.body), NOT_FOUND)
        self.assertIsNone(a._scope_block_device('devA'))
        self.assertIsNone(a._scope_block_device('nobody'), 'an id that no host has still falls through: callers pass body ids and empty ones (no host means all hosts)')
        self.assertIsNone(a._scope_block_device(''))
        with self.assertRaises(a.HTTPError) as cm:
            a._scope_block_device('nobody', strict=True)
        self.assertEqual((cm.exception.status, cm.exception.body), NOT_FOUND, 'strict: a path id that no host has is answered as a host of another tenant is')
        self.as_user('root')
        self.assertIsNone(a._scope_block_device('nobody', strict=True), 'strict is for a caller confined to a tenant: the operator gets the handler\'s own answer')


if __name__ == '__main__':
    unittest.main()
