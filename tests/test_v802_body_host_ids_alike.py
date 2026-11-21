#!/usr/bin/env python3
"""8.0.2: a tenant user cannot tell a host of another tenant from an id that no host has, on the routes that take the id in the body or the query.

`test_v802_host_of_another_tenant_is_not_found.py` holds the 138 routes of /api/devices/<id>. The routes outside that prefix read the host id themselves and call
`_scope_block_device`, and 56 of the 70 calls did not say `strict=True`: an id that no host has fell through to whatever the handler did next. Every route the router lists (846: the exact
table and the pattern rows) was driven as the administrator of one tenant with a request that names a host of that tenant, a host of another tenant and an id no host has, in the body and in the
query (dev-tools/sweep-8.0.2/xtenant_body_matrix.py). Fifteen answered the two differently:

  foreign host                          id no host has
  404 Host not found                    404 unknown host / 400 "subject required" / 200 muted / 200 queued / 400 "valid device_id required" ...   (dns import, tickets, iac request,
                                                                                                                           scap scan, trap-rule test, netscan, exposure and secrets mutes, webhook pin)
  400 No valid host targets             404 Host not found                    (reboot, shutdown, update, upgrade: `_resolve_targets` kept the id that no host has)
  403 out of scope                      404 Host not found                    (compliance remediate: the 403 confirmed that the id exists)

Now every call that takes the id from the request says `strict=True` (the helper looks nothing up for an empty id), `_resolve_targets` drops an id no host has for a caller confined to a tenant
as it drops a host of another tenant, and tickets and compliance answer as the rest. The four calls that stay are the ones whose id comes from a stored record (a stack, a scan): a record whose host
was removed must still be reachable for deletion. A caller that sees every tenant (the platform operator) gets the handlers' own answers as before.

Three parts: an AST ratchet over every call (so a new route cannot be added the old way), the 24 routes that the matrix carried to the host lookup, each driven again for the three answers,
and controls for what did not change. The routes that the generic request does not carry past validation (812 of 846, most of which read no host id at all) are the blind spot of the method; they
are held by the ratchet and not by a request.
"""
import ast
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-bodyhost-'))
_TESTS = Path(__file__).resolve().parent
_CGI = _TESTS.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_CGI))

from test_ip_intel import _fresh_api  # noqa: E402

SCALAR_KEYS = ('device_id', 'host_id', 'host', 'dev_id', 'source_device_id', 'target_device_id', 'scope_device_id', 'from_device_id', 'to_device_id', 'agent_id', 'id',
               'upstream_id', 'peer_id')
LIST_KEYS = ('device_ids', 'host_ids', 'hosts', 'devices', 'assigned_devices', 'endpoints', 'linked_devices', 'targets')


def setUpModule():
    __import__("sys").path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    import api_guard

    api_guard.save(__name__)


def tearDownModule():
    import api_guard

    api_guard.restore(__name__)


# ── part one: every call says strict ────────────────────────────────────────────────────────────────────────────────────

# A call that takes its id from a stored record and not from the caller: a record whose host was removed must still be reachable (to delete it), so the id that no host has is let through.
EXEMPT = {
    ('api.py', 'handle_scan_delete'): 'the host is read from the stored scan, not from the request',
    ('apps_compose_handlers.py', 'handle_compose_stack_get'): 'the host is read from the stored stack',
    ('apps_compose_handlers.py', 'handle_compose_stack_action'): 'the host is read from the stored stack',
    ('apps_compose_handlers.py', 'handle_compose_stack_delete'): 'the host is read from the stored stack',
}


def non_strict_calls(source):
    """(function, line) of every call of _scope_block_device that does not pass strict=True (a variable does not count: it cannot be shown to be true)."""
    tree = ast.parse(source)
    functions = [(n.lineno, n.end_lineno, n.name) for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n.func, 'id', getattr(n.func, 'attr', '')) == '_scope_block_device':
            strict = any(k.arg == 'strict' and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords)
            if not strict:
                owner = min((f for f in functions if f[0] <= n.lineno <= f[1]), key=lambda f: f[1] - f[0], default=(0, 0, '<module>'))[2]
                out.append((owner, n.lineno))
    return out


def all_calls():
    """{file name: (number of calls, [(function, line) not strict])} over server/cgi-bin."""
    out = {}
    for p in sorted(_CGI.glob('*.py')):
        src = p.read_text(encoding='utf-8')
        if '_scope_block_device' not in src:
            continue
        out[p.name] = (len([n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and getattr(n.func, 'id', getattr(n.func, 'attr', '')) == '_scope_block_device']),
                       non_strict_calls(src))
    return out


class TestEveryCallSaysStrict(unittest.TestCase):

    def test_what_the_scan_finds(self):
        for label, src, expected in (
            ('a bare call', "def h():\n    A._scope_block_device(x)\n", ['h']),
            ('a call by name', "def h():\n    _scope_block_device(x)\n", ['h']),
            ('strict=False', "def h():\n    _scope_block_device(x, strict=False)\n", ['h']),
            ('strict from a variable', "def h(s):\n    _scope_block_device(x, strict=s)\n", ['h']),
            ('strict=True', "def h():\n    _scope_block_device(x, strict=True)\n", []),
            ('strict=True through the module', "def h():\n    A._scope_block_device(x, strict=True)\n", []),
            ('two calls on a line, one of them not strict', "def h():\n    _scope_block_device(a, strict=True); _scope_block_device(b)\n", ['h']),
            ('no call at all', "def h():\n    return _scope_filter_devices(x)\n", []),
        ):
            with self.subTest(label):
                self.assertEqual([f for f, _ in non_strict_calls(src)], expected)

    def test_the_population_is_the_calls_of_the_server(self):
        calls = all_calls()
        total = sum(n for n, _ in calls.values())
        self.assertGreaterEqual(total, 65, 'the scan found %d calls of _scope_block_device; 70 at 8.0.2' % total)
        self.assertGreaterEqual(len(calls), 12, 'the calls are spread over 14 files at 8.0.2')
        self.assertIn('api.py', calls)
        self.assertIn('dns_dashboard_handlers.py', calls)

    def test_every_call_that_takes_the_id_from_the_request_says_strict(self):
        bad = sorted('%s %s (line %d)' % (f, fn, ln) for f, (_n, items) in all_calls().items() for fn, ln in items if (f, fn) not in EXEMPT)
        self.assertEqual(bad, [], '\n\nthese calls of _scope_block_device do not say strict=True, so a caller confined to a tenant is answered differently for a host of another tenant '
                                  'and for an id no host has (404 "Host not found" against whatever the handler does next). Say strict=True; an id that is read from a stored '
                                  'record goes in EXEMPT with the reason.')

    def test_an_exemption_that_stops_applying_fails_so_the_list_only_shrinks(self):
        calls = all_calls()
        for (f, fn), reason in EXEMPT.items():
            self.assertTrue(any(name == fn for name, _ln in calls.get(f, (0, []))[1]), '%s %s is exempt and no longer calls _scope_block_device without strict=True: remove it from EXEMPT' % (f, fn))
            self.assertTrue(reason)


# ── part two: the same answer ───────────────────────────────────────────────────────────────────────────────────────────

# The routes that the generic request carries to the host lookup (the control, a host of the caller's own tenant, answers differently from the other two).
CASES = (
    ('POST', '/api/dns/import-from-agent'),
    ('GET', '/api/dns/import-from-agent/status'),
    ('POST', '/api/dependency-suggestions'),
    ('POST', '/api/lldp-suggestions'),
    ('POST', '/api/tickets'),
    ('POST', '/api/iac/request'),
    ('POST', '/api/scap/scan'),
    ('POST', '/api/snmp/trap-rules/test'),
    ('GET', '/api/business-services/impact'),
    ('POST', '/api/autonomy/preview'),
    ('POST', '/api/netscan-schedules'),
    ('POST', '/api/reboot'),
    ('POST', '/api/shutdown'),
    ('POST', '/api/update-device'),
    ('POST', '/api/upgrade-device'),
    ('POST', '/api/schedule'),
    ('PUT', '/api/schedule/x'),
    ('POST', '/api/scans'),
    ('POST', '/api/exposure/mute'),
    ('POST', '/api/secrets/host-mute'),
    ('POST', '/api/wol'),
    ('POST', '/api/compliance/remediate'),
    ('PATCH', '/api/inbound-webhooks/x'),
    ('POST', '/api/ai-exec/propose'),
)


def body_for(host_id):
    out = {k: host_id for k in SCALAR_KEYS}
    out.update({k: [host_id] for k in LIST_KEYS})
    return out


def mask(text):
    text = re.sub(r'dev[ABZ]', 'ID', str(text))
    text = re.sub(r'[A-Za-z0-9_\-]{12,}', 'X', text)
    return re.sub(r'\b\d{5,}\b', 'N', text)


class _Base(unittest.TestCase):

    def setUp(self):
        self._data_dir = os.environ.get('RP_DATA_DIR')
        self.api = _fresh_api()
        a = self.api
        self._fresh_dir = os.environ['RP_DATA_DIR']
        a.respond = lambda status, body=None: (_ for _ in ()).throw(a.HTTPError(status, body))
        a.audit_log = lambda *x, **k: None
        a.fire_webhook = lambda *x, **k: None
        a._run_detached = lambda *x, **k: None
        a.get_token_from_request = lambda: 'tok'
        self.seed()
        self.as_user('aadmin')

    def tearDown(self):
        self.api._RCTX.environ = None
        if self._data_dir is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = self._data_dir
        shutil.rmtree(self._fresh_dir, ignore_errors=True)

    def seed(self):
        a = self.api
        a.save(a.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'created': 0, 'builtin': True},
                                'tenantA': {'name': 'A', 'status': 'active', 'created': 0},
                                'tenantB': {'name': 'B', 'status': 'active', 'created': 0}})
        a.save(a.USERS_FILE, {'aadmin': {'role': 'admin', 'tenant_id': 'tenantA'}, 'root': {'role': 'admin', 'tenant_id': 'default'}})
        a.save(a.CONFIG_FILE, {'tenancy_enforced': True})
        a.save(a.DEVICES_FILE, {'devA': {'name': 'A1', 'tenant': 'tenantA', 'ip': '10.0.0.1', 'last_seen': 1},
                                'devB': {'name': 'B1', 'tenant': 'tenantB', 'ip': '10.0.0.9', 'last_seen': 1}})
        a._LOAD_CACHE.clear()

    def as_user(self, user, role='admin'):
        self.api.verify_token = lambda tok: (user, role)
        self.api.current_username = lambda: user
        self.api._LOAD_CACHE.clear()

    def drive(self, method, path, host_id, keys=None):
        """(status, text) of what the gate and the dispatcher answer to a request that names `host_id` in the body and in the query."""
        a = self.api
        a._LOAD_CACHE.clear()
        body = body_for(host_id) if keys is None else {k: host_id for k in keys}
        query = '&'.join('%s=%s' % (k, host_id) for k in SCALAR_KEYS)
        a._RCTX.environ = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'QUERY_STRING': query, 'REMOTE_ADDR': '203.0.113.9'}
        a.get_json_body = lambda: dict(body)
        a.get_json_obj = lambda: dict(body)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                a._enforce_device_scope()
                a._dispatch(path, method)
            return ('returned', None)
        except a.HTTPError as e:
            b = e.body if isinstance(e.body, dict) else {'_': str(e.body)[:80]}
            text = b.get('error') or b.get('_')
            if text is None:
                text = json.dumps(b, sort_keys=True, default=str)[:200]
            return (e.status, mask(text))
        except SystemExit:
            return ('exit', None)

    def three(self, method, path, **kw):
        out = []
        for host_id in ('devA', 'devB', 'devZ'):
            self.seed()
            out.append(self.drive(method, path, host_id, **kw))
        self.seed()
        return out


class TestTheSameAnswer(_Base):

    def resolves(self, method, path):
        """Whether the router has a route for (method, path): the exact table, then the 'eq' and 'pat' rows, as `_dispatch` reads them."""
        a = self.api
        exact = a._build_exact_routes()
        if exact.get((method, path)) or exact.get((None, path)):
            return True
        for kind, methods, prefix, suffix, _fn in a._build_pattern_routes():
            if kind == 'eq' and path == prefix and (methods is None or method in methods):
                return True
            if kind == 'pat' and (methods is None or method in methods) and path.startswith(prefix) and (not suffix or path.endswith(suffix)):
                return True
        return False

    def test_the_cases_are_routes_of_the_router(self):
        self.assertGreaterEqual(len(CASES), 24)
        self.assertEqual(len(set(CASES)), len(CASES), 'a case is listed twice')
        for method, path in CASES:
            self.assertTrue(self.resolves(method, path), '%s %s is not a route of the router: a case that reaches no handler measures nothing' % (method, path))
        self.assertFalse(self.resolves('POST', '/api/no-such-route'), 'control: the lookup does not say yes to everything')

    def test_a_host_of_another_tenant_and_an_id_no_host_has_are_answered_alike_and_the_lookup_is_reached(self):
        reached = 0
        for method, path in CASES:
            with self.subTest(method=method, route=path):
                own, foreign, unknown = self.three(method, path)
                self.assertEqual(foreign, unknown, '%s %s tells a host of another tenant from an id no host has: %s against %s' % (method, path, foreign, unknown))
                self.assertNotEqual(own, foreign, '%s %s: a host of the caller\'s own tenant is answered like the other two, so the request never reached the lookup and the case measures nothing' % (method, path))
                reached += 1
        self.assertEqual(reached, len(CASES))

    def test_the_answer_for_both_is_not_found_or_no_valid_target(self):
        allowed = {(404, 'Host not found'), (400, 'No valid host targets')}
        for method, path in CASES:
            with self.subTest(method=method, route=path):
                _own, foreign, _unknown = self.three(method, path)
                self.assertIn(foreign, allowed, '%s %s answered %s' % (method, path, foreign))

    def test_a_forbidden_is_not_what_a_host_of_another_tenant_gets_from_compliance(self):
        _own, foreign, unknown = self.three('POST', '/api/compliance/remediate')
        self.assertEqual(foreign, (404, 'Host not found'))
        self.assertEqual(unknown, (404, 'Host not found'))

    def test_a_ticket_for_an_id_no_host_has_is_refused_to_a_tenant_user(self):
        self.seed()
        self.assertEqual(self.drive('POST', '/api/tickets', 'devZ', keys=('device_id',)), (404, 'Host not found'))
        self.assertEqual(self.drive('POST', '/api/tickets', 'devB', keys=('device_id',)), (404, 'Host not found'))


class TestWhatDidNotChange(_Base):

    def test_the_platform_operator_gets_the_handlers_own_answers(self):
        self.as_user('root')
        self.seed()
        # a ticket for an id no host has is still taken (a host that was removed), and the answer is the handler's, "subject required", not the not-found of a tenant user
        self.assertEqual(self.drive('POST', '/api/tickets', 'devZ', keys=('device_id',)), (400, 'subject required'))
        # a host of any tenant is reachable: the handler's own answer, not a refusal
        self.assertNotIn(self.drive('POST', '/api/tickets', 'devB', keys=('device_id',))[0], (404, 403))
        # an id no host has is still reported as "Host not found" by the queue for the operator (the old behaviour of _resolve_targets)
        self.assertEqual(self.drive('POST', '/api/reboot', 'devZ', keys=('device_id',)), (404, 'Host not found'))

    def test_the_operator_gets_the_one_not_found_text_from_the_dns_import_too(self):
        # the import said "unknown host" where 245 other places say "Host not found"; for a tenant user the gate answers first, so only the operator can tell
        self.as_user('root')
        self.seed()
        self.assertEqual(self.drive('POST', '/api/dns/import-from-agent', 'devZ', keys=('device_id',)), (404, 'Host not found'))

    def test_resolve_targets_drops_an_id_no_host_has_for_a_tenant_user_and_keeps_it_for_the_operator(self):
        a = self.api
        a._RCTX.environ = {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/reboot', 'QUERY_STRING': '', 'REMOTE_ADDR': '203.0.113.9'}
        self.as_user('aadmin')
        self.assertEqual(a._resolve_targets({'device_ids': ['devA', 'devB', 'devZ']}), ['devA'])
        self.as_user('root')
        self.assertEqual(a._resolve_targets({'device_ids': ['devA', 'devB', 'devZ']}), ['devA', 'devB', 'devZ'])

    def test_an_empty_id_is_never_looked_up(self):
        a = self.api
        a._RCTX.environ = {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/x', 'QUERY_STRING': '', 'REMOTE_ADDR': '203.0.113.9'}
        self.as_user('aadmin')
        self.assertIsNone(a._scope_block_device('', strict=True))
        with self.assertRaises(a.HTTPError) as caught:
            a._scope_block_device('devZ', strict=True)
        self.assertEqual((caught.exception.status, caught.exception.body), (404, {'error': 'Host not found'}))

    def test_a_host_of_the_callers_own_tenant_passes_strict(self):
        a = self.api
        self.as_user('aadmin')
        self.assertIsNone(a._scope_block_device('devA', strict=True))

    def test_the_operator_is_not_blocked_by_strict(self):
        a = self.api
        self.as_user('root')
        self.assertIsNone(a._scope_block_device('devZ', strict=True))
        self.assertIsNone(a._scope_block_device('devB', strict=True))


if __name__ == '__main__':
    unittest.main()
