#!/usr/bin/env python3
"""_PATTERN_ROUTE_DEFS — the declarative pattern-route table that replaced
_dispatch's ~300-branch elif chain (differential-proven behaviour-identical
over a 2,925-probe corpus at refactor time; resolution behaviour is guarded
by tests/test_router_table.py + routing_harness consumers).

These tests pin the table's structural invariants so a hand-edited row fails
fast instead of silently mis-routing."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(ROOT / 'tests'))

import api  # noqa: E402
from routing_harness import resolve_route  # noqa: E402

VALID_METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}


class TestTableShape(unittest.TestCase):
    def test_rows_are_wellformed_6_tuples(self):
        self.assertGreater(len(api._PATTERN_ROUTE_DEFS), 250)
        for row in api._PATTERN_ROUTE_DEFS:
            self.assertEqual(len(row), 6, row)
            kind, methods, a, b, name, src = row
            self.assertIn(kind, ('eq', 'pat', 'code'), row)
            if methods is not None:
                self.assertTrue(set(methods) <= VALID_METHODS, row)
            self.assertIsInstance(name, str)
            self.assertIsInstance(src, str)
            if kind == 'eq':
                self.assertTrue(a.startswith('/'), row)
            elif kind == 'pat':
                self.assertTrue(a.startswith('/') and a.endswith('/'), row)

    def test_every_handler_resolves(self):
        table = api._build_pattern_routes()
        self.assertEqual(len(table), len(api._PATTERN_ROUTE_DEFS))
        for kind, _methods, _a, _b, fn in table:
            self.assertTrue(callable(fn), fn)

    def test_bespoke_fns_return_bool_contract(self):
        # A 'code' row's function must return falsy for a path it does not
        # own (or the table would swallow every request below it).
        table = api._build_pattern_routes()
        for kind, _m, _a, _b, fn in table:
            if kind == 'code':
                self.assertFalse(fn('/api/__no_such_route__/x', 'GET'),
                                 f'{fn.__name__} claimed a foreign path')

    def test_src_texts_preserved_for_openapi(self):
        # _dispatcher_routes() parses each row's original condition text —
        # every row must carry one mentioning `pi`.
        for row in api._PATTERN_ROUTE_DEFS:
            self.assertIn('pi', row[5], row)


class TestOrderSensitiveResolution(unittest.TestCase):
    """The chain's documented 'must precede' relationships, as behaviour."""

    def test_device_command_queue_delete_beats_device_delete(self):
        name, args = resolve_route('DELETE', '/api/devices/d1/command-queue')
        self.assertEqual(name, 'handle_command_queue_clear')
        self.assertEqual(args, ['d1'])

    def test_bare_device_delete_still_routes(self):
        name, args = resolve_route('DELETE', '/api/devices/d1')
        self.assertEqual(name, 'handle_device_delete')
        self.assertEqual(args, ['d1'])

    def test_devices_agentless_not_swallowed_by_bulk_save(self):
        name, _ = resolve_route('POST', '/api/devices/agentless')
        self.assertNotEqual(name, 'handle_device_save_bulk')

    def test_bulk_save_matches_bare_id_post(self):
        name, args = resolve_route('POST', '/api/devices/d1')
        self.assertEqual(name, 'handle_device_save_bulk')
        self.assertEqual(args, ['d1'])

    def test_vpn_nested_block(self):
        name, args = resolve_route('GET', '/api/vpn-tunnels/t1/clients/c1/stats')
        self.assertEqual(name, 'handle_vpn_client_stats')
        self.assertEqual(args, ['t1', 'c1'])

    def test_unknown_is_404(self):
        name, _ = resolve_route('GET', '/api/__no_such_route__')
        self.assertEqual(name, '__http__404')


class TestOpenApiDerivation(unittest.TestCase):
    def test_dispatcher_routes_survive_the_table(self):
        api._DISPATCHER_ROUTES_CACHE = None
        routes = api._dispatcher_routes()
        self.assertGreater(len(routes), 250)
        self.assertIn(('GET', '/api/devices/{device_id}/checks'), routes)
        self.assertIn(('DELETE', '/api/devices/{device_id}/command-queue'), routes)


if __name__ == '__main__':
    unittest.main()
