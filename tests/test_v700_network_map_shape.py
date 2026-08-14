#!/usr/bin/env python3
"""GET /api/network-map answered 500 on the demo instance.

Found by clicking, not by reading. A seeded click sweep — 2,429 controls across
81 pages — recorded every response of 400 or worse, and this was the only 500:
the Network map page did not load at all.

The cause is a type disagreement nobody had to notice. `connected_to` is a
SCALAR device id everywhere it is written or documented: request_models
declares it `str`, the PUT handler sanitises it as one, the docstring calls it
"the device-id this one connects to upstream". The demo seeder wrote a LIST, in
all eighteen of its devices. `target in devices` with a list key raises
TypeError, the WSGI layer turns that into a 500, and the page is simply gone.

Two separate defects, so two separate guards below:

  * the SEEDER wrote a shape the product does not accept. The rendered gates —
    a11y, box-overflow, the click sweep — all measure the seeded instance, so a
    seeder that lies about shape blinds them, and this one blinded them into
    reporting a page that 500s.
  * the READER crashed on a field whose type it merely assumed. A store can
    hold the other shape for reasons other than a bad seeder: a hand edit, an
    importer, an older record. A read path should degrade, not 500.

The corpus builder in rag_index had the quiet version of the same bug: it
rendered the list into the text fed to the model as `-> ['sw02']`, which is not
a device id and not an answer.
"""
import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-netmap-'))

import importlib.util  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api'] = api
_spec.loader.exec_module(api)


class TestTheSeederWritesTheShapeTheProductAccepts(unittest.TestCase):
    """A seeder that writes an impossible shape does not just break one page —
    it invalidates every gate that measures the seeded instance."""

    def setUp(self):
        self.seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not self.seeder.exists():
            self.skipTest('excluded from dist tree')

    def _connected_to_literals(self):
        """Every `connected_to` value in the seeder's device table."""
        tree = ast.parse(self.seeder.read_text(encoding='utf-8'))
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == 'connected_to':
                    out.append(v)
        return out

    def test_the_scan_finds_the_field_at_all(self):
        self.assertGreaterEqual(
            len(self._connected_to_literals()), 10,
            'the parser found almost no connected_to entries, so the '
            'assertion below would pass by reading nothing')

    def test_no_value_is_list_shaped(self):
        """The rule is "not a list", not "a string literal".

        A first draft asserted every value was a `str` Constant and flagged
        `dev.get('connected_to', '')` — a legitimate pass-through read. Testing
        the shape that actually breaks keeps the gate from failing on correct
        code, which is how gates get switched off.
        """
        def _list_shaped(v):
            if isinstance(v, (ast.List, ast.Tuple)):
                return True
            # `.get('connected_to', [])` — a list DEFAULT reintroduces the shape
            # for any record that lacks the key.
            if isinstance(v, ast.Call) and len(v.args) == 2:
                return isinstance(v.args[1], (ast.List, ast.Tuple))
            return False

        bad = [ast.unparse(v) for v in self._connected_to_literals()
               if _list_shaped(v)]
        self.assertEqual(
            bad, [],
            'the seeder writes connected_to as something other than a device '
            'id string. The product treats it as a scalar everywhere — '
            'request_models declares it str — and a list made '
            'GET /api/network-map answer 500:\n'
            + '\n'.join('  ' + b for b in bad))


class TestTheReaderDegradesInsteadOfCrashing(unittest.TestCase):

    def setUp(self):
        api._LOAD_CACHE.clear()
        self._real = {n: getattr(api, n) for n in
                      ('require_auth', '_caller_scope', '_tenant_gate', 'respond')}
        self.captured = []

        def _respond(status, data=None, *a, **k):
            self.captured.append((status, data))
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.require_auth = lambda *a, **k: ('alice', 'admin')
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None

    def tearDown(self):
        for n, f in self._real.items():
            setattr(api, n, f)

    def _map(self):
        self.captured = []
        try:
            api.handle_network_map()
        except (api.HTTPError, SystemExit):
            pass
        return self.captured[-1] if self.captured else (None, None)

    def test_a_list_valued_uplink_does_not_500(self):
        api.save(api.DEVICES_FILE, {
            'sw01': {'name': 'switch', 'connected_to': ''},
            'srv1': {'name': 'server', 'connected_to': ['sw01']},
        })
        api._LOAD_CACHE.clear()
        st, data = self._map()
        self.assertEqual(st, 200, 'the whole page is gone, not just the edge')
        self.assertEqual(data['edges'], [{'from': 'srv1', 'to': 'sw01'}],
                         'degrading must not mean dropping the edge when the '
                         'value is recoverable')

    def test_the_ordinary_scalar_still_builds_its_edge(self):
        """Positive control: a guard that returned '' for everything would
        satisfy "does not 500" and silently empty the map."""
        api.save(api.DEVICES_FILE, {
            'sw01': {'name': 'switch', 'connected_to': ''},
            'srv1': {'name': 'server', 'connected_to': 'sw01'},
        })
        api._LOAD_CACHE.clear()
        st, data = self._map()
        self.assertEqual(st, 200)
        self.assertEqual(data['edges'], [{'from': 'srv1', 'to': 'sw01'}])

    def test_junk_shapes_are_ignored_rather_than_fatal(self):
        api.save(api.DEVICES_FILE, {
            'sw01': {'name': 'switch'},
            'a': {'name': 'a', 'connected_to': {'nested': 'dict'}},
            'b': {'name': 'b', 'connected_to': 42},
            'c': {'name': 'c', 'connected_to': [None, {}, 'sw01']},
        })
        api._LOAD_CACHE.clear()
        st, data = self._map()
        self.assertEqual(st, 200)
        self.assertEqual(data['edges'], [{'from': 'c', 'to': 'sw01'}])

    def test_the_normaliser_directly(self):
        f = api._connected_to_id
        self.assertEqual(f({'connected_to': 'x'}), 'x')
        self.assertEqual(f({'connected_to': ['x']}), 'x')
        self.assertEqual(f({'connected_to': []}), '')
        self.assertEqual(f({'connected_to': None}), '')
        self.assertEqual(f({}), '')
        self.assertEqual(f(None), '')


if __name__ == '__main__':
    unittest.main()
