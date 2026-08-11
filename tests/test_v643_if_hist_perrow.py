#!/usr/bin/env python3
"""Per-port SNMP history writes ONE device's row, not the whole fleet's.

SNMP_IF_HIST_FILE was added to `storage.ENTITY_FILES` in v6.4.2, with a comment
saying it was to stop "re-serialising the WHOLE fleet's per-port ring under the
DB-wide BEGIN IMMEDIATE lock". The writer kept opening a whole-dict
`_LockedUpdate`, so the registry entry bought nothing.

That is the load-bearing correction, and it generalises: ENTITY promotion alone
is a NO-OP. `_save_entity` still serialises every key to compute its diff and
the entity load reassembles the whole dict row by row, so a writer holding a
whole-store lock pays the same cost either way. The saving appears only when
the WRITER also moves to `_entity_read_one` / `_entity_write_one`, which
`_maybe_sample_metrics` had been doing correctly all along.

MEASURED on a 400-device x 4-port store, SQLite:

    before   103.2 ms per device walk   -> 13.8 % duty at a 300 s cadence
    after      0.4 ms                   ->  ~0 %

The cost is O(fleet) per sample and the arrival rate is O(fleet), so aggregate
duty is O(N^2) — which is why this is invisible on a small fleet and dominant
on a large one. Under SQLite these writes share one DB-wide lock, so the cost
lands on every unrelated write too, not just on SNMP.

The tests below assert BEHAVIOUR (one device's row changes, its neighbours do
not) rather than timing, because a timing assertion is a flake generator. The
source pin is deliberately narrow: it asserts the whole-store lock is gone,
which is the specific thing that regressed here before.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643ifh-'))

_spec = importlib.util.spec_from_file_location('api_v643_ifh', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


def _rows(n=2, **over):
    return [dict({'descr': f'gi1/0/{p}', 'index': p, 'speed_bps': 10 ** 9,
                  'admin': 'up', 'oper': 'up',
                  'in_octets': 10 ** 6, 'out_octets': 10 ** 6,
                  'in_errors': 0, 'out_errors': 0}, **over) for p in range(n)]


class _Base(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api.save(api.SNMP_IF_HIST_FILE, {
            'devA': {'gi1/0/0': {'descr': 'gi1/0/0', 'index': 0,
                                 'samples': [{'ts': self.now - 300,
                                              'in_octets': 1, 'out_octets': 1}]}},
            'devB': {'gi1/0/0': {'descr': 'gi1/0/0', 'index': 0,
                                 'samples': [{'ts': self.now - 300,
                                              'in_octets': 5, 'out_octets': 5}]}},
        })
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)

    def _store(self):
        api._invalidate_load_cache(api.SNMP_IF_HIST_FILE)
        return api.load(api.SNMP_IF_HIST_FILE) or {}


class TestItStillRecords(_Base):
    """Positive controls. A writer that wrote nothing would satisfy every
    isolation assertion below."""

    def test_a_sample_is_appended(self):
        api._record_if_samples('devA', _rows(), self.now)
        h = self._store()['devA']['gi1/0/0']
        self.assertEqual(len(h['samples']), 2)
        self.assertEqual(h['samples'][-1]['in_octets'], 10 ** 6)

    def test_a_new_device_gets_a_row(self):
        api._record_if_samples('devNEW', _rows(), self.now)
        self.assertIn('devNEW', self._store())

    def test_a_new_port_is_added_to_an_existing_device(self):
        api._record_if_samples('devA', _rows(3), self.now)
        self.assertEqual(len(self._store()['devA']), 3)

    def test_rate_and_utilisation_are_computed(self):
        api._record_if_samples('devA', _rows(1), self.now)
        s = self._store()['devA']['gi1/0/0']['samples'][-1]
        self.assertIsNotNone(s.get('in_bps'))
        self.assertIsNotNone(s.get('util'))

    def test_link_down_still_fires_edge_triggered(self):
        pending = api._record_if_samples('devA', _rows(1, oper='down'), self.now)
        self.assertIn('snmp_if_down', [e for e, _p in pending])
        again = api._record_if_samples('devA', _rows(1, oper='down'), self.now + 1)
        self.assertNotIn('snmp_if_down', [e for e, _p in again],
                         'edge-triggered means once per transition')


class TestItTouchesOnlyOneDevice(_Base):
    def test_a_neighbours_row_is_untouched(self):
        before = dict(self._store()['devB']['gi1/0/0'])
        api._record_if_samples('devA', _rows(), self.now)
        self.assertEqual(self._store()['devB']['gi1/0/0'], before,
                         "writing devA modified devB's row")

    def test_a_concurrent_neighbour_write_is_not_lost(self):
        """The point of per-row writes. Under the old whole-store lock, a
        writer that had loaded the fleet before a neighbour's write would
        clobber it on save."""
        stale = api._entity_read_one(api.SNMP_IF_HIST_FILE, 'devA', None)
        api._record_if_samples('devB', _rows(), self.now)      # neighbour writes
        api._entity_write_one(api.SNMP_IF_HIST_FILE, 'devA', stale)  # we save ours
        self.assertEqual(len(self._store()['devB']['gi1/0/0']['samples']), 2,
                         "devB's write was clobbered by an unrelated device")


class TestTheWholeStoreLockIsGone(unittest.TestCase):
    """The specific regression. ENTITY promotion without a per-row WRITER is a
    no-op — the registry entry has been there since v6.4.2 and bought nothing
    until the writer changed too."""

    def test_the_writer_does_not_lock_the_whole_store(self):
        import ast
        import inspect
        src = inspect.getsource(api._record_if_samples)
        tree = ast.parse(src)
        node = tree.body[0]
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)):
            node.body.pop(0)          # the docstring names the old pattern
        code = ast.unparse(node)
        self.assertNotIn('_LockedUpdate', code,
                         'a whole-store lock re-serialises the entire fleet on '
                         'every device walk; use _entity_read_one / '
                         '_entity_write_one')
        self.assertIn('_entity_write_one', code)

    def test_the_store_is_still_entity_promoted(self):
        """Both halves are required. Per-row helpers fall back to
        load()[dev_id] when the store is not in ENTITY_FILES, which would make
        the writer correct and the saving imaginary."""
        import storage
        names = {getattr(f, 'name', str(f)) for f in storage.ENTITY_FILES} \
            if not isinstance(next(iter(storage.ENTITY_FILES), ''), str) \
            else set(storage.ENTITY_FILES)
        self.assertTrue(any('snmp_if_hist' in n for n in names),
                        f'snmp_if_hist is not entity-promoted: {sorted(names)[:8]}')


if __name__ == '__main__':
    unittest.main()
