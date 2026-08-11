#!/usr/bin/env python3
"""Per-device history stores write ONE row, not the whole fleet's.

Four history blobs were rewritten IN FULL on every ingest — one write per
device per cycle — so the cost was O(fleet) per sample while the arrival rate
was also O(fleet), making aggregate duty O(N^2). Invisible at 50 devices,
dominant at 400.

MEASURED, 400 devices, SQLite:

    thermal_history       101.2 ms -> 0.3 ms   (13.5 % duty -> ~0)
    smart_history         145.0 ms -> 0.4 ms   (19.3 % -> 0.1 %)
    gpu_history           144.0 ms -> 0.4 ms   (19.2 % -> ~0)
    custom_metrics_hist   255.9 ms -> 0.6 ms   (34.1 % -> 0.1 %)

Under SQLite these share one DB-wide BEGIN IMMEDIATE, so the cost fell on every
unrelated write too — an ordinary small write measured p90 0.84 ms -> 104 ms
while these were running at production rate.

BOTH HALVES ARE REQUIRED, and this is the part that had already gone wrong
once: adding a store to `storage.ENTITY_FILES` is a NO-OP on its own.
`_save_entity` still serialises every key to compute its diff, so a writer
holding a whole-store lock pays the same either way. snmp_if_hist.json sat
promoted-and-unimproved for a full release because only the registry entry
landed. The tests below therefore assert the writer AND the registration.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643hist-'))

_spec = importlib.util.spec_from_file_location('api_v643_hist', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

_GPUS = [{'name': 'RTX', 'vendor': 'nvidia', 'temp_c': 61, 'util_pct': 33,
          'mem_used_mb': 4000, 'mem_total_mb': 8000}]
_DISKS = [{'device': '/dev/sda', 'model': 'X', 'reallocated_sectors': 0,
           'pending_sectors': 0, 'wear_pct': 5, 'temperature_c': 36,
           'crc_errors': 0}]


class _Base(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        for f in (api.THERMAL_HIST_FILE, api.SMART_HIST_FILE,
                  api.GPU_HIST_FILE, api.CUSTOM_METRICS_HIST_FILE):
            api.save(f, {'other': {'untouched': True}})
            api._invalidate_load_cache(f)

    def _store(self, f):
        api._invalidate_load_cache(f)
        return api.load(f) or {}


class TestEachWriterStillRecords(_Base):
    """Positive controls. A writer that wrote nothing would satisfy every
    isolation assertion in the next class."""

    def test_thermal(self):
        api._maybe_sample_temp('devA', 55.0, self.now)
        s = self._store(api.THERMAL_HIST_FILE)['devA']['samples']
        self.assertEqual(s[-1]['temp'], 55.0)

    def test_smart(self):
        api._maybe_sample_smart('devA', _DISKS, self.now)
        rec = self._store(api.SMART_HIST_FILE)['devA']
        disk = next(iter(rec.values()))
        self.assertEqual(disk['samples'][-1]['temp'], 36)

    def test_gpu(self):
        api._maybe_sample_gpu('devA', _GPUS, self.now)
        rec = self._store(api.GPU_HIST_FILE)['devA']['0']
        self.assertEqual(rec['samples'][-1]['temp'], 61)
        self.assertEqual(rec['samples'][-1]['mem'], 50.0)

    def test_custom_metrics(self):
        # signature is (dev_id, custom_metrics, dev_name, now) — passing
        # dev_name where the metrics go makes it return [] immediately, which
        # is exactly how the first draft of the benchmark for this change
        # measured 0.0 ms on both sides and proved nothing.
        api._ingest_custom_metrics('devA', {'qdepth': 2.0}, 'web', self.now)
        rec = self._store(api.CUSTOM_METRICS_HIST_FILE)['devA']['qdepth']
        self.assertEqual(rec['samples'][-1]['val'], 2.0)

    def test_custom_metric_alerts_still_edge_trigger(self):
        """The alert state lives IN this store, so a per-row round-trip has to
        preserve it or every sample re-fires."""
        api.save(api.CONFIG_FILE, {'custom_metric_thresholds': {
            'qdepth': {'value': 1.0, 'op': 'gt', 'severity': 'high'}}})
        api._invalidate_load_cache(api.CONFIG_FILE)
        first = api._ingest_custom_metrics('devA', {'qdepth': 9.0}, 'web', self.now)
        again = api._ingest_custom_metrics('devA', {'qdepth': 9.0}, 'web', self.now + 1)
        self.assertIn('custom_metric_alert', [e for e, _p in first])
        self.assertNotIn('custom_metric_alert', [e for e, _p in again],
                         'the alerted flag did not survive the per-row write')


class TestEachWriterTouchesOneDevice(_Base):
    def test_no_writer_disturbs_a_neighbour(self):
        api._maybe_sample_temp('devA', 55.0, self.now)
        api._maybe_sample_smart('devA', _DISKS, self.now)
        api._maybe_sample_gpu('devA', _GPUS, self.now)
        api._ingest_custom_metrics('devA', {'qdepth': 2.0}, 'web', self.now)
        for f in (api.THERMAL_HIST_FILE, api.SMART_HIST_FILE,
                  api.GPU_HIST_FILE, api.CUSTOM_METRICS_HIST_FILE):
            self.assertEqual(self._store(f).get('other'), {'untouched': True},
                             f'{f.name}: writing devA modified another device')


class TestBothHalvesOfThePromotion(unittest.TestCase):
    """Registry + writer. Either alone is worthless: the registry without the
    writer changes nothing measurable (snmp_if_hist proved that for a whole
    release), and the writer without the registry silently falls back to
    load()[dev_id], which is the same whole-fleet read it was meant to avoid."""

    STORES = ('thermal_history', 'smart_history', 'gpu_history',
              'custom_metrics_hist', 'snmp_if_hist')

    def test_every_store_is_entity_promoted(self):
        import storage
        names = {str(getattr(f, 'name', f)) for f in storage.ENTITY_FILES}
        for want in self.STORES:
            self.assertTrue(any(want in n for n in names),
                            f'{want} is not in ENTITY_FILES')

    def test_no_writer_locks_the_whole_store(self):
        import ast
        import inspect
        for fn in (api._maybe_sample_temp, api._maybe_sample_smart,
                   api._maybe_sample_gpu, api._ingest_custom_metrics):
            node = ast.parse(inspect.getsource(fn)).body[0]
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)):
                node.body.pop(0)      # docstrings mention the old pattern
            code = ast.unparse(node)
            self.assertNotIn('_locked_update', code, fn.__name__)
            self.assertNotIn('_LockedUpdate', code, fn.__name__)
            self.assertIn('_entity_write_one', code, fn.__name__)

    def test_both_backends_migrate_the_same_set(self):
        """A store promoted on SQLite but not migrated on Postgres would leave
        live data stranded in the old kv blob — invisible until someone asked
        for the history. The existing lockstep guard caught exactly this when
        the SQLite side landed first."""
        import storage
        pg = (_CGI / 'storage_pg.py').read_text()
        self.assertIn('_COLD_TO_ENTITY_V8', pg,
                      'Postgres does not run the v6.4.3 migration wave')
        self.assertEqual(len(storage._COLD_TO_ENTITY_V8), 4)

    def test_the_schema_version_was_bumped(self):
        """The migration only runs when the DB's recorded version is older."""
        import storage
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 10)


if __name__ == '__main__':
    unittest.main()
