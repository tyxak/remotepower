"""v5.0.0: thermal trend history + the hardware-ingest lock-nesting fix.

`_ingest_hardware` records three trend/history stores (SMART, GPU, temperature),
each via a helper that takes its OWN *_HIST_FILE lock. DATA_DIR shares a single
SQLite connection, so doing that work inside the HARDWARE_FILE lock nests
BEGIN IMMEDIATE and the write is lost (SMART was swallowed by try/except; GPU
raised). The fix captures the data in-lock and writes it after the lock exits.

These tests drive the REAL ingest path and assert all three stores are written —
so they fail under the SQLite backend (`make test-sqlite`) if the regression
ever returns. Also covers the new CMDB Business-function field.

Imports api.py against a throwaway data dir (the established pattern).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class TestHardwareIngestHistory(unittest.TestCase):
    """The lock-nesting regression: every history store must be written even
    under the SQLite backend (one shared connection)."""

    def _ingest(self, dev_id):
        body = {
            'smart': [{'device': '/dev/sda', 'health': 'PASSED',
                       'temperature_c': 41, 'reallocated_sectors': 0}],
            'gpus': [{'vendor': 'nvidia', 'name': 'RTX 4070',
                      'temp_c': 55, 'util_pct': 12, 'mem_used_mb': 1000,
                      'mem_total_mb': 12000}],
            'hardware': {'temps': [{'label': 'coretemp/Package',
                                    'current_c': 63, 'crit_c': 100}]},
        }
        api._ingest_hardware(dev_id, 'host-' + dev_id, body, int(api.time.time()))

    def test_smart_history_written(self):
        self._ingest('hw-smart')
        store = api.load(api.SMART_HIST_FILE) or {}
        self.assertIn('hw-smart', store)
        # at least one disk with at least one sample
        disks = store['hw-smart']
        self.assertTrue(any(d.get('samples') for d in disks.values()))

    def test_gpu_history_written(self):
        self._ingest('hw-gpu')
        store = api.load(api.GPU_HIST_FILE) or {}
        self.assertIn('hw-gpu', store)
        self.assertTrue((store['hw-gpu'].get('0') or {}).get('samples'))

    def test_thermal_history_written(self):
        self._ingest('hw-temp')
        store = api.load(api.THERMAL_HIST_FILE) or {}
        self.assertIn('hw-temp', store)
        samples = store['hw-temp'].get('samples') or []
        self.assertTrue(samples)
        # hottest reading is the 100°C-crit GPU... no: max of 41/55/63 = 63
        self.assertEqual(samples[-1]['temp'], 63.0)

    def test_thermal_history_bounded(self):
        # Sampling many cycles must stay capped at MAX_TEMP_SAMPLES.
        for _ in range(api.MAX_TEMP_SAMPLES + 10):
            api._maybe_sample_temp('hw-cap', 50, 1)
        store = api.load(api.THERMAL_HIST_FILE) or {}
        self.assertLessEqual(len(store['hw-cap']['samples']), api.MAX_TEMP_SAMPLES)


class TestCmdbBusinessFunction(unittest.TestCase):
    def test_allowlist_and_default(self):
        self.assertEqual(
            api.CMDB_BUSINESS_FUNCTIONS,
            ('', 'Application Operation', 'OS Operation', 'Server Camp'))
        self.assertIn('business_function', api._cmdb_record_default())
        self.assertEqual(api._cmdb_record_default()['business_function'], '')


class TestLiveStateRagBinding(unittest.TestCase):
    """v5.0.0: agent signals that were collected + shown but never indexed are
    now in the live_state corpus (mount issues, failing checks, processes, and
    fd/conntrack saturation)."""

    def _corpus(self):
        import rag_index
        dev = {
            'id': 'd1', 'name': 'web1',
            'sysinfo': {
                'fd_percent': 91, 'conntrack_percent': 88,
                'mount_issues': ['/mnt/nfs stalled'],
                'proc_names': ['nginx', 'postgres', 'sshd', 'nginx'],
                'custom_check_results': [
                    {'name': 'backup', 'status': 'fail', 'detail': 'no run'},
                    {'name': 'ntp', 'status': 'ok'},
                ],
            },
        }
        return rag_index.build_live_state_corpus([dev])

    def test_new_chunks_present(self):
        kinds = {d.get('type') for d in self._corpus()}
        for k in ('device_mount_issues', 'device_checks', 'device_processes'):
            self.assertIn(k, kinds)

    def test_fd_conntrack_in_usage_chunk(self):
        usage = next((d for d in self._corpus()
                      if d.get('type') == 'device_metrics'), None)
        self.assertIsNotNone(usage)
        self.assertIn('file descriptors', usage['text'])
        self.assertIn('conntrack', usage['text'])

    def test_only_failing_checks_indexed(self):
        checks = next((d for d in self._corpus()
                       if d.get('type') == 'device_checks'), None)
        self.assertIsNotNone(checks)
        self.assertIn('backup', checks['text'])
        self.assertNotIn('ntp', checks['text'])  # ok checks excluded


if __name__ == '__main__':
    unittest.main()
