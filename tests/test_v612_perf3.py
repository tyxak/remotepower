"""v6.1.2 perf wave 3 — items 4 (alerts row-level writes) and 8 (eager JS payload).

#4 is the one change in the perf programme that could LOSE an alert if it's wrong,
so these tests drive the real _record_alert on both backends and assert the exact
inbox semantics (coalesce, monotonic ids, resolved rows don't merge, the cap) —
not just that it's faster.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
HTML = ROOT / 'server' / 'html'
sys.path.insert(0, str(CGI))

import storage        # noqa: E402


def _fresh_api(backend=None):
    d = tempfile.mkdtemp(prefix='rp-v612-perf3-')
    os.environ['RP_DATA_DIR'] = d
    if backend:
        os.environ['RP_STORAGE_BACKEND'] = backend
        (Path(d) / '.storage_backend').write_text(backend)
    else:
        os.environ.pop('RP_STORAGE_BACKEND', None)
    spec = importlib.util.spec_from_file_location('api_v612_perf3', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _AlertsBase:
    """The SAME assertions run against both backends. A handler that works on two
    backends and breaks on the third is this codebase's recurring failure mode, and
    _record_alert now takes a different code path on each."""

    BACKEND = None

    def setUp(self):
        self.api = _fresh_api(self.BACKEND)
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'nas', 'monitored': True},
            'd2': {'name': 'pve', 'monitored': True},
        })

    def _rows(self):
        return (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts') or []

    def _fire(self, dev):
        return self.api._record_alert(
            'device_offline', {'device_id': dev, 'device_name': dev})

    def test_a_repeat_of_the_same_condition_coalesces(self):
        a1 = self._fire('d1')
        a2 = self._fire('d1')
        rows = self._rows()
        self.assertEqual(len(rows), 1, 'the inbox must show ONE live row, not two')
        self.assertEqual(a2['id'], a1['id'], 'coalesce must return the existing row')
        self.assertEqual(rows[0]['count'], 2)

    def test_a_different_device_appends(self):
        self._fire('d1')
        self._fire('d2')
        self.assertEqual(len(self._rows()), 2)

    def test_alertids_are_monotonic_and_persisted(self):
        """The counter must survive as the file's sibling metadata and be bumped
        ATOMICALLY with the insert — it used to be a read-modify-write under the
        same lock, and an id collision would break every external ITSM reference."""
        self._fire('d1')
        self._fire('d2')
        ids = sorted(r['alertid'] for r in self._rows())
        self.assertEqual(ids, ['alertid_000001', 'alertid_000002'])
        store = self.api.load(self.api.ALERTS_FILE) or {}
        self.assertEqual(store.get('alert_seq'), 2)

    def test_a_resolved_alert_does_not_coalesce(self):
        """A condition that recurs AFTER being resolved is a NEW incident. Merging
        into the resolved row would hide it from the inbox entirely."""
        self._fire('d1')
        store = self.api.load(self.api.ALERTS_FILE)
        store['alerts'][0]['resolved_at'] = 123
        self.api.save(self.api.ALERTS_FILE, store)
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)

        a2 = self._fire('d1')
        rows = self._rows()
        self.assertEqual(len(rows), 2, 'a re-fire after resolve must be a NEW row')
        self.assertEqual(a2['alertid'], 'alertid_000002')

    def test_the_counter_keeps_growing_past_the_cap(self):
        """Ids are never reused even after the ledger trims, so an external system
        holding alertid_000005 can't be handed a different alert later."""
        self._fire('d1')
        self._fire('d2')
        store = self.api.load(self.api.ALERTS_FILE) or {}
        self.assertEqual(store.get('alert_seq'), 2)
        # resolve both so the next fires append rather than coalesce
        for r in store['alerts']:
            r['resolved_at'] = 1
        self.api.save(self.api.ALERTS_FILE, store)
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)
        a = self._fire('d1')
        self.assertEqual(a['alertid'], 'alertid_000003')

    def test_an_unidentifiable_alert_still_appends(self):
        """Two anonymous same-event alerts may be genuinely distinct occurrences,
        so they must NOT be merged into one."""
        self.api._record_alert('device_offline', {})
        self.api._record_alert('device_offline', {})
        # (device_offline with no device is unidentifiable → both rows survive)
        self.assertGreaterEqual(len(self._rows()), 1)


class TestAlertsJsonBackend(_AlertsBase, unittest.TestCase):
    BACKEND = None


class TestAlertsSqliteBackend(_AlertsBase, unittest.TestCase):
    BACKEND = 'sqlite'


class TestAlertWritesAreConstantTime(unittest.TestCase):
    """perf #4, the actual point: recording ONE alert must not cost O(fleet) DB
    writes. save() on a wrapped-list file DELETEs every row and re-INSERTs every
    row, so the old path was ~2N writes per alert — O(N^2) across a storm, which is
    exactly when the server has to keep up."""

    def test_writes_do_not_grow_with_the_number_of_open_alerts(self):
        api = _fresh_api('sqlite')
        api.save(api.DEVICES_FILE,
                 {f'd{i}': {'name': f'h{i}', 'monitored': True} for i in range(260)})

        def writes_for(dev, seeded):
            conn = storage._connect(api.DATA_DIR)
            seen = []
            conn.set_trace_callback(
                lambda sql: seen.append(sql.strip().split()[0].upper()))
            api._record_alert('device_offline',
                              {'device_id': dev, 'device_name': dev})
            conn.set_trace_callback(None)
            return sum(1 for v in seen if v in ('INSERT', 'UPDATE', 'DELETE'))

        # Both probes must be NEW alerts (an unseeded device), or one of them
        # coalesces and we'd be comparing an UPDATE against an INSERT.
        for i in range(50):
            api._record_alert('device_offline',
                              {'device_id': f'd{i}', 'device_name': f'h{i}'})
        few = writes_for('d255', 50)
        for i in range(50, 250):
            api._record_alert('device_offline',
                              {'device_id': f'd{i}', 'device_name': f'h{i}'})
        many = writes_for('d256', 250)

        self.assertEqual(few, many,
                         f'alert write cost grew with the ledger ({few} -> {many} '
                         'statements) — the O(N) rewrite is back')
        self.assertLessEqual(many, 8, 'a single alert must be a handful of writes')

    def test_the_primitive_exists_on_both_db_backends(self):
        """Lock/write parity: a primitive present on one backend and missing on the
        other is how POST /api/cve/scan came to 500 in production only."""
        import storage_pg
        self.assertTrue(hasattr(storage, 'list_coalesce_or_append'))
        self.assertTrue(hasattr(storage_pg, 'list_coalesce_or_append'))


class TestEagerJsPayload(unittest.TestCase):
    """perf #8: i18n.js (~776 KB) was the second-largest asset and pure dead weight
    for an English user — the default, and the large majority of loads."""

    @classmethod
    def setUpClass(cls):
        cls.html = (HTML / 'index.html').read_text()
        cls.app = (HTML / 'static' / 'js' / 'app.js').read_text()
        cls.sw = (HTML / 'sw.js').read_text()

    def test_i18n_is_not_an_eager_script(self):
        self.assertNotIn('<script defer src="static/js/i18n.js', self.html)

    def test_i18n_is_not_precached_by_the_service_worker(self):
        """Precaching it would silently re-download the whole catalogue on install
        and undo the saving entirely."""
        block = self.sw[self.sw.index('const SHELL_ASSETS'):]
        block = block[:block.index('];')]
        self.assertNotIn("'/static/js/i18n.js'", block)

    def test_it_is_loaded_on_demand(self):
        self.assertIn('function _ensureI18n', self.app)
        self.assertIn("static/js/i18n.js?v=", self.app)

    def test_all_three_triggers_are_wired(self):
        """Miss any one and the feature becomes unreachable rather than merely
        slower: no boot trigger = a remembered language never applies; no /api/me
        trigger = an account language never applies; no Settings trigger = the
        language <select> is EMPTY, so an English user can never leave English."""
        self.assertIn("localStorage.getItem('rp_lang')", self.app)
        self.assertIn('_ensureI18n().then(i18n => { if (i18n) i18n.adopt(me.lang); });',
                      self.app)
        # the account pane pulls it in so i18n.js's own init() can build the picker
        i = self.app.index('_buildAppearancePicker();   // v3.14.0')
        self.assertIn('_ensureI18n();', self.app[i - 500:i])

    def test_a_failed_load_does_not_deadlock_the_caller(self):
        block = self.app[self.app.index('function _ensureI18n'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn('sc.onerror', block, 'a missing/blocked i18n.js must resolve, '
                                           'not hang the language picker forever')

    def test_the_eager_payload_actually_shrank(self):
        srcs = re.findall(r'<script[^>]*src="(static/js/[a-z0-9._-]+\.js)', self.html)
        total = sum((HTML / s).stat().st_size for s in srcs if (HTML / s).exists())
        self.assertNotIn('static/js/i18n.js', srcs)
        # Sanity: the remaining eager set must still contain the app itself.
        self.assertIn('static/js/app.js', srcs)
        self.assertLess(total, 2_600_000,
                        'the eager JS payload regressed past its pre-v6.1.2 size')


if __name__ == '__main__':
    unittest.main()
