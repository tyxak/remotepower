"""v6.1.2 perf wave 2 — items 3, 5, 6, 7 from perf-10-improvements-internal.md.

These are performance changes, so the tests pin the BEHAVIOUR the optimisation must
not break (the data still comes back, the 304 is never stale) rather than timing —
a timing assertion in CI is a flake generator, and it wouldn't catch the failure
modes that actually matter here.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

import storage                    # noqa: E402
import storage_pg                 # noqa: E402


def _fresh_api(backend=None):
    d = tempfile.mkdtemp(prefix='rp-v612-perf2-')
    os.environ['RP_DATA_DIR'] = d
    if backend:
        os.environ['RP_STORAGE_BACKEND'] = backend
        (Path(d) / '.storage_backend').write_text(backend)
    else:
        os.environ.pop('RP_STORAGE_BACKEND', None)
    spec = importlib.util.spec_from_file_location('api_v612_perf2', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMetricsWindowSingleWrite(unittest.TestCase):
    """perf #3: the DB backends wrote every sample TWICE — once as a row in the
    append-only metric_samples table (O(1)) and once by re-serialising the whole
    ~1440-sample window blob (O(window)). The blob was pure duplication."""

    def test_sqlite_no_longer_maintains_the_window_blob(self):
        api = _fresh_api('sqlite')
        for i in range(5):
            api._record_metrics('d1', {'cpu_percent': 10 + i, 'mem_percent': 50,
                                       'disk_percent': 30, 'swap_percent': 1})
        blob = api._dbmod().entity_get(api.METRICS_FILE, 'd1') or []
        self.assertEqual(blob, [],
                         'the window blob must no longer be written on a DB backend')

    def test_the_window_is_still_readable_and_faithful(self):
        """Deriving the window from the time-series must return the SAME samples —
        this is the thing that would silently break, and it feeds the charts."""
        api = _fresh_api('sqlite')
        m = api._dbmod()
        base = int(time.time()) - 120 * 60
        for i in range(120):                       # one sample a minute, like an agent
            m.metric_append(api.DATA_DIR, 'd1', base + i * 60,
                            float(i), 50.0, 1.0, 30.0)
        win = api._recent_metric_window('d1')
        self.assertEqual(len(win), 120)
        self.assertEqual(win[0]['cpu'], 0.0)
        self.assertEqual(win[-1]['cpu'], 119.0)
        self.assertTrue(all(win[i]['ts'] <= win[i + 1]['ts'] for i in range(len(win) - 1)))

    def test_a_legacy_blob_is_still_served_when_the_series_is_empty(self):
        """An older DB upgraded mid-life has rows in the blob and nothing in the
        time-series yet. Dropping straight to the series would show that host an
        empty chart — so the blob stays the fallback."""
        api = _fresh_api('sqlite')
        m = api._dbmod()
        m.entity_set(api.METRICS_FILE, 'old',
                     [{'ts': int(time.time()) - 60, 'cpu': 99,
                       'mem': 1, 'disk': 2, 'swap': 3}])
        api._invalidate_load_cache(api.METRICS_FILE)
        win = api._recent_metric_window('old')
        self.assertEqual(len(win), 1)
        self.assertEqual(win[0]['cpu'], 99)

    def test_the_json_backend_still_uses_the_blob(self):
        """The JSON backend has no time-series table — there, the blob IS the store,
        and removing it would delete the feature."""
        api = _fresh_api()
        for i in range(3):
            api._record_metrics('d1', {'cpu_percent': 10 + i, 'mem_percent': 50,
                                       'disk_percent': 30, 'swap_percent': 1})
        blob = (api.load(api.METRICS_FILE) or {}).get('d1') or []
        self.assertEqual(len(blob), 3)
        self.assertEqual(len(api._recent_metric_window('d1')), 3)


class TestMetricsRollupIsAnEntityStore(unittest.TestCase):
    """perf #5: metrics_rollup.json is keyed by device and holds hourly(30d) +
    daily(2y) per device — it grows O(devices x 2 years). As a cold blob, the
    hourly sweep rewrote ALL of it and one device's chart parsed ALL of it."""

    def test_it_is_registered_as_an_entity_file(self):
        self.assertIn('metrics_rollup.json', storage.ENTITY_FILES)

    def test_an_existing_database_migrates_its_blob(self):
        """Without a migration wave, a DB that already passed the earlier schema
        gates would never re-run the split and its rollup data would be stranded
        as an unmigrated kv blob forever (the commands.json bug, v6.1.1)."""
        self.assertIn('metrics_rollup.json', storage._COLD_TO_ENTITY_V7)
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 9)
        self.assertGreaterEqual(storage_pg.SCHEMA_VERSION, 8)

    def test_both_backends_run_the_migration(self):
        src = (CGI / 'storage.py').read_text()
        self.assertIn('_migrate_cold_to_entity(conn, _COLD_TO_ENTITY_V7)', src)
        pg = (CGI / 'storage_pg.py').read_text()
        self.assertIn('_migrate_cold_to_entity_pg(conn, storage._COLD_TO_ENTITY_V7)', pg)

    def test_a_single_device_rollup_is_a_one_row_read(self):
        api = _fresh_api('sqlite')
        api.save(api.METRICS_ROLLUP_FILE, {
            '_meta': {'last_run': 123},
            'd1': {'last_ts': 5, 'hourly': [], 'daily': [{'ts': 1, 'cpu': 1}]},
            'd2': {'last_ts': 9, 'hourly': [], 'daily': []},
        })
        rec = api._entity_read_one(api.METRICS_ROLLUP_FILE, 'd1', {})
        self.assertEqual(rec['last_ts'], 5)
        meta = api._entity_read_one(api.METRICS_ROLLUP_FILE, '_meta', {})
        self.assertEqual(meta['last_run'], 123)

    def test_the_cadence_gate_reads_only_the_meta_row(self):
        """The is-it-due? check runs on EVERY request. It used to load+parse the
        whole fleet's rollup history just to read one integer, on the not-due path."""
        src = (CGI / 'api.py').read_text()
        i = src.index('def run_metric_rollup_if_due')
        head = src[i:i + 4000]
        # Everything before the "is it due?" early-return runs on EVERY request.
        gate = head[:head.index('METRIC_ROLLUP_INTERVAL')]
        self.assertIn("_entity_read_one(METRICS_ROLLUP_FILE, '_meta'", gate)
        self.assertNotIn('load(METRICS_ROLLUP_FILE)', gate,
                         'the not-due path must not load the whole store')


class TestConditionalNavCounts(unittest.TestCase):
    """perf #6: the hottest poll in the product — every open tab, every 60s."""

    def setUp(self):
        self.api = _fresh_api()
        self.api.require_auth = lambda *a, **k: 'admin'
        self.env = {}
        self.api._env = lambda k, d='': self.env.get(k, d)
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'a', 'monitored': True}})

    def _call(self):
        try:
            self.api.handle_nav_counts()
        except self.api.HTTPError as e:
            return e.status, e.body, dict(getattr(e, 'headers', None) or [])
        return None, None, {}

    def test_an_etag_is_issued(self):
        st, _body, hdrs = self._call()
        self.assertEqual(st, 200)
        self.assertTrue(hdrs.get('ETag'))
        # A conditional GET is meaningless under no-store: the client would have
        # nothing to revalidate.
        self.assertEqual(hdrs.get('Cache-Control'), 'no-cache')

    def test_an_unchanged_fleet_304s_with_no_body(self):
        _st, _b, hdrs = self._call()
        self.env['HTTP_IF_NONE_MATCH'] = hdrs['ETag']
        st, body, _h = self._call()
        self.assertEqual(st, 304)
        self.assertIsNone(body)

    def test_a_changed_fleet_must_NOT_304(self):
        """The failure that matters: a stale 304 would freeze the sidebar badges
        at their old values and the operator would never see the new alert."""
        _st, _b, hdrs = self._call()
        self.env['HTTP_IF_NONE_MATCH'] = hdrs['ETag']
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'name': 'a', 'monitored': True},
            'd2': {'name': 'b', 'monitored': True}})
        self.api._invalidate_load_cache(self.api.DEVICES_FILE)
        st, body, _h = self._call()
        self.assertEqual(st, 200)
        self.assertIsNotNone(body)

    def test_the_etag_is_content_based_not_mtime_based(self):
        """v6.1.2 fix: the ETag hashes the actual payload, NOT the source-store
        mtimes. An mtime ETag is WRONG here — the offline/monitors-down counts are
        wall-clock-derived (a device crosses the offline TTL with no store write),
        so a store-mtime ETag couldn't detect the transition and would serve a
        stale 304 (a dead device still shown "online" on a small idle fleet).
        Content-hashing also inherently separates callers with different counts,
        so no explicit scope/tenant term is needed in the source."""
        src = (CGI / 'api.py').read_text()
        i = src.index('def handle_nav_counts')
        body = src[i:i + 11000]        # the fresh-path respond is ~9200 chars in
        self.assertIn('_respond_with_etag(out, out)', body,
                      'the fresh path must hash the payload itself')
        self.assertIn('_respond_with_etag(_c, _c)', body,
                      'the cached path must hash the payload itself')
        self.assertNotIn('_nc_etag_src', body,
                         'the old mtime-based ETag source must be gone')

    def test_an_offline_transition_busts_the_etag(self):
        """The concrete staleness fix: an all-online fleet and an all-offline fleet
        must NOT share an ETag, even though a store-mtime ETag might (an offline
        state that arose from wall-clock, not a write, is mtime-invisible).

        Two fresh instances rather than an in-place last_seen edit: in production a
        device goes offline by `now` advancing past a FROZEN last_seen, never by
        rewriting last_seen backward — and the last_seen regression guard blocks
        the backward write anyway. Fresh instances model the real state cleanly."""
        import time
        now = int(time.time())
        online = _fresh_api()
        online.require_auth = lambda *a, **k: 'admin'
        online._env = lambda k, d='': ''
        online.save(online.DEVICES_FILE,
                    {'d1': {'name': 'a', 'monitored': True, 'last_seen': now}})
        offline = _fresh_api()
        offline.require_auth = lambda *a, **k: 'admin'
        offline._env = lambda k, d='': ''
        offline.save(offline.DEVICES_FILE,
                     {'d1': {'name': 'a', 'monitored': True, 'last_seen': now - 10 ** 6}})

        def etag(api):
            try:
                api.handle_nav_counts()
            except api.HTTPError as e:
                return dict(getattr(e, 'headers', None) or []).get('ETag')
        self.assertNotEqual(etag(online), etag(offline),
                            'the offline count differs — the ETag must differ too')


class TestLoadRo(unittest.TestCase):
    """perf #7: load() deepcopies the whole store on every read to protect the
    cache from mutating callers. Read-only handlers don't need that copy."""

    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'nas'}})

    def test_warm_reads_skip_the_deepcopy(self):
        self.api._load_ro(self.api.DEVICES_FILE)          # warm the cache
        a = self.api._load_ro(self.api.DEVICES_FILE)
        b = self.api._load_ro(self.api.DEVICES_FILE)
        self.assertIs(a, b, 'warm _load_ro reads must share one object')

    def test_load_still_copies(self):
        self.assertIsNot(self.api.load(self.api.DEVICES_FILE),
                         self.api.load(self.api.DEVICES_FILE),
                         'load() must keep copying — mutating callers depend on it')

    def test_a_cold_cache_is_still_correct(self):
        self.api._invalidate_load_cache(self.api.DEVICES_FILE)
        self.assertEqual(self.api._load_ro(self.api.DEVICES_FILE)['d1']['name'], 'nas')

    def test_nav_counts_uses_it(self):
        src = (CGI / 'api.py').read_text()
        i = src.index('def handle_nav_counts')
        body = src[i:i + 6000]
        self.assertIn('_load_ro(DEVICES_FILE)', body)


if __name__ == '__main__':
    unittest.main()
