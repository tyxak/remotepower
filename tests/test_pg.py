#!/usr/bin/env python3
"""
PostgreSQL backend integration tests (v3.14.0, #1).

Gated on a real Postgres: set RP_PG_TEST_DSN (or drop the DSN in
~/.rp_pg_test_dsn). When neither is present every test is skipped, so normal CI
on a box without Postgres stays green. Run against a *throwaway* database — the
tests TRUNCATE all backend tables between cases.

    RP_PG_TEST_DSN=postgresql://rp:***@localhost:15432/rp_test \
        python -m unittest tests.test_pg -v

Covers both layers:
  * storage_pg directly — every store kind round-trips, last_seen clamp, deletes,
    list cap, LockedUpdate / DeviceTxn / upsert_device, presence/inventory, and a
    real cross-session non-blocking lock (LockBusyError).
  * api.py dispatch — with backend='postgres', api.load/save/_LockedUpdate/
    _DeviceUpdate route to storage_pg and round-trip.
"""
import os
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

def _resolve_dsn():
    env = os.environ.get('RP_PG_TEST_DSN')
    if env:
        return env
    f = Path.home() / '.rp_pg_test_dsn'
    if f.exists():
        try:
            return f.read_text().strip()
        except OSError:
            return ''
    return ''


_DSN = _resolve_dsn()
_SKIP = not _DSN
# A DSN can be configured (env or ~/.rp_pg_test_dsn) while the server is
# unreachable — e.g. the SSH tunnel is down, or the test DB hasn't been created
# yet. In that case SKIP rather than erroring 16 times: probe once, and if the
# connection fails, treat it the same as "no DSN configured". (Set
# RP_PG_REQUIRE=1 to make an unreachable DSN a hard failure in CI instead.)
_SKIP_REASON = "no Postgres DSN (set RP_PG_TEST_DSN or ~/.rp_pg_test_dsn)"
if not _SKIP and not os.environ.get('RP_PG_REQUIRE'):
    try:
        import psycopg as _probe_psycopg
        _probe_psycopg.connect(_DSN, connect_timeout=3).close()
    except Exception as _e:
        _SKIP = True
        _SKIP_REASON = f"Postgres DSN configured but unreachable ({type(_e).__name__}) — skipping"


def _truncate(S):
    conn = S._connect(None)
    for t in ('kv', 'devices', 'entity', 'listrow', 'file_meta', 'metric_samples'):
        conn.execute(f'TRUNCATE {t}')


@unittest.skipIf(_SKIP, _SKIP_REASON)
class TestStoragePgBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['RP_PG_DSN'] = _DSN
        import storage_pg
        cls.S = storage_pg
        cls.S.configure_dsn(_DSN)

    def setUp(self):
        _truncate(self.S)
        self.d = Path(tempfile.mkdtemp())

    def _p(self, name):
        return self.d / name

    def test_cold_roundtrip(self):
        self.S.save(self._p('config.json'), {'a': 1, 'n': {'x': [1, 2]}})
        self.assertEqual(self.S.load(self._p('config.json')), {'a': 1, 'n': {'x': [1, 2]}})

    def test_devices_clamp_and_delete(self):
        dev = self._p('devices.json')
        self.S.save(dev, {'d1': {'name': 'web', 'last_seen': 100},
                          'd2': {'name': 'db', 'last_seen': 50}})
        # never move last_seen backwards
        self.S.save(dev, {'d1': {'name': 'web', 'last_seen': 40},
                          'd2': {'name': 'db', 'last_seen': 50}})
        self.assertEqual(self.S.load(dev)['d1']['last_seen'], 100)
        # omitting a device deletes its row
        self.S.save(dev, {'d1': {'name': 'web', 'last_seen': 100}})
        self.assertEqual(set(self.S.load(dev)), {'d1'})

    def test_entity_roundtrip(self):
        m = self._p('metrics.json')
        self.S.save(m, {'d1': [{'ts': 1, 'cpu': 5}], 'd2': [{'ts': 2}]})
        self.assertEqual(self.S.entity_get(m, 'd1'), [{'ts': 1, 'cpu': 5}])

    def test_wrapped_list_and_cap(self):
        a = self._p('alerts.json')
        self.S.save(a, {'alerts': [{'id': 'a1'}], 'meta': 'x'})
        self.S.list_append(a, {'id': 'a2'}, cap=2)
        ov = self.S.list_append(a, {'id': 'a3'}, cap=2)   # evicts a1
        got = self.S.load(a)
        self.assertEqual(got['meta'], 'x')
        self.assertEqual([x['id'] for x in got['alerts']], ['a2', 'a3'])
        self.assertEqual([x['id'] for x in ov], ['a1'])

    def test_locked_update(self):
        c = self._p('config.json')
        self.S.save(c, {'v': 1})
        with self.S.LockedUpdate(c) as doc:
            doc['v'] = 2
        self.assertEqual(self.S.load(c)['v'], 2)

    def test_device_txn_fast_path(self):
        dev = self._p('devices.json')
        self.S.save(dev, {'d1': {'name': 'web', 'last_seen': 5}})
        with self.S.DeviceTxn(dev, 'd1') as one:
            one['d1']['cpu'] = 42
        self.assertEqual(self.S.load(dev)['d1']['cpu'], 42)

    def test_upsert_device(self):
        dev = self._p('devices.json')
        self.S.upsert_device(dev, 'd9', lambda cur: {**cur, 'name': 'x', 'last_seen': 7})
        self.assertEqual(self.S.load(dev)['d9']['name'], 'x')

    def test_presence_and_inventory(self):
        self.S.save(self._p('config.json'), {'a': 1})
        self.S.save(self._p('devices.json'), {'d1': {'last_seen': 1}})
        self.assertTrue(self.S.exists(self._p('config.json')))
        self.assertIn('config.json', self.S.iter_files(self.d))
        self.assertGreater(self.S.doc_size(self._p('devices.json')), 0)

    def test_cross_session_nonblocking_lock(self):
        import psycopg
        c = self._p('config.json')
        self.S.save(c, {'v': 1})
        other = psycopg.connect(_DSN, autocommit=True)
        other.execute('BEGIN')
        other.execute("SELECT pg_advisory_xact_lock(hashtext('config.json'))")
        try:
            with self.assertRaises(self.S.LockBusyError):
                with self.S.LockedUpdate(c, non_blocking=True):
                    pass
        finally:
            other.execute('ROLLBACK')
            other.close()


@unittest.skipIf(_SKIP, _SKIP_REASON)
class TestApiDispatchPostgres(unittest.TestCase):
    """api.load/save/_LockedUpdate/_DeviceUpdate must route to storage_pg when
    the active backend is 'postgres'. Flips the backend for this class only and
    restores it, so it can't leak into the rest of the suite."""

    @classmethod
    def setUpClass(cls):
        import storage_pg
        cls.S = storage_pg
        cls.S.configure_dsn(_DSN)
        # Importing api.py fresh re-runs its top-level (which DATA_DIR.mkdir()s);
        # point RP_DATA_DIR at a temp dir first so that works even if an earlier
        # test in the full discover left RP_DATA_DIR unset. Restored in teardown.
        cls._prev_dd = os.environ.get('RP_DATA_DIR')
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp()
        # Fresh, isolated api module so flipping its backend can't leak into the
        # rest of the suite. Force the backend via THIS module's cache only —
        # never touch os.environ['RP_STORAGE_BACKEND'] (that would be global).
        _spec = importlib.util.spec_from_file_location("api_pg", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(cls.api)
        cls.api._BACKEND_CACHE = 'postgres'

    @classmethod
    def tearDownClass(cls):
        cls.S.close_connection()
        if cls._prev_dd is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = cls._prev_dd

    def setUp(self):
        _truncate(self.S)
        self.api._LOAD_CACHE.clear()
        self.d = Path(tempfile.mkdtemp())

    def test_dbmod_is_postgres(self):
        self.assertIs(self.api._dbmod(), self.S)

    def test_api_load_save_roundtrip(self):
        p = self.d / 'config.json'
        self.api.save(p, {'hello': 'pg'})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(p), {'hello': 'pg'})

    def test_api_locked_update(self):
        p = self.d / 'config.json'
        self.api.save(p, {'n': 1})
        with self.api._LockedUpdate(p) as doc:
            doc['n'] = 2
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(p)['n'], 2)

    def test_api_device_update(self):
        dev = self.d / 'devices.json'
        self.api.save(dev, {'d1': {'name': 'web', 'last_seen': 1}})
        self.api._LOAD_CACHE.clear()
        with self.api._DeviceUpdate('d1') as one:
            one['d1']['cpu'] = 88
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(dev)['d1']['cpu'], 88)

    def test_record_metrics_seeds_timeseries_from_recent_window(self):
        # _record_metrics on a DB backend seeds the time-series from the existing
        # metrics.json window the first time, so history isn't empty on day one.
        import time as _t
        now = int(_t.time())
        self.api.save(self.api.METRICS_FILE, {'dv': [
            {'ts': now - 7200, 'cpu': 10, 'mem': 20, 'swap': 1, 'disk': 30},
            {'ts': now - 3600, 'cpu': 12, 'mem': 22, 'swap': 2, 'disk': 31}]})
        self.api._LOAD_CACHE.clear()
        self.assertFalse(self.S.metric_has_any(self.api.DATA_DIR, 'dv'))
        self.api._record_metrics('dv', {'cpu_percent': 14, 'mem_percent': 24,
                                        'swap_percent': 3, 'disk_percent': 32})
        self.assertTrue(self.S.metric_has_any(self.api.DATA_DIR, 'dv'))
        series = self.S.metric_range(self.api.DATA_DIR, 'dv', now - 86400, max_points=100)
        self.assertGreaterEqual(len(series), 2)   # seeded history present


@unittest.skipIf(_SKIP, _SKIP_REASON)
class TestPgMetrics(unittest.TestCase):
    """v3.14.0 — append-only metric time-series on Postgres (30-day Trend charts)."""

    @classmethod
    def setUpClass(cls):
        os.environ['RP_PG_DSN'] = _DSN
        import storage_pg
        cls.S = storage_pg
        cls.S.configure_dsn(_DSN)

    def setUp(self):
        self.S._connect(None).execute('TRUNCATE metric_samples')
        self.d = Path(tempfile.mkdtemp())

    def test_append_range_prune(self):
        import time as _t
        now = int(_t.time())
        for i in range(72):                       # 3 days hourly
            self.S.metric_append(self.d, 'h1', now - i * 3600, float(i % 7), 50.0, 5.0, 30.0)
        self.S.metric_append(self.d, 'other', now, 99, 99, 99, 99)
        r24 = self.S.metric_range(self.d, 'h1', now - 86400, max_points=50)
        r3d = self.S.metric_range(self.d, 'h1', now - 3 * 86400, max_points=50)
        self.assertTrue(all(set(p) == {'ts', 'cpu', 'mem', 'swap', 'disk'} for p in r24))
        self.assertLess(len(r24), len(r3d))                 # 3d has more buckets
        self.assertTrue(all(now - 3 * 86400 <= p['ts'] <= now for p in r3d))
        self.assertAlmostEqual(r3d[0]['mem'], 50.0, places=1)  # downsample averages
        removed = self.S.metric_prune(self.d, now - 86400)
        self.assertGreater(removed, 0)
        left = self.S.metric_range(self.d, 'h1', now - 3 * 86400, max_points=200)
        self.assertTrue(all(p['ts'] >= now - 86400 - 3600 for p in left))


@unittest.skipIf(_SKIP, _SKIP_REASON)
class TestPgMigration(unittest.TestCase):
    """The in-app migrate path JSON -> Postgres (_migrate_storage_pg): copy every
    file, verify the round-trip, flip the marker (carrying the DSN)."""

    @classmethod
    def setUpClass(cls):
        import storage_pg
        cls.S = storage_pg
        cls.S.configure_dsn(_DSN)
        cls._prev_dd = os.environ.get('RP_DATA_DIR')
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp()
        _spec = importlib.util.spec_from_file_location("api_pgmig", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(cls.api)

    @classmethod
    def tearDownClass(cls):
        cls.S.close_connection()
        if cls._prev_dd is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = cls._prev_dd

    def test_json_to_postgres_migrate(self):
        import json as _json
        d = Path(tempfile.mkdtemp())
        # Point the module at a fresh data dir holding JSON, with JSON active.
        self.api.DATA_DIR = d
        self.api.STORAGE_MARKER_FILE = d / 'storage_backend.json'
        self.api._BACKEND_CACHE = 'json'
        (d / 'config.json').write_text(_json.dumps({'k': 'v'}))
        (d / 'devices.json').write_text(_json.dumps({'d1': {'name': 'h', 'last_seen': 3}}))
        _truncate(self.S)

        # dry run lists files, writes nothing
        dry = self.api._migrate_storage_pg('postgres', _DSN, dry_run=True)
        self.assertTrue(dry['dry_run'])
        self.assertIn('config.json', dry['files'])

        res = self.api._migrate_storage_pg('postgres', _DSN)
        self.assertTrue(res['ok'], res)
        marker = _json.loads((d / 'storage_backend.json').read_text())
        self.assertEqual(marker['backend'], 'postgres')
        self.assertEqual(marker['dsn'], _DSN)
        # data is now reconstructable from Postgres
        self.assertEqual(self.S.load(d / 'config.json'), {'k': 'v'})
        self.assertEqual(self.S.load(d / 'devices.json')['d1']['name'], 'h')


@unittest.skipIf(_SKIP, _SKIP_REASON)
class TestStoragePgRagVector(unittest.TestCase):
    """v4.1.0: pgvector RAG chunk store. Runs only against a live Postgres; if
    the `vector` extension can't be created (not installed), the whole class
    skips rather than failing."""

    @classmethod
    def setUpClass(cls):
        os.environ['RP_PG_DSN'] = _DSN
        import storage_pg
        cls.S = storage_pg
        cls.S.configure_dsn(_DSN)
        cls.d = Path(tempfile.mkdtemp())
        try:
            cls.S.rag_init_schema(cls.d)
        except Exception as e:
            raise unittest.SkipTest(f"pgvector not available: {e}")

    def setUp(self):
        conn = self.S._connect(self.d)
        conn.execute('TRUNCATE rag_chunks')

    def _rows(self):
        return [
            {'id': 'live/web01#cves', 'source': 'live_state', 'dtype': 'device_cves',
             'device': 'web01', 'title': 'web01 CVEs', 'ts': 10,
             'text': 'web01 has two critical openssl CVEs needing a patch',
             'embedding': [1.0, 0.0, 0.0]},
            {'id': 'docs/patch#a', 'source': 'docs', 'dtype': 'doc_md',
             'device': None, 'title': 'Patching', 'ts': 5,
             'text': 'how to apply package updates on debian',
             'embedding': [0.0, 1.0, 0.0]},
        ]

    def test_replace_count_built_at(self):
        n = self.S.rag_replace_all(self.d, self._rows(), built_at=123)
        self.assertEqual(n, 2)
        self.assertEqual(self.S.rag_count(self.d), 2)
        self.assertEqual(self.S.rag_built_at(self.d), 123)

    def test_vector_search(self):
        self.S.rag_replace_all(self.d, self._rows(), built_at=1)
        hits = self.S.rag_search(self.d, 'anything', [0.9, 0.1, 0.0], k=1)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['id'], 'live/web01#cves')   # nearest vector
        self.assertEqual(hits[0]['type'], 'device_cves')     # shape mirrors JSON

    def test_fulltext_search_when_no_vector(self):
        self.S.rag_replace_all(self.d, self._rows(), built_at=1)
        hits = self.S.rag_search(self.d, 'openssl patch', None, k=5)
        self.assertTrue(hits)
        self.assertEqual(hits[0]['id'], 'live/web01#cves')

    def test_duplicate_ids_deduped_last_wins(self):
        # A long doc section split into chunks can share one heading-path id;
        # the PK must not abort the reindex — dedup keeps the last.
        rows = [
            {'id': 'docs/x#a', 'source': 'docs', 'dtype': 'doc_md',
             'device': None, 'title': 'X', 'ts': 1, 'text': 'first copy', 'embedding': None},
            {'id': 'docs/x#a', 'source': 'docs', 'dtype': 'doc_md',
             'device': None, 'title': 'X', 'ts': 2, 'text': 'second copy wins', 'embedding': None},
        ]
        n = self.S.rag_replace_all(self.d, rows, built_at=1)
        self.assertEqual(n, 1)
        self.assertEqual(self.S.rag_count(self.d), 1)
        hits = self.S.rag_search(self.d, 'copy', None, k=5)
        self.assertEqual(hits[0]['text'], 'second copy wins')

    def test_clear_drops_table(self):
        self.S.rag_replace_all(self.d, self._rows(), built_at=1)
        self.S.rag_clear(self.d)
        self.assertEqual(self.S.rag_count(self.d), 0)   # table gone → 0
        self.S.rag_init_schema(self.d)                  # restore for other tests


if __name__ == "__main__":
    unittest.main()
