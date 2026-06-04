"""
v3.12.0 — pluggable storage backend (SQLite alongside flat JSON).

This is the dedicated gate for the SQLite backend. The full legacy suite runs
in JSON mode (the default); this file exercises the decomposition, the
transparent shim behind load()/save()/_locked_update(), the row-level fast
helpers, the migration core, and the new endpoints' wiring.

Most tests drive storage.py directly with a per-test temp dir (the connection
is keyed by the file's parent directory, so each temp dir is an isolated DB).
A few drive api.* with the backend forced to sqlite.
"""
import os
import sys
import json
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import storage  # noqa: E402
import api  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        storage.close_connection()

    def tearDown(self):
        storage.close_connection()

    def p(self, name):
        return self.d / name


class TestRoundTrip(_Base):
    def test_cold_blob_roundtrip(self):
        data = {'server_name': 'x', 'nested': {'a': [1, 2, 3]}}
        storage.save(self.p('config.json'), data)
        self.assertEqual(storage.load(self.p('config.json')), data)

    def test_missing_returns_empty_dict(self):
        self.assertEqual(storage.load(self.p('config.json')), {})
        self.assertEqual(storage.load(self.p('devices.json')), {})
        self.assertEqual(storage.load(self.p('history.json')), {'entries': []})

    def test_dict_of_entity_roundtrip(self):
        devs = {'d1': {'name': 'a', 'last_seen': 100},
                'd2': {'name': 'b', 'last_seen': 50}}
        storage.save(self.p('devices.json'), devs)
        self.assertEqual(storage.load(self.p('devices.json')), devs)

    def test_entity_file_roundtrip(self):
        m = {'d1': [1, 2, 3], 'd2': [4]}
        storage.save(self.p('metrics.json'), m)
        self.assertEqual(storage.load(self.p('metrics.json')), m)

    def test_wrapped_list_roundtrip(self):
        h = {'entries': [{'ts': 1}, {'ts': 2}]}
        storage.save(self.p('history.json'), h)
        self.assertEqual(storage.load(self.p('history.json')), h)

    def test_wrapped_list_preserves_sibling_metadata(self):
        fe = {'events': [{'event': 'x'}], 'extra': 9, 'meta': {'k': 'v'}}
        storage.save(self.p('fleet_events.json'), fe)
        self.assertEqual(storage.load(self.p('fleet_events.json')), fe)


class TestDiffWrite(_Base):
    def test_save_deletes_removed_keys(self):
        storage.save(self.p('devices.json'),
                     {'d1': {'last_seen': 1}, 'd2': {'last_seen': 2}})
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 3}})
        self.assertEqual(set(storage.load(self.p('devices.json'))), {'d1'})

    def test_save_only_writes_changed_rows(self):
        storage.save(self.p('metrics.json'), {'a': [1], 'b': [2], 'c': [3]})
        conn = storage._connect(self.d)
        before = conn.total_changes
        # Re-save with only 'b' changed; the diff must write exactly one row.
        storage.save(self.p('metrics.json'), {'a': [1], 'b': [99], 'c': [3]})
        self.assertEqual(conn.total_changes - before, 1)


class TestLastSeenClamp(_Base):
    def test_clamp_blocks_backward_last_seen(self):
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 100}})
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 5, 'x': 1}})
        got = storage.load(self.p('devices.json'))['d1']
        self.assertEqual(got['last_seen'], 100)   # clamped up
        self.assertEqual(got['x'], 1)             # other field still applied

    def test_clamp_disabled_allows_backward(self):
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 100}})
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 5}},
                     clamp_last_seen=False)
        self.assertEqual(
            storage.load(self.p('devices.json'))['d1']['last_seen'], 5)


class TestLockedUpdate(_Base):
    def test_commit_on_clean_exit(self):
        storage.save(self.p('config.json'), {'n': 1})
        with storage.LockedUpdate(self.p('config.json')) as c:
            c['n'] = 2
        self.assertEqual(storage.load(self.p('config.json'))['n'], 2)

    def test_rollback_on_exception(self):
        storage.save(self.p('config.json'), {'n': 1})
        with self.assertRaises(RuntimeError):
            with storage.LockedUpdate(self.p('config.json')) as c:
                c['n'] = 99
                raise RuntimeError('boom')
        self.assertEqual(storage.load(self.p('config.json'))['n'], 1)


class TestRowHelpers(_Base):
    def test_upsert_device_single_row(self):
        storage.upsert_device(self.p('devices.json'), 'd1',
                              lambda d: {**d, 'name': 'a', 'last_seen': 10})
        storage.upsert_device(self.p('devices.json'), 'd1',
                              lambda d: {**d, 'last_seen': 20})
        got = storage.load(self.p('devices.json'))['d1']
        self.assertEqual(got, {'name': 'a', 'last_seen': 20})

    def test_upsert_device_clamps(self):
        storage.upsert_device(self.p('devices.json'), 'd1',
                              lambda d: {'last_seen': 100})
        storage.upsert_device(self.p('devices.json'), 'd1',
                              lambda d: {'last_seen': 5})
        self.assertEqual(
            storage.load(self.p('devices.json'))['d1']['last_seen'], 100)

    def test_list_append_caps_and_returns_overflow(self):
        over = []
        for i in range(5):
            over = storage.list_append(self.p('history.json'), {'i': i}, cap=3)
        entries = storage.load(self.p('history.json'))['entries']
        self.assertEqual([e['i'] for e in entries], [2, 3, 4])  # newest 3
        self.assertEqual(over, [{'i': 1}])  # last append evicted i=1


class TestPresence(_Base):
    def test_exists_parity(self):
        self.assertFalse(storage.exists(self.p('devices.json')))
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 1}})
        self.assertTrue(storage.exists(self.p('devices.json')))
        self.assertFalse(storage.exists(self.p('schedule.json')))
        storage.save(self.p('schedule.json'), {'jobs': []})
        self.assertTrue(storage.exists(self.p('schedule.json')))

    def test_iter_files(self):
        storage.save(self.p('devices.json'), {'d1': {'last_seen': 1}})
        storage.save(self.p('config.json'), {'a': 1})
        storage.save(self.p('history.json'), {'entries': [{'ts': 1}]})
        storage.save(self.p('metrics.json'), {'d1': [1]})
        self.assertEqual(
            set(storage.iter_files(self.d)),
            {'devices.json', 'config.json', 'history.json', 'metrics.json'})


class TestMigration(_Base):
    def _seed_json(self):
        (self.d / 'devices.json').write_text(json.dumps(
            {'d1': {'name': 'a', 'last_seen': 100},
             'd2': {'name': 'b', 'last_seen': 5}}))
        (self.d / 'config.json').write_text(json.dumps({'server_name': 'srv'}))
        (self.d / 'history.json').write_text(json.dumps(
            {'entries': [{'ts': 1}, {'ts': 2}]}))
        (self.d / 'fleet_events.json').write_text(json.dumps(
            {'events': [{'event': 'x'}], 'extra': 9}))

    def test_json_to_sqlite_and_verify(self):
        self._seed_json()
        res = storage.migrate_run(self.d, 'sqlite', do_snapshot=False)
        self.assertTrue(res['ok'], res)
        # Faithful backward last_seen (clamp disabled during migration).
        self.assertEqual(
            storage.load(self.d / 'devices.json')['d2']['last_seen'], 5)
        ok, problems = storage.verify_migration(self.d)
        self.assertTrue(ok, problems)
        self.assertEqual(storage.read_marker(self.d)['backend'], 'sqlite')

    def test_roundtrip_json_sqlite_json_equal(self):
        self._seed_json()
        before = {n: json.loads((self.d / n).read_text())
                  for n in ('devices.json', 'config.json', 'history.json',
                            'fleet_events.json')}
        storage.migrate_run(self.d, 'sqlite', do_snapshot=False)
        storage.migrate_run(self.d, 'json', do_snapshot=False)
        for n, v in before.items():
            self.assertEqual(json.loads((self.d / n).read_text()), v, n)

    def test_dry_run_changes_nothing(self):
        self._seed_json()
        res = storage.migrate_run(self.d, 'sqlite', dry_run=True)
        self.assertTrue(res['dry_run'])
        self.assertFalse(storage.db_path(self.d).exists())


class TestApiIntegrationSqlite(unittest.TestCase):
    """Drive api.* with the backend forced to sqlite via the marker."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        storage.close_connection()
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        self._files = {}
        for attr in ('DEVICES_FILE', 'CONFIG_FILE', 'HISTORY_FILE',
                     'FLEET_EVENTS_FILE', 'STORAGE_MARKER_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        storage.write_marker(self.d, 'sqlite')
        # Force marker-based selection for these tests, but save/restore the
        # env so we don't contaminate other test modules in a shared process
        # (e.g. a full-suite run under RP_STORAGE_BACKEND=sqlite).
        self._env_backend = os.environ.pop('RP_STORAGE_BACKEND', None)

    def tearDown(self):
        for attr, val in self._files.items():
            setattr(api, attr, val)
        if self._env_backend is not None:
            os.environ['RP_STORAGE_BACKEND'] = self._env_backend
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        storage.close_connection()

    def test_marker_selects_sqlite(self):
        self.assertEqual(api._storage_backend(), 'sqlite')

    def test_api_load_save_through_sqlite(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'last_seen': 1}})
        self.assertEqual(api.load(api.DEVICES_FILE),
                         {'d1': {'name': 'a', 'last_seen': 1}})
        # No flat file should have been written.
        self.assertFalse((self.d / 'devices.json').exists())
        self.assertTrue(storage.db_path(self.d).exists())

    def test_log_command_appends_via_sqlite(self):
        api.log_command('admin', 'd1', 'pc', 'ls')
        h = api.load(api.HISTORY_FILE)
        self.assertEqual(len(h['entries']), 1)
        self.assertEqual(h['entries'][0]['command'], 'ls')

    def test_backend_exists_guard(self):
        self.assertFalse(api.backend_exists(api.DEVICES_FILE))
        api.save(api.DEVICES_FILE, {'d1': {'last_seen': 1}})
        self.assertTrue(api.backend_exists(api.DEVICES_FILE))


class TestRoutesRegistered(unittest.TestCase):
    def test_storage_backend_routes(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/storage-backend/status'), routes)
        self.assertIn(('POST', '/api/storage-backend/migrate'), routes)


if __name__ == '__main__':
    unittest.main()
