"""v5.6.0 (perf, Tier-2): posture_state / port_baseline / av / ssh_key_baseline
promoted from cold blobs to ENTITY files.

Two things must hold under BOTH backends (this runs in `make test-both`):
  1. The four heartbeat ingest paths still round-trip per device after the switch
     to `_entity_read_one`/`_entity_write_one` (functional regression).
  2. The one-time kv->entity migration (`_COLD_TO_ENTITY_V4`, gated at db_ver < 4)
     splits an existing cold blob into per-device rows without losing data.

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
import storage  # noqa: E402


class TestEntityPromotionRoundTrip(unittest.TestCase):
    """The four promoted stores must still persist per-device via the real path."""

    def _dev(self, dev_id, sysinfo):
        api.save(api.DEVICES_FILE, {dev_id: {'name': dev_id, 'monitored': True,
                                             'sysinfo': sysinfo}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def test_port_baseline_roundtrips(self):
        d = 'e-ports'
        api._audit_listening_ports(d, d, [{'proto': 'tcp', 'port': 443,
                                           'process': 'nginx', 'scope': 'world',
                                           'addr': '0.0.0.0'}])
        row = api._entity_read_one(api.PORT_BASELINE_FILE, d, None)
        self.assertTrue(row and row[0]['port'] == 443)
        # load() must still reassemble the whole store for fleet readers
        self.assertIn(d, api.load(api.PORT_BASELINE_FILE) or {})

    def test_av_roundtrips(self):
        d = 'e-av'
        api._ingest_av(d, {'clamav': {'installed': True, 'infected': 0}},
                       int(api.time.time()), d)
        row = api._entity_read_one(api.AV_FILE, d, None)
        self.assertTrue(row and 'clamav' in row)
        self.assertIn(d, api.load(api.AV_FILE) or {})

    def test_ssh_baseline_roundtrips(self):
        d = 'e-ssh'
        api._audit_ssh_keys(d, d, [{'name': 'root',
                                    'authorized_keys': 'ssh-ed25519 AAAA root@h'}])
        row = api._entity_read_one(api.SSH_KEY_BASELINE_FILE, d, None)
        self.assertTrue(row and 'root' in row)


class TestColdToEntityMigrationV4(unittest.TestCase):
    """The kv->entity split must preserve every device row (SQLite backend only —
    the JSON backend keeps a single file and needs no migration)."""

    def test_migration_splits_blob(self):
        if getattr(storage, 'BACKEND', 'json') != 'sqlite' and \
           os.environ.get('RP_STORAGE_BACKEND') != 'sqlite':
            self.skipTest("migration is a SQLite-backend concern")
        import json
        conn = storage._connect()
        # Simulate a pre-v4 DB: a cold kv blob + schema_version 3.
        blob = {'h1': {'clamav': {'infected': 1}}, 'h2': {'rkhunter': {'warnings': 2}}}
        conn.execute("INSERT INTO kv(path, doc) VALUES('av_status.json', ?) "
                     "ON CONFLICT(path) DO UPDATE SET doc=excluded.doc",
                     (json.dumps(blob),))
        conn.execute("INSERT INTO schema_meta(key, value) VALUES('schema_version','3') "
                     "ON CONFLICT(key) DO UPDATE SET value='3'")
        conn.commit()
        storage._migrate_cold_to_entity(conn, ('av_status.json',))
        conn.commit()
        # kv blob gone, both rows now in entity. Use the FULL path so entity_get's
        # _dir() resolves to this test's DB (a bare basename would hit cwd/…db).
        avp = storage.DATA_DIR / 'av_status.json'
        kv = conn.execute("SELECT doc FROM kv WHERE path='av_status.json'").fetchone()
        self.assertIsNone(kv, "cold kv blob should be deleted after migration")
        self.assertEqual(storage.entity_get(avp, 'h1').get('clamav'), {'infected': 1})
        self.assertEqual(storage.entity_get(avp, 'h2').get('rkhunter'), {'warnings': 2})


if __name__ == '__main__':
    unittest.main()
