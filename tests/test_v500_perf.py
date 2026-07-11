"""v5.0.0 performance batch:
  - cold-blob -> entity promotion of containers/update_logs/cmds/uptime, with a
    safe one-time reclassification migration + kv-fallback on load()/entity_get()
  - /api/home posture + bandwidth widgets gated behind the ?w= hint
"""
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("storage_perf", _CGI / "storage.py")
storage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(storage)

_DATA = tempfile.mkdtemp(prefix="rp-v500p-")
os.environ["RP_DATA_DIR"] = _DATA
_aspec = importlib.util.spec_from_file_location("api_v500p", _CGI / "api.py")
api = importlib.util.module_from_spec(_aspec)
_aspec.loader.exec_module(api)

API_SRC = (_CGI / "api.py").read_text()


class TestEntityPromotion(unittest.TestCase):
    def test_files_promoted(self):
        for f in ("containers.json", "update_logs.json", "commands.json", "uptime.json"):
            self.assertIn(f, storage.ENTITY_FILES)

    def test_cmds_json_is_not_a_real_file(self):
        # v6.1.1: 'cmds.json' was a stale/wrong string in the v5.0.0 wave that
        # never matched any real file (CMDS_FILE's basename is
        # 'commands.json') -- guard against it silently creeping back into
        # ENTITY_FILES, which would just be dead classification again.
        self.assertNotIn("cmds.json", storage.ENTITY_FILES)
        self.assertEqual(Path(api.CMDS_FILE).name, "commands.json")
        self.assertIn(Path(api.CMDS_FILE).name, storage.ENTITY_FILES,
                     "CMDS_FILE's real basename must be entity-promoted")

    def test_schema_version_bumped(self):
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 3)

    def test_heartbeat_uses_entity_helpers(self):
        # the hot heartbeat paths read/write per-device, not the whole-fleet blob
        self.assertIn("_entity_read_one(CMDS_FILE, dev_id", API_SRC)
        self.assertIn("_entity_write_one(CONTAINERS_FILE, dev_id", API_SRC)
        self.assertIn("_entity_read_one(UPDATE_LOGS_FILE, dev_id", API_SRC)
        self.assertIn("_entity_read_one(UPTIME_FILE, dev_id", API_SRC)
        self.assertIn("_entity_read_one(CONTAINERS_FILE, dev_id", API_SRC)  # diff read


class TestColdToEntityMigration(unittest.TestCase):
    """A pre-v5 SQLite DB stores these files as cold kv blobs. On first connect
    they must be split into entity rows with zero data loss."""

    def _old_db(self):
        d = Path(tempfile.mkdtemp())
        dbp = storage.db_path(d)
        c = sqlite3.connect(str(dbp))
        c.executescript("""
          CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE kv(path TEXT PRIMARY KEY, doc TEXT NOT NULL, updated REAL);
          CREATE TABLE devices(id TEXT PRIMARY KEY, doc TEXT NOT NULL, last_seen INTEGER DEFAULT 0);
          CREATE TABLE entity(file TEXT NOT NULL, k TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY(file,k));
          CREATE TABLE listrow(id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, doc TEXT NOT NULL);
          CREATE TABLE file_meta(file TEXT PRIMARY KEY, updated REAL NOT NULL);
        """)
        c.execute("INSERT INTO schema_meta VALUES('schema_version','2')")
        c.execute("INSERT INTO kv VALUES('containers.json',?,0)",
                  (json.dumps({"d1": {"ts": 1, "items": ["a"]}, "d2": {"ts": 2, "items": []}}),))
        # v6.1.1: 'commands.json' -- CMDS_FILE's REAL basename (the pre-fix kv
        # blob would have sat under the stale 'cmds.json' key, which never
        # matched anything real; this fixture now reflects what an actual
        # pre-v6.1.1 production database looks like).
        c.execute("INSERT INTO kv VALUES('commands.json',?,0)",
                  (json.dumps({"d1": ["reboot"], "d2": ["update"]}),))
        c.execute("INSERT INTO kv VALUES('uptime.json',?,0)",
                  (json.dumps({"d1": {"name": "d1", "events": [{"ts": 1, "online": True}]}}),))
        c.commit(); c.close()
        return d

    def test_migration_preserves_data(self):
        d = self._old_db()
        storage.close_connection()
        # first load triggers _ensure_schema -> _migrate_cold_to_entity
        self.assertEqual(storage.load(d / "containers.json"),
                         {"d1": {"ts": 1, "items": ["a"]}, "d2": {"ts": 2, "items": []}})
        self.assertEqual(storage.entity_get(d / "commands.json", "d1"), ["reboot"])
        self.assertEqual(storage.load(d / "commands.json"),
                         {"d1": ["reboot"], "d2": ["update"]})
        self.assertEqual(storage.entity_get(d / "uptime.json", "d1")["name"], "d1")
        # kv blobs consumed, version stamped to the current schema
        c = sqlite3.connect(str(storage.db_path(d)))
        self.assertEqual(c.execute(
            "SELECT count(*) FROM kv WHERE path IN ('containers.json','commands.json','uptime.json')"
        ).fetchone()[0], 0)
        self.assertEqual(c.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0],
            str(storage.SCHEMA_VERSION))
        c.close()
        storage.close_connection()

    def test_already_migrated_db_still_catches_the_missed_commands_json_wave(self):
        # v6.1.1: the REAL-WORLD broken state. Every existing production
        # database already has schema_version >= 4 (it passed through the v3
        # wave, which never actually touched commands.json because the
        # ENTITY_FILES string was wrong) -- so a naive fix that only
        # corrected the ENTITY_FILES string, without a NEW migration wave
        # gated on a NEW schema version, would never re-run for any database
        # that already exists. Simulate exactly that: a db already stamped
        # at schema_version=7 (the version that shipped just before this
        # fix), with commands.json still sitting as an unmigrated kv blob.
        d = Path(tempfile.mkdtemp())
        dbp = storage.db_path(d)
        c = sqlite3.connect(str(dbp))
        c.executescript("""
          CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE kv(path TEXT PRIMARY KEY, doc TEXT NOT NULL, updated REAL);
          CREATE TABLE devices(id TEXT PRIMARY KEY, doc TEXT NOT NULL, last_seen INTEGER DEFAULT 0);
          CREATE TABLE entity(file TEXT NOT NULL, k TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY(file,k));
          CREATE TABLE listrow(id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, doc TEXT NOT NULL);
          CREATE TABLE file_meta(file TEXT PRIMARY KEY, updated REAL NOT NULL);
        """)
        c.execute("INSERT INTO schema_meta VALUES('schema_version','7')")
        c.execute("INSERT INTO kv VALUES('commands.json',?,0)",
                  (json.dumps({"d1": ["reboot"], "d2": ["update"]}),))
        c.commit(); c.close()
        storage.close_connection()

        self.assertEqual(storage.entity_get(d / "commands.json", "d1"), ["reboot"])
        self.assertEqual(storage.load(d / "commands.json"),
                         {"d1": ["reboot"], "d2": ["update"]})
        c = sqlite3.connect(str(storage.db_path(d)))
        self.assertEqual(c.execute(
            "SELECT count(*) FROM kv WHERE path='commands.json'").fetchone()[0], 0)
        c.close()
        storage.close_connection()

    def test_load_kv_fallback_before_migration(self):
        # if entity rows are absent but a kv blob exists (mid-migration), load()
        # and entity_get() still serve the data — never lost.
        d = Path(tempfile.mkdtemp())
        c = sqlite3.connect(str(storage.db_path(d)))
        c.executescript("""
          CREATE TABLE kv(path TEXT PRIMARY KEY, doc TEXT NOT NULL, updated REAL);
          CREATE TABLE entity(file TEXT NOT NULL, k TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY(file,k));
          CREATE TABLE devices(id TEXT PRIMARY KEY, doc TEXT NOT NULL, last_seen INTEGER DEFAULT 0);
          CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE listrow(id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, doc TEXT NOT NULL);
          CREATE TABLE file_meta(file TEXT PRIMARY KEY, updated REAL NOT NULL);
        """)
        # mark version 3 so the eager migration does NOT run — exercise the
        # pure load()/entity_get() kv-fallback path in isolation.
        c.execute("INSERT INTO schema_meta VALUES('schema_version','3')")
        c.execute("INSERT INTO kv VALUES('uptime.json',?,0)",
                  (json.dumps({"d9": {"name": "d9", "events": []}}),))
        c.commit(); c.close()
        storage.close_connection()
        self.assertEqual(storage.load(d / "uptime.json"), {"d9": {"name": "d9", "events": []}})
        self.assertEqual(storage.entity_get(d / "uptime.json", "d9")["name"], "d9")
        storage.close_connection()


class TestHomeWidgetGating(unittest.TestCase):
    DEVS = {
        "d1": {"name": "d1", "monitored": True,
               "sysinfo": {"reboot_required": True,
                           "network_io": [{"rx_bps": 100, "tx_bps": 50}]}},
    }

    def test_posture_skipped_when_not_wanted(self):
        # want set WITHOUT any posture key -> the O(fleet) loop is skipped, so the
        # reboot count stays 0 even though a device needs a reboot.
        out = api._dashboard_extra_widgets(self.DEVS, {}, 0, want={"alertsev"})
        self.assertEqual(out.get("rebootreq", {}).get("count"), 0)
        self.assertEqual(out.get("bandwidth"), [])

    def test_posture_computed_when_wanted(self):
        out = api._dashboard_extra_widgets(self.DEVS, {}, 0, want={"rebootreq"})
        self.assertEqual(out["rebootreq"]["count"], 1)

    def test_bandwidth_computed_when_wanted(self):
        out = api._dashboard_extra_widgets(self.DEVS, {}, 0, want={"bandwidth"})
        self.assertEqual(len(out["bandwidth"]), 1)
        self.assertEqual(out["bandwidth"][0]["bps"], 150)

    def test_no_hint_computes_all(self):
        # want=None (no ?w=) -> backward-compatible, computes everything.
        out = api._dashboard_extra_widgets(self.DEVS, {}, 0, want=None)
        self.assertEqual(out["rebootreq"]["count"], 1)
        self.assertEqual(len(out["bandwidth"]), 1)


if __name__ == "__main__":
    unittest.main()
