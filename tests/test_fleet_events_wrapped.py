"""v5.8.0: fleet_events.json promoted from a COLD blob to a WRAPPED_LIST_FILE.

Covers: the storage classification, the O(1) list_append hot path (DB backends),
the cold→wrapped migration, and the _compute_attention reader-bug fix (it used to
read the wrapped dict as a bare list and silently process zero events).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import storage  # noqa: E402


class TestClassification(unittest.TestCase):
    def test_fleet_events_is_wrapped(self):
        self.assertEqual(storage.WRAPPED_LIST_FILES.get("fleet_events.json"), "events")
        self.assertEqual(storage._classify("/x/fleet_events.json"), "wrapped")

    def test_schema_bumped(self):
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 6)


class TestSqliteAppendAndMigration(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        storage.configure(self.dir)
        self.path = self.dir + "/fleet_events.json"

    def tearDown(self):
        storage.close_connection()

    def test_list_append_writes_rows(self):
        for i in range(3):
            storage.list_append(self.path, {"ts": i, "event": "e%d" % i}, cap=100)
        doc = storage.load(self.path)
        self.assertEqual(len(doc["events"]), 3)
        self.assertEqual(doc["events"][0]["event"], "e0")

    def test_cap_evicts_oldest_returns_overflow(self):
        ov = []
        for i in range(5):
            ov = storage.list_append(self.path, {"ts": i}, cap=3)
        # last append pushed count to 4>3 → 1 oldest evicted
        self.assertEqual([o["ts"] for o in ov], [1])
        self.assertEqual([e["ts"] for e in storage.load(self.path)["events"]], [2, 3, 4])

    def test_cold_to_wrapped_migration(self):
        conn = storage._connect()
        blob = {"events": [{"ts": 1, "event": "a"}, {"ts": 2, "event": "b"}]}
        conn.execute("INSERT INTO kv(path,doc,updated) VALUES('fleet_events.json',?,0)",
                     (json.dumps(blob),))
        conn.commit()
        storage._migrate_cold_to_wrapped(conn, storage._COLD_TO_WRAPPED_V6)
        conn.commit()
        # cold blob gone, decomposed into listrow, load() returns wrapped
        self.assertIsNone(conn.execute(
            "SELECT doc FROM kv WHERE path='fleet_events.json'").fetchone())
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) c FROM listrow WHERE file='fleet_events.json'").fetchone()["c"], 2)
        self.assertEqual(len(storage.load(self.path)["events"]), 2)


def _load_api(backend):
    os.environ["RP_STORAGE_BACKEND"] = backend
    os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_fe_" + backend, _CGI / "api.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestRecordAndReadBothBackends(unittest.TestCase):
    def _exercise(self, backend):
        api = _load_api(backend)
        for i in range(4):
            api._record_fleet_event("new_port_detected",
                                    {"device_id": "d1", "name": "web1",
                                     "proto": "tcp", "port": 1000 + i,
                                     "process": "nginx"})
        doc = api.load(api.FLEET_EVENTS_FILE)
        self.assertIsInstance(doc, dict)
        self.assertEqual(len(doc["events"]), 4)
        return api

    def test_json_backend(self):
        self._exercise("json")

    def test_sqlite_backend(self):
        self._exercise("sqlite")


class TestReaderBugFixed(unittest.TestCase):
    def test_compute_attention_reads_events_not_keys(self):
        # Source-level guard: the reader must use .get('events'), not `or []`
        # (which returns the dict and iterates its keys → zero events).
        src = (_CGI / "api.py").read_text()
        self.assertIn("(load(FLEET_EVENTS_FILE) or {}).get('events') or []", src)
        self.assertNotIn("events = load(FLEET_EVENTS_FILE) or []", src)

    def test_log_alert_event_becomes_attention_item(self):
        # Before the reader fix, _compute_attention iterated the wrapped dict's
        # KEYS and saw zero events, so log-alert NA cards were silently dropped.
        # log_alert's needs_attention default is ON (unlike new_port), so a fixed
        # reader surfaces it. This proves the fix end to end.
        api = _load_api("sqlite")
        api.save(api.DEVICES_FILE, {"d1": {"name": "web1", "monitored": True}})
        api._record_fleet_event("log_alert",
                                {"device_id": "d1", "name": "web1",
                                 "severity": "WARN", "unit": "sshd",
                                 "pattern": "Failed password", "count": 3,
                                 "sample": ["Failed password for root"]})
        items = api._compute_attention()
        la = [it for it in items if it.get("kind") == "log_alert"]
        self.assertTrue(la, "log_alert fleet event should surface as an NA item")


if __name__ == "__main__":
    unittest.main()
