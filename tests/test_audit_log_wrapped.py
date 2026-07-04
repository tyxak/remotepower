"""v5.8.0: audit_log.json promoted from a COLD blob to a WRAPPED_LIST_FILE with a
chained O(1) append. The hash chain must stay valid (list_append_chained reads
the tail hash inside the same transaction), age-pruning moved to the retention
sweep, and the cold->wrapped migration preserves the chain.
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


class TestClassificationAndPrimitive(unittest.TestCase):
    def test_audit_is_wrapped(self):
        self.assertEqual(storage.WRAPPED_LIST_FILES.get("audit_log.json"), "entries")
        self.assertGreaterEqual(storage.SCHEMA_VERSION, 7)

    def test_list_append_chained_sees_tail(self):
        d = tempfile.mkdtemp()
        storage.configure(d)
        p = d + "/audit_log.json"
        seen = []
        storage.list_append_chained(p, lambda prev: (seen.append(prev) or {"n": 1}))
        storage.list_append_chained(p, lambda prev: (seen.append(prev) or {"n": 2}))
        self.assertIsNone(seen[0])            # empty log → prev is None
        self.assertEqual(seen[1], {"n": 1})   # second sees the first as tail
        storage.close_connection()

    def test_cold_to_wrapped_migration_v7(self):
        d = tempfile.mkdtemp()
        storage.configure(d)
        conn = storage._connect()
        blob = {"entries": [{"ts": 1, "_hash": "a"}, {"ts": 2, "_hash": "b"}]}
        conn.execute("INSERT INTO kv(path,doc,updated) VALUES('audit_log.json',?,0)",
                     (json.dumps(blob),))
        conn.commit()
        storage._migrate_cold_to_wrapped(conn, storage._COLD_TO_WRAPPED_V7)
        conn.commit()
        self.assertIsNone(conn.execute(
            "SELECT doc FROM kv WHERE path='audit_log.json'").fetchone())
        self.assertEqual(len(storage.load(d + "/audit_log.json")["entries"]), 2)
        storage.close_connection()


def _load_api(backend):
    os.environ["RP_STORAGE_BACKEND"] = backend
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for mod in ("api", "storage", "storage_pg"):
        sys.modules.pop(mod, None)
    import storage as _st  # noqa: F401  (re-imported fresh for the backend)
    spec = importlib.util.spec_from_file_location("api_audit_" + backend, _CGI / "api.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._begin_request()
    return m


class TestChainIntegrity(unittest.TestCase):
    def _chain_valid(self, api):
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        prev = ""
        for e in entries:
            body = {k: v for k, v in e.items() if k != "_hash"}
            if e.get("_hash") != api._audit_entry_hash(prev, body):
                return False, len(entries)
            prev = e.get("_hash", "")
        return True, len(entries)

    def test_chain_valid_json(self):
        api = _load_api("json")
        for i in range(6):
            api.audit_log(f"admin{i}", "act", detail=f"d{i}")
        ok, n = self._chain_valid(api)
        self.assertTrue(ok)
        self.assertEqual(n, 6)

    def test_chain_valid_sqlite(self):
        api = _load_api("sqlite")
        for i in range(6):
            api.audit_log(f"admin{i}", "act", detail=f"d{i}")
        ok, n = self._chain_valid(api)
        self.assertTrue(ok)
        self.assertEqual(n, 6)

    def test_verify_endpoint_walks_chain(self):
        api = _load_api("sqlite")
        for i in range(4):
            api.audit_log("admin", "act", detail=str(i))
        chk, broken = api._audit_chain_walk(
            (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", []))
        self.assertTrue(chk)
        self.assertIsNone(broken)


class TestRetentionMoved(unittest.TestCase):
    def test_append_does_not_age_prune(self):
        # An entry older than 90d must survive the APPEND (age-pruning is the
        # sweep's job now) — the old inline code would have dropped it.
        api = _load_api("sqlite")
        api.save(api.AUDIT_LOG_FILE, {"entries": [
            {"ts": 1, "actor": "old", "action": "ancient", "_hash": "x"}]})
        api.audit_log("admin", "recent", detail="now")
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        self.assertTrue(any(e.get("action") == "ancient" for e in entries),
                        "append must not age-prune")

    def test_sweep_prunes_and_archives_old_audit(self):
        api = _load_api("sqlite")
        old_ts = int(__import__("time").time()) - 200 * 86400   # older than 90d
        api.save(api.AUDIT_LOG_FILE, {"entries": [
            {"ts": old_ts, "actor": "old", "action": "ancient", "_hash": "x"},
            {"ts": int(__import__("time").time()), "actor": "new",
             "action": "fresh", "_hash": "y"}]})
        api._purge_old_data(api.load(api.CONFIG_FILE) or {})
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        actions = {e.get("action") for e in entries}
        self.assertIn("fresh", actions)
        self.assertNotIn("ancient", actions)
        # archived to the gz
        arch = Path(os.environ["RP_DATA_DIR"]) / "audit_log_archive.jsonl.gz"
        self.assertTrue(arch.exists())


class TestWiring(unittest.TestCase):
    def test_append_uses_chained_primitive(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_m.list_append_chained(AUDIT_LOG_FILE, _build, cap=MAX_AUDIT_LOG)", src)
        self.assertIn("('audit_log_retention_days',     'AUDIT_LOG_FILE',           'entries')", src)


if __name__ == "__main__":
    unittest.main()
