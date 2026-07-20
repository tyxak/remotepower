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


class TestHmacKeyRotation(unittest.TestCase):
    """v6.1.1 — versioned audit-HMAC rotation. Old entries must keep verifying
    against the generation that actually signed them; new entries sign with
    whatever's current; a chain spanning a rotation still verifies end-to-end
    (docs/feature-buildout-scoping-internal.md #3)."""

    def _chain_valid(self, api):
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        prev = ""
        for e in entries:
            body = {k: v for k, v in e.items() if k != "_hash"}
            if e.get("_hash") != api._audit_entry_hash(prev, body):
                return False, len(entries)
            prev = e.get("_hash", "")
        return True, len(entries)

    def _rotate(self, api):
        # Deliberately do NOT stub audit_log — the rotation's own audited event
        # is part of what these tests verify stays chain-valid.
        api.require_admin_auth = lambda **kw: 'admin'
        api.method = lambda: 'POST'
        cap = {}

        def _resp(s, b=None):
            cap['s'] = s
            cap['b'] = b
            raise SystemExit(0)
        api.respond = _resp
        try:
            api.handle_audit_hmac_rotate()
        except SystemExit:
            pass
        return cap['b']

    def test_starts_at_version_1(self):
        api = _load_api("json")
        self.assertEqual(api._audit_hmac_active_version(), 1)

    def test_rotate_bumps_version_and_persists_key(self):
        api = _load_api("json")
        r = self._rotate(api)
        self.assertTrue(r['ok'])
        self.assertEqual(r['version'], 2)
        self.assertEqual(api._audit_hmac_active_version(), 2)
        rotations = api.load(api.AUDIT_HMAC_ROTATIONS_FILE)
        self.assertIn('2', rotations)
        self.assertTrue(rotations['2']['key_hex'])

    def test_second_rotation_bumps_to_3(self):
        api = _load_api("json")
        self._rotate(api)
        r = self._rotate(api)
        self.assertEqual(r['version'], 3)

    def test_chain_spans_rotation_and_still_verifies(self):
        api = _load_api("json")
        for i in range(3):
            api.audit_log(f"admin{i}", "act", detail=f"before-{i}")
        self._rotate(api)
        for i in range(3):
            api.audit_log(f"admin{i}", "act", detail=f"after-{i}")
        ok, n = self._chain_valid(api)
        self.assertTrue(ok)
        self.assertEqual(n, 7)   # 3 before + the rotation's own entry + 3 after
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        kvs = [e.get('_kv', 1) for e in entries]
        self.assertEqual(kvs[:3], [1, 1, 1])
        self.assertTrue(all(v == 2 for v in kvs[3:]))

    def test_old_key_still_verifies_v1_entries_after_rotation(self):
        api = _load_api("json")
        api.audit_log("admin", "act", detail="v1-entry")
        v1_entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        self._rotate(api)
        body = {k: v for k, v in v1_entries[0].items() if k != "_hash"}
        self.assertEqual(v1_entries[0]['_hash'], api._audit_entry_hash('', body))

    def test_legacy_entry_with_no_kv_defaults_to_v1_key(self):
        # A real legacy entry has no _kv key in its canonical content AT ALL
        # (it predates key rotation) -- comparing against a dict with _kv
        # added would compare two different canonical forms, not this
        # invariant. What must hold: _audit_entry_hash signs it with the v1
        # key specifically, independent of whatever the CURRENT active
        # rotation version is.
        api = _load_api("json")
        self._rotate(api)   # active version is now 2 -- must not affect this
        legacy = {'ts': 1, 'actor': 'old', 'action': 'ancient'}   # no _kv field
        h = api._audit_entry_hash('', legacy)
        msg = '' + api.json.dumps(legacy, sort_keys=True, separators=(',', ':'))
        expected = api.hmac.new(api._audit_hmac_key(1), msg.encode('utf-8'),
                                api.hashlib.sha256).hexdigest()
        self.assertEqual(h, expected)

    def test_tamper_still_detected_across_a_rotation(self):
        api = _load_api("json")
        api.audit_log("admin", "act", detail="before")
        self._rotate(api)
        api.audit_log("admin", "act", detail="after")
        with api._LockedUpdate(api.AUDIT_LOG_FILE) as al:
            al['entries'][-1]['detail'] = 'TAMPERED'
        entries = (api.load(api.AUDIT_LOG_FILE) or {}).get("entries", [])
        checked, broken_at = api._audit_chain_walk(entries)
        self.assertEqual(broken_at, len(entries) - 1)


class TestHmacAutoRotation(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #26 — automate the manual
    rotation above on a configurable interval (default off)."""

    def test_off_by_default_never_rotates(self):
        api = _load_api("json")
        api.save(api.CONFIG_FILE, {})   # audit_hmac_auto_rotate_days unset -> 0
        api.run_audit_hmac_rotation_if_due()
        self.assertEqual(api._audit_hmac_active_version(), 1)

    def test_due_rotation_fires_via_v1_file_mtime(self):
        api = _load_api("json")
        api.save(api.CONFIG_FILE, {'audit_hmac_auto_rotate_days': 30})
        api._audit_hmac_key(1)   # ensure audit_hmac.key exists
        kf = api.DATA_DIR / 'audit_hmac.key'
        old = api.time.time() - 40 * 86400
        os.utime(kf, (old, old))
        api.run_audit_hmac_rotation_if_due()
        self.assertEqual(api._audit_hmac_active_version(), 2)
        rotations = api.load(api.AUDIT_HMAC_ROTATIONS_FILE)
        self.assertEqual(rotations['2']['created'] > 0, True)

    def test_not_due_rotation_does_not_fire(self):
        api = _load_api("json")
        api.save(api.CONFIG_FILE, {'audit_hmac_auto_rotate_days': 30})
        api._audit_hmac_key(1)
        api.run_audit_hmac_rotation_if_due()
        self.assertEqual(api._audit_hmac_active_version(), 1)

    def test_due_rotation_uses_latest_rotation_timestamp_not_v1(self):
        api = _load_api("json")
        api.save(api.CONFIG_FILE, {'audit_hmac_auto_rotate_days': 30})
        self._rotate(api)   # version 2, created=now -- not due yet
        api.run_audit_hmac_rotation_if_due()
        self.assertEqual(api._audit_hmac_active_version(), 2)
        # Backdate the v2 rotation's own timestamp -- now it's due.
        with api._LockedUpdate(api.AUDIT_HMAC_ROTATIONS_FILE) as rotations:
            rotations['2']['created'] = int(api.time.time()) - 40 * 86400
        api.run_audit_hmac_rotation_if_due()
        self.assertEqual(api._audit_hmac_active_version(), 3)

    def _rotate(self, api):
        api.require_admin_auth = lambda **kw: 'admin'
        api.method = lambda: 'POST'
        cap = {}

        def _resp(s, b=None):
            cap['s'] = s
            cap['b'] = b
            raise SystemExit(0)
        api.respond = _resp
        try:
            api.handle_audit_hmac_rotate()
        except SystemExit:
            pass
        return cap['b']

    def test_unknown_generation_falls_back_to_v1_key(self):
        api = _load_api("json")
        self.assertEqual(api._audit_hmac_key(99), api._audit_hmac_key(1))

    def test_verify_endpoint_reports_key_version(self):
        api = _load_api("json")
        api.audit_log("admin", "act", detail="x")
        self._rotate(api)
        api.require_admin_or_auditor_auth = lambda **kw: 'admin'
        cap = {}

        def _resp(s, b=None):
            cap['s'] = s
            cap['b'] = b
            raise SystemExit(0)
        api.respond = _resp
        try:
            api.handle_audit_log_verify()
        except SystemExit:
            pass
        self.assertTrue(cap['b']['ok'])
        self.assertEqual(cap['b']['key_version'], 2)
        self.assertEqual(cap['b']['key_rotations'], 1)


class TestWiring(unittest.TestCase):
    def test_append_uses_chained_primitive(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_m.list_append_chained(AUDIT_LOG_FILE, _build, cap=MAX_AUDIT_LOG)", src)
        self.assertIn("('audit_log_retention_days',     'AUDIT_LOG_FILE',           'entries')", src)

    def test_rotate_hmac_endpoint_wired(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("def handle_audit_hmac_rotate", src)
        self.assertIn("('POST', '/api/audit/rotate-hmac-key'): handle_audit_hmac_rotate", src)

    def test_rotate_hmac_ui_wired(self):
        html = (_ROOT / "server" / "html" / "index.html").read_text()
        self.assertIn('data-action="rotateAuditHmacKey"', html)
        self.assertIn('id="audit-hmac-version"', html)
        app = "".join((_ROOT / "server" / "html" / "static" / "js" / f).read_text()
                       for f in ("app.js", "i18n.js"))
        self.assertIn("async function rotateAuditHmacKey", app)
        self.assertIn("api('POST', '/audit/rotate-hmac-key'", app)
        self.assertIn('"Rotate signing key"', app)   # i18n DICT entry


if __name__ == "__main__":
    unittest.main()


# v6.3.0 gate fix: this module flips RP_STORAGE_BACKEND to exercise the SQLite
# backend but never restored it, so under `unittest discover` / xdist (which share
# one process) the setting leaked into later modules and silently switched THEIR
# storage backend — the source of ~20 order-dependent false failures that all pass
# in isolation. Restore it after the module runs. Captured at import (clean state).
_PRIOR_STORAGE_BACKEND = os.environ.get("RP_STORAGE_BACKEND")


def tearDownModule():
    if _PRIOR_STORAGE_BACKEND is None:
        os.environ.pop("RP_STORAGE_BACKEND", None)
    else:
        os.environ["RP_STORAGE_BACKEND"] = _PRIOR_STORAGE_BACKEND
