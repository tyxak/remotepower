"""v6.4.2: the server's own DR backup must actually carry — and restore — state.

Three defects this pins, all found by driving the real path rather than reading it:

1. **Hollow archive on a database backend.** `_run_data_backup` builds the archive
   by walking DATA_DIR. That is the whole story only on the JSON backend. SQLite
   re-adds a consistent `storage.snapshot()`, so it was covered — but Postgres
   (the `install-server.sh` DEFAULT) has neither a walk-visible file nor a
   snapshot branch, so its archives carried no devices, alerts, config, tickets,
   tokens or vault at all. `_tar_add_logical_stores` exports the logical
   documents for ANY database backend.

2. **The nightly archive could not be restored through the restore endpoint.**
   `_run_data_backup` prefixes every member with `remotepower/`;
   `handle_backup_restore` joined the member name onto DATA_DIR verbatim, so a
   scheduled archive recreated the install one level down at
   `DATA_DIR/remotepower/…` and restored nothing usable — while still reporting
   "N files restored".

3. **The drill passed on both.** `ok = saw_root and members > 0` asserts only
   that the tar opens; an archive with no restorable state satisfied it.

The tests run under whichever backend the suite is running (`make test` = JSON,
`make test-sqlite` = SQLite), and the Postgres export path is covered with a fake
`_dbmod()` so it needs no server.
"""

import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-dr-"))

_spec = importlib.util.spec_from_file_location("api_v642_dr", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _members(path):
    with tarfile.open(str(path), "r:gz") as tar:
        return tar.getnames()


def _member_bytes(path, name):
    with tarfile.open(str(path), "r:gz") as tar:
        f = tar.extractfile(name)
        return f.read() if f else b""


class TestArchiveCarriesState(unittest.TestCase):
    """The DR archive holds the fleet on every backend — not just the JSON one."""

    def setUp(self):
        self.bdir = Path(tempfile.mkdtemp(prefix="rp-v642-bk-"))
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"] = {"enabled": True, "path": str(self.bdir)}
        cfg["server_name"] = "DR-CANARY"
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.DEVICES_FILE, {
            "dev-dr": {"name": "dr-host", "group": "prod", "last_seen": 1},
        })

    def _run(self):
        res = api._run_data_backup(triggered_by="test")
        self.assertTrue(res.get("ok"), res)
        return Path(res["file"]), res

    def test_archive_contains_the_seeded_device(self):
        arc, res = self._run()
        names = _members(arc)
        self.assertIn("remotepower/devices.json", names,
                      f"no devices store in the archive: {names}")
        body = _member_bytes(arc, "remotepower/devices.json")
        self.assertIn(b"dr-host", body,
                      "the archive holds a devices store but not the device")

    def test_archive_contains_config(self):
        arc, _ = self._run()
        self.assertIn(b"DR-CANARY", _member_bytes(arc, "remotepower/config.json"))

    def test_store_count_is_reported(self):
        """`stores` tells the operator whether the archive is hollow, and is
        non-zero exactly when a database backend is in use."""
        _, res = self._run()
        self.assertIn("stores", res)
        if api._dbmod() is None:
            self.assertEqual(res["stores"], 0, "JSON backend needs no export")
        else:
            self.assertGreater(res["stores"], 0,
                               "a database backend must export its stores")

    def test_backup_state_records_the_store_count(self):
        self._run()
        state_file = api.DATA_DIR / "self_backup_state.json"
        api._invalidate_load_cache(state_file)
        self.assertIn("stores", api.load(state_file) or {})


class _FakePgModule:
    """Enough of the storage_pg interface for _tar_add_logical_stores."""

    def __init__(self, docs):
        self.docs = docs

    def iter_files(self, data_dir=None):
        return sorted(self.docs)

    def load(self, path):
        return self.docs[Path(path).name]

    def mtime(self, path):
        return 1700000000


class TestPostgresExportPath(unittest.TestCase):
    """The Postgres branch, without a Postgres server.

    This is the case that shipped broken: nothing on disk, so the walk produced
    an archive with no state in it.
    """

    def setUp(self):
        self._orig = api._dbmod
        api._dbmod = lambda: _FakePgModule({
            "devices.json": {"pg-1": {"name": "pg-host"}},
            "alerts.json": [{"event": "device_offline"}],
        })

    def tearDown(self):
        api._dbmod = self._orig          # never leak a monkeypatch

    def test_stores_are_exported_into_the_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            n = api._tar_add_logical_stores(tar, "remotepower/")
        self.assertEqual(n, 2)
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            self.assertEqual(sorted(tar.getnames()),
                             ["remotepower/alerts.json", "remotepower/devices.json"])
            f = tar.extractfile("remotepower/devices.json")
            self.assertEqual(json.loads(f.read()), {"pg-1": {"name": "pg-host"}})

    def test_a_failing_store_does_not_kill_the_archive(self):
        """One unreadable document must not cost the operator the whole backup."""
        class _Broken(_FakePgModule):
            def load(self, path):
                if Path(path).name == "alerts.json":
                    raise RuntimeError("boom")
                return self.docs[Path(path).name]

        api._dbmod = lambda: _Broken({
            "devices.json": {"pg-1": {"name": "pg-host"}},
            "alerts.json": {},
        })
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            n = api._tar_add_logical_stores(tar, "remotepower/")
        self.assertEqual(n, 1)

    def test_json_backend_exports_nothing(self):
        api._dbmod = lambda: None
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            self.assertEqual(api._tar_add_logical_stores(tar, "remotepower/"), 0)


class TestRestoreAcceptsTheScheduledArchiveShape(unittest.TestCase):
    """A nightly archive uploaded to /api/backup/restore must land at the data
    dir root, not one level down inside it."""

    def setUp(self):
        self.calls = []
        self._orig_admin = api.require_admin_auth
        self._orig_body = api.get_body
        self._orig_audit = api.audit_log
        api.require_admin_auth = lambda *a, **k: "tester"
        api.audit_log = lambda *a, **k: self.calls.append(a)

    def tearDown(self):
        api.require_admin_auth = self._orig_admin
        api.get_body = self._orig_body
        api.audit_log = self._orig_audit

    def _archive(self, prefix):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            payload = json.dumps({"restored-dev": {"name": "came-back"}}).encode()
            ti = tarfile.TarInfo(prefix + "devices.json")
            ti.size = len(payload)
            tar.addfile(ti, io.BytesIO(payload))
        return buf.getvalue()

    def _restore(self, raw):
        api.get_body = lambda: raw
        try:
            api.handle_backup_restore()
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, "status", None), getattr(e, "body", None)
        return None, None

    def test_scheduled_prefix_is_stripped(self):
        status, body = self._restore(self._archive("remotepower/"))
        self.assertEqual(status, 200, body)
        self.assertFalse((api.DATA_DIR / "remotepower").exists(),
                         "the archive was restored one level down")
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertIn("restored-dev", api.load(api.DEVICES_FILE) or {},
                      "restore reported success but the device is not readable")

    def test_download_shape_still_restores(self):
        """The unprefixed `GET /api/backup/download` shape must keep working."""
        status, body = self._restore(self._archive(""))
        self.assertEqual(status, 200, body)
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertIn("restored-dev", api.load(api.DEVICES_FILE) or {})


class TestDrillRejectsAHollowArchive(unittest.TestCase):
    def setUp(self):
        self.bdir = Path(tempfile.mkdtemp(prefix="rp-v642-drill-"))
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"] = {"enabled": True, "path": str(self.bdir)}
        api.save(api.CONFIG_FILE, cfg)

    def _write(self, names):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for n in names:
                ti = tarfile.TarInfo(n)
                ti.size = 2
                tar.addfile(ti, io.BytesIO(b"{}"))
        (self.bdir / "remotepower_data_20260801_000000.tar.gz").write_bytes(buf.getvalue())

    def test_archive_with_no_state_fails_the_drill(self):
        """Exactly what a Postgres install used to produce: structure, no state."""
        self._write(["remotepower/.storage.json.lock", "remotepower/backups"])
        res = api._restore_drill_core()
        self.assertFalse(res.get("ok"), res)
        self.assertIn("no restorable state", (res.get("error") or ""))

    def test_archive_with_stores_passes(self):
        self._write(["remotepower/devices.json", "remotepower/config.json"])
        res = api._restore_drill_core()
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(res.get("stores"), 2)

    def test_sqlite_image_alone_passes(self):
        self._write(["remotepower/remotepower.db"])
        res = api._restore_drill_core()
        self.assertTrue(res.get("ok"), res)
        self.assertTrue(res.get("db_image"))


if __name__ == "__main__":
    unittest.main()
