"""v6.3.0: scheduled restore drill for the server's own DR backup.

Drives the REAL sweep (`_maybe_run_restore_drill`) against real archives in a
scratch backup dir — not source greps — per the "drive the real path before
believing a feature works" rule.
"""

import importlib.util
import io
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v630-drill-"))

_spec = importlib.util.spec_from_file_location("api_v630_drill", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

STATE = api.DATA_DIR / "self_backup_state.json"


def _make_archive(path, good=True):
    """A minimal remotepower_data_*.tar.gz — valid tree, or corrupt bytes."""
    if not good:
        path.write_bytes(b"this is not a gzip stream")
        return
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b'{"a": 1}'
        ti = tarfile.TarInfo("remotepower/config.json")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


class TestScheduledRestoreDrill(unittest.TestCase):
    def setUp(self):
        self.bdir = Path(tempfile.mkdtemp(prefix="rp-drill-bk-"))
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"] = {"enabled": True, "path": str(self.bdir), "drill_days": 7}
        api.save(api.CONFIG_FILE, cfg)
        api.save(STATE, {"last_run": int(time.time()), "last_drill_at": 0})
        self.fired = []
        self._orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, **k: self.fired.append((ev, payload or {}))

    def tearDown(self):
        api.fire_webhook = self._orig_fw   # never leak a monkeypatch

    def _state(self):
        api._invalidate_load_cache(STATE)
        return api.load(STATE) or {}

    def test_good_archive_records_ok_and_stays_quiet(self):
        _make_archive(self.bdir / "remotepower_data_1.tar.gz", good=True)
        api._maybe_run_restore_drill()
        st = self._state()
        self.assertTrue(st.get("last_drill_ok"))
        self.assertGreater(st.get("last_drill_at", 0), 0)
        self.assertEqual(self.fired, [])   # healthy drill fires nothing

    def test_corrupt_archive_fires_failed_once_then_recovers(self):
        _make_archive(self.bdir / "remotepower_data_1.tar.gz", good=False)
        api._maybe_run_restore_drill()
        self.assertEqual([e for e, _ in self.fired], ["restore_drill_failed"])
        ev, payload = self.fired[0]
        self.assertEqual(payload.get("path"), "self:dr-archive")
        self.assertFalse(self._state().get("last_drill_ok"))

        # Edge-trigger: a second due failing drill does NOT re-fire.
        api.save(STATE, dict(self._state(), last_drill_at=0))
        api._maybe_run_restore_drill()
        self.assertEqual([e for e, _ in self.fired], ["restore_drill_failed"])

        # Recovery: archive fixed → restore_drill_ok fires, flag clears.
        _make_archive(self.bdir / "remotepower_data_2.tar.gz", good=True)
        api.save(STATE, dict(self._state(), last_drill_at=0))
        api._maybe_run_restore_drill()
        self.assertEqual([e for e, _ in self.fired][-1], "restore_drill_ok")
        st = self._state()
        self.assertTrue(st.get("last_drill_ok"))
        self.assertFalse(st.get("drill_alerted"))

    def test_not_due_is_a_noop(self):
        _make_archive(self.bdir / "remotepower_data_1.tar.gz", good=False)
        api.save(STATE, {"last_run": int(time.time()),
                         "last_drill_at": int(time.time())})   # just ran
        api._maybe_run_restore_drill()
        self.assertEqual(self.fired, [])

    def test_drill_days_zero_disables(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"]["drill_days"] = 0
        api.save(api.CONFIG_FILE, cfg)
        _make_archive(self.bdir / "remotepower_data_1.tar.gz", good=False)
        api._maybe_run_restore_drill()
        self.assertEqual(self.fired, [])
        self.assertEqual(self._state().get("last_drill_at"), 0)

    def test_never_backed_up_skips(self):
        api.save(STATE, {"last_drill_at": 0})   # no last_run
        _make_archive(self.bdir / "remotepower_data_1.tar.gz", good=False)
        api._maybe_run_restore_drill()
        self.assertEqual(self.fired, [])   # backup_stale owns that alert

    def test_sweep_is_wired_into_main_cadence(self):
        from tests import apisrc
        self.assertIn("_safe(_maybe_run_restore_drill", apisrc.api_source())

    def test_drill_days_persists_through_config_save(self):
        # The save whitelist is the silent-drop spot — drive the real block.
        src = (_CGI / "api.py").read_text()
        self.assertIn("'drill_days' in bk", src)
        self.assertIn("backup.drill_days must be 0..90", src)


class TestManualTestRestoreUnchanged(unittest.TestCase):
    """The manual endpoint's contract survived the core extraction."""

    def setUp(self):
        self.captured = {}

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)

        self._orig = (api.respond, api.require_admin_auth, api.method)
        api.respond = _respond
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"

    def tearDown(self):
        api.respond, api.require_admin_auth, api.method = self._orig

    def test_404_when_no_archives(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"] = {"enabled": True, "path": tempfile.mkdtemp(prefix="rp-empty-")}
        api.save(api.CONFIG_FILE, cfg)
        try:
            api.handle_backup_test_restore()
        except api.HTTPError:
            pass
        self.assertEqual(self.captured["status"], 404)

    def test_200_ok_with_message_on_good_archive(self):
        bdir = Path(tempfile.mkdtemp(prefix="rp-good-"))
        _make_archive(bdir / "remotepower_data_1.tar.gz", good=True)
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["backup"] = {"enabled": True, "path": str(bdir)}
        api.save(api.CONFIG_FILE, cfg)
        try:
            api.handle_backup_test_restore()
        except api.HTTPError:
            pass
        self.assertEqual(self.captured["status"], 200)
        self.assertTrue(self.captured["data"]["ok"])
        self.assertIn("restorable", self.captured["data"]["message"])


if __name__ == "__main__":
    unittest.main()
