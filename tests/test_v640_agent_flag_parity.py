"""v6.4.0 — cross-platform heartbeat-flag parity for the mac/Windows agents.

Field-report class: an operator clicks "Scan packages" / "Update agent" /
configures backup monitors on a Mac or Windows host, gets a success toast, and
the agent SILENTLY DROPS the flag — the Linux agent honoured it, the others
never read it. Now the three portable flags work on all three agents:
  force_package_scan → refresh sysinfo (brew outdated / Windows Update pending)
  force_agent_upgrade → the agent's own self-update path
  backup_monitors → backup-freshness (mtime+size) reporting
And OpenSCAP (Linux-only) is honestly reported per-OS server-side instead of a
silent no-op on Windows/macOS.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _load(fname, modname):
    spec = importlib.util.spec_from_file_location(
        modname, _ROOT / "client" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mac = _load("remotepower-agent-mac.py", "rp_mac_flagparity")
win = _load("remotepower-agent-win.py", "rp_win_flagparity")


class _AgentFlagBase:
    """Shared assertions for an agent module exposing build_heartbeat +
    heartbeat_once + collect_backup_status + the three globals."""
    agent = None

    def _creds(self):
        return {"device_id": "d1", "token": "t",
                "server_url": "http://localhost:0"}

    def test_backup_status_collector_reports_mtime_and_size(self):
        a = self.agent
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "backup.tar")
            with open(fp, "wb") as f:
                f.write(b"x" * 123)
            out = a.collect_backup_status([{"path": fp, "label": "b"}])
            self.assertEqual(len(out), 1)
            self.assertTrue(out[0]["exists"])
            self.assertEqual(out[0]["size"], 123)
            self.assertGreater(out[0]["mtime"], 0)
            # missing path is exists:false, not a crash
            miss = a.collect_backup_status([{"path": fp + ".nope"}])
            self.assertFalse(miss[0]["exists"])

    def test_force_package_scan_forces_sysinfo_off_cadence(self):
        a = self.agent
        a._force_sysinfo = False
        # poll_count that is NOT a sysinfo beat (not <=1, not %12==0)
        hb = a.build_heartbeat(self._creds(), poll_count=5)
        self.assertNotIn("sysinfo", hb, "cadence assumption changed — pick "
                         "another non-sysinfo poll_count")
        a._force_sysinfo = True
        hb = a.build_heartbeat(self._creds(), poll_count=5)
        self.assertIn("sysinfo", hb, "force_package_scan must refresh sysinfo")
        self.assertFalse(a._force_sysinfo, "the force flag is one-shot")

    def test_backup_monitors_ride_the_heartbeat_when_set(self):
        a = self.agent
        a._backup_monitors = []
        hb = a.build_heartbeat(self._creds(), poll_count=5)
        self.assertNotIn("backup_status", hb)
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "b.tar")
            open(fp, "wb").write(b"y")
            a._backup_monitors = [{"path": fp}]
            try:
                hb = a.build_heartbeat(self._creds(), poll_count=5)
                self.assertIn("backup_status", hb)
                self.assertEqual(hb["backup_status"][0]["path"], fp)
            finally:
                a._backup_monitors = []

    def test_response_parsing_sets_the_flags(self):
        # Drive heartbeat_once's response branch directly by stubbing the POST.
        a = self.agent
        a._force_sysinfo = False
        a._backup_monitors = []
        orig_post = a._post_json
        orig_su = a._self_update
        su_called = []
        a._self_update = lambda: su_called.append(1) or {"cmd": "update", "rc": 0}
        a._post_json = lambda url, payload, **k: {
            "force_package_scan": True,
            "backup_monitors": [{"path": "/tmp/x"}],
            "force_agent_upgrade": True,
        }
        try:
            a.heartbeat_once(self._creds(), poll_count=5)
        finally:
            a._post_json = orig_post
            a._self_update = orig_su
        self.assertTrue(a._force_sysinfo, "force_package_scan not consumed")
        self.assertEqual(a._backup_monitors, [{"path": "/tmp/x"}])
        self.assertTrue(su_called, "force_agent_upgrade must run self-update")
        a._force_sysinfo = False
        a._backup_monitors = []


class TestMacFlagParity(_AgentFlagBase, unittest.TestCase):
    agent = mac


class TestWinFlagParity(_AgentFlagBase, unittest.TestCase):
    agent = win


class TestScapIsHonestPerOs(unittest.TestCase):
    """OpenSCAP is Linux-only; the server must not silently accept a
    Windows/macOS SCAP target (the flag the agent would drop). It scans the
    Linux hosts in a mixed batch and reports the rest as skipped."""

    @classmethod
    def setUpClass(cls):
        _CGI = _ROOT / "server" / "cgi-bin"
        sys.path.insert(0, str(_CGI))
        os.environ.setdefault("RP_DATA_DIR",
                              tempfile.mkdtemp(prefix="rp-v640-scap-"))
        spec = importlib.util.spec_from_file_location("api_v640_scap",
                                                      _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def test_split_by_os_support(self):
        api = self.api
        d = Path(tempfile.mkdtemp())
        orig = api.DEVICES_FILE
        api.DEVICES_FILE = d / "devices.json"
        try:
            api.save(api.DEVICES_FILE, {
                "lin": {"name": "lin1", "os": "Ubuntu 22.04"},
                "win": {"name": "win1", "os": "Windows Server 2022"},
                "mac": {"name": "mac1", "os": "macOS 14.5"},
            })
            api._LOAD_CACHE.clear()
            keep, skipped = api._split_targets_by_os_support(
                ["lin", "win", "mac"], supported=("linux",))
            self.assertEqual(keep, ["lin"])
            self.assertEqual(sorted(skipped), ["mac1", "win1"])
            # unknown id is kept (not blocked) — matches _resolve_targets policy
            keep2, _ = api._split_targets_by_os_support(
                ["ghost"], supported=("linux",))
            self.assertEqual(keep2, ["ghost"])
        finally:
            api.DEVICES_FILE = orig
            api._LOAD_CACHE.clear()

    def test_scap_handler_gates_and_reports(self):
        api = self.api
        d = Path(tempfile.mkdtemp())
        saved = {a: getattr(api, a) for a in ("DEVICES_FILE",)}
        api.DEVICES_FILE = d / "devices.json"
        api.save(api.DEVICES_FILE, {
            "win": {"name": "win1", "os": "Windows Server 2022"}})
        api._LOAD_CACHE.clear()
        import scap_handlers
        scap_handlers.bind(api.__dict__)
        cap = {}
        orig = {n: getattr(api, n) for n in
                ("method", "require_perm", "audit_log", "respond",
                 "get_json_obj", "_read_valid")}
        api.method = lambda: "POST"
        api.require_perm = lambda *a, **k: "actor"
        api.audit_log = lambda *a, **k: None
        api._read_valid = lambda m: {"device_ids": ["win"], "profile": "cis"}

        def _resp(s, b=None):
            cap["s"] = s
            cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        try:
            try:
                scap_handlers.handle_scap_scan()
            except api.HTTPError:
                pass
        finally:
            for n, v in orig.items():
                setattr(api, n, v)
            for a, v in saved.items():
                setattr(api, a, v)
            api._LOAD_CACHE.clear()
        # a pure-Windows batch → 400 "Linux only", not a fake success
        self.assertEqual(cap["s"], 400)
        self.assertIn("Linux", cap["b"]["error"])


if __name__ == "__main__":
    unittest.main()
