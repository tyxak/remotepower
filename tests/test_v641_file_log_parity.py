#!/usr/bin/env python3
"""v6.4.1 guardrail: log_watch FILE-PATH rules work on Windows and macOS.

The Linux agent tails arbitrary file paths from log_watch rules and submits
new lines under the synthetic unit 'file:<path>'; Windows and macOS dropped
the `log_watch` heartbeat key entirely, so a file-path rule on those hosts
saved fine, showed as configured, and never fired (the
success-toast-then-silence class — the Windows docstring even implied the
rules worked because the Event Log side did).

This drives the real chain for BOTH ported agents:

    server pushes log_watch             (heartbeat response → heartbeat_once)
      → the agent tails a real file     (_submit_file_logs → collect_file_log)
      → the captured POST body goes     (handle_log_submit — the real server
        through the real ingest          matcher, so a rule pattern alerts)

Runs under both backends via `make test-both`.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import api  # noqa: E402


def _load_agent(fname, modname):
    spec = importlib.util.spec_from_file_location(
        modname, _ROOT / "client" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mac = _load_agent("remotepower-agent-mac.py", "rp_mac_agent_flog")
win = _load_agent("remotepower-agent-win.py", "rp_win_agent_flog")


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _AgentFileLogMixin:
    """Same battery for both ported agents; subclasses pin `agent`."""
    agent = None

    def setUp(self):
        ag = self.agent
        self._saved = (ag._log_watch_paths, dict(ag._file_log_state))

        def _restore():
            ag._log_watch_paths, ag._file_log_state = self._saved
        self.addCleanup(_restore)
        ag._log_watch_paths, ag._file_log_state = [], {}

        self.tmp = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmp, "app.log")
        # Point the agent's persisted tail state into scratch space.
        self._orig_state_path = ag._file_log_state_path
        ag._file_log_state_path = lambda: os.path.join(self.tmp, "state.json")
        self.addCleanup(lambda: setattr(ag, "_file_log_state_path",
                                        self._orig_state_path))

    def test_heartbeat_response_populates_the_path_list(self):
        ag = self.agent
        orig = ag._post_json
        try:
            ag._post_json = lambda *a, **k: {
                "ok": True,
                "log_watch": [
                    {"unit": "nginx.service", "pattern": "x"},   # unit rule: ignored
                    {"path": self.log_path, "pattern": "ERROR"},
                    "not-a-dict",
                ]}
            ag.heartbeat_once(
                {"server_url": "http://x", "device_id": "d1"}, 2)
        finally:
            ag._post_json = orig
        self.assertEqual(ag._log_watch_paths, [self.log_path])

    def test_tail_state_machine(self):
        ag = self.agent
        state = {}
        Path(self.log_path).write_text("historic line\n")
        # First sight: bookmark, never dump history.
        self.assertEqual(ag.collect_file_log(self.log_path, state), [])
        with open(self.log_path, "a") as f:
            f.write("ERROR one\nERROR two\n")
        self.assertEqual(ag.collect_file_log(self.log_path, state),
                         ["ERROR one", "ERROR two"])
        # Nothing new → nothing reported.
        self.assertEqual(ag.collect_file_log(self.log_path, state), [])
        # Truncation resets to the start of the new content.
        Path(self.log_path).write_text("after truncate\n")
        self.assertEqual(ag.collect_file_log(self.log_path, state),
                         ["after truncate"])

    def test_submit_posts_the_linux_wire_shape(self):
        ag = self.agent
        Path(self.log_path).write_text("")
        ag._log_watch_paths = [self.log_path]
        posted = []
        orig = ag._post_json
        ag._post_json = lambda url, payload, **k: posted.append((url, payload))
        try:
            ag._submit_file_logs(
                {"server_url": "https://s", "device_id": "d1", "token": "t"}, 1)
            with open(self.log_path, "a") as f:
                f.write("ERROR boom\n")
            ag._submit_file_logs(
                {"server_url": "https://s", "device_id": "d1", "token": "t"}, 5)
        finally:
            ag._post_json = orig
        self.assertEqual(len(posted), 1, "expected exactly one non-empty POST")
        url, payload = posted[0]
        self.assertTrue(url.endswith("/api/logs"))
        self.assertEqual(payload["units"],
                         {f"file:{self.log_path}": ["ERROR boom"]})

    def test_failed_post_replays_instead_of_dropping(self):
        ag = self.agent
        Path(self.log_path).write_text("")
        ag._log_watch_paths = [self.log_path]
        ag._submit_file_logs(
            {"server_url": "https://s", "device_id": "d1", "token": "t"}, 1)
        with open(self.log_path, "a") as f:
            f.write("must not be lost\n")

        def boom(*a, **k):
            raise OSError("network down")
        orig = ag._post_json
        ag._post_json = boom
        try:
            ag._submit_file_logs(
                {"server_url": "https://s", "device_id": "d1", "token": "t"}, 5)
        finally:
            ag._post_json = orig
        posted = []
        ag._post_json = lambda url, payload, **k: posted.append(payload)
        try:
            ag._submit_file_logs(
                {"server_url": "https://s", "device_id": "d1", "token": "t"}, 10)
        finally:
            ag._post_json = orig
        self.assertEqual(posted and posted[0]["units"],
                         {f"file:{self.log_path}": ["must not be lost"]})


class TestMacFileLog(_AgentFileLogMixin, unittest.TestCase):
    agent = mac

    def test_deny_list_blocks_credentials_even_via_symlink(self):
        link = os.path.join(self.tmp, "innocent.log")
        try:
            os.symlink("/etc/master.passwd", link)
        except OSError:
            self.skipTest("no symlink support")
        self.assertFalse(mac._file_log_path_allowed(link))
        self.assertFalse(mac._file_log_path_allowed("/private/etc/sudoers"))
        self.assertFalse(mac._file_log_path_allowed("/Users/bob/.ssh/id_ed25519"))
        self.assertFalse(mac._file_log_path_allowed("/var/root/.ssh/id_rsa"))
        self.assertTrue(mac._file_log_path_allowed("/var/log/myapp/access.log"))
        self.assertEqual(mac.collect_file_log(link, {}), [])


class TestWinFileLog(_AgentFileLogMixin, unittest.TestCase):
    agent = win

    def test_deny_list_blocks_credentials(self):
        self.assertFalse(win._file_log_path_allowed(
            r"C:\Users\bob\.ssh\id_ed25519"))
        self.assertFalse(win._file_log_path_allowed(
            r"C:\Windows\System32\config\SAM"))
        self.assertFalse(win._file_log_path_allowed(
            r"C:\Users\bob\AppData\Roaming\Microsoft\Protect\S-1-5-21\x"))
        self.assertFalse(win._file_log_path_allowed(
            r"C:\Windows\NTDS\ntds.dit"))
        self.assertTrue(win._file_log_path_allowed(
            r"C:\ProgramData\myapp\app.log"))


class TestServerIngestsThePortedShape(unittest.TestCase):
    """The captured agent POST must fire a real log_watch rule server-side."""

    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method",
                                "require_perm", "verify_token")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"
        self.dev_id = "win-flog-host"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {
                "name": self.dev_id, "hostname": self.dev_id,
                "os": "Windows 11", "token": "devtoken",
                "last_seen": int(time.time()), "enrolled": int(time.time()),
                "tags": [], "group": "", "sysinfo": {}, "agentless": False,
            }
        })
        api.save(api.LOG_WATCH_FILE, {})
        api.save(api.ALERTS_FILE, {"alerts": []})
        # Save the Windows path rule through the REAL config handler — a
        # hand-built rule dict would bypass the save-side normalization
        # (unit='file:<path>') and hide a save-side rejection of C:\ paths.
        api.require_perm = lambda *a, **k: "tester"
        body = {"log_watch": [{"path": r"C:\ProgramData\myapp\app.log",
                               "pattern": "ERROR"}]}
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_services_config(self.dev_id)
        except _Captured as c:
            assert c.status == 200, c.body
        saved = api.load(api.DEVICES_FILE)[self.dev_id].get("log_watch") or []
        assert saved and saved[0].get("unit") == r"file:C:\ProgramData\myapp\app.log", \
            f"save-side rejected the Windows path rule: {saved}"

    def test_file_unit_lines_are_buffered_and_matched(self):
        body = {"device_id": self.dev_id, "token": "devtoken",
                "units": {r"file:C:\ProgramData\myapp\app.log":
                          ["ERROR the disk is on fire"]}}
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_log_submit()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)

        buf = (api.load(api.LOG_WATCH_FILE) or {}).get(self.dev_id) or {}
        unit_buf = (buf.get("units") or {}).get(
            r"file:C:\ProgramData\myapp\app.log") or []
        self.assertTrue(unit_buf, "file: unit lines were not buffered")
        alerts = (api.load(api.ALERTS_FILE) or {}).get("alerts") or []
        self.assertTrue(
            any(a.get("event") == "log_alert" and a.get("device_id") == self.dev_id
                for a in alerts),
            f"log_watch rule did not fire on the ported shape: {alerts}")

    def test_linux_file_units_are_no_longer_dropped_at_ingest(self):
        # The pre-existing bug this sweep unearthed: _sanitize_unit_name
        # rejected ':' and '/', so the LINUX agent's file: units (shipped
        # v3.0.1) were silently dropped here all along. Drive the Linux wire
        # shape (dict entries with a `message` key) through the real handler.
        with api._LockedUpdate(api.DEVICES_FILE) as devices:
            devices[self.dev_id]["log_watch"] = [
                {"unit": "file:/var/log/myapp/access.log",
                 "path": "/var/log/myapp/access.log", "pattern": "ERROR"}]
        body = {"device_id": self.dev_id, "token": "devtoken",
                "units": {"file:/var/log/myapp/access.log": [
                    {"ts": int(time.time() * 1000), "level": "info",
                     "unit": "file:/var/log/myapp/access.log",
                     "message": "ERROR out of disk"}]}}
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_log_submit()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)

        buf = (api.load(api.LOG_WATCH_FILE) or {}).get(self.dev_id) or {}
        unit_buf = (buf.get("units") or {}).get(
            "file:/var/log/myapp/access.log") or []
        self.assertTrue(unit_buf, "Linux file: unit lines were not buffered")
        alerts = (api.load(api.ALERTS_FILE) or {}).get("alerts") or []
        self.assertTrue(
            any(a.get("event") == "log_alert" and a.get("device_id") == self.dev_id
                and a.get("payload", {}).get("unit", "").startswith("file:")
                for a in alerts),
            f"Linux file-path rule did not fire: {alerts}")

    def test_hostile_file_units_still_rejected(self):
        for bad in ("file:../../etc/shadow", "file:relative/path",
                    "file:/with\nnewline", "file:/glob/*.log", "file:"):
            self.assertIsNone(api._sanitize_log_unit(bad), bad)
        self.assertEqual(api._sanitize_log_unit("nginx.service"), "nginx.service")
        self.assertIsNone(api._sanitize_log_unit("bad unit name"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
