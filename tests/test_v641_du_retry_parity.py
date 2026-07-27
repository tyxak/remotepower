#!/usr/bin/env python3
"""v6.4.1 guardrails: macOS du-scan parity + the 202-busy retry_after hint.

du_scan_enabled is a FLEET-WIDE toggle, so enabling it claimed every device
while Macs silently never reported (`du_scan_*` was Linux-only). And the
server has sent `retry_after` with its 202-busy response since v2.1.0 with no
agent ever reading it — every agent waited out a full poll interval on a
momentary lock contention.

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


mac = _load_agent("remotepower-agent-mac.py", "rp_mac_agent_du")
win = _load_agent("remotepower-agent-win.py", "rp_win_agent_du")


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StopLoop(Exception):
    pass


class TestMacDuScan(unittest.TestCase):
    def setUp(self):
        self._cfg = dict(mac._du_cfg)
        self.addCleanup(lambda: mac._du_cfg.update(self._cfg))
        mac._du_cfg.update({"on": False, "paths": None, "force": False})

    def test_parse_du_kib_is_bytes_sorted_and_drops_root(self):
        out = ("102400\t/Users/bob/Movies\n"
               "51200\t/Users/bob/Library\n"
               "1\t/Users/bob\n")          # root total — must be dropped
        rows = mac._parse_du_kib(out, "/Users/bob")
        self.assertEqual([r["path"] for r in rows],
                         ["/Users/bob/Movies", "/Users/bob/Library"])
        self.assertEqual(rows[0]["bytes"], 102400 * 1024)

    def test_config_trio_read_from_heartbeat_response(self):
        orig = mac._post_json
        try:
            mac._post_json = lambda *a, **k: {
                "ok": True, "du_scan_enabled": True,
                "du_scan_paths": ["/Users"], "force_du_scan": True}
            mac.heartbeat_once({"server_url": "http://x", "device_id": "d"}, 2)
        finally:
            mac._post_json = orig
        self.assertEqual(mac._du_cfg,
                         {"on": True, "paths": ["/Users"], "force": True})

    def test_report_reaches_the_disk_usage_store(self):
        dev_id = "mac-du-host"
        api.save(api.DEVICES_FILE, {
            dev_id: {"name": dev_id, "hostname": dev_id, "os": "macOS 15.2",
                     "token": "devtoken", "last_seen": int(time.time()),
                     "enrolled": int(time.time()), "tags": [], "group": "",
                     "sysinfo": {}, "agentless": False}})
        api.save(api.DISK_USAGE_FILE, {})
        mac._du_cfg.update({"on": True, "force": True})
        fake_report = {"/Users": [{"path": "/Users/bob/Movies",
                                   "bytes": 9 * 1024**3}]}
        orig_collect, orig_ts = mac.collect_disk_usage, mac._save_du_scan_ts
        mac.collect_disk_usage = lambda paths=None, **k: fake_report
        mac._save_du_scan_ts = lambda ts: None
        try:
            payload = mac.build_heartbeat(
                {"device_id": dev_id, "token": "devtoken"}, 3)
        finally:
            mac.collect_disk_usage, mac._save_du_scan_ts = orig_collect, orig_ts
        self.assertEqual(payload.get("disk_usage"), fake_report)
        self.assertFalse(mac._du_cfg["force"], "force flag must be one-shot")

        # Through the real server handler → the store the drawer reads.
        orig = {n: getattr(api, n) for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(lambda: [setattr(api, n, v) for n, v in orig.items()])
        api.method = lambda: "POST"
        api.get_json_obj = lambda: {
            "device_id": dev_id, "token": "devtoken",
            "sysinfo": {"os": "macOS 15.2"}, "disk_usage": payload["disk_usage"]}

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
        rec = (api.load(api.DISK_USAGE_FILE) or {}).get(dev_id) or {}
        self.assertIn("/Users", str(rec),
                      "mac du report was not ingested into disk_usage.json")


class TestBusyRetryAfterHonoured(unittest.TestCase):
    """Drive each ported run() loop for one iteration over a busy response and
    assert the sleep is the clamped hint, not the full poll interval."""

    def _drive_win(self, resp):
        calls = {"n": 0}
        delays = []

        def should_stop():
            calls["n"] += 1
            return calls["n"] > 1

        origs = (win.heartbeat_once, win.load_creds, win._init_logging)
        win.heartbeat_once = lambda creds, pc, pending=None: (resp, None)
        win.load_creds = lambda: {"device_id": "d", "poll_interval": 300}
        win._init_logging = lambda: None
        try:
            win.run(should_stop=should_stop, wait=delays.append)
        finally:
            win.heartbeat_once, win.load_creds, win._init_logging = origs
        return delays

    def test_windows_busy_uses_the_hint_with_a_floor(self):
        self.assertEqual(self._drive_win({"busy": True, "retry_after": 1}), [5])
        self.assertEqual(self._drive_win({"busy": True, "retry_after": 42}), [42])
        # Not busy → the full interval, hint or not.
        self.assertEqual(self._drive_win({"ok": True, "retry_after": 1}), [300])
        # Busy with a nonsense hint → full interval, no crash.
        self.assertEqual(self._drive_win({"busy": True, "retry_after": "x"}), [300])

    def _drive_mac(self, resp):
        delays = []

        def capture_sleep(s):
            delays.append(s)
            raise _StopLoop()

        origs = (mac.heartbeat_once, mac.load_creds, mac.time.sleep,
                 mac._trim_boot_log)
        mac.heartbeat_once = lambda creds, pc, pending=None: (resp, None)
        mac.load_creds = lambda: {"device_id": "d", "poll_interval": 300}
        mac.time.sleep = capture_sleep
        mac._trim_boot_log = lambda: False
        try:
            with self.assertRaises(_StopLoop):
                mac.run()
        finally:
            (mac.heartbeat_once, mac.load_creds, mac.time.sleep,
             mac._trim_boot_log) = origs
        return delays

    def test_mac_busy_uses_the_hint_with_a_floor(self):
        self.assertEqual(self._drive_mac({"busy": True, "retry_after": 1}), [5])
        self.assertEqual(self._drive_mac({"busy": True, "retry_after": 42}), [42])
        self.assertEqual(self._drive_mac({"ok": True, "retry_after": 1}), [300])


if __name__ == "__main__":
    unittest.main(verbosity=2)
