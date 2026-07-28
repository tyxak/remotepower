#!/usr/bin/env python3
"""v6.4.1 guardrail: device display-name rename (roadmap D9).

A device's name was set once at enroll (from the hostname) and there was NO
handler to change it afterwards. The rename rides handle_device_save_bulk.
The critical property is the second test: the heartbeat must never overwrite
`name` on an existing record, or the rename silently reverts on the next beat
(the dead-feature trap this project keeps finding).

Runs under both backends via `make test-both`.
"""
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


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestDeviceRename(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method",
                                "require_admin_auth")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"
        api.require_admin_auth = lambda *a, **k: "tester"
        self.dev_id = "rename-host"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {
                "name": "old-hostname", "hostname": "old-hostname",
                "os": "Linux", "token": "devtoken",
                "last_seen": int(time.time()), "enrolled": int(time.time()),
                "tags": [], "group": "", "sysinfo": {}, "agentless": False,
            }
        })

    def _save_bulk(self, body):
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_device_save_bulk(self.dev_id)
        except _Captured as c:
            return c.status, c.body
        raise AssertionError("handler did not respond")

    def test_rename_persists(self):
        status, _ = self._save_bulk({"name": "  db-primary  "})
        self.assertEqual(status, 200)
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        self.assertEqual(dev["name"], "db-primary")
        self.assertEqual(dev["hostname"], "old-hostname",
                         "hostname must stay the agent-reported truth")

    def test_blank_name_does_not_erase(self):
        self._save_bulk({"name": "db-primary"})
        status, body = self._save_bulk({"name": "   ", "group": "web"})
        self.assertEqual(status, 200, body)
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        self.assertEqual(dev["name"], "db-primary",
                         "a blank name field must not erase the display name")
        self.assertEqual(dev["group"], "web")

    def test_rename_survives_a_heartbeat(self):
        # THE trap: if the heartbeat re-derives name from the reported
        # hostname, every rename silently reverts within one poll interval.
        self._save_bulk({"name": "db-primary"})
        api.get_json_obj = lambda: {
            "device_id": self.dev_id, "token": "devtoken",
            "ip": "10.0.0.5", "os": "Linux", "version": api.SERVER_VERSION,
            "sysinfo": {"os": "Linux", "hostname": "old-hostname"},
        }

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        self.assertEqual(dev["name"], "db-primary",
                         "the heartbeat reverted the rename")

    def test_name_is_sanitized_and_bounded(self):
        self._save_bulk({"name": "x" * 500})
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        self.assertLessEqual(len(dev["name"]), api.MAX_NAME_LEN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
