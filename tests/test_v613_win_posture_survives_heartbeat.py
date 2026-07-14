#!/usr/bin/env python3
"""v6.2.0 guardrail: sysinfo.win_posture must SURVIVE the heartbeat sanitizer.

The v6.2.0 Windows posture Checks rows (BitLocker / firewall / Windows Defender
realtime + signature age / Windows Update service) are derived server-side from
`sysinfo.win_posture`. handle_heartbeat rebuilds sysinfo through a strict
whitelist (`safe_si`); a field the agent sends but safe_si drops silently never
reaches the Checks engine — the single most recurring bug class in this project
(proc_names / mailq / custom_check_results all shipped broken this way, and
win_posture itself was found DROPPED in the v6.2.0 bug hunt: four independent
finders flagged the Windows Checks rows as permanently blank).

This is a FUNCTIONAL guardrail on purpose: it drives the REAL heartbeat handler
end to end and reads the persisted device back, rather than grepping the source
for a whitelist branch (which would false-green the moment the branch is present
but broken). If safe_si stops persisting win_posture, this fails.

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
_CGI_BIN = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import api  # noqa: E402


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestWinPostureSurvivesHeartbeat(unittest.TestCase):
    def setUp(self):
        # This suite drives the REAL handle_heartbeat, which reads the request
        # body via the module-level get_json_obj() and the verb via method().
        # In the full-suite process ANY earlier test that leaks a stub of those
        # (the recurring leaked-monkeypatch class) would feed our heartbeat a
        # wrong body → a spurious 403. So we install our OWN body/verb/respond
        # providers here and RESTORE them in cleanup — immune to leaks in either
        # direction (we don't inherit a leak, and we don't cause one).
        self._orig = {n: getattr(api, n) for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"

        self.dev_id = "win-host-1"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {
                "name": self.dev_id, "hostname": self.dev_id,
                "os": "Windows Server 2022", "token": "devtoken",
                "last_seen": int(time.time()), "enrolled": int(time.time()),
                "tags": [], "group": "", "sysinfo": {}, "agentless": False,
            }
        })

    def _beat(self, body):
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            return c.status, c.body
        raise AssertionError("handle_heartbeat did not call respond()")

    def _beat_with_posture(self, posture):
        body = {
            "device_id": self.dev_id,
            "token": "devtoken",
            "sysinfo": {"hostname": self.dev_id, "os": "Windows Server 2022",
                        "win_posture": posture},
        }
        s, _b = self._beat(body)
        self.assertEqual(s, 200, f"heartbeat rejected: {_b}")
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        return (dev.get("sysinfo") or {}).get("win_posture")

    def test_full_posture_survives(self):
        wp = self._beat_with_posture({
            "firewall": [{"name": "Domain", "enabled": True},
                         {"name": "Public", "enabled": False}],
            "bitlocker": [{"mount": "C:", "status": "FullyEncrypted"}],
            "defender_realtime": False,
            "defender_sig_age_days": 5,
            "wu_service": "Running",
        })
        self.assertIsInstance(wp, dict, "win_posture was DROPPED by safe_si")
        # Firewall profiles preserved with name + enabled.
        self.assertEqual({p["name"]: p["enabled"] for p in wp["firewall"]},
                         {"Domain": True, "Public": False})
        # BitLocker mount + status preserved.
        self.assertEqual(wp["bitlocker"][0]["mount"], "C:")
        self.assertEqual(wp["bitlocker"][0]["status"], "FullyEncrypted")
        # Defender realtime is a bool (False must survive, not be pruned as falsy).
        self.assertIs(wp["defender_realtime"], False)
        self.assertEqual(wp["defender_sig_age_days"], 5)
        self.assertEqual(wp["wu_service"], "Running")

    def test_realtime_true_survives(self):
        wp = self._beat_with_posture({"defender_realtime": True})
        self.assertIs(wp["defender_realtime"], True)

    def test_non_dict_posture_is_ignored_not_crashed(self):
        # A malformed agent payload must not 500 the heartbeat.
        body = {"device_id": self.dev_id, "token": "devtoken",
                "sysinfo": {"hostname": self.dev_id, "win_posture": "garbage"}}
        s, _b = self._beat(body)
        self.assertEqual(s, 200)
        dev = api.load(api.DEVICES_FILE)[self.dev_id]
        self.assertNotIn("win_posture", dev.get("sysinfo") or {})


if __name__ == "__main__":
    unittest.main()
