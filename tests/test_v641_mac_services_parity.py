#!/usr/bin/env python3
"""v6.4.1 guardrail: a Mac's watched-service states must survive the real
heartbeat, end to end.

Linux and Windows both honour the heartbeat response's `services_watched` key;
the macOS agent dropped it — the server accepted the config, the Services page
showed the watch as configured, and no Mac ever reported a state (the
success-toast-then-silence class). This drives the whole chain:

    server pushes services_watched      (heartbeat response)
      → the real mac agent stores it    (heartbeat_once)
      → the real mac agent samples it   (build_heartbeat → get_services,
                                         over a faked `launchctl list` table)
      → the real server handler ingests (handle_heartbeat →
                                         process_service_report)

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

_spec = importlib.util.spec_from_file_location(
    "rp_mac_agent_svc", _ROOT / "client" / "remotepower-agent-mac.py")
mac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mac)

# What `launchctl list` prints: PID \t last-exit-status \t label. One running
# job, one crashed job, one loaded-but-idle on-demand job; the fourth watched
# label is deliberately absent (not loaded).
_LAUNCHCTL_TABLE = (
    "PID\tStatus\tLabel\n"
    "512\t0\tcom.example.web\n"
    "-\t78\tcom.example.backup\n"
    "-\t0\tcom.example.ondemand\n"
)


class _FakeLaunchctl:
    """Answers `launchctl list`; every other argv falls through to the REAL
    subprocess.run (patching mac.subprocess.run patches the shared module, and
    build_heartbeat's sysinfo collectors spawn unrelated processes)."""

    def __init__(self, real_run):
        self._real_run = real_run

    def __call__(self, argv, **kw):
        if argv[:2] == ["launchctl", "list"]:
            class R:
                stdout = _LAUNCHCTL_TABLE
                returncode = 0
            return R()
        return self._real_run(argv, **kw)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestMacServicesParity(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"

        self._agent_state = mac._watched_services

        def _restore_agent():
            mac._watched_services = self._agent_state
        self.addCleanup(_restore_agent)
        mac._watched_services = []

        self.dev_id = "mac-svc-host"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {
                "name": self.dev_id, "hostname": self.dev_id,
                "os": "macOS 15.2", "token": "devtoken",
                "last_seen": int(time.time()), "enrolled": int(time.time()),
                "tags": [], "group": "", "sysinfo": {}, "agentless": False,
            }
        })
        # Shared store reset (false-green class 4): another module's test may
        # have left service rows behind under xdist/randomly ordering.
        api.save(api.SERVICES_FILE, {})

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

    def _push_to_agent(self, resp):
        orig = mac._post_json
        try:
            mac._post_json = lambda *a, **k: dict(resp, ok=True)
            mac.heartbeat_once(
                {"server_url": "http://x", "device_id": self.dev_id}, 2)
        finally:
            mac._post_json = orig

    def _agent_beat(self, poll_count=1):
        orig_run, orig_si = mac.subprocess.run, mac.collect_sysinfo
        mac.subprocess.run = _FakeLaunchctl(orig_run)
        mac.collect_sysinfo = lambda: {"os": "macOS 15.2"}
        try:
            payload = mac.build_heartbeat(
                {"device_id": self.dev_id, "token": "devtoken"}, poll_count)
        finally:
            mac.subprocess.run, mac.collect_sysinfo = orig_run, orig_si
        body = {"device_id": self.dev_id, "token": "devtoken",
                "sysinfo": {"os": "macOS 15.2"}}
        if "services" in payload:
            body["services"] = payload["services"]
        status, resp = self._beat(body)
        self.assertEqual(status, 200, f"heartbeat rejected: {resp}")
        return payload

    # ── the chain ────────────────────────────────────────────────────────────

    def test_agent_stores_the_pushed_watch_list(self):
        self._push_to_agent(
            {"services_watched": ["com.example.web", "  ", 42, "com.example.backup"]})
        self.assertEqual(mac._watched_services,
                         ["com.example.web", "42", "com.example.backup"])

    def test_states_reach_the_services_store(self):
        self._push_to_agent({"services_watched": [
            "com.example.web", "com.example.backup",
            "com.example.ondemand", "com.example.gone"]})
        payload = self._agent_beat()
        self.assertIn("services", payload,
                      "mac build_heartbeat produced no services report")

        store = api.load(api.SERVICES_FILE) or {}
        rows = {s["unit"]: s for s in (store.get(self.dev_id) or {}).get("services", [])}
        self.assertEqual(
            set(rows), {"com.example.web", "com.example.backup",
                        "com.example.ondemand", "com.example.gone"},
            "server dropped part of the mac agent's service report")
        self.assertEqual(rows["com.example.web"]["active"], "active")
        self.assertEqual(rows["com.example.backup"]["active"], "failed")
        self.assertEqual(rows["com.example.ondemand"]["active"], "inactive")
        self.assertEqual(rows["com.example.gone"]["active"], "inactive")
        self.assertEqual(rows["com.example.gone"]["sub"], "not loaded")

    def test_every_emitted_entry_survives_the_server_sanitizer(self):
        # The dead-signal lesson: compare what the agent PRODUCES against what
        # the server KEEPS — a shape mismatch is silently dropped, not errored.
        orig_run = mac.subprocess.run
        mac.subprocess.run = _FakeLaunchctl(orig_run)
        try:
            entries = mac.get_services(
                ["com.example.web", "com.example.backup",
                 "com.example.ondemand", "com.example.gone"])
        finally:
            mac.subprocess.run = orig_run
        self.assertEqual(len(entries), 4)
        for e in entries:
            kept = api._sanitize_service_entry(e)
            self.assertIsNotNone(kept, f"sanitizer rejected {e}")
            self.assertEqual(kept["unit"], e["unit"])
            self.assertEqual(kept["active"], e["active"])
            # sub is bounded to 32 chars server-side; the agent must not rely
            # on longer text to convey the state.
            self.assertLessEqual(len(e["sub"]), 32)

    def test_cadence_matches_windows_not_every_beat(self):
        self._push_to_agent({"services_watched": ["com.example.web"]})
        orig_run, orig_si = mac.subprocess.run, mac.collect_sysinfo
        mac.subprocess.run = _FakeLaunchctl(orig_run)
        mac.collect_sysinfo = lambda: {"os": "macOS 15.2"}
        try:
            off_cadence = mac.build_heartbeat(
                {"device_id": self.dev_id, "token": "devtoken"}, 5)
        finally:
            mac.subprocess.run, mac.collect_sysinfo = orig_run, orig_si
        self.assertNotIn("services", off_cadence)

    def test_launchctl_failure_degrades_to_unknown_not_a_crash(self):
        def boom(argv, **kw):
            raise OSError("launchctl missing")
        orig_run = mac.subprocess.run
        mac.subprocess.run = boom
        try:
            entries = mac.get_services(["com.example.web"])
        finally:
            mac.subprocess.run = orig_run
        self.assertEqual(entries,
                         [{"unit": "com.example.web", "active": "unknown",
                           "sub": "", "since": 0}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
