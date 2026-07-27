#!/usr/bin/env python3
"""v6.4.1 guardrail: a macOS host's agent-side check results and drift report
must survive the real heartbeat, end to end.

The macOS agent read 13 of the heartbeat response's keys where the Linux agent
reads 48. Two of the gaps were operator-visible features that returned a success
toast and did nothing: `agent_checks` (every file/job/log custom check assigned
to a Mac reported `unknown` forever) and `watched_files` (a Mac produced no
config-drift report at all).

FUNCTIONAL on purpose. The existing coverage for this area
(`test_v420_hardening.test_custom_check_results_persisted_by_sanitizer`) greps
api.py for the string `safe_si['custom_check_results']` — false-green class #1
in CLAUDE.md: it passes whether or not the branch works, and it says nothing
about whether any agent produces the data. This test drives the whole chain:

    server picks the checks to push  (AGENT_CHECK_TYPES)
      → the real mac agent stores them   (heartbeat_once)
      → the real mac agent evaluates them (build_heartbeat)
      → the real server handler ingests   (handle_heartbeat)
      → the Checks engine reads a status  (_eval_custom_check)

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
    "rp_mac_agent_hb", _ROOT / "client" / "remotepower-agent-mac.py")
mac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mac)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class TestMacAgentChecksSurviveHeartbeat(unittest.TestCase):
    def setUp(self):
        # Own the body/verb/respond providers and restore them, so a leaked stub
        # from another module can neither break us nor leak out of us (the
        # recurring leaked-monkeypatch class).
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"

        self._agent_state = (mac._watched_agent_checks, mac._watched_files)

        def _restore_agent():
            mac._watched_agent_checks, mac._watched_files = self._agent_state
        self.addCleanup(_restore_agent)
        mac._watched_agent_checks, mac._watched_files = [], []

        self.dev_id = "mac-host-1"
        api.save(api.DEVICES_FILE, {
            self.dev_id: {
                "name": self.dev_id, "hostname": self.dev_id,
                "os": "macOS 15.2", "token": "devtoken",
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

    def _push_to_agent(self, resp):
        """Run the REAL agent response handler over a heartbeat response."""
        orig = mac._post_json
        try:
            mac._post_json = lambda *a, **k: dict(resp, ok=True)
            mac.heartbeat_once(
                {"server_url": "http://x", "device_id": self.dev_id}, 2)
        finally:
            mac._post_json = orig

    def _agent_beat(self, poll_count=1):
        """The REAL agent payload builder, posted through the REAL handler."""
        payload = mac.build_heartbeat(
            {"device_id": self.dev_id, "token": "devtoken"}, poll_count)
        body = {"device_id": self.dev_id, "token": "devtoken"}
        for k in ("sysinfo", "drift"):
            if k in payload:
                body[k] = payload[k]
        body.setdefault("sysinfo", {})["os"] = "macOS 15.2"
        status, resp = self._beat(body)
        self.assertEqual(status, 200, f"heartbeat rejected: {resp}")
        return api.load(api.DEVICES_FILE)[self.dev_id]

    # ── the chain ────────────────────────────────────────────────────────────

    def test_launchd_service_is_a_pushable_agent_check_type(self):
        # Step 1: the server only pushes types in AGENT_CHECK_TYPES. If
        # launchd_service is missing from the registry it is never delivered and
        # the whole macOS service-check feature is inert.
        self.assertIn("launchd_service", api.AGENT_CHECK_TYPES)

    def test_results_reach_the_device_record_and_the_checks_engine(self):
        defs = [
            {"id": "c-file", "type": "file_present", "param": "/etc/hosts"},
            {"id": "c-guard", "type": "dir_baseline", "param": "/var/www"},
        ]
        pushed = [c for c in defs if c["type"] in api.AGENT_CHECK_TYPES]
        self.assertEqual(len(pushed), 2)

        self._push_to_agent({"agent_checks": pushed})
        self.assertEqual([c["id"] for c in mac._watched_agent_checks],
                         ["c-file", "c-guard"])

        dev = self._agent_beat()
        ccr = (dev.get("sysinfo") or {}).get("custom_check_results") or {}
        self.assertEqual(set(ccr), {"c-file", "c-guard"},
                         "safe_si dropped the mac agent's check results")
        self.assertEqual(ccr["c-file"]["status"], "ok")

        # And the Checks engine must read that stored result back as a status.
        status, out = api._eval_custom_check(defs[0], dev)
        self.assertEqual(status, "ok", out)

    def test_unsupported_type_reports_unknown_not_a_false_alert(self):
        # A Linux-only guard type on a Mac must not read as OK (silently green)
        # nor as critical (a fake alert an operator would chase).
        self._push_to_agent({"agent_checks": [
            {"id": "c-guard", "type": "dir_baseline", "param": "/var/www"}]})
        dev = self._agent_beat()
        ccr = (dev.get("sysinfo") or {}).get("custom_check_results") or {}
        self.assertEqual(ccr["c-guard"]["status"], "unknown")
        self.assertIn("macOS", ccr["c-guard"]["output"])

    def test_status_values_all_survive_the_sanitizer_whitelist(self):
        # safe_si only keeps ok/warning/critical/unknown. Every status the mac
        # agent can emit must be in that set, or a real result is silently
        # dropped and the row reads "not yet reported" forever.
        emitted = set()
        for res in mac.eval_agent_checks([
                {"id": "a", "type": "file_present", "param": "/etc/hosts"},
                {"id": "b", "type": "file_present", "param": "/nope"},
                {"id": "c", "type": "dir_baseline", "param": "/x"},
                {"id": "d", "type": "launchd_service", "param": "bad label!"},
        ]).values():
            emitted.add(res["status"])
        self.assertTrue(emitted <= {"ok", "warning", "critical", "unknown"},
                        f"status not in the safe_si whitelist: {emitted}")

    def test_drift_report_is_ingested(self):
        self._push_to_agent({"watched_files": ["/etc/hosts"]})
        self.assertEqual(mac._watched_files, ["/etc/hosts"])
        dev = self._agent_beat(poll_count=1)
        drift = api.load(api.DRIFT_STATE_FILE) or {}
        entry = drift.get(self.dev_id) or {}
        self.assertTrue(entry, "the mac agent's drift report was not ingested")
        self.assertIn("/etc/hosts", str(entry))
        self.assertTrue(dev)

    def test_nothing_pushed_means_nothing_reported(self):
        # No checks configured must not fabricate an empty result set that would
        # overwrite a previous beat's data.
        dev = self._agent_beat(poll_count=2)
        self.assertNotIn("custom_check_results", dev.get("sysinfo") or {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
