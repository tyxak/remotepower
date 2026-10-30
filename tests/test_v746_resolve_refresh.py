#!/usr/bin/env python3
"""7.4.6, issue #56: resolving an alert by hand makes the host report again at once.

"A boot-time failed unit raised an alert; resolving the alert closed it, but Needs attention kept listing
the failed unit until the agent's next collection, minutes after the unit had been cleared on the host."

Needs attention and Checks read the last report of the host, and an agent sends the heavy part of it (the
system information) every ten polls. Resolving an alert by hand now leaves a one-shot request on the host,
the next heartbeat answer carries it, and the agent sends its system information on its next beat.

Held here, through the real functions:
  * the two handlers that resolve by hand leave the request, and only for what they resolved;
  * the heartbeat answers it once and clears it;
  * the recovery that closes an alert on its own does not ask (the host just told us);
  * a host with no agent, a host that is gone and an alert nobody may touch are left alone;
  * the three agents read the answer.
"""
import ast
import importlib.util
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def alert(alert_id, device_id=DEV, event="failed_unit", resolved=False):
    a = {"id": alert_id, "event": event, "device_id": device_id, "severity": "high", "title": "t", "ts": 1,
         "payload": {"device_id": device_id}}
    if resolved:
        a["resolved_at"] = 5
    return a


class _Resolve(_Base):

    def setUp(self):
        super().setUp()
        self._saved = {n: getattr(api, n) for n in ("verify_token", "get_token_from_request", "method", "get_json_body",
                                                    "audit_log", "_alert_mutable_by_caller", "_close_external_tickets")}
        api.verify_token = lambda t: ("jakob", "admin")
        api.get_token_from_request = lambda: "t"
        api.method = lambda: "POST"
        api.get_json_body = lambda: {}
        api.audit_log = lambda *a, **k: None
        api._close_external_tickets = lambda *a, **k: None
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs["d2"] = {"id": "d2", "name": "second", "token": "tok2", "last_seen": int(time.time()), "sysinfo": {}}
            devs["gone-agent"] = {"id": "gone-agent", "name": "ping box", "agentless": True, "sysinfo": {}}
        api.save(api.ALERTS_FILE, {"alerts": [alert("a1"), alert("a2", "d2"), alert("a3", ""), alert("a4", "gone-agent"),
                                              alert("a5", "deleted-host"), alert("a6", resolved=True)]})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.DEVICES_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        super().tearDown()

    def resolve(self, alert_id):
        try:
            api.handle_alert_resolve(alert_id)
        except _Captured as c:
            return c.status
        self.fail("no answer")

    def bulk(self, ids):
        api.get_json_body = lambda: {"ids": ids}
        try:
            api.handle_alerts_bulk_resolve()
        except _Captured as c:
            return c.status
        self.fail("no answer")

    def requested(self):
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE) or {}
        return sorted(k for k, v in devs.items() if v.get("force_sysinfo"))

    def heartbeat(self):
        """One heartbeat of the host, through the real handler: the request functions the alert handlers
        needed stubbed are put back for it, since a host signs in with its own token and body."""
        raw = json.dumps({"device_id": DEV, "token": "tok"}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        stubs = {n: getattr(api, n) for n in ("verify_token", "get_token_from_request", "method", "get_json_body")}
        for n in stubs:
            setattr(api, n, self._saved[n])
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return c.body
        finally:
            for n, v in stubs.items():
                setattr(api, n, v)
        self.fail("the heartbeat did not answer")


class TestResolvingByHand(_Resolve):

    def test_resolving_one_alert_asks_its_host_to_report(self):
        self.assertEqual(self.resolve("a1"), 200)
        self.assertEqual(self.requested(), [DEV])

    def test_only_the_host_of_the_alert_is_asked(self):
        self.resolve("a1")
        self.assertNotIn("d2", self.requested())

    def test_resolving_in_bulk_asks_each_host_once_and_only_those(self):
        self.assertEqual(self.bulk(["a1", "a2", "a3", "nope"]), 200)
        self.assertEqual(self.requested(), [DEV, "d2"])

    def test_an_alert_that_was_already_resolved_asks_nothing(self):
        self.assertEqual(self.resolve("a6"), 409)
        self.assertEqual(self.requested(), [])
        self.assertEqual(self.bulk(["a6"]), 200)
        self.assertEqual(self.requested(), [])

    def test_an_alert_the_caller_may_not_touch_asks_nothing(self):
        api._alert_mutable_by_caller = lambda a: False
        self.assertEqual(self.resolve("a1"), 404)
        self.bulk(["a1", "a2"])
        self.assertEqual(self.requested(), [])

    def test_an_alert_with_no_host_is_resolved_and_asks_nothing(self):
        self.assertEqual(self.resolve("a3"), 200)
        self.assertEqual(self.requested(), [])

    def test_a_host_with_no_agent_is_not_asked(self):
        """There is nobody to ask: a ping-only host has no agent to send anything."""
        self.assertEqual(self.resolve("a4"), 200)
        self.assertEqual(self.requested(), [])

    def test_a_host_that_is_gone_is_not_made_up(self):
        self.assertEqual(self.resolve("a5"), 200)
        api._LOAD_CACHE.clear()
        self.assertNotIn("deleted-host", api.load(api.DEVICES_FILE) or {})

    def test_asking_again_within_two_minutes_does_not_repeat_the_request(self):
        """A person who flips an alert resolved and reopened must not make a host collect on every beat."""
        self.resolve("a1")
        self.heartbeat()                                  # the answer is delivered and the request cleared
        self.assertEqual(self.requested(), [])
        api.save(api.ALERTS_FILE, {"alerts": [alert("a1")]})
        api._LOAD_CACHE.clear()
        self.resolve("a1")
        self.assertEqual(self.requested(), [], "a second request inside the cool-down")

    def test_the_cool_down_ends(self):
        self.resolve("a1")
        self.heartbeat()
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["sysinfo_forced_at"] = int(time.time()) - 3600
        api.save(api.ALERTS_FILE, {"alerts": [alert("a1")]})
        api._LOAD_CACHE.clear()
        self.resolve("a1")
        self.assertEqual(self.requested(), [DEV])


class TestTheHeartbeatAnswersOnce(_Resolve):

    def test_the_answer_carries_the_request_and_clears_it(self):
        self.resolve("a1")
        self.assertIs(self.heartbeat().get("force_sysinfo"), True)
        self.assertEqual(self.requested(), [])
        self.assertNotIn("force_sysinfo", self.heartbeat())

    def test_a_host_nobody_asked_is_not_told_to_report(self):
        self.assertNotIn("force_sysinfo", self.heartbeat())


class TestOnlyTheTwoManualPathsAsk(unittest.TestCase):
    """The recovery that closes an alert by itself must not ask: the host has just told us. So the request is
    made from the two handlers that resolve by hand, and from nowhere else."""

    def test_who_asks(self):
        tree = ast.parse((ROOT / "server/cgi-bin/api.py").read_text())
        callers = sorted(
            fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef)
            and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_request_host_refresh"
                    for n in ast.walk(fn)) and fn.name != "_request_host_refresh")
        self.assertEqual(callers, ["handle_alert_resolve", "handle_alerts_bulk_resolve"])


def _load(fname, modname):
    spec = importlib.util.spec_from_file_location(modname, ROOT / "client" / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _ReadsTheAnswer:
    agent = None

    def test_the_answer_makes_the_next_beat_carry_system_information(self):
        a = self.agent
        a._force_sysinfo = False
        creds = {"device_id": "d1", "token": "t", "server_url": "http://localhost:0"}
        self.assertNotIn("sysinfo", a.build_heartbeat(creds, poll_count=5), "cadence assumption changed")
        orig = a._post_json
        a._post_json = lambda url, payload, **k: {"force_sysinfo": True}
        try:
            a.heartbeat_once(creds, poll_count=5)
        finally:
            a._post_json = orig
        self.assertTrue(a._force_sysinfo)
        self.assertIn("sysinfo", a.build_heartbeat(creds, poll_count=5))
        self.assertFalse(a._force_sysinfo, "one-shot")

    def test_an_answer_without_it_leaves_the_flag_alone(self):
        a = self.agent
        a._force_sysinfo = False
        creds = {"device_id": "d1", "token": "t", "server_url": "http://localhost:0"}
        orig = a._post_json
        a._post_json = lambda url, payload, **k: {}
        try:
            a.heartbeat_once(creds, poll_count=5)
        finally:
            a._post_json = orig
        self.assertFalse(a._force_sysinfo)


class TestTheMacAgent(_ReadsTheAnswer, unittest.TestCase):
    agent = _load("remotepower-agent-mac.py", "rp_mac_v746_refresh")


class TestTheWindowsAgent(_ReadsTheAnswer, unittest.TestCase):
    agent = _load("remotepower-agent-win.py", "rp_win_v746_refresh")


class TestTheLinuxAgent(unittest.TestCase):
    """The Linux poll loop is too large to run here, so this reads its syntax: the branch for the answer sets
    the flag that makes the next beat send its system information."""

    def test_the_answer_sets_the_flag_that_forces_the_report(self):
        tree = ast.parse((ROOT / "client/remotepower-agent.py").read_text())
        sets = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and "force_sysinfo" in ast.unparse(node.test) and ".get" in ast.unparse(node.test):
                sets += [t.id for n in node.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)]
        self.assertEqual(sets, ["_FORCE_CHECK_EVAL"])

    def test_the_flag_is_the_one_the_beat_reads(self):
        src = (ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn("or _FORCE_CHECK_EVAL)", src)


if __name__ == "__main__":
    unittest.main()
