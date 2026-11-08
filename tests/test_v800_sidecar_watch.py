#!/usr/bin/env python3
"""8.0.0: the sidecar watcher also watches the agent push channel, the SSH gateway and the web terminal.

`run_sidecar_watch_if_due` alerted when an enabled syslog receiver, flow receiver or KMIP key server had stopped, and nothing else: the push channel and the SSH gateway had a row on Server status
and no event, so a daemon that died left the feature silently off, and the web terminal had no word at all. The two with a switch (the push channel's `push_enabled`, the `sshgw` module) are
watched when the switch is on, like the others. The web terminal has no switch to read, and a unit that was never installed answers `inactive` for ever, which is not a fault, so it is watched once
it has been seen running. Nothing changes for what was watched before, and a write of the state file happens only when something moved.

Driven through the real sweep with `systemctl` answered by a table, as tests/test_v642_control_plane_health.py does for the first three.
"""
import importlib.util
import os
import shutil as _real_shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sidecar800-"))
ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_SPEC = importlib.util.spec_from_file_location("api_sidecar800", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(api)


class _ShutilProxy:
    """Only `which` is stubbed: api.shutil is also used for copy2 in the save path."""

    def __init__(self, which_result):
        self._w = which_result

    def __getattr__(self, n):
        return getattr(_real_shutil, n)

    def which(self, x):
        return self._w


class _Base(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="rp-sc800-"))
        self._files = {n: getattr(api, n) for n in ("CONFIG_FILE", "KMIP_FILE", "INBOUND_WEBHOOKS_FILE", "SIDECAR_STATE_FILE")}
        for n, v in self._files.items():
            setattr(api, n, d / v.name)           # the product's own file names: the basename is the storage key
        self._saved = {k: getattr(api, k) for k in ("fire_webhook", "get_server_name", "shutil", "subprocess")}
        self.fired, self.calls = [], []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api.get_server_name = lambda: "rp"
        api.shutil = _ShutilProxy("/usr/bin/systemctl")
        self.status = {}

        class _R:
            def __init__(s, o):
                s.stdout = o

        def run(cmd, **k):
            self.calls.append(cmd[-1])
            return _R(self.status.get(cmd[-1], "inactive"))

        api.subprocess = type("P", (), {"run": staticmethod(run)})()
        api.save(api.CONFIG_FILE, {})
        api.save(api.KMIP_FILE, {})
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": []})
        api.save(api.SIDECAR_STATE_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)
        for n, v in self._files.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def configure(self, **cfg):
        c = api.load(api.CONFIG_FILE) or {}
        c.update(cfg)
        api.save(api.CONFIG_FILE, c)
        api._LOAD_CACHE.clear()

    def sweep(self):
        self.fired.clear()
        self.calls.clear()
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["last_sidecar_watch"] = 0
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.run_sidecar_watch_if_due()
        return [(e, p.get("unit")) for e, p in self.fired]


class TestThePushChannelAndTheSshGatewayAreWatchedWhenSwitchedOn(_Base):
    def test_a_dead_push_daemon_fires_when_the_channel_is_on(self):
        self.configure(push_enabled=True)
        self.status["remotepower-push"] = "failed"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-push")])

    def test_a_dead_push_daemon_is_silent_when_the_channel_is_off(self):
        self.status["remotepower-push"] = "failed"
        self.assertEqual(self.sweep(), [])
        self.assertNotIn("remotepower-push", self.calls, "not even asked")

    def test_a_dead_ssh_gateway_fires_when_the_module_is_on(self):
        self.configure(sshgw_enabled=True)
        self.status["remotepower-sshgw"] = "inactive"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-sshgw")])

    def test_a_dead_ssh_gateway_is_silent_when_the_module_is_off(self):
        self.status["remotepower-sshgw"] = "failed"
        self.assertEqual(self.sweep(), [])
        self.assertNotIn("remotepower-sshgw", self.calls)

    def test_a_running_one_is_silent(self):
        self.configure(push_enabled=True, sshgw_enabled=True)
        self.status.update({"remotepower-push": "active", "remotepower-sshgw": "active"})
        self.assertEqual(self.sweep(), [])

    def test_each_is_edge_triggered_and_recovers_on_its_own(self):
        self.configure(push_enabled=True, sshgw_enabled=True)
        self.status.update({"remotepower-push": "failed", "remotepower-sshgw": "active"})
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-push")])
        self.assertEqual(self.sweep(), [], "still down: said once")
        self.status["remotepower-sshgw"] = "failed"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-sshgw")])
        self.status["remotepower-push"] = "active"
        self.assertEqual(self.sweep(), [("sidecar_recovered", "remotepower-push")])

    def test_a_restart_is_not_a_failure(self):
        self.configure(push_enabled=True, sshgw_enabled=True)
        for st in ("activating", "deactivating", "unknown", ""):
            with self.subTest(status=st):
                api.save(api.SIDECAR_STATE_FILE, {})
                api._LOAD_CACHE.clear()
                self.status.update({"remotepower-push": st, "remotepower-sshgw": st})
                self.assertEqual(self.sweep(), [])

    def test_the_payload_names_the_unit_and_what_it_serves(self):
        self.configure(push_enabled=True)
        self.status["remotepower-push"] = "failed"
        self.sweep()
        ev, payload = self.fired[0]
        self.assertEqual((ev, payload["unit"]), ("sidecar_down", "remotepower-push"))
        self.assertIn("agent push channel", payload["detail"])


class TestTheWebTerminalIsWatchedOnceItHasBeenSeen(_Base):
    def test_a_unit_that_was_never_running_is_not_a_fault(self):
        self.status["remotepower-webterm"] = "inactive"
        self.assertEqual(self.sweep(), [])
        self.assertEqual(self.sweep(), [])

    def test_it_is_asked_about_even_when_nothing_else_is_enabled(self):
        self.status["remotepower-webterm"] = "inactive"
        self.sweep()
        self.assertEqual(self.calls, ["remotepower-webterm"])

    def test_once_seen_running_a_dead_state_is_reported_and_then_the_recovery(self):
        self.status["remotepower-webterm"] = "active"
        self.assertEqual(self.sweep(), [])
        self.status["remotepower-webterm"] = "failed"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-webterm")])
        self.assertEqual(self.sweep(), [], "said once")
        self.status["remotepower-webterm"] = "active"
        self.assertEqual(self.sweep(), [("sidecar_recovered", "remotepower-webterm")])

    def test_seen_is_remembered_across_sweeps(self):
        self.status["remotepower-webterm"] = "active"
        self.sweep()
        self.assertTrue((api.load(api.SIDECAR_STATE_FILE) or {}).get("seen", {}).get("remotepower-webterm"))
        self.status["remotepower-webterm"] = "inactive"
        self.assertEqual(self.sweep(), [("sidecar_down", "remotepower-webterm")])

    def test_a_restart_of_a_seen_unit_is_not_a_failure(self):
        self.status["remotepower-webterm"] = "active"
        self.sweep()
        for st in ("activating", "deactivating", "unknown", ""):
            with self.subTest(status=st):
                self.status["remotepower-webterm"] = st
                self.assertEqual(self.sweep(), [])

    def test_no_systemd_means_no_opinion_on_any_of_them(self):
        self.configure(push_enabled=True, sshgw_enabled=True)
        api.shutil = _ShutilProxy(None)
        self.status.update({"remotepower-push": "failed", "remotepower-sshgw": "failed", "remotepower-webterm": "failed"})
        self.assertEqual(self.sweep(), [])
        self.assertEqual(self.calls, [])


class TestWhatWasWatchedBeforeIsUnchanged(_Base):
    def test_kmip_syslog_and_flow_still_fire(self):
        api.save(api.KMIP_FILE, {"enabled": True})
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": [{"kind": "syslog"}, {"kind": "flow"}]})
        api._LOAD_CACHE.clear()
        self.status.update({"remotepower-kmipd": "failed", "remotepower-syslogd": "failed", "remotepower-flowd": "active"})
        self.assertEqual(sorted(self.sweep()), [("sidecar_down", "remotepower-kmipd"), ("sidecar_down", "remotepower-syslogd")])

    def test_nothing_on_means_one_question_and_no_write(self):
        before = api.load(api.SIDECAR_STATE_FILE)
        writes = []
        real_save = api.save
        api.save = lambda path, *a, **k: (writes.append(Path(path).name), real_save(path, *a, **k))[1]
        try:
            self.sweep()
        finally:
            api.save = real_save
        self.assertEqual(self.calls, ["remotepower-webterm"])
        self.assertEqual(api.load(api.SIDECAR_STATE_FILE), before, "a quiet install keeps a quiet state file")
        self.assertNotIn(api.SIDECAR_STATE_FILE.name, [n for n in writes], "and does not write it")

    def test_a_second_quiet_sweep_with_a_gateway_running_writes_nothing_either(self):
        self.configure(sshgw_enabled=True)
        self.status["remotepower-sshgw"] = "active"
        self.sweep()
        writes = []
        real_save = api.save
        api.save = lambda path, *a, **k: (writes.append(Path(path).name), real_save(path, *a, **k))[1]
        try:
            self.sweep()
        finally:
            api.save = real_save
        self.assertNotIn(api.SIDECAR_STATE_FILE.name, writes)


if __name__ == "__main__":
    unittest.main()
