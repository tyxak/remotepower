#!/usr/bin/env python3
"""7.5.0 agent review: the host-probe channel honours `require-signed-commands`.

The monitors a server assigns to a host ride the heartbeat answer as a setting. A probe opens a connection, or starts ping, to an
address the server names, from this host's network. The channel asked for observe-only mode when it was written (7.4.9) and not for
the other flag an operator sets to say the server's word is not enough. Canary files, backup verification and the restore drill got
that in 7.4.9 (`_refuse_unsigned_channel`); this one arrived after the list was written and was not on it.

RP_TEST_AGENT points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name="agent_v750_probes"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()

SPEC = {"label": "db", "type": "tcp", "target": "10.0.0.5:5432"}


class TestHostProbesAndSignedCommands(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-probe-")
        self.addCleanup(self._td.cleanup)
        self.flag = Path(self._td.name) / "require-signed-commands"
        for target, value in (("REQUIRE_SIGNED_CMDS_FILE", self.flag), ("_audit_mode", lambda: False)):
            p = mock.patch.object(agent, target, value)
            p.start()
            self.addCleanup(p.stop)
        agent._REFUSED_UNSIGNED.clear()
        agent._PROBE.update({"specs": [], "interval": 300, "next": 0.0, "running": False})
        with agent._PROBE_LOCK:
            agent._PROBE_OUTBOX.clear()

    def test_control_without_the_flag_the_assignment_is_taken(self):
        agent._probe_update([SPEC], 300)
        self.assertEqual([s["label"] for s in agent._PROBE["specs"]], ["db"])

    def test_with_the_flag_the_assignment_is_refused(self):
        self.flag.write_text("")
        agent._probe_update([SPEC], 300)
        self.assertEqual(agent._PROBE["specs"], [], "a host that asks for signed commands took monitors from an unsigned setting")

    def test_with_the_flag_monitors_taken_earlier_are_dropped_and_their_results_forgotten(self):
        agent._probe_update([SPEC], 300)
        with agent._PROBE_LOCK:
            agent._PROBE_OUTBOX.append({"label": "db", "ok": True})
        self.flag.write_text("")                       # the operator sets the flag while the agent runs
        agent._probe_update([SPEC], 300)
        self.assertEqual(agent._PROBE["specs"], [])
        self.assertEqual(agent._probe_take(), [])

    def test_the_flag_set_after_the_assignment_stops_the_run_that_was_due(self):
        agent._probe_update([SPEC], 300)
        self.flag.write_text("")
        started = []
        with mock.patch.object(agent.threading, "Thread", lambda *a, **k: started.append(1) or mock.Mock()):
            agent._probe_tick()
        self.assertEqual(started, [], "a due run of probes started on a host that wants signed commands")
        self.assertFalse(agent._PROBE["running"])

    def test_control_a_due_run_starts_without_the_flag(self):
        agent._probe_update([SPEC], 300)
        started = []
        with mock.patch.object(agent.threading, "Thread", lambda *a, **k: started.append(1) or mock.Mock()):
            agent._probe_tick()
        self.assertEqual(started, [1])
        agent._PROBE["running"] = False

    def test_the_refusal_is_logged_once_not_on_every_poll(self):
        self.flag.write_text("")
        with mock.patch.object(agent.log, "error") as err:
            for _ in range(5):
                agent._probe_update([SPEC], 300)
        self.assertEqual(err.call_count, 1)
        self.assertIn("host probes", " ".join(str(a) for a in err.call_args[0]))


if __name__ == "__main__":
    unittest.main()
