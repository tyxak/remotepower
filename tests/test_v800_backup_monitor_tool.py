#!/usr/bin/env python3
"""8.0.0: a backup monitor that asks for an integrity check and names no tool says so.

`collect_backup_verify` took the tool from the monitor's hint, or by looking in the path for restic, borg or a tar file name, and went on to the next monitor when it found none. A monitor with
Verify integrity ticked and the tool left on `auto`, on a path such as /srv/nightly, therefore checked nothing and showed nothing, for ever: the one control the operator had asked for was off
without a word. The agent now reports `no_tool` once per interval, in the record every other result uses, and the host drawer shows it in amber with the reason. It is a setting to fix, not an
incident, so it does not alert (the same class as `tool_missing` and `invalid_path`).

Driven through the real function, with the agent's state store replaced by a dictionary and the clock held.
"""
import importlib.machinery
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_loader = importlib.machinery.SourceFileLoader("agent_backup_tool", str(ROOT / "client" / "remotepower-agent.py"))
_spec = importlib.util.spec_from_loader("agent_backup_tool", _loader)
agent = importlib.util.module_from_spec(_spec)
_loader.exec_module(agent)

NOW = 1_800_000_000
WEEK = 168 * 3600


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = {}
        self.clock = [NOW]
        self._patches = [
            patch.object(agent, "_audit_mode", return_value=False),
            patch.object(agent, "_refuse_unsigned_channel", return_value=False),
            patch.object(agent, "_safe_state_read", side_effect=lambda name: self.store.get(name)),
            patch.object(agent, "_safe_state_write", side_effect=lambda name, text: self.store.__setitem__(name, text)),
            patch.object(agent, "_which", return_value=None),
            patch.object(agent.time, "time", side_effect=lambda: self.clock[0]),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self._patches)])

    def run_checks(self, *monitors):
        return agent.collect_backup_verify(list(monitors))

    @staticmethod
    def mon(path, **extra):
        return dict({"path": path, "verify_enabled": True}, **extra)


class TestAMonitorThatNamesNoTool(_Base):
    def test_auto_on_a_path_that_names_no_tool_is_reported(self):
        out = self.run_checks(self.mon("/srv/nightly", tool="auto"))
        self.assertEqual(len(out), 1, out)
        self.assertEqual((out[0]["path"], out[0]["tool"], out[0]["verify_status"], out[0]["verify_at"]), ("/srv/nightly", "", "no_tool", NOW))
        self.assertIn("names no backup tool", out[0]["verify_output"])

    def test_no_tool_given_at_all_is_the_same_as_auto(self):
        out = self.run_checks(self.mon("/srv/nightly"))
        self.assertEqual([r["verify_status"] for r in out], ["no_tool"])

    def test_it_is_reported_once_per_interval_like_any_other_result(self):
        self.assertEqual(len(self.run_checks(self.mon("/srv/nightly"))), 1)
        self.clock[0] = NOW + WEEK - 1
        self.assertEqual(self.run_checks(self.mon("/srv/nightly")), [], "still inside the week")
        self.clock[0] = NOW + WEEK
        self.assertEqual([r["verify_status"] for r in self.run_checks(self.mon("/srv/nightly"))], ["no_tool"])
        self.assertEqual(json.loads(self.store[agent._BACKUP_VERIFY_STATE])["/srv/nightly"], NOW + WEEK)

    def test_the_interval_is_the_monitors_own(self):
        self.run_checks(self.mon("/srv/nightly", verify_max_age_hours=2))
        self.clock[0] = NOW + 2 * 3600 - 1
        self.assertEqual(self.run_checks(self.mon("/srv/nightly", verify_max_age_hours=2)), [])
        self.clock[0] = NOW + 2 * 3600
        self.assertEqual(len(self.run_checks(self.mon("/srv/nightly", verify_max_age_hours=2))), 1)

    def test_each_path_is_judged_on_its_own(self):
        out = self.run_checks(self.mon("/srv/nightly"), self.mon("/srv/restic-main"), self.mon("/srv/other"))
        self.assertEqual({r["path"]: r["verify_status"] for r in out}, {"/srv/nightly": "no_tool", "/srv/restic-main": "tool_missing", "/srv/other": "no_tool"})


class TestWhatIsNotThatCase(_Base):
    def test_an_explicit_tool_wins_over_the_path_and_goes_on_to_the_check(self):
        out = self.run_checks(self.mon("/srv/nightly", tool="restic"))
        self.assertEqual([(r["tool"], r["verify_status"]) for r in out], [("restic", "tool_missing")], "the tool was named: not a no_tool case")

    def test_a_path_that_names_the_tool_is_not_one_either(self):
        for path, tool in (("/srv/restic-main", "restic"), ("/srv/borg-repo", "borg"), ("/srv/set.tar.gz", "tar")):
            self.store.clear()
            out = self.run_checks(self.mon(path))
            self.assertEqual([(r["tool"], r["verify_status"]) for r in out], [(tool, "tool_missing")], path)

    def test_a_monitor_that_does_not_ask_for_verification_is_left_alone(self):
        self.assertEqual(self.run_checks({"path": "/srv/nightly", "verify_enabled": False}), [])
        self.assertEqual(self.store, {})

    def test_a_path_the_agent_cannot_use_keeps_the_status_it_always_had(self):
        out = self.run_checks(self.mon("nightly"))
        self.assertEqual([r["verify_status"] for r in out], ["invalid_path"])

    def test_audit_mode_still_reports_nothing_at_all(self):
        with patch.object(agent, "_audit_mode", return_value=True):
            self.assertEqual(self.run_checks(self.mon("/srv/nightly")), [])

    def test_an_unsigned_channel_still_reports_nothing_at_all(self):
        with patch.object(agent, "_refuse_unsigned_channel", return_value=True):
            self.assertEqual(self.run_checks(self.mon("/srv/nightly")), [])


class TestTheTwoFilesOfTheAgentAgree(unittest.TestCase):
    def test_the_extensionless_copy_is_byte_identical(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
