#!/usr/bin/env python3
"""7.5.0 agent review (NF-1): the macOS agent runs Homebrew as the account that owns it, not as root.

`_brew_path()` returns /opt/homebrew/bin/brew or /usr/local/bin/brew, both owned by the account that installed Homebrew. The daemon
runs as root and ran `brew outdated` and `brew upgrade` as root, so a process running as that account could rewrite the script and
be root at the next patch check (and Homebrew refuses to run as root, so the feature probably never worked there). The child now takes
the owner's uid, the file's group, a small environment and none of root's supplementary groups.

Run on Linux: the daemon's euid, the owner and subprocess.run are stood in for, and what is asserted is what reaches subprocess.run.
`RP_TEST_MAC_AGENT` points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import importlib.machinery
import importlib.util
import os
import pwd
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-brew-"))
ROOT = Path(__file__).resolve().parent.parent
MAC = Path(os.environ.get("RP_TEST_MAC_AGENT") or ROOT / "client" / "remotepower-agent-mac.py")


def load():
    loader = importlib.machinery.SourceFileLoader("agent_v750_brew", str(MAC))
    spec = importlib.util.spec_from_loader("agent_v750_brew", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load()
ME = os.getuid()
MY_GID = os.getgid()


class _Run:
    """Records the keywords subprocess.run was called with."""

    def __init__(self, stdout="{}"):
        self.calls = []
        self.stdout = stdout

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        return types.SimpleNamespace(returncode=0, stdout=self.stdout, stderr="")


class _Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="rp-v750-brewbin-")
        self.addCleanup(self.td.cleanup)
        self.brew = Path(self.td.name) / "brew"
        self.brew.write_text("#!/bin/sh\necho ok\n")
        self.sub = _Run()
        for target, value in (("_brew_path", lambda: str(self.brew)), ("_audit_mode", lambda: False),
                              ("_require_signed_commands_mac", lambda: False)):
            p = mock.patch.object(agent, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(agent.subprocess, "run", self.sub)
        p.start()
        self.addCleanup(p.stop)

    def as_root(self, owner_uid=None, owner_gid=None):
        """The daemon is root; the brew file belongs to owner_uid (this account when not given)."""
        st = os.stat_result((0o100755, 1, 1, 1, ME if owner_uid is None else owner_uid,
                             MY_GID if owner_gid is None else owner_gid, 10, 0, 0, 0))
        for patch in (mock.patch.object(agent.os, "geteuid", lambda: 0),
                      mock.patch.object(agent.os, "stat", lambda p, *a, **k: st)):
            patch.start()
            self.addCleanup(patch.stop)


class TestTheKeywords(_Base):

    def test_root_daemon_and_a_user_owned_brew_drops_to_the_owner(self):
        if ME == 0:
            self.skipTest("this test needs a non-root account to stand in for the Homebrew user")
        self.as_root()
        kw = agent._brew_run_kwargs(str(self.brew))
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (ME, MY_GID, [MY_GID]))
        env = kw["env"]
        self.assertEqual(env["HOME"], pwd.getpwuid(ME).pw_dir)
        self.assertEqual(env["USER"], pwd.getpwuid(ME).pw_name)
        self.assertIn("/opt/homebrew/bin", env["PATH"])
        self.assertEqual(env["HOMEBREW_NO_ANALYTICS"], "1")
        self.assertNotIn("SUDO_USER", env)

    def test_a_root_owned_brew_needs_no_change(self):
        self.as_root(owner_uid=0)
        self.assertEqual(agent._brew_run_kwargs(str(self.brew)), {})

    def test_a_daemon_that_is_not_root_changes_nothing(self):
        with mock.patch.object(agent.os, "geteuid", lambda: 501):
            self.assertEqual(agent._brew_run_kwargs(str(self.brew)), {})

    def test_an_owner_that_cannot_be_found_is_not_run_as_root(self):
        self.as_root(owner_uid=2_000_000_123)                                  # no such account
        self.assertIsNone(agent._brew_run_kwargs(str(self.brew)))

    def test_a_brew_that_cannot_be_looked_at_is_not_run_as_root(self):
        with mock.patch.object(agent.os, "geteuid", lambda: 0), \
                mock.patch.object(agent.os, "stat", mock.Mock(side_effect=OSError("gone"))):
            self.assertIsNone(agent._brew_run_kwargs("/no/such/brew"))

    def test_python_without_user_support_is_not_run_as_root(self):
        self.as_root()
        with mock.patch.object(agent.sys, "version_info", (3, 8, 0)):
            self.assertIsNone(agent._brew_run_kwargs(str(self.brew)))


class TestWhatReachesSubprocess(_Base):

    def test_outdated_runs_as_the_owner(self):
        if ME == 0:
            self.skipTest("needs a non-root account")
        self.as_root()
        agent.brew_outdated()
        argv, kw = self.sub.calls[-1]
        self.assertEqual(argv[:3], [str(self.brew), "outdated", "--formula"])
        self.assertEqual((kw["user"], kw["group"]), (ME, MY_GID))
        self.assertEqual(kw["env"]["HOME"], pwd.getpwuid(ME).pw_dir)

    def test_an_upgrade_command_runs_as_the_owner(self):
        if ME == 0:
            self.skipTest("needs a non-root account")
        self.as_root()
        out = agent.handle_command("upgrade:wget")
        self.assertEqual(out["rc"], 0, out)
        argv, kw = self.sub.calls[-1]
        self.assertEqual(argv, [str(self.brew), "upgrade", "--formula", "wget"])
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (ME, MY_GID, [MY_GID]))

    def test_an_owner_that_cannot_be_found_runs_nothing_and_says_so(self):
        self.as_root(owner_uid=2_000_000_123)
        out = agent.handle_command("upgrade")
        self.assertEqual(out["rc"], 1)
        self.assertIn("not run as root", out["output"])
        self.assertEqual(self.sub.calls, [])
        self.assertIsNone(agent.brew_outdated())
        self.assertEqual(self.sub.calls, [])

    def test_other_commands_are_not_touched(self):
        """exec: and the rest keep running as they did; only Homebrew changes account."""
        self.as_root()
        out = agent.handle_command("exec:echo hi")
        argv, kw = self.sub.calls[-1]
        self.assertNotIn("user", kw)
        self.assertNotIn("env", kw)
        self.assertEqual(out["rc"], 0)

    def test_a_root_daemon_with_a_root_owned_brew_runs_it_as_before(self):
        self.as_root(owner_uid=0)
        agent.handle_command("upgrade")
        _argv, kw = self.sub.calls[-1]
        self.assertNotIn("user", kw)


class TestTheDocs(unittest.TestCase):
    def test_the_agent_guide_says_who_runs_homebrew(self):
        doc = (ROOT / "docs" / "agent-commands.md").read_text()
        self.assertIn("starts Homebrew", doc)
        self.assertIn("the account that owns Homebrew", doc)


if __name__ == "__main__":
    unittest.main()
