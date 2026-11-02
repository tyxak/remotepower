#!/usr/bin/env python3
"""The Linux agent items of the 7.4.9 agent review that were listed as lower severity and are now closed (U1 to U5).

* U1  a canary decoy in a directory a user owns could be redirected by a link: `~/.aws` made a link to `/etc/sudoers.d`, and root
      then created a 0600 file there that sudo refuses to start on. The directory is resolved first, the location rule is applied to
      where the file would really land, and the file is created without following a link at the leaf.
* U2  the file manager opened a FIFO at the path and waited for ever, and a file it wrote became root's 0600 whatever it had been.
* U3  `dir_baseline` counted only matching files, so a tree of millions of empty directories kept the poll loop busy.
* U4  the downgrade guard trusted the version the server advertises, and a forced upgrade skipped it. With a release key pinned, a
      signed release older than the running agent is now refused, by the version inside the signed bytes.
* U5  three channels that start a process or write a file as root from a setting the server sends (canary files, backup
      verification, the restore drill) ignored `require-signed-commands`; the custom-script channel had the same hole until 6.4.3.
"""
import importlib.machinery
import importlib.util
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name="agent_channels"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()


class _Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-chan-")
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name).resolve()
        for target, value in (("_audit_mode", lambda: False), ("host_path", lambda p: p), ("unhost_path", lambda p: p)):
            patcher = mock.patch.object(agent, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.tmp / "state").mkdir()
        state = mock.patch.object(agent, "STATE_DIR", self.tmp / "state")
        state.start()
        self.addCleanup(state.stop)
        agent._canary_planted.clear()
        agent._canary_failed.clear()
        agent._REFUSED_UNSIGNED.clear()

    def signed(self, on):
        flag = self.tmp / "require-signed-commands"
        if on:
            flag.write_text("")
        p = mock.patch.object(agent, "REQUIRE_SIGNED_CMDS_FILE", flag)
        p.start()
        self.addCleanup(p.stop)


class TestCanaryThroughALinkedDirectory(_Base):
    """U1"""

    def make(self):
        home = self.tmp / "home" / "user"
        sudoers = self.tmp / "etc" / "sudoers.d"
        home.mkdir(parents=True)
        sudoers.mkdir(parents=True)
        (home / ".aws").symlink_to(sudoers)               # what the user did
        return home / ".aws" / "credentials", sudoers

    def test_a_decoy_behind_a_link_into_a_denied_directory_is_not_planted(self):
        self.signed(False)
        path, sudoers = self.make()
        agent._plant_canaries([{"path": str(path)}])
        self.assertEqual(os.listdir(sudoers), [], "root created a file where the link points")
        self.assertIn(str(path), agent._canary_failed)
        self.assertIn("resolves into", agent._canary_failed[str(path)])

    def test_control_the_same_decoy_in_a_plain_directory_is_planted(self):
        self.signed(False)
        d = self.tmp / "home" / "plain" / ".aws"
        d.mkdir(parents=True)
        agent._plant_canaries([{"path": str(d / "credentials")}])
        self.assertTrue((d / "credentials").exists())
        self.assertEqual(stat.S_IMODE((d / "credentials").stat().st_mode), 0o600)

    def test_a_link_at_the_leaf_is_not_followed(self):
        self.signed(False)
        d = self.tmp / "home" / "leaf"
        d.mkdir(parents=True)
        victim = self.tmp / "victim.txt"
        (d / "credentials").symlink_to(victim)             # dangling: exists() is False, so the open would create the victim
        agent._plant_canaries([{"path": str(d / "credentials")}])
        self.assertFalse(victim.exists())


class TestFileManagerPaths(_Base):
    """U2"""

    def op(self, op, path, content=None):
        import base64
        b64 = lambda b: base64.urlsafe_b64encode(b).decode()
        cmd = "files:%s:%s" % (op, b64(str(path).encode()))
        if content is not None:
            cmd += ":" + b64(content)
        with mock.patch.object(agent, "_file_mgr_allowed", lambda p: True):
            return agent._handle_file_op(cmd)

    def test_reading_a_fifo_answers_at_once_with_an_error(self):
        fifo = self.tmp / "pipe"
        os.mkfifo(fifo)
        out = {}
        t = threading.Thread(target=lambda: out.update(self.op("read", fifo)), daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "the agent is waiting for a writer on a FIFO")
        self.assertNotEqual(out.get("rc"), 0)

    def test_control_a_regular_file_is_read(self):
        f = self.tmp / "plain.txt"
        f.write_text("hello")
        out = self.op("read", f)
        self.assertEqual(out["rc"], 0)
        self.assertIn("hello", out["output"])

    def test_a_write_keeps_the_mode_the_file_had(self):
        f = self.tmp / "app.conf"
        f.write_text("old")
        f.chmod(0o644)
        out = self.op("write", f, b"new")
        self.assertEqual(out["rc"], 0, out)
        self.assertEqual(f.read_text(), "new")
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644, "the rename put the temporary file's 0600 on the target")

    def test_a_new_file_is_created_0600(self):
        f = self.tmp / "fresh.conf"
        self.op("write", f, b"x")
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)


class TestDirectoryBaselineBudget(_Base):
    """U3"""

    def run_check(self, root):
        return agent._eval_one_agent_check({"id": "c1", "type": "dir_baseline", "param": str(root)})

    def test_a_walk_past_its_budget_stops_with_unknown(self):
        root = self.tmp / "tree"
        (root / "a").mkdir(parents=True)
        (root / "a" / "f.txt").write_text("x")
        real = time.monotonic
        ticks = iter([0.0] + [100.0] * 50)
        with mock.patch.object(agent.time, "monotonic", lambda: next(ticks, real())):
            status, detail = self.run_check(root)[:2]
        self.assertEqual(status, "unknown")
        self.assertIn("too large or too slow", detail)

    def test_control_a_small_tree_is_baselined(self):
        root = self.tmp / "small"
        root.mkdir()
        (root / "f.txt").write_text("x")
        with mock.patch.object(agent, "_check_baseline_load", lambda *a, **k: (None, "")), \
                mock.patch.object(agent, "_check_baseline_save", lambda *a, **k: None):
            status = self.run_check(root)[0]
        self.assertEqual(status, "ok")


class TestSignedReleaseOlderThanTheRunningAgent(_Base):
    """U4"""

    def test_the_version_is_read_from_the_bytes(self):
        self.assertEqual(agent._embedded_version(b"#!/usr/bin/env python3\nVERSION = '7.4.2'\nimport os\n"), "7.4.2")
        self.assertEqual(agent._embedded_version(b'VERSION = "7.5.0"\n'), "7.5.0")
        self.assertEqual(agent._embedded_version(b"nothing here"), "")
        self.assertEqual(agent._embedded_version(b"# VERSION = '1.0.0'\n"), "", "a comment is not the version")

    def test_a_lower_release_is_a_downgrade_and_an_unreadable_one_is_not(self):
        self.assertTrue(agent._is_downgrade("7.4.9", "7.4.2"))
        self.assertTrue(agent._is_downgrade("7.4.9", "6.9.9"))
        self.assertFalse(agent._is_downgrade("7.4.9", "7.4.9"))
        self.assertFalse(agent._is_downgrade("7.4.9", "7.5.0"))
        self.assertFalse(agent._is_downgrade("7.4.9", ""))
        self.assertFalse(agent._is_downgrade("7.4.9", "garbage"))

    def _update(self, offered_version, allow_file):
        """check_for_update against a stub server that advertises a NEWER version but serves a signed older build."""
        data = ("VERSION = '%s'\n" % offered_version).encode()
        import hashlib
        info = {"sha256": hashlib.sha256(data).hexdigest(), "version": "9.9.9", "key_fingerprint": ""}
        dest = self.tmp / "remotepower-agent"
        dest.write_bytes(b"VERSION = '7.4.9'\n")
        allow = self.tmp / "allow-downgrade"
        if allow_file:
            allow.write_text("")
        with mock.patch.object(agent, "IN_CONTAINER", False), \
                mock.patch.object(agent, "AGENT_BINARY", dest), \
                mock.patch.object(agent, "ALLOW_DOWNGRADE_FILE", allow), \
                mock.patch.object(agent, "VERSION", "7.4.9"), \
                mock.patch.object(agent, "http_get", lambda *a, **k: info), \
                mock.patch.object(agent, "http_get_binary", lambda url, **k: data if "signature" not in url
                                  else b'{"signature": "sig"}'), \
                mock.patch.object(agent, "_release_pubkey", lambda: "PUBKEY"), \
                mock.patch.object(agent, "_verify_detached_sig", lambda *a, **k: (True, "ok")), \
                mock.patch.object(agent, "_safe_state_write", lambda *a, **k: None), \
                mock.patch.object(agent, "_safe_state_unlink", lambda *a, **k: None), \
                mock.patch.object(agent.subprocess, "Popen", lambda *a, **k: None):
            return agent.check_for_update("https://server.example", force=True), dest.read_bytes()

    def test_a_forced_upgrade_to_an_older_signed_release_is_refused(self):
        installed, content = self._update("7.4.2", allow_file=False)
        self.assertFalse(installed)
        self.assertEqual(content, b"VERSION = '7.4.9'\n", "the binary was replaced")

    def test_the_host_can_allow_a_rollback_itself(self):
        installed, content = self._update("7.4.2", allow_file=True)
        self.assertTrue(installed)
        self.assertEqual(content, b"VERSION = '7.4.2'\n")

    def test_control_a_newer_signed_release_installs(self):
        installed, content = self._update("7.5.0", allow_file=False)
        self.assertTrue(installed)
        self.assertEqual(content, b"VERSION = '7.5.0'\n")


class TestConfigDrivenChannelsHonourSignedCommands(_Base):
    """U5"""

    def test_canary_files_are_refused_when_commands_must_be_signed(self):
        self.signed(True)
        d = self.tmp / "dir"
        d.mkdir()
        agent._plant_canaries([{"path": str(d / "decoy.txt")}])
        self.assertFalse((d / "decoy.txt").exists())
        self.assertIn("refused", agent._canary_failed[str(d / "decoy.txt")])

    def test_control_without_the_flag_the_canary_is_planted(self):
        self.signed(False)
        d = self.tmp / "dir2"
        d.mkdir()
        agent._plant_canaries([{"path": str(d / "decoy.txt")}])
        self.assertTrue((d / "decoy.txt").exists())

    def test_backup_verification_and_the_restore_drill_start_nothing(self):
        self.signed(True)
        mons = [{"path": "/backups/x", "tool": "tar", "verify_enabled": True, "restore_drill_enabled": True,
                 "restore_sample_path": "etc/hosts"}]
        with mock.patch.object(agent.subprocess, "run", side_effect=AssertionError("a process was started")), \
                mock.patch.object(agent.subprocess, "Popen", side_effect=AssertionError("a process was started")):
            self.assertEqual(agent.collect_backup_verify(mons), [])
            self.assertEqual(agent.run_restore_drills(mons, now=1_800_000_000), [])

    def test_control_without_the_flag_both_do_start_a_process(self):
        self.signed(False)
        mons = [{"path": "/backups/x", "tool": "tar", "verify_enabled": True, "restore_drill_enabled": True,
                 "restore_sample_path": "etc/hosts"}]
        started = []
        with mock.patch.object(agent.subprocess, "run", side_effect=lambda *a, **k: started.append(a) or mock.MagicMock(
                returncode=1, stdout="", stderr="x")), \
                mock.patch.object(agent, "_safe_state_read", lambda *a, **k: "{}"), \
                mock.patch.object(agent, "_safe_state_write", lambda *a, **k: None):
            agent.collect_backup_verify(mons)
            agent.run_restore_drills(mons, now=1_800_000_000)
        self.assertTrue(started, "neither channel runs even without the flag: this test cannot see the refusal")

    def test_the_refusal_is_logged_once_per_channel(self):
        self.signed(True)
        with mock.patch.object(agent.log, "error") as err:
            for _ in range(3):
                agent._refuse_unsigned_channel("restore drills", "x")
            agent._refuse_unsigned_channel("canary files", "x")
        self.assertEqual(err.call_count, 2)

    def test_the_extensionless_agent_is_the_same_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
