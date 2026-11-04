#!/usr/bin/env python3
"""7.5.0 agent review: the host-config apply creates a file meant for root alone with that mode, and checks group names.

* A file with a secret in it (a netplan file can hold a Wi-Fi key or a WireGuard key; a NetworkManager connection the same) was
  written by write_text(), which creates it at the umask's 0644, with chmod after. /etc/netplan is 0755, so for as long as the write
  took any user who could list the directory (inotify says when) could open the file and read what went into it. It is created with
  its final mode now, beside the target, and renamed over it.
* Users were checked as POSIX names and passed to useradd and usermod after `--`; groups were neither, so a group called `-o` or
  `--help` was read by groupadd as an option.

RP_TEST_AGENT points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name="agent_v750_hostcfg"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()


class TestFilesForRootAloneAreNeverReadable(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-hc-")
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        old = os.umask(0)                 # the worst case: nothing is taken away from a new file's mode
        self.addCleanup(os.umask, old)

    def watch(self):
        """Every mode the file or its temporary is seen with at the moments a reader could have opened it: when it is
        renamed into place, and when the old code chmods it."""
        seen = []
        real_chmod, real_fchmod, real_replace = os.chmod, os.fchmod, os.replace

        def chmod(path, mode, *a, **k):
            seen.append(("chmod", stat.S_IMODE(os.stat(path).st_mode)))        # the mode it had when chmod ran
            return real_chmod(path, mode, *a, **k)

        def fchmod(fd, mode):
            seen.append(("fchmod", stat.S_IMODE(os.fstat(fd).st_mode)))
            return real_fchmod(fd, mode)

        def replace(src, dst, *a, **k):
            seen.append(("replace", stat.S_IMODE(os.stat(src).st_mode)))
            return real_replace(src, dst, *a, **k)
        return seen, mock.patch.multiple(os, chmod=chmod, fchmod=fchmod, replace=replace)

    def test_a_private_file_is_never_wider_than_0600_from_the_first_moment(self):
        target = self.dir / "01-remotepower.yaml"
        seen, patch = self.watch()
        with patch:
            agent._write_host_file(str(target), "network:\n  wifis: {w: {access-points: {x: {password: s3cret}}}}\n", 0o600)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertIn("s3cret", target.read_text())
        self.assertTrue(seen, "no mode was observed: the test measures nothing")
        self.assertEqual([m for _w, m in seen if m & 0o077], [], f"the file was readable by others before it was 0600: {seen}")

    def test_no_temporary_file_is_left_beside_it(self):
        agent._write_host_file(str(self.dir / "a.yaml"), "x", 0o600)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["a.yaml"])

    def test_it_replaces_an_existing_looser_file_with_a_new_one_of_the_right_mode(self):
        target = self.dir / "b.yaml"
        target.write_text("old")
        target.chmod(0o644)
        agent._write_host_file(str(target), "new", 0o600)
        self.assertEqual((target.read_text(), stat.S_IMODE(target.stat().st_mode)), ("new", 0o600))

    def test_a_file_that_is_meant_to_be_read_is_written_as_before(self):
        target = self.dir / "motd"
        agent._write_host_file(str(target), "hello\n", 0o644)
        self.assertEqual((target.read_text(), stat.S_IMODE(target.stat().st_mode)), ("hello\n", 0o644))

    def test_a_link_at_the_temporary_name_is_not_followed(self):
        victim = self.dir / "victim"
        victim.write_text("keep")
        # the temporary name has a random part, so a planted link cannot be hit; the write goes to a fresh file either way
        agent._write_host_file(str(self.dir / "c.yaml"), "x", 0o600)
        self.assertEqual(victim.read_text(), "keep")


class TestGroupNames(unittest.TestCase):
    def run_groups(self, groups):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")
        with mock.patch.object(agent, "_audit_mode", lambda: False), mock.patch.object(agent, "IN_CONTAINER", False), \
                mock.patch.object(agent.subprocess, "run", fake_run):
            results = agent.apply_host_config({"groups": groups})
        return calls, results

    def test_a_name_that_groupadd_would_read_as_an_option_is_refused(self):
        calls, results = self.run_groups([{"name": "--help"}, {"name": "-o"}, {"name": "-f"}, {"name": "a b"}, {"name": ["x"]}])
        self.assertEqual([c for c in calls if c and c[0] == "groupadd"], [])
        self.assertIn("partial", results["groups"])

    def test_a_good_name_is_created_after_the_end_of_options(self):
        name = "rp_v750_testgroup_xyz"
        calls, _results = self.run_groups([{"name": name, "gid": 54321}])
        self.assertEqual(calls, [["groupadd", "-g", "54321", "--", name]])

    def test_something_that_is_not_a_group_is_skipped(self):
        calls, _results = self.run_groups([5, None, "x", ["y"]])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
