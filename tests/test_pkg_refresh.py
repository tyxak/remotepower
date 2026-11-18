#!/usr/bin/env python3
"""Check for updates now: a host's package lists as a state, on the agent and on the server.

`Scan packages` re-reads what the package manager already knows, so a host whose lists are a week old reports a week-old answer. The
Linux agent now refreshes the lists with the distribution's own fixed command and keeps how it went as {at, status, source,
error_class}, which the server stores with the host and the host's Packages section shows.

What this holds, by driving the real agent functions and the real server handlers (fake package managers are shell scripts in
temporary directories that answer in each manager's own words):

* The classifier turns each manager's output into a status and one fixed class, for realistic samples of apt, dnf, zypper, apk and
  pacman's checkupdates. Nothing the manager printed leaves the host: the record has four keys, each from a fixed set that the server
  holds as a copy.
* The command per distribution is fixed (arguments, environment, no input) and the plan never runs pacman -Sy: Arch uses checkupdates
  when it is there and otherwise answers "no safe way". A container and an agent in audit mode run nothing.
* The run is bounded: a command still going at the limit is ended, and one that is still printing that it waits for another process's
  lock after the lock wait is ended and reported as a lock; its process group goes with it. A stray process that keeps the pipe open
  does not hold the refresh up.
* The record is kept in the state file (it survives a restart), the stamp the "Package index updated recently" check reads is written
  on success only, and the agent's loop refreshes before the scheduled scan only while the server says so, reads the pending list again
  after the operator's refresh, and sends the record with the system information.
* The server keeps only a record from the fixed sets, sends the setting to a Linux host only while it may take an action, refuses the
  command for the platforms that lack it, gates it like another package action, and stores the setting as a real true or false.
"""
import importlib.machinery
import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-pkgrefresh-data-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

_TMP = tempfile.mkdtemp(prefix="rp-pkgrefresh-")


def _load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = _load(ROOT / "client" / "remotepower-agent.py", "agent_pkg_refresh")
win_agent = _load(ROOT / "client" / "remotepower-agent-win.py", "win_agent_pkg_refresh")
mac_agent = _load(ROOT / "client" / "remotepower-agent-mac.py", "mac_agent_pkg_refresh")

_spec = importlib.util.spec_from_file_location("api_pkg_refresh", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import pkg_refresh as pr_mod  # noqa: E402  (the server's own copy of the fixed sets)
import env_guard  # noqa: E402
from routing_harness import routes_to  # noqa: E402


def setUpModule():
    env_guard.save(__name__)
    logging.disable(logging.CRITICAL)      # the agent logs every refresh at INFO; the tests read results, not logs


def tearDownModule():
    logging.disable(logging.NOTSET)
    env_guard.restore(__name__)
    shutil.rmtree(_TMP, ignore_errors=True)


# ── fake package managers ────────────────────────────────────────────────────
def tool(directory, name, body):
    """An executable shell script `name` in `directory`."""
    path = Path(directory) / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def which_in(*dirs):
    """The lookup the agent's plan takes, over these directories only: a real apt-get on the machine that runs the test cannot be found."""
    def which(name):
        for d in dirs:
            p = os.path.join(str(d), name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return None
    return which


def speaks(log, text, rc=0):
    """A script that records how it was started, answers `text` and exits `rc`. stdin is read once: a closed one gives end of file."""
    return (f'{{ echo "ARGV $*"; echo "LC_ALL=$LC_ALL"; echo "ZYPP_LOCK_TIMEOUT=$ZYPP_LOCK_TIMEOUT"; '
            f'if read -r _x; then echo STDIN-DATA; else echo STDIN-EOF; fi; }} >> "{log}"\n'
            f"cat <<'RP_END'\n{text}\nRP_END\nexit {rc}\n")


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="case-", dir=_TMP))
        self.bin = self.d / "bin"
        self.bin.mkdir()
        self.log = self.d / "calls.log"
        self.state = self.d / "state"

    def logged(self):
        return self.log.read_text() if self.log.exists() else ""


# ── what each manager says ───────────────────────────────────────────────────
APT_OK = """Hit:1 http://deb.debian.org/debian bookworm InRelease
Get:2 http://deb.debian.org/debian-security bookworm-security InRelease [48.0 kB]
Get:3 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages [150 kB]
Fetched 198 kB in 1s (275 kB/s)
Reading package lists..."""
APT_NET = """Err:1 http://deb.debian.org/debian bookworm InRelease
  Temporary failure resolving 'deb.debian.org'
Reading package lists...
W: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease  Temporary failure resolving 'deb.debian.org'
W: Some index files failed to download. They have been ignored, or old ones used instead."""
APT_PARTIAL = """Hit:1 http://deb.debian.org/debian bookworm InRelease
Ign:2 https://example.org/repo stable InRelease
Err:3 https://example.org/repo stable Release
  404  Not Found [IP: 93.184.216.34 443]
Reading package lists...
E: The repository 'https://example.org/repo stable Release' does not have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default."""
APT_LOCK = """Reading package lists... Done
E: Could not get lock /var/lib/apt/lists/lock. It is held by process 1234 (apt-get)
E: Unable to lock directory /var/lib/apt/lists/"""
APT_LOCK_WAITED = """Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 5678 (unattended-upgr)
E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 5678 (unattended-upgr)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?"""
APT_NOT_ROOT = """Reading package lists... Done
E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)
E: Unable to lock directory /var/lib/apt/lists/"""
APT_DISK = """Err:1 http://deb.debian.org/debian bookworm InRelease
  Write error - write (28: No space left on device)
E: Write error - write (28: No space left on device)"""
DNF_OK = """Fedora 39 - x86_64                              12 MB/s |  38 MB     00:03
Fedora 39 openh264 (From Cisco) - x86_64       2.4 kB/s | 2.5 kB     00:01
Metadata cache created."""
DNF_NET = """Errors during downloading metadata for repository 'fedora':
  - Curl error (6): Couldn't resolve host name for https://mirrors.fedoraproject.org/metalink?repo=fedora-39&arch=x86_64 [Could not resolve host: mirrors.fedoraproject.org]
Error: Failed to download metadata for repo 'fedora': Cannot prepare internal mirrorlist: Curl error (6): Couldn't resolve host name"""
DNF_PARTIAL = """Fedora 39 - x86_64                              12 MB/s |  38 MB     00:03
Failed to download metadata for repo 'vendor': Cannot download repomd.xml: Cannot download repodata/repomd.xml: All mirrors were tried
Ignoring repositories: vendor
Metadata cache created."""
DNF_LOCK = "Waiting for process with pid 4321 to finish."
ZYPPER_OK = """Retrieving repository 'Main Repository (OSS)' metadata ........................................[done]
Building repository 'Main Repository (OSS)' cache ........................................[done]
All repositories have been refreshed."""
ZYPPER_SKIPPED = """Retrieving repository 'foo' metadata ........................................[error]
Repository 'foo' is invalid.
[foo|https://example.org/foo] Valid metadata not found at specified URL
Skipping repository 'foo' because of the above error.
Some of the repositories have not been refreshed because of an error."""
ZYPPER_LOCKED = "System management is locked by the application with pid 1234 (zypper). Close this application before trying again."
ZYPPER_ROOT = "Root privileges are required for refreshing repositories."
APK_OK = """fetch https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64/APKINDEX.tar.gz
v3.19.1-8-g1234567 [https://dl-cdn.alpinelinux.org/alpine/v3.19/main]
OK: 22983 distinct packages available"""
APK_NET = """fetch https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64/APKINDEX.tar.gz
WARNING: updating and opening https://dl-cdn.alpinelinux.org/alpine/v3.19/main: temporary error (try again later)"""
APK_PARTIAL = """fetch https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64/APKINDEX.tar.gz
WARNING: Ignoring https://dl-cdn.alpinelinux.org/alpine/v3.19/community/x86_64/APKINDEX.tar.gz: DNS lookup error
OK: 5120 distinct packages available"""
CHECKUPDATES = "linux 6.6.1-1 -> 6.7.2-1\nopenssl 3.2.0-1 -> 3.2.1-1"
CHECKUPDATES_NET = "error: failed retrieving file 'core.db' from mirror.example.org : Could not resolve host: mirror.example.org"

# (source, rc, text) -> (status, class)
SAMPLES = (
    ("apt", 0, APT_OK, "ok", ""),
    ("apt", 100, APT_NET, "failed", "network"),
    ("apt", 0, APT_NET, "failed", "network"),          # an older apt answered 0 with the same warnings
    ("apt", 100, APT_PARTIAL, "partial", "repository"),
    ("apt", 100, APT_LOCK, "failed", "lock"),
    ("apt", 100, APT_LOCK_WAITED, "failed", "lock"),
    ("apt", 100, APT_NOT_ROOT, "failed", "permission"),
    ("apt", 100, APT_DISK, "failed", "disk"),
    ("apt", 100, "", "failed", "unknown"),
    ("dnf", 0, DNF_OK, "ok", ""),
    ("dnf", 1, DNF_NET, "failed", "network"),
    ("dnf", 0, DNF_PARTIAL, "partial", "repository"),
    ("dnf", 1, DNF_LOCK, "failed", "lock"),
    ("yum", 0, DNF_OK, "ok", ""),
    ("zypper", 0, ZYPPER_OK, "ok", ""),
    ("zypper", 106, ZYPPER_SKIPPED, "partial", "repository"),
    ("zypper", 7, ZYPPER_LOCKED, "failed", "lock"),
    ("zypper", 5, ZYPPER_ROOT, "failed", "permission"),
    ("apk", 0, APK_OK, "ok", ""),
    ("apk", 99, APK_NET, "failed", "network"),
    ("apk", 0, APK_PARTIAL, "partial", "network"),
    ("pacman", 0, CHECKUPDATES, "ok", ""),
    ("pacman", 2, "", "ok", ""),                        # checkupdates answers 2 when nothing is waiting
    ("pacman", 1, CHECKUPDATES_NET, "failed", "network"),
    ("pacman", 1, "", "failed", "unknown"),
)


class TestTheClassifier(unittest.TestCase):

    def test_each_sample_is_read_as_its_manager_meant_it(self):
        for source, rc, text, status, cls in SAMPLES:
            with self.subTest(source=source, rc=rc, text=text[:40]):
                self.assertEqual(agent._pkg_refresh_classify(source, rc, text), (status, cls))

    def test_the_samples_cover_every_status_and_most_classes(self):
        """Control: a table that stopped producing a status would pass for the wrong reason."""
        seen_status = {s for _src, _rc, _t, s, _c in SAMPLES}
        seen_class = {c for _src, _rc, _t, _s, c in SAMPLES}
        self.assertEqual(seen_status, {"ok", "partial", "failed"})
        self.assertTrue({"lock", "network", "repository", "disk", "permission", "unknown", ""} <= seen_class)

    def test_a_result_is_always_from_the_fixed_sets_and_a_clean_run_has_no_class(self):
        for source, rc, text, _s, _c in SAMPLES:
            status, cls = agent._pkg_refresh_classify(source, rc, text)
            self.assertIn(status, agent._PKG_REFRESH_STATUSES)
            self.assertIn(cls, agent._PKG_REFRESH_CLASSES)
            self.assertEqual(cls == "", status == "ok")

    def test_the_agents_sets_are_the_servers_sets(self):
        """Two copies of one fact: a class the agent can send and the server has no word for would read as "unknown" for ever."""
        self.assertEqual(set(agent._PKG_REFRESH_STATUSES), set(pr_mod.STATUSES))
        self.assertEqual(set(agent._PKG_REFRESH_CLASSES), set(pr_mod.CLASSES))
        self.assertEqual(set(agent._PKG_REFRESH_SOURCES) | {""}, set(pr_mod.SOURCES))

    def test_every_class_the_agent_can_name_has_words_in_the_page(self):
        """The Packages section draws a class from its own table; a class without a row would print the "unknown" wording for it."""
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        block = js[js.index("const _PKG_REFRESH_CLASS = {"):]
        block = block[:block.index("};")]
        for cls in agent._PKG_REFRESH_CLASSES:
            if cls:
                self.assertIn(f"  {cls}:", block, cls)


class TestThePlan(_Tmp):

    def plan(self, *names, container=False):
        for n in names:
            tool(self.bin, n, "exit 0\n")
        with mock.patch.object(agent, "IN_CONTAINER", container):
            return agent._pkg_refresh_plan(which_in(self.bin))

    def test_apt(self):
        src, argv, env = self.plan("apt-get")
        self.assertEqual(src, "apt")
        self.assertEqual(argv[1:], ["-o", "DPkg::Lock::Timeout=30", "-o", "APT::Sandbox::User=root", "update"])
        self.assertEqual(env, {})

    def test_dnf_dnf5_and_yum(self):
        self.assertEqual(self.plan("dnf")[:2][0], "dnf")
        self.assertEqual(self.plan("dnf")[1][1:], ["-y", "makecache", "--refresh"])

    def test_dnf5_when_it_is_the_only_one(self):
        src, argv, _env = self.plan("dnf5")
        self.assertEqual((src, argv[1:]), ("dnf", ["-y", "makecache", "--refresh"]))
        self.assertTrue(argv[0].endswith("dnf5"))

    def test_yum_when_it_is_the_only_one(self):
        src, argv, _env = self.plan("yum")
        self.assertEqual((src, argv[1:]), ("yum", ["-y", "makecache"]))

    def test_zypper_waits_for_the_lock_by_its_own_setting(self):
        src, argv, env = self.plan("zypper")
        self.assertEqual((src, argv[1:]), ("zypper", ["--non-interactive", "refresh"]))
        self.assertEqual(env, {"ZYPP_LOCK_TIMEOUT": "30"})

    def test_apk_waits_for_the_lock_by_its_own_option(self):
        src, argv, _env = self.plan("apk")
        self.assertEqual((src, argv[1:]), ("apk", ["--wait", "30", "update"]))

    def test_arch_uses_checkupdates_and_never_pacman(self):
        src, argv, _env = self.plan("pacman", "checkupdates")
        self.assertEqual(src, "pacman")
        self.assertEqual(len(argv), 1)
        self.assertTrue(argv[0].endswith("checkupdates"))
        self.assertFalse(any("pacman" in a and not a.endswith("checkupdates") for a in argv))

    def test_arch_without_checkupdates_has_no_safe_way(self):
        src, argv, why = self.plan("pacman")
        self.assertEqual((src, argv, why), ("pacman", None, "no_safe_way"))

    def test_no_manager_at_all(self):
        self.assertEqual(self.plan(), ("", None, "no_manager"))

    def test_apt_wins_when_a_host_has_more_than_one(self):
        src, _argv, _env = self.plan("apt-get", "dnf", "pacman", "checkupdates")
        self.assertEqual(src, "apt")

    def test_no_word_of_a_command_comes_from_anywhere_but_the_agent(self):
        """The arguments are fixed words and numbers: nothing a server sent or a file held is in them."""
        allowed = {"-o", "-y", "update", "makecache", "--refresh", "refresh", "--non-interactive", "--wait",
                   "DPkg::Lock::Timeout=30", "APT::Sandbox::User=root", "30"}
        for names in (("apt-get",), ("dnf",), ("yum",), ("zypper",), ("apk",), ("pacman", "checkupdates")):
            d = Path(tempfile.mkdtemp(dir=self.d))
            for n in names:
                tool(d, n, "exit 0\n")
            _src, argv, _env = agent._pkg_refresh_plan(which_in(d))
            self.assertLessEqual(set(argv[1:]), allowed, argv)


class TestARun(_Tmp):
    """The command really runs: fake managers answer in their own words."""

    def run_with(self, name, text, rc, **kw):
        tool(self.bin, name, speaks(self.log, text, rc))
        with mock.patch.object(agent, "IN_CONTAINER", False):
            return agent._pkg_refresh_run(which=which_in(self.bin), **kw)

    def test_each_manager_end_to_end(self):
        cases = (("apt-get", APT_OK, 0, "apt", "ok", ""), ("apt-get", APT_NET, 100, "apt", "failed", "network"),
                 ("apt-get", APT_PARTIAL, 100, "apt", "partial", "repository"), ("dnf", DNF_OK, 0, "dnf", "ok", ""),
                 ("dnf", DNF_PARTIAL, 0, "dnf", "partial", "repository"), ("zypper", ZYPPER_SKIPPED, 106, "zypper", "partial", "repository"),
                 ("zypper", ZYPPER_LOCKED, 7, "zypper", "failed", "lock"), ("apk", APK_NET, 99, "apk", "failed", "network"))
        for name, text, rc, source, status, cls in cases:
            with self.subTest(name=name, rc=rc):
                shutil.rmtree(self.bin)
                self.bin.mkdir()
                rec = self.run_with(name, text, rc, timeout=20, lock_wait=10)
                self.assertEqual((rec["source"], rec["status"], rec["error_class"]), (source, status, cls))
                self.assertEqual(set(rec), {"at", "status", "source", "error_class"})
                self.assertLessEqual(abs(rec["at"] - int(time.time())), 5)

    def test_the_command_gets_no_input_the_c_locale_and_its_fixed_arguments(self):
        self.run_with("apt-get", APT_OK, 0)
        logged = self.logged()
        self.assertIn("ARGV -o DPkg::Lock::Timeout=30 -o APT::Sandbox::User=root update", logged)
        self.assertIn("LC_ALL=C", logged)
        self.assertIn("STDIN-EOF", logged)
        self.assertNotIn("STDIN-DATA", logged)

    def test_zypper_is_told_its_lock_wait_in_its_environment(self):
        self.run_with("zypper", ZYPPER_OK, 0)
        self.assertIn("ZYPP_LOCK_TIMEOUT=30", self.logged())

    def test_what_the_manager_printed_never_leaves_in_the_record_or_the_line(self):
        canary = "SECRET-CANARY-TOKEN-0123456789"
        rec = self.run_with("apt-get", APT_NET + "\n" + canary, 100)
        self.assertNotIn(canary, json.dumps(rec))
        self.assertNotIn(canary, agent._pkg_refresh_line(rec))
        self.assertNotIn("deb.debian.org", agent._pkg_refresh_line(rec))

    def test_a_command_still_running_at_the_limit_is_ended(self):
        pidfile = self.d / "pid"
        tool(self.bin, "apt-get", f'echo $$ > "{pidfile}"\nsleep 60\n')
        t0 = time.monotonic()
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(timeout=1, lock_wait=30, which=which_in(self.bin))
        self.assertLess(time.monotonic() - t0, 12)
        self.assertEqual((rec["status"], rec["error_class"]), ("failed", "timeout"))
        pid = int(pidfile.read_text())
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_manager_still_waiting_for_a_lock_after_the_wait_is_ended_as_a_lock(self):
        pidfile = self.d / "pid"
        tool(self.bin, "dnf", f'echo $$ > "{pidfile}"\necho "Waiting for process with pid 4321 to finish."\nsleep 60\n')
        t0 = time.monotonic()
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(timeout=30, lock_wait=1, which=which_in(self.bin))
        self.assertLess(time.monotonic() - t0, 10, "the lock wait is far shorter than the limit and must end the run")
        self.assertEqual((rec["source"], rec["status"], rec["error_class"]), ("dnf", "failed", "lock"))
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_a_slow_command_that_is_not_waiting_for_a_lock_is_left_alone_past_the_lock_wait(self):
        tool(self.bin, "apk", "sleep 2\necho 'OK: 10 distinct packages available'\n")
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(timeout=20, lock_wait=1, which=which_in(self.bin))
        self.assertEqual((rec["status"], rec["error_class"]), ("ok", ""))

    def test_a_process_the_manager_leaves_holding_the_pipe_does_not_hold_the_refresh_up(self):
        tool(self.bin, "apk", "sleep 8 &\necho 'OK: 1 distinct packages available'\nexit 0\n")
        t0 = time.monotonic()
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(timeout=30, lock_wait=20, which=which_in(self.bin))
        self.assertLess(time.monotonic() - t0, 6)
        self.assertEqual(rec["status"], "ok")

    def test_the_output_kept_to_be_read_is_capped(self):
        tool(self.bin, "apk", "head -c 3000000 /dev/zero | tr '\\0' 'x'\necho\nexit 0\n")
        rc, text, how = agent._pkg_refresh_exec([str(self.bin / "apk")], {}, 30, 20)
        self.assertEqual((rc, how), (0, "done"))
        self.assertLessEqual(len(text), agent.PKG_REFRESH_OUTPUT_CAP + 4096)

    def test_a_tool_that_cannot_be_started_is_a_failure_with_an_unknown_class(self):
        path = self.bin / "apt-get"
        path.write_text("#!/nonexistent/interpreter\n")
        path.chmod(0o755)
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(which=which_in(self.bin))
        self.assertEqual((rec["status"], rec["error_class"]), ("failed", "unknown"))

    def test_arch_runs_checkupdates_and_never_pacman(self):
        tool(self.bin, "pacman", speaks(self.log, "SHOULD NOT RUN", 0))
        tool(self.bin, "checkupdates", speaks(self.d / "cu.log", CHECKUPDATES, 0))
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(which=which_in(self.bin))
        self.assertEqual((rec["source"], rec["status"]), ("pacman", "ok"))
        self.assertEqual(self.logged(), "", "pacman was run")
        self.assertTrue((self.d / "cu.log").exists())

    def test_arch_without_checkupdates_runs_nothing_and_says_there_is_no_safe_way(self):
        tool(self.bin, "pacman", speaks(self.log, "SHOULD NOT RUN", 0))
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(which=which_in(self.bin))
        self.assertEqual((rec["source"], rec["status"], rec["error_class"]), ("pacman", "unsupported", "no_safe_way"))
        self.assertEqual(self.logged(), "", "pacman was run")
        self.assertEqual(agent._pkg_refresh_line(rec), "not refreshed: no safe way on this distribution")

    def test_a_container_runs_nothing(self):
        tool(self.bin, "apt-get", speaks(self.log, APT_OK, 0))
        with mock.patch.object(agent, "IN_CONTAINER", True):
            rec = agent._pkg_refresh_run(which=which_in(self.bin))
        self.assertEqual((rec["status"], rec["error_class"]), ("unsupported", "container"))
        self.assertEqual(self.logged(), "")
        self.assertEqual(agent._pkg_refresh_line(rec), "not refreshed: not available in a container")

    def test_a_host_with_no_package_manager(self):
        with mock.patch.object(agent, "IN_CONTAINER", False):
            rec = agent._pkg_refresh_run(which=which_in(self.bin))
        self.assertEqual((rec["status"], rec["error_class"], rec["source"]), ("unsupported", "no_manager", ""))


class TestTheRecord(_Tmp):

    def setUp(self):
        super().setUp()
        for p in (mock.patch.object(agent, "STATE_DIR", self.state), mock.patch.object(agent, "IN_CONTAINER", False),
                  mock.patch.object(agent, "_audit_mode", lambda: False), mock.patch.object(agent, "_PKG_REFRESH_LAST", None)):
            p.start()
            self.addCleanup(p.stop)

    def refresh(self, name, text, rc):
        tool(self.bin, name, speaks(self.log, text, rc))
        return agent.refresh_package_lists(which=which_in(self.bin), timeout=20, lock_wait=10)

    def test_the_record_is_kept_and_survives_a_restart(self):
        rec = self.refresh("apt-get", APT_OK, 0)
        self.assertEqual(json.loads((self.state / agent.PKG_REFRESH_STATE).read_text()), rec)
        with mock.patch.object(agent, "_PKG_REFRESH_LAST", None):     # a fresh process: nothing in memory
            self.assertEqual(agent._pkg_refresh_last(), rec)

    def test_nothing_is_reported_before_the_first_refresh(self):
        self.assertIsNone(agent._pkg_refresh_last())

    def test_a_record_that_is_not_ours_is_not_read(self):
        self.state.mkdir(parents=True, exist_ok=True)
        for raw in ("not json", "[1]", json.dumps({"at": "x", "status": "ok"}), json.dumps({"at": 5, "status": "bogus"}),
                    json.dumps({"at": True, "status": "ok"}), json.dumps({"at": -4, "status": "ok"})):
            (self.state / agent.PKG_REFRESH_STATE).write_text(raw)
            with mock.patch.object(agent, "_PKG_REFRESH_LAST", None):
                self.assertIsNone(agent._pkg_refresh_last(), raw)

    def test_a_class_or_source_outside_the_sets_is_read_as_unknown_or_blank(self):
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / agent.PKG_REFRESH_STATE).write_text(json.dumps(
            {"at": 1700000000, "status": "failed", "source": "<b>apt</b>", "error_class": "<script>"}))
        with mock.patch.object(agent, "_PKG_REFRESH_LAST", None):
            self.assertEqual(agent._pkg_refresh_last(),
                             {"at": 1700000000, "status": "failed", "source": "", "error_class": "unknown"})

    def test_the_stamp_is_written_on_success_and_not_on_failure(self):
        self.refresh("apt-get", APT_OK, 0)
        stamp = self.state / agent.PKG_REFRESH_STAMP
        self.assertTrue(stamp.exists())
        old = time.time() - 3 * 86400
        os.utime(stamp, (old, old))
        self.refresh("apt-get", APT_NET, 100)
        self.assertAlmostEqual(stamp.stat().st_mtime, old, delta=2, msg="a failed refresh moved the stamp")
        self.refresh("apt-get", APT_PARTIAL, 100)
        self.assertGreater(stamp.stat().st_mtime, old + 86400, "a partial refresh updated some lists and counts")

    def test_audit_mode_refuses_and_records_nothing(self):
        tool(self.bin, "apt-get", speaks(self.log, APT_OK, 0))
        with mock.patch.object(agent, "_audit_mode", lambda: True):
            self.assertIsNone(agent.refresh_package_lists(which=which_in(self.bin)))
        self.assertEqual(self.logged(), "", "a refresh ran in audit mode")
        self.assertFalse((self.state / agent.PKG_REFRESH_STATE).exists())

    def test_a_fault_inside_a_refresh_is_a_failed_record_and_not_an_exception(self):
        with mock.patch.object(agent, "_pkg_refresh_run", side_effect=RuntimeError("boom")):
            rec = agent.refresh_package_lists()
        self.assertEqual((rec["status"], rec["error_class"]), ("failed", "unknown"))


class TestTheCommand(_Tmp):

    def setUp(self):
        super().setUp()
        for p in (mock.patch.object(agent, "STATE_DIR", self.state), mock.patch.object(agent, "IN_CONTAINER", False),
                  mock.patch.object(agent, "_audit_mode", lambda: False), mock.patch.object(agent, "_PKG_REFRESH_LAST", None),
                  mock.patch.object(agent, "_PKG_RESCAN_NOW", False)):
            p.start()
            self.addCleanup(p.stop)
        self.which = which_in(self.bin)

    def send(self, name, text, rc):
        tool(self.bin, name, speaks(self.log, text, rc))
        with mock.patch.object(agent, "_which", self.which):
            return agent.execute_command("pkg_refresh")

    def test_the_result_is_one_fixed_line_and_the_pending_list_is_read_again(self):
        res = self.send("apt-get", APT_OK, 0)
        self.assertEqual(res, {"cmd": "pkg_refresh", "output": "package lists refreshed (apt)", "rc": 0})
        self.assertTrue(agent._PKG_RESCAN_NOW)

    def test_a_failure_answers_with_its_class_in_words_and_a_non_zero_code(self):
        canary = "CANARY-4711"
        res = self.send("apt-get", APT_NET + "\n" + canary, 100)
        self.assertEqual(res["rc"], 1)
        self.assertEqual(res["output"], "package lists not refreshed (apt): the repositories could not be reached")
        self.assertNotIn(canary, res["output"])

    def test_a_partial_refresh_counts_as_done_for_the_exit_code(self):
        res = self.send("apt-get", APT_PARTIAL, 100)
        self.assertEqual(res["rc"], 0)
        self.assertTrue(res["output"].startswith("package lists partly refreshed (apt)"))

    def test_audit_mode_refuses_the_command_before_anything_runs(self):
        tool(self.bin, "apt-get", speaks(self.log, APT_OK, 0))
        with mock.patch.object(agent, "_audit_mode", lambda: True), mock.patch.object(agent, "_which", self.which):
            res = agent.execute_command("pkg_refresh")
        self.assertEqual(res["rc"], 126)
        self.assertEqual(self.logged(), "")
        self.assertFalse(agent._PKG_RESCAN_NOW)

    def test_the_refusal_inside_the_function_also_holds(self):
        """execute_command refuses in audit mode first; the function asks again, so the scheduled path cannot get round it."""
        tool(self.bin, "apt-get", speaks(self.log, APT_OK, 0))
        with mock.patch.object(agent, "_audit_mode", lambda: True), mock.patch.object(agent, "_which", self.which):
            res = agent._run_pkg_refresh_command("pkg_refresh")
        self.assertEqual((res["rc"], res["output"]), (126, "refused: agent is in audit (read-only) mode"))
        self.assertEqual(self.logged(), "")

    def test_the_other_agents_answer_unsupported_honestly(self):
        for mod in (win_agent, mac_agent):
            with mock.patch.object(mod, "_audit_mode", lambda: False):
                res = mod.handle_command("pkg_refresh")
            self.assertEqual(res, {"cmd": "pkg_refresh", "output": "unsupported command: pkg_refresh", "rc": 1})


# ── the agent's loop ─────────────────────────────────────────────────────────
class _Stop(BaseException):
    """Not an Exception, so nothing in the agent's loop can swallow it."""


class _NoThreads:
    """`threading`, but a Thread starts nothing."""

    class Thread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

    def __getattr__(self, name):
        return getattr(threading_real, name)


import threading as threading_real  # noqa: E402

_QUIET = (
    "get_metrics", "get_host_health", "get_smart_status", "get_kernel_status", "get_hardware_inventory", "get_gpu_status",
    "get_cert_files", "get_local_accounts", "get_ups_status", "get_av_status", "get_ecc_errors", "get_zram",
    "get_autoupdate_posture", "get_platform_health", "get_disk_encryption", "get_ssh_config", "get_ssh_hostkeys", "get_repo_files",
    "get_usb_devices", "get_battery", "get_chassis", "get_journal", "collect_sudo_events", "collect_peer_connections",
    "collect_lldp_neighbors", "get_containers", "get_compose_projects", "get_docker_disk_usage", "get_helm_releases",
    "send_package_list", "get_mdns_services", "collect_acme_state", "collect_custom_metrics",
    "collect_disk_io", "collect_net_io", "get_network_info", "get_host_addresses", "collect_dmesg_logs", "collect_apt_history",
    "collect_web_access_logs", "submit_unit_logs", "detect_auto_watch_units", "get_local_ip", "collect_cpu_time",
    "get_third_party_updates", "collect_backup_verify", "run_restore_drills", "_burst_live_samples", "discover_apps",
    "get_os_info", "get_uptime", "get_uptime_seconds", "collect_disk_usage",
)


def drive(answers, rounds, patch_every=None, run_result=None):
    """Run the real heartbeat() loop for `rounds` polls. `answers` are the server's answers in order (the last one repeats); a
    command in one is executed by the real execute_command. With `run_result` the real refresh_package_lists runs and only the
    package manager is replaced by that record; without it refresh_package_lists is a recorder.
    Returns (posts, events): every heartbeat body the agent sent, and the order the refresh and the pending-list read happened in."""
    tmp = Path(tempfile.mkdtemp(prefix="hb-", dir=_TMP))
    state = {"n": 0}
    posts, events = [], []

    def post(url, data, timeout=10):
        if url.endswith("/api/heartbeat") and "cmd_output" not in (data or {}):
            state["n"] += 1
            posts.append(data)
            if state["n"] > rounds:
                raise _Stop()
            return answers[min(state["n"], len(answers)) - 1]
        return {}

    def quiet(*a, **k):
        return {}

    def recorded_refresh(*a, **k):
        events.append("refresh")

    def fake_patch(*a, **k):
        events.append("patch")
        return {"manager": "apt", "upgradable": 4}

    patches = [
        mock.patch.object(agent, "http_post", post),
        mock.patch.object(agent, "check_for_update", lambda *a, **k: False),
        mock.patch.object(agent, "threading", _NoThreads()),
        mock.patch.object(agent, "STATE_DIR", tmp),
        mock.patch.object(agent, "_audit_mode", lambda: False),
        mock.patch.object(agent, "_require_signed_commands", lambda: False),
        mock.patch.object(agent, "get_patch_info", fake_patch),
        mock.patch.object(agent, "_PKG_RESCAN_NOW", False),
        mock.patch.object(agent, "_PKG_REFRESH_LAST", None),
    ]
    if run_result is None:
        patches.append(mock.patch.object(agent, "refresh_package_lists", recorded_refresh))
    else:
        patches.append(mock.patch.object(agent, "_pkg_refresh_run", lambda *a, **k: run_result))
    if patch_every:
        patches.append(mock.patch.object(agent, "PATCH_EVERY", patch_every))
    for name in _QUIET:
        if hasattr(agent, name):
            patches.append(mock.patch.object(agent, name, quiet))
    for p in patches:
        p.start()
    try:
        agent.heartbeat({"server_url": "https://rp.example", "device_id": "DEVLOOP", "token": "t" * 32}, interval=0)
    except _Stop:
        pass
    finally:
        for p in reversed(patches):
            p.stop()
    return posts, events


class TestTheAgentsLoop(unittest.TestCase):

    def test_the_lists_are_refreshed_before_the_scheduled_scan_while_the_server_says_so(self):
        _posts, events = drive([{"refresh_lists_before_scan": True}], rounds=3, patch_every=3)
        self.assertEqual(events, ["refresh", "patch"], "the refresh comes first, then the scan reads against the new lists")

    def test_nothing_about_the_scheduled_scan_changes_while_the_setting_is_off(self):
        _posts, events = drive([{}], rounds=3, patch_every=3)
        self.assertEqual(events, ["patch"])

    def test_a_busy_answer_carries_no_settings_and_does_not_switch_the_setting_off(self):
        _posts, events = drive([{"refresh_lists_before_scan": True}, {"busy": True}], rounds=3, patch_every=3)
        self.assertEqual(events, ["refresh", "patch"])

    def test_an_answer_without_the_key_switches_it_off_again(self):
        _posts, events = drive([{"refresh_lists_before_scan": True}, {}], rounds=3, patch_every=3)
        self.assertEqual(events, ["patch"])

    def test_the_operators_refresh_is_followed_by_a_read_of_the_pending_list_and_the_record_goes_with_it(self):
        rec = {"at": int(time.time()), "status": "ok", "source": "apt", "error_class": ""}
        posts, events = drive([{"command": "pkg_refresh"}, {}], rounds=3, run_result=rec)
        self.assertEqual(events, ["patch"], "the pending list is read once, on the poll after the refresh")
        self.assertNotIn("pkg_refresh", posts[0].get("sysinfo") or {}, "nothing is reported before the first refresh")
        second = posts[1].get("sysinfo") or {}
        self.assertEqual(second.get("pkg_refresh"), rec)
        self.assertEqual((second.get("packages") or {}).get("upgradable"), 4)

    def test_a_refresh_that_fails_is_reported_too(self):
        rec = {"at": int(time.time()), "status": "failed", "source": "apt", "error_class": "network"}
        posts, _events = drive([{"command": "pkg_refresh"}, {}], rounds=3, run_result=rec)
        self.assertEqual((posts[1].get("sysinfo") or {}).get("pkg_refresh"), rec)


# ── the check template ───────────────────────────────────────────────────────
class TestTheFreshnessTemplate(_Tmp):

    def template(self):
        import checks
        return next(t for t in checks.CHECK_BASELINE_CATALOG if t.get("id") == "apt_update_fresh")

    def test_the_template_names_the_stamp_the_agent_writes(self):
        parts = self.template()["param"].split("|")
        self.assertIn(f"{agent.STATE_DIR}/{agent.PKG_REFRESH_STAMP}", parts)
        self.assertIn("/var/lib/apt/lists", parts)

    def test_a_refresh_makes_the_check_pass_where_no_apt_path_exists_and_a_failure_does_not(self):
        """On a dnf host the apt paths are not there: the stamp is the only candidate, so it is what the check reads."""
        stamp = self.state / agent.PKG_REFRESH_STAMP
        param = "|".join([str(self.d / "no-stamp"), str(self.d / "no-lists"), str(stamp)])
        check = {"type": "job_fresh", "param": param, "max_age_hours": 48}
        self.assertEqual(agent._eval_one_agent_check(check)[0], "critical", "no refresh has ever run")
        for p in (mock.patch.object(agent, "STATE_DIR", self.state), mock.patch.object(agent, "IN_CONTAINER", False),
                  mock.patch.object(agent, "_audit_mode", lambda: False), mock.patch.object(agent, "_PKG_REFRESH_LAST", None)):
            p.start()
            self.addCleanup(p.stop)
        tool(self.bin, "dnf", speaks(self.log, DNF_OK, 0))
        agent.refresh_package_lists(which=which_in(self.bin), timeout=20, lock_wait=10)
        self.assertEqual(agent._eval_one_agent_check(check)[0], "ok")
        old = time.time() - 5 * 86400
        os.utime(stamp, (old, old))
        tool(self.bin, "dnf", speaks(self.log, DNF_NET, 1))
        agent.refresh_package_lists(which=which_in(self.bin), timeout=20, lock_wait=10)
        self.assertEqual(agent._eval_one_agent_check(check)[0], "critical", "a refresh that failed does not make the lists fresh")


# ── the server ───────────────────────────────────────────────────────────────
NOW = int(time.time())


class TestTheServersReading(unittest.TestCase):

    def test_a_good_record_is_kept_as_it_is(self):
        rec = {"at": NOW - 60, "status": "ok", "source": "apt", "error_class": ""}
        self.assertEqual(pr_mod.clean(rec, NOW), rec)

    def test_only_four_keys_survive(self):
        out = pr_mod.clean({"at": NOW, "status": "failed", "source": "dnf", "error_class": "network", "output": "x" * 5000,
                            "token": "t"}, NOW)
        self.assertEqual(set(out), {"at", "status", "source", "error_class"})

    def test_a_status_outside_the_set_drops_the_record(self):
        for bad in ("bogus", "", None, 7, ["ok"], "<script>"):
            self.assertIsNone(pr_mod.clean({"at": NOW, "status": bad, "source": "apt"}, NOW), bad)

    def test_a_time_that_is_not_believed_drops_the_record(self):
        for bad in (0, -5, True, "17", None, 1.5, NOW + 3600, NOW - 6 * 365 * 86400, 10 ** 30):
            self.assertIsNone(pr_mod.clean({"at": bad, "status": "ok"}, NOW), bad)

    def test_a_clock_a_little_ahead_is_read_as_now(self):
        self.assertEqual(pr_mod.clean({"at": NOW + 120, "status": "ok"}, NOW)["at"], NOW)

    def test_a_source_or_class_outside_the_sets_is_blank_or_unknown(self):
        out = pr_mod.clean({"at": NOW, "status": "failed", "source": "<b>apt</b>", "error_class": "<img onerror=x>"}, NOW)
        self.assertEqual((out["source"], out["error_class"]), ("", "unknown"))

    def test_a_refresh_that_worked_has_no_class(self):
        self.assertEqual(pr_mod.clean({"at": NOW, "status": "ok", "error_class": "network"}, NOW)["error_class"], "")

    def test_what_is_not_a_record_is_not_one(self):
        for bad in (None, "x", 5, [], [1], True):
            self.assertIsNone(pr_mod.clean(bad, NOW))


class _Server(unittest.TestCase):
    """Real handlers over stores in a temporary directory. Only verify_token and the recorders are stubbed: the permission gate, the
    queue's pre-flight and the approval parking are the real ones."""

    FILES = ("CONFIG_FILE", "DEVICES_FILE", "CMDS_FILE", "CONFIRMATIONS_FILE", "USERS_FILE", "TOKENS_FILE", "ROLES_FILE", "MAINT_FILE",
             "HISTORY_FILE")
    WHO, ROLE = "alice", "admin"
    TOKENS = {"d1": "tok1", "dw": "tokw", "dm": "tokm", "dq": "tokq", "da": "toka", "dg": "tokg"}

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="srv-", dir=_TMP))
        self._saved = {n: getattr(api, n) for n in self.FILES}
        for n in self.FILES:
            setattr(api, n, self.d / self._saved[n].name)       # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        self.audit = []
        for name, value in (("verify_token", lambda token=None, *a, **k: (self.WHO, self.ROLE)),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: "POST"),
                            ("audit_log", lambda *a, **k: self.audit.append((a, k))),
                            ("log_command", lambda *a, **k: None),
                            ("fire_webhook", lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.body = {}
        for name, value in (("get_json_obj", lambda: dict(self.body)), ("get_json_body", lambda: dict(self.body))):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.set_config()
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "web01", "os": "Ubuntu 22.04", "token": self.TOKENS["d1"]},
            "dw": {"name": "win01", "os": "Windows 11 (Build 22631)", "token": self.TOKENS["dw"]},
            "dm": {"name": "mac01", "os": "macOS 14.5 (23F79)", "token": self.TOKENS["dm"]},
            "dq": {"name": "held", "os": "Ubuntu 22.04", "quarantined": True, "token": self.TOKENS["dq"]},
            "da": {"name": "audit", "os": "Debian 12", "sysinfo": {"audit_mode": True}, "token": self.TOKENS["da"]},
            "dg": {"name": "agentless", "os": "Ubuntu 22.04", "agentless": True, "token": self.TOKENS["dg"]},
        })
        api.save(api.CMDS_FILE, {})
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api.save(api.USERS_FILE, {"alice": {"role": "admin"}, "bob": {"role": "admin"}})
        api.save(api.MAINT_FILE, {"windows": []})
        api._LOAD_CACHE.clear()

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def set_config(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def call(self, fn, *args):
        try:
            fn(*args)
        except api.HTTPError as e:
            return e.status, e.body
        self.fail(f"{getattr(fn, '__name__', fn)} answered nothing")

    def queue(self):
        api._LOAD_CACHE.clear()
        return {k: v for k, v in (api.load(api.CMDS_FILE) or {}).items() if v}

    def pending(self):
        api._LOAD_CACHE.clear()
        return [c for c in (api.load(api.CONFIRMATIONS_FILE) or {}).get("confirmations", []) if c.get("status") == "pending"]


class TestTheEndpoint(_Server):

    def ask(self, dev="d1"):
        return self.call(api.handle_device_pkg_refresh, dev)

    def test_the_route_is_registered_under_the_device_prefix(self):
        self.assertEqual(routes_to("POST", "/api/devices/abc123/refresh-package-lists"), "handle_device_pkg_refresh")
        self.assertEqual(routes_to("GET", "/api/devices/abc123/refresh-package-lists"), "__http__404",
                         "a GET reaches no handler")

    def test_an_admin_queues_the_verb_on_a_linux_host_and_it_is_audited(self):
        status, body = self.ask()
        self.assertEqual((status, body), (200, {"ok": True}))
        self.assertEqual(self.queue(), {"d1": ["pkg_refresh"]})
        self.assertEqual(self.audit[0][0][:2], ("alice", "pkg_refresh"))
        self.assertIn("d1", self.audit[0][0][2])

    def test_the_same_request_twice_queues_one_command(self):
        self.ask()
        self.ask()
        self.assertEqual(self.queue(), {"d1": ["pkg_refresh"]})

    def test_a_viewer_is_refused(self):
        self.ROLE = "viewer"
        status, body = self.ask()
        self.assertEqual(status, 403)
        self.assertEqual(self.queue(), {})

    def test_a_custom_role_with_the_patch_permission_may_and_one_with_only_packages_may_not(self):
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "patcher", "permissions": ["patch"], "scope": {"type": "all"}},
            {"name": "installer", "permissions": ["packages"], "scope": {"type": "all"}},
            {"name": "web-only", "permissions": ["patch"], "scope": {"type": "groups", "values": ["web"]}}]})
        api._LOAD_CACHE.clear()
        self.ROLE = "installer"
        self.assertEqual(self.ask()[0], 403)
        self.ROLE = "patcher"
        self.assertEqual(self.ask()[0], 200, "the under-permissive direction: a role holding the permission must be able to act")
        self.assertEqual(self.queue(), {"d1": ["pkg_refresh"]})

    def test_a_role_scoped_to_other_hosts_is_refused_for_this_one(self):
        api.save(api.ROLES_FILE, {"roles": [{"name": "web-only", "permissions": ["patch"],
                                             "scope": {"type": "groups", "values": ["web"]}}]})
        api._LOAD_CACHE.clear()
        self.ROLE = "web-only"
        self.assertEqual(self.ask()[0], 403)
        self.assertEqual(self.queue(), {})

    def test_a_windows_and_a_macos_host_are_refused_with_a_sentence(self):
        for dev in ("dw", "dm"):
            status, body = self.ask(dev)
            self.assertEqual((status, body["error"]), (409, "the package list refresh is available for Linux hosts only"))
        self.assertEqual(self.queue(), {})

    def test_the_queue_gate_refuses_the_verb_for_those_platforms_too(self):
        """The handler's own sentence is for the person; the shared gate is what every other path (a batch, an approval) meets."""
        for dev in ("dw", "dm"):
            blocked = api._command_block_reason(api.load(api.DEVICES_FILE)[dev], "pkg_refresh")
            self.assertEqual(blocked[0], 409)
        self.assertIsNone(api._command_block_reason(api.load(api.DEVICES_FILE)["d1"], "pkg_refresh"))

    def test_an_agentless_host_has_no_agent_to_run_it(self):
        status, body = self.ask("dg")
        self.assertEqual((status, body["error"]), (400, "an agentless host has no agent to refresh package lists"))
        self.assertEqual(self.queue(), {})

    def test_quarantine_audit_mode_and_maintenance_mode_refuse_it(self):
        self.assertEqual(self.ask("dq")[0], 409)
        self.assertEqual(self.ask("da")[0], 409)
        self.set_config(maintenance_mode=True, maintenance_reason="upgrade")
        status, body = self.ask("d1")
        self.assertEqual(status, 503)
        self.assertTrue(body.get("maintenance"))
        self.assertEqual(self.queue(), {})

    def test_an_unknown_or_malformed_host_is_not_found(self):
        self.assertEqual(self.ask("nope1234")[0], 404)
        self.assertEqual(self.ask("../etc")[0], 404)

    def test_four_eyes_parks_it_when_the_scan_kind_is_gated_and_not_otherwise(self):
        self.set_config(change_approval_enabled=True)             # the default gated set has no scan kind
        self.assertEqual(self.ask()[0], 200)
        self.assertEqual(self.queue(), {"d1": ["pkg_refresh"]})
        api.save(api.CMDS_FILE, {})
        self.set_config(change_approval_enabled=True, approval_gated_kinds=["scan"])
        self.body = {"reason": "before the window", "ticket_ref": "CHG-7"}
        status, body = self.ask()
        self.assertEqual(status, 202)
        self.assertTrue(body["approval_required"])
        self.assertEqual(self.queue(), {}, "a parked change writes nothing to the queue")
        pend = self.pending()
        self.assertEqual(len(pend), 1)
        self.assertEqual(pend[0]["params"]["summary"], "refresh the package lists")
        self.assertEqual((pend[0]["reason"], pend[0]["ticket_ref"]), ("before the window", "CHG-7"))

    def test_the_verb_is_the_scan_kind_and_has_a_readable_line_in_the_queue(self):
        self.assertEqual(api._command_kind("pkg_refresh"), "scan")
        self.assertIn("scan", api._APPROVAL_KINDS_ALL, "an operator can only gate a kind the settings offer")
        self.assertEqual(api._humanize_queued_command("pkg_refresh"), {"kind": "scan", "summary": "refresh the package lists"})
        self.assertEqual(api._VERB_OS_SUPPORT["pkg_refresh"], ("linux",))


class TestAHostOutsideTheCallersTenant(unittest.TestCase):
    """The route sits under /api/devices/<id>/, which main() covers with its pre-dispatch gate: a tenant admin never reaches the handler
    for another tenant's host."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ten-", dir=_TMP))
        self._saved = {n: getattr(api, n) for n in ("CONFIG_FILE", "DEVICES_FILE")}
        for n in self._saved:
            setattr(api, n, self.d / self._saved[n].name)
        self.addCleanup(lambda: [setattr(api, n, v) for n, v in self._saved.items()] and api._LOAD_CACHE.clear())
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        api.save(api.DEVICES_FILE, {"devA": {"name": "A", "tenant": "tenantA", "os": "Ubuntu 22.04", "token": "a"},
                                    "devB": {"name": "B", "tenant": "tenantB", "os": "Ubuntu 22.04", "token": "b"}})
        api._LOAD_CACHE.clear()
        for name, value in (("verify_token", lambda token=None, *a, **k: ("alice", "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("_caller_effective_tenant", lambda u, _t="tenantA": _t)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def gate(self, dev_id):
        with mock.patch.object(api, "path_info", lambda: f"/api/devices/{dev_id}/refresh-package-lists"):
            try:
                api._enforce_device_scope()
            except api.HTTPError as e:
                return e.status
        return None

    def test_a_tenant_admin_is_stopped_at_another_tenants_host_and_not_at_its_own(self):
        self.assertEqual(self.gate("devB"), 403)
        self.assertIsNone(self.gate("devA"))


class TestTheSettingAndTheHeartbeat(_Server):
    """What the server tells a host's agent in its heartbeat answer, and the record it takes in."""

    def beat(self, dev="d1", os_name=None, sysinfo=None, **extra):
        devices = api.load(api.DEVICES_FILE)
        # the first beat of a host replaces its plaintext token with a hash, so the token is kept here
        body = {"device_id": dev, "token": self.TOKENS[dev], "os": os_name or devices[dev].get("os", ""), "version": "8.0.1"}
        if sysinfo is not None:
            body["sysinfo"] = sysinfo
        body.update(extra)
        self.body = body
        return self.call(api.handle_heartbeat)

    def told(self, dev="d1", **kw):
        status, body = self.beat(dev, **kw)
        self.assertEqual(status, 200, body)
        return body.get("refresh_lists_before_scan")

    def test_the_setting_is_off_by_default_and_nothing_is_sent(self):
        self.assertIsNone(self.told())
        status, body = self.call(api.handle_config_get)
        self.assertIs(body["pkg_refresh_before_scan"], False)

    def test_on_it_is_sent_to_a_linux_host(self):
        self.set_config(pkg_refresh_before_scan=True)
        self.assertIs(self.told(), True)

    def test_a_windows_or_macos_host_is_never_told(self):
        self.set_config(pkg_refresh_before_scan=True)
        self.assertIsNone(self.told("dw"))
        self.assertIsNone(self.told("dm"))

    def test_a_quarantined_host_an_audit_mode_host_and_maintenance_mode_hold_it(self):
        self.set_config(pkg_refresh_before_scan=True)
        self.assertIsNone(self.told("dq"))
        self.assertIsNone(self.told("da", sysinfo={"audit_mode": True}))
        self.set_config(pkg_refresh_before_scan=True, maintenance_mode=True)
        self.assertIsNone(self.told())

    def test_a_closed_change_window_holds_it_and_an_open_one_lets_it_through(self):
        self.set_config(pkg_refresh_before_scan=True)
        off_hour = (time.localtime().tm_hour + 12) % 24
        api.save(api.MAINT_FILE, {"windows": [{"id": "w1", "scope": "global", "target": "", "gate_exec": True,
                                               "cron": f"0 {off_hour} * * *", "duration": 600}]})
        api._LOAD_CACHE.clear()
        self.assertIsNone(self.told(), "commands are held until the window opens, and so is this")
        api.save(api.MAINT_FILE, {"windows": [{"id": "w1", "scope": "global", "target": "", "gate_exec": True,
                                               "cron": "* * * * *", "duration": 3600}]})
        api._LOAD_CACHE.clear()
        self.assertIs(self.told(), True)
        api.save(api.MAINT_FILE, {"windows": [{"id": "w2", "scope": "global", "target": "", "gate_exec": False,
                                               "cron": f"0 {off_hour} * * *", "duration": 600}]})
        api._LOAD_CACHE.clear()
        self.assertIs(self.told(), True, "a window that does not hold commands holds nothing")

    def test_the_setting_is_saved_as_a_real_true_or_false(self):
        for sent, kept in ((True, True), (False, False)):
            self.body = {"pkg_refresh_before_scan": sent}
            self.assertEqual(self.call(api.handle_config_save)[0], 200)
            api._LOAD_CACHE.clear()
            self.assertIs(api.load(api.CONFIG_FILE)["pkg_refresh_before_scan"], kept)
        for bad in ("false", "true", 1, 0, None, [], "yes"):
            with self.subTest(bad=bad):
                self.body = {"pkg_refresh_before_scan": bad}
                status, body = self.call(api.handle_config_save)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "pkg_refresh_before_scan must be true or false")

    def test_the_setting_is_instance_wide_and_a_tenant_admin_cannot_change_it(self):
        self.set_config(tenancy_enforced=True)
        with mock.patch.object(api, "_caller_is_superadmin", lambda: False):
            self.body = {"pkg_refresh_before_scan": True}
            self.assertEqual(self.call(api.handle_config_save)[0], 403)
        api._LOAD_CACHE.clear()
        self.assertNotIn("pkg_refresh_before_scan", api.load(api.CONFIG_FILE))

    # ── the record the agent reports ──
    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE)["d1"].get("sysinfo") or {}).get("pkg_refresh")

    def test_the_record_rides_the_system_information_into_the_host(self):
        rec = {"at": NOW - 90, "status": "partial", "source": "apt", "error_class": "repository"}
        self.assertEqual(self.beat(sysinfo={"uptime": "up 1 day", "pkg_refresh": rec})[0], 200)
        self.assertEqual(self.stored(), rec)

    def test_a_record_with_values_outside_the_sets_is_cleaned_or_left_out(self):
        self.beat(sysinfo={"uptime": "u", "pkg_refresh": {"at": NOW, "status": "failed", "source": "<script>x</script>",
                                                         "error_class": "<img src=x onerror=alert(1)>", "output": "x" * 9000}})
        self.assertEqual(self.stored(), {"at": NOW, "status": "failed", "source": "", "error_class": "unknown"})
        for bad in ({"at": NOW, "status": "<b>ok</b>"}, "text", ["ok"], 42, None, {"status": "ok"}, {"at": "now", "status": "ok"}):
            with self.subTest(bad=bad):
                self.beat(sysinfo={"uptime": "u", "pkg_refresh": bad})
                self.assertIsNone(self.stored())

    def test_a_beat_that_carries_no_record_leaves_none(self):
        self.beat(sysinfo={"uptime": "u"})
        self.assertIsNone(self.stored())


class TestTheStampPathAndTheDocs(unittest.TestCase):

    def test_the_verb_is_in_the_matrix_the_agents_are_checked_against(self):
        """test_v643_verb_parity derives the platform matrix from the agents' sources; the verb has to be a branch of execute_command
        and of no other agent's dispatcher for the table row to be true."""
        src = (ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertIn("cmd == 'pkg_refresh'", src)
        for other in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            self.assertNotIn("pkg_refresh", (ROOT / "client" / other).read_text())

    def test_the_two_agent_copies_are_one_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent.py").read_bytes(), (ROOT / "client" / "remotepower-agent").read_bytes())

    def test_the_key_the_server_sends_is_declared_by_the_agents_that_do_not_read_it(self):
        """test_heartbeat_key_parity holds this for every key; this names the one this feature adds, in both directions: the server
        sends it, and neither other agent reads it (so the declaration is true, not a stale entry)."""
        import re
        sent = re.findall(r"common_resp\['(refresh_lists_before_scan)'\]", (_CGI / "api.py").read_text())
        self.assertEqual(sent, ["refresh_lists_before_scan"])
        for other in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            src = (ROOT / "client" / other).read_text()
            declared = re.search(r"HEARTBEAT_KEYS_NOT_HONOURED = \((.*?)\n\)", src, re.S).group(1)
            self.assertIn("'refresh_lists_before_scan'", declared, other)
            self.assertIsNone(re.search(r"\.get\(\s*['\"]refresh_lists_before_scan['\"]", src), other + " reads a key it declares as not read")


class TestTheFleetKnowledgeCorpus(unittest.TestCase):
    """"Which hosts failed to refresh their package lists" is a fleet question the drawer answered and the corpus did not."""

    NOW = int(time.time())

    @staticmethod
    def corpus(**sysinfo):
        import rag_index
        docs = rag_index.build_live_state_corpus([{"id": "d1", "name": "web01", "os": "linux", "last_seen": int(time.time()),
                                                   "monitored": True, "sysinfo": sysinfo}], now=int(time.time()))
        return "\n".join(d.get("text", "") for d in docs)

    def test_a_refresh_that_worked_is_said_with_its_date(self):
        at = 1_700_000_000                                              # 2023-11-14
        text = self.corpus(pkg_refresh={"at": at, "status": "ok", "source": "apt", "error_class": ""})
        self.assertIn("package lists last refreshed 2023-11-14: ok", text)

    def test_a_refresh_that_failed_says_so_in_capitals_with_its_class(self):
        for status, expect in (("failed", "FAILED (network)"), ("partial", "PARTLY failed (network)")):
            with self.subTest(status=status):
                text = self.corpus(pkg_refresh={"at": self.NOW, "status": status, "source": "apt", "error_class": "network"})
                self.assertIn(expect, text)

    def test_a_distribution_with_no_safe_way_is_not_called_a_failure(self):
        text = self.corpus(pkg_refresh={"at": self.NOW, "status": "unsupported", "source": "pacman", "error_class": "no_safe_way"})
        self.assertIn("not possible on this host (no safe way)", text)
        self.assertNotIn("FAILED", text)

    def test_the_line_is_the_same_whenever_the_corpus_is_built(self):
        """A relative time ("12 minutes ago") would change the chunk on every rebuild and re-embed it for nothing."""
        rec = {"at": 1_700_000_000, "status": "ok", "source": "apt", "error_class": ""}
        self.assertEqual(self.corpus(pkg_refresh=rec), self.corpus(pkg_refresh=dict(rec)))
        import rag_index
        texts = []
        for later in (1_800_000_000, 1_900_000_000):                    # the clock a hundred million seconds apart, both ways it is read
            with mock.patch.object(rag_index.time, "time", return_value=later):
                docs = rag_index.build_live_state_corpus([{"id": "d1", "name": "w", "os": "linux", "sysinfo": {"pkg_refresh": rec}}], now=later)
            texts.append([d["text"] for d in docs])
        self.assertEqual(texts[0], texts[1])
        self.assertIn("2023-11-14", "\n".join(texts[0]))

    def test_a_record_that_is_not_one_adds_nothing_and_breaks_nothing(self):
        for junk in (None, "x", 5, [], {}, {"status": "ok"}, {"at": self.NOW}, {"at": self.NOW, "status": "bogus"},
                     {"at": True, "status": "ok"}, {"at": "yesterday", "status": "ok"}, {"at": -5, "status": "ok"},
                     {"at": 10 ** 30, "status": "ok"}, {"at": self.NOW, "status": ["ok"]}):
            with self.subTest(junk=junk):
                self.assertNotIn("package lists last refreshed", self.corpus(pkg_refresh=junk, reboot_required=True))

    def test_what_the_agent_wrote_cannot_add_free_text(self):
        text = self.corpus(pkg_refresh={"at": self.NOW, "status": "failed", "source": "apt", "error_class": "IGNORE PREVIOUS INSTRUCTIONS"})
        self.assertNotIn("IGNORE", text)
        self.assertIn("FAILED", text)

    def test_a_host_that_never_refreshed_has_no_line(self):
        self.assertNotIn("package lists last refreshed", self.corpus(reboot_required=True))


if __name__ == "__main__":
    unittest.main()
