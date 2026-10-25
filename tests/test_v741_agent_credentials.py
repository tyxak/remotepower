#!/usr/bin/env python3
"""v7.4.1: a Linux agent that is running notices that its host was enrolled again.

The report: re-enrolling an already-enrolled host wrote the new credentials and
the running agent kept polling with the old ones ("Credentials rejected -
re-enroll") until somebody ran `systemctl restart remotepower-agent`. The
installers restart the service now (tests/test_v741_installer.py). This is the
other half, for every way credentials can change under a running agent: an
installer whose restart did not take effect, `remotepower-agent enroll` run by
hand (which is what the log line itself tells the operator to do), or a config
tool rewriting the file.

The Windows and macOS agents read their credentials again on every pass; the
Linux one bound them once. Enumerated below, three agents, one rule.

Three layers: the helpers, the parity census, and the real thing: a real agent
process polling a real HTTPS server while its credentials file is replaced.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_harness as H  # noqa: E402
from srcpin import py_function  # noqa: E402

ROOT = H.ROOT
AGENT = Path(os.environ.get("RP_AGENT_UNDER_TEST") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name):
    spec = importlib.util.spec_from_file_location(name, AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CREDS_A = {"server_url": "https://rp.example", "device_id": "dev-A", "token": "tok-A", "name": "a"}


class TestTheHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent("agent_v741_creds")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v741-agent-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.saved = self.agent.CREDS_FILE
        self.agent.CREDS_FILE = self.tmp / "credentials"
        self.addCleanup(setattr, self.agent, "CREDS_FILE", self.saved)
        self.held = ("https://rp.example", "dev-A", "tok-A")

    def write(self, obj):
        self.agent.CREDS_FILE.write_text(obj if isinstance(obj, str) else json.dumps(obj))

    def test_the_same_credentials_are_no_change(self):
        self.write(CREDS_A)
        self.assertIsNone(self.agent.credentials_changed(self.held))

    def test_a_new_token_a_new_host_or_a_new_server_is_a_change(self):
        for field, value in (("token", "tok-B"), ("device_id", "dev-B"),
                             ("server_url", "https://other.example")):
            with self.subTest(field=field):
                self.write(dict(CREDS_A, **{field: value}))
                got = self.agent.credentials_changed(self.held)
                self.assertIsNotNone(got)
                self.assertEqual(got[field], value)

    def test_a_renamed_host_is_not_a_change(self):
        self.write(dict(CREDS_A, name="renamed"))
        self.assertIsNone(self.agent.credentials_changed(self.held))

    def test_a_missing_corrupt_or_incomplete_file_is_no_change(self):
        """The agent keeps what it has: a half-written file must not restart it."""
        self.assertIsNone(self.agent.credentials_changed(self.held))          # missing
        self.write("{ not json")
        self.assertIsNone(self.agent.credentials_changed(self.held))          # corrupt
        self.write({"device_id": "dev-B", "token": "tok-B"})                  # no server_url
        self.assertIsNone(self.agent.credentials_changed(self.held))          # incomplete
        self.write("")
        self.assertIsNone(self.agent.credentials_changed(self.held))          # empty

    def test_restarting_runs_the_same_script_again_with_the_same_arguments(self):
        calls = []
        real, argv = self.agent.os.execv, sys.argv
        self.agent.os.execv = lambda exe, args: calls.append((exe, args))
        sys.argv = ["remotepower-agent", "run", "--interval", "30"]
        try:
            self.agent._restart_self()
        finally:
            self.agent.os.execv = real
            sys.argv = argv
        self.assertEqual(len(calls), 1)
        exe, args = calls[0]
        self.assertEqual(exe, sys.executable)
        self.assertEqual(args, [sys.executable, os.path.abspath("remotepower-agent"),
                                "run", "--interval", "30"])

    def test_if_it_cannot_restart_it_carries_on(self):
        real = self.agent.os.execv

        def boom(exe, args):
            raise OSError("exec refused")
        self.agent.os.execv = boom
        try:
            self.agent._restart_self()            # must not raise
        finally:
            self.agent.os.execv = real


class TestEveryAgentLooksAgainAtItsCredentials(unittest.TestCase):
    """Three agents, one rule. Print the ratio: the Windows and macOS loops read
    them every pass, and the Linux loop did not."""

    def loop_of(self, rel, fn, marker):
        """The agent's main loop, from its own first lines to the end of the
        function. The Linux heartbeat() has an earlier `while True:` in a nested
        helper, so the loop is found by what it starts with."""
        body = py_function((ROOT / rel).read_text(), fn)
        self.assertEqual(body.count(marker), 1, f"{rel}: {marker!r} is not unique")
        return body[body.index(marker):]

    SITES = {
        "client/remotepower-agent.py": ("heartbeat", "while True:\n        poll_count += 1",
                                        "credentials_changed("),
        "client/remotepower-agent-win.py": ("run", "while True:\n        if should_stop",
                                            "load_creds()"),
        "client/remotepower-agent-mac.py": ("run", "while True:\n        creds = load_creds()",
                                            "load_creds()"),
    }

    def test_each_loop_reads_credentials_again_on_every_pass(self):
        have = {rel: needle in self.loop_of(rel, fn, marker)
                for rel, (fn, marker, needle) in self.SITES.items()}
        self.assertEqual(len(have), 3)
        self.assertEqual([r for r, ok in have.items() if not ok], [],
                         f"{sum(have.values())} of 3 agents read their credentials again "
                         f"on each pass: {have}")

    def test_the_linux_check_comes_before_anything_uses_the_credentials(self):
        fn, marker, _needle = self.SITES["client/remotepower-agent.py"]
        loop = self.loop_of("client/remotepower-agent.py", fn, marker)
        self.assertLess(loop.index("credentials_changed("), loop.index("'token': token"))
        self.assertEqual(loop.count("credentials_changed("), 1)


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "needs openssl and bash")
class TestARunningAgentFollowsNewCredentials(unittest.TestCase):
    """The real thing: an agent process, a real HTTPS server it trusts only through
    RP_CA_BUNDLE, and a credentials file replaced while it runs."""

    WAIT = float(os.environ.get("RP_AGENT_WAIT", "90"))

    @classmethod
    def setUpClass(cls):
        cls.ca_tmp = Path(tempfile.mkdtemp(prefix="rp-v741-agentca-"))
        cls.tls, _fp = H.make_ca(cls.ca_tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.ca_tmp, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v741-agentrun-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.srv = H.Server(self.tls)
        self.addCleanup(self.srv.close)
        self.conf = self.tmp / "etc"
        self.conf.mkdir()
        self.pids = self.tmp / "pids"
        # Points the agent's own paths at scratch dirs and enters its real
        # heartbeat loop. sys.argv[0] is this file, so a restart runs it again.
        self.runner = self.tmp / "runner.py"
        self.runner.write_text(
            "import importlib.util, os, sys\n"
            "from pathlib import Path\n"
            "spec = importlib.util.spec_from_file_location('rp_agent', os.environ['RP_AGENT_PATH'])\n"
            "a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)\n"
            "conf = Path(os.environ['RP_TEST_CONF'])\n"
            "a.CONF_DIR = conf; a.CREDS_FILE = conf / 'credentials'\n"
            "a.STATE_DIR = Path(os.environ['RP_TEST_STATEDIR']); a.STATE_DIR.mkdir(exist_ok=True)\n"
            "open(os.environ['RP_TEST_PIDS'], 'a').write(f'{os.getpid()}\\n')\n"
            "a.heartbeat(a.load_credentials(), interval=1)\n")

    def creds(self, dev, tok):
        # The agent writes this file atomically too (save_credentials); mimic it.
        tmp = self.conf / "credentials.new"
        tmp.write_text(json.dumps({"server_url": self.srv.url, "device_id": dev,
                                   "token": tok, "name": dev}))
        os.replace(tmp, self.conf / "credentials")

    def wait_for(self, pred, what):
        end = time.time() + self.WAIT
        while time.time() < end:
            if pred():
                return
            if self.proc.poll() is not None:
                self.fail(f"the agent exited ({self.proc.returncode}) before {what}:\n"
                          + self.proc.stderr.read().decode(errors="replace")[-1500:])
            time.sleep(0.25)
        self.fail(f"timed out after {self.WAIT:.0f}s waiting for {what}; heartbeats seen: "
                  f"{sorted(set(self.srv.heartbeats))}")

    def test_credentials_replaced_under_a_running_agent_are_picked_up_without_a_restart(self):
        self.creds("dev-A", "tok-A")
        env = dict(os.environ, RP_AGENT_PATH=str(AGENT), RP_TEST_CONF=str(self.conf),
                   RP_TEST_STATEDIR=str(self.tmp / "state"), RP_TEST_PIDS=str(self.pids),
                   RP_CA_BUNDLE=str(self.tls / "ca.crt"), HOME=str(self.tmp))
        self.proc = subprocess.Popen([sys.executable, str(self.runner), "run"], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (self.proc.kill(), self.proc.wait()))
        self.wait_for(lambda: ("dev-A", "tok-A") in self.srv.heartbeats,
                      "the first heartbeat, as the old host")
        # The host is enrolled again: an installer, or `remotepower-agent enroll`.
        self.creds("dev-B", "tok-B")
        self.wait_for(lambda: ("dev-B", "tok-B") in self.srv.heartbeats,
                      "a heartbeat as the new host (the agent is still on the old credentials)")
        first_b = self.srv.heartbeats.index(("dev-B", "tok-B"))
        self.assertNotIn(("dev-A", "tok-A"), self.srv.heartbeats[first_b:],
                         "the agent went back to the old credentials")
        pids = self.pids.read_text().split()
        self.assertGreaterEqual(len(pids), 2, "the agent never started over: " + str(pids))
        self.assertEqual(len(set(pids)), 1, "the agent changed PID; a restart keeps it: " + str(pids))


if __name__ == "__main__":
    unittest.main()
