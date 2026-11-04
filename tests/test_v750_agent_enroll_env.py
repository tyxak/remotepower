#!/usr/bin/env python3
"""7.5.0 agent review (NF-5): the enrolment PIN and token do not have to be on a command line.

`install-macos.sh --pin`, `install-windows.ps1 -Pin/-Token` and `remotepower-agent enroll --pin` put the value into the agent's argv,
where any local account reads it in the process list for the seconds enrolment takes. The three agents read REMOTEPOWER_ENROLL_PIN
(and, as the Linux agent already did, REMOTEPOWER_ENROLL_TOKEN) from the environment, an argument still wins, and the two installers
hand the value over that way.

RP_TEST_AGENT, RP_TEST_MAC_AGENT and RP_TEST_WIN_AGENT point the test at other copies (a `git show HEAD:` of the old file fails it).
"""
import importlib.machinery
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-enrenv-"))
ROOT = Path(__file__).resolve().parent.parent
LINUX = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")
MAC = Path(os.environ.get("RP_TEST_MAC_AGENT") or ROOT / "client" / "remotepower-agent-mac.py")
WIN = Path(os.environ.get("RP_TEST_WIN_AGENT") or ROOT / "client" / "remotepower-agent-win.py")


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _Env(unittest.TestCase):
    def setUp(self):
        for k in ("REMOTEPOWER_ENROLL_PIN", "REMOTEPOWER_ENROLL_TOKEN"):
            p = mock.patch.dict(os.environ)
            p.start()
            self.addCleanup(p.stop)
            os.environ.pop(k, None)


class TestMacAndWindows(_Env):
    """The two agents share the shape: main(argv) calls enroll(server, pin=, token=, name=)."""

    AGENTS = (("mac", MAC), ("win", WIN))

    def enrolled_with(self, path, name, argv, **env):
        agent = load(path, f"agent_v750_enrenv_{name}")
        seen = {}

        def fake_enroll(server, pin=None, token=None, name=None):
            seen.update(server=server, pin=pin, token=token)
            return {"device_id": "d1"}

        with mock.patch.dict(os.environ, env), mock.patch.object(agent, "enroll", fake_enroll), \
                mock.patch.object(agent, "_creds_path", lambda: "/tmp/creds", create=True):
            rc = agent.main(argv)
        return rc, seen

    def test_the_pin_can_come_from_the_environment(self):
        for name, path in self.AGENTS:
            rc, seen = self.enrolled_with(path, name, ["--enroll", "--server", "https://rp.example.com"],
                                          REMOTEPOWER_ENROLL_PIN="123456")
            self.assertEqual((rc, seen.get("pin")), (0, "123456"), name)

    def test_the_token_can_come_from_the_environment(self):
        tok = "t" * 40
        for name, path in self.AGENTS:
            rc, seen = self.enrolled_with(path, name, ["--enroll", "--server", "https://rp.example.com"],
                                          REMOTEPOWER_ENROLL_TOKEN=tok)
            self.assertEqual((rc, seen.get("token")), (0, tok), name)

    def test_an_argument_wins_over_the_environment(self):
        for name, path in self.AGENTS:
            rc, seen = self.enrolled_with(path, name, ["--enroll", "--server", "https://rp.example.com", "--pin", "654321"],
                                          REMOTEPOWER_ENROLL_PIN="123456")
            self.assertEqual((rc, seen.get("pin")), (0, "654321"), name)

    def test_no_pin_anywhere_is_still_refused(self):
        for name, path in self.AGENTS:
            agent = load(path, f"agent_v750_enrenv2_{name}")
            with self.assertRaises(SystemExit):                     # argparse's error() exits
                agent.main(["--enroll", "--server", "https://rp.example.com"])

    def test_a_blank_variable_counts_as_nothing(self):
        for name, path in self.AGENTS:
            agent = load(path, f"agent_v750_enrenv3_{name}")
            with mock.patch.dict(os.environ, {"REMOTEPOWER_ENROLL_PIN": "   "}), self.assertRaises(SystemExit):
                agent.main(["--enroll", "--server", "https://rp.example.com"])


class TestLinux(_Env):

    def run_main(self, argv, **env):
        agent = load(LINUX, "agent_v750_enrenv_linux")
        got = {}
        with mock.patch.dict(os.environ, env), mock.patch.object(sys, "argv", ["remotepower-agent", *argv]), \
                mock.patch.object(agent, "enroll_interactive", lambda **kw: got.update(kw)), \
                mock.patch.object(agent.os, "geteuid", lambda: 0):
            agent.main()
        return got

    def test_enroll_takes_the_pin_from_the_environment(self):
        got = self.run_main(["enroll", "--server", "https://rp.example.com"], REMOTEPOWER_ENROLL_PIN="123456")
        self.assertEqual((got.get("pin"), got.get("re_enroll")), ("123456", False))

    def test_re_enroll_does_too_and_an_argument_wins(self):
        got = self.run_main(["re-enroll", "--server", "https://rp.example.com"], REMOTEPOWER_ENROLL_PIN="123456")
        self.assertEqual((got.get("pin"), got.get("re_enroll")), ("123456", True))
        got = self.run_main(["enroll", "--server", "https://rp.example.com", "--pin", "654321"], REMOTEPOWER_ENROLL_PIN="123456")
        self.assertEqual(got.get("pin"), "654321")

    def test_no_pin_is_none_so_the_prompt_still_runs(self):
        got = self.run_main(["enroll", "--server", "https://rp.example.com"])
        self.assertIsNone(got.get("pin"))
        got = self.run_main(["enroll"], REMOTEPOWER_ENROLL_PIN="  ")
        self.assertIsNone(got.get("pin"))

    def test_the_extensionless_twin_is_identical(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


class TestTheInstallers(unittest.TestCase):

    def test_the_macos_installer_passes_the_pin_in_the_environment(self):
        sh = (ROOT / "client" / "install-macos.sh").read_text()
        line = next(ln for ln in sh.splitlines() if "--enroll --server" in ln and "AGENT_BIN" in ln and not ln.lstrip().startswith(("#", "echo")))
        self.assertIn('REMOTEPOWER_ENROLL_PIN="$PIN"', line)
        self.assertNotIn("--pin", line)

    def test_the_windows_installer_passes_both_in_the_environment_and_clears_them(self):
        ps = (ROOT / "client" / "install-windows.ps1").read_text()
        self.assertNotRegex(ps, r"'--pin'|'--token'")
        self.assertIn("$env:REMOTEPOWER_ENROLL_PIN = $Pin", ps)
        self.assertIn("$env:REMOTEPOWER_ENROLL_TOKEN = $Token", ps)
        self.assertRegex(ps, r"finally \{\s*Remove-Item Env:REMOTEPOWER_ENROLL_PIN")
        self.assertIn("Remove-Item Env:REMOTEPOWER_ENROLL_TOKEN", ps)
        self.assertIn("throw 'Enrollment failed.'", ps)

    def test_the_docs_name_the_variable(self):
        self.assertIn("REMOTEPOWER_ENROLL_PIN", (ROOT / "docs" / "agent-commands.md").read_text())
        self.assertIn("REMOTEPOWER_ENROLL_PIN", (ROOT / "docs" / "windows-client.md").read_text())
        self.assertTrue(re.search(r"REMOTEPOWER_ENROLL_PIN", (ROOT / "client" / "remotepower-agent.py").read_text()))


if __name__ == "__main__":
    unittest.main()
