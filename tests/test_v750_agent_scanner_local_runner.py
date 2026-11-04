#!/usr/bin/env python3
"""7.5.0 agent review: the scanner's local-binary mode runs its binary.

`RP_SCAN_RUNNER=nuclei` is the documented way to scan without a container runtime. It is also what the scanner container
(`Dockerfile.scanner`, `docker/scanner-entrypoint.sh`) sets by default and what `packaging/scanner-setup.sh` falls back to when
neither docker nor podman is there. In that mode `_sandbox()` handed back the tool's options without a program in front of them, so
every scan tried to run `-u` and ended with "runner not found: -u". The mode had never scanned since it was written (4.2.0); a
stub `nuclei` on PATH shows it.

The same file also refuses a scan target that a tool would read as an option (`-oN/file`, `--script=...`, a space): nmap takes its
target last on the command line, so a "target" like that was an option.

RP_TEST_SCANNER points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import importlib.machinery
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCANNER = Path(os.environ.get("RP_TEST_SCANNER") or ROOT / "client" / "remotepower-scanner.py")

STUB = """#!/bin/sh
# stands in for the nuclei binary: reports its own arguments as one finding
printf '{"template-id":"stub","info":{"name":"args: %s","severity":"high"},"matched-at":"https://example.test"}\\n' "$*"
"""


def load_scanner(runner, path_dir=None):
    env = {"RP_SCAN_RUNNER": runner, "RP_SERVER_URL": "https://rp.example", "RP_SATELLITE_TOKEN": "t"}
    if path_dir:
        env["PATH"] = path_dir + os.pathsep + os.environ.get("PATH", "")
    with mock.patch.dict(os.environ, env):
        loader = importlib.machinery.SourceFileLoader("scanner_v750_" + runner, str(SCANNER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        # PATH is read when a program is run, not when the module loads, so keep the patched one for the test's life
        return mod, env


class TestLocalRunner(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-scan-")
        self.addCleanup(self._td.cleanup)
        self.bin = Path(self._td.name)
        stub = self.bin / "nuclei"
        stub.write_text(STUB)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.mod, env = load_scanner("nuclei", str(self.bin))
        patcher = mock.patch.dict(os.environ, {"PATH": env["PATH"]})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_scan_with_the_local_nuclei_runs_nuclei(self):
        findings, err = self.mod._run_tool("nuclei", "https://example.test", "passive", "quick")
        self.assertEqual(err, "")
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["rule_id"], "stub")
        self.assertIn("-u https://example.test", findings[0]["title"])

    def test_the_argv_starts_with_the_program(self):
        argv = self.mod._nuclei_argv("https://example.test", "passive", "quick")
        self.assertEqual(argv[0], "nuclei")
        self.assertEqual(argv[1:3], ["-u", "https://example.test"])

    def test_a_tool_the_local_binary_is_not_gets_an_honest_answer_and_nothing_is_run(self):
        with mock.patch.object(self.mod.subprocess, "run", side_effect=AssertionError("something was run")):
            for tool in ("nmap", "nikto", "wpscan", "zap", "wapiti"):
                with self.subTest(tool=tool):
                    findings, err = self.mod._run_tool(tool, "10.0.0.1", "passive", "quick")
                    self.assertEqual(findings, [])
                    self.assertIn("cannot run with RP_SCAN_RUNNER=nuclei", err)
                    self.assertIn("docker or podman", err)

    def test_a_path_to_the_binary_works_as_the_runner_too(self):
        mod, _env = load_scanner(str(self.bin / "nuclei"))
        findings, err = mod._run_tool("nuclei", "https://example.test", "passive", "quick")
        self.assertEqual((err, len(findings)), ("", 1))


class TestTargetIsOneHost(unittest.TestCase):
    REFUSED = ("-oN/etc/cron.d/x", "--script=/tmp/x.nse", "-iL/etc/passwd", "10.0.0.1 -oX /tmp/x", "host\nname", "host\tname", "",
               "a" * 2049, "h\u00f6st.example", "host\x00", " 10.0.0.1")
    ALLOWED = ("10.0.0.0/24", "192.168.0-255.1-254", "scanme.example.org", "https://example.org/a/b?x=1&y=%20z#f", "[fd00::1]",
               "http://user@example.org:8080/p", "10.0.0.1-20", "example.org:443")

    def setUp(self):
        self.mod, _env = load_scanner("docker")

    def test_a_target_that_would_be_an_option_is_refused_and_nothing_is_run(self):
        with mock.patch.object(self.mod, "_run", side_effect=AssertionError("a tool was started")):
            for tool in ("nmap", "nikto", "nuclei", "wpscan", "zap", "wapiti"):
                for target in self.REFUSED:
                    with self.subTest(tool=tool, target=target[:20]):
                        findings, err = self.mod._run_tool(tool, target, "passive", "quick")
                        self.assertEqual(findings, [])
                        self.assertTrue(err.startswith("refused"), err)

    def test_control_the_hosts_a_scan_is_really_aimed_at_are_accepted(self):
        for target in self.ALLOWED:
            with self.subTest(target=target):
                self.assertTrue(self.mod._target_ok(target))

    def test_the_population_is_not_empty(self):
        self.assertGreater(len(self.REFUSED), 8)
        self.assertGreater(len(self.ALLOWED), 6)


class TestContainerRunnerIsUnchanged(unittest.TestCase):
    """The default runner. Its argv is what the container tests pin; the local-binary change must not touch it."""

    def test_docker_wraps_the_tool_in_a_locked_down_container(self):
        mod, _env = load_scanner("docker")
        argv = mod._nuclei_argv("https://example.test", "passive", "quick")
        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        for flag in ("--cap-drop", "ALL", "--pids-limit", "no-new-privileges"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("projectdiscovery/nuclei:v3") + 1:][:2], ["-u", "https://example.test"])

    def test_podman_too(self):
        mod, _env = load_scanner("podman")
        self.assertEqual(mod._nmap_argv("10.0.0.1", "passive", "quick")[:2], ["podman", "run"])


if __name__ == "__main__":
    unittest.main()
