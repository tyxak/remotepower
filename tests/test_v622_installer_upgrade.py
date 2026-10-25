"""v6.2.2 "Pu1seMatters" — upgrade-friendly install-client.sh.

Re-running the installer on an already-enrolled host must be an in-place
UPGRADE: binary + unit refreshed, enrollment kept, agent RESTARTED (not
`enable --now`, which is a no-op on a running unit — the exact trap behind the
v6.2.1 sandboxing incident), a customized unit backed up first, --re-enroll
opting back into enrollment. Tested FUNCTIONALLY: the real script runs under
bash with RP_INSTALL_ROOT pointing at a scratch root and a fully controlled
PATH (stub systemctl/agent + symlinks to only the real utilities needed).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_SCRIPT = _ROOT / "install-client.sh"

# Real utilities the script legitimately needs; nothing else is reachable.
_REAL_TOOLS = ("sed", "install", "mkdir", "cp", "cmp", "grep", "dirname",
               "rm", "mktemp", "tr", "id", "bash")


@unittest.skipUnless(_SCRIPT.exists(), "excluded from dist tree")
class TestInstallerUpgrade(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-inst-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # Fake dist dir: the real script + a stub agent + the real unit.
        self.dist = self.tmp / "dist"
        (self.dist / "client").mkdir(parents=True)
        shutil.copy(_SCRIPT, self.dist / "install-client.sh")
        self.log = self.tmp / "calls.log"
        agent = self.dist / "client" / "remotepower-agent"
        agent.write_text("#!/bin/sh\necho \"AGENT $*\" >> \"$RP_TEST_LOG\"\n")
        agent.chmod(0o755)
        shutil.copy(_ROOT / "client" / "remotepower-agent.service",
                    self.dist / "client" / "remotepower-agent.service")

        # Controlled PATH: stubs first, then symlinks to the real tools.
        self.stub = self.tmp / "stub"
        self.realbin = self.tmp / "realbin"
        self.stub.mkdir()
        self.realbin.mkdir()
        for tool in _REAL_TOOLS:
            real = shutil.which(tool)
            if real:
                (self.realbin / tool).symlink_to(real)
        for name in ("systemctl", "systemd-run"):
            s = self.stub / name
            s.write_text(f"#!/bin/sh\necho \"{name.upper()} $*\" >> \"$RP_TEST_LOG\"\n")
            s.chmod(0o755)
        sleep = self.stub / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)

        self.root = self.tmp / "root"
        self.root.mkdir()

    def _run(self, *args, env_extra=None):
        env = {
            "PATH": f"{self.stub}:{self.realbin}",
            "RP_INSTALL_ROOT": str(self.root),
            "RP_TEST_LOG": str(self.log),
            "HOME": str(self.tmp),
        }
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", str(self.dist / "install-client.sh"), *args],
            env=env, capture_output=True, text=True, timeout=30)

    def _calls(self):
        return self.log.read_text() if self.log.exists() else ""

    def _enrolled(self):
        cred = self.root / "etc/remotepower/credentials"
        cred.parent.mkdir(parents=True, exist_ok=True)
        cred.write_text("id=abc token=xyz\n")

    # ── fresh install ────────────────────────────────────────────────
    def test_fresh_install_enrolls_and_enables(self):
        r = self._run("--server", "https://rp.example", "--pin", "123456")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self._calls()
        self.assertIn("AGENT enroll --server https://rp.example --pin 123456", calls)
        # v7.4.1: enable, then restart. `enable --now` starts a stopped unit and
        # does nothing for a running one, and a host that is being enrolled again
        # is a running one; `restart` does both.
        self.assertIn("SYSTEMCTL enable remotepower-agent", calls)
        self.assertIn("SYSTEMCTL restart remotepower-agent", calls)
        self.assertNotIn("enable --now", calls)
        self.assertTrue((self.root / "usr/local/bin/remotepower-agent").exists())
        self.assertTrue(
            (self.root / "etc/systemd/system/remotepower-agent.service").exists())

    # ── upgrade path ─────────────────────────────────────────────────
    def test_upgrade_skips_enroll_and_restarts(self):
        self._enrolled()
        r = self._run("--server", "https://rp.example", "--pin", "123456")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self._calls()
        self.assertNotIn("AGENT enroll", calls, "an upgrade must never re-enroll")
        self.assertIn("SYSTEMCTL daemon-reload", calls)
        self.assertIn("SYSTEMCTL restart remotepower-agent", calls)
        self.assertNotIn("enable --now", calls,
                         "enable --now is a no-op on a running unit — the agent "
                         "would keep running under the OLD unit definition")
        # Credentials untouched.
        self.assertIn("token=xyz",
                      (self.root / "etc/remotepower/credentials").read_text())

    def test_upgrade_refreshes_the_unit_file(self):
        self._enrolled()
        unit = self.root / "etc/systemd/system/remotepower-agent.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Service]\nProtectKernelModules=yes\n")   # the bad old unit
        self._run()
        shipped = (self.dist / "client" / "remotepower-agent.service").read_text()
        self.assertEqual(unit.read_text(), shipped)

    def test_differing_unit_is_backed_up_before_replacement(self):
        self._enrolled()
        unit = self.root / "etc/systemd/system/remotepower-agent.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        custom = "[Service]\nEnvironment=HTTPS_PROXY=http://proxy:3128\n"
        unit.write_text(custom)
        self._run()
        backup = Path(str(unit) + ".rp-old")
        self.assertTrue(backup.exists(), "customized unit must be preserved")
        self.assertEqual(backup.read_text(), custom)

    def test_identical_unit_is_not_backed_up(self):
        self._enrolled()
        unit = self.root / "etc/systemd/system/remotepower-agent.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.dist / "client" / "remotepower-agent.service", unit)
        self._run()
        self.assertFalse(Path(str(unit) + ".rp-old").exists())

    def test_re_enroll_flag_enrolls_despite_credentials(self):
        self._enrolled()
        r = self._run("--server", "https://rp.example", "--pin", "654321",
                      "--re-enroll")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self._calls()
        self.assertIn("AGENT enroll --server https://rp.example --pin 654321", calls)
        # v7.4.1: the host was enrolled again, so the agent that is running holds the
        # old credentials; it must be restarted AFTER the new ones are written.
        self.assertNotIn("enable --now", calls)
        self.assertLess(calls.index("AGENT enroll"),
                        calls.index("SYSTEMCTL restart remotepower-agent"))

    # ── the cgroup-suicide guard ─────────────────────────────────────
    def test_inside_the_agents_own_service_the_restart_is_detached(self):
        """Inside the agent's cgroup the restart must be a DETACHED transient unit,
        or the script kills itself mid-run (the v6.2.1 remediation lesson: the
        first fleet batch died exactly this way). RP_CGROUP_FILE stands in for
        /proc/self/cgroup, so the guard can be driven (v7.4.1) and not only read."""
        self._enrolled()
        cg = self.tmp / "cgroup"
        cg.write_text("0::/system.slice/remotepower-agent.service\n")
        for extra in ((), ("--re-enroll",)):
            with self.subTest(extra=extra):
                self.log.unlink(missing_ok=True)
                env = {"RP_CGROUP_FILE": str(cg)}
                r = self._run("--server", "https://rp.example", "--pin", "123456",
                              *extra, env_extra=env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                calls = self._calls()
                self.assertIn("SYSTEMD-RUN --unit=rp-installer-restart --on-active=5 "
                              "systemctl restart remotepower-agent", calls)
                self.assertNotIn("SYSTEMCTL restart", calls)


if __name__ == "__main__":
    unittest.main()
