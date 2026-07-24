"""v6.4.0 — auto-patch "Reboot after upgrade if required" is finally conditional.

Field report: the checkbox said "if required" but every path rebooted after
every clean patch run. Now:
  - Linux (_SCHED_UPGRADE_REBOOT_CMD) reboots only on a need signal — the
    Debian/Ubuntu /var/run/reboot-required marker, needs-restarting -r
    (dnf/yum; rc!=0 = needed), or a newer installed kernel than the running
    one. No signal -> "reboot SKIPPED", exit 0.
  - Windows/macOS patch paths queue the new `reboot-if-required` verb instead
    of a bare `reboot`; the Windows agent consults its pending-reboot registry
    signals, macOS honestly never reboots for brew. Old agents report
    "unsupported command" and stay up (fail-safe).
  - `reboot-if-required` classifies as kind 'reboot' so the four-eyes approval
    gate still covers it (the v6.2.0 bare-`upgrade` bypass class).
The shell logic is DRIVEN in bash with fake roots, not just source-pinned.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v640-rir-"))
_spec = importlib.util.spec_from_file_location("api_v640_rir", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_wspec = importlib.util.spec_from_file_location(
    "winagent_v640_rir", ROOT / "client" / "remotepower-agent-win.py")
winagent = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(winagent)


class TestLinuxNeedCheck(unittest.TestCase):
    def test_command_carries_all_three_signals_and_the_skip(self):
        cmd = api._SCHED_UPGRADE_REBOOT_CMD
        for needle in ("/var/run/reboot-required", "needs-restarting",
                       "uname -r", "no reboot required, reboot SKIPPED",
                       "systemctl reboot"):
            self.assertIn(needle, cmd, needle)
        # ordering: the need-check must sit between the initrd guard and the
        # actual reboot
        self.assertLess(cmd.index("BADIRD"), cmd.index('NEED=""'))
        self.assertLess(cmd.index('NEED=""'), cmd.index("systemctl reboot"))

    @unittest.skipUnless(shutil.which("bash"), "bash not available")
    def _drive(self, setup):
        """Run the need-check tail of the real command against a fake root.
        Returns the produced stdout (WOULD-REBOOT marker or nothing)."""
        cmd = api._SCHED_UPGRADE_REBOOT_CMD
        tail = cmd[cmd.index('NEED=""'):].replace(
            "systemctl reboot || /sbin/reboot || reboot", "echo WOULD-REBOOT")
        d = Path(tempfile.mkdtemp())
        (d / "lib" / "modules").mkdir(parents=True)
        setup(d)
        tail = (tail
                .replace("/var/run/reboot-required", str(d / "reboot-required"))
                .replace("/lib/modules", str(d / "lib" / "modules"))
                .replace("/usr/lib/modules", str(d / "usr-lib-modules")))
        # neutralize a host needs-restarting binary so scenarios are hermetic
        r = subprocess.run(["bash", "-c", f'command(){{ return 1; }}; L=/dev/null; {tail}'],
                           capture_output=True, text=True, timeout=30)
        return r.stdout

    def _running_kernel_dir(self, d):
        (d / "lib" / "modules" / os.uname().release).mkdir(parents=True,
                                                           exist_ok=True)

    def test_no_signal_skips_the_reboot(self):
        out = self._drive(lambda d: self._running_kernel_dir(d))
        self.assertNotIn("WOULD-REBOOT", out)

    def test_debian_marker_reboots(self):
        def setup(d):
            self._running_kernel_dir(d)
            (d / "reboot-required").touch()
        self.assertIn("WOULD-REBOOT", self._drive(setup))

    def test_newer_installed_kernel_reboots(self):
        def setup(d):
            self._running_kernel_dir(d)
            (d / "lib" / "modules" / "999.0.0-newer").mkdir()
        self.assertIn("WOULD-REBOOT", self._drive(setup))


class TestServerQueuesTheConditionalVerb(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._devfile = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        api.save(api.DEVICES_FILE, {
            "lin1": {"name": "lin1", "os": "Debian 12"},
            "win1": {"name": "win1", "os": "Windows Server 2022"},
        })
        self.batches = []
        self._orig_batch = api._queue_command_batch
        api._queue_command_batch = lambda ids, cmd, actor: \
            self.batches.append((sorted(ids), cmd))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._queue_command_batch = self._orig_batch
        api.DEVICES_FILE = self._devfile
        api._LOAD_CACHE.clear()

    def test_autopatch_native_batch_uses_reboot_if_required(self):
        pol = {"id": "p1", "name": "p", "target": {"type": "all"},
               "reboot": True}
        api._autopatch_queue(pol, "tester")
        cmds = dict((tuple(ids), cmd) for ids, cmd in self.batches)
        self.assertIn((("win1",), "reboot-if-required"),
                      [(k, v) for k, v in cmds.items()
                       if v == "reboot-if-required"])
        self.assertNotIn("reboot", [c for _, c in self.batches],
                         "bare unconditional reboot must not be queued")
        lin_cmd = next(c for ids, c in self.batches if ids == ["lin1"])
        self.assertIn("no reboot required", lin_cmd)

    def test_unticked_policy_queues_no_reboot_at_all(self):
        pol = {"id": "p2", "name": "p", "target": {"type": "all"},
               "reboot": False}
        api._autopatch_queue(pol, "tester")
        joined = " ".join(c for _, c in self.batches)
        self.assertNotIn("reboot-if-required", joined)
        self.assertNotIn("systemctl reboot", joined)


class TestApprovalGateStillCovers(unittest.TestCase):
    def test_conditional_verb_classifies_as_reboot_kind(self):
        # An unmapped verb classifies 'other' and silently bypasses the
        # four-eyes gate — the exact v6.2.0 bare-`upgrade` class.
        self.assertEqual(api._command_kind("reboot-if-required"), "reboot")


class TestWindowsAgentVerb(unittest.TestCase):
    def test_skips_when_no_pending_reboot(self):
        # Off-Windows, _reboot_required() returns False (no winreg) — the verb
        # must report a clean skip, never fall through to shutdown.exe.
        orig = winagent._audit_mode
        winagent._audit_mode = lambda: False
        try:
            r = winagent.handle_command("reboot-if-required")
        finally:
            winagent._audit_mode = orig
        self.assertEqual(r["rc"], 0)
        self.assertIn("skipped", r["output"])

    def test_reboots_when_pending(self):
        orig_rr = winagent._reboot_required
        orig_audit = winagent._audit_mode
        orig_run = winagent.subprocess.run
        calls = []
        winagent._reboot_required = lambda: True
        winagent._audit_mode = lambda: False

        class _R:
            returncode = 0
            stdout = "ok"
            stderr = ""
        winagent.subprocess.run = lambda argv, **k: calls.append(argv) or _R()
        try:
            r = winagent.handle_command("reboot-if-required")
        finally:
            winagent._reboot_required = orig_rr
            winagent._audit_mode = orig_audit
            winagent.subprocess.run = orig_run
        self.assertEqual(r["rc"], 0)
        self.assertTrue(calls and "shutdown" in str(calls[0][0]).lower(),
                        f"expected a shutdown /r dispatch, got {calls}")

    def test_mac_agent_reports_honest_skip(self):
        src = (ROOT / "client" / "remotepower-agent-mac.py").read_text()
        self.assertIn("reboot-if-required", src)
        self.assertIn("brew upgrades never need one", src)


if __name__ == "__main__":
    unittest.main()
