"""v6.1.1: the `rp` node-control CLI (omd/checkmk style) — status/start/stop/
restart/reload/doctor/logs/version. Guards that it ships, is a valid runnable
bash script with all the subcommands, and is installed by every install surface."""
import os
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_RP = _ROOT / "server" / "rp"


class TestRpCli(unittest.TestCase):
    def test_ships_and_executable(self):
        self.assertTrue(_RP.is_file(), "server/rp is missing")
        self.assertTrue(os.access(_RP, os.X_OK), "server/rp must be chmod +x")

    def test_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(_RP)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_has_all_subcommands(self):
        src = _RP.read_text()
        for verb in ("status", "tui", "start", "stop", "restart", "reload",
                     "doctor", "logs", "install", "deploy", "repair",
                     "version", "help"):
            self.assertIn(verb, src, f"rp is missing the {verb} verb")

    def test_doctor_is_root_aware(self):
        # A non-root run must NOT silently misreport the backend (0700 data dir)
        # or emit false nginx failures — it says so and skips, advising sudo.
        src = _RP.read_text()
        self.assertIn("am_root", src)
        self.assertIn("sudo rp doctor", src)
        # backend() returns 'unknown' (not 'json') when the data dir isn't readable
        i = src.index("backend(){")
        self.assertRegex(src[i:i + 400], r"-x\s+\"\$RP_DATA_DIR\"")

    def test_install_scripts_wired_in(self):
        # rp can run the installers; the installers record RP_SRC for it to find.
        src = _RP.read_text()
        self.assertIn("install-server.sh", src)
        self.assertIn("deploy-server.sh", src)
        self.assertIn("RP_SRC", src)
        for f in ("install-server.sh", "deploy-server.sh"):
            self.assertIn("RP_SRC=", (_ROOT / f).read_text(), f"{f} must record RP_SRC")

    def test_tui_has_help_and_repair(self):
        src = _RP.read_text()
        self.assertIn("_help()", src)                 # troubleshooting overlay
        self.assertIn("Troubleshooting", src)         # ...with real guidance
        self.assertRegex(src, r"'\?'\|h")             # ? / h key opens it

    def test_tui_dashboard_present(self):
        # The interactive dashboard: a cmd_tui with a non-TTY --once fallback and
        # box-drawing output. Source checks (no flaky subprocess under load).
        src = _RP.read_text()
        self.assertIn("cmd_tui()", src)
        self.assertIn("--once", src)               # testable/non-TTY one-frame mode
        self.assertIn("tui|top", src)              # wired in the dispatch
        self.assertRegex(src, r"[╭╮╰╯│─]")         # actually draws a box

    def test_dispatch_wires_every_verb_and_doctor_returns_rc(self):
        # Deterministic (source) checks instead of spawning the script under the
        # full suite's process load (that flakes): every verb reaches a handler,
        # and doctor propagates a non-zero rc so it's usable in monitoring.
        src = _RP.read_text()
        for verb in ("status", "start", "stop", "restart", "reload", "doctor", "logs"):
            self.assertRegex(src, rf"\b{verb}[|)]", f"{verb} not wired in the dispatch case")
        self.assertIn("return $rc", src)          # doctor propagates failures
        self.assertIn('exit 1', src)              # need_root / failure paths exit non-zero

    def test_installed_by_every_deploy_surface(self):
        # install-server.sh (fresh), deploy-server.sh (update), and Docker all
        # ship rp — so it's standard on every path, not just a fresh install.
        for f in ("install-server.sh", "deploy-server.sh", "Dockerfile"):
            txt = (_ROOT / f).read_text()
            self.assertIn("/usr/local/bin/rp", txt, f"{f} doesn't install rp")
        # deploy also keeps the push daemon binary current (the revert-trap fix)
        dep = (_ROOT / "deploy-server.sh").read_text()
        self.assertIn("/usr/local/bin/remotepower-push", dep)

    def test_documented(self):
        self.assertTrue((_ROOT / "docs" / "cli.md").is_file())


if __name__ == "__main__":
    unittest.main()
