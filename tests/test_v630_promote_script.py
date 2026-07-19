"""v6.3.0: tools/promote.sh — the prod-promotion checklist as a script.

Source pins only (the script's real run is interactive and touches prod).
What matters: it stays shell-valid, keeps every checklist step, and keeps the
load-bearing gotchas that were each missed at least once when the checklist
was prose.
"""

import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "tools" / "promote.sh"


class TestPromoteScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _SCRIPT.exists():
            raise unittest.SkipTest("excluded from dist tree")
        cls.src = _SCRIPT.read_text()

    def test_shell_valid(self):
        r = subprocess.run(["bash", "-n", str(_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_plan_mode_runs_nothing_and_exits_zero(self):
        r = subprocess.run(["bash", str(_SCRIPT), "--plan", "v0.0.1", '"X"'],
                           capture_output=True, text=True, cwd=_ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nothing was executed", r.stdout)

    def test_all_checklist_steps_present(self):
        for step in ("pre-release", "changelog", "signed-tag", "push-prod",
                     "artifacts", "gh-release", "ghcr", "aur", "site", "wiki",
                     "codeql", "keep5"):
            self.assertIn(step, self.src, f"missing checklist step: {step}")

    def test_load_bearing_gotchas_encoded(self):
        # Each of these was missed at least once when the checklist was prose.
        self.assertIn("unreleased", self.src)          # CHANGELOG date flip gate
        self.assertIn("BEFORE any", self.src)          # push tags before fetch
        self.assertIn("detach-sign", self.src)         # sign built tarball directly
        self.assertIn("TARBALL LEAK", self.src)        # leak gate
        self.assertIn("_Sidebar", self.src)            # hand-curated wiki sidebar
        # the keep-5 warning must be present — and the flag must never appear
        # as an actual argument to a gh command, only inside the warning text
        self.assertIn("NEVER --cleanup-tag", self.src)
        for line in self.src.splitlines():
            if "gh release delete" in line:
                self.assertNotIn("--cleanup-tag", line, line)
        self.assertIn("pre-release-ok", self.src)      # the push-stamp gate

    def test_no_unattended_signing(self):
        # gpg signing must stay interactive with the operator — no wrapper
        # that feeds a passphrase or loosens pinentry.
        for bad in ("--passphrase", "--pinentry-mode loopback", "--batch --yes --sign"):
            self.assertNotIn(bad, self.src)

    def test_state_files_excluded_from_dist(self):
        mk = (_ROOT / "Makefile").read_text()
        self.assertIn("--exclude='./.promote-state'", mk)
        self.assertIn("--exclude='./.pre-release-ok'", mk)


if __name__ == "__main__":
    unittest.main()
