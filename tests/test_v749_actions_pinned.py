#!/usr/bin/env python3
"""The GitHub Actions in the workflows are pinned to commits, and Dependabot waits a week (7.4.9).

A workflow line such as `uses: actions/checkout@v7` follows whatever the tag `v7` points at on the day the job runs. Whoever
controls that repository can move the tag, so a compromised action reaches the release workflow, which signs and publishes the
images, the same hour. A commit cannot be moved. Every `uses:` line is now `owner/repo@<40 hex> # vX.Y.Z`; Dependabot understands
that shape and moves the commit and the comment together. `tools/pin-actions.py` does the pinning and its `--check` is what is
held here, with controls that feed it the old shape.

Dependabot's cooldown holds a new release back for seven days. A compromised release is normally pulled within days, so an update
that old is the safer one to take; security updates are not delayed by it.
"""
import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _ROOT / "tools" / "pin-actions.py"
_WORKFLOWS = sorted((_ROOT / ".github" / "workflows").glob("*.y*ml"))
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"


def _load_tool():
    spec = importlib.util.spec_from_file_location("pin_actions", _TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(_WORKFLOWS, "no .github/workflows in this tree (a dist tarball leaves them out)")
class TestEveryActionIsPinned(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()

    def test_no_workflow_uses_a_tag(self):
        for f in _WORKFLOWS:
            with self.subTest(workflow=f.name):
                self.assertEqual(self.tool.unpinned(f.read_text()), [])

    def test_the_population_is_not_empty(self):
        # A checker over nothing passes. The three workflows hold 21 remote uses: lines at the time of writing.
        total = sum(len(self.tool.uses_lines(f.read_text())) for f in _WORKFLOWS)
        self.assertGreaterEqual(total, 15, "the checker found almost no `uses:` lines; its regex has probably stopped matching")

    def test_the_tool_agrees(self):
        r = subprocess.run([sys.executable, str(_TOOL), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestTheCheckerCanSeeTheOldShape(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tool = _load_tool()

    SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

    def test_a_tag_is_reported(self):
        for ref in ("v7", "v7.0.1", "main", "master"):
            with self.subTest(ref=ref):
                out = self.tool.unpinned(f"    steps:\n      - uses: actions/checkout@{ref}\n")
                self.assertEqual(len(out), 1, out)
                self.assertIn("not a commit", out[0])

    def test_a_commit_without_a_version_comment_is_reported(self):
        out = self.tool.unpinned(f"      - uses: actions/checkout@{self.SHA}\n")
        self.assertEqual(len(out), 1, out)
        self.assertIn("no version comment", out[0])

    def test_a_pinned_line_with_a_version_comment_passes(self):
        for text in (f"      - uses: actions/checkout@{self.SHA} # v7.0.1\n",
                     f"        uses: github/codeql-action/init@{self.SHA} # v4.39.1\n",
                     f"      - uses: docker/login-action@{self.SHA}   # v4\n"):
            with self.subTest(text=text.strip()):
                self.assertEqual(self.tool.unpinned(text), [])

    def test_a_short_commit_is_not_a_pin(self):
        out = self.tool.unpinned("      - uses: actions/checkout@3d3c42e # v7.0.1\n")
        self.assertEqual(len(out), 1, out)

    def test_local_actions_and_docker_images_are_not_actions_to_pin(self):
        self.assertEqual(self.tool.unpinned("      - uses: ./.github/actions/local\n      - uses: docker://alpine:3.20\n"), [])


class TestDependabotWaitsAWeek(unittest.TestCase):

    @unittest.skipUnless(_DEPENDABOT.exists(), "no .github/dependabot.yml in this tree")
    def test_every_ecosystem_has_a_cooldown_of_at_least_seven_days(self):
        text = _DEPENDABOT.read_text()
        blocks = re.split(r"(?m)^  - package-ecosystem:", text)[1:]
        self.assertGreaterEqual(len(blocks), 3, "github-actions, pip and docker are all watched")
        for block in blocks:
            name = block.split("\n", 1)[0].strip().strip('"')
            with self.subTest(ecosystem=name):
                m = re.search(r"(?m)^    cooldown:\n      default-days:\s*(\d+)\s*$", block)
                if m is None:
                    self.fail(f"{name} has no cooldown")
                self.assertGreaterEqual(int(m.group(1)), 7)

    def test_the_control_sees_a_block_without_one(self):
        block = '  - package-ecosystem: "pip"\n    directory: "/packaging"\n    schedule:\n      interval: "weekly"\n'
        self.assertIsNone(re.search(r"(?m)^    cooldown:\n      default-days:\s*(\d+)\s*$", block))


if __name__ == "__main__":
    unittest.main()
