#!/usr/bin/env python3
"""v7.4.5 "Int3rnalMatters" — what the folded version left behind.

7.4.5 (issue #55, a host can be marked internal) was never released on its own: it was folded into
v7.4.6 before it shipped, so the strict release pins live in tests/test_v746.py. What stays here is
the record that its security review left the window of three, and the list of test files that carry its proof.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestTheReviewLeftTheWindow(unittest.TestCase):
    """The review of 7.4.5 left the three kept reviews at the v7.4.8 bump. 7.4.5 never shipped on its own, so its history
    stays in CHANGELOG.md and in the 7.4.6 notes, and the 7.4.6 review writes out what it carries forward."""

    def test_it_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.5.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "docs/security-review-7.4.6.md",
                    "server/html/index.html"):
            self.assertNotIn("security-review-7.4.5.md", (_ROOT / rel).read_text(), rel)

    def test_the_changelog_still_counts_its_issues(self):
        # The 7.4.6 notes carried this count too; they left the window at the v7.4.9 bump, so the CHANGELOG is the record.
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.5 \u2014 "):]
        section = body[body.index("### Security"):][:900]
        self.assertIn("two issues", re.sub(r"\s+", " ", section))

    def test_the_reviews_that_left_the_window_before_it_are_still_gone(self):
        for gone in ("7.4.0", "7.4.2", "7.4.3", "7.4.4"):
            self.assertFalse((_ROOT / f"docs/security-review-{gone}.md").exists(), gone)
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
                self.assertNotIn(f"security-review-{gone}.md", (_ROOT / rel).read_text(), (gone, rel))


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof,
    watched failing before it was committed. This pins that they ship."""

    FILES = (
        "tests/test_v745_exposure_scope.py",    # #55: which addresses are private, what a report can say, what the switch does to the rows
        "tests/test_v745_exposure_ingest.py",   # #55: the grade through the real heartbeat and the real port audit
        "tests/test_v745_exposure_route.py",    # #55: the switch's route, the Exposure answer, the Checks row
        "tests/test_v745_host_addresses.py",    # #55: the Linux agent's addresses
        "tests/test_v745_exposure_e2e.py",      # #55: the Exposure page and the host's Ports card
        "tests/test_v745_seeder.py",            # #55: the demo hosts that carry the switch
        "tests/test_v745_security.py",          # the review: tenants, roles, hostile reports, stored values, redaction
        "tests/test_v745_security_e2e.py",      # the review: the real stack (tenants, origin, a race) and planted text in a browser
        "tests/test_v745_translations.py",      # the text the release added, in six languages
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
