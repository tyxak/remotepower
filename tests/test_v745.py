#!/usr/bin/env python3
"""v7.4.5 "Int3rnalMatters" — what the folded version left behind.

7.4.5 (issue #55, a host can be marked internal) was never released on its own: it was folded into
v7.4.6 before it shipped, so the strict release pins live in tests/test_v746.py. What stays here is
the security review that was written for it and the list of test files that carry its proof.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it names
    what it found, it says what it did not run, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.5.md"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_says_where_its_version_went(self):
        self.assertIn("7.4.5 was folded into 7.4.6 before it was released", self.text())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.5.md", (_ROOT / rel).read_text(), rel)

    def test_security_md_points_at_it_as_the_latest(self):
        text = (_ROOT / "docs/security.md").read_text()
        self.assertGreaterEqual(text.count("latest is\n[security-review-7.4.5.md]") +
                                text.count("latest:\n  [security-review-7.4.5.md]"), 2)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("everything that changed since 7.4.4, the last reviewed release", text)
        self.assertIn("were not run this time", text)           # the nginx scanners
        self.assertIn("## Known and unchanged", text)
        self.assertIn("a live probe of the maintainer's own instance", text)

    def test_it_names_the_findings_and_the_summary_has_two_rows(self):
        text = self.text()
        self.assertIn("**two** issues", text)
        self.assertIn("A request to the new route that did not say what it wanted turned the switch off", text)
        self.assertIn("raised on a stored port list that is not a list of maps", text)
        rows = re.findall(r"^\| ([1-9]) \|", self.raw(), re.M)
        self.assertEqual(rows, ["1", "2"])

    def test_it_ran_the_scans_and_the_sweeps_it_says_it_did(self):
        text = self.text()
        for needle in ("bandit", "semgrep", "gitleaks", "pip-audit", "CodeQL", "nuclei",
                       "Who may do what", "Hostile input to every route", "Hostile input to the new route",
                       "Hostile heartbeats", "A race", "Stored values the code did not write",
                       "Planted text in a real browser", "Mutation checks"):
            self.assertIn(needle, text, needle)

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())

    def test_it_reveals_no_command_for_the_attack(self):
        text = self.raw()
        for needle in ("curl", "X-Token", "wget", "nc -"):
            self.assertNotIn(needle, text, needle)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        for rel, heading in (("CHANGELOG.md", "### Security"), ("docs/v7.4.6.md", "## Security review")):
            body = (_ROOT / rel).read_text()
            if rel == "CHANGELOG.md":
                body = body[body.index("## v7.4.5 \u2014 "):]
            section = body[body.index(heading):][:900]
            self.assertIn("two issues", re.sub(r"\s+", " ", section), rel)

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new \u2014 v7.4.6"):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.5.md", card)

    def test_three_reviews_are_kept_and_this_is_one_of_them(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.4.3.md", "security-review-7.4.4.md", "security-review-7.4.5.md"])

    def test_the_review_that_left_the_window_is_gone_everywhere(self):
        for gone in ("7.4.0", "7.4.2"):
            self.assertFalse((_ROOT / f"docs/security-review-{gone}.md").exists(), gone)
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
                self.assertNotIn(f"security-review-{gone}.md", (_ROOT / rel).read_text(), (gone, rel))

    def test_the_kept_reviews_do_not_send_a_reader_to_the_one_that_left(self):
        """This review is self-contained: the items it carries forward are written out, not pointed at."""
        self.assertNotIn("7.4.2 review", self.text())


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
