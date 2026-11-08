#!/usr/bin/env python3
"""v7.4.8 "Hon3stMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape
checks. Headline: three screens that said something that was not true. A Problems row read "never" under Updated
(#56), the Thermal page showed a sensor limit of 65261.8 C (#54), and a host read "Fully Patched" while apt kept a
kernel update back (Discussion #30). The behaviour lives in their own test files, each guard watched failing before
it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.8"
CODENAME = "Hon3stMatters"
PREVIOUS = "7.4.7"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v8.0.0 bump. The STRICT pins for the current release live in tests/test_v800.py; what stays here is the
    shape: the surfaces must still agree with each other, whatever version they carry, and 7.4.8 has left the kept windows."""

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{_server_version()}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{_server_version()} \u2014 "'), first)

    def test_version_doc_has_left_the_keep_three_window(self):
        """docs/v7.4.8.md went at the v8.0.0 bump. The CHANGELOG entry is the record now."""
        self.assertFalse((_ROOT / f"docs/v{V}.md").exists(), f"docs/v{V}.md should be gone")

    def test_changelog_entry_has_no_template_left(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index(f"\n## v{PREVIOUS}")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_names_a_newer_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md") if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertNotIn(f"v{V}", vers)

    def test_it_is_still_in_the_readme_list(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], _server_version(), "the new release leads")
        self.assertIn(V, bullets)

    def test_its_card_left_and_its_codename_stays_searchable(self):
        html = _html()
        cards = re.findall(r"What's new \u2014 v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertNotIn(V, cards)
        older = html[html.index('older versions history'):]
        self.assertIn(CODENAME.lower(), older[:older.index('"')].lower())

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md", "v7.4.6.md", "v7.4.7.md", "v7.4.8.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(), f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheReviewHasLeftTheWindow(unittest.TestCase):
    """The review of 7.4.8 left the three kept reviews at the 8.0.0 bump. Its one finding stays counted in CHANGELOG.md."""

    def test_it_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.8.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "docs/security-review-7.4.9.md", "docs/security-review-7.5.0.md",
                    "docs/security-review-8.0.0.md", "server/html/index.html"):
            self.assertNotIn("security-review-7.4.8.md", (_ROOT / rel).read_text(), rel)

    def test_the_changelog_still_counts_its_issue(self):
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.8 \u2014 "):body.index("## v7.4.7 \u2014 ")]
        self.assertIn("too big for a float", body)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)
        self.assertNotIn("security-review-7.4.8.md", reviews)



class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of 7.4.7 are listed in tests/test_v747.py."""

    FILES = (
        "tests/test_problems_page.py",         # #56: the Updated column and its sort read one time
        "tests/test_problems_e2e.py",          # #56: a row with no alert shows its host's last report, in a browser
        "tests/test_raw_drive_sensors.py",     # #54: a limit that is not a temperature is no limit, and a drive's sensors follow its lines
        "tests/test_apt_kept_back.py",         # Discussion #30: a package apt keeps back is pending
        "tests/test_v748_security.py",         # the review: hostile values for every reader this release changed
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
