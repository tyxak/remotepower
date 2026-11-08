#!/usr/bin/env python3
"""v7.4.7 "0nceMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape
checks. Headline: two reports from the same Docker install (#56, one list of problems, and #57, which CVE
findings the numbers count), and the Thermal, Disk and Host metrics work that followed 7.4.6. The behaviour
lives in their own test files, each guard watched failing before it was trusted; what is here is that the
release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.7"
CODENAME = "0nceMatters"
PREVIOUS = "7.4.6"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.5.0 bump. The STRICT pins for the current release live in tests/test_v750.py; what stays here is the
    shape: the surfaces must still agree with each other, whatever version they carry."""

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{_server_version()}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{_server_version()} \u2014 "'), first)

    def test_version_doc_has_left_the_keep_three_window(self):
        """docs/v7.4.7.md went at the v7.5.0 bump. The CHANGELOG entry is the record now."""
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
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md", "v7.4.6.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(), f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheReviewLeftTheWindow(unittest.TestCase):
    """The review of 7.4.7 left the three kept reviews at the v7.5.0 bump. Its one finding stays counted in CHANGELOG.md."""

    def test_it_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.7.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md",
                    "docs/security-review-7.4.9.md", "docs/security-review-7.5.0.md", "server/html/index.html"):
            self.assertNotIn("security-review-7.4.7.md", (_ROOT / rel).read_text(), rel)

    def test_the_changelog_still_counts_its_issue(self):
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.7 \u2014 "):body.index("## v7.4.6 \u2014 ")]
        section = body[body.index("### Security"):][:700]
        self.assertIn("found one issue", re.sub(r"\s+", " ", section))

    def test_the_reviews_that_left_the_window_before_it_are_still_gone(self):
        for gone in ("7.4.3", "7.4.4", "7.4.5", "7.4.6"):
            self.assertFalse((_ROOT / f"docs/security-review-{gone}.md").exists(), gone)
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
                self.assertNotIn(f"security-review-{gone}.md", (_ROOT / rel).read_text(), (gone, rel))


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of #55 are listed in tests/test_v745.py."""

    FILES = (
        "tests/test_problems.py",                 # #56: the read model, the two routes, the state on the three pages' data
        "tests/test_problems_page.py",            # #56: the page is registered everywhere, and everything it shows is translated
        "tests/test_problems_e2e.py",             # #56: the views, the history, every action and the state on the other pages, in a browser
        "tests/test_cve_count_option.py",         # #57: the count option on every counter, the badge, the digest and the Fleet query
        "tests/test_cve_store_readers.py",        # #57: every reader of the findings store is accounted for
        "tests/test_v747_security.py",            # the review: a stored alert of any shape, for every reader that failed on one
        "tests/test_e2e_harness_stderr_e2e.py",   # the browser harness keeps answering while the server logs a lot
        "tests/test_v700_sidebar_autohide_e2e.py",  # the page makes room for the pinned sidebar, measured
        "tests/test_thermal_sensor_history.py",   # any sensor has a history, bounded
        "tests/test_thermal_sensor_e2e.py",       # the Thermal page charts any sensor, in a browser
        "tests/test_disk_views_e2e.py",           # one entry for each filesystem, in a browser
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
