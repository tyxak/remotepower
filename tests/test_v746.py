#!/usr/bin/env python3
"""v7.4.6 "F1xableMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: four reports from the same Docker
install (#55 to #58). #55, a host can be marked internal, was built as v7.4.5 and
folded into this release before it shipped; its proofs stay in tests/test_v745*.py.
The behaviour of the other three lives in their own test files, each guard watched
failing before it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.6"
CODENAME = "F1xableMatters"
PREVIOUS = "7.4.5"     # the entry under it in CHANGELOG.md: the folded version


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.4.9 bump. The STRICT pins for the current release
    live in tests/test_v749.py; what stays here is the shape: the surfaces
    must still agree with each other, whatever version they carry."""

    def test_server_version_shape(self):
        self.assertRegex(_server_version(), r"^\d+\.\d+\.\d+$")

    def test_agents_match_the_server(self):
        v = _server_version()
        self.assertIn(f"VERSION      = '{v}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{v}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_every_static_page_carries_the_same_stamp(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{_server_version()}-blue",
                      (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{_server_version()} — "'), first)

    def test_version_doc_has_left_the_keep_three_window(self):
        """docs/v7.4.6.md went at the v7.4.9 bump. The CHANGELOG entry is the record now."""
        self.assertFalse((_ROOT / f"docs/v{V}.md").exists(), f"docs/v{V}.md should be gone")

    def test_changelog_entry_has_no_template_left(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index(f"\n## v{PREVIOUS}")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_carries_a_codename(self):
        """gen-wiki.py's Home line hardcodes the codename. Which one it is
        belongs to the current release's pins; that it is not this older one
        belongs here."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertNotIn(f"v{V}", vers)

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], _server_version(), "the new release leads")
        self.assertIn(V, bullets)

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], _server_version(), "the new release leads")
        self.assertNotIn(V, cards)
        # The card left at the v7.4.9 bump. Its search keywords moved to the 'Older releases' card, so doc search
        # still finds it by its codename.
        older = html[html.index('older versions history'):]
        self.assertIn(CODENAME.lower(), older[:older.index('"')].lower())

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.5.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheFoldedVersion(unittest.TestCase):
    """7.4.5 never shipped on its own. Nothing a reader sees may announce it as a release, and the
    entry that records what it built says where it went."""

    def test_the_changelog_keeps_its_entry_as_a_folded_one(self):
        heads = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v7.4.5 ")]
        self.assertEqual(len(heads), 1, heads)
        self.assertIn("Int3rnalMatters", heads[0])
        self.assertTrue(heads[0].endswith("folded into v7.4.6 (no standalone release)"), heads[0])

    def test_the_changelog_carries_what_it_built(self):
        self.assertFalse((_ROOT / "docs/v7.4.5.md").exists())
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.5 \u2014 "):]
        body = body[:body.index("\n## v", 1)]               # this entry only, whatever its length
        self.assertIn("internal", body.lower())             # the notes of 7.4.6 carried this too; they left at the v7.4.9 bump

    def test_no_surface_announces_a_release_that_never_shipped(self):
        readme = (_ROOT / "README.md").read_text()
        self.assertNotIn('**v7.4.5 "', readme)
        self.assertNotIn("What's new \u2014 v7.4.5", _html())
        self.assertNotIn("(v7.4.5.md)", (_ROOT / "docs/README.md").read_text())

    def test_its_codename_stays_searchable(self):
        html = _html()
        older = html[html.index('older versions history'):]
        self.assertIn("int3rnalmatters", older[:older.index('"')].lower())


class TestTheReviewLeftTheWindow(unittest.TestCase):
    """The review of 7.4.6 left the three kept reviews at the v7.4.9 bump. Its two findings stay counted in CHANGELOG.md."""

    def test_it_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.6.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "docs/security-review-7.4.7.md",
                    "docs/security-review-7.4.8.md", "docs/security-review-7.4.9.md", "server/html/index.html"):
            self.assertNotIn("security-review-7.4.6.md", (_ROOT / rel).read_text(), rel)

    def test_the_changelog_still_counts_its_issues(self):
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.6 \u2014 "):body.index("## v7.4.5 \u2014 ")]
        section = body[body.index("### Security"):][:700]
        self.assertIn("two issues", re.sub(r"\s+", " ", section))

    def test_the_reviews_that_left_the_window_before_it_are_still_gone(self):
        for gone in ("7.4.3", "7.4.4", "7.4.5"):
            self.assertFalse((_ROOT / f"docs/security-review-{gone}.md").exists(), gone)
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
                self.assertNotIn(f"security-review-{gone}.md", (_ROOT / rel).read_text(), (gone, rel))


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it
    was committed. This pins that they ship. The proofs of #55 are listed in tests/test_v745.py."""

    FILES = (
        "tests/test_v746_peer_direction.py",    # #58: the agent leaves out what the host accepted, the server's rule, the heartbeat contract
        "tests/test_v746_cve_fix_status.py",    # #57: the scan per release, the alert option and the re-alert, the report and the readers
        "tests/test_v746_cve_fix_page.py",      # #57: the page counts a finding as the server does, and the demo data keeps the contract
        "tests/test_v746_cve_fix_e2e.py",       # #57: the tiles, the filter, the host view and the Settings option, in a browser
        "tests/test_v746_translations.py",      # #57: the text the release added, in six languages
        "tests/test_v746_resolve_refresh.py",   # #56: resolving an alert by hand makes its host report; the three agents read it
        "tests/test_v746_drive_lines_thermal.py",  # #54: the Thermal page and the risk score hold a drive to its own lines
        "tests/test_v746_thermal_e2e.py",       # #54: the sensor table paints a drive by its own state, in a browser
        "tests/test_v746_security.py",          # the review: who may ask a host to report, a strict switch, hostile records and stores
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
