#!/usr/bin/env python3
"""v7.4.2 "Re4lMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: a patch release for four
reports from a Docker install of 7.4.1. In each, the dashboard says one thing
and the host is doing another. The behaviour lives in the per-item test files,
each guard watched failing before it was trusted; what is here is that the
release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.2"
CODENAME = "Re4lMatters"
PREVIOUS = "7.4.1"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.4.3 bump. The STRICT pins for the current release
    live in tests/test_v743.py; what stays here is the shape: the surfaces
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

    def test_version_doc_left_the_keep_three_window(self):
        """v7.4.5 pushed v7.4.2 out of the three kept version docs. Its history
        stays in CHANGELOG.md."""
        self.assertFalse((_ROOT / f"docs/v{V}.md").exists(),
                         f"docs/v{V}.md should have been removed at the v7.4.5 bump")

    def test_changelog_entry_has_no_template_left(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index("\n## v7.4.1")]
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
        self.assertNotIn(V, cards, "v7.4.2 left the three kept cards at v7.4.5")
        # Its search keywords moved to the "Older releases" card, so doc search
        # still finds the release by its codename.
        older = html[html.index('older versions history'):]
        kw = older[:older.index('"')]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "the older-releases card must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it names
    what it found, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.2.md"

    def text(self):
        return re.sub(r"\s+", " ", (_ROOT / self.DOC).read_text())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.2.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("so this one covers both", text)
        self.assertIn("7.4.1 went out as a pre-release without a review of its own", text)
        self.assertIn("were not run this time", text)          # the nginx scanners
        self.assertIn("## Known and unchanged", text)

    def test_it_names_the_three_findings_and_the_summary_has_three_rows(self):
        text = self.text()
        self.assertIn("**three** issues", text)
        for needle in ("state files from `/tmp`", "turn into a FIFO", "certificate check off"):
            self.assertIn(needle, text)
        rows = re.findall(r"^\| ([123]) \|", (_ROOT / self.DOC).read_text(), re.M)
        self.assertEqual(rows, ["1", "2", "3"])

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", (_ROOT / self.DOC).read_text())

    def test_it_reveals_no_command_for_the_attack(self):
        text = (_ROOT / self.DOC).read_text()
        self.assertNotIn("mkfifo", text)
        self.assertNotIn("/tmp/remotepower-poll-interval", text)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        for rel, heading in (("CHANGELOG.md", "### Security"),):
            body = (_ROOT / rel).read_text()
            if rel == "CHANGELOG.md":
                body = body[body.index("## v7.4.2 \u2014 "):]      # the newer entries have a Security section too
            section = body[body.index(heading):][:900]
            self.assertIn("three issues", re.sub(r"\s+", " ", section), rel)

    def test_three_reviews_are_kept_and_this_is_one_of_them(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)
        self.assertIn("security-review-7.4.2.md", reviews)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof,
    watched failing before it was committed. This pins that they ship."""

    FILES = (
        "tests/test_v742_container_recovery.py",
        "tests/test_v742_container_excludes.py",
        "tests/test_v742_container_excludes_card_e2e.py",
        "tests/test_v742_snmp_memory.py",
        "tests/test_v742_snmp_card_e2e.py",
        "tests/test_v742_host_integrations.py",
        "tests/test_v742_host_integrations_e2e.py",
        "tests/test_v742_integration_trend.py",
        "tests/test_v742_translations.py",
        "tests/test_v742_agent_fifo.py",
        "tests/test_v742_drawer_focus_e2e.py",
        "tests/test_v742_recoveries_follow_the_window.py",
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
