#!/usr/bin/env python3
"""v7.4.4 "Spec1ficMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: the next request from the same
Docker install (#54), temperature lines for each drive, where the most specific
line wins. The behaviour lives in the per-item test files, each guard watched
failing before it was trusted; what is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.4"
CODENAME = "Spec1ficMatters"
PREVIOUS = "7.4.3"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.4.5 bump. The STRICT pins for the current release
    live in tests/test_v745.py; what stays here is the shape: the surfaces
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

    def test_version_doc_still_exists_inside_the_keep_three_window(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")
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
        self.assertIn(f"v{V}", vers)

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
        self.assertIn(V, cards)
        # The sneaky non-visible surface: the doc-search keyword attribute. A
        # visible-text rename never touches it, so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

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
    what it found, it says what it did not run, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.4.md"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.4.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("everything that changed since 7.4.3, the last reviewed release", text)
        self.assertIn("were not run this time", text)           # the nginx scanners
        self.assertIn("## Known and unchanged", text)
        self.assertIn("a live probe of the maintainer's own instance", text)

    def test_it_names_the_finding_and_the_summary_has_one_row(self):
        text = self.text()
        self.assertIn("**one** issue", text)
        self.assertIn("Saving or resetting a host's thresholds left nothing on the audit trail", text)
        rows = re.findall(r"^\| ([1-9]) \|", self.raw(), re.M)
        self.assertEqual(rows, ["1"])

    def test_it_ran_the_scans_and_the_sweeps_it_says_it_did(self):
        text = self.text()
        for needle in ("bandit", "semgrep", "gitleaks", "pip-audit", "CodeQL", "nuclei",
                       "Who may do what", "Hostile input to every route", "Hostile heartbeats",
                       "Planted text in a real browser", "Mutation checks"):
            self.assertIn(needle, text, needle)

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())

    def test_it_reveals_no_command_for_the_attack(self):
        text = self.raw()
        for needle in ("curl", "X-Token", "wget", "nc -"):
            self.assertNotIn(needle, text, needle)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        for rel, heading in (("CHANGELOG.md", "### Security"), ("docs/v7.4.4.md", "## Security review")):
            body = (_ROOT / rel).read_text()
            if rel == "CHANGELOG.md":
                body = body[body.index("## v7.4.4 \u2014 "):]
            section = body[body.index(heading):][:900]
            self.assertIn("one issue", re.sub(r"\s+", " ", section), rel)

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new \u2014 v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.4.md", card)

    def test_three_reviews_are_kept_and_this_is_one_of_them(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)
        self.assertIn("security-review-7.4.4.md", reviews)

    def test_the_review_that_left_the_window_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.0.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
            self.assertNotIn("security-review-7.4.0.md", (_ROOT / rel).read_text(), rel)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof,
    watched failing before it was committed. This pins that they ship."""

    FILES = (
        "tests/test_v744_drive_temp.py",     # #54: the lines, the alert and its close, the handlers, the agent's drive type
        "tests/test_v744_drive_temp_e2e.py", # #54: the Hardware tab's colour and boxes, the host's block, the fleet's pane
        "tests/test_v744_translations.py",   # the text the release added, in six languages
        "tests/test_v744_security.py",       # the review: the audit trail, the tenant and role checks, hostile reports, header injection, stored junk
        "tests/test_v744_security_e2e.py",   # the review: markup in a drive's strings stays text on the pages that print them
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
