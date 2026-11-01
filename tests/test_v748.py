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

    def test_server_version(self):
        self.assertEqual(_server_version(), V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        self.assertTrue(m.group(1).startswith(V + "-"), m.group(1))
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_every_static_page_carries_the_same_stamp(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_readme_badge(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_header_is_newest(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{V} — "{CODENAME}"'), first)

    def test_version_doc_exists_and_is_titled(self):
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

    def test_gen_wiki_codename(self):
        """gen-wiki.py's Home line hardcodes the codename — bump it or the
        wiki ships the previous release's name."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn(CODENAME, p.read_text())

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
        self.assertEqual(bullets[0], V, "the new release leads")

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], V, "the new release leads")
        # The sneaky non-visible surface: the doc-search keyword attribute. A
        # visible-text rename never touches it, so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_dropped_release_stays_searchable(self):
        """v7.4.4 left the three kept cards. Its search keywords moved to the
        'Older releases' card, so doc search still finds it by its codename."""
        html = _html()
        older = html[html.index('older versions history'):]
        kw = older[:older.index('"')]
        self.assertIn("spec1ficmatters", kw.lower())
        self.assertIn("m3asurematters", kw.lower(), "the release before it is still found")

    def test_the_older_releases_card_says_where_it_starts(self):
        """The card names the newest release it stands for."""
        html = _html()
        i = html.index("<strong>Older releases</strong>")
        label = html[i:html.index("</summary>", i)]
        self.assertIn("v7.4.4 and earlier", label)


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it names what it
    found, it says what it did not run, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.8.md"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed_and_is_the_latest(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.8.md", (_ROOT / rel).read_text(), rel)
        sec = (_ROOT / "docs/security.md").read_text()
        self.assertGreaterEqual(sec.count("latest is\n[security-review-7.4.8.md]") +
                                sec.count("latest:\n  [security-review-7.4.8.md]"), 2)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("This review covers everything that changed since 7.4.7", text)
        self.assertIn("were not run this time", text)           # CodeQL, the nginx scanners and nuclei
        self.assertIn("## Known and unchanged", text)
        self.assertIn("A live probe of the maintainer's own instance", text)
        self.assertIn("`apt` itself", text, "the agent was never run against a real apt")

    def test_it_names_its_finding_and_the_summary_has_one_row(self):
        text = self.text()
        self.assertIn("**one** issue", text)
        self.assertIn("A stored reading or limit too big for a float made the Thermal page and the Prometheus export fail", text)
        rows = re.findall(r"^\| ([1-9]) \|", self.raw(), re.M)
        self.assertEqual(rows, ["1"])

    def test_it_ran_the_scans_and_the_checks_it_says_it_did(self):
        text = self.text()
        for needle in ("bandit", "semgrep", "gitleaks", "pip-audit", "Hostile values through the real functions",
                       "Hostile text from apt", "The Updated cell", "The Prometheus export", "Mutation checks"):
            self.assertIn(needle, text, needle)

    def test_no_placeholder_is_left(self):
        for stub in ("@@", "TBD-", "SEMGREPAPIRESULT", "MUTATIONSRESULT"):
            self.assertNotIn(stub, self.raw(), stub)

    def test_it_reveals_no_command_for_the_attack(self):
        text = self.raw()
        for needle in ("curl", "X-Token", "wget", "nc -"):
            self.assertNotIn(needle, text, needle)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        body = (_ROOT / "CHANGELOG.md").read_text()
        body = body[body.index("## v7.4.8 — "):body.index("## v7.4.7 — ")]
        section = body[body.index("### Security"):][:400]
        self.assertIn("found one issue", re.sub(r"\s+", " ", section))
        notes = re.sub(r"\s+", " ", (_ROOT / "docs/v7.4.8.md").read_text())
        self.assertIn("One low issue was fixed before release", notes)

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new — v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.8.md", card)

    def test_three_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(reviews, ["security-review-7.4.6.md", "security-review-7.4.7.md", "security-review-7.4.8.md"])

    def test_the_review_that_left_the_window_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.4.5.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
            p = _ROOT / rel
            if p.exists():
                self.assertNotIn("security-review-7.4.5.md", p.read_text(), rel)

    def test_the_kept_reviews_do_not_send_a_reader_to_the_one_that_left(self):
        self.assertNotIn("7.4.5 review", self.text())


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
