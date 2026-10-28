#!/usr/bin/env python3
"""v7.4.3 "M3asureMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: the next batch of requests from
the same Docker install (#46 to #52): more of what the fleet knows measured and
alerted on, and a few rough edges of the HTTP monitors. The behaviour lives in
the per-item test files, each guard watched failing before it was trusted; what
is here is that the release contains them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "7.4.3"
CODENAME = "M3asureMatters"
PREVIOUS = "7.4.2"


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
        for dropped in ("v7.3.0.md", "v7.4.0.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_dropped_release_stays_searchable(self):
        """v7.4.0 left the three kept cards. Its search keywords moved to the
        'Older releases' card, so doc search still finds it by its codename."""
        html = _html()
        older = html[html.index('older versions history'):]
        kw = older[:older.index('"')]
        self.assertIn("f1nishmatters", kw.lower())


class TestTheSecurityReview(unittest.TestCase):
    """The review is part of the release: it exists, it is indexed where a reader looks, it names
    what it found, it says what it did not run, and the three kept reviews are the last three."""

    DOC = "docs/security-review-7.4.3.md"

    def raw(self):
        return (_ROOT / self.DOC).read_text()

    def text(self):
        return re.sub(r"\s+", " ", self.raw())

    def test_it_exists_and_is_indexed(self):
        self.assertTrue((_ROOT / self.DOC).exists())
        for rel in ("docs/README.md", "docs/security.md"):
            self.assertIn("security-review-7.4.3.md", (_ROOT / rel).read_text(), rel)

    def test_it_says_what_it_covers_and_what_it_did_not_run(self):
        text = self.text()
        self.assertIn("everything that changed since 7.4.2, the last reviewed release", text)
        self.assertIn("were not run this time", text)           # the nginx scanners
        self.assertIn("## Known and unchanged", text)
        self.assertIn("a live probe of the maintainer's own instance", text)

    def test_it_names_the_four_findings_and_the_summary_has_four_rows(self):
        text = self.text()
        self.assertIn("**four** issues", text)
        for needle in ("Six Test buttons that take an address or a recipient from the request",
                       "The integration list showed a tenant administrator more than a viewer sees",
                       "A host's report could make its own heartbeat fail",
                       "did not say that a window raises no alerts"):
            self.assertIn(needle, text)
        rows = re.findall(r"^\| ([1-9]) \|", self.raw(), re.M)
        self.assertEqual(rows, ["1", "2", "3", "4"])

    def test_no_placeholder_is_left(self):
        self.assertNotIn("@@", self.raw())

    def test_it_reveals_no_command_for_the_attack(self):
        text = self.raw()
        for needle in ("curl", "X-Token", "wget", "nc -"):
            self.assertNotIn(needle, text, needle)

    def test_the_changelog_and_the_notes_agree_on_the_count(self):
        for rel, heading in (("CHANGELOG.md", "### Security"), ("docs/v7.4.3.md", "## Security review")):
            body = (_ROOT / rel).read_text()
            section = body[body.index(heading):][:900]
            self.assertIn("four issues", re.sub(r"\s+", " ", section), rel)

    def test_the_card_links_the_review(self):
        html = _html()
        card = html[html.index("What's new — v" + V):]
        card = card[:card.index("</details>")]
        self.assertIn("docs/security-review-7.4.3.md", card)

    def test_three_reviews_are_kept_and_this_is_one_of_them(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)
        self.assertIn("security-review-7.4.3.md", reviews)

    def test_the_review_that_left_the_window_is_gone_everywhere(self):
        self.assertFalse((_ROOT / "docs/security-review-7.3.0.md").exists())
        for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html"):
            self.assertNotIn("security-review-7.3.0.md", (_ROOT / rel).read_text(), rel)


class TestTheDocsKeepWhatTheyPromised(unittest.TestCase):
    """A closing comment on a report said "we will say so in the docs"; the sentence has to be there."""

    def test_the_snmp_memory_note_says_what_the_laundry_does(self):
        text = (_ROOT / "docs" / "agentless-devices.md").read_text(encoding="utf-8")
        i = text.index("**Memory without the cache")
        para = text[i:text.index("\n- **", i + 10)]
        flat = " ".join(para.split())
        self.assertIn("FreeBSD", flat)
        self.assertIn("Laundry", flat)
        self.assertIn("count as in use", flat)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof,
    watched failing before it was committed. This pins that they ship."""

    FILES = (
        "tests/test_v743_monitors.py",          # #51, #52: an expected 4xx/5xx, the alert an edit stranded, method and TLS
        "tests/test_v743_monitor_form_e2e.py",  # #52: the form carries Method and Verify TLS both ways
        "tests/test_v743_maintenance_alerts.py",   # #48: a window that raises no alerts at all
        "tests/test_v743_maintenance_form_e2e.py", # #48: the window form, and the targets it could not save
        "tests/test_v743_disk_names.py",           # #47: names for drives, keyed on serial
        "tests/test_v743_disk_names_e2e.py",       # #47: the Hardware tab box and the fleet list
        "tests/test_v743_container_thresholds.py", # #50: the lines, the run, the alert and its close, the history
        "tests/test_v743_container_limits_e2e.py", # #50: the Tuning card, each host's form, the colours and trends
        "tests/test_v743_disk_io.py",              # #49: the agent's reading, the line, the alert, the history
        "tests/test_v743_disk_io_e2e.py",          # #49: the Hardware tab table, the host's boxes, the fleet's pane
        "tests/test_v743_prometheus.py",           # #46: the parsers, the connectors, the client, the handlers, the host card
        "tests/test_v743_prometheus_e2e.py",       # #46: the card with its box of lines, the round trip, a refused line
        "tests/test_v743_security.py",             # the review: tenant admins and the Test routes, the integration list, hostile reports
        "tests/test_v743_translations.py",      # the text the release added, in six languages
    )

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
