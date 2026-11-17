#!/usr/bin/env python3
"""v8.0.2 "C0verMatters": release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape checks.
Headline: what was missing from pages you already use: hosts and operating systems a page could not reach (one enrolment token for many hosts,
the software on Windows and macOS hosts) and the settings and numbers a page did not have. The behaviour lives in the test files of each change,
each guard watched failing before it was trusted; what is here is that the release is versioned, documented and carries them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "8.0.2"
CODENAME = "C0verMatters"
PREVIOUS = "8.0.1"     # the entry under it in CHANGELOG.md


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
                 if l.startswith("## ")][0]
        self.assertTrue(first.startswith(f'## v{V} — "{CODENAME}"'), first)

    def test_the_previous_release_is_a_shipped_one(self):
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn('## v8.0.1 — "L0gMatters" — 2026-11-16', changelog)
        self.assertLess(changelog.index(f"## v{V}"), changelog.index(f"\n## v{PREVIOUS}"))

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
        """gen-wiki.py's Home line hardcodes the codename: bump it or the wiki ships the previous release's name."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        text = p.read_text()
        self.assertIn(CODENAME, text)
        self.assertNotIn("L0gMatters", text)

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(vers, ["v8.0.0", "v8.0.1", "v8.0.2"], f"keep exactly 3 version docs: {vers}")

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
        self.assertEqual(cards, [V, "8.0.1", "8.0.0"], f"cap the cards at 3: {cards}")
        # The non-visible surface: the doc-search keyword attribute. A visible-text rename never touches it,
        # so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md",
                        "v7.4.6.md", "v7.4.7.md", "v7.4.8.md", "v7.4.9.md", "v7.5.0.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

    def test_the_dropped_release_stays_searchable(self):
        """v7.5.0 left the three kept cards. Its search keywords moved to the 'Older releases' card, so doc search still
        finds it by its codename, and the releases before it are still found."""
        html = _html()
        older = html[html.index("older versions history"):]
        kw = older[:older.index('"')].lower()
        self.assertIn("wh0lematters", kw)
        self.assertIn("ch0icematters", kw, "the releases before it are still found")
        self.assertIn("hon3stmatters", kw)
        self.assertIn("0ncematters", kw, "the releases before it are still found")
        self.assertIn("f1xablematters", kw)
        self.assertIn("spec1ficmatters", kw)

    def test_the_older_releases_card_says_where_it_starts(self):
        """The card names the newest release it stands for."""
        html = _html()
        i = html.index("<strong>Older releases</strong>")
        label = html[i:html.index("</summary>", i)]
        self.assertIn("v7.5.0 and earlier", label)


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof, watched failing before it was committed. This pins that
    they ship."""

    FILES = (
        "tests/test_v802.py",    # the release pins themselves
        "tests/test_scroll_cap_focus_rings_e2e.py",    # the keyboard focus ring of every control in the lists that scroll stays inside their edge (four lists, both engines measured by hand)
        "tests/test_v800_host_purge.py",               # the addresses a sensor queued for a host leave with it
    )

    def test_the_list_is_not_empty(self):
        self.assertGreater(len(self.FILES), 0)

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)


if __name__ == "__main__":
    unittest.main()
