#!/usr/bin/env python3
"""v8.0.0 "Pil0tMatters": release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files have theirs loosened to shape checks.
Headline: what you can adjust in the interface (text size, tabs, named layouts, ten wizards) and what the agent finds on its own
(the apps a host runs), with three connectors, four monitor types, a read-only MCP endpoint and automatic image updates beside them.
The behaviour lives in the test files of each change, each guard watched failing before it was trusted; what is here is that the
release is versioned, documented and carries them.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent

V = "8.0.0"
CODENAME = "Pil0tMatters"
PREVIOUS = "7.5.0"     # the entry under it in CHANGELOG.md


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _server_version():
    src = (_ROOT / "server/cgi-bin/api.py").read_text()
    m = re.search(r"^SERVER_VERSION = '([^']+)'", src, re.M)
    return m.group(1) if m else None


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v8.0.1 bump. The STRICT pins for the current release live in tests/test_v801.py; what stays here is the shape: the
    surfaces must still agree with each other, whatever version they carry, and 8.0.0 is inside the kept windows."""

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{_server_version()}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines() if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{_server_version()} \u2014 "'), first)

    def test_version_doc_exists_and_is_titled(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} \u2014 "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary", "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index(f"\n## v{PREVIOUS}")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_names_a_newer_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_it_is_still_in_the_kept_windows(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md") if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertIn(f"v{V}", vers)
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], _server_version(), "the new release leads")
        self.assertIn(V, bullets)
        html = _html()
        cards = re.findall(r"What's new \u2014 v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertIn(V, cards)
        head = html[:html.index(f"What's new \u2014 v{V}")]
        self.assertIn(CODENAME.lower(), head[head.rindex('data-keywords="'):].lower())

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.3.0.md", "v7.4.0.md", "v7.4.1.md", "v7.4.2.md", "v7.4.3.md", "v7.4.4.md", "v7.4.5.md",
                        "v7.4.6.md", "v7.4.7.md", "v7.4.8.md", "v7.4.9.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md", "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(), f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)


if __name__ == "__main__":
    unittest.main()
