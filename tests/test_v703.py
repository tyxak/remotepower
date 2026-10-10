#!/usr/bin/env python3
"""v7.0.3 "C4useMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: three failures that named the
wrong cause — a monitor reading a bot challenge as "host down", a TLS floor that
lowered one, and a test helper reporting isolation it was not providing. The
behaviour lives in the per-fix test files, each guard demonstrated failing
before it was trusted; what is here is that the release actually contains them.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v703-pins-"))
_spec = importlib.util.spec_from_file_location("api_v703_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "7.0.3"
CODENAME = "C4useMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.1.0 bump. The STRICT pins for the current release
    live in tests/test_v710.py; what stays here is the shape — the surfaces
    must still agree with each other, whatever version they carry."""

    def test_server_version_shape(self):
        self.assertRegex(api.SERVER_VERSION, r"^\d+\.\d+\.\d+$")

    def test_agents_match_the_server(self):
        v = api.SERVER_VERSION
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
        """index.html is not the only page with cache-busted assets — the
        portal, the status page, the report renderer, fleet-query and swagger
        all load the same bundles, and a page left behind serves a stale one.

        v7.0.3: `tools/bump_version.py` stamped index.html alone, so every bump
        since this guard was widened left five pages on the previous version and
        this test failed on the release commit. The tool derives the set from the
        directory now."""
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_bump_tool_stamps_every_surface_not_just_index(self):
        """The durable half of the fix above: assert the tool reads the
        directory rather than naming one file. A tool that hardcodes index.html
        passes every test in this file and re-breaks the one before it."""
        p = _ROOT / "tools/bump_version.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        src = p.read_text()
        self.assertIn("html_dir.glob('*.html')", src,
                      "bump_version.py must derive the stamped pages from the "
                      "html directory, not stamp index.html alone")

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{api.SERVER_VERSION}-blue",
                      (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{api.SERVER_VERSION} — "'), first)

    def test_version_doc_left_the_keep_three_window(self):
        """v7.3.0 pushed v7.0.3 out of the three kept version docs, and its
        security review out of the three kept reviews. Their history stays in
        CHANGELOG.md."""
        self.assertFalse((_ROOT / f"docs/v{V}.md").exists(),
                         f"docs/v{V}.md should have been removed at the v7.3.0 bump")
        self.assertFalse((_ROOT / f"docs/security-review-{V}.md").exists())

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
        self.assertEqual(bullets[0], api.SERVER_VERSION, "the new release leads")

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], api.SERVER_VERSION, "the new release leads")
        self.assertNotIn(V, cards, "v7.0.3 left the three kept cards at v7.3.0")

    def test_no_dangling_links_to_the_dropped_version_doc(self):
        for dropped in ("v7.0.0.md", "v7.0.3.md", "security-review-7.0.3.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")


if __name__ == "__main__":
    unittest.main()
