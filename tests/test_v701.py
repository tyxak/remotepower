"""v7.0.1 "C0llapseMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: the sidebar collapses when you
ask it to — open alerts were holding it open in every mode, and between 721 and
768 pixels the Collapse button did nothing at all. The behaviour for both lives
in test_v700_sidebar_autohide.py (class contract) and
test_v700_sidebar_autohide_e2e.py (the rendered geometry, which is the only
place either fault was ever visible).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v701-"))
_spec = importlib.util.spec_from_file_location("api_v701_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "7.0.1"
CODENAME = "C0llapseMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.0.2 bump. The STRICT pins for the current release
    live in tests/test_v702.py; what stays here is the shape — the surfaces
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

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{api.SERVER_VERSION}-blue",
                      (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{api.SERVER_VERSION} — "'), first)

    def test_version_doc_still_exists_inside_the_keep_three_window(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")

    def test_gen_wiki_carries_a_codename(self):
        """gen-wiki.py's Home line hardcodes the codename. Which one it is
        belongs to the current release's pins; that it is not the one from two
        releases ago belongs here."""
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
        # This release still has a card, and it still carries its own codename
        # in the doc-search keywords — the surface a visible-text rename never
        # touches.
        self.assertIn(V, cards)
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_version_doc(self):
        dropped = "v6.4.2.md"
        for rel in ("README.md", "docs/README.md", "server/html/index.html",
                    "docs/features.md"):
            p = _ROOT / rel
            if p.exists():
                self.assertNotIn(dropped, p.read_text(),
                                 f"{rel} still links the deleted {dropped}")
class TestTheFixesAreInThisRelease(unittest.TestCase):
    """A release pin, not a behavioural one — the proofs live in the two
    sidebar files. This asserts the release actually contains them, so a
    version bump that shipped without the fix would be caught here."""

    def test_the_alert_pin_is_the_derived_class(self):
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        self.assertNotIn("has-active-alert", css)
        self.assertIn("body.sidebar-collapsed.sidebar-alert-pinned", css)

    def test_the_rail_rules_start_at_the_drawer_ceiling_plus_one(self):
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        m = re.search(r"@media \(min-width: (\d+)px\) \{\s*"
                      r"body\.sidebar-collapsed \.sidebar \{", css)
        self.assertTrue(m, "the collapse-rail block moved or changed shape")
        self.assertEqual(int(m.group(1)), 721)

    def test_the_keep_hiding_option_shipped(self):
        self.assertIn("acct-autohide-thru-alerts", _html())
        self.assertIn("toggleAutohideThroughAlerts", _js("app.js"))


