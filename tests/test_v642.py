"""v6.4.2 "Qu1etMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: per-container alert mutes and a
container log window that waits for the agent instead of toasting "queued".
Feature behaviour lives in test_v642_container_mute.py / _container_logs.py.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-"))
_spec = importlib.util.spec_from_file_location("api_v642_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.4.2"
CODENAME = "Qu1etMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, V)

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

    def test_no_dangling_links_to_the_dropped_version_doc(self):
        dropped = "v6.3.0.md"
        for rel in ("README.md", "docs/README.md", "server/html/index.html",
                    "docs/features.md"):
            p = _ROOT / rel
            if p.exists():
                self.assertNotIn(dropped, p.read_text(),
                                 f"{rel} still links the deleted {dropped}")


class TestReleaseSurfaceWiring(unittest.TestCase):
    """The two headline features must be reachable, not just present."""

    def test_container_mute_helpers_exist(self):
        for fn in ("_container_mute_set", "_alert_muted", "_alert_mute_set"):
            self.assertTrue(hasattr(api, fn), f"missing {fn}")

    def test_mute_buttons_are_wired_to_globals(self):
        js = _js("app-containers.js")
        for fn in ("muteContainer", "unmuteContainer"):
            self.assertIn(f'data-action-btn="{fn}"', js)
            self.assertIn(f"function {fn}(", js)

    def test_log_viewer_modal_and_handlers_exist(self):
        html = _html()
        for el in ("container-logs-modal", "container-logs-tail",
                   "container-logs-filter", "container-logs-progress",
                   "container-logs-body"):
            self.assertIn(f'id="{el}"', html, el)
        js = _js("app.js")
        for fn in ("openContainerLogs", "containerLogsRefetch",
                   "containerLogsFilter", "containerLogsToggleAuto",
                   "containerLogsCopy", "containerLogsDownload"):
            self.assertIn(f"function {fn}(", js, fn)

    def test_the_log_modal_is_body_level(self):
        """.container is a z-index:1 stacking context — a fixed overlay nested
        inside it can never rise above the sidebar (CLAUDE.md)."""
        html = _html()
        self.assertGreater(html.index('id="container-logs-modal"'),
                           html.index("<!-- /app -->"))

    def test_docs_cover_both_features(self):
        doc = (_ROOT / "docs/containers.md").read_text()
        self.assertIn("Muting one container", doc)
        self.assertIn("Viewing container logs", doc)
        feats = (_ROOT / "docs/features.md").read_text()
        self.assertIn("per-container mute", feats)
        self.assertIn("Container logs", feats)

    def test_features_md_stays_tables_only(self):
        body = (_ROOT / "docs/features.md").read_text()
        bad = re.findall(r"^### |^## (?:v[0-9]|What.s new|Added in)|```",
                         body, re.M)
        self.assertEqual(bad, [], f"features.md hygiene: {bad}")


if __name__ == "__main__":
    unittest.main()
