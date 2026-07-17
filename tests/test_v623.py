"""v6.2.3 "Un1fyMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened to the live version). This is a consolidation/tidy release;
the behaviour pieces are tested in their own files: the tunnel listen-port option
in test_v520_features.py (TestHandlers.test_tunnel_create_*), the _read_valid
sweep coverage in test_v612_pydantic.py, and the dampening de-duplication in
test_v430_metricdamp.py.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v623-"))
_spec = importlib.util.spec_from_file_location("api_v623_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.2.3"
CODENAME = "Un1fyMatters"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, V)

    def test_agent_versions(self):
        self.assertIn(
            f"VERSION      = '{V}'",
            (_ROOT / "client/remotepower-agent.py").read_text(),
        )
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{V}", (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={V}", _html())

    def test_no_stale_cachebust(self):
        self.assertNotIn("?v=6.2.2", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{V}.md").exists())

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 3, f"expected exactly 3 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{V}", _html())

    def test_whats_new_cards_capped_at_three(self):
        self.assertEqual(_html().count("What's new — v"), 3)

    def test_whats_new_card_is_doc_searchable(self):
        """The data-keywords attribute embeds the codename as a lowercase search
        term — the surface a visible-text rename always misses."""
        html = _html()
        i = html.index(f"What's new — v{V}")
        card = html[max(0, i - 2200):i]
        self.assertIn(CODENAME.lower(), card)

    def test_changelog_header(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn(f'## v{V} — "{CODENAME}"', head)

    def test_gen_wiki_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn(CODENAME, p.read_text(),
                      "gen-wiki.py's Home line hardcodes the codename — bump it")

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        self.assertTrue(bullets[0].startswith(f'- **v{V} "{CODENAME}"'))


class TestConsolidationSweep(unittest.TestCase):
    """Guardrails for the v6.2.3 consolidation — keep the collapsed idioms
    collapsed and the removed duplication removed."""

    @classmethod
    def setUpClass(cls):
        cls.api_src = (_CGI / "api.py").read_text()
        cls.app_js = (_ROOT / "server/html/static/js/app.js").read_text()
        cls.html = _html()

    def test_read_valid_helper_exists_and_is_used(self):
        self.assertIn("def _read_valid(model):", self.api_src)
        # The sweep wired the helper into the bulk of body-reading handlers.
        self.assertGreater(self.api_src.count("_read_valid(request_models."), 200)

    def test_dampening_not_duplicated_in_general_pane(self):
        # The General-pane duplicates were removed; Alert parameters is the home.
        self.assertNotIn("cfg-metric-fba", self.html)
        self.assertNotIn("cfg-snmp-fba", self.html)
        self.assertIn("ap-metric-fails", self.html)
        self.assertIn("ap-snmp-fails", self.html)

    def test_dead_tls_container_section_fns_removed(self):
        self.assertNotIn("function showTLSSection", self.app_js)
        self.assertNotIn("function showContainerSection", self.app_js)

    def test_tls_page_autoloads_both_panels(self):
        # The ACME "needs a manual Refresh" fix: navigating to tls loads both.
        self.assertRegex(self.app_js, r"name === 'tls'[^\n]*loadTLS\(\)[^\n]*loadAcme\(\)")


class TestWebtermSilencesCryptoDeprecation(unittest.TestCase):
    """The webterm daemon must filter asyncssh's CryptographyDeprecationWarning
    BEFORE importing asyncssh (the warning fires at import) — else it spams stderr
    and the log monitor raises it as a recurring log_alert."""

    def test_filter_precedes_asyncssh_import(self):
        src = (_ROOT / 'server/webterm/remotepower-webterm.py').read_text()
        self.assertIn('CryptographyDeprecationWarning', src)
        self.assertLess(src.index('filterwarnings'), src.index('    import asyncssh'),
                        'the warning filter must run before asyncssh is imported')


if __name__ == "__main__":
    unittest.main()
