"""Strict version-surface pins for v6.0.0 "ClarityMatters" — the v6 interface
overhaul (one flat UI, 12-domain sidebar accordion, left-nav Settings, always-on
standard modules, optional auto-hide sidebar, per-page documentation links),
promoted from the untagged v5.8.0 accumulator.

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the NEXT bump,
the same way test_v560 / test_v570 / test_v580 were loosened.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v600-test-"))
_spec = importlib.util.spec_from_file_location("api_v600_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    # v6.0.1: loosened to dynamic (tracks the current version) — test_v601 owns
    # the strict current-release pins now, same as test_v560/570/580 before it.
    V = api.SERVER_VERSION

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{self.V}",
                      (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={self.V}", _html())

    def test_no_stale_cachebust(self):
        # every ?v= must be the current version — no lingering 5.8.0 busts
        self.assertNotIn("?v=5.8.0", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 3, f"expected exactly 3 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())

    def test_changelog_has_claritymatters_entry(self):
        # ClarityMatters is no longer the top entry (loosened) — just assert its
        # release section still exists in the complete history.
        self.assertIn('## v6.0.0 — "ClarityMatters"',
                      (_ROOT / "CHANGELOG.md").read_text())


class TestClarityMattersInterface(unittest.TestCase):
    """The v6 interface is THE interface — the Industrial skin and the New/Old
    toggle are fully gone (guardrail against reintroduction)."""

    def test_no_industrial_skin_or_toggle(self):
        html = _html()
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertNotIn('data-ui', html)
        self.assertNotIn("dataset.ui", js)
        self.assertNotIn('data-action="setUIVersion"', html)

    def test_standard_modules_always_on(self):
        # the opt-in toggles for the now-standard modules are gone
        html = _html()
        for gone in ("cfg-tickets-enabled", "cfg-billing-enabled",
                     "cfg-kb-enabled", "cfg-show-provisioning", "cfg-file-manager"):
            self.assertNotIn(gone, html, gone)

    def test_autohide_sidebar_only(self):
        # sidebar auto-hide stays; the top-bar auto-hide was removed
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("toggleAutohideSidebar", js)
        self.assertNotIn("toggleAutohideTopbar", js)


if __name__ == "__main__":
    unittest.main()
