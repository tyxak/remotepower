"""Strict version-surface pins for v5.7.0 "F4ct0rMatters" — the refactor-and-fix
release (New-UI theming/accent/light-mode fixes reported by @AndiBSE, api.py
decomposition into bound modules, whole-tree config-secret encryption,
multi-table Postgres RLS, lazy pages + parallel fonts).

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the NEXT bump,
the same way test_v540 / test_v550 / test_v560 were loosened.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v570-test-"))
_spec = importlib.util.spec_from_file_location("api_v570_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    # Loosened to dynamic on the v5.8.0 bump (same as test_v540/v550/v560):
    # these now pin whole-surface consistency for the CURRENT version.
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
        # every ?v= must be the current version — no lingering 5.6.0 busts
        self.assertNotIn("?v=5.6.0", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())

    def test_changelog_codename(self):
        self.assertIn('## v5.7.0 — "F4ct0rMatters"', (_ROOT / "CHANGELOG.md").read_text())


class TestF4ct0rMattersWiring(unittest.TestCase):
    """A few load-bearing surfaces this release introduced/changed."""

    def test_bound_modules_present(self):
        for m in ("notify.py", "checks.py", "tickets_handlers.py",
                  "provisioning_handlers.py", "backups_handlers.py", "cmdb_handlers.py"):
            self.assertTrue((_CGI / m).exists(), m)

    def test_ticket_lifecycle_events_registered(self):
        for ev in ("ticket_opened", "ticket_resolved"):
            self.assertIn(ev, api.WEBHOOK_EVENT_NAMES)

    def test_contributor_credited(self):
        self.assertIn("@AndiBSE", (_ROOT / "CONTRIBUTORS.md").read_text())


if __name__ == "__main__":
    unittest.main()
