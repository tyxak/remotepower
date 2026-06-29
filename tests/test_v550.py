"""Strict version-surface pins for v5.5.0 "ScaleMatters" — the persistent-tier +
enterprise release (keystone WSGI app server + out-of-band scheduler, hard
multi-tenancy + Postgres RLS, plus the folded-in enterprise-hardening program).

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the next bump, the
same way test_v540 / test_v541 were loosened. The keystone behaviour itself is
covered by test_v600_* (WSGI / scheduler / thread-safe storage) and test_v610_rls.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v550-test-"))
_spec = importlib.util.spec_from_file_location("api_v550_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "5.5.0"

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
        # the previous dev line was v5.4.1 (its -N suffixed cache busts)
        self.assertNotIn("?v=5.4.1", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())

    def test_changelog_codename(self):
        self.assertIn('## v5.5.0 — "ScaleMatters"', (_ROOT / "CHANGELOG.md").read_text())


class TestKeystoneWiring(unittest.TestCase):
    """The opt-in persistent-tier + tenancy surfaces ship with this version."""

    def test_units_present(self):
        for u in ("remotepower-wsgi.service", "remotepower-scheduler.service"):
            self.assertTrue((_ROOT / "server/conf" / u).exists(), u)

    def test_app_modules_present(self):
        for m in ("wsgi.py", "scheduler.py"):
            self.assertTrue((_CGI / m).exists(), m)

    def test_tenancy_rls_gate(self):
        self.assertTrue(hasattr(api, "_tenancy_rls_active"))

    def test_no_v6_labels_leaked(self):
        # the keystone was briefly labelled v6.0.0 then settled on v5.5.0
        for f in ("docs/features.md", "docs/scaling.md", "docs/deployment.md",
                  "server/conf/remotepower-wsgi.service",
                  "server/conf/remotepower-scheduler.service"):
            self.assertNotIn("v6.0.0", (_ROOT / f).read_text(), f)


if __name__ == "__main__":
    unittest.main()
