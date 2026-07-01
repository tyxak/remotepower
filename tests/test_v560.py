"""Strict version-surface pins for v5.6.0 "HeapMatters" — the IaC /
automation + alert-tuning release (Provisioning blueprint catalog + server-side
Terraform exec, Monitoring → Tuning with per-host alert mute, timesheet watchers).

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the next bump, the
same way test_v540 / test_v550 were loosened.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v560-test-"))
_spec = importlib.util.spec_from_file_location("api_v560_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "5.6.0"

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
        self.assertNotIn("?v=5.5.0", _html())

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
        self.assertIn('## v5.6.0 — "HeapMatters"', (_ROOT / "CHANGELOG.md").read_text())


class TestHeapMattersWiring(unittest.TestCase):
    """The opt-in surfaces that ship with this version."""

    def test_provisioning_handlers(self):
        for fn in ("handle_blueprints_list", "handle_blueprint_render",
                   "handle_blueprint_run", "_terraform_run", "_iac_execute_enabled"):
            self.assertTrue(hasattr(api, fn), fn)

    def test_alert_mute_handlers(self):
        for fn in ("handle_alert_mutes", "handle_alert_tuning", "_alert_muted"):
            self.assertTrue(hasattr(api, fn), fn)

    def test_timesheet_watch_handlers(self):
        for fn in ("handle_timesheet_watchers", "handle_timesheet_watchable",
                   "_can_view_timesheet"):
            self.assertTrue(hasattr(api, fn), fn)

    def test_page_modules_present(self):
        for m in ("app-provisioning.js", "app-tuning.js"):
            self.assertTrue((_CGI.parent / "html" / "static" / "js" / m).exists(), m)


if __name__ == "__main__":
    unittest.main()
