"""Strict version-surface + feature pins for v6.0.1 "RefineMatters" — the
refinement release (whole-project polish/hardening/correctness pass, sidebar
reorg, real world map, single-device auto-patch, PDF patch export, cert-expiry
alert, two new alerts: read-only remount + mail-queue backlog).

TestVersionBumps loosened to dynamic (V = api.SERVER_VERSION) on the v6.1.0
bump — see tests/test_v610.py for the new strict version-surface pins.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v601-test-"))
_spec = importlib.util.spec_from_file_location("api_v601_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
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
        self.assertNotIn("?v=6.0.0", _html())

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


class TestRefineMattersFeatures(unittest.TestCase):
    def test_new_alert_events_registered(self):
        for ev in ("readonly_fs", "readonly_fs_cleared", "mailq_high", "mailq_normal"):
            self.assertIn(ev, api.EVENT_REGISTRY, ev)
        # recover events resolve their firing counterparts
        self.assertIn("readonly_fs", api.EVENT_REGISTRY["readonly_fs_cleared"]["resolves"])
        self.assertIn("mailq_high", api.EVENT_REGISTRY["mailq_normal"]["resolves"])

    def test_new_alert_kinds_exist(self):
        kinds = {k for k, _l, _g in api.CHANNEL_KIND_DEFS}
        self.assertIn("mailq", kinds)
        # readonly_fs rides the existing 'storage' kind
        self.assertEqual(api.EVENT_REGISTRY["readonly_fs"]["kind"], "storage")

    def test_cert_expiry_alert_on_by_default(self):
        # firing gate defaults on now (behavioural default covered in test_v3140).
        self.assertIn("cert_expiry_alerts_enabled', True)",
                      (_CGI / "api.py").read_text())

    def test_autopatch_single_device_target(self):
        html = _html()
        self.assertIn('value="device"', html)          # target-type option
        self.assertIn("autopatch-target-device", html)  # device combo

    def test_patch_report_pdf_export(self):
        self.assertIn('data-action="exportPatchPdf"', _html())

    def test_app_catalog_under_automation(self):
        html = _html()
        auto = html.find('data-group="automation"')
        sched = html.find('data-group="scheduling"')
        cat = html.find('data-page="catalog"')
        self.assertGreater(auto, 0)
        self.assertTrue(auto < cat < sched, "App catalog should sit in the Automation group")


if __name__ == "__main__":
    unittest.main()
