#!/usr/bin/env python3
"""Strict version-surface pins for v4.10.0 — loosen to regex on the next bump
(see tests/test_v490.py for the loosened pattern). The v4.10.0 feature tests
live in tests/test_v4100_firewall.py, test_v4100_rag_sources.py and
test_v4100_ai_insights.py."""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("api_v4100_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestVersionBumps(unittest.TestCase):
    # v5.0.0: loosened from the exact "4.10.0" pin to track the CURRENT version
    # (the strict pin now lives in tests/test_v500.py). These stay as
    # version-surface CONSISTENCY checks across all the files that must agree.
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
        self.assertIn(f"?v={self.V}", (_ROOT / "server/html/index.html").read_text())

    def test_no_stale_cachebust(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertEqual(set(re.findall(r"\?v=(4\.9\.0[^\"&]*)", html)), set(),
                         "stale ?v=4.9.0 cache-busts left")

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_old_version_doc_pruned(self):
        self.assertFalse((_ROOT / "docs/v4.6.0.md").exists(),
                         "docs/v4.6.0.md should be pruned to keep last 5")

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}",
                      (_ROOT / "server/html/index.html").read_text())


if __name__ == "__main__":
    unittest.main()
