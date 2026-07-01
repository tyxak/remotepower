#!/usr/bin/env python3
"""
Tests for v4.0.0 — the release that folds the whole post-v3.13 accumulation
together (PostgreSQL HA + relay satellites + load-balanced multi-node, encryption
on every hop, deep fleet visibility, and a security-hardening pass).

Holds the STRICT version-surface pins for this release. On the next bump these
become regex (see how tests/test_v3140.py was loosened to TestVersionBumpsLoosened).
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

VERSION = "4.0.0"
# v4.1.0: loosened to a 4.x regex — these are history checks now; the current
# release's exact pins live in the newest test_vXYZ (test_v410).


class TestVersionBumps(unittest.TestCase):
    """Every spot the version string must be bumped — loosened to a 4.x regex."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r"\d+\.\d+\.\d+")

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertRegex(txt, r"VERSION\s+=\s+'\d+\.\d+\.\d+'")

    def test_win_mac_agent_version(self):
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertRegex((_ROOT / rel).read_text(), r"VERSION = '\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertRegex(txt, r"remotepower-shell-v\d+\.\d+\.\d+")

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertRegex(txt, r"\?v=\d+\.\d+\.\d+")
        self.assertNotIn("?v=3.14.0", txt)
        self.assertNotIn("?v=3.13.0", txt)

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertRegex(txt, r"version-\d+\.\d+\.\d+-blue")

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(txt[:2000], r"v\d+\.\d+\.\d+")

    def test_version_doc_exists(self):
        # loosened: v4.0.0 has since rotated out of the kept set — assert the
        # *current* release's doc exists instead of the historical pin.
        self.assertTrue((_ROOT / f"docs/v{api.SERVER_VERSION}.md").exists())

    def test_old_version_doc_gone(self):
        # v3.14.0 became v4.0.0 — there is no separate v3.14.0 doc anymore.
        self.assertFalse((_ROOT / "docs/v3.14.0.md").exists())

    def test_whats_new_card_present(self):
        # loosened: assert the current release's What's-new card, not v4.0.0's.
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"What's new — v{api.SERVER_VERSION}", html)

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")


if __name__ == "__main__":
    unittest.main()
