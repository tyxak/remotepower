"""Strict version-surface pins for v6.1.2 "AfterglowMatters" — a
correctness-and-fit release: three reported bugs (two of which made a shipped
feature simply not work), a sweep of frontend defects, the first wave of the
performance programme, and optional modules a minimal homelab can switch off.

Feature/regression coverage lives in the sibling files:
  tests/test_v612_bugfixes.py  — the three reported bugs
  tests/test_v612_js_fixes.py  — the frontend defects
  tests/test_v612_modules.py   — the optional-module system

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the NEXT bump.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-ver-"))
_spec = importlib.util.spec_from_file_location("api_v612_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "6.1.2"

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(
            f"VERSION      = '{self.V}'",
            (_ROOT / "client/remotepower-agent.py").read_text(),
        )
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )

    def test_sw_and_cachebust(self):
        self.assertIn(
            f"remotepower-shell-v{self.V}", (_ROOT / "server/html/sw.js").read_text()
        )
        self.assertIn(f"?v={self.V}", _html())

    def test_no_stale_cachebust(self):
        self.assertNotIn("?v=6.1.1", _html())

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

    def test_changelog_header_is_afterglowmatters(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn('## v6.1.2 — "AfterglowMatters"', head)

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases") :]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        self.assertTrue(bullets[0].startswith(f'- **v{self.V} "AfterglowMatters"'))


class TestFeaturesDocStaysTablesOnly(unittest.TestCase):
    """features.md is a flat, tables-only snapshot — no changelog sections, no
    prose, no code fences. Enforced by grep in CLAUDE.md; enforced here too."""

    def test_no_prose_or_changelog_sections(self):
        import re

        text = (_ROOT / "docs/features.md").read_text()
        self.assertEqual(
            re.findall(r"^### |^## (?:v[0-9]|What.s new|Added in)|```", text, re.M),
            [],
        )


if __name__ == "__main__":
    unittest.main()
