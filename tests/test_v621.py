"""v6.2.1 "In1tMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened to the live version). The release's behaviour itself is
tested in tests/test_v621_patch_safety.py (upgrade-command module guard,
gated patch-window reboot, agent-unit hardening guardrail).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v621-"))
_spec = importlib.util.spec_from_file_location("api_v621_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "6.2.1"

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
        self.assertNotIn("?v=6.2.0", _html())

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

    def test_whats_new_cards_capped_at_three(self):
        self.assertEqual(_html().count("What's new — v"), 3)

    def test_whats_new_card_is_doc_searchable(self):
        """The data-keywords attribute embeds the codename as a lowercase search
        term — the surface a visible-text rename always misses."""
        html = _html()
        i = html.index(f"What's new — v{self.V}")
        card = html[max(0, i - 1600):i]
        self.assertIn("in1tmatters", card)

    def test_changelog_header(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn('## v6.2.1 — "In1tMatters"', head)

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        self.assertTrue(bullets[0].startswith(f'- **v{self.V} "In1tMatters"'))


if __name__ == "__main__":
    unittest.main()
