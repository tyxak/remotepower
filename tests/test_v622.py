"""v6.2.2 "Pu1seMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened to the live version). The release's behaviour itself is
tested in the dedicated files: test_v622_modules_check.py (forced
kernel-module visibility check + condition alert), test_v622_delta_sysinfo.py
(negotiated heartbeat delta protocol), test_v622_keepalive.py (persistent
agent HTTP), test_v622_installer_upgrade.py (upgrade-in-place installer).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-"))
_spec = importlib.util.spec_from_file_location("api_v622_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "6.2.2"

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
        self.assertNotIn("?v=6.2.1", _html())

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
        self.assertIn("pu1sematters", card)

    def test_changelog_header(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn('## v6.2.2 — "Pu1seMatters"', head)

    def test_gen_wiki_codename(self):
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn('Pu1seMatters', p.read_text(),
                      "gen-wiki.py's Home line hardcodes the codename — bump it")

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        self.assertTrue(bullets[0].startswith(f'- **v{self.V} "Pu1seMatters"'))


class TestBackendIndexParity(unittest.TestCase):
    """v6.2.2 metric-prune index: `DELETE … WHERE ts <` needs a bare-ts index;
    the composite (device, ts) can't serve it. BOTH backends must carry it or
    the retention sweep full-scans on one of them."""

    def test_both_backends_define_the_ts_index(self):
        for rel in ("server/cgi-bin/storage.py", "server/cgi-bin/storage_pg.py"):
            src = (_ROOT / rel).read_text()
            self.assertIn("idx_metric_samples_ts", src, rel)


class TestLazyModuleLockstep(unittest.TestCase):
    """A module listed BOTH in index.html's <script> tags and app.js's
    _LAZY_PAGE_MODULES would load twice (double event listeners — the v3.3.0
    freeze-bug class); a module in NEITHER is dead code nobody can reach."""

    def _lazy_set(self):
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        block = js[js.index("_LAZY_PAGE_MODULES = {"):]
        block = block[:block.index("};")]
        import re
        return set(re.findall(r"'([a-z-]+\.js)'", block))

    def test_lazy_modules_not_also_boot_loaded(self):
        html = _html()
        for f in self._lazy_set():
            self.assertNotIn(f"static/js/{f}?", html,
                             f"{f} is lazy AND boot-loaded — it would load twice")

    def test_every_module_file_is_reachable(self):
        html = _html()
        lazy = self._lazy_set()
        jsdir = _ROOT / "server/html/static/js"
        # Files serving other standalone pages, not index.html.
        other_pages = {"fleet-query.js", "portal.js", "report.js", "status.js",
                       "swagger-init.js"}
        for f in sorted(p.name for p in jsdir.glob("app-*.js")) + ["wg-access.js"]:
            if f in other_pages:
                continue
            reachable = (f"static/js/{f}?" in html) or (f in lazy)
            self.assertTrue(reachable, f"{f} is neither boot-loaded nor lazy-mapped")


if __name__ == "__main__":
    unittest.main()
