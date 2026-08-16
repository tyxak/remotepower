"""v6.4.1 "Cust0dyMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened). Headline: the built-in KMIP key server (opt-in sidecar,
mutual TLS, encrypted recovery bundle) plus two field-reported monitor fixes.

Feature behaviour lives in test_v640_kmip.py and test_v640_monitor_save.py —
this file pins the RELEASE surfaces the bump checklist covers.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v641-"))
_spec = importlib.util.spec_from_file_location("api_v641_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "6.4.1"
CODENAME = "Cust0dyMatters"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v6.4.2 bump: the CURRENT release owns the exact-version
    pins (test_v642.TestVersionBumps). What survives here is the SHAPE — the
    fields must exist and stay in lockstep — plus this release's own history,
    which never changes."""

    def test_server_version_shape(self):
        self.assertRegex(api.SERVER_VERSION, r"^\d+\.\d+\.\d+$")

    def test_agent_versions_match_the_server(self):
        v = api.SERVER_VERSION
        self.assertIn(f"VERSION      = '{v}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{v}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        # The CURRENT release owns the exact stamp (test_v642); only the
        # lockstep shape survives here.
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_readme_badge_shape(self):
        self.assertRegex((_ROOT / "README.md").read_text(),
                         r"version-\d+\.\d+\.\d+-blue")

    def test_changelog_still_carries_this_release(self):
        chg = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f'## v{V} — "{CODENAME}"', chg)

    def test_version_doc_exists_and_is_titled(self):
        p = _ROOT / f"docs/v{V}.md"
        if not p.exists():
            self.skipTest(f"docs/v{V}.md trimmed by the keep-3 retention policy")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        p = _ROOT / f"docs/v{V}.md"
        if not p.exists():
            self.skipTest(f"docs/v{V}.md trimmed by the keep-3 retention policy")
        body = p.read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")

    def test_docs_keep_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v\d+\.\d+\.\d+", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)

    def test_whats_new_card_present_and_capped(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")

    def test_no_dangling_links_to_the_dropped_version_doc(self):
        dropped = "v6.2.3.md"
        for rel in ("README.md", "docs/README.md", "server/html/index.html",
                    "docs/features.md"):
            p = _ROOT / rel
            if p.exists():
                self.assertNotIn(dropped, p.read_text(),
                                 f"{rel} still links the deleted {dropped}")


class TestKmipShipsInThisRelease(unittest.TestCase):
    """The headline subsystem's release-surface wiring (behaviour is covered
    in test_v640_kmip.py)."""

    def test_daemon_and_unit_ship(self):
        self.assertTrue((_ROOT / "server/kmip/remotepower-kmipd.py").exists())
        self.assertTrue((_ROOT / "packaging/remotepower-kmipd.service").exists())

    def test_docs_and_features_row(self):
        self.assertTrue((_ROOT / "docs/kmip.md").exists())
        self.assertIn("KMIP key server", (_ROOT / "docs/features.md").read_text())

    def test_changelog_and_version_doc_cover_it(self):
        doc = _ROOT / f"docs/v{V}.md"
        if doc.exists():            # trimmed by keep-3 three releases on
            self.assertIn("KMIP", doc.read_text())
        chg = (_ROOT / "CHANGELOG.md").read_text()
        section = chg[chg.index(f"## v{V}"):chg.index("## v6.4.0")]
        self.assertIn("KMIP key server", section,
                      "KMIP ships in 6.4.1, not the already-released 6.4.0")

    def test_kmip_is_not_claimed_by_the_shipped_release(self):
        """v6.4.0 is already in production — it must not advertise 6.4.1 work.

        The CHANGELOG is the durable half and keeps every release forever, so
        that assertion stands. The per-version doc does NOT: docs/vX.Y.Z.md is
        keep-3, and v6.4.0.md was deleted at the v6.4.3 bump. Reading a file
        the retention policy is designed to remove would turn a routine bump
        into a red suite, so it is checked only while it exists.
        """
        chg = (_ROOT / "CHANGELOG.md").read_text()
        v640 = chg[chg.index("## v6.4.0"):chg.index("## v6.3.0")]
        self.assertNotIn("KMIP key server", v640)
        doc = _ROOT / "docs/v6.4.0.md"
        if doc.exists():
            self.assertNotIn("KMIP", doc.read_text())


if __name__ == "__main__":
    unittest.main()
