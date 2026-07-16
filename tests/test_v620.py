"""v6.2.0 "Daem0nMatters" — release pins.

The CURRENT release carries the strict version pins (older test_vXYZ.py files
have theirs loosened to regex). Feature behaviour is tested in the dedicated
files: test_v613_priv_group / _defender / _usb / _disk_usage / _reliability.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v613-"))
_spec = importlib.util.spec_from_file_location("api_v613", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    # v6.2.1: loosened from the "6.2.0" literal to the live version, exactly as
    # the convention instructs on each bump. The STRICT pins for the current
    # release live in tests/test_v621.py; what stays valuable here is that
    # every version surface remains in lockstep with SERVER_VERSION.
    V = api.SERVER_VERSION

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
        self.assertNotIn("?v=6.1.2", _html())

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

    # test_whats_new_card_is_doc_searchable removed in v6.2.3: the v6.2.0
    # What's-new card aged out of the keep-3 in-app cards (its data-keywords
    # searchability is no longer applicable). The v6.2.0 CHANGELOG entry — the
    # durable history — is still pinned below.

    def test_changelog_header(self):
        # v6.2.1: loosened from the [:400] head window (newer releases sit
        # above this one now) — the entry itself must remain.
        self.assertIn('## v6.2.0 — "Daem0nMatters"',
                      (_ROOT / "CHANGELOG.md").read_text())

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[: block.index("Full history")]
        bullets = [ln for ln in block.splitlines() if ln.startswith("- **v")]
        self.assertLessEqual(len(bullets), 5, "README 'Recent releases' caps at 5")
        # v6.2.1: codename dropped from the pin (the live top release owns it).
        self.assertTrue(bullets[0].startswith(f'- **v{self.V} "'))


class TestNewEventsRegistered(unittest.TestCase):
    """Every event added this release, in one place — a registry entry that never
    reaches WEBHOOK_EVENTS is an event nobody can subscribe to."""

    NEW = ("priv_group_added", "av_realtime_off", "av_realtime_on", "usb_device_added")

    def test_all_in_registry(self):
        for ev in self.NEW:
            self.assertIn(ev, api.EVENT_REGISTRY, ev)

    def test_all_in_derived_webhook_events(self):
        # WEBHOOK_EVENTS is DERIVED from EVENT_REGISTRY as (name, label, default)
        # triples — an event missing here is one nobody can subscribe to.
        names = {row[0] for row in api.WEBHOOK_EVENTS}
        for ev in self.NEW:
            self.assertIn(ev, names, ev)

    def test_kinds_exist_in_the_channel_matrix(self):
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        for ev in self.NEW:
            self.assertIn(api.EVENT_REGISTRY[ev]["kind"], kinds, ev)


class TestNewRoutes(unittest.TestCase):
    NEW = ("/api/reliability", "/disk-usage", "/disk-usage/scan")

    def test_registered(self):
        src = (_CGI / "api.py").read_text()
        for r in self.NEW:
            self.assertIn(f"'{r}'", src, r)


if __name__ == "__main__":
    unittest.main()
