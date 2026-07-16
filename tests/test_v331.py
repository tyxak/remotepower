"""v3.3.1 release tests.

Strict version pins for v3.3.1. The v3.3.0 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.1 is a correctness + polish release on top of v3.3.0:
  - OFFLINE detection hardening: per-device threshold
    (max(global ttl, poll_interval * OFFLINE_MISSED_POLLS) + grace) plus a
    debounce (offline_pending) so a single stale/late sample can no longer
    flap a device OFFLINE → ONLINE in the same second. Bar is now 5 missed
    polls.
  - Maintenance windows resolve a device-scoped target id to its hostname.
  - Action buttons aligned across pages (icon vs raw glyph), and the ACME
    force-renew button gets its missing icon.
  - PWA standalone clipping fix (device-table Status column + nav badge).
  - "Did you know?" tips on the About page.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.3.2 now holds the strict pin (test_v332.py).
    Version-pin assertions relax to pattern-only; the v3.3.1 feature
    regression tests below stay."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(\d+\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(\d+\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v\d+\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=\d+\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-\d+\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.3.1 release notes must stay present forever
        # notes recorded in CHANGELOG.md; per-version docs pruned to last 5
        self.assertIn('3.3.1', (REPO_ROOT / 'CHANGELOG.md').read_text())


class TestOfflineHardening(unittest.TestCase):
    """OFFLINE flap fixes: per-device threshold + debounce + 5-missed bar."""

    def setUp(self):
        self.api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_missed_polls_is_five(self):
        m = re.search(r'^OFFLINE_MISSED_POLLS\s*=\s*(\d+)', self.api, re.MULTILINE)
        self.assertIsNotNone(m, 'OFFLINE_MISSED_POLLS constant missing')
        self.assertEqual(int(m.group(1)), 5,
            'offline bar must be 5 missed polls')

    def test_per_device_threshold_helper(self):
        self.assertIn('def _offline_thresholds(', self.api,
            '_offline_thresholds helper must exist')
        # v6.2.2: the multiplier is now operator-configurable (offline_missed_polls,
        # default OFFLINE_MISSED_POLLS) — still scales with the poll interval.
        self.assertIn('poll * _missed', self.api,
            'threshold must scale with the device poll interval')
        self.assertIn("_config_ro().get('offline_missed_polls', OFFLINE_MISSED_POLLS)", self.api,
            'the missed-poll multiplier must be config-backed')

    def test_debounce_pending_state(self):
        # check_offline_webhooks must arm a candidate before firing OFFLINE
        self.assertIn("offline_pending", self.api,
            'debounce requires an offline_pending candidate map')
        m = re.search(
            r'def check_offline_webhooks\(.*?\n(?:.*?\n){0,120}',
            self.api, re.DOTALL)
        self.assertIsNotNone(m, 'check_offline_webhooks missing')
        self.assertIn('offline_pending', m.group(0),
            'check_offline_webhooks must use offline_pending for debounce')

    def test_pending_cleared_on_device_delete(self):
        # v5.0.0 (#F1): the per-device cleanup moved into the shared _purge_device
        # helper (handle_device_delete + bulk-delete both call it).
        m = re.search(
            r'def _purge_device\(.*?\n(?:.*?\n){0,80}',
            self.api, re.DOTALL)
        self.assertIsNotNone(m, '_purge_device missing')
        self.assertIn('offline_pending', m.group(0),
            'device delete must purge offline_pending')


class TestMaintenanceTargetName(unittest.TestCase):
    def test_maintenance_list_resolves_target_name(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(
            r'def handle_maintenance_list\(.*?\n(?:.*?\n){0,55}',
            api, re.DOTALL)
        self.assertIsNotNone(m, 'handle_maintenance_list missing')
        self.assertIn('target_name', m.group(0),
            'maintenance list must resolve a device target to target_name')


class TestUiPolish(unittest.TestCase):
    def setUp(self):
        self.appjs = client_js()
        self.css   = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        self.html  = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_acme_force_renew_has_icon(self):
        # The force-renew button used to be empty; it must now carry an icon.
        self.assertIn("_icon('refresh',14)", self.appjs,
            'ACME force-renew button must render the refresh icon')

    def test_pwa_installed_clipping_block(self):
        # Scoped to any installed mode (not a browser tab) so it also
        # covers minimal-ui installs, not just standalone.
        self.assertIn('not (display-mode: browser)', self.css,
            'installed-PWA media query missing')
        self.assertIn('max-width: 1480px', self.css,
            'PWA column-drop breakpoint shift missing')

    def test_status_cell_ellipsis_backstop(self):
        self.assertRegex(self.css,
            r'\.dev-status-cell\s*\{[^}]*overflow:\s*visible',
            'Status cell must not collapse to an ellipsis')

    def test_manifest_minimal_ui_default(self):
        manifest = (REPO_ROOT / 'server' / 'html' / 'manifest.json').read_text()
        self.assertIn('"minimal-ui"', manifest,
            'PWA manifest display should default to minimal-ui')

    def test_did_you_know_tips(self):
        self.assertIn('_DYK_TIPS', self.appjs, 'Did-you-know tips array missing')
        self.assertIn('function nextAboutTip', self.appjs,
            'nextAboutTip handler missing')
        self.assertIn('about-tip-text', self.html,
            'About-page tip element missing')


if __name__ == '__main__':
    unittest.main()
