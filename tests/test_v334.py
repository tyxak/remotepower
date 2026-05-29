"""v3.3.4 release tests.

Strict version pins for v3.3.4. The v3.3.3 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.4 adds container image-update detection: the agent reports each
container's pulled image digest, and the server checks it against the
registry's current digest for that tag, flagging stale images on the
Containers page and (debounced) in the alert inbox. The behavioural
regression tests for that feature live in tests/test_image_updates.py;
this file only pins the version bump + that the feature is wired/shipped.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.3.4 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.3.4'

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertIn(f"'remotepower-shell-v{self.EXPECTED}'", sw,
            f'sw.js CACHE_NAME must be bumped to remotepower-shell-v{self.EXPECTED}')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn(f'?v={self.EXPECTED}', html,
            f'index.html cache-bust ?v= must be {self.EXPECTED}')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertIn(f'version-{self.EXPECTED}-blue.svg', text,
            'README.md version badge not bumped')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v<x.y.z> header')
        self.assertEqual(m.group(1), self.EXPECTED,
            f'CHANGELOG.md top entry is v{m.group(1)}, expected v{self.EXPECTED}')

    def test_release_notes_doc_present(self):
        path = REPO_ROOT / 'docs' / f'v{self.EXPECTED}.md'
        self.assertTrue(path.exists(), f'docs/v{self.EXPECTED}.md is missing')
        self.assertIn(self.EXPECTED, path.read_text())


class TestImageUpdatesShipped(unittest.TestCase):
    """The image-update detection feature must be present + wired."""

    def test_registry_module_present(self):
        path = REPO_ROOT / 'server' / 'cgi-bin' / 'image_registry.py'
        self.assertTrue(path.exists(), 'image_registry.py is missing')
        body = path.read_text()
        self.assertIn('def parse_image_ref', body)
        self.assertIn('def remote_digest', body)

    def test_scan_wired_into_dispatcher(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def run_image_scan_if_due', api)
        self.assertIn("_safe(run_image_scan_if_due", api)
        self.assertIn("'/api/image-updates'", api)

    def test_image_update_event_registered(self):
        api = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'image_update_available'", api)
        self.assertIn("'image_updated'", api)

    def test_whats_new_card_mentions_image_updates(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn("What's new — v3.3.4", html)


if __name__ == '__main__':
    unittest.main()
