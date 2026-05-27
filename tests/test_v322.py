"""v3.2.2 release tests.

Strict version pins for v3.2.2. The v3.2.1 strict pin loosens to regex
when this file ships, following the same convention every prior
release-bump test followed. v3.2.2 is a hotfix release — all major
feature regression tests stay in test_v320.py and test_v321.py.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.2.2 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.2.2'

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

    def test_max_fleet_events_raised(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r'^MAX_FLEET_EVENTS\s*=\s*(\d+)', text, re.MULTILINE)
        self.assertIsNotNone(m, 'MAX_FLEET_EVENTS missing from api.py')
        self.assertGreaterEqual(int(m.group(1)), 1000,
            'MAX_FLEET_EVENTS should be >= 1000 (raised from 200 in v3.2.2)')

    def test_nginx_body_size_raised(self):
        for conf in ('server/conf/remotepower.conf', 'docker/nginx-docker.conf'):
            text = (REPO_ROOT / conf).read_text()
            m = re.search(r'client_max_body_size\s+(\S+)', text)
            self.assertIsNotNone(m, f'client_max_body_size missing from {conf}')
            size = m.group(1).lower()
            self.assertNotEqual(size, '64k',
                f'{conf}: client_max_body_size still 64k — must be raised')


if __name__ == '__main__':
    unittest.main()
