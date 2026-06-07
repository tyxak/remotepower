"""v3.2.2 release tests.

Loosened to regex — v3.3.0 now holds the strict pin (test_v330.py).
Feature regression tests for v3.2.2 remain here; only the version-pin
assertions relax to pattern-only so future bumps don't break them.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.3.0 now holds the strict pin (test_v330.py)."""

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
        # v3.2.2 release notes must stay present forever
        # notes recorded in CHANGELOG.md; per-version docs pruned to last 5
        self.assertIn('3.2.2', (REPO_ROOT / 'CHANGELOG.md').read_text())

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

    def test_scheduler_dedup_guard(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('last_fired_minute', text,
            'process_schedule must stamp last_fired_minute to prevent duplicate firings')
        self.assertIn('current_minute = now // 60', text,
            'process_schedule must compute current_minute for the dedup guard')


if __name__ == '__main__':
    unittest.main()
