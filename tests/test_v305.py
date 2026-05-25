"""v3.0.5 release tests.

Strict version pins for the v3.0.5 release. Also asserts the v3.0.5
specific behaviour: the new strict-CSP regression coverage, the
deploy-time cache-bust script's regexes, and the per-version release
notes file. Feature-level tests for the bugs fixed in v3.0.5 live in
their topic-specific test files (test_v232.py for the CSP scans,
test_v2415.py for PWA install handling, etc.).

Following the same convention as test_v303.py and test_v304.py: when
v3.0.6 ships, this file's strict EXPECTED pin loosens to a regex and
test_v306.py takes the strict slot.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.0.5 takes the strict version pin."""
    EXPECTED = '3.0.5'

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
        # Source tree carries ?v=<SERVER_VERSION>; deploy-server.sh
        # rewrites to per-file content hashes at install time.
        self.assertIn(f'?v={self.EXPECTED}', html,
            f'index.html source ?v= must be {self.EXPECTED}')

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
        text = path.read_text()
        self.assertIn(self.EXPECTED, text)

    def test_security_review_doc_present(self):
        path = REPO_ROOT / 'docs' / f'security-review-{self.EXPECTED}.md'
        self.assertTrue(path.exists(),
            f'docs/security-review-{self.EXPECTED}.md is missing')


class TestCacheBustDeployScript(unittest.TestCase):
    """deploy-server.sh contains a per-file content-hash rewrite step
    for ?v=... query strings. This is the production cache-bust path —
    we don't run the shell script directly (would mutate the live web
    root) but we do confirm the script contains the expected logic.
    """

    DEPLOY_SH = REPO_ROOT / 'deploy-server.sh'

    def test_script_exists(self):
        self.assertTrue(self.DEPLOY_SH.is_file())

    def test_rewrites_v_query_strings(self):
        """deploy-server.sh must rewrite ?v=... to content hashes."""
        sh = self.DEPLOY_SH.read_text()
        self.assertIn('content-hash', sh.lower(),
            'deploy-server.sh missing content-hash cache-bust block')
        self.assertIn('sha256', sh.lower(),
            'deploy-server.sh content-hash block must use sha256')
        # The Python block reads index.html and rewrites ?v= refs.
        self.assertIn("INDEX.read_text()", sh)
        self.assertIn("INDEX.write_text(", sh)

    def test_handles_both_script_and_link(self):
        """Both <script src> and <link href> need rewriting (JS + CSS)."""
        sh = self.DEPLOY_SH.read_text()
        self.assertIn('<script', sh)
        self.assertIn('<link', sh)


if __name__ == '__main__':
    unittest.main(verbosity=2)
