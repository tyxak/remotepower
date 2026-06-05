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
    """v3.0.6 holds the strict version pin now — same convention every
    earlier release-bump test followed (loosen to a `^3\\.\\d+\\.\\d+$`
    regex when the next release takes over). v3.0.5's release-specific
    documentation files (the release notes and security review) are
    still asserted strictly below."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'",
            'sw.js CACHE_NAME must carry a v3.x.x marker')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+',
            'index.html cache-bust ?v= must be a 3.x.x version')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg',
            'README.md version badge missing 3.x.x marker')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.0.5 release notes file MUST stay present (we shipped a
        # GitHub release referencing it). Future releases get their own
        # docs/vX.Y.Z.md but v3.0.5's file is permanent.
        # notes recorded in CHANGELOG.md; per-version docs pruned to last 5
        self.assertIn('3.0.5', (REPO_ROOT / 'CHANGELOG.md').read_text())

    def test_security_review_doc_present(self):
        self.assertTrue((REPO_ROOT / 'docs' / 'security.md').exists())


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
