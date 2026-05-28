"""v3.3.2 release tests.

Strict version pins for v3.3.2. The v3.3.1 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.2 is a cache-bust + follow-through release:
  - The responsive device-table column-shedding (which prevents the
    Status column collapsing to a lone "…" when the docked sidebar
    leaves the table too little room) now applies in ALL contexts, not
    just installed PWAs — a narrow browser window gets it too. The
    earlier display-mode: standalone scope missed minimal-ui installs
    (the PWA default) and the plain browser entirely.
  - The version bump itself busts the service-worker cache (?v= +
    CACHE_NAME), so installed PWAs actually receive the v3.3.1/v3.3.2 UI
    fixes instead of serving the stale cache-first copy.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.3.2 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.3.2'

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


class TestColumnSheddingGeneralised(unittest.TestCase):
    """The device-table column-drop breakpoints must apply in the plain
    browser too, not just installed PWAs (display-mode-scoped)."""

    def setUp(self):
        self.css = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    def test_column_drop_not_display_mode_scoped(self):
        # The hostname/version/group/ip/os shifted breakpoints (1480/1280/
        # 1120/960/840) must not carry a display-mode condition.
        for px in (1480, 1280, 1120, 960, 840):
            line = re.search(rf'^@media[^\n]*max-width:\s*{px}px\)[^\n]*$',
                             self.css, re.MULTILINE)
            self.assertIsNotNone(line, f'shifted breakpoint {px}px missing')
            self.assertNotIn('display-mode', line.group(0),
                f'{px}px breakpoint must not be display-mode scoped')

    def test_status_cell_ellipsis_backstop(self):
        self.assertRegex(self.css,
            r'\.dev-status-cell\s*\{[^}]*overflow:\s*visible',
            'Status cell must not collapse to an ellipsis')


if __name__ == '__main__':
    unittest.main()
