"""v3.4.1 release tests.

Strict version pins for v3.4.1. The v3.4.0 strict pins loosen to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.4.1's theme is "bind it together": three cohesion features that connect
surfaces which previously lived on separate pages —
  - a per-device unified Timeline (fleet events + command runs in one stream),
  - a Fleet health score (0-100 rollup of the Needs Attention signals), and
  - a Fleet posture Report (patches + CVE + health + compliance) with on-demand
    export and scheduled email delivery,
plus an extended command palette that can deep-link into a device's timeline.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to  # noqa: E402


class TestVersionBumps(unittest.TestCase):
    """v3.4.1 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.4.1'

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


class TestV341Routes(unittest.TestCase):
    """Each new path must reach its handler through the real dispatcher."""

    def test_routes_registered(self):
        for method, path, handler in (
                ('GET', '/api/devices/abc/timeline', 'handle_device_timeline'),
                ('GET', '/api/fleet/health',         'handle_fleet_health'),
                ('GET', '/api/report/fleet',         'handle_fleet_report'),
                ('GET', '/api/report/schedule',      'handle_report_schedule_get'),
                ('PUT', '/api/report/schedule',      'handle_report_schedule_set')):
            self.assertEqual(routes_to(method, path), handler,
                             f'{method} {path} must route to {handler}')


class TestV341Backend(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_handlers_defined(self):
        for fn in ('def handle_device_timeline(',
                   'def _timeline_event_detail(',
                   'def handle_fleet_health(',
                   'def _fleet_health(',
                   'def _health_grade(',
                   'def _build_fleet_report(',
                   'def _fleet_report_csv_bytes(',
                   'def handle_fleet_report(',
                   'def _render_report_email(',
                   'def _maybe_send_scheduled_report(',
                   'def handle_report_schedule_get(',
                   'def handle_report_schedule_set('):
            self.assertIn(fn, self.API, f'{fn} missing from api.py')

    def test_health_in_home_bundle(self):
        # The home bundle must carry the health rollup so the dashboard panel
        # renders without a second request.
        self.assertIn("'health':       _fleet_health()", self.API)

    def test_scheduled_report_wired_into_heartbeat(self):
        # The cron-driven report send must run on the heartbeat hot path.
        self.assertIn("_safe(_maybe_send_scheduled_report", self.API)

    def test_report_schedule_is_admin_gated(self):
        # The schedule mutation must require admin (it can email fleet posture).
        m = re.search(r'def handle_report_schedule_set\(.*?\n(.*?)\ndef ',
                      self.API, re.DOTALL)
        self.assertIsNotNone(m)
        self.assertIn('require_admin_auth()', m.group(1))

    def test_health_score_weights_present(self):
        self.assertIn('_HEALTH_WEIGHTS', self.API)


class TestV341Frontend(unittest.TestCase):
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    CSS = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    def test_timeline_page_present(self):
        self.assertIn('data-page="timeline"', self.HTML)
        self.assertIn('id="page-timeline"', self.HTML)
        self.assertIn('function enterTimeline(', self.APP)
        self.assertIn('function loadTimeline(', self.APP)
        self.assertIn("name === 'timeline'", self.APP)

    def test_health_panel_present(self):
        self.assertIn('id="home-health"', self.HTML)
        self.assertIn('function _renderHomeHealth(', self.APP)
        self.assertIn('_renderHomeHealth(home.health)', self.APP)
        self.assertIn('function openDeviceTimeline(', self.APP)

    def test_reports_page_present(self):
        self.assertIn('data-page="reports"', self.HTML)
        self.assertIn('id="page-reports"', self.HTML)
        self.assertIn('function loadReports(', self.APP)
        self.assertIn('function downloadFleetReport(', self.APP)
        self.assertIn('function saveReportSchedule(', self.APP)

    def test_palette_extended_with_timeline(self):
        # The palette must offer a per-device timeline jump + the new pages.
        self.assertIn('openDeviceTimeline(d.id)', self.APP)
        self.assertIn("['Timeline', 'timeline']", self.APP)
        self.assertIn("['Reports', 'reports']", self.APP)

    def test_timeline_css_present(self):
        # Per the CSP rule, styling lives in styles.css, not inline.
        for cls in ('.tl-row', '.tl-dot', '.tl-chip', '.hh-wrap', '.rep-grid'):
            self.assertIn(cls, self.CSS, f'{cls} missing from styles.css')

    def test_no_inline_style_in_new_markup(self):
        # New pages must not introduce inline style= attributes (CSP L1).
        for marker in ('id="page-timeline"', 'id="page-reports"', 'id="home-health"'):
            idx = self.HTML.find(marker)
            self.assertNotEqual(idx, -1)
            # Scan the ~1200 chars following the marker for a style= attribute.
            window = self.HTML[idx:idx + 1200]
            self.assertNotIn('style=', window,
                             f'inline style= found near {marker} (CSP violation)')


if __name__ == '__main__':
    unittest.main()
