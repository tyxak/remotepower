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
    """Loosened to regex — v3.4.2 now holds the strict pin (test_v342.py).
    Version-pin assertions relax to pattern-only; the v3.4.1 feature
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
        # v3.4.1 release notes must stay present forever
        # v3.4.1 notes live in CHANGELOG.md; per-version docs/vX.Y.Z.md are
        # pruned to the last 5 (keep-last-5 housekeeping).
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        self.assertIn('3.4.1', chlog)


class TestV341Routes(unittest.TestCase):
    """Each new path must reach its handler through the real dispatcher."""

    def test_routes_registered(self):
        for method, path, handler in (
                ('GET', '/api/devices/abc/timeline', 'handle_device_timeline'),
                ('GET', '/api/fleet/health',         'handle_fleet_health'),
                ('GET', '/api/fleet/health/history', 'handle_fleet_health_history'),
                ('GET', '/api/fleet/timeline',       'handle_fleet_timeline'),
                ('GET', '/api/inventory/search',     'handle_inventory_search'),
                ('GET', '/api/schedule.ics',         'handle_schedule_ics'),
                ('GET', '/api/fleet/sla',            'handle_fleet_sla'),
                ('GET', '/api/fleet/capacity',       'handle_fleet_capacity'),
                ('GET', '/api/public/status',        'handle_public_status'),
                ('GET', '/api/report/fleet',         'handle_fleet_report'),
                ('GET', '/api/report/schedule',      'handle_report_schedule_get'),
                ('PUT', '/api/report/schedule',      'handle_report_schedule_set')):
            self.assertEqual(routes_to(method, path), handler,
                             f'{method} {path} must route to {handler}')


class TestV341HealthHistoryAndAlerts(unittest.TestCase):
    """Health-score history sampler + edge-triggered health_degraded alerting.

    The health_degraded event must be wired through every registry — the three
    silent ones (_ALERT_RULES, CHANNEL_KINDS, _webhook_title) are verified here
    by source-pin; the guardrail tests (test_v184/v223/v225) cover the rest."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()

    def test_history_handlers_defined(self):
        for fn in ('def _maybe_sample_health(',
                   'def handle_fleet_health_history(',
                   'def _check_health_webhooks('):
            self.assertIn(fn, self.API, f'{fn} missing from api.py')

    def test_sampler_and_check_wired_into_heartbeat(self):
        self.assertIn("_safe(_maybe_sample_health", self.API)
        self.assertIn("_safe(_check_health_webhooks", self.API)

    def test_health_degraded_in_all_server_registries(self):
        # All the formerly-scattered registries (_ALERT_RULES, CHANNEL_KINDS,
        # _webhook_title, _ALERT_RECOVER) now derive from the one
        # EVENT_REGISTRY row — pin that row's fields.
        idx = self.API.find("'health_degraded': dict(")
        self.assertGreater(idx, 0, 'health_degraded missing from EVENT_REGISTRY')
        row = self.API[idx: idx + 300]
        # _ALERT_RULES (silent if missed → never lands in Alerts inbox)
        self.assertIn('severity=None', row)
        # CHANNEL_KINDS routing (silent if missed → no routing row)
        self.assertIn("kind='health'", row)
        # _webhook_title (silent-ish if missed → falls back to raw event)
        self.assertIn("title='Device Health Degraded'", row)
        # recover mapping
        ridx = self.API.find("'health_recovered': dict(")
        self.assertGreater(ridx, 0, 'health_recovered missing from EVENT_REGISTRY')
        self.assertIn("resolves=('health_degraded',)", self.API[ridx: ridx + 300])

    def test_health_degraded_severity_from_score(self):
        # _alert_severity must derive severity from the score, not return None
        # (None would skip the alert).
        self.assertIn("if event == 'health_degraded':", self.API)

    def test_threshold_is_config_gated_and_opt_in(self):
        # health_alert_threshold accepted by the config POST + default-off check.
        self.assertIn("'health_alert_threshold'", self.API)
        self.assertIn('if threshold <= 0:', self.API)

    def test_frontend_wiring(self):
        # health_degraded must be in the frontend FLEET_EVENTS set (v223 pins
        # equality with the server) AND have a _homeActivityAttrs case (v225).
        self.assertIn("'health_degraded'", self.APP)
        self.assertIn("case 'health_degraded':", self.APP)
        self.assertIn('function _healthSparkline(', self.APP)
        self.assertIn('function saveHealthAlertSettings(', self.APP)


class TestV341Backend(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_handlers_defined(self):
        for fn in ('def handle_device_timeline(',
                   'def handle_fleet_timeline(',
                   'def _timeline_collect(',
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

    def test_both_timelines_share_the_collector(self):
        # The roadmap's intent: fleet-wide reuses the per-device merge core.
        for fn in ('def handle_device_timeline', 'def handle_fleet_timeline'):
            idx = self.API.find(fn)
            self.assertGreater(idx, 0, f'{fn} missing')
            self.assertIn('_timeline_collect(', self.API[idx:idx + 1400],
                          f'{fn} should call the shared _timeline_collect')

    def test_fleet_timeline_excludes_unmonitored(self):
        idx = self.API.find('def handle_fleet_timeline')
        body = self.API[idx:idx + 1400]
        self.assertIn("monitored') is not False", body)

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

    def test_timeline_has_fleet_scope(self):
        # The Timeline page does whole-fleet OR a single device.
        self.assertIn("'/fleet/timeline?limit=", self.APP)
        self.assertIn('Whole fleet', self.APP)
        self.assertIn('tl-devchip', self.APP)

    def test_health_panel_present(self):
        self.assertIn('id="home-health"', self.HTML)
        self.assertIn('function _renderHomeHealth(', self.APP)
        self.assertIn('_renderHomeHealth(home.health', self.APP)
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


class TestV341QuickWins(unittest.TestCase):
    """CVE↔patch cross-link, software inventory search, end-of-life OS."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    CSS = (REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
    COMPLIANCE = (REPO_ROOT / 'server' / 'cgi-bin' / 'compliance.py').read_text()

    # ── CVE ↔ patch cross-link ──
    def test_cross_link_backend(self):
        self.assertIn('def _cve_fixable_by_device(', self.API)
        self.assertIn("'cve_fixable'", self.API)
        self.assertIn("'cve_fixable_total'", self.API)

    def test_cross_link_frontend(self):
        self.assertIn('patch-cve-badge', self.APP)
        self.assertIn('patch-cve-badge', self.CSS)
        # The badge links to the device's CVE view.
        self.assertIn("data-action=\"openDeviceCVE\"", self.APP)

    # ── Software inventory search ──
    def test_inventory_backend(self):
        for fn in ('def handle_inventory_search(', 'def _inventory_version_match('):
            self.assertIn(fn, self.API)

    def test_inventory_frontend_sortable(self):
        self.assertIn('function runInventorySearch(', self.APP)
        self.assertIn('id="inv-q"', self.HTML)
        # Sortable-tables rule: the results table must wire sort + data-col.
        self.assertIn("wireSortOnly('inv-thead'", self.APP)
        self.assertIn('data-col="package"', self.APP)

    # ── End-of-life OS ──
    def test_eol_backend(self):
        self.assertIn('_OS_EOL', self.API)
        self.assertIn('def _device_os_eol(', self.API)
        # Persisted from the package-scan ecosystem_hint (no agent change).
        self.assertIn("'os_id':        safe_hint['ID']", self.API)
        # NA item → flows into the health score; routing kind present.
        self.assertRegex(self.API, r"'kind': 'os_eol'")
        self.assertIn("('os_eol',", self.API)

    def test_eol_compliance_control(self):
        self.assertIn('def _eol_control(', self.COMPLIANCE)
        self.assertIn('_eol_control', self.COMPLIANCE)   # registered in _CONTROLS
        self.assertIn("facts['eol_os']", self.API)


class TestV341SmallTrio(unittest.TestCase):
    """Richer Prometheus exporters, iCal feed, quiet hours."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    PROM = (REPO_ROOT / 'server' / 'cgi-bin' / 'prometheus_export.py').read_text()

    def test_prometheus_health_metrics(self):
        for name in ('remotepower_fleet_health_score',
                     'remotepower_device_health_score',
                     'remotepower_attention_items',
                     'remotepower_timeline_events_24h',
                     'remotepower_cve_fixable_total'):
            self.assertIn(name, self.PROM, f'{name} missing from prometheus_export')
        # The metrics handler must feed health/fleet_events/cve into the ctx.
        self.assertIn("'health':            _fleet_health()", self.API)
        self.assertIn("'fleet_events':      load(FLEET_EVENTS_FILE)", self.API)

    def test_ical_feed(self):
        self.assertIn('def handle_schedule_ics(', self.API)
        self.assertIn('def _cron_to_ics(', self.API)
        self.assertIn('BEGIN:VCALENDAR', self.API)
        # Auth via status token (so calendar apps can subscribe).
        idx = self.API.find('def handle_schedule_ics')
        self.assertIn('status_token', self.API[idx:idx + 1200])

    def test_quiet_hours(self):
        self.assertIn('def _quiet_hours_active(', self.API)
        self.assertIn('def _in_time_window(', self.API)
        # Gated in the dispatch path, after maintenance suppression.
        self.assertIn('qh_reason = _quiet_hours_active(', self.API)
        # Config accepted + validated.
        self.assertIn("'quiet_hours'", self.API)
        # Settings UI + save.
        self.assertIn('id="qh-enabled"', self.HTML)
        self.assertIn('function saveQuietHours(', self.APP)

    def test_quiet_hours_window_wraps_midnight(self):
        # Behavioural check on the pure helper (load api via the routing harness'
        # already-imported module path).
        import importlib, sys as _s
        _s.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        self.assertTrue(api._in_time_window('23:30', '22:00', '07:00'))
        self.assertTrue(api._in_time_window('02:00', '22:00', '07:00'))
        self.assertFalse(api._in_time_window('12:00', '22:00', '07:00'))
        self.assertTrue(api._in_time_window('09:00', '08:00', '17:00'))
        self.assertFalse(api._in_time_window('19:00', '08:00', '17:00'))


class TestV341MediumTier(unittest.TestCase):
    """SLA/uptime reporting, capacity dashboard, public status page, ticketing."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    ROOT = REPO_ROOT

    def test_sla_backend(self):
        for fn in ('def _uptime_pct(', 'def handle_fleet_sla('):
            self.assertIn(fn, self.API)
        # SLA headline folded into the posture report.
        self.assertIn("'sla':            {'days': 30", self.API)

    def test_sla_uptime_pct_behaviour(self):
        import importlib, sys as _s, time as _t
        _s.path.insert(0, str(self.ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        now = int(_t.time())
        win = now - 10 * 86400
        # always up
        pct, down, cov = api._uptime_pct([{'ts': now - 40 * 86400, 'online': True}], win, now)
        self.assertTrue(cov); self.assertEqual(pct, 100.0); self.assertEqual(down, 0)
        # no data → unknown
        self.assertEqual(api._uptime_pct([], win, now), (None, 0, False))
        # one day down out of ten → ~90%
        ev = [{'ts': now - 40 * 86400, 'online': True},
              {'ts': now - 3 * 86400, 'online': False},
              {'ts': now - 2 * 86400, 'online': True}]
        pct, down, cov = api._uptime_pct(ev, win, now)
        self.assertTrue(cov); self.assertAlmostEqual(pct, 90.0, delta=0.5)

    def test_capacity_backend(self):
        self.assertIn('def handle_fleet_capacity(', self.API)

    def test_capacity_frontend(self):
        self.assertIn('function loadReportsCapacity(', self.APP)
        self.assertIn('id="reports-capacity"', self.HTML)
        # SLA table must wire sort (sortable-tables rule).
        self.assertIn("wireSortOnly('sla-thead'", self.APP)

    def test_public_status_page(self):
        self.assertIn('def handle_public_status(', self.API)
        self.assertTrue((self.ROOT / 'server' / 'html' / 'status.html').exists())
        self.assertTrue((self.ROOT / 'server' / 'html' / 'static' / 'js' / 'status.js').exists())
        # Gated by the status token, not a session.
        idx = self.API.find('def handle_public_status')
        self.assertIn('status_token', self.API[idx:idx + 800])

    def test_ticketing_adapters(self):
        # Builders live in notify.py (notification-builder carve); dispatch
        # stays in api.py.
        notify_src = (REPO_ROOT / 'server' / 'cgi-bin' / 'notify.py').read_text()
        for fn in ('def _build_pagerduty_body(', 'def _build_opsgenie_body('):
            self.assertIn(fn, notify_src)
        # registered + dispatched + auto-detected
        self.assertIn("'pagerduty'", self.API)
        self.assertIn("'opsgenie'", self.API)
        self.assertIn("fmt == 'pagerduty'", self.API)
        self.assertIn("events.pagerduty.com", self.API + notify_src)
        # frontend format options
        self.assertIn("['pagerduty', 'PagerDuty'", self.APP)
        self.assertIn("['opsgenie',  'Opsgenie'", self.APP)


if __name__ == '__main__':
    unittest.main()
