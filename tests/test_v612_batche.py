"""v6.1.2 batch E leftovers — kiosk mode, theme schedule, chart annotations,
Pi-hole/AdGuard top-blocked.

The two frontend features are pinned in source (they have no server surface); the
two with a server half are driven through the real code.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
JS = ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(CGI))

import integrations as integrations_mod    # noqa: E402


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v612-e-')
    spec = importlib.util.spec_from_file_location('api_v612_e', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeClient(integrations_mod.HTTPClient):
    """Same canned-response client the connector suite uses (test_integrations).
    routes = {path_without_query: (status, payload)}; a 404 route makes the
    connector's get_json raise IntegrationError, which is how a failing endpoint
    is simulated."""

    def __init__(self, routes=None):
        super().__init__('http://x')
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path))
        v = self.routes.get(path.split('?')[0])
        if v is None:
            return integrations_mod.Resp(404, '')
        st, payload = v
        return integrations_mod.Resp(
            st, payload if isinstance(payload, str) else json.dumps(payload), {})


PIHOLE_BASE = {
    '/api/auth': (200, {'session': {'sid': 's', 'valid': True}}),
    '/api/stats/summary': (200, {'queries': {'total': 100, 'percent_blocked': 25.0},
                                 'gravity': {'domains_being_blocked': 50000}}),
    '/api/info/version': (200, {'version': {'core': {'local': {'version': 'v6.0'}}}}),
}
PIHOLE_TOP = {
    '/api/stats/top_domains': (200, {'domains': [
        {'domain': 'tracker.example', 'count': 4000},
        {'domain': 'ads.example', 'count': 12}]}),
    '/api/stats/top_clients': (200, {'clients': [
        {'name': 'living-room-tv', 'ip': '10.0.0.9', 'count': 4100}]}),
}


class TestPiholeTopBlocked(unittest.TestCase):
    def test_top_blocked_and_clients_are_returned(self):
        c = _FakeClient({**PIHOLE_BASE, **PIHOLE_TOP})
        r = integrations_mod.poll_instance({'type': 'pihole', 'secret': 'pw'}, c)
        self.assertEqual(r['top_blocked'][0],
                         {'name': 'tracker.example', 'count': 4000})
        self.assertEqual(r['top_clients'][0]['name'], 'living-room-tv')

    def test_a_failing_top_n_call_does_not_fail_the_health_check(self):
        """The connector's real job is HEALTH. If the extra stats call fails, the
        tile must still report OK — degrade the panel, never the monitoring."""
        c = _FakeClient(PIHOLE_BASE)          # top_* routes 404 -> IntegrationError
        r = integrations_mod.poll_instance({'type': 'pihole', 'secret': 'pw'}, c)
        self.assertEqual(r['status'], integrations_mod.OK)
        self.assertEqual(r['top_blocked'], [])
        self.assertEqual(r['top_clients'], [])
        self.assertIn('25.0% blocked', r['detail'])


class TestAdguardTopBlocked(unittest.TestCase):
    def test_adguard_single_pair_shape_is_normalised(self):
        """AdGuard returns [{"name": count}], Pi-hole returns [{name, count}].
        One renderer serves both, so they must be normalised server-side."""
        out = integrations_mod._adguard_top([
            {'tracker.example': 4000}, {'ads.example': 12}, 'junk', {}])
        self.assertEqual(out, [{'name': 'tracker.example', 'count': 4000},
                               {'name': 'ads.example', 'count': 12}])

    def test_top_lists_come_from_the_stats_call_we_already_make(self):
        c = _FakeClient({
            '/control/status': (200, {'running': True, 'protection_enabled': True,
                                      'version': 'v0.107'}),
            '/control/stats': (200, {'num_dns_queries': 100,
                                     'num_blocked_filtering': 25,
                                     'top_blocked_domains': [{'t.example': 9}],
                                     'top_clients': [{'10.0.0.5': 44}]}),
        })
        r = integrations_mod.poll_instance(
            {'type': 'adguard', 'username': 'u', 'secret': 'p'}, c)
        self.assertEqual(r['top_blocked'], [{'name': 't.example', 'count': 9}])
        self.assertEqual(r['top_clients'], [{'name': '10.0.0.5', 'count': 44}])
        # No EXTRA request: the top lists ride the stats call we already make.
        paths = [p for _m, p in c.calls]
        self.assertEqual(paths, ['/control/status', '/control/stats'])

    def test_a_stopped_adguard_still_returns_the_keys(self):
        """Asymmetric early returns are a recurring bug class here — a caller that
        subscripts the result must not KeyError on the failure path."""
        c = _FakeClient({'/control/status': (200, {'running': False}),
                         '/control/stats': (200, {})})
        r = integrations_mod.poll_instance({'type': 'adguard'}, c)
        self.assertEqual(r['status'], integrations_mod.CRIT)
        self.assertIn('top_blocked', r)
        self.assertIn('top_clients', r)


class TestIntegrationReadWhitelist(unittest.TestCase):
    def test_the_top_lists_are_copied_into_the_api_response(self):
        """A key a connector returns but that handle_integrations doesn't copy
        never reaches the browser, however correct the connector is."""
        src = (CGI / 'api.py').read_text()
        self.assertIn("for _k in ('top_blocked', 'top_clients')", src)


class TestMetricAnnotations(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()

    def test_every_annotated_event_actually_exists(self):
        """An annotation keyed on an event that never fires is a marker that can
        never appear — and it looks perfectly correct in review. (Four of the six
        names I first wrote were invented; this test is why they were caught.)"""
        for ev in self.api._METRIC_ANNOTATION_EVENTS:
            self.assertIn(ev, self.api.EVENT_REGISTRY,
                          f'{ev!r} is annotated but is not a real event')

    def test_annotations_are_scoped_to_the_device_and_the_window(self):
        now = int(__import__('time').time())
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [
            {'ts': now - 10000, 'device_id': 'd1', 'event': 'agent_started'},
            {'ts': now - 500,   'device_id': 'd1', 'event': 'oom_detected'},
            {'ts': now - 400,   'device_id': 'd2', 'event': 'oom_detected'},
            {'ts': now - 300,   'device_id': 'd1', 'event': 'device_offline'},
        ]})
        out = self.api._metric_annotations('d1', now - 1000)
        kinds = [a['kind'] for a in out]
        self.assertEqual(kinds, ['oom'],
                         'only in-window, this-device, annotatable events')
        self.assertEqual(out[0]['label'], 'OOM kill')

    def test_no_window_means_no_annotations(self):
        self.assertEqual(self.api._metric_annotations('d1', 0), [])

    def test_the_marker_count_is_bounded(self):
        now = int(__import__('time').time())
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [
            {'ts': now - i, 'device_id': 'd1', 'event': 'command_executed'}
            for i in range(200, 0, -1)]})
        out = self.api._metric_annotations('d1', now - 1000)
        self.assertLessEqual(len(out), 40,
                             'a chart with hundreds of ticks tells you nothing')


class TestKioskMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (JS / 'app.js').read_text()
        cls.html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        cls.css = (ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    def test_there_are_two_ways_out(self):
        """A touch-only wall tablet has no keyboard; a kiosk with no visible exit
        and no Esc is a trap. Both must exist."""
        self.assertIn('function exitKiosk', self.js)
        self.assertIn("e.key === 'Escape'", self.js)
        self.assertIn('data-action="exitKiosk"', self.html)
        self.assertIn('.kiosk-exit', self.css)

    def test_the_exit_button_lives_at_body_level(self):
        """A fixed overlay inside .container (z-index:1) is sealed beneath the
        sidebar — the documented stacking-context trap in this codebase."""
        after_app = self.html.split('</div><!-- /app -->', 1)[1]
        self.assertIn('kiosk-exit', after_app)

    def test_the_cycle_only_visits_real_enabled_pages(self):
        """A cycle that lands on a disabled module's page would toast an error at
        the wall every N seconds, forever."""
        block = self.js[self.js.index('function _kioskPages'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn("document.getElementById('page-' + p)", block)
        self.assertIn('_moduleOffFor(p)', block)

    def test_kiosk_is_documented_as_display_only_not_a_security_boundary(self):
        self.assertIn('not a security boundary', self.css.lower()
                      .replace('security boundary', 'security boundary'))


class TestThemeSchedule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (JS / 'app.js').read_text()

    def test_schedule_is_a_resolvable_theme(self):
        self.assertIn("id:'schedule'", self.js)
        self.assertIn("if (id === 'schedule')", self.js)

    def test_a_midnight_wrapping_window_is_handled(self):
        """Day 21:00 -> 05:00 is a real night-shift setup. Naive from<=h<to would
        silently resolve it to 'never daytime'."""
        block = self.js[self.js.index('function _scheduleIsDaytime'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn('from < to', block)
        self.assertIn('hour >= from || hour < to', block)

    def test_an_equal_window_does_not_pin_the_theme_on(self):
        block = self.js[self.js.index('function _scheduleIsDaytime'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn('if (from === to) return false;', block)

    def test_the_boundary_is_crossed_without_a_reload(self):
        """The target is a wall tablet that hasn't been reloaded in months —
        resolving only at page load would mean it never actually switches."""
        self.assertIn("if (t === 'schedule') applyTheme();", self.js)

    def test_the_schedule_cannot_select_itself(self):
        """Offering 'schedule' (or 'auto') as the day theme would be circular."""
        block = self.js[self.js.index('function _buildThemeSchedule'):]
        self.assertIn("THEMES.filter(t => t.type !== 'auto')", block)


if __name__ == '__main__':
    unittest.main()
