"""v5.6.0 — per-(host, event) alert mutes + Monitoring → Tuning.

A mute silences one exact (host, event): no inbox row, no webhook, no
needs-attention — but fleet_events keeps recording it so the Tuning page can
still surface (and lift) noisy sources. These tests pin the suppression
behaviour, the "fleet_events is NOT suppressed" guarantee, and the wiring.
"""
import importlib.util
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_mute', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_SRC = (_CGI / 'api.py').read_text()

_EV = 'device_offline'   # reliably alert-able, per-device


class TestMuteHelpers(unittest.TestCase):
    def setUp(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'm1', 'device_id': 'd1', 'event': _EV},
        ]})

    def tearDown(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': []})

    def test_mute_set(self):
        self.assertIn(('d1', _EV), api._alert_mute_set())

    def test_alert_muted_matches_host_and_event(self):
        self.assertTrue(api._alert_muted(_EV, {'device_id': 'd1'}))
        self.assertFalse(api._alert_muted(_EV, {'device_id': 'd2'}))      # other host
        self.assertFalse(api._alert_muted('cpu_high', {'device_id': 'd1'}))  # other event
        self.assertFalse(api._alert_muted(_EV, {}))                       # no device


class TestRecordAlertSuppression(unittest.TestCase):
    def setUp(self):
        self.assertTrue(api._alert_severity(_EV, {'device_id': 'd1'}),
                        'test event must be alert-able')
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.save(api.ALERT_MUTES_FILE, {'mutes': []})

    def tearDown(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.save(api.ALERT_MUTES_FILE, {'mutes': []})

    def _open_count(self):
        return len((api.load(api.ALERTS_FILE) or {}).get('alerts') or [])

    def test_records_without_mute(self):
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'host1'})
        self.assertEqual(self._open_count(), 1)

    def test_suppressed_when_muted(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'm1', 'device_id': 'd1', 'event': _EV}]})
        api._record_alert(_EV, {'device_id': 'd1', 'device_name': 'host1'})
        self.assertEqual(self._open_count(), 0)                 # muted host -> nothing
        api._record_alert(_EV, {'device_id': 'd2', 'device_name': 'host2'})
        self.assertEqual(self._open_count(), 1)                 # other host still alerts


class TestFleetEventsNotSuppressed(unittest.TestCase):
    def test_fleet_event_recorder_has_no_mute_gate(self):
        seg = _SRC[_SRC.index('def _record_fleet_event'):
                   _SRC.index('def _record_fleet_event') + 1600]
        self.assertNotIn('_alert_muted', seg,
                         'fleet_events must record even when muted (Tuning needs it)')

    def test_fire_webhook_records_fleet_event_before_mute_gate(self):
        body = _SRC[_SRC.index('def fire_webhook'):
                    _SRC.index('def fire_webhook') + 6000]
        self.assertIn('_record_fleet_event(event, payload)', body)
        # v5.6.0: the mute is computed once into `_muted` and the delivery gate is
        # `if _muted: return`; fleet_events must still be recorded before it.
        self.assertLess(body.index('_record_fleet_event(event, payload)'),
                        body.index('if _muted:'),
                        'fleet_events must be recorded before delivery is muted')


class TestApiWiring(unittest.TestCase):
    def test_handlers_exist(self):
        for fn in ('handle_alert_mutes', 'handle_alert_mute_delete',
                   'handle_alert_tuning'):
            self.assertTrue(hasattr(api, fn), f'missing {fn}')

    def test_routes_registered(self):
        self.assertIn("('GET', '/api/alert-mutes'): handle_alert_mutes", _SRC)
        self.assertIn("('POST', '/api/alert-mutes'): handle_alert_mutes", _SRC)
        self.assertIn("('GET', '/api/alert-tuning'): handle_alert_tuning", _SRC)
        self.assertIn("/api/alert-mutes/') and m == 'DELETE'", _SRC)

    def test_mutations_admin_gated_and_audited(self):
        for fn in ('handle_alert_mute_delete',):
            seg = _SRC[_SRC.index('def ' + fn): _SRC.index('def ' + fn) + 1200]
            self.assertIn('require_admin_auth()', seg)
            self.assertIn('audit_log(', seg)
        add = _SRC[_SRC.index('def handle_alert_mutes'):
                   _SRC.index('def handle_alert_mute_delete')]
        self.assertIn('require_admin_auth()', add)
        self.assertIn("audit_log(actor, 'alert_mute_add'", add)
        # the X button resolves open matching alerts when muting
        self.assertIn("a['resolved_by'] = 'muted'", add)

    def test_inbox_suppression_wired(self):
        # Window widened v6.1.2 (the Alerts-module gate was inserted above the
        # mute check). These fixed-size source windows are brittle by nature:
        # anything added near the top of _record_alert pushes the marker out.
        seg = _SRC[_SRC.index('def _record_alert'):
                   _SRC.index('def _record_alert') + 2600]
        self.assertIn('if _alert_muted(event, p):', seg)


class TestFrontendWiring(unittest.TestCase):
    def test_ack_button_replaced_with_mute(self):
        from clientjs import client_js
        appjs = client_js()   # alerts-inbox JS moved to app-alerts.js in the app.js split
        self.assertIn("data-action=\"muteAlert\"", appjs)
        self.assertIn('function muteAlert', appjs)
        # the per-row Ack button is gone (bulk ack stays)
        self.assertNotIn('data-action="ackAlert"', appjs)

    def test_tuning_page_present(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="page-tuning"', index)
        self.assertIn('data-page="tuning"', index)
        # v6.2.2: app-tuning.js is a LAZY page module — wired through app.js's
        # _LAZY_PAGE_MODULES map (loaded on first navigation), not a boot tag.
        appjs = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("'app-tuning.js'", appjs)
        tun = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-tuning.js').read_text()
        for fn in ('function loadTuning', 'function silenceNoisy', 'function unmuteAlert'):
            self.assertIn(fn, tun)


if __name__ == '__main__':
    unittest.main()
