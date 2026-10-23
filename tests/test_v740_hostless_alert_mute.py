"""7.4.0: an alert with no host can be muted, and the mute can be lifted.

"Addresses Reported" (ip_reported) and the edge-feed alerts belong to the install and
not to a host. Mute on such a row answered 400 "device_id and event (or container) are
required", so the button failed. A mute with no host now silences the event for the
whole install; only an unscoped admin may set one, because everyone sees the alert.
"""
import os as _os, tempfile as _tf
_os.environ.setdefault("RP_DATA_DIR", _tf.mkdtemp())
import importlib.util
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_hostless_mute', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_EV = 'ip_reported'
_P = {'detail': '2 addresses reported to AbuseIPDB: 192.0.2.40, 192.0.2.42'}


def _reset():
    api.save(api.ALERTS_FILE, {'alerts': []})
    api.save(api.ALERT_MUTES_FILE, {'mutes': []})
    api._ALERT_MUTE_SET_CACHE['mtime'] = None


class TestHostlessMute(unittest.TestCase):
    def setUp(self):
        _reset()
        self._orig = (api.require_admin_auth, api.audit_log, api.method,
                      api.get_json_body, api._tenant_gate, api._caller_scope)
        api.require_admin_auth = lambda *a, **k: 'tester'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'
        api._tenant_gate = lambda: None
        api._caller_scope = lambda: None

    def tearDown(self):
        (api.require_admin_auth, api.audit_log, api.method,
         api.get_json_body, api._tenant_gate, api._caller_scope) = self._orig
        _reset()

    def _post(self, body):
        api.get_json_body = lambda: dict(body)
        try:
            api.handle_alert_mutes()
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, 'status', None), getattr(e, 'body', None)
        return None, None

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
                if not a.get('resolved_at')]

    def _alert_id(self):
        api._record_alert(_EV, dict(_P))
        rows = self._open()
        self.assertEqual(len(rows), 1, 'ip_reported must record an alert')
        return rows[0]['id']

    def test_mute_from_the_alert_row_works(self):
        status, body = self._post({'alert_id': self._alert_id()})
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get('resolved'), 1)
        self.assertEqual(self._open(), [])

    def test_the_next_firing_is_silent(self):
        self._post({'alert_id': self._alert_id()})
        api._record_alert(_EV, dict(_P))
        self.assertEqual(self._open(), [])

    def test_other_hostless_events_still_fire(self):
        self._post({'alert_id': self._alert_id()})
        self.assertTrue(api._alert_muted(_EV, dict(_P)))
        self.assertFalse(api._alert_muted('edge_feed_down', {'label': 'x'}))

    def test_a_host_mute_is_not_a_fleet_mute(self):
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'm1', 'device_id': 'd1', 'event': 'device_offline'}]})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        self.assertFalse(api._alert_muted('device_offline', {}))
        self.assertTrue(api._alert_muted('device_offline', {'device_id': 'd1'}))

    def test_lifting_it_restores_the_alert(self):
        self._post({'alert_id': self._alert_id()})
        api.save(api.ALERT_MUTES_FILE, {'mutes': []})
        api._ALERT_MUTE_SET_CACHE['mtime'] = None
        api._record_alert(_EV, dict(_P))
        self.assertEqual(len(self._open()), 1)

    def test_it_is_idempotent(self):
        aid = self._alert_id()
        self._post({'alert_id': aid})
        self._post({'alert_id': aid})
        self.assertEqual(len(api._alert_mutes_load()['mutes']), 1)

    def test_a_tenant_admin_cannot_mute_for_everyone(self):
        aid = self._alert_id()
        api._tenant_gate = lambda: 'tenantA'
        status, _ = self._post({'alert_id': aid})
        self.assertEqual(status, 403)
        self.assertEqual(api._alert_mutes_load()['mutes'], [])

    def test_no_host_and_no_alert_is_still_a_400(self):
        status, _ = self._post({'event': _EV})
        self.assertEqual(status, 400)


if __name__ == '__main__':
    unittest.main()
