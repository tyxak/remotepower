#!/usr/bin/env python3
"""Connector wave G — 9 new homelab integration connectors (pure layer only).

Every connector is exercised against canned API JSON via a fake HTTP client
(no network): one happy-path parse and one hard-failure (unreachable → the
poller turns IntegrationError into 'critical'). Also pins that each new type
carries a _STATS chip spec (test_every_connector_has_a_stat_spec's contract).
"""
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402

WAVE_G = ('immich', 'paperless', 'vaultwarden', 'gitea', 'syncthing',
          'frigate', 'octoprint', 'esphome', 'homebridge')


class FakeClient(I.HTTPClient):
    """Canned-response client: routes is {path_without_query: (status, payload)}.
    payload may be a dict/list (JSON-encoded) or a raw string. A 3-tuple adds
    response headers."""
    def __init__(self, base='http://x', routes=None):
        super().__init__(base)
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path.split('?')[0], dict(headers or {})))
        v = self.routes.get(path.split('?')[0])
        if v is None:
            return I.Resp(404, '')
        if len(v) == 3:
            st, payload, hdrs = v
        else:
            st, payload = v
            hdrs = {}
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return I.Resp(st, text, hdrs)


class TestRegistry(unittest.TestCase):
    def test_all_wave_g_registered_with_stats(self):
        for t in WAVE_G:
            self.assertIn(t, I.CONNECTORS, t)
            self.assertTrue(I._STATS.get(t), f'{t} has no stat-chip spec')

    def test_unreachable_is_critical_for_every_connector(self):
        for t in WAVE_G:
            r = I.poll_instance(
                {'type': t, 'secret': 'k', 'username': 'u'}, FakeClient(routes={}))
            self.assertEqual(r['status'], I.CRIT, t)


class TestImmich(unittest.TestCase):
    def test_happy(self):
        c = FakeClient(routes={
            '/api/server/about': (200, {'version': 'v1.118.0'}),
            '/api/server/statistics': (200, {'photos': 1200, 'videos': 34,
                                             'usage': 5 * 1024 * 1024 * 1024}),
        })
        r = I.poll_instance({'type': 'immich', 'secret': 'key'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['version'], 'v1.118.0')
        self.assertEqual(r['metrics'],
                         {'photos': 1200, 'videos': 34, 'usage_mb': 5120})
        self.assertEqual(c.calls[0][2].get('x-api-key'), 'key')

    def test_statistics_missing_is_critical(self):
        c = FakeClient(routes={'/api/server/about': (200, {'version': 'v1'})})
        r = I.poll_instance({'type': 'immich', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.CRIT)


class TestPaperless(unittest.TestCase):
    def test_happy(self):
        c = FakeClient(routes={
            '/api/statistics/': (200, {'documents_total': 812, 'documents_inbox': 7}),
        })
        r = I.poll_instance({'type': 'paperless', 'secret': 'tok'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics'], {'documents': 812, 'inbox': 7})
        self.assertEqual(c.calls[0][2].get('Authorization'), 'Token tok')

    def test_null_inbox_tolerated(self):
        # documents_inbox is null when no inbox tag is configured.
        c = FakeClient(routes={
            '/api/statistics/': (200, {'documents_total': 5, 'documents_inbox': None}),
        })
        r = I.poll_instance({'type': 'paperless', 'secret': 't'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics']['inbox'], 0)

    def test_unauthorized_is_critical(self):
        c = FakeClient(routes={'/api/statistics/': (401, '')})
        self.assertEqual(I.poll_instance({'type': 'paperless', 'secret': 'bad'}, c)['status'],
                         I.CRIT)


class TestVaultwarden(unittest.TestCase):
    def test_happy_no_credential(self):
        c = FakeClient(routes={
            '/alive': (200, '"2026-07-03T10:00:00.000000"'),   # body is a timestamp
            '/api/config': (200, {'version': '1.32.0'}),
        })
        r = I.poll_instance({'type': 'vaultwarden'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['version'], '1.32.0')
        self.assertEqual(r['metrics'], {'alive': True})

    def test_version_optional(self):
        c = FakeClient(routes={'/alive': (200, '"ts"')})   # /api/config 404s
        r = I.poll_instance({'type': 'vaultwarden'}, c)
        self.assertEqual(r['status'], I.OK)

    def test_fields_empty(self):
        self.assertEqual(I.CONNECTORS['vaultwarden']['fields'], [])

    def test_dead_is_critical(self):
        self.assertEqual(I.poll_instance({'type': 'vaultwarden'}, FakeClient())['status'],
                         I.CRIT)


class TestGitea(unittest.TestCase):
    def test_happy_total_from_header(self):
        c = FakeClient(routes={
            '/api/v1/version': (200, {'version': '1.22.3'}),
            '/api/v1/repos/search': (200, {'ok': True, 'data': [{'name': 'r'}]},
                                     {'X-Total-Count': '42'}),
        })
        r = I.poll_instance({'type': 'gitea', 'secret': 'tok'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['version'], '1.22.3')
        self.assertEqual(r['metrics'], {'repos': 42})
        self.assertEqual(c.calls[0][2].get('Authorization'), 'token tok')

    def test_no_token_no_auth_header_and_repos_fallback(self):
        c = FakeClient(routes={
            '/api/v1/version': (200, {'version': '9.0.1'}),   # Forgejo
            '/api/v1/repos/search': (200, {'ok': True, 'data': [{'name': 'a'}, {'name': 'b'}]}),
        })
        r = I.poll_instance({'type': 'gitea'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertNotIn('Authorization', c.calls[0][2])
        self.assertEqual(r['metrics']['repos'], 2)   # no header → len(data)

    def test_down_is_critical(self):
        self.assertEqual(I.poll_instance({'type': 'gitea'}, FakeClient())['status'], I.CRIT)


class TestSyncthing(unittest.TestCase):
    def test_happy(self):
        c = FakeClient(routes={
            '/rest/noauth/health': (200, {'status': 'OK'}),
            '/rest/system/status': (200, {'uptime': 7300, 'myID': 'AAA'}),
            '/rest/system/connections': (200, {'connections': {
                'DEV1': {'connected': True}, 'DEV2': {'connected': False},
                'DEV3': {'connected': True}}, 'total': {}}),
        })
        r = I.poll_instance({'type': 'syncthing', 'secret': 'key'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics']['devices_connected'], 2)
        self.assertEqual(r['metrics']['devices'], 3)
        # the authed calls carry the API key; the noauth probe needs none
        self.assertEqual(c.calls[1][2].get('X-API-Key'), 'key')

    def test_health_not_ok_is_critical(self):
        c = FakeClient(routes={'/rest/noauth/health': (200, {'status': 'starting'})})
        self.assertEqual(I.poll_instance({'type': 'syncthing', 'secret': 'k'}, c)['status'],
                         I.CRIT)

    def test_bad_key_is_critical(self):
        c = FakeClient(routes={
            '/rest/noauth/health': (200, {'status': 'OK'}),
            '/rest/system/status': (403, ''),
        })
        self.assertEqual(I.poll_instance({'type': 'syncthing', 'secret': 'bad'}, c)['status'],
                         I.CRIT)


class TestFrigate(unittest.TestCase):
    def test_happy_per_camera_fps(self):
        c = FakeClient(routes={'/api/stats': (200, {
            'cameras': {'front': {'detection_fps': 4.1, 'camera_fps': 5.0},
                        'back': {'detection_fps': 2.4}},
            'service': {'version': '0.14.1-f4f3cfa', 'uptime': 100},
        })})
        r = I.poll_instance({'type': 'frigate'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics']['cameras'], 2)
        self.assertEqual(r['metrics']['det_fps'], 6.5)
        self.assertEqual(r['version'], '0.14.1-f4f3cfa')

    def test_top_level_fps_preferred(self):
        c = FakeClient(routes={'/api/stats': (200, {
            'cameras': {'front': {'detection_fps': 4.0}}, 'detection_fps': 4.0})})
        r = I.poll_instance({'type': 'frigate'}, c)
        self.assertEqual(r['metrics']['det_fps'], 4.0)

    def test_fields_empty(self):
        self.assertEqual(I.CONNECTORS['frigate']['fields'], [])

    def test_down_is_critical(self):
        self.assertEqual(I.poll_instance({'type': 'frigate'}, FakeClient())['status'], I.CRIT)


class TestOctoPrint(unittest.TestCase):
    _VER = {'api': '0.1', 'server': '1.10.2', 'text': 'OctoPrint 1.10.2'}

    def test_happy_printing(self):
        c = FakeClient(routes={
            '/api/version': (200, self._VER),
            '/api/printer': (200, {'state': {'text': 'Printing',
                                             'flags': {'operational': True, 'printing': True}}}),
        })
        r = I.poll_instance({'type': 'octoprint', 'secret': 'key'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['version'], '1.10.2')
        self.assertEqual(r['metrics'], {'printing': True, 'operational': True})
        self.assertEqual(c.calls[0][2].get('X-Api-Key'), 'key')

    def test_printer_disconnected_409_is_warning_not_critical(self):
        c = FakeClient(routes={
            '/api/version': (200, self._VER),
            '/api/printer': (409, 'Printer is not operational'),
        })
        r = I.poll_instance({'type': 'octoprint', 'secret': 'k'}, c)
        self.assertEqual(r['status'], I.WARN)
        self.assertIn('disconnected', r['detail'])

    def test_bad_key_is_critical(self):
        c = FakeClient(routes={'/api/version': (403, '')})
        self.assertEqual(I.poll_instance({'type': 'octoprint', 'secret': 'bad'}, c)['status'],
                         I.CRIT)


class TestESPHome(unittest.TestCase):
    def test_happy_with_outdated(self):
        c = FakeClient(routes={'/devices': (200, {'configured': [
            {'name': 'sensor1', 'configuration': 'sensor1.yaml',
             'deployed_version': '2026.5.0', 'current_version': '2026.6.0'},
            {'name': 'sensor2', 'configuration': 'sensor2.yaml',
             'deployed_version': '2026.6.0', 'current_version': '2026.6.0'},
        ], 'importable': []})})
        r = I.poll_instance({'type': 'esphome'}, c)
        self.assertEqual(r['status'], I.WARN)   # one node behind → warning
        self.assertEqual(r['metrics'], {'nodes': 2, 'outdated': 1})

    def test_all_current_ok(self):
        c = FakeClient(routes={'/devices': (200, {'configured': [
            {'name': 'a', 'deployed_version': '1', 'current_version': '1'}]})})
        r = I.poll_instance({'type': 'esphome'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics'], {'nodes': 1, 'outdated': 0})

    def test_fields_empty(self):
        self.assertEqual(I.CONNECTORS['esphome']['fields'], [])

    def test_down_is_critical(self):
        self.assertEqual(I.poll_instance({'type': 'esphome'}, FakeClient())['status'], I.CRIT)


class TestHomebridge(unittest.TestCase):
    def test_happy(self):
        c = FakeClient(routes={
            '/api/auth/login': (201, {'access_token': 'jwt', 'token_type': 'Bearer'}),
            '/api/status/homebridge': (200, {'status': 'up'}),
            '/api/plugins': (200, [{'name': 'p1'}, {'name': 'p2'}, {'name': 'p3'}]),
        })
        r = I.poll_instance({'type': 'homebridge', 'username': 'admin', 'secret': 'pw'}, c)
        self.assertEqual(r['status'], I.OK)
        self.assertEqual(r['metrics'], {'up': True, 'plugins': 3})
        # login body carried the credentials; status call used the bearer token
        self.assertEqual(c.calls[1][2].get('Authorization'), 'Bearer jwt')

    def test_bridge_down_is_warning(self):
        c = FakeClient(routes={
            '/api/auth/login': (201, {'access_token': 'jwt'}),
            '/api/status/homebridge': (200, {'status': 'down'}),
            '/api/plugins': (200, []),
        })
        r = I.poll_instance({'type': 'homebridge', 'username': 'a', 'secret': 'p'}, c)
        self.assertEqual(r['status'], I.WARN)

    def test_login_rejected_is_critical(self):
        c = FakeClient(routes={'/api/auth/login': (403, {'message': 'bad'})})
        r = I.poll_instance({'type': 'homebridge', 'username': 'a', 'secret': 'bad'}, c)
        self.assertEqual(r['status'], I.CRIT)
        self.assertIn('login failed', r['detail'])

    def test_login_without_token_is_critical(self):
        c = FakeClient(routes={'/api/auth/login': (200, {})})
        self.assertEqual(
            I.poll_instance({'type': 'homebridge', 'username': 'a', 'secret': 'p'}, c)['status'],
            I.CRIT)


if __name__ == '__main__':
    unittest.main()
