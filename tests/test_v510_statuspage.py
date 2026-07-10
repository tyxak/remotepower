"""v5.1.0 public status page — projection logic + sanitization guarantees."""
import importlib.util, json, os, sys, time, unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
os.environ.setdefault("RP_DATA_DIR", "/tmp/rp-statuspage-test")
Path(os.environ["RP_DATA_DIR"]).mkdir(parents=True, exist_ok=True)
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v510_sp", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestComponentState(unittest.TestCase):
    def test_states(self):
        now = int(time.time())
        devs = {'d1': {'last_seen': now, 'monitored': True},
                'd2': {'last_seen': now - 99999, 'monitored': True}}
        op, _, _ = api._status_page_component_state({'device_ids': ['d1']}, devs, now, 180, {})
        self.assertEqual(op, 'operational')
        deg, _, _ = api._status_page_component_state({'device_ids': ['d1', 'd2']}, devs, now, 180, {})
        self.assertEqual(deg, 'degraded')
        out, _, _ = api._status_page_component_state({'device_ids': ['d2']}, devs, now, 180, {})
        self.assertEqual(out, 'major_outage')
        empty, _, _ = api._status_page_component_state({'device_ids': ['nope']}, devs, now, 180, {})
        self.assertEqual(empty, 'operational')

    def test_monitor_member(self):
        now = int(time.time())
        st, _, _ = api._status_page_component_state(
            {'monitors': ['web']}, {}, now, 180, {'web': {'up': False}})
        self.assertEqual(st, 'major_outage')


class TestProjection(unittest.TestCase):
    def setUp(self):
        api.save(api.MON_HIST_FILE, {})
        api.save(api.ALERTS_FILE, {'alerts': []})

    def test_disabled_returns_none(self):
        self.assertIsNone(api._status_page_projection(
            {'status_page': {'enabled': False}}, {}, int(time.time()), 180))

    def test_projection_and_no_secret_leak(self):
        now = int(time.time())
        devs = {'dev-secret-id': {'last_seen': now - 99999, 'monitored': True,
                                  'name': 'prod-db-01.internal', 'ip': '10.0.0.5'}}
        api.save(api.ALERTS_FILE, {'alerts': [{
            'event': 'device_offline', 'severity': 'critical',
            'device_id': 'dev-secret-id', 'ts': now - 3600, 'resolved_at': None,
            'title': 'prod-db-01.internal went offline',
            'payload': {'ip': '10.0.0.5', 'host': 'prod-db-01.internal'}}]})
        cfg = {'status_page': {'enabled': True, 'title': 'Acme Status',
                               'show_incidents': True, 'incident_days': 30,
                               'components': [{'id': 'db', 'name': 'Database',
                                              'group': 'Core',
                                              'device_ids': ['dev-secret-id'],
                                              'monitors': []}]}}
        proj = api._status_page_projection(cfg, devs, now, 180)
        self.assertTrue(proj['status_page_enabled'])
        self.assertEqual(proj['title'], 'Acme Status')
        self.assertEqual(proj['overall'], 'major_outage')
        self.assertEqual(proj['components'][0]['name'], 'Database')
        self.assertEqual(proj['components'][0]['status'], 'major_outage')
        self.assertTrue(proj['incidents'])
        self.assertEqual(proj['incidents'][0]['component'], 'Database')
        self.assertLess(proj['components'][0]['uptime_pct'], 100.0)
        # SECURITY: the public projection must leak NO host identity / alert detail.
        blob = json.dumps(proj)
        for secret in ('prod-db-01', 'internal', '10.0.0.5', 'dev-secret-id',
                       'went offline', 'device_offline'):
            self.assertNotIn(secret, blob, f"leaked {secret!r} in public projection")

    def test_incident_outside_window_excluded(self):
        now = int(time.time())
        devs = {'d1': {'last_seen': now, 'monitored': True}}
        api.save(api.ALERTS_FILE, {'alerts': [{
            'severity': 'warning', 'device_id': 'd1',
            'ts': now - 60 * 86400, 'resolved_at': now - 59 * 86400}]})
        cfg = {'status_page': {'enabled': True, 'incident_days': 30,
                               'components': [{'id': 'a', 'name': 'A',
                                              'device_ids': ['d1'], 'monitors': []}]}}
        proj = api._status_page_projection(cfg, devs, now, 180)
        self.assertEqual(proj['incidents'], [])
        self.assertEqual(proj['components'][0]['uptime_pct'], 100.0)


class TestPublicStatusControlPlaneUptime(unittest.TestCase):
    """docs/master-improvement-scoping-internal.md #51 — RemotePower's own
    observed availability (_control_uptime, previously admin-only via
    GET /api/self-test) is now also on the public status page. Calls the
    real handle_public_status() end-to-end."""

    def setUp(self):
        self.d = Path(__import__('tempfile').mkdtemp())
        self._saved = {}
        for a in ('CONFIG_FILE', 'DEVICES_FILE', 'MON_HIST_FILE', 'CONTROL_UPTIME_FILE'):
            self._saved[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        api.save(api.CONFIG_FILE, {'status_token': 'sekret-tok'})
        api.save(api.DEVICES_FILE, {})
        api.save(api.MON_HIST_FILE, {})
        self._orig_env = api._env
        self._qs = 'token=sekret-tok'
        api._env = lambda k, d=None: (self._qs if k == 'QUERY_STRING' else d)
        self.cap = {}

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        self._orig_respond = api.respond
        api.respond = _resp

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        api._env = self._orig_env
        api.respond = self._orig_respond

    def _call(self):
        try:
            api.handle_public_status()
        except api.HTTPError:
            pass
        return self.cap.get('b')

    def test_no_tracking_yet_omits_control_plane(self):
        api.save(api.CONTROL_UPTIME_FILE, {})
        body = self._call()
        self.assertNotIn('control_plane', body)

    def test_tracking_surfaces_rolling_windows(self):
        now = int(time.time())
        hr = now - (now % 3600)
        api.save(api.CONTROL_UPTIME_FILE, {'hours': [hr, hr - 3600], 'since': hr - 3600})
        body = self._call()
        self.assertIn('control_plane', body)
        self.assertIn('24h', body['control_plane']['windows'])
        self.assertEqual(body['control_plane']['since'], hr - 3600)

    def test_wrong_token_never_reaches_control_plane_data(self):
        api.save(api.CONTROL_UPTIME_FILE, {'hours': [int(time.time())], 'since': 0})
        self._qs = 'token=wrong'
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_public_status()
        self.assertEqual(cm.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
