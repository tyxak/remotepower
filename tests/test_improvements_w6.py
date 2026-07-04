"""Wave-6 improvement-program guardrails (big rocks & decide-first items)."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_w6", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'fire_webhook',
                       'respond', 'method', 'get_json_body', 'get_json_obj')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestGeoAnomaly(_HandlerBase):
    """W6-41: impossible-travel detector + config."""

    def test_anomaly_pure(self):
        now = 1_000_000
        # different country within window → anomaly
        self.assertTrue(api._geo_anomaly({'country': 'US', 'ts': now - 3600}, 'GB', now, 2))
        # same country → not
        self.assertFalse(api._geo_anomaly({'country': 'US', 'ts': now - 3600}, 'US', now, 2))
        # outside window → not
        self.assertFalse(api._geo_anomaly({'country': 'US', 'ts': now - 4 * 3600}, 'GB', now, 2))
        # no prior → not
        self.assertFalse(api._geo_anomaly(None, 'GB', now, 2))

    def test_config_saves_geoip_paths(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'geoip_db_path': '/var/lib/GeoLite2-Country.mmdb',
                                    'geo_anomaly_enabled': True, 'geo_anomaly_hours': 6}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg['geoip_db_path'], '/var/lib/GeoLite2-Country.mmdb')
        self.assertTrue(cfg['geo_anomaly_enabled'])
        self.assertEqual(cfg['geo_anomaly_hours'], 6)

    def test_geo_enrich_empty_when_unconfigured(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api.geo_enrich('8.8.8.8'), {})

    def test_event_registered(self):
        self.assertIn('login_geo_anomaly', api.EVENT_REGISTRY)
        self.assertEqual(api.EVENT_REGISTRY['login_geo_anomaly']['severity'], 'high')


class _FakeResp:
    def __init__(self, body):
        self._b = body.encode() if isinstance(body, str) else body
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class TestCloudProviders(unittest.TestCase):
    """W6-44: Hetzner + DigitalOcean importers (pure, injected opener)."""

    def setUp(self):
        sys.path.insert(0, str(_CGI_BIN))
        import cloud_import
        self.ci = cloud_import

    def test_hetzner_parse(self):
        body = ('{"servers":[{"id":42,"name":"web1","status":"running",'
                '"server_type":{"name":"cx21"},'
                '"public_net":{"ipv4":{"ip":"5.6.7.8"}},'
                '"private_net":[{"ip":"10.0.0.2"}],'
                '"datacenter":{"location":{"name":"fsn1"}}}]}')
        insts = self.ci.import_hetzner('tok', _opener=lambda req, timeout=15: _FakeResp(body))
        self.assertEqual(len(insts), 1)
        i = insts[0]
        self.assertEqual(i['instance_id'], '42')
        self.assertEqual(i['public_ip'], '5.6.7.8')
        self.assertEqual(i['private_ip'], '10.0.0.2')
        self.assertEqual(i['type'], 'cx21')
        self.assertEqual(i['az'], 'fsn1')

    def test_digitalocean_parse(self):
        body = ('{"droplets":[{"id":99,"name":"db1","status":"active",'
                '"size_slug":"s-1vcpu-1gb","region":{"slug":"nyc3"},'
                '"networks":{"v4":[{"ip_address":"1.2.3.4","type":"public"},'
                '{"ip_address":"10.1.1.1","type":"private"}]}}]}')
        insts = self.ci.import_digitalocean('tok', _opener=lambda req, timeout=15: _FakeResp(body))
        i = insts[0]
        self.assertEqual(i['instance_id'], '99')
        self.assertEqual(i['private_ip'], '10.1.1.1')
        self.assertEqual(i['az'], 'nyc3')

    def test_instance_to_device_shape(self):
        did, frag = self.ci.instance_to_device('hetzner', 'fsn1',
            {'instance_id': '42', 'name': 'web1', 'private_ip': '10.0.0.2', 'type': 'cx21'})
        self.assertEqual(did, 'hetzner-42')
        self.assertTrue(frag['agentless'])
        self.assertEqual(frag['ip'], '10.0.0.2')


class TestCloudSync(_HandlerBase):
    """W6-44: shared import runner + mark-gone reconcile."""

    def test_mark_gone_decommissions(self):
        # one existing cloud device that WON'T be returned this run
        api.save(api.DEVICES_FILE, {
            'hetzner-1': {'name': 'old', 'source': 'cloud:hetzner',
                          'cloud': {'provider': 'hetzner'}, 'agentless': True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        saved = api._cloud_fetch_instances
        # fetch returns a DIFFERENT device (hetzner-2), so hetzner-1 is "gone"
        api._cloud_fetch_instances = lambda a: (
            {'hetzner-2': {'name': 'new', 'source': 'cloud:hetzner',
                           'cloud': {'provider': 'hetzner'}, 'agentless': True}}, None)
        try:
            res = api._cloud_import_run([{'provider': 'hetzner'}], 'jakob', mark_gone=True)
        finally:
            api._cloud_fetch_instances = saved
        self.assertEqual(res['imported'], 1)
        self.assertEqual(res['decommissioned'], 1)
        devs = api.load(api.DEVICES_FILE)
        self.assertTrue(devs['hetzner-1']['decommissioned'])
        self.assertIn('hetzner-2', devs)

    def test_error_run_does_not_decommission(self):
        api.save(api.DEVICES_FILE, {
            'hetzner-1': {'name': 'x', 'source': 'cloud:hetzner',
                          'cloud': {'provider': 'hetzner'}, 'agentless': True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        saved = api._cloud_fetch_instances
        api._cloud_fetch_instances = lambda a: ({}, 'API error')
        try:
            res = api._cloud_import_run([{'provider': 'hetzner'}], 'jakob', mark_gone=True)
        finally:
            api._cloud_fetch_instances = saved
        self.assertEqual(res['decommissioned'], 0)   # never reconcile on error
        self.assertFalse(api.load(api.DEVICES_FILE)['hetzner-1'].get('decommissioned'))


if __name__ == '__main__':
    unittest.main()
