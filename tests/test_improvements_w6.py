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


if __name__ == '__main__':
    unittest.main()
