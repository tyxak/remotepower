"""v6.1.1 (#1) -- server-side wiring for the opt-in agent push channel:
the heartbeat response only advertises `push_enabled` when the operator has
explicitly turned it on (Settings), and the config get/save round-trip
persists the flag. The daemon itself (server/push/remotepower-push.py) and
the agent-side listener are covered by tests/test_v611_push.py and manual
protocol review respectively -- this file is just the api.py glue that
opts a fleet in, following the exact same pattern already established for
secrets_scan_enabled/image_scan_enabled.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))


class TestHeartbeatAdvertisesPushEnabled(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'POST')
        os.environ.setdefault('PATH_INFO', '/api/heartbeat')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v611_push_wiring", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api = self.api
        api.DATA_DIR = self._tmp
        api.DEVICES_FILE = self._tmp / 'devices.json'
        api.CMDS_FILE = self._tmp / 'cmds.json'
        api.CONFIG_FILE = self._tmp / 'config.json'
        api.TOKENS_FILE = self._tmp / 'tokens.json'
        api.save(api.CMDS_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'host1', 'token': 'tok',
            'poll_interval': 60,
        }})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _heartbeat(self):
        api = self.api
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'device_id': 'd1', 'token': 'tok', 'version': '6.1.1'}
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        return cap.get('body') or {}

    def test_push_enabled_advertised_when_config_on(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertTrue(body.get('push_enabled'))

    def test_push_enabled_absent_when_config_off(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': False})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertNotIn('push_enabled', body)

    def test_push_enabled_absent_by_default(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        body = self._heartbeat()
        self.assertNotIn('push_enabled', body)


class _ConfigHandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        _spec = importlib.util.spec_from_file_location(
            "api_v611_push_cfg", _CGI_BIN / "api.py")
        self.api = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(self.api)
        api = self.api
        for attr in ('USERS_FILE', 'CONFIG_FILE'):
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def call(self, fn, *a):
        try:
            fn(*a)
        except self.api.HTTPError:
            pass
        return self.cap.get('b')


class TestPushEnabledConfigRoundTrip(_ConfigHandlerBase):
    def test_config_save_persists_flag(self):
        api = self.api
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'push_enabled': True}
        self.call(api.handle_config_save)
        self.assertTrue((api.load(api.CONFIG_FILE) or {}).get('push_enabled'))

    def test_config_save_can_turn_it_back_off(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'push_enabled': True})
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'push_enabled': False}
        self.call(api.handle_config_save)
        self.assertFalse((api.load(api.CONFIG_FILE) or {}).get('push_enabled'))

    def test_config_get_defaults_to_false(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api.method = lambda: 'GET'
        out = self.call(api.handle_config_get)
        self.assertFalse(out.get('push_enabled'))


if __name__ == "__main__":
    unittest.main()
