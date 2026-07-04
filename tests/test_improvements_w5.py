"""Wave-5 improvement-program guardrails (fleet, CMDB & topology)."""
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

_spec = importlib.util.spec_from_file_location("api_w5", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE',
                     'DEVICE_PROFILES_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'fire_webhook',
                       'respond', 'method', 'get_json_body', 'get_json_obj')}
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


class TestDeviceProfiles(_HandlerBase):
    """W5-7: named device-config profiles + stamp-on-apply."""

    def _create(self, body):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: body
        return self.call(api.handle_device_profiles)

    def test_create_validates_and_stores(self):
        out = self._create({'name': 'web tier', 'poll_interval': 120,
                            'services_watched': ['nginx.service', 'php-fpm.service'],
                            'metric_thresholds': {'mem_warn_percent': 70, 'mem_crit_percent': 90}})
        self.assertTrue(out.get('id'))
        profs = api.load(api.DEVICE_PROFILES_FILE) or {}
        p = list(profs.values())[0]
        self.assertEqual(p['name'], 'web tier')
        self.assertEqual(p['poll_interval'], 120)
        self.assertEqual(p['metric_thresholds']['mem_warn_percent'], 70)

    def test_create_requires_name(self):
        out = self._create({'poll_interval': 60})
        self.assertIn('name', str(out))

    def test_bad_poll_interval_rejected(self):
        out = self._create({'name': 'x', 'poll_interval': 5})
        self.assertIn('poll_interval', str(out))

    def test_apply_stamps_fields(self):
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'a', 'poll_interval': 60, 'metric_state': {'mem': 'warning'}},
            'd2': {'name': 'b', 'poll_interval': 60}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        pid = self._create({'name': 'p', 'poll_interval': 300,
                            'services_watched': ['sshd.service'],
                            'metric_thresholds': {'mem_warn_percent': 80}})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'device_ids': ['d1', 'd2', 'ghost']}
        out = self.call(api.handle_device_profile_apply, pid)
        self.assertEqual(out['applied'], 2)
        devs = api.load(api.DEVICES_FILE)
        self.assertEqual(devs['d1']['poll_interval'], 300)
        self.assertEqual(devs['d1']['services_watched'], ['sshd.service'])
        # metric_state cleared because thresholds changed
        self.assertNotIn('metric_state', devs['d1'])

    def test_apply_is_one_shot_copy(self):
        # editing a device after apply does not touch the profile
        prof = {'poll_interval': 300}
        dev = {'name': 'a', 'poll_interval': 60}
        updated = api._apply_profile_to_device(dev, prof)
        self.assertEqual(updated['poll_interval'], 300)
        self.assertEqual(dev['poll_interval'], 60)   # original untouched

    def test_patch_replaces_present_fields(self):
        pid = self._create({'name': 'p', 'poll_interval': 120})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'PATCH'
        api.get_json_obj = lambda: {'poll_interval': 600, 'name': 'p2'}
        self.call(api.handle_device_profile, pid)
        p = (api.load(api.DEVICE_PROFILES_FILE) or {})[pid]
        self.assertEqual(p['poll_interval'], 600)
        self.assertEqual(p['name'], 'p2')

    def test_delete(self):
        pid = self._create({'name': 'p'})['id']
        api._invalidate_load_cache(api.DEVICE_PROFILES_FILE)
        api.method = lambda: 'DELETE'
        self.call(api.handle_device_profile, pid)
        self.assertNotIn(pid, api.load(api.DEVICE_PROFILES_FILE) or {})


if __name__ == '__main__':
    unittest.main()
