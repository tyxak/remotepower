#!/usr/bin/env python3
"""v4.3.0: per-device offline alert delay (configurable in the device drawer).

A silent host normally becomes an OFFLINE candidate after
_offline_thresholds()'s computed cutoff. offline_alert_delay_min adds extra
grace so a box on a flaky link / known-slow poller doesn't page on every blip.
0 (default) leaves behaviour exactly as before.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430ad", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP_JS = (_ROOT / 'server/html/static/js/app.js').read_text()


class TestOfflineThresholdDelay(unittest.TestCase):
    def test_default_unchanged(self):
        dev = {'poll_interval': 60}
        base_after, base_deb = api._offline_thresholds(dev, 180)
        # Explicit 0 must equal the no-field default.
        dev0 = {'poll_interval': 60, 'offline_alert_delay_min': 0}
        self.assertEqual(api._offline_thresholds(dev0, 180), (base_after, base_deb))

    def test_delay_extends_offline_after(self):
        dev = {'poll_interval': 60}
        base_after, _ = api._offline_thresholds(dev, 180)
        dev10 = {'poll_interval': 60, 'offline_alert_delay_min': 10}
        after, _ = api._offline_thresholds(dev10, 180)
        self.assertEqual(after, base_after + 10 * 60)   # +10 minutes

    def test_debounce_not_affected(self):
        dev = {'poll_interval': 60, 'offline_alert_delay_min': 30}
        _, deb = api._offline_thresholds(dev, 180)
        self.assertEqual(deb, max(api.OFFLINE_GRACE_S, 60))

    def test_capped_and_garbage_safe(self):
        base, _ = api._offline_thresholds({'poll_interval': 60}, 180)
        # over the 24h cap is clamped
        big, _ = api._offline_thresholds(
            {'poll_interval': 60, 'offline_alert_delay_min': 99999}, 180)
        self.assertEqual(big, base + 1440 * 60)
        # garbage falls back to 0
        junk, _ = api._offline_thresholds(
            {'poll_interval': 60, 'offline_alert_delay_min': 'soon'}, 180)
        self.assertEqual(junk, base)
        neg, _ = api._offline_thresholds(
            {'poll_interval': 60, 'offline_alert_delay_min': -5}, 180)
        self.assertEqual(neg, base)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('DEVICES_FILE', 'AUDIT_LOG_FILE'):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'get_json_body', 'require_admin_auth',
                       'audit_log')}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_admin_auth = lambda: 'admin'
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestAlertDelayEndpoint(_HandlerBase):
    def test_patch_sets_and_caps(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}})
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'offline_alert_delay_min': 9999}
        r = self.call(api.handle_device_alert_delay, 'd1')
        self.assertEqual(r['offline_alert_delay_min'], 1440)   # capped
        self.assertEqual(
            api.load(api.DEVICES_FILE)['d1']['offline_alert_delay_min'], 1440)

    def test_patch_404_unknown_device(self):
        api.save(api.DEVICES_FILE, {})
        api.method = lambda: 'PATCH'
        api.get_json_body = lambda: {'offline_alert_delay_min': 5}
        self.call(api.handle_device_alert_delay, 'nope')
        self.assertEqual(self.cap['s'], 404)

    def test_route_registered(self):
        # dynamic route — exercised through _dispatch, so check the source wiring
        import inspect
        src = inspect.getsource(api._dispatch)
        self.assertIn("/alert-delay", src)
        self.assertIn('handle_device_alert_delay', src)


class TestSaveBulkAcceptsField(_HandlerBase):
    def test_save_bulk_whitelists_delay(self):
        import inspect
        src = inspect.getsource(api.handle_device_save_bulk)
        self.assertIn('offline_alert_delay_min', src)


class TestDeviceListExposesField(unittest.TestCase):
    def test_list_row_includes_field(self):
        import inspect
        src = inspect.getsource(api.handle_devices_list)
        self.assertIn("'offline_alert_delay_min'", src)


class TestDrawerUI(unittest.TestCase):
    def test_drawer_control_and_save(self):
        self.assertIn('ds-alert-delay', _APP_JS)
        self.assertIn('offline_alert_delay_min', _APP_JS)


if __name__ == '__main__':
    unittest.main()
