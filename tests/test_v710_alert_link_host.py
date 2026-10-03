#!/usr/bin/env python3
"""v7.1.0: signed alert-email links never take their address from a request.

With "Acknowledge / Resolve links in alert emails" switched on, each alert
email carried two signed, login-free links. Their address was the Host header
of whichever request happened to fire the alert — and the shipped nginx
accepts any Host. Alerts fire inside heartbeats, inbound webhooks, failed
logins and the maintenance sweeps that run on ordinary requests, so a request
with `Host: attacker.example` produced a genuine email from your own server
with links to the attacker's site, carrying working ack/resolve signatures for
that alert. A phishing page on your own mail, and a way to silence the alert.

The customer portal solved the same problem for its sign-in link with an
admin-set canonical URL. The ack links now use the same idea: the dashboard's
public URL from Settings, or no links at all.
"""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v710link-'))
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710link-api-')
    spec = importlib.util.spec_from_file_location('api_v710link', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAckLinksIgnoreTheRequestHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def setUp(self):
        api = self.api
        api.save(api.ALERTS_FILE, [{'id': 'al1', 'event': 'device_offline', 'device_id': 'd1',
                                    'ts': int(time.time()), 'payload': {}}])
        api._find_open_alert_id = lambda event, payload: 'al1'
        api._RCTX.environ = {'HTTP_HOST': 'attacker.example', 'REQUEST_METHOD': 'POST'}

    def tearDown(self):
        self.api._RCTX.environ = None

    def test_without_a_public_url_there_are_no_links(self):
        block = self.api._alert_email_ack_block('device_offline', {}, {'alert_email_ack_links': True})
        self.assertEqual(block, '', 'links were built from the request Host')

    def test_with_a_public_url_the_links_use_it(self):
        cfg = {'alert_email_ack_links': True, 'public_base_url': 'https://rp.example.com'}
        block = self.api._alert_email_ack_block('device_offline', {}, cfg)
        self.assertIn('https://rp.example.com/api/alerts/act?a=al1&op=ack', block)
        self.assertNotIn('attacker.example', block)

    def test_links_stay_off_when_switched_off(self):
        cfg = {'alert_email_ack_links': False, 'public_base_url': 'https://rp.example.com'}
        self.assertEqual(self.api._alert_email_ack_block('device_offline', {}, cfg), '')


class TestTheSetting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def _save(self, body):
        api = self.api
        api._LOAD_CACHE.clear()
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.require_instance_admin_auth = lambda *a, **k: 'admin'
        api._require_platform_operator = lambda *a, **k: None
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'
        api.get_json_body = lambda: dict(body)
        api.get_json_obj = lambda: dict(body)
        out = {}

        def _respond(status, data=None, *a, **k):
            out['status'], out['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return out.get('status'), out.get('data'), api.load(api.CONFIG_FILE) or {}

    def test_only_an_origin_is_stored(self):
        self._save({'alert_email_ack_links': False})
        st, _d, cfg = self._save({'public_base_url': 'https://rp.example.com/some/path?x=1'})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('public_base_url'), 'https://rp.example.com')
        for bad in ('javascript:alert(1)', 'ftp://rp.example.com', 'rp.example.com'):
            self._save({'public_base_url': bad})
            self.assertIn(self.api.load(self.api.CONFIG_FILE).get('public_base_url'),
                          ('', 'https://rp.example.com'), f'{bad!r} was stored')
        self._save({'public_base_url': ''})
        self.assertEqual(self.api.load(self.api.CONFIG_FILE).get('public_base_url'), '')

    def test_links_cannot_be_switched_on_without_it(self):
        self._save({'public_base_url': ''})
        st, data, cfg = self._save({'alert_email_ack_links': True})
        self.assertEqual(st, 400, data)
        self.assertFalse(cfg.get('alert_email_ack_links'))
        st, _d, cfg = self._save({'alert_email_ack_links': True,
                                  'public_base_url': 'https://rp.example.com'})
        self.assertEqual(st, 200)
        self.assertTrue(cfg.get('alert_email_ack_links'))
        st, _d, cfg = self._save({'public_base_url': ''})
        self.assertEqual(st, 400, 'the URL was cleared from under live links')
        self.assertEqual(cfg.get('public_base_url'), 'https://rp.example.com')

    def test_the_settings_page_reads_and_writes_it(self):
        root = _CGI.parent / 'html'
        html = (root / 'index.html').read_text()
        js = (root / 'static' / 'js' / 'app.js').read_text()
        self.assertTrue('id="cfg-public-base-url"' in html, 'no input on the settings page')
        self.assertTrue("public_base_url" in js, 'the settings page never sends it')


if __name__ == '__main__':
    unittest.main()
