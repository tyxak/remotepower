#!/usr/bin/env python3
"""8.0.2 review (threat-flow R7, and the Request log): a key or a role confined to some hosts does not act as the platform operator on the Threat Intel page.

`operator` was "an administrator, and with tenants the platform operator". An administrator's API key with a host scope is confined to those hosts, but it passed as the
operator: `POST /api/ip-intel/clear` forgot what was recorded for every other host, for the Cloudflare edge and for the honeypot and dropped every host's queued evidence, and the
page gave it the Request log (a line for every host that sent evidence), the edge feeds and the settings. The scope is part of the question now.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-ipi-scope-'))
sys.path.insert(0, str(CGI))
sys.path.insert(0, str(ROOT / 'tests'))

NOW = int(time.time())
SCOPE = {'type': 'groups', 'values': ['web']}


def _api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-ipi-scope-')
    spec = importlib.util.spec_from_file_location('api_ipi_scope', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAScopedAdministratorIsNotTheOperator(unittest.TestCase):

    def setUp(self):
        self.api = api = _api()
        api.save(api.CONFIG_FILE, {'ip_intel': {'sensor_enabled': True}})
        api.save(api.DEVICES_FILE, {'web1': {'name': 'web-one', 'os': 'Debian 12', 'token': 't1', 'group': 'web', 'last_seen': NOW},
                                    'db1': {'name': 'db-payroll', 'os': 'Debian 12', 'token': 't2', 'group': 'db', 'last_seen': NOW}})
        seen = {'count': 5, 'unit': 'threat-sensor', 'at': NOW}
        api.save(api.IPINTEL_FILE, {'attackers': {
            '185.220.101.1': {'first_seen': NOW, 'last_seen': NOW, 'devices': {'web1': dict(seen)}},
            '185.220.101.2': {'first_seen': NOW, 'last_seen': NOW, 'devices': {'db1': dict(seen)}},
            '185.220.101.3': {'first_seen': NOW, 'last_seen': NOW, 'devices': {'edge:cloudflare': dict(seen)}}}})
        api.save(api.IPINTEL_INTAKE_FILE, {'adopted': True, 'sensors': {}, 'cursors': {}, 'log': [
            {'device_id': 'db1', 'at': NOW, 'n': 1, 'queued': 1, 'throttled': 0, 'dropped': 0, 'ignored': {}, 'ips': ['185.220.101.2']}],
            'queue': [{'ip': '185.220.101.2', 'device_id': 'db1', 'unit': 'threat-sensor', 'count': 3, 'window_s': 60, 'at': NOW,
                       'evidence': {'ip': '185.220.101.2', 'src': {'web': 3}, 'tok': {'web': {'req:probe': 3}}, 'first': NOW, 'last': NOW}}]})
        api._LOAD_CACHE.clear()
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        api.verify_token = lambda tok=None: ('svc', 'admin')
        self.scope = None
        api._caller_scope = lambda: self.scope

    def call(self, fn, method):
        api, cap = self.api, {}

        def respond(status, data=None, headers=None):
            cap['r'] = (status, data)
            raise api.HTTPError(status, data)
        real = api.respond
        api.respond = respond
        api.method = lambda: method
        api._LOAD_CACHE.clear()
        try:
            fn()
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.respond = real
        return cap.get('r')

    def left(self):
        self.api._LOAD_CACHE.clear()
        return sorted(self.api.load(self.api.IPINTEL_FILE).get('attackers') or {}), len((self.api.load(self.api.IPINTEL_INTAKE_FILE) or {}).get('queue') or [])

    def test_a_scoped_key_clears_the_addresses_of_its_hosts_and_nothing_else(self):
        self.scope = SCOPE
        status, out = self.call(self.api.handle_ip_intel_clear, 'POST')
        self.assertEqual(status, 200)
        self.assertEqual(self.left(), (['185.220.101.2', '185.220.101.3'], 1), 'the database host, the edge and the queue were not its to clear')

    def test_control_an_unscoped_administrator_clears_everything(self):
        self.scope = None
        self.call(self.api.handle_ip_intel_clear, 'POST')
        self.assertEqual(self.left(), ([], 0))

    def test_a_scoped_key_is_not_given_the_request_log_or_the_instance_feeds(self):
        self.scope = SCOPE
        status, page = self.call(self.api.handle_ip_intel, 'GET')
        self.assertEqual(status, 200)
        self.assertFalse(page['operator'])
        self.assertIsNone(page['requests'])
        self.assertEqual([a['ip'] for a in page['attackers']], ['185.220.101.1'])

    def test_control_the_unscoped_administrator_is_the_operator_and_reads_the_request_log(self):
        self.scope = None
        status, page = self.call(self.api.handle_ip_intel, 'GET')
        self.assertTrue(page['operator'])
        self.assertIsNotNone(page['requests'])


if __name__ == '__main__':
    unittest.main()
