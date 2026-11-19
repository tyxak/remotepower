#!/usr/bin/env python3
"""8.0.2 review (found while closing UI-01 and UI-02): a tenant cannot read from the Threat Intel page that an address is another tenant's host or sign-in source.

The sweep holds back an address that is on the protected networks (the never-block list, the operator's allow-list, the addresses of every host of the installation and where
every tenant's users signed in from) and stores the reason on the address's row. A host's sensor may name any public address, so a user of tenant A named tenant B's host
address and read "on the never-block list". With tenants the reason is the operator's to read; the other callers get the row without it.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-nb-oracle-'))
sys.path.insert(0, str(CGI))
sys.path.insert(0, str(ROOT / 'tests'))
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

NOW = int(time.time())
B_HOST_IP, ORDINARY = '45.33.32.200', '45.33.32.201'


def _api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-nb-oracle-')
    spec = importlib.util.spec_from_file_location('api_nb_oracle_t', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTheReasonIsTheOperatorsToRead(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = api = _api()
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True, 'abuseipdb_api_key': 'a' * 80, 'sniffcat_api_key': 's' * 40,
                                   'ip_intel': {'sensor_enabled': True, 'report_enabled': True, 'lookup_enabled': True, 'report_min_count': 10}})
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'created': 0, 'builtin': True},
                                    'tenantA': {'name': 'A', 'status': 'active', 'created': 1}, 'tenantB': {'name': 'B', 'status': 'active', 'created': 1}})
        api.save(api.USERS_FILE, {'adminA': {'role': 'admin', 'tenant_id': 'tenantA'}, 'root': {'role': 'admin'}})
        api.save(api.DEVICES_FILE, {'devA': {'name': 'a-web', 'tenant': 'tenantA', 'token': 'tokA', 'os': 'Ubuntu 24.04 (Linux)'},
                                    'devB': {'name': 'b-web', 'tenant': 'tenantB', 'token': 'tokB', 'os': 'Ubuntu 24.04 (Linux)', 'public_ip': B_HOST_IP}})
        api._LOAD_CACHE.clear()
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        api._ip_intel_http = lambda req: (200, {'success': True, 'data': {}} if req['method'] == 'POST' else {'data': {'abuseConfidenceScore': 5, 'totalReports': 1,
                                                                                                          'countryCode': 'DE', 'isp': 'x'}, 'success': True})

        def ev(ip):
            return te.normalize_event({'ip': ip, 'first': NOW - 60, 'last': NOW - 10, 'src': {'web': 1, 'f2b': 1}, 'ban': ['sshd']}, now=NOW)
        api.ip_intel_note_evidence('devA', [ev(B_HOST_IP), ev(ORDINARY)], {'sources': []})
        api._LOAD_CACHE.clear()
        st = api.load(api.IPINTEL_FILE) or {}
        st['last_sweep'] = 0
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()
        api.run_ip_intel_if_due()
        api._LOAD_CACHE.clear()

    def page(self, user):
        api, cap = self.api, {}

        def respond(status, data=None, headers=None):
            cap['data'] = data
            raise api.HTTPError(status, data)
        real = api.respond
        api.respond = respond
        api.verify_token = lambda tok=None, _u=user: (_u, 'admin')
        api.method = lambda: 'GET'
        api._LOAD_CACHE.clear()
        try:
            api.handle_ip_intel()
        except (api.HTTPError, SystemExit):
            pass
        finally:
            api.respond = real
        return {a['ip']: a for a in (cap.get('data') or {}).get('attackers', [])}

    def test_the_constant_is_what_the_sweep_stores(self):
        from ip_intel_handlers import PROTECTED_REASON
        import ipaddress
        self.assertEqual(PROTECTED_REASON, ip_intel.never_block_reason('45.33.32.200', [ipaddress.ip_network('45.33.32.0/24')]))

    def test_the_sweep_did_store_the_reason_for_the_protected_address(self):
        stored = self.api.load(self.api.IPINTEL_FILE)['attackers'][B_HOST_IP]
        self.assertIn('never-block', str(stored.get('errors')) + str(stored.get('devices')), 'control: the reason is stored, so the page has something to hide')

    def test_a_tenant_reads_neither_the_reason_nor_the_difference_in_words(self):
        rows = self.page('adminA')
        for ip in (B_HOST_IP, ORDINARY):
            r = rows[ip]
            self.assertNotIn('never-block', str([r.get('errors'), [d.get('not_blocked') for d in r.get('devices', [])]]), ip)

    def test_the_operator_reads_it(self):
        rows = self.page('root')
        r = rows[B_HOST_IP]
        self.assertIn('never-block', str([r.get('errors'), [d.get('not_blocked') for d in r.get('devices', [])]]))


if __name__ == '__main__':
    unittest.main()
