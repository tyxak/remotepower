"""v6.2.3: exposure-weighted CVE ranking. Combines the CVE findings store with
the world-exposed-ports signal so a critical CVE on a world-reachable host
outranks more criticals on a loopback-only host. Tenant/scope-safe fleet aggregate.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-cvx-'))
_spec = importlib.util.spec_from_file_location('api_v623_cvx', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestExposureRankedCVE(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            'exp': {'name': 'exposed-host', 'tenant': '',
                    'sysinfo': {'listening_ports': [
                        {'proto': 'tcp', 'port': 443, 'scope': 'world'},
                        {'proto': 'tcp', 'port': 22, 'scope': 'world'}]}},
            'int': {'name': 'internal-host', 'tenant': '',
                    'sysinfo': {'listening_ports': [
                        {'proto': 'tcp', 'port': 8006, 'scope': 'local'}]}},
            'clean': {'name': 'clean-host', 'tenant': '', 'sysinfo': {'listening_ports': []}},
        })
        api.save(api.CVE_FINDINGS_FILE, {
            'exp': {'findings': [
                {'vuln_id': 'CVE-A', 'severity': 'critical', 'fixed_version': '1.1'},
                {'vuln_id': 'CVE-B', 'severity': 'high', 'fixed_version': ''}]},
            'int': {'findings': [
                {'vuln_id': 'CVE-C', 'severity': 'critical', 'fixed_version': '2'},
                {'vuln_id': 'CVE-D', 'severity': 'critical', 'fixed_version': '2'},
                {'vuln_id': 'CVE-E', 'severity': 'critical', 'fixed_version': ''}]},
            'clean': {'findings': []},
        })
        for f in (api.DEVICES_FILE, api.CVE_FINDINGS_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._r, self._a = api.respond, api.require_auth

        def resp(s, d=None):
            self.cap['s'], self.cap['d'] = s, d
            raise SystemExit
        api.respond = resp
        api.require_auth = lambda: 'admin'

    def tearDown(self):
        api.respond, api.require_auth = self._r, self._a

    def _rank(self):
        try:
            api.handle_cve_exposure_ranked()
        except SystemExit:
            pass
        return self.cap['d']

    def test_world_exposed_host_outranks_more_criticals_behind_firewall(self):
        d = self._rank()
        self.assertEqual(d['hosts'][0]['device_name'], 'exposed-host',
                         'a critical on a world-exposed host must rank first')
        self.assertTrue(d['hosts'][0]['world_exposed'])
        self.assertIn('tcp/443', d['hosts'][0]['exposed_ports'])
        self.assertEqual(d['exposed_with_critical'], 1)

    def test_hosts_without_open_cves_are_excluded(self):
        names = {h['device_name'] for h in self._rank()['hosts']}
        self.assertNotIn('clean-host', names)

    def test_ignored_findings_do_not_count(self):
        api.save(api.CVE_FINDINGS_FILE, {'exp': {'findings': [
            {'vuln_id': 'X', 'severity': 'critical', 'ignored': True}]}})
        api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
        d = self._rank()
        self.assertEqual(d['total'], 0, 'an all-ignored host has no rankable CVEs')


if __name__ == '__main__':
    unittest.main()
