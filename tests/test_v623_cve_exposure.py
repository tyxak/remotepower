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

    def _score_for(self, rows, name):
        return next(h['score'] for h in rows if h['device_name'] == name)

    def test_criticality_weight_scales_the_score(self):
        # Baseline score with no CMDB criticality set.
        base = self._score_for(self._rank()['hosts'], 'exposed-host')
        # Mark the exposed host business-critical → 3× weight.
        api.save(api.CMDB_FILE, {'exp': {'criticality': 'critical'}})
        api._invalidate_load_cache(api.CMDB_FILE)
        rows = self._rank()['hosts']
        weighted = self._score_for(rows, 'exposed-host')
        self.assertAlmostEqual(weighted, round(base * 3.0, 2), places=2,
                               msg='critical criticality must triple the score')
        self.assertEqual(next(h['criticality'] for h in rows
                              if h['device_name'] == 'exposed-host'), 'critical')

    def test_low_criticality_can_reorder_below_a_default_host(self):
        # exposed-host outranks internal-host by default. Make exposed 'low'
        # (0.5×) and internal 'critical' (3×) → internal must now lead.
        api.save(api.CMDB_FILE, {'exp': {'criticality': 'low'},
                                 'int': {'criticality': 'critical'}})
        api._invalidate_load_cache(api.CMDB_FILE)
        self.assertEqual(self._rank()['hosts'][0]['device_name'], 'internal-host')

    def test_unknown_criticality_falls_back_to_neutral_weight(self):
        api.save(api.CMDB_FILE, {'exp': {'criticality': 'bogus'}})
        api._invalidate_load_cache(api.CMDB_FILE)
        # Same as no-criticality baseline (weight 1.0), not a crash.
        self.assertEqual(self._rank()['hosts'][0]['device_name'], 'exposed-host')

    def tearDown(self):
        api.respond, api.require_auth = self._r, self._a
        try:
            api.save(api.CMDB_FILE, {})
            api._invalidate_load_cache(api.CMDB_FILE)
        except Exception:
            pass


class TestCriticalityConstants(unittest.TestCase):
    def test_criticality_choices_and_weights(self):
        self.assertEqual(api.CMDB_CRITICALITIES, ('', 'low', 'normal', 'high', 'critical'))
        # Every non-empty choice has a weight; higher criticality → higher weight.
        for c in api.CMDB_CRITICALITIES:
            self.assertIn(c, api._CMDB_CRIT_WEIGHT)
        self.assertGreater(api._CMDB_CRIT_WEIGHT['critical'], api._CMDB_CRIT_WEIGHT['high'])
        self.assertGreater(api._CMDB_CRIT_WEIGHT['high'], api._CMDB_CRIT_WEIGHT['normal'])
        self.assertGreater(api._CMDB_CRIT_WEIGHT['normal'], api._CMDB_CRIT_WEIGHT['low'])
        self.assertEqual(api._CMDB_CRIT_WEIGHT[''], 1.0, 'no criticality is neutral')


if __name__ == '__main__':
    unittest.main()
