"""Security Advisory — the "what should I fix first" roll-up.

Every other security page answers "what is the state of X". This one answers
the operator's actual question, so the properties that matter are:

  * ORDER is the product — severity first, then blast radius. A list of forty
    things in arbitrary order is just a second inbox.
  * a finding must carry EVIDENCE and a concrete FIX, or it does not earn its
    place on the list;
  * identical findings across hosts GROUP into one decision;
  * the AI brief is REDACTED — evidence never leaves the box.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import advisory  # noqa: E402

_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _dev(name, **si):
    return {'name': name, 'sysinfo': si}


class TestFindingQuality(unittest.TestCase):
    """A finding that can't say what to do is noise."""

    def _all(self, devices, **kw):
        return advisory.build(devices, **kw)['findings']

    def test_every_finding_has_a_concrete_fix_and_reason(self):
        devs = {
            'd1': _dev('web1', packages={'upgradable': 12, 'security': 4},
                       reboot_required=True,
                       listening_ports=[{'scope': 'world', 'port': 22, 'proto': 'tcp',
                                         'process': 'sshd'}],
                       firewall={'active': False, 'backends': [{'name': 'ufw'}]},
                       ssh_config={'permit_root_login': 'yes',
                                   'password_authentication': 'yes'},
                       guard_quarantine=[{'orig': '/var/www/x.php', 'id': 'q1'}]),
        }
        found = self._all(devs)
        self.assertTrue(found)
        for g in found:
            self.assertTrue(g['fix'].strip(), g['title'])
            self.assertTrue(g['why'].strip(), g['title'])
            self.assertTrue(g['source'].strip(), g['title'])
            self.assertIn(g['layer'], advisory.LAYERS, g['title'])
            self.assertIn(g['severity'], advisory.SEVERITY_RANK, g['title'])

    def test_findings_are_ordered_by_severity_then_blast_radius(self):
        devs = {f'd{i}': _dev(f'h{i}', packages={'upgradable': 5}) for i in range(5)}
        devs['dq'] = _dev('hq', guard_quarantine=[{'orig': '/tmp/x', 'id': 'q'}])
        found = self._all(devs)
        ranks = [advisory.SEVERITY_RANK[g['severity']] for g in found]
        self.assertEqual(ranks, sorted(ranks), 'order is the product')
        # critical (1 host) must still outrank medium (5 hosts)
        self.assertEqual(found[0]['severity'], 'critical')

    def test_more_affected_hosts_wins_within_a_severity(self):
        devs = {f'p{i}': _dev(f'p{i}', packages={'upgradable': 3}) for i in range(4)}
        devs['r1'] = _dev('r1', reboot_required=True)
        med = [g for g in self._all(devs) if g['severity'] == 'medium']
        self.assertGreaterEqual(len(med), 2)
        self.assertGreaterEqual(med[0]['device_count'], med[1]['device_count'])

    def test_a_clean_fleet_produces_nothing(self):
        """Manufacturing concerns for a healthy fleet destroys the signal."""
        devs = {'d1': _dev('clean', packages={'upgradable': 0},
                           firewall={'active': True, 'backends': [{'name': 'ufw',
                                                                   'active': True,
                                                                   'rules': 12}]})}
        self.assertEqual(self._all(devs), [])

    def test_evidence_is_carried_not_just_a_count(self):
        devs = {'d1': _dev('web1', listening_ports=[
            {'scope': 'world', 'port': 6379, 'proto': 'tcp', 'process': 'redis-server'}])}
        g = next(g for g in self._all(devs) if g['id'] == 'exp.world')
        self.assertTrue(any('6379' in e and 'redis' in e for e in g['evidence']))


class TestGrouping(unittest.TestCase):
    def test_the_same_problem_on_many_hosts_is_one_decision(self):
        devs = {f'd{i}': _dev(f'h{i}', packages={'upgradable': 3}) for i in range(20)}
        found = advisory.build(devs)['findings']
        patches = [g for g in found if g['id'] == 'os.patches']
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['device_count'], 20)

    def test_a_group_takes_the_worst_severity_any_member_reported(self):
        devs = {'a': _dev('a', packages={'upgradable': 3}),               # medium
                'b': _dev('b', packages={'upgradable': 3, 'security': 2})}  # high
        g = next(g for g in advisory.build(devs)['findings'] if g['id'] == 'os.patches')
        self.assertEqual(g['severity'], 'high')

    def test_the_device_list_is_bounded_but_the_count_is_not(self):
        devs = {f'd{i}': _dev(f'h{i}', packages={'upgradable': 1}) for i in range(60)}
        g = advisory.build(devs)['findings'][0]
        self.assertEqual(g['device_count'], 60)
        self.assertLessEqual(len(g['devices']), 25)


class TestLayers(unittest.TestCase):
    """From OS to application — the point is that it spans all of them."""

    def test_application_layer_comes_from_scan_findings(self):
        devs = {'d1': _dev('web1')}
        scans = {'d1': [{'tool': 'wpscan', 'findings': [
            {'severity': 'critical', 'name': 'Vulnerable plugin foo 1.2',
             'url': 'https://example.test/wp-content/plugins/foo',
             'remediation': 'Update the plugin to 1.3'}]}]}
        g = advisory.build(devs, scans_by_dev=scans)['findings'][0]
        self.assertEqual(g['layer'], 'application')
        self.assertIn('wpscan', g['title'])
        self.assertIn('Update the plugin', g['fix'])

    def test_low_severity_scan_findings_do_not_pad_the_list(self):
        devs = {'d1': _dev('web1')}
        scans = {'d1': [{'tool': 'nikto', 'findings': [
            {'severity': 'info', 'name': 'Server banner disclosed'}]}]}
        self.assertEqual(advisory.build(devs, scans_by_dev=scans)['findings'], [])

    def test_integrity_layer_surfaces_quarantine_as_critical(self):
        devs = {'d1': _dev('web1', guard_quarantine=[{'orig': '/var/www/s.php', 'id': 'q'}])}
        g = advisory.build(devs)['findings'][0]
        self.assertEqual((g['layer'], g['severity']), ('integrity', 'critical'))

    def test_identity_layer_flags_root_ssh(self):
        devs = {'d1': _dev('h', ssh_config={'permit_root_login': 'yes'})}
        g = next(g for g in advisory.build(devs)['findings'] if g['id'] == 'id.rootssh')
        self.assertEqual(g['layer'], 'identity')
        self.assertTrue(any('PermitRootLogin' in e for e in g['evidence']))

    def test_a_muted_exposure_is_not_reported(self):
        """An operator who has already accepted a public port must not keep
        being told about it — that is what muting means."""
        devs = {'d1': _dev('h', listening_ports=[
            {'scope': 'world', 'port': 443, 'proto': 'tcp', 'process': 'nginx'}])}
        out = advisory.build(devs, muted_fn=lambda *a, **k: True)['findings']
        self.assertEqual([g for g in out if g['id'] == 'exp.world'], [])


class TestAiBriefIsRedacted(unittest.TestCase):
    """The provider may be off-box. Titles and counts go; guts do not."""

    def test_evidence_never_reaches_the_model(self):
        devs = {'d1': _dev('secret-host-01', listening_ports=[
            {'scope': 'world', 'port': 6379, 'proto': 'tcp', 'process': 'redis-server'}],
            guard_quarantine=[{'orig': '/var/www/html/evil-shell.php', 'id': 'q'}])}
        brief = advisory.summarize_for_ai(advisory.build(devs), 'the whole fleet')
        for leak in ('evil-shell.php', '/var/www', 'redis-server', '6379',
                     'secret-host-01'):
            self.assertNotIn(leak, brief, f'{leak} leaked into the AI brief')

    def test_the_brief_still_carries_what_the_model_needs(self):
        devs = {'d1': _dev('h', packages={'upgradable': 9})}
        brief = advisory.summarize_for_ai(advisory.build(devs), 'the whole fleet')
        self.assertIn('MEDIUM', brief)
        self.assertIn('os', brief)
        self.assertIn('1 host', brief)

    def test_a_clean_fleet_says_so_rather_than_sending_an_empty_list(self):
        brief = advisory.summarize_for_ai(advisory.build({'d': _dev('h')}), 'host h')
        self.assertIn('No critical or high findings', brief)

    def test_the_brief_is_bounded(self):
        devs = {f'd{i}': _dev(f'h{i}', packages={'upgradable': i + 1},
                              guard_quarantine=[{'orig': f'/x/{i}', 'id': f'q{i}'}])
                for i in range(400)}
        self.assertLessEqual(
            len(advisory.summarize_for_ai(advisory.build(devs), 'fleet')), 6000)


class TestRobustness(unittest.TestCase):
    """It reads whatever the stores happen to hold, so it must not throw."""

    def test_malformed_stores_do_not_raise(self):
        for devs in ({}, {'d': None}, {'d': {}}, {'d': {'sysinfo': None}},
                     {'d': {'sysinfo': {'listening_ports': 'nope'}}},
                     {'d': {'sysinfo': {'tls_certs': [{'days_left': 'soon'}]}}},
                     {'d': {'sysinfo': {'packages': {'upgradable': 'many'}}}}):
            advisory.build(devs)          # must not raise

    def test_a_cve_record_in_either_shape_is_tolerated(self):
        devs = {'d': _dev('h')}
        advisory.build(devs, cve_by_dev={'d': None})
        advisory.build(devs, cve_by_dev={'d': {'findings': None}})
        out = advisory.build(devs, cve_by_dev={'d': {'findings': [
            {'severity': 'critical', 'vuln_id': 'CVE-1', 'package': 'p'}]}})
        self.assertEqual(out['findings'][0]['severity'], 'critical')

    def test_an_ignored_cve_stops_driving_the_advisory(self):
        devs = {'d': _dev('h')}
        out = advisory.build(devs, cve_by_dev={'d': {'findings': [
            {'severity': 'critical', 'vuln_id': 'CVE-1', 'package': 'p',
             'ignored': True}]}})
        self.assertEqual(out['findings'], [])


class TestApiWiring(unittest.TestCase):
    def test_handlers_are_bound_from_the_module(self):
        for n in ('handle_security_advisory', 'handle_security_advisory_brief',
                  '_advisory_scope', '_build_advisory', '_failed_protect_checks'):
            self.assertEqual(getattr(api, n).__module__, 'advisory_handlers', n)

    def test_routes_are_registered(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("('GET', '/api/security/advisory'): handle_security_advisory", src)
        self.assertIn("('POST', '/api/security/advisory/brief')", src)

    def test_scope_is_filtered_through_the_tenant_aware_helper(self):
        """A tenant admin has scope=None, so gating on _caller_scope() alone
        would advise across the whole fleet. See CLAUDE.md."""
        src = (_CGI / 'advisory_handlers.py').read_text()
        self.assertIn('_scope_filter_devices', src)
        self.assertNotIn('_caller_scope', src)

    def test_the_ai_prompt_exists(self):
        import ai_provider
        self.assertIn('security_advisory', ai_provider.SYSTEM_PROMPTS)
        self.assertIn('security_advisory', api._AI_PROMPT_LABELS)


if __name__ == '__main__':
    unittest.main()
