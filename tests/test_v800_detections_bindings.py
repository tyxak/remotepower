#!/usr/bin/env python3
"""8.0.0: what reads a Detections finding besides its own page: the Data Explorer, Fleet Query, the risk score, the compliance evidence, the AI context of a host, the fleet report
and the host's own drawer (its `?host=` read).

A finding that only its own tab can show is a finding that the risk score, the questions an operator asks of the fleet and the report an auditor reads do not know about. Each
reader here is driven through the real handler or builder over a store the real sweep wrote, with the module off as its control (nothing reads a store the module did not write)
and a second organisation as the other one (nobody reads another tenant's findings).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-detections-bind-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import compliance  # noqa: E402
from test_v800_detections_sweep import PUB2, _Server, device, row  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

ROOT = _TESTS.parent


class _Found(_Server):
    """Two hosts, a shell on the Internet on the first and a way back in and a new destination on the second; the sweep has run."""

    def setUp(self):
        super().setUp()
        self.api.fire_webhook('ssh_key_added', {'device_id': 'web02', 'name': 'web02', 'user': 'root', 'fingerprint': 'SHA256:x'})
        self.plant('web01', rows=[row(ip=PUB2, port=4444, proc='bash')])
        self.plant('web02', rows=[row(ip='9.9.9.9', proc='curl')])
        self.sweep()

    def ask(self, qs, fn=None, token='k'):
        return _run(self.api, fn or self.api.handle_fleet_query, None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': qs})


class TestTheDataExplorer(_Found):

    def test_the_entity_is_listed_and_answers_one_row_for_each_finding(self):
        self.assertIn('detections', self.api._qe_entity_names())
        st, got = self.call(self.api.handle_query, body={'entity': 'detections'}, method='POST')
        self.assertEqual(st, 200, got)
        self.assertEqual(got['meta']['total'], 2)
        by = {r['device_id']: r for r in got['rows']}
        self.assertEqual(set(by), {'web01', 'web02'})
        r = by['web01']
        self.assertEqual((r['rule'], r['rule_title'], r['severity'], r['address'], r['port'], r['program'], r['monitored']),
                         ('interpreter_egress', 'A shell or network tool talks to the Internet', 'high', PUB2, 4444, 'bash', True))
        self.assertIn('bash on web01 is connected to', r['detail'])
        self.assertIsInstance(r['raised_at'], int)
        self.assertEqual(by['web02']['rule'], 'persistence_then_egress')

    def test_a_condition_on_a_field_picks_the_rows(self):
        st, got = self.call(self.api.handle_query, body={'entity': 'detections', 'where': {'field': 'rule', 'op': 'eq', 'value': 'persistence_then_egress'}}, method='POST')
        self.assertEqual((st, [r['device_id'] for r in got['rows']]), (200, ['web02']))
        st, got = self.call(self.api.handle_query, body={'entity': 'detections', 'where': {'field': 'severity', 'op': 'eq', 'value': 'critical'}}, method='POST')
        self.assertEqual((st, got['rows']), (200, []))

    def test_with_the_module_off_the_entity_is_not_listed_and_has_no_rows(self):
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=False, traffic_module_enabled=True)
        self.assertNotIn('detections', self.api._qe_entity_names())
        self.assertEqual(self.api._qe_detections_rows(), [], 'the route is outside /api/detections, so the loader checks the switch itself')

    def test_the_stored_findings_of_a_host_the_caller_cannot_see_are_not_rows(self):
        self.api.verify_token = lambda t: {'sc': ('scoped', 'viewer')}.get(t, (None, None))
        self.api._scope_filter_devices = lambda devs: {k: v for k, v in devs.items() if k == 'web01'}
        st, got = self.call(self.api.handle_query, body={'entity': 'detections'}, method='POST', token='sc')
        self.assertEqual((st, [r['device_id'] for r in got['rows']]), (200, ['web01']))


class TestFleetQuery(_Found):

    def test_the_helper_reads_only_the_hosts_it_is_given(self):
        self.api._LOAD_CACHE.clear()
        store = self.api._load_ro(self.api.DETECTIONS_FILE)
        dm = self.api.detections_handlers_mod
        one = {'web01': self.api._load_ro(self.api.DEVICES_FILE)['web01']}
        self.assertEqual(dm.hosts_detected(one, store, 'high'), {'web01'}, 'web02 also has a high finding and was not asked about')
        self.assertEqual(dm.hosts_detected({}, store, 'high'), set())
        self.assertEqual(dm.hosts_detected(one, store, ''), set(), 'an empty needle is no criterion')
        self.assertEqual([r['device_id'] for r in dm.explorer_rows(one, store)], ['web01'])

    def test_the_criterion_finds_the_hosts_by_rule_sentence_address_program_and_severity(self):
        for needle, want in (('bash', ['web01']), ('shell', ['web01']), (PUB2, ['web01']), ('interpreter_egress', ['web01']), ('way back in', ['web02']), ('high', ['web01', 'web02']),
                             ('BASH', ['web01']), ('persistence', ['web02'])):
            st, got = self.ask('detected=' + needle.replace(' ', '%20'))
            self.assertEqual(st, 200, got)
            self.assertEqual(sorted(r['device_id'] for r in got['devices']), want, needle)

    def test_a_criterion_nothing_matches_finds_no_host_and_no_criterion_finds_both(self):
        st, got = self.ask('detected=nothing-like-this')
        self.assertEqual((st, got['devices']), (200, []))
        st, got = self.ask('')
        self.assertEqual(sorted(r['device_id'] for r in got['devices']), ['web01', 'web02'])

    def test_with_the_module_off_the_criterion_finds_no_host(self):
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=False, traffic_module_enabled=True)
        st, got = self.ask('detected=bash')
        self.assertEqual((st, got['devices']), (200, []), 'it answers only while the module is on, like Talks to')

    def test_the_criterion_is_one_of_the_ones_the_server_names_and_the_form_has_its_field(self):
        src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'app', 'talks', 'detected',", src)
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="fq-detected"', html)
        self.assertIn('data-module="detections"><label class="form-label">Detection</label><input type="text" id="fq-detected"', html)
        app = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("detected: 'fq-detected'", app)


class TestTheRiskScore(_Found):

    def factors(self, dev='web01'):
        self.api._LOAD_CACHE.clear()
        return {f['kind']: f for r in self.api._compute_fleet_risk() if r['device_id'] == dev for f in r['factors']}

    def test_a_high_finding_scores_once_and_names_the_sentence(self):
        f = self.factors('web01')['detections']
        self.assertEqual(f['points'], self.api._RISK_WEIGHTS['detections'])
        self.assertIn('1 serious finding from the Detections rules (bash on web01 is connected to', f['detail'])

    def test_a_critical_finding_scores_twice_and_the_cap_holds(self):
        self.api.fire_webhook('brute_force_detected', {'device_id': 'web01', 'name': 'web01', 'source_ip': PUB2, 'count': 50})
        self.api.fire_webhook('login_new_source', {'device_id': 'web01', 'name': 'web01', 'source': PUB2, 'user': 'root'})
        self.sweep()
        self.assertEqual(self.factors('web01')['detections']['points'], 3 * self.api._RISK_WEIGHTS['detections'], 'one high and one critical: 1 + 2')
        self.plant('web01', rows=[row(ip='9.9.%d.%d' % (i // 200, i % 200 + 1), proc='bash') for i in range(10)])
        self.sweep()
        self.assertEqual(self.factors('web01')['detections']['points'], self.api._RISK_CAPS['detections'], 'five findings of the host are shown, and the score is capped')

    def test_a_medium_finding_is_a_notice_and_does_not_score(self):
        self.plant('web01', rows=[row(ip=PUB2, proc='nc')])
        self.sweep()
        self.assertEqual([r['severity'] for r in self.api._qe_detections_rows() if r['device_id'] == 'web01'], ['medium'])
        self.assertNotIn('detections', self.factors('web01'))

    def test_with_the_module_off_or_the_weight_at_zero_there_is_no_factor(self):
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=False, traffic_module_enabled=True)
        self.assertNotIn('detections', self.factors('web01'))
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=True, traffic_module_enabled=True, risk_weight_detections=0)
        self.assertNotIn('detections', self.factors('web01'))
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=True, traffic_module_enabled=True, risk_weight_detections=5)
        self.assertEqual(self.factors('web01')['detections']['points'], 5, 'the weight is the operator\'s')

    def test_the_factor_is_in_every_registry_a_factor_must_be_in(self):
        api = self.api
        self.assertIn('detections', api._RISK_WEIGHTS)
        self.assertIn('detections', api._RISK_CAPS)
        js = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('detections: %d' % api._RISK_WEIGHTS['detections'], js)
        self.assertIn("detections: 'Detections'", js)
        self.assertIn('id="ap-rw-detections"', (ROOT / 'server' / 'html' / 'index.html').read_text())
        self.assertIn('Detections rule found counts', (ROOT / 'docs' / 'risk.md').read_text())


class TestComplianceEvidence(_Found):

    def test_the_intrusion_control_fails_on_a_detection_and_names_the_hosts(self):
        st, ev = compliance._intrusion_control({'detections': ['web01', 'web02']})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('Behaviour detections raised on 2 hosts in the last 30 days: web01, web02.', ev)

    def test_with_brute_force_too_it_says_both(self):
        st, ev = compliance._intrusion_control({'brute_force': ['web01'], 'detections': ['web02']})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('Brute-force attempts detected on 1 host', ev)
        self.assertIn('Behaviour detections raised on 1 host: web02.', ev)

    def test_with_neither_it_passes_as_it_did_before(self):
        self.assertEqual(compliance._intrusion_control({}), (compliance.PASS, 'No brute-force login activity in the last 30 days.'))
        self.assertEqual(compliance._intrusion_control({'detections': []})[0], compliance.PASS)

    def test_the_facts_are_read_from_the_fleet_log_the_sweep_wrote(self):
        facts = self.api._compliance_facts()
        self.assertEqual(sorted(facts['detections']), ['web01', 'web02'])


class TestTheAiContext(_Found):

    def test_only_the_serious_findings_are_counted_for_the_model(self):
        self.plant('web01', rows=[row(ip=PUB2, port=4444, proc='bash'), row(ip='9.9.9.7', proc='nc')])
        self.sweep()
        out = {d['id']: d for d in self.api._ai_fleet_with_attack_flags(self.api.load(self.api.DEVICES_FILE))}
        flags = [str(f) for f in out['web01'].get('_extra_flags') or [] if 'behaviour detection' in str(f)]
        self.assertEqual(len(flags), 1)
        self.assertIn('1 serious behaviour detection (', flags[0], 'the shell, and not the network tool that is only a medium finding')

    def test_a_host_with_a_serious_finding_is_flagged_for_the_model_and_a_quiet_one_is_not(self):
        devices = self.api.load(self.api.DEVICES_FILE)
        out = {d['id']: d for d in self.api._ai_fleet_with_attack_flags(devices)}
        flags = out['web01'].get('_extra_flags') or []
        self.assertTrue(any('1 serious behaviour detection (A shell or network tool talks to the Internet)' in str(f) for f in flags), flags)
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=False, traffic_module_enabled=True)
        devices = self.api.load(self.api.DEVICES_FILE)
        out = {d['id']: d for d in self.api._ai_fleet_with_attack_flags(devices)}
        self.assertFalse(any('behaviour detection' in str(f) for f in out['web01'].get('_extra_flags') or []), 'module off: nothing read')


class TestTheFleetReport(_Found):

    def test_the_threats_section_counts_the_findings_by_severity(self):
        rep = self.api._build_fleet_report()
        self.assertEqual(rep['threats']['detections'], {'hosts': 2, 'critical': 0, 'high': 2, 'medium': 0})

    def test_a_host_with_two_findings_is_one_host_and_a_medium_one_is_counted_as_medium(self):
        self.plant('web01', rows=[row(ip=PUB2, port=4444, proc='bash'), row(ip='9.9.9.8', proc='bash'), row(ip='9.9.9.7', proc='nc')])
        self.sweep()
        self.assertEqual(self.api._build_fleet_report()['threats']['detections'], {'hosts': 2, 'critical': 0, 'high': 3, 'medium': 1})

    def test_the_csv_and_the_email_say_it(self):
        rep = self.api._build_fleet_report()
        csv = self.api._fleet_report_csv_bytes(rep).decode()
        self.assertIn('Hosts with a detection finding', csv)
        self.assertIn('Detection findings (critical / high / medium)', csv)
        self.assertIn('0 / 2 / 0', csv)
        _subj, body = self.api._render_report_email(rep)
        self.assertIn('Detections         : 2 hosts with a finding (0 critical, 2 high, 0 medium)', body)

    def test_the_print_page_has_the_rows(self):
        js = (ROOT / 'server' / 'html' / 'static' / 'js' / 'report.js').read_text()
        self.assertIn("'Hosts with a detection finding'", js)
        self.assertIn("'Detection findings (critical / high / medium)'", js)

    def test_with_the_module_off_the_section_has_no_detection_rows(self):
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=False, traffic_module_enabled=True)
        rep = self.api._build_fleet_report()
        self.assertIsNone(rep['threats']['detections'])
        self.assertNotIn('Hosts with a detection finding', self.api._fleet_report_csv_bytes(rep).decode())


class TestTheHostsOwnRead(_Found):

    def test_the_host_filter_narrows_the_page_to_one_host(self):
        st, got = self.ask('host=web01', self.api.handle_detections_get)
        self.assertEqual((st, [f['id'] for f in got['findings']], got['total']), (200, ['web01'], 1))
        st, got = self.ask('host=web02', self.api.handle_detections_get)
        self.assertEqual([f['id'] for f in got['findings']], ['web02'])
        st, got = self.ask('host=nope', self.api.handle_detections_get)
        self.assertEqual((st, got['findings']), (200, []), 'a host that is not there has nothing, and nothing is an answer')
        st, got = self.ask('', self.api.handle_detections_get)
        self.assertEqual(got['total'], 2, 'no filter, the whole page')

    def test_a_host_the_caller_may_not_see_is_not_read_by_naming_it(self):
        self.api._scope_filter_devices = lambda devs: {k: v for k, v in devs.items() if k == 'web01'}
        st, got = self.ask('host=web02', self.api.handle_detections_get)
        self.assertEqual((st, got['findings']), (200, []))

    def test_the_drawer_has_its_section_and_its_loader(self):
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="drawer-detections-section" hidden', html)
        self.assertIn('id="drawer-detections-body"', html)
        app = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("if (window._modules && window._modules.detections) _loadJsModule('app-detections.js').then(() => { if (typeof loadDrawerDetections === 'function') loadDrawerDetections(id); });", app)


class TestTwoOrganisations(_Server):
    """What a tenant reads of another tenant's findings through each reader: nothing."""

    def setUp(self):
        super().setUp()
        self.api.verify_token = lambda token: {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin')}.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: {'alice': 'acme', 'bob': 'globex', 'root': 'default'}[user]
        self.put({'web01': device(tenant='acme'), 'web02': device(id='web02', name='web02', token='t2', tenant='globex')},
                 detections_module_enabled=True, traffic_module_enabled=True, tenancy_enforced=True)
        self.plant('web01', rows=[row(ip='9.9.9.1', proc='bash')])
        self.plant('web02', rows=[row(ip='9.9.9.2', proc='bash')])
        self.sweep()

    def test_the_explorer_the_fleet_query_and_the_page_show_a_tenant_its_own_findings_only(self):
        for tok, mine, other in (('ta', 'web01', '9.9.9.2'), ('tb', 'web02', '9.9.9.1')):
            st, got = self.call(self.api.handle_query, body={'entity': 'detections'}, method='POST', token=tok)
            self.assertEqual((st, [r['device_id'] for r in got['rows']]), (200, [mine]), tok)
            self.assertNotIn(other, json.dumps(got), tok)
            st, got = _run(self.api, self.api.handle_fleet_query, None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + tok, 'QUERY_STRING': 'detected=bash'})
            self.assertEqual((st, [r['device_id'] for r in got['devices']]), (200, [mine]), tok)
            self.assertNotIn(other, json.dumps(got), tok)
            st, got = _run(self.api, self.api.handle_detections_get, None, method='GET', env={'HTTP_AUTHORIZATION': 'Bearer ' + tok, 'QUERY_STRING': 'host=' + ('web02' if mine == 'web01' else 'web01')})
            self.assertEqual((st, got['findings']), (200, []), 'naming the other tenant\'s host reads nothing')
        st, got = self.call(self.api.handle_query, body={'entity': 'detections'}, method='POST', token='op')
        self.assertEqual(sorted(r['device_id'] for r in got['rows']), ['web01', 'web02'], 'the platform operator reads both')


class TestTheDocsSayTheSameAsTheCode(unittest.TestCase):

    def test_the_explorer_doc_counts_the_entities_it_has(self):
        from test_ip_intel import _fresh_api
        api = _fresh_api()
        words = {11: 'eleven', 12: 'twelve', 13: 'thirteen', 14: 'fourteen', 15: 'fifteen'}
        n = len(api._QE_ENTITIES)
        doc = (ROOT / 'docs' / 'data-explorer.md').read_text()
        self.assertIn('## The %s entities' % words[n], doc, 'the heading names the number of entities the code has: %d' % n)
        for name in api._QE_ENTITIES:
            self.assertIn('| `%s` |' % name, doc, name)
        self.assertIn('### `detections`', doc)

    def test_fleet_query_names_the_criterion(self):
        self.assertIn('**Detection**', (ROOT / 'docs' / 'fleet-query.md').read_text())


if __name__ == '__main__':
    unittest.main()
