#!/usr/bin/env python3
"""v7.1.0: attacks and SSH-gateway access reach every surface that reads posture.

Brute-force sources, IP intel's reputation verdicts and blocks, and SSH-gateway
sessions each had a page of their own and nothing else. The advisory saw the
attempts but not whether the source was known-abusive or already blocked; the
risk score saw none of it; the Data Explorer, the report, the AI context, the
Prometheus exporter, RAG, compliance evidence and the timeline had no way to
ask.

Each surface is exercised for real against one seeded store, so a broken
binding fails here rather than reading as "no attacks".
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v710tb-'))
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import advisory  # noqa: E402
import ai_context  # noqa: E402
import compliance  # noqa: E402
import prometheus_export  # noqa: E402
import rag_index  # noqa: E402

BAD = '185.220.101.7'      # known-abusive, not blocked
NOISE = '203.0.113.50'     # no verdict
BLOCKED = '185.220.101.9'  # known-abusive, blocked


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710tb-api-')
    spec = importlib.util.spec_from_file_location('api_v710tb', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Seeded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        now = int(time.time())
        cls.now = now
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Debian 12', 'last_seen': now, 'sshgw_enabled': True},
            'd2': {'name': 'db01', 'os': 'Debian 12', 'last_seen': now}})
        api.save(api.BRUTE_FORCE_FILE, {'d1': {'sshd.service': {
            BAD: [now - 5] * 30, NOISE: [now - 5] * 25}}})
        api.save(api.IPINTEL_FILE, {
            'attackers': {
                BAD: {'verdict': {'score': 100, 'country': 'DE', 'reports': 900},
                      'devices': {'d1': {'count': 30, 'unit': 'sshd.service', 'at': now}},
                      'reported': {'abuseipdb': now}, 'last_seen': now},
                BLOCKED: {'verdict': {'score': 95},
                          'devices': {'d1': {'count': 40, 'unit': 'sshd.service', 'at': now}}},
                NOISE: {'devices': {'d1': {'count': 25, 'unit': 'sshd.service', 'at': now}}},
            },
            'blocks': {'d1': {BLOCKED: {'at': now, 'until': now + 3600, 'by': 'auto'}}}})
        api.save(api.SSHGW_SESSIONS_FILE, {'sessions': [
            {'session_id': 's1', 'username': 'alice', 'device_id': 'd1',
             'client_ip': '198.51.100.4', 'started': now - 600, 'duration_s': 300,
             'bytes_in': 10, 'bytes_out': 20}]})
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update({'brute_force_threshold': 20, 'brute_force_window_seconds': 600,
                    'sshgw_enabled': True})
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: ('alice', 'admin')


class TestAdvisoryAndRisk(_Seeded):
    def test_advisory_names_the_known_abusive_source(self):
        rows = self.api._advisory_brute_force({'d1'})['d1']
        by_ip = {r['source_ip']: r for r in rows}
        self.assertEqual(by_ip[BAD]['score'], 100)
        self.assertFalse(by_ip[BAD]['blocked'])
        f = [x for x in advisory._identity_findings('d1', 'web01', {}, bf_sources=rows)
             if x['id'] == 'id.bruteforce'][0]
        self.assertIn('1 known-abusive', f['title'])
        self.assertEqual(f['severity'], 'high')
        self.assertIn('reputation 100/100', f['evidence'][0], 'known-abusive first')
        self.assertIn('Threat intel', f['fix'])

    def test_risk_scores_both_attack_factors(self):
        r = {x['device_id']: x for x in self.api._compute_fleet_risk()}
        kinds = {f['kind']: f for f in r['d1']['factors']}
        self.assertIn('brute_force', kinds)
        self.assertIn('known_attacker', kinds)
        self.assertIn(BAD, kinds['known_attacker']['detail'])
        self.assertNotIn(BLOCKED, kinds['known_attacker']['detail'], 'a blocked source counted')
        self.assertNotIn('brute_force', {f['kind'] for f in r['d2']['factors']})

    def test_weights_are_tunable_in_every_registry(self):
        js = (_CGI.parent / 'html' / 'static' / 'js' / 'app.js').read_text()
        html = (_CGI.parent / 'html' / 'index.html').read_text()
        for k in ('brute_force', 'known_attacker'):
            self.assertIn(k, self.api._RISK_WEIGHTS)
            self.assertIn(k, self.api._RISK_CAPS)
            self.assertIn(f'{k}: {self.api._RISK_WEIGHTS[k]}', js)
            self.assertIn(f'id="ap-rw-{k}"', html)


class TestQueryReportsAndExport(_Seeded):
    def test_data_explorer_entities(self):
        st, d = self.api._query_run_one({'entity': 'attackers',
                                         'where': {'field': 'blocked', 'op': 'eq', 'value': False}})
        self.assertEqual(st, 200, d)
        self.assertEqual({r['ip'] for r in d['rows']}, {BAD, NOISE})
        st, d = self.api._query_run_one({'entity': 'gateway_sessions'})
        self.assertEqual([r['username'] for r in d['rows']], ['alice'])
        self.api.verify_token = lambda _t=None: ('bob', 'viewer')
        try:
            st, d = self.api._query_run_one({'entity': 'gateway_sessions'})
            self.assertEqual(d['rows'], [], 'a viewer read gateway sessions')
        finally:
            self.api.verify_token = lambda _t=None: ('alice', 'admin')

    def test_report_section_csv_and_email(self):
        rep = self.api._build_fleet_report()
        th = rep['threats']
        self.assertEqual((th['bf_hosts'], th['known_bad_unblocked'], th['blocks_active']), (1, 1, 1))
        self.assertEqual((th['gw_sessions'], th['gw_users']), (1, 1))
        self.assertIn('threats', self.api._REPORT_SECTIONS)
        csv = self.api._fleet_report_csv_bytes(rep).decode()
        self.assertIn('Known-abusive, not blocked', csv)
        _subj, body = self.api._render_report_email(rep)
        self.assertIn('Threats and remote access', body)

    def test_prometheus_families(self):
        ctx = self.api._build_metrics_ctx()
        out = prometheus_export.generate_metrics(ctx)
        self.assertRegex(out, r'remotepower_device_bruteforce_sources\{[^}]*device="d1"[^}]*\} 2')
        self.assertRegex(out, r'remotepower_device_known_attackers_unblocked\{[^}]*\} 1')
        self.assertIn('remotepower_sshgw_devices_opted_in 1', out)
        self.assertIn('remotepower_sshgw_sessions_24h 1', out)


class TestAiRagComplianceTimeline(_Seeded):
    def test_ai_fleet_carries_attack_flags(self):
        fleet = self.api._ai_fleet_with_attack_flags(self.api._load_ro(self.api.DEVICES_FILE))
        web = [d for d in fleet if d.get('name') == 'web01'][0]
        flags = ai_context._device_flags(web)
        self.assertTrue(any('brute force from 2 sources' in f for f in flags), flags)
        self.assertTrue(any('1 known-abusive attacker not blocked' in f for f in flags), flags)
        self.assertNotIn('_extra_flags', self.api._load_ro(self.api.DEVICES_FILE)['d1'],
                         'the shared cached record was mutated')

    def test_rag_indexes_attackers_and_gateway_access(self):
        docs = rag_index.build_threats_corpus(
            self.api._load_ro(self.api.DEVICES_FILE), intel=self.api.load(self.api.IPINTEL_FILE),
            sessions=self.api.load(self.api.SSHGW_SESSIONS_FILE)['sessions'], now=self.now)
        text = '\n'.join(d['text'] for d in docs)
        self.assertIn(f'{BAD}: 30 failed logins', text)
        self.assertIn('BLOCKED on this host', text)
        self.assertIn('alice from 198.51.100.4', text)

    def test_intrusion_evidence_names_unblocked_known_abusive_hosts(self):
        facts = {'brute_force': ['web01'], 'known_bad_unblocked': ['web01'], 'ip_blocks_active': 1}
        _st, ev = compliance._intrusion_control(facts)
        self.assertIn('still not blocked on 1 host(s): web01', ev)
        self.assertIn('1 source address(es) are currently blocked', ev)

    def test_timeline_carries_blocks_and_gateway_logins(self):
        for action in ('ip_intel_block', 'ip_intel_unblock', 'sshgw_open', 'sshgw_device_enabled'):
            self.assertTrue(action.startswith(self.api._TIMELINE_AUDIT_PREFIXES), action)
        self.assertFalse('sshgw_session'.startswith(self.api._TIMELINE_AUDIT_PREFIXES),
                         'a session would show twice (open + close)')


if __name__ == '__main__':
    unittest.main()
