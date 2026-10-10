"""The edge feeds, driven for real against a real store: the server reads
Cloudflare's firewall events and the honeypot Worker's log, queues what they say,
and Threat intel's own sweep reports it.

The seam is `_ip_intel_http`, as in the other Threat intel tests: Cloudflare's API
is faked there and nothing else is. What matters here: nothing is read without
the operator turning it on, the token never comes back out, a failing feed says so
and stops short of moving its cursor, nothing from the edge is ever blocked on a
host, and what reaches a provider is the fixed vocabulary.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-edge-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
from test_ip_intel import ATTACKER, _Case  # noqa: E402

T = 1_790_000_000
ACCT = 'a' * 32
ZONE = '7' * 32
RULE_PROBE = 'b' * 32
RULE_LIST = 'c' * 32
TOKEN = 'CFtoken_' + 'x' * 32
SECOND = '45.155.205.233'
THIRD = '89.248.165.52'
EVIL = '"; DROP TABLE x; <script>alert(1)</script>'


def group(ip, source='firewallCustom', rule=RULE_PROBE, count=5, action='block'):
    return {'count': count, 'dimensions': {'clientIP': ip, 'action': action, 'source': source,
                                           'ruleId': rule}}


def graphql(*groups):
    return {'data': {'viewer': {'zones': [{'zoneTag': ZONE,
                                           'firewallEventsAdaptiveGroups': list(groups)}]}}}


def trap_line(ip, kind='bait', action='banned', at='2026-09-21T10:00:00.000Z', **extra):
    return dict({'msg': 'trap hit', 'kind': kind, 'ip': ip, 'action': action, 'at': at}, **extra)


class _Edge(_Case):
    def setUp(self):
        super().setUp()
        api = self.api
        self.cf_calls = []
        self.zones = {'success': True, 'result': [{'id': ZONE, 'name': 'example.org'}]}
        self.rules = {'success': True, 'result': {'rules': [
            {'id': RULE_PROBE, 'description': 'Block probes and disclosure', 'action': 'block',
             'expression': '(http.request.uri.path contains "/.git")'},
            {'id': RULE_LIST, 'description': 'Block unusual HTTP methods', 'action': 'block',
             'expression': '(http.request.method eq "TRACE") or (ip.src in $community_list)'}]}}
        self.graphql = graphql(group(ATTACKER, count=7), group(SECOND, source='country', count=40),
                               group(THIRD, rule=RULE_LIST, count=9))
        self.trap = {'success': True, 'result': {'events': [
            trap_line(SECOND, kind='robots', action='banned'),
            trap_line(THIRD, kind='login', action='counted')]}}
        self.refuse = {}                    # url fragment -> (status, body)
        provider = api._ip_intel_http

        def _router(req):
            if req['url'].startswith('https://api.cloudflare.com/'):
                return self._cf(req)
            return provider(req)
        api._ip_intel_http = _router
        cfg = api.load(api.CONFIG_FILE)
        cfg['edge_cloudflare_token'] = TOKEN
        api.save(api.CONFIG_FILE, cfg)
        self.policy(edge_enabled=True, edge_account_id=ACCT, report_enabled=True, report_min_count=10)

    def _cf(self, req):
        self.cf_calls.append(req)
        url = req['url']
        for frag, resp in self.refuse.items():
            if frag in url:
                return resp
        if '/client/v4/zones?' in url:
            return 200, self.zones
        if '/rulesets/phases/http_request_firewall_custom/entrypoint' in url:
            return 200, self.rules
        if url.endswith('/graphql'):
            return 200, self.graphql
        if url.endswith('/telemetry/query'):
            return 200, self.trap
        return 404, {'success': False}

    def poll(self, at=T, due=True):
        """One run of the edge sweep at a fixed time."""
        api = self.api
        if due:
            st = api.load(api.IPINTEL_FILE) or {}
            st.setdefault('edge', {})['polled'] = 0
            api.save(api.IPINTEL_FILE, st)
            api._LOAD_CACHE.clear()
        with mock.patch('time.time', return_value=at):
            api.run_edge_intel_if_due()
        api._LOAD_CACHE.clear()
        return api.load(api.IPINTEL_FILE) or {}

    def call(self, fn, method='POST', body=None, role='admin'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def reports(self):
        return [c for c in self.calls if c['method'] == 'POST' and 'report' in c['url']]


class TestOffMeansOff(_Edge):
    def test_nothing_is_read_until_it_is_switched_on(self):
        self.policy(edge_enabled=False)
        self.poll()
        self.assertEqual(self.cf_calls, [])

    def test_a_token_is_needed_and_a_missing_one_is_not_an_error(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_cloudflare_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.poll()
        self.assertEqual(self.cf_calls, [])

    def test_each_feed_has_its_own_switch(self):
        self.policy(edge_trap=False)
        self.poll()
        self.assertTrue(self.cf_calls and all('telemetry' not in c['url'] for c in self.cf_calls))
        self.cf_calls.clear()
        self.policy(edge_trap=True, edge_cf_events=False)
        self.poll()
        self.assertTrue(self.cf_calls and all('graphql' not in c['url'] for c in self.cf_calls))

    def test_the_poll_interval_is_kept(self):
        self.poll()
        n = len(self.cf_calls)
        self.assertGreater(n, 0)
        self.poll(at=T + 120, due=False)
        self.assertEqual(len(self.cf_calls), n)
        self.poll(at=T + 700, due=False)
        self.assertGreater(len(self.cf_calls), n)


class TestTheSweep(_Edge):
    def test_what_each_feed_said_is_queued_under_its_own_name(self):
        st = self.poll()
        q = {(x['ip'], x['device_id']): x for x in st['queue']}
        self.assertEqual(set(q), {(ATTACKER, 'edge:cloudflare'), (SECOND, 'edge:trap'),
                                  (THIRD, 'edge:trap')})
        e = q[(ATTACKER, 'edge:cloudflare')]
        self.assertEqual((e['unit'], e['evidence']['src']), ('edge-feed', {'cf': 7}))
        self.assertEqual(e['evidence']['tok']['cf'], {'req:probe': 7})     # the operator's rule says probes
        self.assertEqual(q[(SECOND, 'edge:trap')]['evidence']['trp'], 1)

    def test_what_is_not_evidence_is_set_aside_and_counted(self):
        st = self.poll()
        cf = st['edge']['cf']
        self.assertEqual(cf['state'], 'ok')
        self.assertEqual((cf['rows'], cf['kept']), (3, 7))
        self.assertEqual(cf['ignored'], {'not_an_attack_source': 40, 'list_rule': 9})
        self.assertNotIn(SECOND, [x['ip'] for x in st['queue'] if x['device_id'] == 'edge:cloudflare'])
        self.assertNotIn(THIRD, [x['ip'] for x in st['queue'] if x['device_id'] == 'edge:cloudflare'])

    def test_a_ban_by_the_honeypot_is_reported_at_once_to_both_providers(self):
        self.poll()
        self.sweep()
        by = {}
        for c in self.reports():
            if 'sniffcat' in c['url']:
                b = json.loads(c['body'])
                by.setdefault(b['ip'], {})['sniffcat'] = b
            else:
                f = parse_qs(c['body'].decode())
                by.setdefault(f['ip'][0], {})['abuseipdb'] = f
        # the honeypot's ban qualifies at one hit; seven Cloudflare refusals qualify
        # like a WAF's; one counted hit on a trap and a list rule's refusals do not
        self.assertEqual(set(by), {SECOND, ATTACKER})
        self.assertEqual(by[ATTACKER]['sniffcat']['categories'], [21])
        self.assertEqual(by[SECOND]['sniffcat']['categories'], [15])
        self.assertEqual(by[SECOND]['abuseipdb']['categories'], ['19'])
        text = by[SECOND]['sniffcat']['comment']
        self.assertEqual(text, 'unwanted web crawling: 1 attempt within 1 minute, seen by edge '
                               'honeypot (reported by RemotePower)')

    def test_cloudflare_refusals_report_after_three_like_the_waf(self):
        self.graphql = graphql(group(ATTACKER, count=3))
        self.trap = {'success': True, 'result': {'events': []}}
        self.poll()
        self.sweep()
        by = {json.loads(c['body'])['ip'] for c in self.reports() if 'sniffcat' in c['url']}
        self.assertEqual(by, {ATTACKER})
        comment = [json.loads(c['body'])['comment'] for c in self.reports() if 'sniffcat' in c['url']][0]
        self.assertTrue(comment.startswith('probing for exposed files and admin pages: 3 attempts'))
        self.assertIn('seen by Cloudflare WAF', comment)

    def test_a_report_says_nothing_the_visitor_typed(self):
        self.trap = {'success': True, 'result': {'events': [
            dict(trap_line(SECOND, kind='bait'), path=EVIL, ua=EVIL, note=EVIL, host=EVIL)]}}
        self.poll()
        self.sweep()
        blob = json.dumps([c['body'].decode() if isinstance(c['body'], bytes) else c['body']
                           for c in self.reports()])
        self.assertTrue(self.reports())
        for needle in ('DROP', 'script', 'example.org'):
            self.assertNotIn(needle, blob)

    def test_an_edge_source_is_never_blocked_on_a_host(self):
        self.policy(block_enabled=True, block_min_score=1, report_enabled=False)
        self.poll()
        st = self.sweep()
        for dev in ('d1', 'd2', 'd3'):
            self.assertEqual([c for c in self.queued(dev) if 'rp-ipintel' in c], [], dev)
        self.assertEqual(st.get('blocks') or {}, {})
        seen = st['attackers'][SECOND]['devices']['edge:trap']
        self.assertEqual(seen['not_blocked'], 'edge sources are only reported')

    def test_the_same_window_is_not_read_twice(self):
        self.poll()
        first = [c for c in self.cf_calls if c['url'].endswith('/graphql')]
        w1 = re.search(r'datetime_geq: "([^"]+)", datetime_lt: "([^"]+)"', json.loads(first[0]['body'])['query'])
        self.cf_calls.clear()
        st = self.poll(at=T + 700)
        q2 = json.loads([c for c in self.cf_calls if c['url'].endswith('/graphql')][0]['body'])['query']
        w2 = re.search(r'datetime_geq: "([^"]+)", datetime_lt: "([^"]+)"', q2)
        self.assertEqual(w2.group(1), w1.group(2))
        self.assertEqual(st['edge']['cf_to'], T + 700 - 90)
        t2 = json.loads([c for c in self.cf_calls if c['url'].endswith('/telemetry/query')][0]['body'])
        self.assertEqual(t2['timeframe']['from'], (T - 5) * 1000)

    def test_a_first_read_goes_back_six_hours_not_a_day(self):
        self.poll()
        q = json.loads([c for c in self.cf_calls if c['url'].endswith('/graphql')][0]['body'])['query']
        since = re.search(r'datetime_geq: "([^"]+)"', q).group(1)
        self.assertTrue(since.startswith('2026-09-21T'))
        import calendar
        import time as _t
        got = calendar.timegm(_t.strptime(since, '%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(got, T - 6 * 3600)

    def test_rules_are_read_once_an_hour(self):
        self.poll()
        n = sum('entrypoint' in c['url'] for c in self.cf_calls)
        self.assertEqual(n, 1)
        self.poll(at=T + 700)
        self.assertEqual(sum('entrypoint' in c['url'] for c in self.cf_calls), 1)
        self.poll(at=T + 4000)
        self.assertEqual(sum('entrypoint' in c['url'] for c in self.cf_calls), 2)

    def test_the_operators_zone_list_is_used_without_asking_for_zones(self):
        self.policy(edge_zone_ids=[ZONE])
        self.poll()
        self.assertTrue(all('/client/v4/zones?' not in c['url'] for c in self.cf_calls))


class TestWhenAFeedFails(_Edge):
    def test_a_token_without_the_permission_says_so_and_keeps_its_cursor(self):
        self.refuse['/graphql'] = (200, {'data': None, 'errors': [
            {'message': 'zone does not have access to the path', 'extensions': {'code': 'authz'}}]})
        st = self.poll()
        cf = st['edge']['cf']
        self.assertEqual(cf['state'], 'no_access')
        self.assertNotIn('cf_to', st['edge'])
        self.assertEqual(st['edge']['trap']['state'], 'ok')           # the other feed carried on
        self.assertIn(SECOND, [x['ip'] for x in st['queue']])

    def test_cloudflare_being_unreachable_is_an_error_not_a_crash(self):
        self.refuse['/telemetry/'] = (0, {'message': 'unreachable: URLError'})
        st = self.poll()
        self.assertEqual(st['edge']['trap']['state'], 'error')
        self.assertEqual(st['edge']['cf']['state'], 'ok')
        self.assertNotIn('trap_to', st['edge'])

    def test_unreadable_rules_do_not_stop_the_events(self):
        self.refuse['/entrypoint'] = (403, {'success': False, 'errors': [{'code': 10000, 'message': 'denied'}]})
        st = self.poll()
        self.assertTrue(st['edge']['cf']['rules_unreadable'])
        self.assertEqual(st['edge']['cf']['state'], 'ok')
        # without the rule list the carrier cannot be told from a probe rule
        self.assertIn(THIRD, [x['ip'] for x in st['queue'] if x['device_id'] == 'edge:cloudflare'])

    def test_a_missing_account_id_only_costs_the_honeypot_feed(self):
        self.policy(edge_account_id='')
        st = self.poll()
        self.assertEqual(st['edge']['trap']['state'], 'no_account')
        self.assertEqual(st['edge']['cf']['state'], 'ok')

    def test_a_bug_in_one_feed_does_not_take_the_sweep_down(self):
        orig = self.api.edge_intel_handlers_mod.edge_evidence.parse_trap

        def boom(*_a, **_k):
            raise RuntimeError('parser bug')
        with mock.patch.object(self.api.edge_intel_handlers_mod.edge_evidence, 'parse_trap', boom):
            st = self.poll()
        self.assertEqual(st['edge']['trap'], {'state': 'error', 'at': T, 'error': 'RuntimeError'})
        self.assertEqual(st['edge']['cf']['state'], 'ok')
        self.assertIsNotNone(orig)


class TestSettings(_Edge):
    def save(self, **body):
        return self.call(self.api.handle_ip_intel_settings, 'POST', body)

    def test_the_token_is_written_but_never_read_back(self):
        st, d = self.save(edge_cloudflare_token='NEWtoken_' + 'y' * 30)
        self.assertEqual(st, 200)
        self.assertTrue(d['settings']['edge_token_set'])
        self.assertNotIn('NEWtoken_', json.dumps(d))
        st, page = self.call(self.api.handle_ip_intel, 'GET')
        self.assertEqual(st, 200)
        self.assertNotIn('NEWtoken_', json.dumps(page))
        self.assertNotIn(TOKEN, json.dumps(page))
        cfg = self.api.load(self.api.CONFIG_FILE)
        self.assertEqual(cfg['edge_cloudflare_token'], 'NEWtoken_' + 'y' * 30)
        self.assertTrue(self.api._SECRET_KEY_RE.search('edge_cloudflare_token'),
                        'the config reader scrubs it by name')
        self.assertTrue(self.api._is_config_secret_name('edge_cloudflare_token'),
                        'and the at-rest encryption walk picks it up by name too')
        # an empty value keeps the stored token, and clearing removes it
        self.save(edge_cloudflare_token='')
        self.assertTrue(self.api.load(self.api.CONFIG_FILE).get('edge_cloudflare_token'))
        self.save(clear_edge_token=True)
        self.assertNotIn('edge_cloudflare_token', self.api.load(self.api.CONFIG_FILE))

    def test_the_audit_line_names_the_change_not_the_secret(self):
        self.save(edge_cloudflare_token='NEWtoken_' + 'y' * 30, edge_enabled=True)
        line = ' '.join(str(a) for a in self.audit[-1])
        self.assertIn('edge_cloudflare_token=set', line)
        self.assertNotIn('NEWtoken_', line)

    def test_every_field_is_validated(self):
        for body in ({'edge_cloudflare_token': 'has space ' * 3}, {'edge_cloudflare_token': 'short'},
                     {'edge_account_id': 'nope'}, {'edge_zone_ids': ['xyz']}, {'edge_zone_ids': 'a' * 31},
                     {'edge_workers': ['bad name']}, {'edge_workers': ['a', 'b', 'c', 'd']},
                     {'edge_poll_minutes': 'soon'}):
            st, d = self.save(**body)
            self.assertEqual(st, 400, body)

    def test_the_values_are_stored_clamped_and_cleaned(self):
        st, d = self.save(edge_poll_minutes=1, edge_zone_ids=f'{ZONE.upper()}, {ZONE}\n{"8" * 32}',
                          edge_workers='trap-sink\ntrap-edge', edge_account_id=ACCT.upper(),
                          edge_cf_events=False, edge_count_list_rules=True)
        self.assertEqual(st, 200)
        s = d['settings']
        self.assertEqual(s['edge_poll_minutes'], 5)
        self.assertEqual(s['edge_zone_ids'], [ZONE, '8' * 32])
        self.assertEqual(s['edge_workers'], ['trap-sink', 'trap-edge'])
        self.assertEqual(s['edge_account_id'], ACCT)
        self.assertEqual((s['edge_cf_events'], s['edge_count_list_rules']), (False, True))
        st, d = self.save(edge_workers=[])
        self.assertEqual(d['settings']['edge_workers'], ['trap-sink'])

    def test_only_an_admin_changes_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'edge_enabled': True}, role='viewer')
        self.assertIn(st, (401, 403))


class TestThePage(_Edge):
    def test_the_operator_sees_the_edge_and_nobody_else_does(self):
        self.poll()
        self.sweep()
        st, d = self.call(self.api.handle_ip_intel, 'GET')
        self.assertEqual(st, 200)
        names = {a['ip']: [x['name'] for x in a['devices']] for a in d['attackers']}
        self.assertEqual(names[SECOND], ['Edge honeypot'])
        self.assertEqual(names[ATTACKER], ['Cloudflare edge'])
        self.assertEqual(d['edge']['cf']['state'], 'ok')
        self.assertTrue(d['edge']['token_set'])
        ev = [a for a in d['attackers'] if a['ip'] == SECOND][0]['evidence']
        self.assertEqual(ev['confirmed'], 'the edge honeypot')
        self.assertIn({'id': 'trap', 'n': 1}, ev['sources'])
        st, d = self.call(self.api.handle_ip_intel, 'GET', role='viewer')
        self.assertEqual(d.get('attackers'), [])
        self.assertIsNone(d.get('edge'))

    def test_the_edge_is_not_a_host_for_the_fleet_views(self):
        self.poll()
        self.sweep()
        self.assertEqual(self.api.ip_intel_by_device(T + 60), {})


class TestTheConnectionTest(_Edge):
    def run_test(self, body=None, role='admin'):
        return self.call(self.api.handle_ip_intel_edge_test, 'POST', body or {}, role=role)

    def test_every_check_runs_and_the_rules_are_listed(self):
        st, d = self.run_test()
        self.assertEqual(st, 200)
        c = d['checks']
        self.assertEqual({k: v['state'] for k, v in c.items()},
                         {'zones': 'ok', 'firewall': 'ok', 'rules': 'ok', 'trap': 'ok'})
        self.assertEqual(c['zones']['names'], ['example.org'])
        listed = {r['d']: r['k'] for r in c['rules']['rules']}
        self.assertEqual(listed, {'Block probes and disclosure': False, 'Block unusual HTTP methods': True})
        self.assertNotIn(TOKEN, json.dumps(d))

    def test_a_missing_permission_shows_as_exactly_that(self):
        self.refuse['/telemetry/'] = (403, {'success': False, 'errors': [
            {'code': 10000, 'message': 'Authentication error'}]})
        st, d = self.run_test()
        self.assertEqual(d['checks']['trap']['state'], 'no_access')
        self.assertEqual(d['checks']['zones']['state'], 'ok')

    def test_the_typed_token_is_the_one_tried_and_is_not_saved(self):
        typed = 'TYPED_token_' + 'z' * 30
        self.run_test({'token': typed})
        self.assertTrue(self.cf_calls and all(c['headers']['Authorization'] == 'Bearer ' + typed
                                              for c in self.cf_calls))
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['edge_cloudflare_token'], TOKEN)

    def test_no_token_no_call(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_cloudflare_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        st, _ = self.run_test()
        self.assertEqual(st, 409)
        self.assertEqual(self.cf_calls, [])

    def test_only_an_admin_and_only_a_post(self):
        st, _ = self.run_test(role='viewer')
        self.assertIn(st, (401, 403))
        self.assertEqual(self.call(self.api.handle_ip_intel_edge_test, 'GET', {})[0], 405)
        self.assertEqual(self.run_test({'account_id': 'nope'})[0], 400)


class TestPolicyDefaults(unittest.TestCase):
    def test_everything_is_off_until_asked_for(self):
        self.assertIs(ip_intel.DEFAULTS['edge_enabled'], False)
        self.assertIs(ip_intel.DEFAULTS['edge_count_list_rules'], False)
        self.assertEqual(set(ip_intel.EDGE_DEVICES), {'edge:cloudflare', 'edge:trap'})
        for dev in ip_intel.EDGE_DEVICES:
            self.assertIn(':', dev, 'a host id never has this shape')


if __name__ == '__main__':
    unittest.main()
