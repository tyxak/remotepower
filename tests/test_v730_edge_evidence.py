"""edge_evidence: Cloudflare's firewall events and the honeypot's hits, reduced
to threat_evidence summaries.

The questions worth proving: only a REFUSAL by a mechanism that means an attack
counts (a country rule, a challenge, an IP access rule the honeypot or fail2ban
put there are not evidence); a rule that also blocks an IP list is not trusted;
and nothing a visitor typed is read, kept or put in a report.
"""
import json
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import edge_evidence as ee  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

NOW = 1_790_000_000
ACCT = 'a' * 32
ZONE = '7' * 32
RULE = 'b' * 32
RULE2 = 'c' * 32
ATK = '185.220.101.7'
ATK2 = '45.155.205.233'
EVIL = '"; DROP TABLE x; <script>alert(1)</script> /etc/passwd'


def row(ip=ATK, action='block', source='firewallcustom', rule=RULE, count=5, zone=ZONE):
    return {'zone': zone, 'ip': ip, 'action': action, 'source': source, 'rule': rule, 'count': count}


class TestRequests(unittest.TestCase):
    def test_ids_and_names(self):
        self.assertTrue(ee.valid_id(ACCT))
        for bad in ('', 'A' * 32, 'a' * 31, 'a' * 33, 'g' * 32, None, 5, 'a' * 32 + '\n'):
            self.assertFalse(ee.valid_id(bad), repr(bad))
        self.assertTrue(ee.valid_worker('trap-sink'))
        for bad in ('', '-x', 'a b', 'a/b', 'a' * 64, None, '../x', 'x\n'):
            self.assertFalse(ee.valid_worker(bad), repr(bad))

    def test_the_token_goes_in_a_header_only(self):
        reqs = [ee.zones_request('TOKEN123', ACCT), ee.rules_request('TOKEN123', ZONE),
                ee.firewall_request('TOKEN123', [ZONE], NOW - 600, NOW),
                ee.trap_request('TOKEN123', ACCT, 'trap-sink', NOW * 1000 - 600000, NOW * 1000)]
        for r in reqs:
            self.assertEqual(r['headers']['Authorization'], 'Bearer TOKEN123')
            self.assertNotIn('TOKEN123', r['url'])
            self.assertNotIn('TOKEN123', (r['body'] or b'').decode())
            self.assertTrue(r['url'].startswith('https://api.cloudflare.com/client/v4/'))

    def test_zone_listing_is_scoped_to_the_account(self):
        self.assertIn('account.id=' + ACCT, ee.zones_request('t', ACCT)['url'])
        self.assertNotIn('account.id', ee.zones_request('t', '')['url'])
        self.assertNotIn('account.id', ee.zones_request('t', 'x; rm -rf')['url'])

    def test_a_bad_id_is_refused_before_it_reaches_a_url(self):
        with self.assertRaises(ValueError):
            ee.rules_request('t', '../../etc')
        with self.assertRaises(ValueError):
            ee.trap_request('t', 'nope', 'trap-sink', 1, 2)
        with self.assertRaises(ValueError):
            ee.trap_request('t', ACCT, 'trap sink', 1, 2)

    def test_the_firewall_query_asks_for_groups_not_paths(self):
        body = json.loads(ee.firewall_request('t', [ZONE, 'bad', ZONE], NOW - 600, NOW, 99999999)['body'])
        q = body['query']
        self.assertIn('firewallEventsAdaptiveGroups', q)
        for field in ('clientRequestPath', 'clientRequestQuery', 'userAgent', 'clientRequestHTTPHost'):
            self.assertNotIn(field, q)
        self.assertEqual(body['variables']['zoneTags'], [ZONE, ZONE])
        self.assertEqual(body['variables']['limit'], ee.MAX_ROWS)
        self.assertTrue(body['variables']['since'].endswith('Z'))

    def test_the_trap_query_is_the_shape_the_operators_own_scripts_use(self):
        body = json.loads(ee.trap_request('t', ACCT, 'trap-sink', 1000, 2000, 50)['body'])
        self.assertEqual(body['view'], 'events')
        self.assertEqual(body['timeframe'], {'from': 1000, 'to': 2000})
        self.assertEqual(body['parameters']['datasets'], ['cloudflare-workers'])
        self.assertEqual(body['parameters']['filters'], [
            {'key': '$metadata.service', 'operation': 'eq', 'type': 'string', 'value': 'trap-sink'},
            {'key': 'msg', 'operation': 'eq', 'type': 'string', 'value': 'trap hit'}])


class TestParsers(unittest.TestCase):
    def test_zones(self):
        ok = ee.parse_zones(200, {'success': True, 'result': [
            {'id': ZONE, 'name': 'example.org'}, {'id': 'nope', 'name': 'x'}, 'junk', {'id': ZONE * 2}]})
        self.assertTrue(ok['ok'])
        self.assertEqual(ok['zones'], [{'id': ZONE, 'name': 'example.org'}])
        bad = ee.parse_zones(403, {'success': False, 'errors': [{'code': 9109, 'message': 'Unauthorized\x00 to access'}]})
        self.assertFalse(bad['ok'])
        self.assertTrue(bad['auth'])
        self.assertNotIn('\x00', bad['error'])

    def test_rules_find_a_list_reference_and_a_class(self):
        body = {'success': True, 'result': {'rules': [
            {'id': RULE, 'description': 'Block probes and disclosure', 'action': 'block',
             'expression': '(http.request.uri.path contains "/.git")'},
            {'id': RULE2, 'description': 'Block unusual HTTP methods', 'action': 'block',
             'expression': '(http.request.method in {"TRACE"}) or (ip.src in $tyxak_cf_waf)'},
            {'id': 'short', 'description': 'ignored'}]}}
        r = ee.parse_rules(200, body)['rules']
        self.assertEqual(set(r), {RULE, RULE2})
        self.assertEqual((r[RULE]['c'], r[RULE]['k']), ('probe', False))
        self.assertEqual((r[RULE2]['c'], r[RULE2]['k']), ('probe', True))
        self.assertEqual(ee.parse_rules(404, None), {'ok': True, 'rules': {}})
        self.assertFalse(ee.parse_rules(500, None)['ok'])

    def test_rule_class_reads_the_operators_words(self):
        for text, cls in (('Block SQL injection attempts', 'sqli'), ('XSS filter', 'xss'),
                          ('path traversal', 'traversal'), ('Rate limit login', 'flood'),
                          ('wp-login probes', 'probe'), ('Block WordPress probes', 'probe'),
                          ('Challenge non-DK on admin', 'probe'), ('hello world', None), ('', None)):
            self.assertEqual(ee.rule_class(text), cls, text)

    def test_firewall_rows(self):
        body = {'data': {'viewer': {'zones': [{'zoneTag': ZONE, 'firewallEventsAdaptiveGroups': [
            {'count': 7, 'dimensions': {'clientIP': ATK, 'action': 'block', 'source': 'firewallCustom',
                                        'ruleId': RULE}},
            {'count': 'x', 'dimensions': None}, 'junk']}]}}}
        r = ee.parse_firewall(200, body)
        self.assertTrue(r['ok'])
        self.assertEqual(r['rows'], [row(source='firewallcustom', count=7)])
        self.assertFalse(r['truncated'])

    def test_a_graphql_error_is_read_even_on_http_200(self):
        r = ee.parse_firewall(200, {'data': None, 'errors': [
            {'message': 'zone does not have access to the path', 'extensions': {'code': 'authz'}}]})
        self.assertFalse(r['ok'])
        self.assertTrue(r['auth'])
        r = ee.parse_firewall(200, {'errors': [{'message': 'query too large'}]})
        self.assertFalse(r['ok'])
        self.assertNotIn('auth', r)
        self.assertEqual(ee.parse_firewall(0, None)['error'], 'unreachable')

    def test_a_full_page_is_flagged_truncated(self):
        groups = [{'count': 1, 'dimensions': {'clientIP': ATK, 'action': 'block', 'source': 'waf',
                                              'ruleId': RULE}}] * ee.MAX_ROWS
        r = ee.parse_firewall(200, {'data': {'viewer': {'zones': [
            {'zoneTag': ZONE, 'firewallEventsAdaptiveGroups': groups}]}}})
        self.assertTrue(r['truncated'])

    def test_trap_lines_in_every_wrapper_the_api_uses(self):
        line = {'msg': 'trap hit', 'kind': 'bait', 'ip': ATK, 'action': 'banned',
                'at': '2026-10-10T20:00:00.000Z'}
        events = [
            line,                                              # printed object at top level
            {'source': dict(line)},                            # wrapped under source
            {'$data': json.dumps(line)},                       # wrapped as a JSON string
            {'source': json.dumps({k: v for k, v in line.items() if k != 'at'} | {'kind': 'robots'}),
             '$metadata': {'timestamp': 1790000000000}},       # no `at`: the event's own time
            json.dumps(line),                                  # the whole event as a string
            {'msg': 'sweep', 'scanned': 3},                    # another line of the same Worker
            {'source': {'msg': 'trap hit', 'kind': 'bait', 'ip': ATK, 'action': 'banned',
                        'path': EVIL}},                        # a path is never read
            12, None, [],
        ]
        r = ee.parse_trap(200, {'success': True, 'result': {'events': events}})
        self.assertTrue(r['ok'])
        self.assertEqual(len(r['hits']), 6)
        self.assertEqual({h['kind'] for h in r['hits']}, {'bait', 'robots'})
        for h in r['hits']:
            self.assertEqual(set(h), {'kind', 'ip', 'action', 'at'})
        self.assertEqual(r['hits'][0]['at'], 1791662400)
        self.assertEqual(r['hits'][3]['at'], 1790000000)

    def test_trap_result_as_a_bare_list_and_as_logs(self):
        line = {'msg': 'trap hit', 'kind': 'login', 'ip': ATK, 'action': 'counted'}
        self.assertEqual(len(ee.parse_trap(200, {'result': [line]})['hits']), 1)
        self.assertEqual(len(ee.parse_trap(200, {'result': {'logs': [line]}})['hits']), 1)
        self.assertEqual(ee.parse_trap(200, {'result': None})['hits'], [])
        self.assertFalse(ee.parse_trap(403, {'success': False, 'errors': [
            {'code': 10000, 'message': 'Authentication error'}]})['ok'])


class TestCloudflareEvents(unittest.TestCase):
    def reduce(self, rows, rules=None, **kw):
        return ee.cf_events(rows, rules=rules, now=NOW, since=NOW - 600, until=NOW, **kw)

    def test_a_block_by_a_custom_rule_is_evidence(self):
        evs, st = self.reduce([row(count=5)])
        self.assertEqual(len(evs), 1)
        e = evs[0]
        self.assertEqual(e['ip'], ATK)
        self.assertEqual(e['src'], {'cf': 5})
        self.assertEqual(e['tok'], {'cf': {'cf:custom': 5}})
        self.assertEqual((e['first'], e['last']), (NOW - 600, NOW))
        self.assertEqual(st['kept'], 5)
        self.assertEqual(st['ignored'], {})

    def test_only_a_refusal_counts(self):
        for action in ('challenge', 'managed_challenge', 'jschallenge', 'log', 'skip', 'allow',
                       'challengesolved', 'bypass', ''):
            evs, st = self.reduce([row(action=action)])
            self.assertEqual(evs, [], action)
            self.assertEqual(st['ignored'], {'not_a_refusal': 5}, action)
        for action in ('block', 'connectionclose'):
            self.assertEqual(len(self.reduce([row(action=action)])[0]), 1, action)

    def test_policy_is_not_evidence(self):
        for source in ('country', 'asn', 'ip', 'iprange', 'securitylevel', 'zonelockdown', 'hot',
                       'validation', 'apishield', 'dlp', 'unknown', 'somethingnew'):
            evs, st = self.reduce([row(source=source)])
            self.assertEqual(evs, [], source)
            self.assertEqual(st['ignored'], {'not_an_attack_source': 5}, source)

    def test_each_mechanism_has_its_token_and_class(self):
        for source, tok, cls in (('waf', 'cf:waf', 'waf'), ('firewallmanaged', 'cf:waf', 'waf'),
                                 ('firewallcustom', 'cf:custom', 'waf'), ('ratelimit', 'cf:ratelimit', 'flood'),
                                 ('l7ddos', 'cf:ddos', 'ddos'), ('botfight', 'cf:bot', 'bad_bot'),
                                 ('bic', 'cf:bot', 'bad_bot'), ('uablock', 'cf:ua', 'bad_bot')):
            e = self.reduce([row(source=source, count=4)])[0][0]
            self.assertEqual(list(e['tok']['cf']), [tok], source)
            self.assertIn(cls, te.classes(e), source)

    def test_weak_mechanisms_do_not_make_a_refusal_count(self):
        e = self.reduce([row(source='botfight', count=50)])[0][0]
        self.assertNotIn('cf', e['src'])
        self.assertFalse(te.qualifies(e, 100)[0])
        self.assertTrue(te.qualifies(e, 10)[0])          # through the hostile-request total
        strong = self.reduce([row(source='firewallcustom', count=3)])[0][0]
        self.assertEqual(te.qualifies(strong, 100), (True, 'blocked by Cloudflare 3 times'))

    def test_a_rule_that_also_blocks_a_list_is_not_trusted(self):
        rules = {ZONE: {RULE: {'d': 'carrier', 'c': 'probe', 'k': True}}}
        evs, st = self.reduce([row(count=9)], rules=rules)
        self.assertEqual(evs, [])
        self.assertEqual(st['ignored'], {'list_rule': 9})
        evs, _ = self.reduce([row(count=9)], rules=rules, include_carriers=True)
        self.assertEqual(len(evs), 1)

    def test_the_rule_the_operator_wrote_picks_the_class(self):
        rules = {ZONE: {RULE: {'d': 'Block probes', 'c': 'probe', 'k': False}}}
        e = self.reduce([row(count=6)], rules=rules)[0][0]
        self.assertEqual(e['tok']['cf'], {'req:probe': 6})
        self.assertEqual(te.classes(e), {'probe': 6})
        # another zone's rule with the same id is a different rule
        e = self.reduce([row(count=6, zone='8' * 32)], rules=rules)[0][0]
        self.assertEqual(e['tok']['cf'], {'cf:custom': 6})

    def test_addresses_nobody_should_report(self):
        evs, st = self.reduce([row(ip='10.0.0.5'), row(ip='not-an-ip'), row(ip='173.245.48.9'),
                               row(ip='162.158.1.1'), row(ip='')])
        self.assertEqual(evs, [])
        self.assertEqual(st['ignored'], {'not_public': 15, 'cloudflare_address': 10})

    def test_counts_add_per_address_and_mechanism(self):
        evs, _ = self.reduce([row(count=2), row(count=3, rule=RULE2), row(ip=ATK2, count=4),
                              row(source='waf', count=1)])
        by = {e['ip']: e for e in evs}
        self.assertEqual(by[ATK]['src'], {'cf': 6})
        self.assertEqual(by[ATK]['tok']['cf'], {'cf:custom': 5, 'cf:waf': 1})
        self.assertEqual(by[ATK2]['src'], {'cf': 4})

    def test_nothing_the_visitor_typed_survives(self):
        evil_row = row(count=4)
        evil_row.update(ip=ATK, rule=EVIL, zone=EVIL, source='firewallcustom', action='block')
        evil_row['path'] = EVIL
        evil_row['ua'] = EVIL
        evs, _ = self.reduce([evil_row, dict(row(count=3), source=EVIL, action=EVIL)])
        self.assertEqual(len(evs), 1)
        blob = json.dumps(evs)
        for needle in ('DROP', 'script', 'passwd', 'x;'):
            self.assertNotIn(needle, blob)
        self.assertTrue(set(evs[0]) <= set(te.blank()))

    def test_the_reduction_ends_in_a_report_that_names_what_was_seen(self):
        rules = {ZONE: {RULE: {'d': 'Block probes', 'c': 'probe', 'k': False}}}
        e = self.reduce([row(count=8)], rules=rules)[0][0]
        self.assertTrue(te.qualifies(e, 10)[0])          # five or more refusals by a WAF-like mechanism
        text = ip_intel.evidence_comment(e)
        self.assertEqual(text, 'probing for exposed files and admin pages: 8 attempts within 10 '
                               'minutes, seen by Cloudflare WAF (reported by RemotePower)')
        self.assertEqual(te.categories(e, 'abuseipdb'), [21])


class TestTrapEvents(unittest.TestCase):
    def hit(self, kind='bait', action='banned', ip=ATK, at=NOW - 30):
        return {'kind': kind, 'ip': ip, 'action': action, 'at': at}

    def test_a_ban_is_a_decision_and_is_reportable_at_once(self):
        evs, st = ee.trap_events([self.hit()], now=NOW)
        e = evs[0]
        self.assertEqual((e['src'], e['trp']), ({'trap': 1}, 1))
        self.assertEqual(e['tok']['trap'], {'trap:bait': 1})
        self.assertEqual(te.confirmed_by(e), 'the edge honeypot')
        self.assertTrue(te.qualifies(e, 10)[0])
        self.assertEqual(st['kept'], 1)

    def test_a_counted_hit_waits_for_the_threshold(self):
        e = ee.trap_events([self.hit(kind='login', action='counted')], now=NOW)[0][0]
        self.assertEqual(e['trp'], 0)
        self.assertFalse(te.qualifies(e, 10)[0])

    def test_what_is_not_evidence_is_dropped_and_said(self):
        hits = [self.hit(kind='oddclient'), self.hit(kind='selftest'), self.hit(kind='wpauthed'),
                self.hit(kind='js_beacon'), self.hit(kind='canary_mail'), self.hit(kind='???'),
                self.hit(action='allowlisted'), self.hit(action='shared-egress'),
                self.hit(ip='10.0.0.9'), self.hit(ip='162.158.1.1'), self.hit(ip='junk')]
        evs, st = ee.trap_events(hits, now=NOW)
        self.assertEqual(evs, [])
        self.assertEqual(st['ignored'], {'not_evidence': 6, 'own_or_shared_address': 2,
                                         'not_public': 2, 'cloudflare_address': 1})

    def test_the_decision_actions(self):
        for action in ('banned', 'already-banned', 'already-blocked-elsewhere'):
            self.assertEqual(ee.trap_events([self.hit(action=action)], now=NOW)[0][0]['trp'], 1, action)
        for action in ('counted', 'recorded', 'dk-exempt', 'ban-failed', ''):
            self.assertEqual(ee.trap_events([self.hit(action=action)], now=NOW)[0][0]['trp'], 0, action)

    def test_the_kinds_map_to_the_vocabulary(self):
        for kind, tok in (('canary_use', 'trap:canary'), ('decoy_login', 'trap:decoylogin'),
                          ('robots', 'trap:robots'), ('impostor', 'trap:impostor'),
                          ('mazeloot', 'trap:mazeloot')):
            e = ee.trap_events([self.hit(kind=kind)], now=NOW)[0][0]
            self.assertEqual(list(e['tok']['trap']), [tok], kind)
            self.assertTrue(te.token_valid(tok))
        for tok in ee._TRAP_TOKEN.values():
            self.assertIn(tok, te.TRAP_KINDS)

    def test_one_summary_per_address_with_the_time_span(self):
        evs, _ = ee.trap_events([self.hit(at=NOW - 500), self.hit(kind='robots', action='counted', at=NOW - 100),
                                 self.hit(ip=ATK2, kind='bait', at=0)], now=NOW)
        by = {e['ip']: e for e in evs}
        self.assertEqual(by[ATK]['src'], {'trap': 2})
        self.assertEqual((by[ATK]['first'], by[ATK]['last']), (NOW - 500, NOW - 100))
        self.assertEqual((by[ATK2]['first'], by[ATK2]['last']), (NOW, NOW))

    def test_a_hostile_log_line_reaches_nothing(self):
        evs, _ = ee.trap_events([dict(self.hit(), path=EVIL, ua=EVIL, note=EVIL)], now=NOW)
        self.assertNotIn('DROP', json.dumps(evs))
        text = ip_intel.evidence_comment(evs[0])
        self.assertEqual(text, 'probing for exposed files and admin pages: 1 attempt within 1 '
                               'minute, seen by edge honeypot (reported by RemotePower)')


if __name__ == '__main__':
    unittest.main()
