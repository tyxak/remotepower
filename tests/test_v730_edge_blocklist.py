"""edge_blocklist: what goes into the Cloudflare list, and what never does.

The questions worth proving are the ones that would hurt if wrong: nothing the
operator protects reaches the list, a source that fails or shrinks cannot empty it,
the cap is the account's and not just the operator's, and no request carries the
token anywhere but its header.
"""
import ipaddress
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import edge_blocklist as eb  # noqa: E402
import ip_intel  # noqa: E402

ACCT = 'a' * 32
LIST = 'b' * 32
OP = 'c' * 32
NOW = 1_790_000_000
OFFICE = ip_intel.parse_cidrs(['93.184.216.0/24', '151.101.1.7'])   # public: documentation ranges fail first


class TestSpelling(unittest.TestCase):
    def test_names(self):
        for ok in ('remotepower_blocklist', 'tyxak_cf_waf', 'a', 'x' * 50):
            self.assertTrue(eb.valid_name(ok), ok)
        for bad in ('', 'Upper', '1abc', 'has-dash', 'has space', 'x' * 51, None, 5, 'a.b'):
            self.assertFalse(eb.valid_name(bad), repr(bad))

    def test_one_spelling_for_an_entry(self):
        self.assertEqual(eb.canonical('185.220.101.7'), '185.220.101.7')
        self.assertEqual(eb.canonical('185.220.101.7/32'), '185.220.101.7')
        self.assertEqual(eb.canonical('185.220.101.0/24'), '185.220.101.0/24')
        self.assertEqual(eb.canonical('185.220.101.9/24'), '185.220.101.0/24')
        self.assertEqual(eb.canonical('2001:DB8:0:0:0:0:0:1'), '2001:db8::1')
        self.assertEqual(eb.canonical('2001:db8::1/128'), '2001:db8::1')
        for bad in ('', 'nope', '999.1.1.1', None, '1.2.3.4/33'):
            self.assertIsNone(eb.canonical(bad), repr(bad))

    def test_a_list_read_back_compares_equal_to_what_was_sent(self):
        sent = eb.canonical('2001:db8::1')
        back = eb.canonical('2001:DB8:0:0:0:0:0:1')
        self.assertEqual(sent, back)
        self.assertEqual(eb.diff([back], [sent]), ([], []))

    def test_public_and_wide(self):
        for private in ('10.0.0.1', '192.168.1.5', '127.0.0.1', '169.254.1.1', '224.0.0.1', '10.0.0.0/8',
                        'fe80::1', '::1'):
            self.assertFalse(eb.is_public(eb.canonical(private)), private)
        self.assertTrue(eb.is_public('185.220.101.7'))
        self.assertTrue(eb.is_public('185.220.0.0/16'))
        self.assertFalse(eb.too_wide('185.220.0.0/16'))
        self.assertTrue(eb.too_wide('185.0.0.0/8'))
        self.assertTrue(eb.too_wide('2a00::/16'))
        self.assertFalse(eb.too_wide('2a00:1450::/32'))

    def test_the_operators_entries(self):
        out, err = eb.clean_entries('185.220.101.7\n# a comment\n  \n198.18.0.0/16 # not public\n')
        self.assertEqual(out, [])
        self.assertTrue(err.startswith('Not a public address'), err)
        out, err = eb.clean_entries('185.220.101.7, 185.220.101.7\n45.155.205.0/24 # scanner range')
        self.assertEqual((out, err), (['185.220.101.7', '45.155.205.0/24'], ''))
        for text, start in (('hello', 'Not an address'), ('10.0.0.1', 'Not a public'),
                            ('185.0.0.0/8', 'Too wide'), ('2a00::/16', 'Too wide')):
            self.assertTrue(eb.clean_entries(text)[1].startswith(start), text)
        many = '\n'.join(f'185.220.{i // 250}.{i % 250 + 1}' for i in range(2000))
        self.assertEqual(len(eb.clean_entries(many, limit=50)[0]), 50)


class TestWhatIsNeverIncluded(unittest.TestCase):
    def test_a_protected_address_or_range(self):
        self.assertEqual(eb.protected_reason('93.184.216.20', OFFICE), 'on the never-block list')
        self.assertEqual(eb.protected_reason('151.101.1.7', OFFICE), 'on the never-block list')
        self.assertEqual(eb.protected_reason('185.220.101.7', OFFICE), '')
        # a range that merely overlaps a protected address is kept out whole
        self.assertEqual(eb.protected_reason('93.184.0.0/16', OFFICE), 'on the never-block list')
        self.assertEqual(eb.protected_reason('93.184.216.0/25', OFFICE), 'on the never-block list')
        self.assertEqual(eb.protected_reason('185.220.0.0/16', OFFICE), '')
        self.assertEqual(eb.protected_reason('10.1.2.3', OFFICE), 'not a public address')

    def test_cloudflare_itself_is_never_listed(self):
        # one of Cloudflare's own ranges: a list entry would cut the proxy off
        self.assertTrue(eb.protected_reason('104.16.0.1', []))

    def test_build_drops_them_and_counts_them(self):
        got = eb.build(['185.220.101.7'], ['93.184.216.20', '45.155.205.1'], ['151.101.1.7', '89.248.165.2'],
                       [], 100, OFFICE)
        self.assertEqual([e for e, _s in got['items']], ['185.220.101.7', '45.155.205.1', '89.248.165.2'])
        self.assertEqual(got['dropped'], {'protected': 2})


class TestTheChoice(unittest.TestCase):
    def test_priority_dedupe_and_cap(self):
        got = eb.build(['1.1.1.10', '1.1.1.11'], ['1.1.1.11', '2.2.2.2'], ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                       ['5.5.5.5'], 5, [])
        self.assertEqual(got['items'], [('1.1.1.10', 'always'), ('1.1.1.11', 'always'), ('2.2.2.2', 'own'),
                                        ('3.3.3.3', 'abuseipdb'), ('4.4.4.4', 'abuseipdb')])
        self.assertEqual(got['kept'], {'always': 2, 'own': 1, 'abuseipdb': 2, 'sniffcat': 0})
        self.assertEqual(got['trimmed'], 1, 'the one that did not fit')
        self.assertEqual(got['offered']['sniffcat'], 1)

    def test_nothing_past_the_capacity_and_zero_is_empty(self):
        self.assertEqual(eb.build([], [], ['1.1.1.1', '2.2.2.2'], [], 0, [])['items'], [])
        self.assertEqual(len(eb.build([], [], ['1.1.1.1', '2.2.2.2'], [], 1, [])['items']), 1)

    def test_own_evidence(self):
        atts = {
            '185.220.101.7': {'last_seen': NOW - 100, 'verdict': {'score': 95}},            # scored
            '45.155.205.1': {'last_seen': NOW - 100, 'verdict': {'score': 10}, 'reported': {'sniffcat': 1}},
            '89.248.165.2': {'last_seen': NOW - 100, 'verdict': {'score': 40}},             # too low, unreported
            '1.2.3.4': {'last_seen': NOW - 20 * 86400, 'verdict': {'score': 99}},           # not lately
            '5.6.7.8': {'last_seen': NOW - 100, 'verdict': {'score': 99, 'whitelisted': True}},
            '9.9.9.9': {'last_seen': NOW - 50, 'verdict': {'score': 80}},
            'junk': 'x',
        }
        got = eb.own_candidates(atts, NOW, 75, 14)
        self.assertEqual(got, ['185.220.101.7', '9.9.9.9', '45.155.205.1'], 'by score, then recency')
        self.assertEqual(eb.own_candidates(atts, NOW, 75, 30)[0], '1.2.3.4', 'a longer window brings it back, first')

    def test_diff_and_the_guards(self):
        self.assertEqual(eb.diff(['a', 'b', 'c'], ['b', 'c', 'd']), (['d'], ['a']))
        self.assertEqual(eb.hold_reason(0, 0), '')
        self.assertEqual(eb.hold_reason(5000, 0), 'nothing would be left in the list')
        self.assertIn('shrink from 9000 to 4000', eb.hold_reason(9000, 4000))
        self.assertEqual(eb.hold_reason(9000, 4500), '', 'half is the line')
        self.assertEqual(eb.hold_reason(100, 10), '', 'a small list may be rebuilt freely')
        self.assertEqual(eb.hold_reason(0, 5000), '')

    def test_the_capacity_is_the_accounts_not_just_the_operators(self):
        lists = [{'id': LIST, 'kind': 'ip', 'num_items': 9000},
                 {'id': 'd' * 32, 'kind': 'ip', 'num_items': 300},
                 {'id': 'e' * 32, 'kind': 'redirect', 'num_items': 50},
                 {'id': 'f' * 32, 'kind': 'hostname', 'num_items': 700}]
        self.assertEqual(eb.capacity_for(10000, lists, LIST), 10000 - 300 - 50)
        self.assertEqual(eb.capacity_for(10000, lists, None), 10000 - 9000 - 300 - 50)
        self.assertEqual(eb.capacity_for(200, lists, LIST), 0, 'never negative')

    def test_the_marker(self):
        d = eb.description('7.3.0', ['own', 'abuseipdb'])
        self.assertTrue(eb.managed(d))
        self.assertIn('own, abuseipdb', d)
        self.assertFalse(eb.managed('Managed by Cloudflare-WAF-Expressions v3.3.2'))
        self.assertFalse(eb.managed(''))
        self.assertFalse(eb.managed(None))


class TestTheSources(unittest.TestCase):
    def test_abuseipdb_request_and_answer(self):
        r = eb.abuseipdb_request('K' * 40, 75, 8000)
        self.assertEqual(r['headers']['Key'], 'K' * 40)
        self.assertIn('confidenceMinimum=75', r['url'])
        self.assertIn('limit=8000', r['url'])
        self.assertNotIn('K' * 40, r['url'])
        self.assertIn('confidenceMinimum=25', eb.abuseipdb_request('k', 1, 5)['url'], 'its floor is 25')
        self.assertIn('confidenceMinimum=100', eb.abuseipdb_request('k', 900, 5)['url'])
        body = {'meta': {}, 'data': [{'ipAddress': '185.220.101.7', 'abuseConfidenceScore': 100},
                                     {'ipAddress': '10.0.0.1'}, {'ipAddress': 'junk'},
                                     {'ipAddress': '185.220.101.7'}, 'x',
                                     {'ipAddress': '2001:DB8::5'}]}
        got = eb.abuseipdb_parse(200, body)
        self.assertEqual(got, {'ok': True, 'ips': ['185.220.101.7']}, 'private, junk and repeats dropped')

    def test_abuseipdb_errors(self):
        self.assertTrue(eb.abuseipdb_parse(429, {'errors': [{'detail': 'Daily rate limit'}]})['rate_limited'])
        self.assertIn('rejected', eb.abuseipdb_parse(401, {})['error'])
        self.assertEqual(eb.abuseipdb_parse(0, None)['error'], 'unreachable')
        self.assertFalse(eb.abuseipdb_parse(200, {'data': 'x'})['ok'])

    def test_sniffcat_request_and_answer(self):
        r = eb.sniffcat_request('S' * 40, 80, 2000)
        self.assertEqual(r['headers']['X-Secret-Token'], 'S' * 40)
        for part in ('type=json', 'confidenceMin=80', 'limit=2000'):
            self.assertIn(part, r['url'])
        self.assertIn('confidenceMin=30', eb.sniffcat_request('k', 1, 5)['url'], 'its floor is 30')
        self.assertIn('limit=10', eb.sniffcat_request('k', 80, 1)['url'])
        body = {'success': True, 'status': 200, 'meta': {'count': 3},
                'reports': [{'ip': '45.155.205.1', 'abuse': 100}, {'ip': '192.168.0.1'}, {'ip': '45.155.205.1'}]}
        self.assertEqual(eb.sniffcat_parse(200, body), {'ok': True, 'ips': ['45.155.205.1']})

    def test_sniffcat_without_a_blacklist_quota_says_so(self):
        got = eb.sniffcat_parse(403, {'success': False, 'message': 'No quota assigned to the role'})
        self.assertTrue(got['no_quota'])
        self.assertIn('no blacklist quota', got['error'])
        self.assertTrue(eb.sniffcat_parse(429, {})['rate_limited'])


class TestCloudflareLists(unittest.TestCase):
    def test_the_token_is_in_a_header_and_nowhere_else(self):
        reqs = [eb.lists_request('TOKEN123', ACCT), eb.items_request('TOKEN123', ACCT, LIST, 'cur'),
                eb.create_request('TOKEN123', ACCT, 'my_list', 'd'),
                eb.describe_request('TOKEN123', ACCT, LIST, 'd'),
                eb.replace_request('TOKEN123', ACCT, LIST, [('1.1.1.1', 'own')]),
                eb.operation_request('TOKEN123', ACCT, OP)]
        for r in reqs:
            self.assertEqual(r['headers']['Authorization'], 'Bearer TOKEN123')
            self.assertNotIn('TOKEN123', r['url'])
            self.assertNotIn('TOKEN123', (r['body'] or b'').decode())
            self.assertTrue(r['url'].startswith('https://api.cloudflare.com/client/v4/accounts/' + ACCT))

    def test_shapes(self):
        self.assertEqual(eb.lists_request('t', ACCT)['method'], 'GET')
        self.assertIn('per_page=500', eb.items_request('t', ACCT, LIST)['url'])
        self.assertIn('cursor=a%2Fb%3D', eb.items_request('t', ACCT, LIST, 'a/b=')['url'])
        c = eb.create_request('t', ACCT, 'my_list', 'hello')
        self.assertEqual((c['method'], json.loads(c['body'])), ('POST', {'name': 'my_list', 'kind': 'ip',
                                                                       'description': 'hello'}))
        d = eb.describe_request('t', ACCT, LIST, 'hi')
        self.assertEqual((d['method'], d['url'].rsplit('/', 1)[-1], json.loads(d['body'])),
                         ('PUT', LIST, {'description': 'hi'}))
        r = eb.replace_request('t', ACCT, LIST, [('1.1.1.1', 'own'), ('2.2.2.0/24', 'always')])
        self.assertEqual(r['method'], 'PUT')
        self.assertTrue(r['url'].endswith(f'/rules/lists/{LIST}/items'))
        self.assertEqual(json.loads(r['body']), [{'ip': '1.1.1.1', 'comment': 'RemotePower: own'},
                                                 {'ip': '2.2.2.0/24', 'comment': 'RemotePower: always'}])
        self.assertTrue(eb.operation_request('t', ACCT, OP)['url'].endswith(f'/bulk_operations/{OP}'))

    def test_an_id_from_outside_cannot_reach_a_url(self):
        for bad in ('../x', 'a' * 31, 'A' * 32, '', None):
            with self.assertRaises(ValueError):
                eb.lists_request('t', bad)
            with self.assertRaises(ValueError):
                eb.items_request('t', ACCT, bad)
            with self.assertRaises(ValueError):
                eb.operation_request('t', ACCT, bad)
        with self.assertRaises(ValueError):
            eb.create_request('t', ACCT, 'Bad Name', 'd')

    def test_parsers(self):
        got = eb.parse_lists(200, {'success': True, 'result': [
            {'id': LIST, 'name': 'tyxak_cf_waf', 'kind': 'ip', 'description': 'Managed by x', 'num_items': 9079},
            {'id': 'short', 'name': 'x'}, 'junk']})
        self.assertEqual([x['name'] for x in got['lists']], ['tyxak_cf_waf'])
        self.assertEqual(got['lists'][0]['num_items'], 9079)
        items = eb.parse_items(200, {'success': True, 'result': [{'ip': '2001:DB8:0:0:0:0:0:1'}, {'ip': 'x'},
                                                                {'ip': '185.220.101.7'}],
                                     'result_info': {'cursors': {'after': 'next'}}})
        self.assertEqual(items, {'ok': True, 'ips': ['2001:db8::1', '185.220.101.7'], 'cursor': 'next'})
        self.assertEqual(eb.parse_created(200, {'success': True, 'result': {'id': LIST}}), {'ok': True, 'id': LIST})
        self.assertFalse(eb.parse_created(200, {'success': True, 'result': {}})['ok'])
        self.assertEqual(eb.parse_replace(200, {'success': True, 'result': {'operation_id': OP}}),
                         {'ok': True, 'operation_id': OP})
        self.assertFalse(eb.parse_replace(200, {'success': True, 'result': {}})['ok'])
        for state in ('pending', 'running', 'completed', 'failed'):
            got = eb.parse_operation(200, {'success': True, 'result': {'status': state, 'error': 'x'}})
            self.assertEqual(got['state'], state)
        self.assertEqual(eb.parse_operation(200, {'success': True, 'result': {}})['state'], 'pending')

    def test_the_failures_are_told_apart(self):
        full = eb.parse_created(400, {'success': False, 'errors': [{'code': 10019, 'message': 'list limit reached'}]})
        self.assertTrue(full['list_limit'])
        busy = eb.parse_replace(409, {'success': False, 'errors': [
            {'code': 10020, 'message': 'a bulk operation is already in progress'}]})
        self.assertTrue(busy['busy'])
        denied = eb.parse_lists(403, {'success': False, 'errors': [{'code': 10000, 'message': 'Authentication error'}]})
        self.assertTrue(denied['auth'])
        self.assertEqual(eb.parse_lists(0, {'message': 'unreachable'})['error'], 'unreachable')


class TestAllNetworksParse(unittest.TestCase):
    def test_every_entry_a_sync_can_hold_is_a_network_python_reads(self):
        got = eb.build(['185.220.0.0/16'], ['2a00:1450::/32'], ['185.220.101.7'], [], 100, [])
        for entry, _src in got['items']:
            ipaddress.ip_network(entry)


if __name__ == '__main__':
    unittest.main()
