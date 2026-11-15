"""Samples and real times from the edge sources (8.0.1).

A report built from Cloudflare's events or the honeypot's log had no example, and its window was the ten minutes of
one read. With the operator's samples setting on, a zone that is read one event at a time is also asked for the path,
the method and the time of each refused request, and the honeypot's line is read for its method and path.

The method's field name is not on a Cloudflare page that could be read, so the read asks in tiers and settles for the
first one Cloudflare accepts. What has to hold:

  * a field Cloudflare refuses costs a request, never the feed, and the card says what the read got;
  * a refusal of the token or the dataset, a rate limit and no answer cost no extra request;
  * the tier a zone answered is remembered, asked for in full again now and then, and a stored value of the wrong
    kind reads as "not known";
  * a query string, a host name and a user agent are never asked for and never kept, and a path is kept only after it
    is rebuilt from a short alphabet;
  * a report carries a path only when the operator turned examples on.

Everything runs through the real sweep (`run_edge_intel_if_due`, then the report sweep), with Cloudflare and the two
services faked at the one seam that touches the network.
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-edge-samples-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import edge_evidence as ee  # noqa: E402
import edge_intel_handlers  # noqa: E402
import ip_intel  # noqa: E402
import ip_intel_handlers  # noqa: E402
import ipintel_store  # noqa: E402
from test_ip_intel import ATTACKER  # noqa: E402
from test_v730_edge_intel import RULE_PROBE, SECOND, T, ZONE, _Edge, dataset_refusal, trap_line  # noqa: E402
from test_v801_request_log import _Real  # noqa: E402

ZONE2 = '8' * 32
FOUR = ['clientIP', 'action', 'source', 'ruleId']
FULL = FOUR + ['clientRequestPath', 'datetime', 'clientRequestHTTPMethodName']
NEVER = ('clientRequestQuery', 'userAgent', 'clientRequestHTTPHost')
SAFE = re.compile(r'\A[A-Za-z0-9._~/%+-]+(\.\.\.)?\Z')
EVIL = '"; DROP TABLE x; <script>alert(1)</script>'


def iso(t):
    import time
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))


def hit(ip, path, method='GET', at=T - 300, rule=RULE_PROBE):
    """One refused request as Cloudflare holds it: every field it could be asked for."""
    return {'clientIP': ip, 'action': 'block', 'source': 'firewallCustom', 'ruleId': rule,
            'clientRequestPath': path, 'clientRequestHTTPMethodName': method, 'datetime': iso(at),
            'clientRequestQuery': '?token=SECRET', 'userAgent': 'evil/1.0', 'clientRequestHTTPHost': 'intranet.example.org'}


class _Samples(_Edge):
    """A Free zone: the grouped view is refused and the single events answer. `refuse_fields[zone]` are the event
    fields Cloudflare will not run a query with, answered as GraphQL does for a field it does not know."""

    def setUp(self):
        super().setUp()
        self.groups_refused = {'*'}
        self.hits = {ZONE: [hit(ATTACKER, '/.env', at=T - 400), hit(ATTACKER, '/.git/config', at=T - 340),
                            hit(ATTACKER, '/wp-login.php', 'POST', at=T - 200)]}
        self.refuse_fields = {}
        self.refuse_status = 400
        self.events_answer = None           # (status, body) for every events query, when a test wants a failure
        self.trap = {'success': True, 'result': {'events': []}}

    def selection(self, query):
        return re.search(r'\{ (clientIP[^}]*) \}', query).group(1).split()

    def events_queries(self):
        out = []
        for c in self.cf_calls:
            if c['url'].endswith('/graphql'):
                q = json.loads(c['body'])['query']
                if 'firewallEventsAdaptive(' in q:
                    out.append(self.selection(q))
        return out

    def _cf(self, req):
        if req['url'].endswith('/graphql'):
            q = json.loads(req['body'])['query']
            if 'firewallEventsAdaptive(' in q:
                self.cf_calls.append(req)
                zone = re.search(r'zoneTag(?:_in)?: \[?"([0-9a-f]{32})"', q).group(1)
                if self.events_answer is not None:
                    return self.events_answer
                asked = self.selection(q)
                bad = [f for f in asked if f in self.refuse_fields.get(zone, ())]
                if bad:
                    return self.refuse_status, {'data': None, 'errors': [{
                        'message': 'unknown field "%s"' % bad[0], 'path': ['viewer', 'zones', '0', 'firewallEventsAdaptive']}]}
                rows = [{k: e[k] for k in asked} for e in self.hits.get(zone, [])]
                return 200, {'data': {'viewer': {'zones': [{'zoneTag': zone, 'firewallEventsAdaptive': rows}]}}}
        return super()._cf(req)

    def cf(self, st):
        return st['edge']['cf']

    def sweep_at(self, at):
        """The report sweep at the test's own clock: evidence that poll() stamped at T is weeks old to the real one."""
        st = ipintel_store.read(self.api)
        st['last_sweep'] = 0
        ipintel_store.write(self.api, st)
        with mock.patch('time.time', return_value=at):
            self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        return ipintel_store.read(self.api)

    def evidence(self, st, ip=ATTACKER, dev='edge:cloudflare'):
        return next(x['evidence'] for x in st['queue'] if x['ip'] == ip and x['device_id'] == dev)

    def two_zones(self):
        self.zones = {'success': True, 'result': [{'id': ZONE, 'name': 'example.org'}, {'id': ZONE2, 'name': 'example.net'}]}
        self.hits[ZONE2] = [hit(SECOND, '/phpmyadmin/', at=T - 250)]


class TestWhatIsAsked(unittest.TestCase):
    def fields(self, extra=()):
        req = ee.events_request('t' * 40, [ZONE], T - 600, T, 10, extra)
        return re.search(r'\{ (clientIP[^}]*) \}', json.loads(req['body'])['query']).group(1).split()

    def test_the_tiers(self):
        self.assertEqual(ee.EVENT_EXTRA_TIERS, (('clientRequestPath', 'datetime', 'clientRequestHTTPMethodName'),
                                                ('clientRequestPath', 'datetime'), ()))
        self.assertEqual(self.fields(), FOUR)
        self.assertEqual(self.fields(ee.EVENT_EXTRA_TIERS[0]), FULL)
        self.assertEqual(self.fields(ee.EVENT_EXTRA_TIERS[1]), FOUR + ['clientRequestPath', 'datetime'])
        self.assertEqual(self.fields(ee.EVENT_EXTRA_TIERS[2]), FOUR)

    def test_a_name_outside_the_list_never_reaches_the_query(self):
        for extra in (('userAgent',), ('clientRequestQuery', 'clientRequestHTTPHost'), ('clientRequestPath } } } } #',),
                      ('clientRequestPath', 'x { y }'), 'clientRequestPath'):
            got = self.fields(extra)
            self.assertTrue(set(got) <= set(FULL), (extra, got))
            for field in NEVER:
                self.assertNotIn(field, got)
        self.assertEqual(self.fields(('clientRequestHTTPMethodName', 'clientRequestPath')),
                         FOUR + ['clientRequestPath', 'clientRequestHTTPMethodName'], "the list's own order, whatever was passed")

    def test_no_query_the_reader_can_send_asks_for_what_else_a_visitor_typed(self):
        queries = [json.loads(ee.events_request('t' * 40, [ZONE], T - 600, T, 10, tier)['body'])['query']
                   for tier in ee.EVENT_EXTRA_TIERS]
        queries.append(json.loads(ee.firewall_request('t' * 40, [ZONE], T - 600, T)['body'])['query'])
        self.assertIn('clientRequestPath', queries[0], 'the control: this check can see a field that is asked for')
        for q in queries:
            for field in NEVER:
                self.assertNotIn(field, q)
        self.assertNotIn('clientRequestPath', queries[-1], 'the grouped view is asked for no request')


class TestTheReducerKeepsSamplesOnlyWhenAsked(unittest.TestCase):
    """The setting is honoured twice: nothing extra is asked of Cloudflare, and what a row holds is kept only when the
    caller says so. This is the second half, on rows that do hold requests."""

    ROWS = [{'zone': ZONE, 'ip': ATTACKER, 'action': 'block', 'source': 'firewallcustom', 'rule': RULE_PROBE, 'count': 2,
             'first': T - 300, 'last': T - 100,
             'smp': [{'m': 'GET', 'p': '/.env', 't': T - 300}, {'m': 'GET', 'p': '/.git/config', 't': T - 100}]}]

    def test_cloudflare_rows(self):
        kept = ee.cf_events(self.ROWS, {}, T, T - 600, T - 90, samples=True)[0][0]
        self.assertEqual([s['p'] for s in kept['smp']], ['/.env', '/.git/config'])
        for call in (lambda: ee.cf_events(self.ROWS, {}, T, T - 600, T - 90, samples=False),
                     lambda: ee.cf_events(self.ROWS, {}, T, T - 600, T - 90)):
            ev = call()[0][0]
            self.assertEqual(ev['smp'], [], 'off unless the caller asks')
            self.assertEqual((ev['src'], ev['first'], ev['last']), ({'cf': 2}, T - 300, T - 100), 'the count and the times stay')

    def test_honeypot_hits(self):
        hits = [{'kind': 'bait', 'ip': ATTACKER, 'action': 'banned', 'at': T - 30, 'method': 'GET', 'path': '/.env'}]
        self.assertEqual([s['p'] for s in ee.trap_events(hits, now=T, samples=True)[0][0]['smp']], ['/.env'])
        self.assertEqual(ee.trap_events(hits, now=T)[0][0]['smp'], [])


class TestTheRead(_Samples):
    def test_cloudflare_takes_every_field(self):
        st = self.poll()
        cf = self.cf(st)
        self.assertEqual((cf['state'], cf['mode'], cf['samples']), ('ok', 'events', 'full'))
        self.assertEqual(self.events_queries(), [FULL], 'one request')
        self.assertEqual(cf['modes'][ZONE]['x'], 0)
        e = self.evidence(st)
        self.assertEqual((e['src'], e['blk']), ({'cf': 3}, 3))
        self.assertEqual([(s['f'], s['m'], s['p'], s['c']) for s in e['smp']],
                         [('cf', 'GET', '/.env', 0), ('cf', 'GET', '/.git/config', 0), ('cf', 'POST', '/wp-login.php', 0)])
        self.assertEqual((e['first'], e['last']), (T - 400, T - 200), "the events' own times, not the window that was read")

    def test_a_refused_method_field_costs_one_request_and_keeps_the_path(self):
        for status in (400, 200):
            with self.subTest(status=status):
                self.cf_calls.clear()
                self.refuse_status = status
                self.refuse_fields = {ZONE: {'clientRequestHTTPMethodName'}}
                st = self.poll(at=T + (0 if status == 400 else 8 * 3600))
                cf = self.cf(st)
                self.assertEqual((cf['state'], cf['samples'], cf['kept']), ('ok', 'path', 3))
                self.assertEqual(self.events_queries(), [FULL, FOUR + ['clientRequestPath', 'datetime']])
                self.assertEqual(cf['modes'][ZONE]['x'], 1)
                e = self.evidence(st)
                self.assertEqual([(s['m'], s['p']) for s in e['smp']],
                                 [('', '/.env'), ('', '/.git/config'), ('', '/wp-login.php')])

    def test_every_extra_field_refused_still_counts_the_events(self):
        self.refuse_fields = {ZONE: {'clientRequestPath'}}
        st = self.poll()
        cf = self.cf(st)
        self.assertEqual((cf['state'], cf['samples'], cf['kept'], cf['rows']), ('ok', 'none', 3, 1))
        self.assertEqual(self.events_queries(), [FULL, FOUR + ['clientRequestPath', 'datetime'], FOUR])
        self.assertEqual(cf['modes'][ZONE]['x'], edge_intel_handlers.NO_EXTRAS)
        e = self.evidence(st)
        self.assertEqual((e['src'], e['smp']), ({'cf': 3}, []))
        self.assertEqual(e['last'], T - 90, 'no event time was read, so the window is used')

    def test_what_is_not_a_refused_field_costs_no_extra_request(self):
        answers = {
            'the token': (401, {'errors': [{'message': 'Authentication error', 'code': 10000}]}),
            'a rate limit': (429, {}),
            'no answer': (0, None),
            'a failure on their side': (500, {'errors': [{'message': 'internal error'}]}),
            'the dataset': (200, dataset_refusal(ZONE, 'firewallEventsAdaptive')),
        }
        for name, answer in answers.items():
            with self.subTest(name):
                self.cf_calls.clear()
                self.events_answer = answer
                st = self.poll()
                self.assertEqual(len(self.events_queries()), 1, name)
                self.assertNotEqual(self.cf(st)['state'], 'ok', name)
                self.assertEqual([x for x in st['queue'] if x['device_id'] == 'edge:cloudflare'], [], name)

    def test_with_samples_switched_off_nothing_extra_is_asked_or_kept_or_said(self):
        self.policy(sensor_samples=False)
        st = self.poll()
        cf = self.cf(st)
        self.assertEqual(self.events_queries(), [FOUR])
        self.assertEqual((cf['state'], cf['kept']), ('ok', 3))
        self.assertNotIn('samples', cf)
        self.assertNotIn('x', cf['modes'][ZONE])
        e = self.evidence(st)
        self.assertEqual(e['smp'], [])
        self.assertEqual((e['first'], e['last']), (st['edge']['cf_to'] - (T - 90 - e['first']), T - 90))

    def test_the_grouped_view_is_unchanged_and_says_it_carries_no_request(self):
        self.groups_refused = set()
        st = self.poll()
        cf = self.cf(st)
        self.assertEqual((cf['state'], cf['mode'], cf['samples']), ('ok', 'groups', 'grouped'))
        self.assertEqual(self.events_queries(), [])
        self.assertEqual(self.evidence(st)['smp'], [])


class TestTheTierIsRemembered(_Samples):
    def test_the_next_read_starts_where_the_zone_answered(self):
        self.refuse_fields = {ZONE: {'clientRequestHTTPMethodName'}}
        self.poll()
        self.cf_calls.clear()
        st = self.poll(at=T + 700)
        self.assertEqual(self.events_queries(), [FOUR + ['clientRequestPath', 'datetime']], 'one request, at the tier that worked')
        self.assertEqual(self.cf(st)['samples'], 'path')

    def test_everything_is_asked_for_again_after_a_while(self):
        self.refuse_fields = {ZONE: {'clientRequestHTTPMethodName'}}
        self.poll()
        self.refuse_fields = {}
        self.cf_calls.clear()
        st = self.poll(at=T + edge_intel_handlers.MODE_PROBE_S + 60)
        self.assertEqual(self.events_queries()[-1], FULL)
        self.assertEqual((self.cf(st)['samples'], self.cf(st)['modes'][ZONE]['x']), ('full', 0))

    def test_a_stored_tier_of_the_wrong_kind_reads_as_not_known(self):
        self.poll()
        for i, bad in enumerate(('full', True, None, [1], {'a': 1}, 2.5)):
            with self.subTest(bad=bad):
                st = ipintel_store.read(self.api)
                st['edge']['cf']['modes'][ZONE]['x'] = bad
                ipintel_store.write(self.api, st)
                self.cf_calls.clear()
                st = self.poll(at=T + 700 * (i + 1))
                self.assertEqual(self.cf(st)['state'], 'ok', bad)
                self.assertEqual(self.events_queries()[0], FULL, bad)
                self.assertEqual(self.cf(st)['modes'][ZONE]['x'], 0, bad)

    def test_a_number_out_of_range_is_held_to_the_tiers(self):
        self.poll()
        for i, (bad, want) in enumerate(((99, FOUR), (-5, FULL))):
            st = ipintel_store.read(self.api)
            st['edge']['cf']['modes'][ZONE]['x'] = bad
            ipintel_store.write(self.api, st)
            self.cf_calls.clear()
            self.poll(at=T + 700 * (i + 1))
            self.assertEqual(self.events_queries()[0], want, bad)

    def test_a_read_that_is_skipped_keeps_what_the_last_one_said(self):
        self.refuse_fields = {ZONE: {'clientRequestHTTPMethodName'}}
        self.poll()
        self.cf_calls.clear()
        st = self.poll(at=T + 20)
        cf = self.cf(st)
        self.assertTrue(cf.get('skipped'), 'the control: the window was under a minute, so nothing was read')
        self.assertEqual(self.events_queries(), [])
        self.assertEqual(cf['samples'], 'path')


class TestSeveralZones(_Samples):
    """The card's sentence is about "a zone", so the status is the least any zone gave."""

    def test_the_least_any_zone_gave(self):
        self.two_zones()
        cases = (
            ({}, set(), 'full'),
            ({ZONE2: {'clientRequestHTTPMethodName'}}, set(), 'path'),
            ({ZONE2: {'clientRequestPath'}}, set(), 'none'),
            ({ZONE: {'clientRequestHTTPMethodName'}, ZONE2: {'clientRequestPath'}}, set(), 'none'),
        )
        for i, (refuse, grouped_ok, want) in enumerate(cases):
            with self.subTest(want=want, refuse=refuse):
                self.refuse_fields = refuse
                st = self.poll(at=T + i * 8 * 3600)
                self.assertEqual((self.cf(st)['state'], self.cf(st)['samples']), ('ok', want))

    def test_a_zone_read_grouped_beside_one_read_as_events(self):
        self.two_zones()
        self.groups_refused = {ZONE}                      # the second zone has the grouped view
        st = self.poll()
        cf = self.cf(st)
        self.assertEqual((cf['state'], cf['mode'], cf['samples']), ('ok', 'mixed', 'grouped'))
        self.assertEqual(len(self.evidence(st)['smp']), 3, 'the zone read as events still carries its samples')

    def test_the_order_is_one_tuple(self):
        self.assertEqual(edge_intel_handlers.SAMPLES_WORST_FIRST, ('none', 'grouped', 'path', 'full'))
        sent = edge_intel_handlers.edge_intel_status({'edge': {'cf': {'state': 'ok', 'samples': 'none'}}}, {})
        self.assertEqual(sent['cf']['samples'], 'none', 'the page is sent it')


class TestWhatAVisitorTyped(_Samples):
    def test_a_path_is_kept_only_as_safe_characters(self):
        self.hits = {ZONE: [hit(ATTACKER, '/.env?token=SECRET&x=1'), hit(ATTACKER, '/a' + EVIL), hit(ATTACKER, EVIL),
                            hit(ATTACKER, '/b' * 400), hit(ATTACKER, '/x', method='BREW /etc/passwd'),
                            hit(ATTACKER, 'https://evil.example/x'), hit(ATTACKER, None), hit(ATTACKER, ['/list'])]}
        st = self.poll()
        e = self.evidence(st)
        self.assertEqual(e['src'], {'cf': 8}, 'every refusal counts, sample or not')
        self.assertEqual(len(e['smp']), 3, 'at most three')
        self.assertEqual(e['smp'][0]['p'], '/.env', 'the query string is cut')
        for s in e['smp']:
            self.assertRegex(s['p'], SAFE)
            self.assertLessEqual(len(s['p']), 83)
            self.assertIn(s['m'], ('GET', ''))
        self.assertFalse(SAFE.match('/a' + EVIL), 'the control: the hostile text is not safe as it arrived')
        stored = json.dumps(ipintel_store.read(self.api))
        for word in ('SECRET', 'DROP', '<script>', 'evil/1.0', 'intranet.example.org', 'BREW'):
            self.assertNotIn(word, stored, word)

    def test_the_honeypots_line_gives_a_sample_and_nothing_else_of_itself(self):
        self.trap = {'success': True, 'result': {'events': [
            trap_line(SECOND, kind='bait', action='banned', method='GET', path='/.env?k=SECRET', ua=EVIL, host='intranet.example.org',
                      note=EVIL),
            trap_line(SECOND, kind='login', action='counted', method='post', path='/wp-login.php'),
            trap_line(SECOND, kind='login', action='counted')]}}
        st = self.poll()
        e = self.evidence(st, SECOND, 'edge:trap')
        self.assertEqual(e['src'], {'trap': 3})
        self.assertEqual([(s['f'], s['m'], s['p']) for s in e['smp']], [('trap', 'GET', '/.env'), ('trap', 'POST', '/wp-login.php')])
        stored = json.dumps(ipintel_store.read(self.api))
        for word in ('SECRET', 'DROP', 'intranet.example.org'):
            self.assertNotIn(word, stored, word)

    def test_the_same_box_switches_the_honeypots_samples_off(self):
        self.policy(sensor_samples=False)
        self.trap = {'success': True, 'result': {'events': [
            trap_line(SECOND, kind='bait', action='banned', method='GET', path='/.env')]}}
        st = self.poll()
        e = self.evidence(st, SECOND, 'edge:trap')
        self.assertEqual((e['src'], e['smp']), ({'trap': 1}, []))


class TestTheReport(_Samples):
    def comments(self):
        out = {}
        for c in self.reports():
            body = c['body']
            if 'sniffcat' in c['url']:
                b = json.loads(body)
                out.setdefault(b['ip'], {})['sniffcat'] = b
            else:
                f = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                out.setdefault(f['ip'], {})['abuseipdb'] = f
        return out

    def test_a_path_reaches_a_report_only_when_examples_are_on(self):
        self.poll()
        self.sweep_at(T + 20)
        text = self.comments()[ATTACKER]['sniffcat']['comment']
        self.assertEqual(text, 'probing for exposed files and admin pages: 3 attempts within 3 minutes, seen by Cloudflare WAF '
                               '(reported by RemotePower)')
        self.assertNotIn('/.env', json.dumps(self.comments()))

    def test_with_examples_on_the_report_ends_with_them(self):
        self.policy(report_samples=True)
        self.poll()
        self.sweep_at(T + 20)
        by = self.comments()[ATTACKER]
        want = ('probing for exposed files and admin pages: 3 attempts within 3 minutes, seen by Cloudflare WAF '
                '(reported by RemotePower) Examples: GET /.env, GET /.git/config, POST /wp-login.php')
        self.assertEqual(by['sniffcat']['comment'], want)
        self.assertEqual(by['abuseipdb']['comment'], want)
        self.assertEqual(by['abuseipdb']['timestamp'], iso(T - 200).replace('Z', '+00:00'), "the last event's own time")



class TestTheRequestLogThroughTheRealRequest(_Real):
    """The real request function and a socket that answers by script (the harness of test_v801_request_log)."""

    def test_a_reports_line_says_what_it_was_filed_under_and_nothing_of_its_text(self):
        import threat_evidence as te
        ev = te.normalize_event({'ip': ATTACKER, 'first': T - 600, 'last': T, 'src': {'web': 12},
                                 'tok': {'web': {'req:config': 12}}}, now=T)
        with mock.patch('time.time', return_value=T):
            self.api.ip_intel_note_evidence('d1', [ev], {'sources': [], 'ignored': {}, 'dropped': 0}, T)
        self.api._LOAD_CACHE.clear()
        st = self.sweep_at(T + 20)
        lines = [e for e in st.get('reqlog', []) if e.get('op') == 'report']
        self.assertEqual({(e['prov'], tuple(e['cats'])) for e in lines}, {('abuseipdb', (15, 21)), ('sniffcat', (11, 21))})
        for e in lines:
            self.assertEqual(set(e), {'at', 'prov', 'op', 'ip', 'status', 'ms', 'result', 'note', 'cats'})
        self.assertNotIn('probing for configuration files', json.dumps(st.get('reqlog')), 'the text of a report is never kept here')
        lookups = [e for e in st.get('reqlog', []) if e.get('op') == 'check']
        self.assertTrue(lookups and all('cats' not in e for e in lookups), 'a lookup files nothing')


class TestTheCategoryIdsOfALoggedReport(unittest.TestCase):
    def test_both_services_request_bodies(self):
        a = ip_intel.abuseipdb_report_request('45.155.205.10', 'k' * 20, [15, 21], 'x' * 20)
        s = ip_intel.sniffcat_report_request('45.155.205.10', 'k' * 20, [17, 22], 'x' * 20)
        self.assertEqual(ip_intel_handlers._req_cats(a), [15, 21])
        self.assertEqual(ip_intel_handlers._req_cats(s), [17, 22])
        self.assertEqual(ip_intel_handlers._req_cats(ip_intel.abuseipdb_check_request('45.155.205.10', 'k' * 20)), [])

    def test_a_body_it_cannot_read_is_no_ids_and_never_an_error(self):
        for body in (b'\xff\xfe\x00', b'[15, 21]', b'{"categories": {"a": 1}}', b'{"categories": null}', b'{broken',
                     b'categories=x,y', 'categories=15'.encode('utf-16'), None, 'a str', b''):
            self.assertEqual(ip_intel_handlers._req_cats({'url': 'https://x/report', 'body': body}), [], body)

    def test_only_plain_small_numbers_count(self):
        clean = ip_intel_handlers._clean_cats
        self.assertEqual(clean([15, '21', ' 7 ', 21, 0, -1, 100, True, None, [1], {'a': 1}, '²', '١٥', 2.0, 'x']), [15, 21, 7])
        self.assertEqual(clean(list(range(1, 40))), [1, 2, 3, 4, 5, 6, 7, 8], 'a short list')
        for not_a_list in ('15,21', 21, True, None, {'0': 15}):
            self.assertEqual(clean(not_a_list), [], not_a_list)

    def test_a_stored_line_is_checked_again_before_the_page_gets_it(self):
        rows = [{'op': 'report', 'cats': [15, 21]}, {'op': 'report', 'cats': '11,21'}, {'op': 'report', 'cats': True},
                {'op': 'report', 'cats': [15, '<img src=x>', None]}, {'op': 'check'}, 'not a line']
        view = ip_intel_handlers._reqlog_view({'reqlog': rows})
        self.assertEqual([e.get('cats') for e in view], [None, [15], None, None, [15, 21]], 'newest first')
        self.assertEqual(rows[1]['cats'], '11,21', 'the stored line is not changed by reading it')


if __name__ == '__main__':
    unittest.main()
