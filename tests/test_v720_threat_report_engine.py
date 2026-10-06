"""The sweep, for addresses the host's logs described.

Driven for real: the providers are faked at the one seam that talks to the
network, everything else (queue, ledger, lookups, reports, blocks) runs. What is
checked is what a report SAYS and WHEN one is sent, because that is the part
fail2ban's reporting does badly: one report per address however many jails saw
it, categories from what actually happened, a text that carries nothing an
attacker typed, a repeat answered as a repeat rather than an error, and the day's
allowance going to the addresses that earned it.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v720-engine-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_ip_intel import ATTACKER, _Case  # noqa: E402

SECOND = '185.220.101.8'
THIRD = '185.220.101.9'


def raw_event(ip=ATTACKER, **kw):
    now = int(time.time())
    e = {'ip': ip, 'first': now - 600, 'last': now}
    e.update(kw)
    return e


def web(ip=ATTACKER, n=12, kind='probe', **kw):
    return raw_event(ip, src={'web': n}, tok={'web': {f'req:{kind}': n}}, **kw)


SQLI = dict(src={'web': 41, 'waf': 12},
            tok={'web': {'req:sqli': 30, 'req:traversal': 11}, 'waf': {'crs:942100': 12}})


class _Engine(_Case):
    def setUp(self):
        super().setUp()
        self.policy(sensor_enabled=True, report_enabled=True, report_min_count=10)

    def feed(self, raw, dev='d1', sources=None):
        ev = te.normalize_event(raw, now=int(time.time()))
        assert ev is not None, raw
        self.api.ip_intel_note_evidence(dev, [ev], {'sources': sources or []})
        self.api._LOAD_CACHE.clear()

    def posts(self):
        return [c for c in self.calls if c['method'] == 'POST']

    def post_to(self, prov):
        return [c for c in self.posts() if prov in c['url']]

    def abuse_form(self, n=-1):
        return parse_qs(self.post_to('abuseipdb')[n]['body'].decode())

    def sniff_body(self, n=-1):
        return json.loads(self.post_to('sniffcat')[n]['body'])

    def att(self, ip=ATTACKER):
        return (self.store().get('attackers') or {}).get(ip) or {}

    def store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IPINTEL_FILE) or {}

    def answer_with(self, abuse=None, sniff=None):
        """Replace the providers' answer to a REPORT; lookups still work."""
        inner = self.api._ip_intel_http

        def http(req):
            if req['method'] == 'POST':
                self.calls.append(req)
                r = abuse if 'abuseipdb' in req['url'] else sniff
                if r is not None:
                    return r
                return 200, {'success': True, 'data': {}}
            return inner(req)
        # inner records lookups itself; POSTs are recorded here
        self.api._ip_intel_http = http


class TestWhatIsReported(_Engine):
    def test_the_report_says_what_happened_in_the_services_own_categories(self):
        self.feed(raw_event(**SQLI))
        self.sweep()
        self.assertEqual(len(self.posts()), 2)
        form = self.abuse_form()
        self.assertEqual(form['categories'], ['16,21'])
        self.assertEqual(form['comment'], ['SQL injection and path traversal: 41 attempts within 10 minutes, '
                                           'seen by web server log and WAF (reported by RemotePower)'])
        self.assertEqual(self.sniff_body()['categories'], [12, 21, 16])
        self.assertEqual(self.sniff_body()['comment'], form['comment'][0])

    def test_abuseipdb_gets_when_it_happened_and_sniffcat_does_not(self):
        self.feed(raw_event(**SQLI))
        self.sweep()
        self.assertRegex(self.abuse_form()['timestamp'][0], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$')
        self.assertNotIn('timestamp', self.sniff_body())

    def test_a_fail2ban_ban_reports_ssh_with_the_ssh_categories(self):
        self.feed(raw_event(ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}))
        self.sweep()
        self.assertEqual(self.abuse_form()['categories'], ['18,22'])
        self.assertEqual(self.sniff_body()['categories'], [17, 18])
        self.assertEqual(self.abuse_form()['comment'][0],
                         'SSH brute force: 3 attempts within 10 minutes, seen by fail2ban (reported by RemotePower)')

    def test_a_cve_the_logs_named_is_in_the_comment_and_nothing_else_they_said_is(self):
        self.feed(raw_event(src={'waf': 4}, tok={'waf': {'crs:944150': 4}}, cve=['CVE-2021-44228'], ban=['modsec']))
        self.sweep()
        c = self.abuse_form()['comment'][0]
        self.assertIn('remote code execution attempts (CVE-2021-44228)', c)
        self.assertEqual(self.abuse_form()['categories'], ['15,21'])

    def test_the_operators_own_wording_is_used_with_the_new_placeholders(self):
        self.policy(report_comment='{attack}: {count} hits, {seen_by}')
        self.feed(raw_event(**SQLI))
        self.sweep()
        self.assertEqual(self.abuse_form()['comment'], ['SQL injection and path traversal: 41 hits, web server log and WAF'])

    def test_attacker_text_cannot_reach_the_report(self):
        marker = 'ZZPWNEDZZ'
        self.feed(raw_event(src={'web': 20, 'waf': 5}, ban=['sshd'],
                            tok={'web': {'req:sqli': 20, f'jail:{marker}': 9, f'cs:{marker}': 9},
                                 'waf': {f'crstag:attack-{marker.lower()}': 5, 'crs:942100': 5}}))
        self.sweep()
        for p in self.posts():
            self.assertNotIn(marker.lower(), p['body'].decode().lower())
        self.assertTrue(self.posts())

    def test_what_was_sent_is_kept_to_show(self):
        self.feed(raw_event(**SQLI))
        self.sweep()
        log = self.att()['report_log']
        self.assertEqual(sorted(e['prov'] for e in log), ['abuseipdb', 'sniffcat'])
        ab = [e for e in log if e['prov'] == 'abuseipdb'][0]
        self.assertEqual((ab['ok'], ab['cats']), (True, [16, 21]))
        self.assertEqual(ab['comment'], self.abuse_form()['comment'][0])
        self.assertTrue(any(a[1] == 'ip_intel_report' and 'kind=sqli+traversal' in a[2] for a in self.audit))


class TestOneReportPerAddress(_Engine):
    def test_two_hosts_and_the_brute_force_counter_are_one_report(self):
        self.feed(web(n=12), dev='d1')
        self.feed(web(n=15, kind='sqli'), dev='d3')
        self.attack(dev='d1', ip=ATTACKER, count=40)
        self.sweep()
        self.assertEqual(len(self.post_to('abuseipdb')), 1, 'one report per service, not one per host or detector')
        self.assertEqual(len(self.post_to('sniffcat')), 1)
        a = self.att()
        self.assertEqual(set(a['devices']), {'d1', 'd3'})
        self.assertEqual(sorted(a['reported']), ['abuseipdb', 'sniffcat'])

    def test_evidence_wins_the_text_and_the_older_counter_adds_its_categories(self):
        self.feed(web(n=15, kind='sqli'))
        self.attack(dev='d1', ip=ATTACKER, count=40, unit='sshd.service')
        self.sweep()
        cats = self.abuse_form()['categories'][0].split(',')
        self.assertTrue({'16', '21', '18', '22'} <= set(cats), cats)
        self.assertTrue(self.abuse_form()['comment'][0].startswith('SQL injection:'))

    def test_the_older_counter_alone_says_what_it_counted(self):
        self.attack(count=40)
        self.sweep()
        self.assertEqual(self.abuse_form()['categories'], ['18,22'])
        self.assertEqual(self.abuse_form()['comment'][0],
                         'SSH brute force: 40 attempts within 10 minutes, seen by system log (reported by RemotePower)')


class TestWhenAnAddressIsReported(_Engine):
    def reported(self):
        return len(self.posts()) > 0

    def test_a_few_unconfirmed_requests_are_not_enough_and_the_page_says_why(self):
        self.feed(web(n=4))
        self.sweep()
        self.assertFalse(self.reported())
        self.assertEqual(self.att()['errors'], {'abuseipdb': 'not reported: 4 of 10 attempts so far',
                                                'sniffcat': 'not reported: 4 of 10 attempts so far'})

    def test_the_threshold_is_the_operators(self):
        self.policy(report_min_count=3)
        self.feed(web(n=4))
        self.sweep()
        self.assertTrue(self.reported())

    def test_a_ban_engines_decision_is_enough_on_its_own(self):
        self.feed(raw_event(ban=['nginx-botsearch'], src={'f2b': 1}, tok={'f2b': {'jail:nginx-botsearch': 1}}))
        self.sweep()
        self.assertTrue(self.reported())
        self.assertEqual(self.abuse_form()['categories'], ['21'])

    def test_crowdsec_deciding_is_enough(self):
        self.feed(raw_event(dec=1, src={'cs': 6}, tok={'cs': {'cs:crowdsecurity/http-probing': 1}}))
        self.sweep()
        self.assertTrue(self.reported())

    def test_the_waf_refusing_it_three_times_is_enough_two_is_not(self):
        self.feed(raw_event(src={'waf': 2}, tok={'waf': {'crs:942100': 2}}))
        self.sweep()
        self.assertFalse(self.reported())
        self.feed(raw_event(src={'waf': 1}, tok={'waf': {'crs:942100': 1}}))
        self.sweep()
        self.assertTrue(self.reported(), 'the ledger added the two sweeps')

    def test_an_address_with_no_recognisable_class_is_never_reported(self):
        self.feed(raw_event(ban=['recidive'], src={'f2b': 50}, tok={'f2b': {'jail:recidive': 50}}))
        self.sweep()
        self.assertFalse(self.reported())
        self.assertIn('nothing recognisable', self.att()['errors']['abuseipdb'])

    def test_off_means_off(self):
        self.policy(report_enabled=False)
        self.feed(raw_event(ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}))
        self.sweep()
        self.assertFalse(self.reported())
        self.assertEqual(self.att().get('errors') or {}, {})

    def test_a_provider_that_calls_it_legitimate_is_never_given_a_report(self):
        inner = self.api._ip_intel_http

        def http(req):
            st, body = inner(req)
            if req['method'] == 'GET' and 'abuseipdb' in req['url']:
                body['data']['isWhitelisted'] = True
            return st, body
        self.api._ip_intel_http = http
        self.feed(raw_event(ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}))
        self.sweep()
        self.assertFalse(self.reported())

    def test_a_proxy_a_fleet_member_and_an_allowlisted_address_are_never_reported(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_allowlist'] = ['185.220.101.0/24']
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        devices = self.api.load(self.api.DEVICES_FILE)
        devices['d3']['public_ip'] = '45.9.9.9'                              # a real-looking address of ours
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api._LOAD_CACHE.clear()
        strong = dict(ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}})
        self.feed(raw_event(ATTACKER, **strong))                              # allow-listed
        self.feed(raw_event('45.9.9.9', **strong))                            # the fleet's own address
        # Cloudflare is turned away at the door; this is the belt for an old queue
        # or a hand-edited store, so it goes in the queue directly
        st = self.store()
        st.setdefault('queue', []).append({'ip': '104.16.5.5', 'device_id': 'd1', 'unit': 'threat-sensor',
                                           'count': 9, 'window_s': 600, 'at': int(time.time()),
                                           'evidence': te.normalize_event(raw_event('104.16.5.5', **strong))})
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual(self.posts(), [])
        self.assertIn('never-block', self.att()['errors']['abuseipdb'])
        self.assertIn('never-block', self.att('45.9.9.9')['errors']['abuseipdb'])
        self.assertIn('Cloudflare', self.att('104.16.5.5')['errors']['abuseipdb'])


class TestTheLedger(_Engine):
    def test_a_slow_attacker_adds_up_across_sweeps(self):
        self.feed(web(n=4))
        self.sweep()
        self.assertEqual(self.att()['ev']['src'], {'web': 4})
        self.feed(web(n=4))
        self.sweep()
        self.assertEqual(self.posts(), [], '8 so far')
        self.feed(web(n=4))
        self.sweep()
        self.assertEqual(len(self.posts()), 2, '12 now')
        self.assertIn('12 attempts', self.abuse_form()['comment'][0])

    def test_a_report_starts_the_ledger_over_and_what_it_said_is_kept(self):
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertNotIn('ev', a)
        self.assertEqual(a['ev_reported']['ev']['src'], {'web': 12})
        self.feed(web(n=4))
        self.sweep()
        self.assertEqual(self.att()['ev']['src'], {'web': 4}, 'the next day starts from what is new')
        self.assertEqual(len(self.posts()), 2, 'and nothing more was sent within the day')

    def test_evidence_older_than_a_day_is_forgotten(self):
        self.feed(web(n=6))
        self.sweep()
        st = self.store()
        st['attackers'][ATTACKER]['ev']['first'] = int(time.time()) - 2 * 86400
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.feed(web(n=6))
        self.sweep()
        self.assertEqual(self.posts(), [], 'six and six are not twelve when one lot is two days old')
        self.assertEqual(self.att()['ev']['src'], {'web': 6})

    def test_the_stored_ledger_is_small(self):
        self.policy(report_enabled=False)
        toks = {f'crs:{942000 + i}': 3 for i in range(30)}
        self.feed(raw_event(src={'waf': 5}, tok={'waf': toks}))
        self.sweep()
        self.assertLessEqual(len(self.att()['ev']['tok']['waf']), 8)

    def test_the_device_count_is_a_running_total_for_the_day(self):
        self.feed(web(n=4))
        self.sweep()
        self.feed(web(n=5))
        self.sweep()
        self.assertEqual(self.att()['devices']['d1']['count'], 9)


class TestTheServicesAnswers(_Engine):
    def test_a_repeat_report_is_an_answer_not_a_failure(self):
        dup = (429, {'errors': [{'detail': 'You can only report the same IP address (`x`) once in 15 minutes.'}]})
        self.answer_with(abuse=dup)
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertIn('abuseipdb', a['reported'], 'it was reported moments ago; that report exists')
        self.assertEqual(a['errors']['abuseipdb'], 'already reported a moment ago')
        self.assertNotIn('abuseipdb', a.get('retry') or {})
        self.assertIn('sniffcat', a['reported'])
        self.assertTrue([e for e in a['report_log'] if e['prov'] == 'abuseipdb'][0]['duplicate'])
        self.assertFalse(any(a_[1] == 'ip_intel_report' and 'abuseipdb' in a_[2] for a_ in self.audit),
                         'a repeat is not a report we made')

    def test_a_sniffcat_repeat_that_says_so_is_an_answer_too(self):
        dup = (429, {'success': False, 'status': 429,
                     'message': 'You can only report this IP once every 20 minutes. Try again in 426 seconds.'})
        self.answer_with(sniff=dup)
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertIn('sniffcat', a['reported'], 'it was reported moments ago; that report exists')
        self.assertEqual(a['errors']['sniffcat'], 'already reported a moment ago')
        self.assertNotIn('sniffcat', a.get('retry') or {})
        self.assertTrue([e for e in a['report_log'] if e['prov'] == 'sniffcat'][0]['duplicate'])
        self.assertIn('abuseipdb', a['reported'])

    def test_a_rate_limit_backs_off_past_the_services_repeat_window(self):
        self.answer_with(sniff=(429, {'success': False, 'message': 'Submission rate limit exceeded or repeated report'}))
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertNotIn('sniffcat', a.get('reported') or {})
        self.assertEqual(a['errors']['sniffcat'], 'rate limited or already reported')
        self.assertGreater(a['retry']['sniffcat'], int(time.time()) + 20 * 60)
        self.assertIn('abuseipdb', a['reported'])
        n = len(self.post_to('sniffcat'))
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(len(self.post_to('sniffcat')), n, 'it did not ask again inside the window')
        st = self.store()
        st['attackers'][ATTACKER]['retry']['sniffcat'] = int(time.time()) - 1
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(len(self.post_to('sniffcat')), n + 1, 'and did once the window had passed')

    def test_any_other_failure_is_recorded_and_tried_again_next_time(self):
        self.answer_with(abuse=(500, {'message': 'upstream broke'}))
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertNotIn('abuseipdb', a.get('reported') or {})
        self.assertIn('upstream broke', a['errors']['abuseipdb'])
        self.assertNotIn('abuseipdb', a.get('retry') or {})
        n = len(self.post_to('abuseipdb'))
        self.answer_with()
        self.feed(web(n=1))
        self.sweep()
        self.assertEqual(len(self.post_to('abuseipdb')), n + 1)
        self.assertIn('abuseipdb', self.att()['reported'])
        self.assertNotIn('abuseipdb', self.att().get('errors') or {}, 'the old reason is gone once it worked')

    def test_the_evidence_is_kept_for_the_service_that_has_not_been_told(self):
        """One service took the report and the other failed. Clearing the ledger
        would leave the second with nothing to go on until a whole new threshold of
        attempts had piled up; keeping it lets the next sweep finish the job."""
        self.answer_with(abuse=(500, {'message': 'upstream broke'}))
        self.feed(web(n=12))
        self.sweep()
        a = self.att()
        self.assertIn('sniffcat', a['reported'])
        self.assertEqual(a['ev']['src'], {'web': 12}, 'kept: AbuseIPDB has not been told')
        self.assertNotIn('ev_reported', a)
        self.answer_with()
        self.feed(web(n=1))
        self.sweep()
        a = self.att()
        self.assertIn('abuseipdb', a['reported'], 'the lagging service got its report')
        self.assertEqual(len(self.post_to('sniffcat')), 1, 'the one that was told is not told twice')
        self.assertNotIn('ev', a)
        self.assertEqual(a['ev_reported']['ev']['src'], {'web': 13})

    def test_a_success_clears_the_reason_it_was_waiting_on(self):
        self.feed(web(n=4))
        self.sweep()
        self.assertIn('not reported', self.att()['errors']['abuseipdb'])
        self.feed(web(n=8))
        self.sweep()
        self.assertNotIn('abuseipdb', self.att().get('errors') or {})


class TestSpendingTheAllowance(_Engine):
    def test_network_work_is_rationed_and_free_work_is_not(self):
        h = self.api.ip_intel_handlers_mod
        self.assertEqual(h.NET_PER_SWEEP, 25)
        for i in range(40):
            self.feed(web(ip=f'45.1.{i // 250}.{i % 250 + 1}', n=12))
        self.sweep()
        left = len(self.store().get('queue') or [])
        self.assertEqual(left, 15, 'twenty-five addresses needed the network, fifteen wait for the next sweep')
        self.sweep()
        self.assertEqual(len(self.store().get('queue') or []), 0)

    def test_entries_that_cost_nothing_are_all_taken_at_once(self):
        """Already looked up, nothing to report: no reason to leave them waiting."""
        self.policy(report_enabled=False)
        now = int(time.time())
        st = self.store()
        st['attackers'] = {f'45.2.{i // 250}.{i % 250 + 1}': {'checked_at': now, 'verdict': {'score': 10}}
                           for i in range(120)}
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        for i in range(120):
            self.feed(web(ip=f'45.2.{i // 250}.{i % 250 + 1}', n=5))
        self.sweep()
        self.assertEqual(self.calls, [])
        self.assertEqual(len(self.store().get('queue') or []), 0)

    def test_a_short_allowance_goes_to_the_address_that_earned_it(self):
        self.policy(daily_lookup_budget=1, daily_report_budget=1)
        for i in range(8):
            self.feed(web(ip=f'45.3.0.{i + 1}', n=12 + i))               # unconfirmed, bulk
        self.feed(raw_event(THIRD, ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}))
        self.sweep()
        self.assertEqual({p['url'].split('/')[2] for p in self.posts()}, {'api.abuseipdb.com', 'api.sniffcat.com'})
        self.assertIn('reported', self.att(THIRD))
        self.assertEqual(sum(1 for i in range(8) if 'reported' in self.att(f'45.3.0.{i + 1}')), 0)

    def test_a_confirmed_address_is_kept_when_the_queue_overflows_and_still_gets_reported(self):
        h = self.api.ip_intel_handlers_mod
        old = h.QUEUE_CAP
        h.QUEUE_CAP = 5
        self.addCleanup(setattr, h, 'QUEUE_CAP', old)
        self.feed(raw_event(THIRD, ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}))
        for i in range(10):
            self.feed(web(ip=f'45.4.0.{i + 1}', n=3))
        self.sweep()
        self.assertIn('reported', self.att(THIRD))


class TestBlocking(_Engine):
    def setUp(self):
        super().setUp()
        self.policy(block_enabled=True, block_min_score=90)

    def sources(self, proxied):
        return [{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 1,
                 'parsed': 1, 'events': 1, 'proxied': proxied}]

    def feed_from(self, raw, proxied):
        """As the agent does: the evidence and the host's source health together."""
        self.feed(raw, sources=self.sources(proxied))

    def test_web_attacks_behind_a_proxy_are_not_blocked_at_the_host(self):
        """The visitor's address is not the packet's source behind a proxy, so the
        rule would sit in the firewall and block nothing."""
        self.feed_from(web(n=12), True)
        st = self.sweep()
        self.assertEqual(st['attackers'][ATTACKER]['devices']['d1']['not_blocked'], 'web attacks arrive through a proxy')
        self.assertEqual(self.queued('d1'), [])

    def test_the_same_attack_on_a_host_that_is_not_behind_one_is_blocked(self):
        self.feed_from(web(n=12), False)
        st = self.sweep()
        self.assertIn(ATTACKER, st['blocks']['d1'])
        self.assertTrue(any(ATTACKER in c and 'deny from' in c for c in self.queued('d1')))
        self.assertEqual(st['blocks']['d1'][ATTACKER]['kind'], 'web')

    def test_a_service_that_is_not_proxied_is_blocked_even_when_the_web_is(self):
        self.feed_from(raw_event(ban=['sshd'], src={'f2b': 3}, tok={'f2b': {'jail:sshd': 3}}), True)
        st = self.sweep()
        self.assertIn(ATTACKER, st['blocks']['d1'])

    def test_a_host_with_no_sensor_record_is_treated_as_not_proxied(self):
        self.feed(web(n=12))
        st = self.sweep()
        self.assertIn(ATTACKER, st['blocks']['d1'])


class TestEndToEnd(_Engine):
    def test_the_same_attack_through_the_real_intake(self):
        """Agent summary in, report out: the whole path, no shortcut."""
        self.api.verify_token = lambda _t=None: ('alice', 'admin')
        self.api.method = lambda: 'POST'
        body = {'device_id': 'd1', 'token': 't', 'sources': [], 'events': [raw_event(**SQLI)]}
        self.api.get_json_obj = lambda: dict(body)
        try:
            self.api.handle_threat_events()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['status'], 200, self.cap)
        self.api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual(self.abuse_form()['categories'], ['16,21'])


if __name__ == '__main__':
    unittest.main()
