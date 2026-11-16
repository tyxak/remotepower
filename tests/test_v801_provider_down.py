"""A service that does not answer is not charged to the day's allowance and does not stall the sweep (8.0.1).

Found on a live instance: SniffCat answered every report with HTTP 500 for a day. Each try was charged to the 900
reports a day, an address was tried again at every sighting, and by evening the allowance was gone, so nothing
would have been reported to SniffCat after it recovered either. Three rules now, each pinned below with the real
sweep against a provider stub that fails on demand:

  * an answer that is a network failure or an HTTP 5xx is not charged to the allowance;
  * the address waits ip_intel.TRANSIENT_RETRY_S before that service is asked about it again;
  * a service that fails ip_intel.TRANSIENT_BREAKER times in one sweep is not asked again in that sweep.

The manual Lookup button is not part of it: it asks as before and answers from what it spent.

The Edge blocklist's downloads of the two blacklists had the same fault in a second place: a download that failed was one of
the day's four, every new edge ban makes a sync due at once, and four failed tries by lunchtime left the list reading an old
copy under "downloads are used up for today" while the service said it had not been asked.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-provdown-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
from test_ip_intel import _Case  # noqa: E402

import edge_blocklist  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402
from test_v730_edge_blocklist_sync import _Lists  # noqa: E402

T = 1_790_000_000
MIN = 60
DOWN_500 = (500, {'success': False, 'message': 'Internal server error. Please report this to: support@sniffcat.com'})
DOWN_NET = (0, {'message': 'unreachable: TimeoutError'})


def addr(n):
    return '185.220.101.%d' % (10 + n)


def waf_event(ip, now=T):
    """What the sensor sends for an address a WAF refused three times: enough to report."""
    return threat_evidence.normalize_event(
        {'ip': ip, 'first': now - 60, 'last': now - 58, 'src': {'waf': 3},
         'tok': {'waf': {'crs:949110': 3, 'req:probe': 2}}, 'ans': 0, 'blk': 3, 'ban': [], 'dec': 0, 'cve': []},
        now=now)


class TestWhatCountsAsNoAnswer(unittest.TestCase):
    def test_a_network_failure_and_a_server_error_are_transient(self):
        for status in (0, 500, 502, 503, 599):
            r = ip_intel._error(status, {'message': 'x'})
            self.assertTrue(r.get('transient'), status)
            self.assertFalse(r['ok'])

    def test_an_answer_about_the_request_is_not(self):
        for status in (400, 401, 403, 404, 422, 429):
            self.assertFalse(ip_intel._error(status, {'message': 'x'}).get('transient'), status)

    def test_the_report_parsers_pass_it_on_and_keep_a_repeat_a_repeat(self):
        self.assertTrue(ip_intel.sniffcat_parse_report(*DOWN_500).get('transient'))
        self.assertTrue(ip_intel.abuseipdb_parse_report(*DOWN_NET).get('transient'))
        dup = ip_intel.abuseipdb_parse_report(429, {'errors': [{'detail': 'You can only report the same IP once in 15 minutes.'}]})
        self.assertTrue(dup.get('duplicate'))
        self.assertFalse(dup.get('transient'))


class TestWhatCountsAsNoAnswerForABlacklist(unittest.TestCase):
    def test_a_network_failure_and_a_server_error_are_transient(self):
        for status in (0, 500, 503):
            self.assertTrue(edge_blocklist.sniffcat_parse(status, {'message': 'x'}).get('transient'), status)
            self.assertTrue(edge_blocklist.abuseipdb_parse(status, {'errors': [{'detail': 'x'}]}).get('transient'), status)

    def test_an_answer_about_the_request_is_not(self):
        for status in (401, 403, 404, 429):
            self.assertFalse(edge_blocklist.sniffcat_parse(status, {'message': 'x'}).get('transient'), status)
        self.assertTrue(edge_blocklist.sniffcat_parse(429, {}).get('rate_limited'))


class TestBlocklistDownloads(_Lists):
    def setUp(self):
        super().setUp()
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=True)
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def due_now(self):
        """What every new edge ban does: the next sync is due at once."""
        ipintel_store.update(self.api, edgelist=dict(ipintel_store.read(self.api).get('edgelist') or {}, attempt=0))

    def source(self, el):
        return (el.get('last') or {}).get('sources', {}).get('sniffcat', {})

    def stale_failing(self, minutes_apart, n):
        """A copy a day old, the service answering 500, and a sync made due again each time."""
        el = self.tick(at=T)                                         # the copy, saved at T
        self.assertEqual((el['calls']['abuseipdb'], el['calls']['sniffcat']), (1, 1))
        self.sniff_status = 500
        out = []
        for i in range(n):
            self.due_now()
            out.append(self.tick(at=T + 7 * 3600 + i * minutes_apart * 60))
        return out

    def test_a_download_that_got_no_answer_is_not_one_of_the_days_downloads(self):
        els = self.stale_failing(11, 8)                              # eleven minutes apart: past the wait each time
        el = els[-1]
        self.assertEqual(el['calls']['sniffcat'], 1, 'only the download that worked is counted')
        self.assertNotIn('used up', self.source(el).get('error', ''))
        self.assertEqual(self.source(el)['from'], 'copy', 'the list is still made from the last copy')

    def test_the_service_is_left_alone_for_a_while_after_it_fails(self):
        self.stale_failing(1, 5)                                     # five syncs in five minutes
        self.assertEqual(self.downloads['sniffcat'], 2, 'the first download, and one failed try, not five')

    def test_it_is_asked_again_once_the_wait_is_over_and_a_good_answer_counts(self):
        self.stale_failing(1, 3)
        self.sniff_status = 200
        self.due_now()
        el = self.tick(at=T + 7 * 3600 + 11 * 60)
        self.assertEqual(self.source(el)['from'], 'download')
        self.assertEqual(el['calls']['sniffcat'], 2)
        self.assertNotIn('wait', el['calls'], 'a service that answered is not waited on')

    def test_a_real_refusal_still_counts_and_still_runs_out(self):
        self.stale_failing(1, 0)
        self.sniff_status = 429
        for i in range(6):
            self.due_now()
            el = self.tick(at=T + 7 * 3600 + i * 60)
        self.assertEqual(el['calls']['sniffcat'], edge_blocklist.CALLS_PER_DAY)
        self.assertIn('used up', self.source(el).get('error', ''))


class _Sweep(_Case):
    def setUp(self):
        super().setUp()
        api = self.api
        self.sniff_report = DOWN_500        # None = healthy
        self.sniff_check = None
        base = api._ip_intel_http

        def router(req):
            host = urlparse(req['url']).netloc
            if 'sniffcat' in host:
                bad = self.sniff_report if req['method'] == 'POST' else self.sniff_check
                if bad is not None:
                    self.calls.append(req)
                    return bad
            return base(req)
        api._ip_intel_http = router
        self.policy(lookup_enabled=True, report_enabled=True, block_enabled=False, report_waf_after=1)
        self.scores = {'abuseipdb': 10, 'sniffcat': 10}
        api._LOAD_CACHE.clear()

    def queue(self, n, start=0, now=T):
        events = [waf_event(addr(start + i), now) for i in range(n)]
        with mock.patch('time.time', return_value=now):
            self.api.ip_intel_note_evidence('d1', events, {'sources': [], 'ignored': {}, 'dropped': 0}, now)
        self.api._LOAD_CACHE.clear()

    def sweep_at(self, at):
        ipintel_store.update(self.api, last_sweep=0)
        with mock.patch('time.time', return_value=at):
            self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        return ipintel_store.read(self.api)

    def call(self, fn, method='GET', body=None, role='admin'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', role)
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def posts(self, host):
        return [c for c in self.calls if c['method'] == 'POST' and host in c['url']]

    def gets(self, host):
        return [c for c in self.calls if c['method'] == 'GET' and host in c['url']]


class TestReports(_Sweep):
    def test_a_service_that_is_down_costs_three_requests_a_sweep_and_none_of_the_allowance(self):
        self.queue(10)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('sniffcat')), ip_intel.TRANSIENT_BREAKER)
        self.assertEqual(len(self.posts('abuseipdb')), 10, 'the other service is not held back by it')
        budget = st['budget']
        self.assertEqual(budget.get('report:sniffcat', 0), 0, 'a try that filed nothing is not charged')
        self.assertEqual(budget.get('report:abuseipdb'), 10)
        errs = {ip: (a.get('errors') or {}).get('sniffcat') for ip, a in st['attackers'].items()}
        self.assertEqual(sum(1 for e in errs.values() if e and 'Internal server error' in e), ip_intel.TRANSIENT_BREAKER)
        self.assertEqual(sum(1 for e in errs.values() if e == 'not reported: the service is not answering'),
                         10 - ip_intel.TRANSIENT_BREAKER)
        self.assertTrue(all((a.get('reported') or {}).get('abuseipdb') for a in st['attackers'].values()))
        self.assertFalse(any((a.get('reported') or {}).get('sniffcat') for a in st['attackers'].values()))

    def test_an_address_waits_before_the_service_is_asked_about_it_again(self):
        self.queue(1)
        st = self.sweep_at(T + MIN)
        ip = addr(0)
        wait = st['attackers'][ip]['retry']['sniffcat']
        self.assertEqual(wait, T + MIN + ip_intel.TRANSIENT_RETRY_S)
        self.sniff_report = None                       # the service is back
        self.calls.clear()
        self.queue(1, now=T + 3 * MIN)                 # the same address again, inside the wait
        self.sweep_at(T + 4 * MIN)
        self.assertEqual(self.posts('sniffcat'), [], 'tried again at the next sighting')
        self.calls.clear()
        later = T + MIN + ip_intel.TRANSIENT_RETRY_S + MIN
        self.queue(1, now=later - MIN)
        st = self.sweep_at(later)
        self.assertEqual(len(self.posts('sniffcat')), 1, 'not tried once the wait is over')
        self.assertTrue(st['attackers'][ip]['reported'].get('sniffcat'))

    def test_the_allowance_is_still_there_when_the_service_comes_back(self):
        """The day it was lost: the allowance ran out while the service was down, so nothing went to it after. The
        addresses that were left waiting are taken up again once the wait is over, and each is charged then."""
        self.policy(daily_report_budget=12)
        self.queue(10)
        st = self.sweep_at(T + MIN)
        self.assertEqual(st['budget'].get('report:sniffcat', 0), 0)
        self.sniff_report = None
        st = self.sweep_at(T + 31 * MIN)               # past the wait; nothing new arrived
        self.assertEqual(len(self.posts('sniffcat')), ip_intel.TRANSIENT_BREAKER + 10)
        self.assertEqual(st['budget'].get('report:sniffcat'), 10)
        for ip, a in st['attackers'].items():
            self.assertTrue((a.get('reported') or {}).get('sniffcat'), ip)
            self.assertNotIn('daily report limit', str((a.get('errors') or {}).get('sniffcat') or ''), ip)

    def test_a_network_failure_is_treated_the_same(self):
        self.sniff_report = DOWN_NET
        self.queue(6)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('sniffcat')), ip_intel.TRANSIENT_BREAKER)
        self.assertEqual(st['budget'].get('report:sniffcat', 0), 0)

    def test_a_healthy_service_is_asked_about_every_address_and_charged_for_each(self):
        self.sniff_report = None
        self.queue(10)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('sniffcat')), 10)
        self.assertEqual(st['budget'].get('report:sniffcat'), 10)

    def test_a_rate_limit_still_counts_and_still_waits_as_before(self):
        self.sniff_report = (429, {'message': 'Submission rate limit exceeded or repeated report for the same IP'})
        self.queue(2)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('sniffcat')), 2, 'a 429 is an answer: the breaker is for no answer')
        self.assertEqual(st['budget'].get('report:sniffcat'), 2)
        self.assertEqual(st['attackers'][addr(0)]['retry']['sniffcat'], T + MIN + ip_intel.REPORT_RETRY_S['sniffcat'])


class TestLookups(_Sweep):
    def setUp(self):
        super().setUp()
        self.sniff_report = None
        self.sniff_check = DOWN_500

    def test_a_service_that_is_down_is_asked_three_times_a_sweep_and_not_charged(self):
        self.queue(10)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.gets('sniffcat')), ip_intel.TRANSIENT_BREAKER)
        self.assertEqual(len(self.gets('abuseipdb')), 10)
        self.assertEqual(st['budget'].get('sniffcat', 0), 0)
        self.assertEqual(st['budget'].get('abuseipdb'), 10)
        self.assertEqual(len(st['attackers']), 10, 'every address is recorded with the one service that answered')

    def test_the_manual_lookup_asks_as_before_and_answers_from_what_it_spent(self):
        self.policy(daily_lookup_budget=100)
        st, d = self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': addr(0)})
        self.assertEqual(st, 200, d)
        self.assertIn('sniffcat', d['errors'])
        self.api._LOAD_CACHE.clear()
        budget = ipintel_store.read(self.api)['budget']
        self.assertEqual((budget.get('abuseipdb'), budget.get('sniffcat')), (1, 1), 'the manual lookup charges what it asked')


if __name__ == '__main__':
    unittest.main()
