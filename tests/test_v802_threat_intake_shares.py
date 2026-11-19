"""8.0.2: one host cannot spend the day's lookups and reports, or push the other hosts' evidence out of the queue.

The day's allowance is one for the installation (900 lookups and 900 reports a service, unless the operator set others) and the evidence that
spends it comes from hosts. The intake promised that a compromised host could not spend it on invented addresses, and the limit that was meant to
keep the promise (3,000 addresses an hour a host) is larger than the allowance: one host, sending 300 invented addresses every six minutes,
spent both services' reports in thirty-six minutes, had 900 addresses filed under the operator's keys, and every other host's evidence was
refused for the rest of the day. The queue (500 entries) and the order in which the sweep takes entries both put the entries that rank highest
first, and a host chooses its own counts.

Each host has a share of each service's limit now (the limit divided by the number of hosts, at least five), and the queue and the claim take the
hosts in turn. The intake, the handler and the sweep run for real, with the clock moved a sweep at a time; only the two services are replaced.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-shares-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ipintel_store  # noqa: E402
from request_harness import RequestCase  # noqa: E402

import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402

T0 = int(time.time()) - 6 * 3600
HONEST = ['185.220.101.%d' % i for i in range(1, 4)]


def event(ip, at, n=1, ban=True):
    ev = {'ip': ip, 'first': at - 60, 'last': at - 5, 'src': {'f2b': n}, 'tok': {'f2b': {'jail:sshd': n}}, 'blk': n}
    if ban:
        ev['ban'] = ['sshd']
    return ev


def invented(i, at):
    n = i + 1
    return event('23.%d.%d.%d' % (n // 65536 % 256, n // 256 % 256, n % 256 or 1), at)


class TestTheHostsAreTakenInTurn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_ip_intel import _fresh_api
        cls.api = _fresh_api()
        cls.h = cls.api.ip_intel_handlers_mod

    def entries(self, host, ips, n=1, confirmed=True):
        return [{'ip': ip, 'device_id': host, 'unit': 'threat-sensor', 'count': n, 'window_s': 60, 'at': T0,
                 'evidence': threat_evidence.normalize_event(event(ip, T0, n, ban=confirmed), now=T0)} for ip in ips]

    def test_a_full_queue_keeps_the_other_hosts_evidence(self):
        old = self.h.QUEUE_CAP
        self.h.QUEUE_CAP = 20
        self.addCleanup(setattr, self.h, 'QUEUE_CAP', old)
        hostile = self.entries('hE', ['23.0.%d.%d' % (i // 250, i % 250 + 1) for i in range(60)], n=900)       # the most, and the strongest
        honest = self.entries('hA', HONEST, n=2)
        kept = self.h._trim_queue(hostile + honest)
        self.assertEqual(len(kept), 20)
        self.assertEqual({q['ip'] for q in kept} & set(HONEST), set(HONEST), 'the three of the host that sent three are all kept')

    def test_the_claim_gives_each_host_its_turn_of_the_places_that_are_rationed(self):
        hostile = self.entries('hE', ['23.0.%d.%d' % (i // 250, i % 250 + 1) for i in range(60)], n=900)
        honest = self.entries('hA', HONEST, n=2)
        pol = dict(ip_intel.DEFAULTS, report_enabled=True, keys={'abuseipdb': 'k' * 80, 'sniffcat': ''}, ignore_nets=[], ignore_kinds=set())
        batch, rest = self.h._claim_batch(hostile + honest, {}, pol, T0 + 100)
        self.assertEqual(len(batch), self.h.NET_PER_SWEEP)
        self.assertEqual({q['ip'] for q in batch} & set(HONEST), set(HONEST), 'the three of the other host came before the hostile host\'s fourth')
        self.assertEqual(len(rest), 60 + 3 - self.h.NET_PER_SWEEP)

    def test_with_one_host_the_order_is_the_strongest_first_as_it_was(self):
        a = self.entries('hA', ['45.1.1.1'], n=3, confirmed=False)
        b = self.entries('hA', ['45.1.1.2'], n=9, confirmed=False)
        c = self.entries('hA', ['45.1.1.3'], n=1, confirmed=True)
        order = self.h._fair_order(a + b + c, tiered=True, newest_first=False)
        self.assertEqual([(a + b + c)[i]['ip'] for i in order], ['45.1.1.3', '45.1.1.2', '45.1.1.1'])

    def test_the_brute_force_counters_entries_still_come_first_and_keep_their_order(self):
        legacy = [{'ip': '45.2.2.%d' % i, 'device_id': 'hA', 'unit': 'sshd.service', 'count': 25, 'window_s': 600, 'at': T0} for i in range(1, 4)]
        sensor = self.entries('hE', ['23.0.0.1'], n=900)
        order = self.h._fair_order(sensor + legacy, tiered=True, newest_first=False)
        self.assertEqual([(sensor + legacy)[i]['ip'] for i in order], ['45.2.2.1', '45.2.2.2', '45.2.2.3', '23.0.0.1'])

    def test_a_tie_in_a_trim_keeps_the_newer_entry_and_in_a_claim_the_older(self):
        pair = self.entries('hA', ['45.3.3.1', '45.3.3.2'], n=4, confirmed=False)
        self.assertEqual(self.h._fair_order(pair, tiered=False, newest_first=True)[0], 1)
        self.assertEqual(self.h._fair_order(pair, tiered=True, newest_first=False)[0], 0)


class TestTheSharesAreTheLimitDividedByTheHosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_ip_intel import _fresh_api
        cls.api = _fresh_api()
        cls.h = cls.api.ip_intel_handlers_mod

    def shares(self, hosts=2, windows=0, edge=False, budget=None, **pol):
        devices = {f'h{i}': {'os': 'Ubuntu 24.04'} for i in range(hosts)}
        devices.update({f'w{i}': {'os': 'Windows 11'} for i in range(windows)})
        devices['agentless'] = {'os': 'Debian 12', 'agentless': True}
        p = dict(ip_intel.DEFAULTS, keys={'abuseipdb': 'k' * 80, 'sniffcat': 's' * 40}, edge_enabled=edge, **pol)
        return self.h._HostShares(p, budget or {}, devices, {}, set())

    def test_the_limit_is_divided_by_the_linux_agents(self):
        s = self.shares(hosts=3, windows=2)
        self.assertEqual(s.n, 3, 'a Windows host and an agentless one are not hosts that send evidence')
        self.assertEqual(s.share('abuseipdb', 'reports'), 300)
        self.assertEqual(s.share('abuseipdb', 'lookups'), 300)

    def test_one_host_has_the_whole_limit(self):
        s = self.shares(hosts=1)
        self.assertEqual((s.share('abuseipdb', 'reports'), s.share('sniffcat', 'lookups')), (900, 900))

    def test_a_fleet_larger_than_the_limit_still_gives_every_host_a_few(self):
        s = self.shares(hosts=2000)
        self.assertEqual(s.share('abuseipdb', 'reports'), self.h.HOST_SHARE_MIN)

    def test_the_service_that_has_its_own_limit_is_divided_by_that(self):
        s = self.shares(hosts=4, limit_sniffcat_reports=100)
        self.assertEqual((s.share('sniffcat', 'reports'), s.share('abuseipdb', 'reports')), (25, 225))

    def test_a_limit_of_nothing_is_a_share_of_nothing(self):
        s = self.shares(hosts=2, daily_report_budget=0)
        self.assertEqual(s.share('abuseipdb', 'reports'), 0)
        self.assertFalse(s.any_left('h0', 'reports'))

    def test_the_edge_feeds_count_as_a_host_each_while_they_are_on(self):
        self.assertEqual(self.shares(hosts=2, edge=False).n, 2)
        self.assertEqual(self.shares(hosts=2, edge=True, edge_cf_events=True, edge_trap=True).n, 4)
        self.assertEqual(self.shares(hosts=2, edge=True, edge_cf_events=False, edge_trap=True).n, 3)

    def test_what_a_host_used_comes_off_its_share_and_a_new_day_starts_it_again(self):
        s = self.shares(hosts=2, budget={'host:h0:r:abuseipdb': 449, 'host:h0:r:sniffcat': 450})
        self.assertEqual((s.left('h0', 'abuseipdb', 'reports'), s.left('h0', 'sniffcat', 'reports'), s.left('h1', 'sniffcat', 'reports')), (1, 0, 450))
        self.assertTrue(s.any_left('h0', 'reports'))
        spent = {}
        s.charge('h0', 'abuseipdb', 'reports', spent)
        self.assertFalse(s.any_left('h0', 'reports'))
        self.assertEqual(spent, {'host:h0:r:abuseipdb': 1})
        day = self.h._budget_today({'day': '2000-01-01', 'host:h0:r:abuseipdb': 449}, '2000-01-02')
        self.assertEqual(day, {'day': '2000-01-02', 'v': ip_intel.BUDGET_VERSION})

    def test_the_first_host_of_an_address_that_has_a_share_pays_for_its_report(self):
        s = self.shares(hosts=2, budget={'host:h0:r:abuseipdb': 450})
        group = [{'dev_id': 'h0'}, {'dev_id': 'h1'}]
        self.assertEqual(s.payer(group, 'abuseipdb', 'reports'), 'h1')
        self.assertEqual(s.payer(group[:1], 'abuseipdb', 'reports'), None)

    def test_a_count_that_went_up_and_came_back_is_not_written(self):
        st = {}
        self.h._add_spend(st, '2000-01-01', {'host:h0:r:abuseipdb': 0, 'report:abuseipdb': 0, 'abuseipdb': 2})
        self.assertEqual(st['budget'], {'day': '2000-01-01', 'v': ip_intel.BUDGET_VERSION, 'report:abuseipdb': 0, 'abuseipdb': 2},
                         'the service-level counts are written as they always were')


class _Sweeps(RequestCase):
    LIMIT = 20            # a day's lookups and reports for each service; the share of each of two hosts is ten

    def setUp(self):
        super().setUp()
        self.put(devices={
            'hA': {'id': 'hA', 'name': 'web-acme', 'os': 'Ubuntu 24.04', 'token': 'tokA', 'tenant': 'acme', 'last_seen': T0},
            'hE': {'id': 'hE', 'name': 'web-globex', 'os': 'Ubuntu 24.04', 'token': 'tokE', 'tenant': 'globex', 'last_seen': T0}},
            tenancy_enforced=True, abuseipdb_api_key='a' * 80, sniffcat_api_key='s' * 40,
            ip_intel={'sensor_enabled': True, 'report_enabled': True, 'lookup_enabled': True,
                      'daily_report_budget': self.LIMIT, 'daily_lookup_budget': self.LIMIT})
        self.sent = []
        self.status = 200
        self.lookup_status = 200

        def http(req):
            self.sent.append(req)
            if req['method'] == 'POST':
                return (self.status, {'success': True, 'data': {}} if self.status == 200 else None)
            if self.lookup_status != 200:
                return self.lookup_status, None
            if 'abuseipdb' in req['url']:
                return 200, {'data': {'abuseConfidenceScore': 10, 'totalReports': 0, 'countryCode': 'DE', 'isp': 'x'}}
            return 200, {'success': True, 'status': 200, 'abuseConfidenceScore': 10}
        self.api._ip_intel_http = http
        self.minute = 0

    def post(self, dev, token, events, at):
        with mock.patch('time.time', return_value=at):
            return self.call(self.api.handle_threat_events, body={'device_id': dev, 'token': token, 'events': events, 'sources': []}, method='POST')

    def sweep(self, times=1):
        for _ in range(times):
            self.minute += 1
            at = T0 + 3600 + self.minute * 61
            ipintel_store.update(self.api, last_sweep=0)
            self.api._LOAD_CACHE.clear()
            with mock.patch('time.time', return_value=at):
                self.api.run_ip_intel_if_due()
            self.api._LOAD_CACHE.clear()

    def reports(self, who):
        return sum(1 for r in self.sent if r['method'] == 'POST' and who in r['url'])

    def lookups(self, who):
        return sum(1 for r in self.sent if r['method'] == 'GET' and who in r['url'])

    def budget(self):
        return dict(self.api.load(self.api.IPINTEL_FILE).get('budget') or {})


class TestOneHostCannotSpendTheDaysAllowance(_Sweeps):
    def test_the_control_one_honest_address_is_looked_up_and_reported(self):
        self.post('hA', 'tokA', [event(HONEST[0], T0 + 3600)], T0 + 3600)
        self.sweep()
        self.assertEqual((self.reports('abuseipdb'), self.reports('sniffcat')), (1, 1))
        self.assertEqual((self.lookups('abuseipdb'), self.lookups('sniffcat')), (1, 1))

    def test_a_host_that_makes_up_addresses_spends_its_share_and_no_more(self):
        at = T0 + 3600
        st, body = self.post('hE', 'tokE', [invented(i, at) for i in range(60)], at)
        self.assertEqual(body['accepted'], 60)
        self.sweep(times=6)
        b = self.budget()
        for who in ('abuseipdb', 'sniffcat'):
            self.assertEqual(self.reports(who), 10, f'{who}: the host\'s share of {self.LIMIT} among two hosts')
            self.assertEqual(self.lookups(who), 10)
            self.assertEqual(b['host:hE:r:' + who], 10)
            self.assertEqual(b['host:hE:l:' + who], 10)
            self.assertEqual(b['report:' + who], 10, 'the service-level count is still the sum of what was sent')

    def test_the_evidence_of_another_host_is_still_looked_up_and_reported_afterwards(self):
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(60)], at)
        self.sweep(times=6)
        before = len(self.sent)
        self.post('hA', 'tokA', [event(ip, at + 4000) for ip in HONEST], at + 4000)
        self.sweep(times=2)
        self.assertGreater(len(self.sent), before, 'the sweep still had calls to make')
        st = self.api.load(self.api.IPINTEL_FILE)
        for ip in HONEST:
            att = st['attackers'][ip]
            self.assertEqual(sorted(att.get('reported') or {}), ['abuseipdb', 'sniffcat'], f'{ip} was reported to both services')
            self.assertEqual(att.get('errors') or {}, {}, f'{ip}: nothing the page says is wrong')
        self.assertEqual(self.reports('abuseipdb'), 10 + 3)
        self.assertEqual(self.budget()['host:hA:r:abuseipdb'], 3)

    def test_what_the_hosts_share_is_not_more_than_the_limit(self):
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(60)], at)
        self.post('hA', 'tokA', [invented(i + 100, at) for i in range(60)], at)
        self.sweep(times=12)
        for who in ('abuseipdb', 'sniffcat'):
            self.assertEqual((self.reports(who), self.lookups(who)), (self.LIMIT, self.LIMIT), 'two hosts at their shares are the limit and not over it')

    def test_an_address_the_host_could_not_pay_for_says_so_and_waits_for_tomorrow(self):
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(30)], at)
        self.sweep(times=4)
        st = self.api.load(self.api.IPINTEL_FILE)
        said = [(a.get('errors') or {}).get('abuseipdb') for a in st['attackers'].values()]
        self.assertEqual(said.count("not reported: this host has used its share of the day's report limit"), 20,
                         'ten of the thirty were reported, and each of the other twenty says why it was not')
        self.assertEqual(sum(1 for a in st['attackers'].values() if a.get('reported')), 10)

    def test_a_service_the_host_has_used_its_share_of_is_not_asked_while_another_still_is(self):
        """SniffCat is limited to twelve a day, so each of two hosts has six of it and ten of AbuseIPDB's twenty."""
        self.put(devices=self.api.load(self.api.DEVICES_FILE), tenancy_enforced=True, abuseipdb_api_key='a' * 80, sniffcat_api_key='s' * 40,
                 ip_intel={'sensor_enabled': True, 'report_enabled': True, 'lookup_enabled': True, 'daily_report_budget': self.LIMIT,
                           'daily_lookup_budget': self.LIMIT, 'limit_sniffcat_lookups': 12})
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(30)], at)
        self.sweep(times=4)
        self.assertEqual((self.lookups('abuseipdb'), self.lookups('sniffcat')), (10, 6))
        b = self.budget()
        self.assertEqual((b['host:hE:l:abuseipdb'], b['host:hE:l:sniffcat']), (10, 6))

    def test_a_host_that_has_used_its_share_does_not_hold_the_sweeps_places(self):
        """The sweep makes calls for 25 addresses at most. An entry of a host with nothing left to spend has no call to make, so it is taken
        without taking a place, and the queue is empty after two sweeps and not after three."""
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(60)], at)
        self.sweep()
        self.assertEqual(len(ipintel_store.read_intake(self.api)['queue']), 35, 'the first sweep makes calls for 25 of them')
        self.sweep()
        self.assertEqual(len(ipintel_store.read_intake(self.api)['queue']), 0, 'the host has used its ten: the rest are taken at once')

    def test_a_request_the_service_never_answered_is_not_charged_to_the_host(self):
        self.status = 500
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(3)], at)
        self.sweep(times=2)
        self.assertFalse([k for k in self.budget() if k.startswith('host:') and k.split(':')[2] == 'r' and self.budget()[k]],
                         'a report that was refused as transient was not filed, so it is not on the host\'s account')

    def test_a_lookup_the_service_never_answered_is_not_charged_to_the_host(self):
        self.lookup_status = 503
        at = T0 + 3600
        self.post('hE', 'tokE', [invented(i, at) for i in range(3)], at)
        self.sweep(times=2)
        self.assertGreater(self.lookups('abuseipdb'), 0, 'the instrument: the service was asked')
        self.assertFalse([k for k, v in self.budget().items() if k.startswith('host:') and k.split(':')[2] == 'l' and v],
                         'a lookup that got no answer is not on the host\'s account')

    def test_a_single_host_install_keeps_the_whole_limit(self):
        self.put(devices={'hA': {'id': 'hA', 'name': 'web', 'os': 'Ubuntu 24.04', 'token': 'tokA', 'last_seen': T0}},
                 abuseipdb_api_key='a' * 80, sniffcat_api_key='s' * 40,
                 ip_intel={'sensor_enabled': True, 'report_enabled': True, 'lookup_enabled': True,
                           'daily_report_budget': self.LIMIT, 'daily_lookup_budget': self.LIMIT})
        at = T0 + 3600
        self.post('hA', 'tokA', [invented(i, at) for i in range(40)], at)
        self.sweep(times=4)
        self.assertEqual((self.reports('abuseipdb'), self.lookups('abuseipdb')), (self.LIMIT, self.LIMIT))


if __name__ == '__main__':
    unittest.main()
