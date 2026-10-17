"""The edge blocklist, driven for real: the sweep and the endpoints against a small
in-memory Cloudflare Lists API and the two blacklists.

The seam is `_ip_intel_http`, as in the other Threat intel tests. What matters here
is what the feature does to somebody's account: nothing without being asked, nothing
to a list it did not create until told to take it over, nothing that is protected,
nothing that would empty or halve a list unasked, and the token never leaves the
header.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-eblist-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import edge_blocklist as eb  # noqa: E402
from test_ip_intel import _Case  # noqa: E402

T = 1_790_000_000
ACCT = 'a' * 32
TOKEN = 'LISTtoken_' + 'z' * 32
OFFICE = '93.184.216.34'


def ips(prefix, n, start=1):
    return [f'{prefix}.{(start + i) // 250}.{(start + i) % 250 + 1}' for i in range(n)]


class _Lists(_Case):
    def setUp(self):
        super().setUp()
        api = self.api
        self.lists = {}                      # id -> {id, name, kind, description, items}
        self.ops = {}                        # id -> polls left before it completes
        self.abuse = ['185.220.101.1', '185.220.101.2', '185.220.101.3']
        self.sniff = ['45.155.205.1', '45.155.205.2']
        self.abuse_status, self.sniff_status = 200, 200
        self.list_limit = False
        self.busy = False
        self.page = 500
        self.polls = 0                       # bulk-operation polls that answer "pending" first
        self.cf = []                         # every Cloudflare request, in order
        self.downloads = {'abuseipdb': 0, 'sniffcat': 0}
        self._n = 0
        provider = api._ip_intel_http

        def _router(req):
            host = urlparse(req['url']).netloc
            if host == 'api.cloudflare.com':
                return self._cloudflare(req)
            if host == 'api.abuseipdb.com' and '/blacklist' in req['url']:
                self.downloads['abuseipdb'] += 1
                self.calls.append(req)
                if self.abuse_status != 200:
                    return self.abuse_status, {'errors': [{'detail': 'nope'}]}
                return 200, {'data': [{'ipAddress': a} for a in self.abuse]}
            if host == 'api.sniffcat.com' and '/blacklist' in req['url']:
                self.downloads['sniffcat'] += 1
                self.calls.append(req)
                if self.sniff_status != 200:
                    return self.sniff_status, {'success': False, 'message': 'No quota assigned to the role'}
                return 200, {'success': True, 'reports': [{'ip': a} for a in self.sniff]}
            return provider(req)
        api._ip_intel_http = _router
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': '10.0.0.5',
                   'public_ip': OFFICE},
        })
        cfg = api.load(api.CONFIG_FILE)
        cfg['edge_list_token'] = TOKEN
        api.save(api.CONFIG_FILE, cfg)
        self.policy(edgelist_enabled=True, edge_account_id=ACCT, edgelist_name='my_list', edgelist_own=False,
                    report_enabled=False)
        api._LOAD_CACHE.clear()

    # ── a small Cloudflare ──
    def new_list(self, name='my_list', items=(), description='', kind='ip'):
        self._n += 1
        lid = f'{self._n:032x}'
        self.lists[lid] = {'id': lid, 'name': name, 'kind': kind, 'description': description,
                           'items': list(items)}
        return lid

    def _cloudflare(self, req):
        self.cf.append(req)
        assert req['headers']['Authorization'] == 'Bearer ' + TOKEN, 'the token goes in the header'
        u = urlparse(req['url'])
        path, q = u.path, parse_qs(u.query)
        m = re.fullmatch(r'/client/v4/accounts/([0-9a-f]{32})/rules/lists(?:/([0-9a-f]{32}))?(/items)?', path)
        op = re.fullmatch(r'/client/v4/accounts/[0-9a-f]{32}/rules/lists/bulk_operations/([0-9a-f]{32})', path)
        meth = req['method']
        if op:
            oid = op.group(1)
            left = self.ops.get(oid)
            if left is None:
                return 404, {'success': False, 'errors': [{'code': 7003, 'message': 'no such operation'}]}
            if left > 0:
                self.ops[oid] = left - 1
                return 200, {'success': True, 'result': {'id': oid, 'status': 'running'}}
            return 200, {'success': True, 'result': {'id': oid, 'status': 'completed'}}
        if not m:
            return 404, {'success': False, 'errors': [{'code': 7003, 'message': 'no route'}]}
        lid, items = m.group(2), m.group(3)
        if not lid and meth == 'GET':
            return 200, {'success': True, 'result': [
                {'id': x['id'], 'name': x['name'], 'kind': x['kind'], 'description': x['description'],
                 'num_items': len(x['items'])} for x in self.lists.values()]}
        if not lid and meth == 'POST':
            if self.list_limit:
                return 400, {'success': False, 'errors': [{'code': 10019, 'message': 'list limit reached'}]}
            body = json.loads(req['body'])
            return 200, {'success': True, 'result': {'id': self.new_list(
                body['name'], (), body.get('description', ''))}}
        if lid not in self.lists:
            return 404, {'success': False, 'errors': [{'code': 10001, 'message': 'list not found'}]}
        lst = self.lists[lid]
        if items and meth == 'GET':
            start = int((q.get('cursor') or ['0'])[0] or 0)
            page = lst['items'][start:start + self.page]
            nxt = start + self.page
            info = {'cursors': {'after': str(nxt)}} if nxt < len(lst['items']) else {}
            return 200, {'success': True, 'result': [{'ip': x} for x in page], 'result_info': info}
        if items and meth == 'PUT':
            if self.busy:
                return 409, {'success': False, 'errors': [{'code': 10020,
                                                           'message': 'another bulk operation is in progress'}]}
            lst['items'] = [x['ip'] for x in json.loads(req['body'])]
            oid = f'{900 + len(self.ops):032x}'
            self.ops[oid] = self.polls
            return 200, {'success': True, 'result': {'operation_id': oid}}
        if meth == 'PUT':
            lst['description'] = json.loads(req['body'])['description']
            return 200, {'success': True, 'result': {'id': lid}}
        return 405, {'success': False}

    # ── driving it ──
    def writes(self):
        return [c for c in self.cf if c['method'] in ('PUT', 'POST')]

    def tick(self, at=T):
        with mock.patch('time.time', return_value=at), mock.patch('time.sleep'):
            self.api.run_edge_blocklist_if_due()
        self.api._LOAD_CACHE.clear()
        return (self.api.load(self.api.IPINTEL_FILE) or {}).get('edgelist') or {}

    def call(self, fn, body=None, role='admin', at=T, method='POST'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', role)
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        with mock.patch('time.time', return_value=at), mock.patch('time.sleep'):
            try:
                fn()
            except api.HTTPError:
                pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def only_list(self):
        return next(iter(self.lists.values()))


class TestOffUntilAskedFor(_Lists):
    def test_nothing_happens_when_it_is_off(self):
        self.policy(edgelist_enabled=False)
        self.tick()
        self.assertEqual(self.cf, [])
        self.assertEqual(self.downloads, {'abuseipdb': 0, 'sniffcat': 0})

    def test_nothing_happens_without_the_token(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_list_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.tick()
        self.assertEqual(self.cf, [])

    def test_a_missing_account_id_is_said(self):
        self.policy(edge_account_id='')
        el = self.tick()
        self.assertEqual(el['last']['state'], 'needs_setup')
        self.assertIn('account id', el['last']['why'])
        self.assertEqual(self.cf, [])


class TestMakingTheList(_Lists):
    def setUp(self):
        super().setUp()
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=True)
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def test_it_creates_the_list_and_fills_it_in_priority_order(self):
        self.policy(edgelist_always=['2.2.2.2', '9.9.9.0/24'])
        el = self.tick()
        lst = self.only_list()
        self.assertEqual(lst['name'], 'my_list')
        self.assertTrue(eb.managed(lst['description']), lst['description'])
        self.assertEqual(lst['items'], ['2.2.2.2', '9.9.9.0/24', '185.220.101.1', '185.220.101.2',
                                        '185.220.101.3', '45.155.205.1', '45.155.205.2'])
        self.assertEqual((el['last']['state'], el['last']['changed'], el['last']['created']), ('ok', True, True))
        self.assertEqual(el['last']['kept'], {'always': 2, 'own': 0, 'abuseipdb': 3, 'sniffcat': 2})

    def test_every_item_says_where_it_came_from(self):
        self.tick()
        puts = [c for c in self.cf if c['method'] == 'PUT' and c['url'].endswith('/items')]
        body = json.loads(puts[-1]['body'])
        self.assertEqual({x['comment'] for x in body}, {'RemotePower: abuseipdb', 'RemotePower: sniffcat'})

    def test_the_second_run_changes_nothing(self):
        self.tick()
        n = len(self.writes())
        el = self.tick(at=T + 7 * 3600)
        self.assertEqual(len(self.writes()), n)
        self.assertEqual((el['last']['state'], el['last']['changed']), ('ok', False))

    def test_it_is_not_run_again_before_its_interval(self):
        self.tick()
        n = len(self.cf)
        self.tick(at=T + 600)
        self.assertEqual(len(self.cf), n)
        self.tick(at=T + 6 * 3600 + 5)
        self.assertGreater(len(self.cf), n)

    def test_ipv6_does_not_churn(self):
        self.abuse = ['2a01:4f8:c17:1234::1', '2a00:1450:4001:81b::200e']
        self.sniff = []
        self.policy(edgelist_sniffcat=False)
        self.tick()
        self.assertEqual(len(self.only_list()['items']), 2, 'both addresses went in')
        # Cloudflare keeps its own spelling: upper case, expanded groups
        self.only_list()['items'] = ['2A01:4F8:C17:1234:0:0:0:1', '2A00:1450:4001:81B:0:0:0:200E']
        n = len(self.writes())
        el = self.tick(at=T + 7 * 3600)
        self.assertEqual(len(self.writes()), n, 'the same addresses in another spelling are not a change')
        self.assertEqual((el['last']['added'], el['last']['removed']), (0, 0))

    def test_the_lists_pages_are_all_read(self):
        lid = self.new_list(description=eb.description('7.3.0', ['abuseipdb']),
                            items=ips('185.221', 10))
        self.page = 3
        el = self.tick()
        self.assertEqual(el['last']['current'], 10)
        self.assertEqual(sorted(self.lists[lid]['items']),
                         sorted(self.abuse + self.sniff))

    def test_what_the_page_reads_is_counts_and_never_the_copies_or_the_token(self):
        self.tick()
        st = self.api.load(self.api.IPINTEL_FILE)
        view = self.api.edge_list_status(st, self.api.ip_intel_policy())
        blob = json.dumps(view)
        self.assertNotIn(TOKEN, blob)
        self.assertEqual(view['src']['abuseipdb'], {'at': T, 'n': 3}, 'a copy is a count and a time')
        self.assertTrue(view['token_set'])

    def test_a_big_source_reaches_the_page_as_a_count_and_a_short_sample(self):
        self.abuse = ips('185.240', 400)
        self.tick()
        st = self.api.load(self.api.IPINTEL_FILE)
        view = self.api.edge_list_status(st, self.api.ip_intel_policy())
        self.assertEqual(view['src']['abuseipdb']['n'], 400)
        self.assertEqual(len(re.findall(r'185\.240\.', json.dumps(view))), 20,
                         'only the added sample is sent, and it is capped')


class TestALeftAloneList(_Lists):
    def test_a_list_it_did_not_create_is_left_alone_until_taken_over(self):
        lid = self.new_list(description='Managed by Cloudflare-WAF-Expressions v3.3.2', items=ips('203.1', 30))
        before = list(self.lists[lid]['items'])
        el = self.tick()
        self.assertEqual(el['last']['state'], 'needs_adopt')
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.lists[lid]['items'], before)
        self.assertEqual(self.downloads, {'abuseipdb': 0, 'sniffcat': 0}, 'it did not even fetch')

    def test_the_preview_shows_what_taking_over_would_do_and_writes_nothing(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'] = 'a' * 80
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False)
        lid = self.new_list(description='Managed by Cloudflare-WAF-Expressions v3.3.2', items=ips('203.1', 30))
        st, d = self.call(self.api.handle_edge_list_preview)
        self.assertEqual(st, 200)
        r = d['result']
        self.assertEqual((r['state'], r['needs_adopt'], r['added'], r['removed']), ('preview', True, 3, 30))
        self.assertEqual(self.writes(), [])
        self.assertEqual(len(self.lists[lid]['items']), 30)

    def test_taking_over_replaces_it_and_marks_it(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'] = 'a' * 80
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False)
        lid = self.new_list(description='Managed by Cloudflare-WAF-Expressions v3.3.2', items=ips('203.1', 30))
        st, d = self.call(self.api.handle_edge_list_sync, {'adopt': True})
        self.assertEqual((st, d['result']['state']), (200, 'ok'))
        self.assertEqual(self.lists[lid]['items'], self.abuse)
        self.assertTrue(eb.managed(self.lists[lid]['description']))
        self.assertIn(('ip-intel' if False else 'alice'), [a[0] for a in self.audit])   # attributed to the operator
        self.assertTrue(any(a[1] == 'edge_list_sync' for a in self.audit))
        # and from then on the schedule keeps it
        self.abuse.append('185.220.101.99')
        self.api._LOAD_CACHE.clear()
        el = self.tick(at=T + 7 * 3600)
        self.assertEqual(el['last']['state'], 'ok')
        self.assertIn('185.220.101.99', self.lists[lid]['items'])

    def test_a_list_that_is_not_an_ip_list_is_never_touched(self):
        self.new_list(kind='hostname')
        el = self.tick()
        self.assertEqual(el['last']['state'], 'needs_setup')
        self.assertEqual(self.writes(), [])


class TestWhatNeverGoesIn(_Lists):
    def setUp(self):
        super().setUp()
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'] = 'a' * 80
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False, never_block=['151.101.0.0/24'])
        self.api._LOAD_CACHE.clear()

    def test_the_fleet_the_never_block_list_and_cloudflare_stay_out(self):
        self.abuse = [OFFICE, '151.101.0.9', '104.16.0.1', '10.0.0.5', '185.220.101.1']
        el = self.tick()
        self.assertEqual(self.only_list()['items'], ['185.220.101.1'])
        # the office address, the never-block range and Cloudflare's are protected; a
        # private address is not an internet address at all and is dropped on reading
        self.assertEqual(el['last']['dropped'], {'protected': 3})
        self.assertEqual(el['last']['sources']['abuseipdb']['n'], 4)

    def test_a_range_the_operator_lists_that_covers_a_protected_address_is_refused_whole(self):
        self.policy(edgelist_always=['185.220.101.0/24'], never_block=['185.220.101.200'])
        self.abuse = []
        el = self.tick()
        self.assertEqual(self.only_list()['items'], [])
        self.assertEqual(el['last']['dropped'], {'protected': 1})


class TestWhatItWillNotDoUnasked(_Lists):
    def setUp(self):
        super().setUp()
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False)
        self.api._LOAD_CACHE.clear()
        self.big = ips('185.230', 1000)
        self.lid = self.new_list(description=eb.description('7.3.0', ['abuseipdb']), items=self.big)

    def test_it_will_not_halve_a_list_unasked_but_will_when_told_to(self):
        self.abuse = self.big[:100]
        el = self.tick()
        self.assertEqual(el['last']['state'], 'held')
        self.assertEqual(el['last']['why'], 'The list would shrink by more than half.')
        self.assertEqual((el['last']['current'], el['last']['size']), (1000, 100), 'the numbers are in the result')
        self.assertEqual(len(self.lists[self.lid]['items']), 1000)
        self.assertEqual(self.writes(), [])
        st, d = self.call(self.api.handle_edge_list_sync, {'force': True}, at=T + 10)
        self.assertEqual(d['result']['state'], 'ok')
        self.assertEqual(len(self.lists[self.lid]['items']), 100)

    def test_a_read_cut_short_does_not_make_a_big_list_look_small(self):
        """Cloudflare says the list holds 1000; the item pages stop at the page
        limit. The guard measures the larger of the two."""
        self.page = 3
        self.abuse = self.big[:100]
        el = self.tick()
        self.assertEqual(el['last']['state'], 'held')
        self.assertEqual(el['last']['current'], 1000)
        self.assertEqual(self.writes(), [])

    def test_a_read_cut_short_never_skips_the_write(self):
        """150 entries, and the pages stop after 120: what was read matches what is
        wanted, and the other 30 were never seen. They must still go."""
        held = ips('185.250', 150)
        self.lists[self.lid]['items'] = list(held)
        self.page = 3
        self.abuse = held[:120]
        el = self.tick()
        self.assertEqual(el['last']['state'], 'ok')
        self.assertEqual(self.lists[self.lid]['items'], held[:120])

    def test_a_slow_read_stops_at_its_budget_and_still_writes_the_whole_list(self):
        held = ips('185.250', 150)
        self.lists[self.lid]['items'] = list(held)
        self.page = 3
        self.abuse = list(held)
        ticks = iter(range(0, 10 ** 6, 30))          # 30 s of reading for every look at the clock
        mod = self.api.edge_blocklist_handlers_mod
        real = mod._mono
        mod._mono = lambda: next(ticks)
        try:
            el = self.tick()
        finally:
            mod._mono = real
        pages = [c for c in self.cf if c['method'] == 'GET' and '/items' in c['url']]
        self.assertLess(len(pages), 10, 'the read stopped at its budget, not at the end of the list')
        self.assertEqual(el['last']['state'], 'ok')
        self.assertEqual(el['last']['current'], 150, 'the size is what Cloudflare says, not what was read')
        self.assertEqual(sorted(self.lists[self.lid]['items']), sorted(held))

    def test_a_source_that_answers_nothing_cannot_empty_the_list(self):
        self.abuse = []
        el = self.tick()
        self.assertEqual(el['last']['state'], 'held')
        self.assertEqual(len(self.lists[self.lid]['items']), 1000)

    def test_a_source_that_fails_holds_the_sync_when_there_is_no_copy(self):
        self.abuse_status = 500
        el = self.tick()
        self.assertEqual(el['last']['state'], 'held')
        self.assertIn('abuseipdb', el['last']['failed'])
        # the reason says a source failed, not "no source is switched on"; which one
        # is in `failed`, with its own sentence
        self.assertIn('did not answer', el['last']['why'])
        self.assertNotIn('switched on', el['last']['why'])
        self.assertTrue(el['last']['failed']['abuseipdb'])
        self.assertEqual(self.writes(), [])

    def test_a_source_that_fails_is_read_from_its_last_copy(self):
        self.abuse = self.big
        self.tick()
        self.abuse_status = 429
        self.abuse = []
        self.api._LOAD_CACHE.clear()
        el = self.tick(at=T + 7 * 3600)
        self.assertEqual(el['last']['state'], 'ok')
        self.assertEqual(el['last']['sources']['abuseipdb']['from'], 'copy')
        self.assertIn('limit', el['last']['sources']['abuseipdb']['error'])
        self.assertEqual(len(self.lists[self.lid]['items']), 1000)

    def test_a_copy_older_than_three_days_is_not_trusted(self):
        self.abuse = self.big
        self.tick()
        self.abuse_status = 500
        self.api._LOAD_CACHE.clear()
        el = self.tick(at=T + 4 * 86400)
        self.assertEqual(el['last']['state'], 'held')

    def test_downloads_are_rationed_to_the_days_allowance(self):
        self.abuse = self.big
        self.policy(edgelist_hours=1)
        for i in range(8):
            self.api._LOAD_CACHE.clear()
            # never copies young enough to reuse: force a download each time
            st = self.api.load(self.api.IPINTEL_FILE) or {}
            st.get('edgelist', {}).get('src', {}).pop('abuseipdb', None)
            self.api.save(self.api.IPINTEL_FILE, st)
            self.api._LOAD_CACHE.clear()
            self.tick(at=T + i * 3700)
        self.assertEqual(self.downloads['abuseipdb'], eb.CALLS_PER_DAY)


class TestCapacityAndOperations(_Lists):
    def setUp(self):
        super().setUp()
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'] = 'a' * 80
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False, edgelist_always=['2.2.2.2'])
        self.api._LOAD_CACHE.clear()

    def test_the_accounts_other_lists_come_off_the_cap(self):
        self.new_list(name='someone_elses', items=ips('7.7', 9998))
        self.abuse = ['185.220.101.1', '185.220.101.2', '185.220.101.3']
        el = self.tick()
        self.assertEqual(el['last']['capacity'], 2)
        self.assertEqual(self.only_list_named('my_list')['items'], ['2.2.2.2', '185.220.101.1'])
        self.assertEqual(el['last']['trimmed'], 2)

    def only_list_named(self, name):
        return next(x for x in self.lists.values() if x['name'] == name)

    def test_an_operation_that_is_still_running_is_waited_for_and_not_overtaken(self):
        self.polls = 50                      # longer than one request will wait
        el = self.tick()
        self.assertEqual(el['last']['state'], 'pending')
        self.assertTrue(el.get('op'))
        puts = [c for c in self.cf if c['method'] == 'PUT' and c['url'].endswith('/items')]
        self.assertEqual(len(puts), 1)
        # the next sweep looks at the operation first, and starts nothing while it runs
        el = self.tick(at=T + 400)
        self.assertEqual(len([c for c in self.cf if c['method'] == 'PUT' and c['url'].endswith('/items')]), 1)
        self.assertTrue(el.get('op'))

    def test_a_finished_operation_is_cleared_and_the_schedule_goes_on(self):
        self.polls = 50
        self.tick()
        for oid in list(self.ops):
            self.ops[oid] = 0
        el = self.tick(at=T + 400)
        self.assertFalse(el.get('op'))
        self.assertEqual(el['last']['state'], 'ok')

    def test_cloudflare_being_busy_is_a_wait_not_a_failure(self):
        self.busy = True
        el = self.tick()
        self.assertEqual(el['last']['state'], 'pending')
        self.assertIn('still working', el['last']['why'])

    def test_the_account_list_limit_is_said_in_words(self):
        self.list_limit = True
        el = self.tick()
        self.assertEqual(el['last']['state'], 'error')
        self.assertIn('limit', el['last']['why'])

    def test_a_token_that_cannot_edit_lists_says_so(self):
        orig = self.api._ip_intel_http

        def deny(req):
            if urlparse(req['url']).netloc == 'api.cloudflare.com':
                return 403, {'success': False, 'errors': [{'code': 10000, 'message': 'Authentication error'}]}
            return orig(req)
        self.api._ip_intel_http = deny
        el = self.tick()
        self.assertEqual(el['last']['state'], 'error')
        self.assertTrue(el['last']['auth'])
        self.assertIn('cannot edit lists', el['last']['why'])


class TestOwnEvidence(_Lists):
    def test_what_remotepower_found_goes_in_when_it_was_reported_or_scored(self):
        self.policy(edgelist_own=True, edgelist_abuseipdb=False, edgelist_sniffcat=False)
        st = self.api.load(self.api.IPINTEL_FILE) or {}
        st['attackers'] = {
            '185.220.101.7': {'last_seen': T - 100, 'verdict': {'score': 95}},
            '45.155.205.9': {'last_seen': T - 100, 'verdict': {'score': 5}, 'reported': {'sniffcat': T - 50}},
            '89.248.165.2': {'last_seen': T - 100, 'verdict': {'score': 30}},
            OFFICE: {'last_seen': T - 100, 'verdict': {'score': 99}},
        }
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        el = self.tick()
        self.assertEqual(self.only_list()['items'], ['185.220.101.7', '45.155.205.9'])
        self.assertEqual(el['last']['kept']['own'], 2)
        self.assertEqual(el['last']['dropped'], {'protected': 1}, 'the fleet\'s own address, scored high or not')


class TestTheEndpointsAndSettings(_Lists):
    def test_only_an_admin_and_only_a_post(self):
        for fn in (self.api.handle_edge_list_preview, self.api.handle_edge_list_sync):
            st, _ = self.call(fn, role='viewer')
            self.assertIn(st, (401, 403))
            self.assertEqual(self.call(fn, method='GET')[0], 405)

    def test_sync_now_with_no_token_answers_in_place_and_calls_nothing(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_list_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        st, d = self.call(self.api.handle_edge_list_sync, {})
        self.assertEqual(st, 200, 'an answer the page can show, not an error status')
        self.assertEqual((d['result']['state'], d['result']['why']),
                         ('needs_setup', 'Add a Cloudflare token that can edit lists.'))
        self.assertEqual(self.cf, [])
        self.assertEqual([a for a in self.audit if a[1] == 'edge_list_sync'], [], 'nothing happened to audit')

    def test_the_token_is_written_never_read_back_and_never_audited(self):
        def save(**b):
            return self.call(self.api.handle_ip_intel_settings, b)
        st, d = save(edge_list_token='NEWlist_' + 'y' * 30)
        self.assertEqual(st, 200)
        self.assertTrue(d['settings']['edge_list_token_set'])
        self.assertNotIn('NEWlist_', json.dumps(d))
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['edge_list_token'], 'NEWlist_' + 'y' * 30)
        line = ' '.join(str(a) for a in self.audit[-1])
        self.assertIn('edge_list_token=set', line)
        self.assertNotIn('NEWlist_', line)
        self.assertTrue(self.api._is_config_secret_name('edge_list_token'))
        self.assertEqual(save(edge_list_token='short')[0], 400)
        save(clear_edge_list_token=True)
        self.assertNotIn('edge_list_token', self.api.load(self.api.CONFIG_FILE))

    def test_the_other_token_is_not_the_one_that_edits(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['edge_cloudflare_token'] = 'READtoken_' + 'r' * 30
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.tick()
        for c in self.cf:
            self.assertEqual(c['headers']['Authorization'], 'Bearer ' + TOKEN)

    def test_every_field_is_validated_and_clamped(self):
        def save(**b):
            return self.call(self.api.handle_ip_intel_settings, b)
        for bad in ({'edgelist_name': 'Bad Name'}, {'edgelist_name': '1abc'}, {'edgelist_always': '10.0.0.1'},
                    {'edgelist_always': '185.0.0.0/8'}, {'edgelist_always': 'hello'},
                    {'edgelist_hours': 'soon'}):
            self.assertEqual(save(**bad)[0], 400, bad)
        st, d = save(edgelist_hours=0, edgelist_max=5, edgelist_own_score=500, edgelist_abuseipdb_conf=1,
                     edgelist_sniffcat_conf=1, edgelist_always='185.220.101.7, 45.155.205.0/24 # a range')
        s = d['settings']
        self.assertEqual((s['edgelist_hours'], s['edgelist_max'], s['edgelist_own_score']), (1, 100, 100))
        self.assertEqual((s['edgelist_abuseipdb_conf'], s['edgelist_sniffcat_conf']), (25, 30))
        self.assertEqual(s['edgelist_always'], ['185.220.101.7', '45.155.205.0/24'])

    def test_the_page_payload_carries_the_blocklist_for_the_operator_only(self):
        self.tick()
        st, d = self.call(self.api.handle_ip_intel, method='GET')
        self.assertEqual(st, 200)
        self.assertTrue(d['edge_list']['enabled'])
        self.assertNotIn(TOKEN, json.dumps(d))
        st, d = self.call(self.api.handle_ip_intel, method='GET', role='viewer')
        self.assertIsNone(d.get('edge_list'))


if __name__ == '__main__':
    unittest.main()
