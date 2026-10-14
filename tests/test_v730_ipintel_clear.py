"""Clearing what Threat intel has recorded, and the flood that asked for it (v7.3.0).

The store behind the Threat intel page is one document that every writer rewrites
whole, and it holds up to 5,000 addresses. Two questions came out of that. Does a
burst of attacking sources cost the heartbeat more than it should (it did: ten
seconds for forty sources at the cap, because the hook took one lock per source),
and what does a "Clear" button have to leave alone.

The second is the part that can do harm. A clear that took every row would have
dropped, at the Edge blocklist's next sync, each address the list takes from this
table, and would have made the next sighting of an address reported an hour ago
report it again. Both are pinned below with the real sweep and the real sync, and
every guard was shown red by mutation before this was committed.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-ipclear-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

from test_v730_edge_blocklist_sync import T, _Lists, ips  # noqa: E402

import edge_blocklist  # noqa: E402
import ip_intel  # noqa: E402

A1, A2, A3, A4, A5 = ('185.220.101.%d' % n for n in (11, 12, 13, 14, 15))
HOUR, DAY = 3600, 86400


def seen(*devs, at=T - 60, count=30):
    return {d: {'count': count, 'unit': 'sshd.service', 'at': at, 'not_blocked': 'score 10 is below 90'}
            for d in devs}


def att(devs, score=10, last=T - 60, **extra):
    a = {'first_seen': last - 600, 'last_seen': last, 'devices': devs,
         'verdict': {'score': score, 'country': 'DE'}, 'errors': {}}
    a.update(extra)
    return a


def queued(ip, dev, at=T - 5):
    return {'ip': ip, 'device_id': dev, 'unit': 'sshd.service', 'count': 30, 'window_s': 600, 'at': at}


class _Clear(_Lists):
    def setUp(self):
        super().setUp()
        api = self.api
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': '10.0.0.5', 'tenant': 't1'},
            'd2': {'name': 'web02', 'os': 'Debian 12', 'token': 't', 'ip': '10.0.0.6', 'tenant': 't2'},
        })
        api.save(api.ROLES_FILE, {'roles': [{'name': 'web-op', 'permissions': ['command']}]})
        self.abuse, self.sniff = ips('203.9', 6), []       # offered whatever the table holds
        api._LOAD_CACHE.clear()

    def put(self, **keys):
        api = self.api
        st = api.load(api.IPINTEL_FILE) or {}
        st.update(keys)
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()

    def store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IPINTEL_FILE) or {}

    def clear(self, role='admin', at=T, **body):
        return self.call(self.api.handle_ip_intel_clear, body, role=role, at=at)

    def view(self, role='admin'):
        return self.call(self.api.handle_ip_intel, method='GET', role=role)[1]

    def queue(self, dev):
        self.api._LOAD_CACHE.clear()
        return [c if isinstance(c, str) else c.get('command', '')
                for c in (self.api.load(self.api.CMDS_FILE) or {}).get(dev, [])]

    def sweep_at(self, at):
        api = self.api
        self.put(last_sweep=0)
        with mock.patch('time.time', return_value=at):
            api.run_ip_intel_if_due()
        return self.store()

    def note_at(self, at, dev, ip, count=40):
        with mock.patch('time.time', return_value=at):
            self.api.ip_intel_note_attack(dev, 'sshd.service', ip, count, 600)
        self.api._LOAD_CACHE.clear()

    def posts(self):
        return [c for c in self.calls if c['method'] == 'POST']


class TestWhatItClears(_Clear):
    def seed(self):
        self.put(
            attackers={A1: att(seen('d1')), A2: att(seen('d1', 'edge:cloudflare'), score=95),
                       A3: att(seen('d2')), A4: att(seen('edge:trap'))},
            queue=[queued(A1, 'd1'), queued(A3, 'd2'), queued(A4, 'edge:trap')],
            blocks={'d1': {A2: {'at': T - 100, 'until': T + DAY, 'score': 95, 'by': 'auto', 'kind': 'ssh'}}},
            edgeban={A2: {'at': T - 100, 'until': T + DAY, 'by': 'alice'}},
            sensors={'d1': {'at': T - 30, 'sources': [{'kind': 'web', 'path': '/var/log/nginx/access.log',
                                                      'state': 'ok', 'lines': 10, 'parsed': 10, 'events': 1}],
                            'events': 1, 'dropped': 0, 'throttled': 0, 'ignored': {}}},
            edge={'cf': {'state': 'ok', 'at': T - 300, 'rows': 4}, 'polled': T - 300},
            budget={'day': '2026-09-21', 'abuseipdb': 7, 'sniffcat': 7},
            last_sweep=T - 30)

    def test_it_forgets_what_is_recorded_and_what_is_waiting(self):
        self.seed()
        st, d = self.clear()
        self.assertEqual(st, 200, d)
        self.assertEqual((d['cleared'], d['queue'], d['kept_listed'], d['remembered']), (4, 3, 0, 0))
        after = self.store()
        self.assertEqual(after['attackers'], {})
        self.assertEqual(after['queue'], [])
        page = self.view()
        self.assertEqual((page['attackers'], page['attackers_total'], page['queued']), ([], 0, 0))

    def test_what_has_an_effect_of_its_own_is_left_alone(self):
        """Blocks, bans, the sensors' status, the feeds' place in their logs, the
        day's budget and the sweep's clock are not what the table records."""
        self.seed()
        before = self.store()
        self.clear()
        after = self.store()
        for key in ('blocks', 'edgeban', 'sensors', 'edge', 'budget', 'last_sweep'):
            self.assertEqual(after[key], before[key], key)
        rows = self.view()['blocks']
        self.assertEqual([(b['ip'], b['device_id']) for b in rows], [(A2, 'd1')])

    def test_a_block_still_expires_and_is_lifted_after_a_clear(self):
        """The reason blocks are not cleared: the sweep lifts them, and a rule
        left on a host that nothing remembers would stay for ever."""
        self.seed()
        self.put(blocks={'d1': {A2: {'at': T - 5 * HOUR, 'until': T - 10, 'score': 95, 'by': 'auto',
                                     'kind': 'ssh'}}})
        self.clear()
        self.sweep_at(T)
        self.assertNotIn('d1', self.store().get('blocks') or {})
        self.assertIn('exec:' + ip_intel.unblock_command(A2), self.queue('d1'))

    def test_the_sweep_does_not_bring_them_back(self):
        """Why the queue is cleared too: otherwise the next minute's sweep makes
        the same rows again and the button looks as though it did nothing."""
        self.seed()
        self.clear()
        self.assertEqual(self.sweep_at(T + 60).get('attackers'), {})

    def test_clearing_twice_is_harmless_and_says_so(self):
        self.seed()
        self.clear()
        st, d = self.clear()
        self.assertEqual(st, 200)
        self.assertEqual((d['cleared'], d['queue'], d['kept_listed'], d['remembered']), (0, 0, 0, 0))

    def test_the_audit_line_has_the_counts_and_nothing_else(self):
        self.seed()
        self.clear()
        line = ' '.join(str(x) for x in next(a for a in self.audit if a[1] == 'ip_intel_clear'))
        self.assertIn('cleared=4', line)
        self.assertIn('queue=3', line)
        self.assertNotIn(A1, line)


class TestWhatTheBlocklistTakes(_Clear):
    """The list is kept equal to its sources, and "found by RemotePower" is this
    table. A clear that took those rows would have shrunk the Cloudflare list at
    the next sync, which nobody asked for."""

    def seed(self):
        self.policy(edgelist_own=True, edgelist_own_score=75, edgelist_own_days=14)
        self.put(attackers={
            A1: att(seen('d1'), score=95),                                   # scores enough
            A2: att(seen('d1'), score=10, reported={'abuseipdb': T - HOUR}),  # was reported
            A3: att(seen('d1'), score=10),                                   # neither
            A4: att(seen('d1'), score=95, last=T - 30 * DAY),                # too old to count
        }, queue=[queued(A3, 'd1')])

    def own(self):
        return set(edge_blocklist.own_candidates(self.store()['attackers'], T, 75, 14))

    def test_the_rows_the_list_uses_stay_and_the_rest_go(self):
        self.seed()
        self.assertEqual(self.own(), {A1, A2})
        st, d = self.clear()
        self.assertEqual(st, 200, d)
        self.assertEqual((d['cleared'], d['kept_listed']), (2, 2))
        after = self.store()['attackers']
        self.assertEqual(set(after), {A1, A2})
        self.assertEqual(self.own(), {A1, A2}, 'the list would see the same candidates')

    def test_the_next_sync_makes_the_same_list(self):
        """Through the real sync, against the in-memory Cloudflare: the list a
        sync makes after a clear is the list it made before."""
        self.seed()
        self.tick(at=T)
        before = set(self.only_list()['items'])
        self.assertTrue({A1, A2} <= before, before)
        self.clear()
        self.tick(at=T + 7 * HOUR)               # past edgelist_hours, so it is due
        self.assertEqual(set(self.only_list()['items']), before)

    def test_without_the_blocklist_nothing_depends_on_the_table(self):
        self.seed()
        self.policy(edgelist_enabled=False)
        st, d = self.clear()
        self.assertEqual((d['cleared'], d['kept_listed']), (4, 0))
        # every row is gone; the one address reported an hour ago keeps only its date
        self.assertEqual(self.store()['attackers'], {A2: {'reported': {'abuseipdb': T - HOUR}}})

    def test_with_the_source_switched_off_nothing_depends_on_it_either(self):
        self.seed()
        self.policy(edgelist_own=False)
        self.assertEqual(self.clear()[1]['kept_listed'], 0)

    def test_without_a_token_the_list_cannot_write_so_nothing_is_kept(self):
        self.seed()
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_list_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.clear()[1]['kept_listed'], 0)


class TestNotReportedTwice(_Clear):
    """The date an address was last reported is what stops a second report. It
    lives in the row a clear removes, so the clear keeps it, for the day it
    counts and no longer."""

    def seed(self, told):
        self.policy(report_enabled=True, report_min_count=1, lookup_enabled=True)
        self.put(attackers={A1: att(seen('d1'), score=100, checked_at=T - HOUR,
                                    reported={'abuseipdb': told, 'sniffcat': told})})

    def test_a_report_made_an_hour_ago_is_remembered(self):
        self.seed(T - HOUR)
        st, d = self.clear()
        self.assertEqual((d['cleared'], d['remembered']), (1, 1))
        self.assertEqual(self.store()['attackers'][A1], {'reported': {'abuseipdb': T - HOUR, 'sniffcat': T - HOUR}})
        self.note_at(T + 60, 'd1', A1)
        self.sweep_at(T + 120)
        self.assertEqual(self.posts(), [], 'the address was reported again')

    def test_a_report_made_two_days_ago_is_not(self):
        """The control: the marker is what held the report back above."""
        self.seed(T - 2 * DAY)
        st, d = self.clear()
        self.assertEqual((d['cleared'], d['remembered']), (1, 0))
        self.assertNotIn(A1, self.store()['attackers'])
        self.note_at(T + 60, 'd1', A1)
        self.sweep_at(T + 120)
        self.assertEqual(len(self.posts()), 2, 'both services are told again after a day')

    def test_a_wait_a_service_asked_for_is_kept_while_it_lasts(self):
        self.seed(T - 2 * DAY)
        self.put(attackers={A1: att(seen('d1'), retry={'abuseipdb': T + 300, 'sniffcat': T - 5})})
        self.clear()
        self.assertEqual(self.store()['attackers'][A1], {'retry': {'abuseipdb': T + 300}})

    def test_a_marker_is_not_a_row(self):
        """It carries no host, so the page, the Data Explorer and the counts do not
        show it, and a second clear removes it once it has run out."""
        self.seed(T - HOUR)
        self.clear()
        page = self.view()
        self.assertEqual((page['attackers'], page['attackers_total']), ([], 0))
        self.assertEqual(self.api.ip_intel_handlers_mod.explorer_rows({'d1': {'name': 'web01'}}), [])
        st, d = self.clear(at=T + 2 * DAY)
        self.assertEqual(d['remembered'], 0)
        self.assertEqual(self.store()['attackers'], {})


class TestWhoseRowsTheyAre(_Clear):
    def seed(self):
        self.put(attackers={
            A1: att(seen('d1')),                      # tenant 1 only
            A2: att(seen('d2')),                      # tenant 2 only
            A3: att(seen('d1', 'd2')),                # both
            A4: att(seen('edge:cloudflare')),         # the platform's edge
        }, queue=[queued(A1, 'd1'), queued(A2, 'd2'), queued(A4, 'edge:cloudflare')])

    def tenanted(self, superadmin=False):
        api = self.api
        api._tenancy_enforced = lambda: True
        api._caller_is_superadmin = lambda: superadmin
        api._tenant_filter_devices = lambda ds: {k: v for k, v in ds.items() if v.get('tenant') == 't1'}

    def test_a_tenants_administrator_clears_only_what_their_hosts_saw(self):
        self.seed()
        self.tenanted()
        st, d = self.clear()
        self.assertEqual(st, 200, d)
        after = self.store()
        self.assertEqual(set(after['attackers']), {A2, A3, A4})
        self.assertEqual(set(after['attackers'][A3]['devices']), {'d2'}, 'the other tenant still saw it')
        self.assertEqual([q['device_id'] for q in after['queue']], ['d2', 'edge:cloudflare'])
        self.assertEqual((d['cleared'], d['queue']), (2, 1))

    def test_the_edge_is_the_platform_operators(self):
        self.seed()
        self.tenanted()
        self.clear()
        self.assertIn('edge:cloudflare', self.store()['attackers'][A4]['devices'])
        self.tenanted(superadmin=True)
        self.clear()
        after = self.store()
        self.assertEqual((after['attackers'], after['queue']), ({}, []))

    def test_an_unscoped_administrator_clears_everything_including_hosts_that_were_removed(self):
        self.put(attackers={A1: att(seen('gone-device'))}, queue=[queued(A1, 'gone-device')])
        st, d = self.clear()
        self.assertEqual((d['cleared'], d['queue']), (1, 1))
        self.assertEqual(self.store()['attackers'], {})

    def test_the_list_a_tenant_cannot_change_is_not_changed_by_their_clear(self):
        self.policy(edgelist_own=True, edgelist_own_score=75, edgelist_own_days=14)
        self.put(attackers={A1: att(seen('d1'), score=95)})
        self.tenanted()
        st, d = self.clear()
        self.assertEqual((d['cleared'], d['kept_listed']), (0, 1))
        self.assertIn(A1, self.store()['attackers'])


class TestWhoMayClear(_Clear):
    def test_only_an_administrator(self):
        self.put(attackers={A1: att(seen('d1'))})
        for role in ('viewer', 'web-op', 'auditor', 'finance'):
            st, _ = self.clear(role=role)
            self.assertEqual(st, 403, role)
        self.assertIn(A1, self.store()['attackers'])

    def test_not_anonymously_and_not_by_get(self):
        api = self.api
        self.put(attackers={A1: att(seen('d1'))})
        self.assertEqual(self.call(api.handle_ip_intel_clear, {}, method='GET')[0], 405)
        api.verify_token = lambda _t=None: (None, None)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {}
        self.cap.clear()
        try:
            api.handle_ip_intel_clear()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 401)
        self.assertIn(A1, self.store()['attackers'])

    def test_a_body_of_the_wrong_shape_is_not_a_server_error(self):
        api = self.api
        self.put(attackers={A1: att(seen('d1'))})
        for body in ({'x': [1, 2], 'y': {'z': 1}}, {'cleared': 'all'}):
            self.assertEqual(self.clear(**body)[0], 200)

    def test_it_is_in_the_route_table_as_a_post_only(self):
        api = self.api
        routes = api._build_exact_routes()
        self.assertIs(routes[('POST', '/api/ip-intel/clear')], api.handle_ip_intel_clear)
        self.assertEqual([k for k in routes if k[1] == '/api/ip-intel/clear'], [('POST', '/api/ip-intel/clear')])


class TestAFloodOfSources(_Clear):
    """What one heartbeat costs when many sources cross the threshold at once."""

    def burst(self, n, store_attackers=0):
        api = self.api
        api._brute_config = lambda: (True, 3, 600)
        if store_attackers:
            self.put(attackers={'45.%d.%d.%d' % (i // 60000, i // 250 % 240, i % 250 + 1): att(seen('d1'))
                                for i in range(store_attackers)})
        sources = ['185.220.%d.%d' % (101 + i // 200, i % 200 + 1) for i in range(n)]
        lines = ['Failed password for root from %s port 4%d ssh2' % (ip, j) for ip in sources for j in range(4)]
        real = api._LockedUpdate
        locks = []

        def counting(path, *a, **k):
            if path == api.IPINTEL_FILE:
                locks.append(1)
            return real(path, *a, **k)
        with mock.patch.object(api, '_LockedUpdate', counting):
            api._detect_brute_force('d1', 'web01', 'sshd.service', lines)
        api._LOAD_CACHE.clear()
        return len(locks), sources

    def test_a_burst_of_sources_is_one_write_of_the_store(self):
        locks, sources = self.burst(30)
        self.assertEqual(locks, 1, 'the store was rewritten once per source')
        self.assertEqual([q['ip'] for q in self.store()['queue']], sources)

    def test_the_same_burst_on_a_full_store_is_one_write_too(self):
        locks, _ = self.burst(30, store_attackers=300)
        self.assertEqual(locks, 1)
        self.assertEqual(len(self.store()['queue']), 30)

    def test_private_sources_are_still_left_out_of_the_batch(self):
        api = self.api
        api.ip_intel_note_attacks('d1', 'sshd.service',
                                  [('10.1.2.3', 30), ('host.example.com', 30), (A1, 30), ('', 5)], 600)
        self.assertEqual([q['ip'] for q in self.store()['queue']], [A1])

    def test_a_disabled_feature_queues_nothing(self):
        self.policy(lookup_enabled=False)
        self.api.ip_intel_note_attacks('d1', 'sshd.service', [(A1, 30)], 600)
        self.assertEqual(self.store().get('queue') or [], [])

    def test_a_flood_does_not_push_out_what_a_ban_engine_decided_on(self):
        """The sensor's path kept this rule; the brute-force path took the newest
        500 whatever they were, so forty new sources could push out an address
        fail2ban had banned a minute earlier."""
        api = self.api
        confirmed = {'ip': A5, 'device_id': 'd1', 'unit': 'threat-sensor', 'count': 3, 'window_s': 600,
                     'at': T - 1000,
                     'evidence': {'ip': A5, 'first': T - 1100, 'last': T - 1000, 'src': {'f2b': 3},
                                  'tok': {'f2b': {'jail:sshd': 3}}, 'ban': ['sshd'], 'ans': 0, 'blk': 0,
                                  'dec': 0, 'cve': []}}
        filler = [queued('45.1.%d.%d' % (i // 250, i % 250 + 1), 'd1', at=T - 900) for i in range(499)]
        self.put(queue=[confirmed] + filler)
        new = [('185.220.%d.%d' % (101 + i // 200, i % 200 + 1), 40) for i in range(25)]
        with mock.patch('time.time', return_value=T):
            api.ip_intel_note_attacks('d1', 'sshd.service', new, 600)
        q = self.store()['queue']
        self.assertEqual(len(q), 500)
        self.assertEqual(q[0]['ip'], A5, 'the address a ban engine decided on was pushed out')
        self.assertTrue({ip for ip, _n in new} <= {x['ip'] for x in q}, 'the new sources were dropped')


class TestTheCountTheListWasCutAt(_Clear):
    def fill(self, n):
        self.put(attackers={'66.%d.%d.%d' % (i // 60000, i // 250 % 240, i % 250 + 1):
                            att(seen('d1'), last=T - i) for i in range(n)})

    def test_more_than_a_page_says_how_many_there_are(self):
        self.fill(1200)
        page = self.view()
        self.assertEqual(len(page['attackers']), 1000)
        self.assertEqual(page['attackers_total'], 1200)
        stamps = [a['last_seen'] for a in page['attackers']]
        self.assertEqual(stamps, sorted(stamps, reverse=True), 'the page is the most recent')
        self.assertEqual(stamps[0], T)

    def test_a_short_list_says_its_own_length(self):
        self.fill(7)
        page = self.view()
        self.assertEqual((len(page['attackers']), page['attackers_total']), (7, 7))

    def rows_for(self, qs):
        with mock.patch.object(self.api, '_env', lambda k, d='': qs if k == 'QUERY_STRING' else d):
            return self.view()

    def test_a_larger_limit_returns_more_and_never_more_than_is_kept(self):
        self.fill(1300)
        self.assertEqual(len(self.rows_for('limit=1300')['attackers']), 1300)
        self.assertEqual(len(self.rows_for('limit=50')['attackers']), 50)
        with mock.patch.object(self.api.ip_intel_handlers_mod, 'ATTACKER_CAP', 1100):
            page = self.rows_for('limit=99999999')
        self.assertEqual((len(page['attackers']), page['attackers_total']), (1100, 1300))

    def test_a_limit_that_is_not_a_positive_number_is_the_default(self):
        self.fill(1200)
        for qs in ('limit=abc', 'limit=0', 'limit=-5', 'limit=', 'limit=1e400', 'other=1'):
            self.assertEqual(len(self.rows_for(qs)['attackers']), 1000, qs)

    def test_the_total_does_not_depend_on_the_limit(self):
        self.fill(1200)
        self.assertEqual(self.rows_for('limit=10')['attackers_total'], 1200)

    def test_the_total_is_what_the_caller_may_see(self):
        self.put(attackers={A1: att(seen('d1')), A2: att(seen('d2')), A3: att(seen('d2'))})
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        self.api._tenant_filter_devices = lambda ds: {k: v for k, v in ds.items() if v.get('tenant') == 't1'}
        page = self.view()
        self.assertEqual((len(page['attackers']), page['attackers_total']), (1, 1))


if __name__ == '__main__':
    unittest.main()
