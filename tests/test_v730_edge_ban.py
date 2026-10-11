"""A ban by hand: one address, at the edge and on hosts (v7.3.0).

Driven through the real endpoints and the real sweep, against the in-memory
Cloudflare Lists API the blocklist tests use. What matters here is what the button
can do to somebody's account and fleet: it needs the right to do each half, it
never touches an address that is theirs, a host rule goes only to Linux agents the
caller can see, an expired ban leaves the list on time, and the list marker says
only what the last sync did.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v730_edge_blocklist_sync import OFFICE, T, _Lists, ips  # noqa: E402

import ip_intel  # noqa: E402

BAD = '185.220.101.50'
OTHER = '45.155.205.7'
HOUR = 3600


class _Bans(_Lists):
    def setUp(self):
        super().setUp()
        api = self.api
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': '10.0.0.5', 'public_ip': OFFICE,
                   'group': 'web'},
            'd2': {'name': 'web02', 'os': 'Debian 12', 'token': 't', 'ip': '10.0.0.6', 'group': 'web'},
            'd3': {'name': 'db01', 'os': 'Ubuntu 22.04', 'token': 't', 'ip': '10.0.0.7', 'group': 'db'},
            'd4': {'name': 'win01', 'os': 'Windows 11', 'token': 't', 'ip': '10.0.0.8'},
            'd5': {'name': 'snmp1', 'os': 'Linux', 'token': 't', 'agentless': True},
        })
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'web-op', 'permissions': ['command'], 'scope': {'type': 'groups', 'values': ['web']}}]})
        st = api.load(api.IPINTEL_FILE) or {}
        st['attackers'] = {
            BAD: {'first_seen': T - 900, 'last_seen': T - 10, 'verdict': {'score': 40},
                  'devices': {'d1': {'count': 30, 'at': T - 10}, 'edge:cloudflare': {'count': 3, 'at': T - 10}}},
        }
        api.save(api.IPINTEL_FILE, st)
        # AbuseIPDB offers other addresses and not BAD, so only the ban can put BAD in
        # the list, and taking it out leaves a list that is not empty (an emptied list is
        # held by the guard, which TestLiftingIt checks separately)
        self.abuse, self.sniff = ips('203.9', 6), []
        api._LOAD_CACHE.clear()

    def store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IPINTEL_FILE) or {}

    def queue(self, dev):
        self.api._LOAD_CACHE.clear()
        return [c if isinstance(c, str) else c.get('command', '')
                for c in (self.api.load(self.api.CMDS_FILE) or {}).get(dev, [])]

    def ban(self, **body):
        body.setdefault('ip', BAD)
        return self.call(self.api.handle_ip_intel_ban, body, role=body.pop('_role', 'admin'),
                         at=body.pop('_at', T))

    def unban(self, **body):
        body.setdefault('ip', BAD)
        return self.call(self.api.handle_ip_intel_unban, body, role=body.pop('_role', 'admin'),
                         at=body.pop('_at', T))


class TestBanAtTheEdge(_Bans):
    def test_it_goes_in_the_list_at_once_and_the_address_is_marked(self):
        self.tick()                      # a sync has just run, so the schedule is hours from due
        self.assertNotIn(BAD, self.only_list()['items'])
        st, d = self.ban(edge=True, hours=24, _at=T + 60)
        self.assertEqual(st, 200, d)
        self.assertEqual(d['edge']['state'], 'ok')
        self.assertEqual(d['until'], T + 60 + 24 * HOUR)
        self.assertIn(BAD, self.only_list()['items'])
        att = self.store()['attackers'][BAD]
        self.assertEqual(att['in_list'], T + 60)
        self.assertEqual(self.store()['edgeban'][BAD]['by'], 'alice')
        # and the page can say so, to the operator
        st, page = self.call(self.api.handle_ip_intel, method='GET')
        row = next(a for a in page['attackers'] if a['ip'] == BAD)
        self.assertEqual(row['in_list'], T + 60)
        self.assertEqual(row['edge_ban'], {'until': T + 60 + 24 * HOUR})
        self.assertEqual(page['edge_list']['bans'], 1)

    def test_the_list_comment_says_it_is_the_operators_own(self):
        self.ban(edge=True)
        import json
        puts = [c for c in self.cf if c['method'] == 'PUT' and c['url'].endswith('/items')]
        body = json.loads(puts[-1]['body'])
        self.assertEqual({x['ip']: x['comment'] for x in body}[BAD], 'RemotePower: always')

    def test_it_will_not_ban_what_is_theirs(self):
        for ip in (OFFICE, '10.0.0.5', '104.16.0.1', '127.0.0.1'):
            st, d = self.ban(ip=ip, edge=True)
            self.assertEqual(st, 409, ip)
            self.assertIn('Not banning', d['error'])
        self.assertNotIn('edgeban', self.store())
        self.assertEqual(self.writes(), [], 'nothing reached Cloudflare')

    def test_a_never_block_range_covers_it(self):
        self.policy(never_block=['185.220.101.0/24'])
        st, d = self.ban(edge=True)
        self.assertEqual(st, 409)
        self.assertIn('never-block', d['error'])

    def test_a_bad_address_is_refused(self):
        for ip in ('', 'hello', '185.220.101.0/24', '999.1.1.1'):
            self.assertEqual(self.ban(ip=ip, edge=True)[0], 400, ip)

    def test_it_needs_the_blocklist_to_be_on_with_a_token(self):
        self.policy(edgelist_enabled=False)
        st, d = self.ban(edge=True)
        self.assertEqual(st, 409)
        self.assertIn('Edge blocklist is off', d['error'])
        self.policy(edgelist_enabled=True)
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg.pop('edge_list_token')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        st, d = self.ban(edge=True)
        self.assertEqual(st, 409)
        self.assertIn('token', d['error'])
        self.assertNotIn('edgeban', self.store(), 'a ban that cannot take effect is not stored')

    def test_a_list_that_is_not_ours_keeps_the_ban_waiting(self):
        self.new_list(name='my_list', description='Managed by someone else', items=ips('203.9', 5))
        st, d = self.ban(edge=True)
        self.assertEqual(st, 200)
        self.assertEqual(d['edge']['state'], 'needs_adopt')
        self.assertEqual(self.writes(), [])
        self.assertIn(BAD, self.store()['edgeban'], 'stored, and applied when the list is taken over')

    def test_only_the_operator_may_ban_at_the_edge(self):
        for role in ('viewer', 'web-op'):
            st, d = self.ban(edge=True, _role=role)
            self.assertEqual(st, 403, role)
        self.assertNotIn('edgeban', self.store())

    def test_on_a_multi_tenant_install_only_the_platform_operator(self):
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        st, d = self.ban(edge=True)
        self.assertEqual(st, 403)
        self.api._caller_is_superadmin = lambda: True
        self.assertEqual(self.ban(edge=True)[0], 200)

    def test_a_repeat_ban_extends_it_and_adds_no_second_entry(self):
        self.ban(edge=True, hours=1)
        self.ban(edge=True, hours=48, _at=T + 60)
        self.assertEqual(self.store()['edgeban'][BAD]['until'], T + 60 + 48 * HOUR)
        self.assertEqual(self.only_list()['items'].count(BAD), 1)

    def test_hours_are_bounded(self):
        st, d = self.ban(edge=True, hours=10 ** 6)
        self.assertEqual(d['until'], T + 24 * 90 * HOUR)
        st, d = self.ban(edge=True, hours='soon')
        self.assertEqual(d['until'], T + int(self.api.ip_intel_policy()['block_ttl_hours']) * HOUR)


class TestBanOnHosts(_Bans):
    def test_the_hosts_that_saw_it(self):
        st, d = self.ban(hosts='seen')
        self.assertEqual(st, 200, d)
        self.assertEqual(d['hosts']['queued'], 1)
        self.assertEqual(d['hosts']['matched'], 1)
        cmd = self.queue('d1')
        self.assertEqual(len(cmd), 1)
        self.assertEqual(cmd[0], 'exec:' + ip_intel.block_command(BAD))
        for other in ('d2', 'd3', 'd4', 'd5'):
            self.assertEqual(self.queue(other), [], other)
        blk = self.store()['blocks']['d1'][BAD]
        self.assertEqual((blk['kind'], blk['until'], blk['by']), ('manual', T + 24 * HOUR, 'alice'))

    def test_every_linux_agent_and_nothing_else(self):
        st, d = self.ban(hosts='all')
        self.assertEqual(d['hosts']['queued'], 3)
        self.assertEqual({k for k in ('d1', 'd2', 'd3', 'd4', 'd5') if self.queue(k)}, {'d1', 'd2', 'd3'})

    def test_a_list_of_ids_skips_what_cannot_take_a_rule(self):
        st, d = self.ban(hosts=['d1', 'd4', 'd5', 'not-a-device'])
        # the Windows host, the agentless one and the id that is no device at all
        self.assertEqual((d['hosts']['queued'], d['hosts']['skipped']), (1, 3))
        self.assertEqual(self.queue('d4'), [])
        self.assertEqual(self.queue('d5'), [])

    def test_it_does_not_ban_what_is_theirs_on_a_host_either(self):
        st, d = self.ban(ip=OFFICE, hosts='all')
        self.assertEqual(st, 409)
        self.assertEqual([self.queue(k) for k in ('d1', 'd2', 'd3')], [[], [], []])

    def test_a_repeat_extends_the_block_and_queues_nothing_more(self):
        self.ban(hosts='seen', hours=1)
        st, d = self.ban(hosts='seen', hours=72, _at=T + 120)
        self.assertEqual((d['hosts']['queued'], d['hosts']['extended']), (0, 1))
        self.assertEqual(len(self.queue('d1')), 1)
        self.assertEqual(self.store()['blocks']['d1'][BAD]['until'], T + 120 + 72 * HOUR)

    def test_a_host_that_refuses_is_named_and_not_recorded(self):
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['d2']['quarantined'] = True
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()
        st, d = self.ban(hosts='all')
        self.assertEqual(d['hosts']['queued'], 2)
        self.assertEqual([(f['device_id'], f['name']) for f in d['hosts']['failed']], [('d2', 'web02')])
        self.assertIn('quarantined', d['hosts']['failed'][0]['error'])
        self.assertNotIn('d2', self.store().get('blocks', {}))

    def many_hosts(self, n):
        devs = {f'm{i}': {'name': f'm{i}', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': f'10.2.0.{i + 1}'}
                for i in range(n)}
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()
        return sorted(devs)

    def test_the_record_is_written_before_the_commands_so_a_crash_leaves_it(self):
        """A request that dies half way must leave a record for every rule that may
        exist: the expiry sweep lifts those, and nothing is left on a host that no
        record remembers."""
        ids = self.many_hosts(6)
        mod = self.api.edge_blocklist_handlers_mod
        mod.BAN_CHUNK = 2
        real = self.api._queue_command_batch
        calls = []

        def dies_on_the_second_step(dev_ids, cmd, actor):
            calls.append(list(dev_ids))
            if len(calls) == 2:
                raise RuntimeError('worker killed')
            return real(dev_ids, cmd, actor)
        self.api._queue_command_batch = dies_on_the_second_step
        try:
            with self.assertRaises(RuntimeError):
                self.ban(hosts='all')
        finally:
            self.api._queue_command_batch = real
            mod.BAN_CHUNK = 20
        self.assertEqual(sorted(self.store()['blocks']), ids, 'every host has a record')

    def test_a_budget_stops_new_steps_and_forgets_what_was_not_reached(self):
        ids = self.many_hosts(7)
        mod = self.api.edge_blocklist_handlers_mod
        mod.BAN_CHUNK = 3
        ticks = iter([0, 100, 200, 300])          # the second step starts after the budget
        real = mod._mono
        mod._mono = lambda: next(ticks)
        try:
            st, d = self.ban(hosts='all')
        finally:
            mod._mono = real
            mod.BAN_CHUNK = 20
        self.assertEqual(st, 200)
        self.assertEqual((d['hosts']['queued'], d['hosts']['deferred'], d['hosts']['matched']), (3, 4, 7))
        self.assertEqual([k for k in ids if self.queue(k)], ids[:3])
        self.assertEqual(sorted(self.store()['blocks']), ids[:3], 'what was not reached has no record')
        # asking again finishes the rest and extends the first three
        ticks2 = iter(range(0, 1000, 1))
        mod._mono = lambda: next(ticks2)
        try:
            st, d = self.ban(hosts='all', _at=T + 30)
        finally:
            mod._mono = real
        self.assertEqual((d['hosts']['queued'], d['hosts']['extended'], d['hosts']['deferred']), (4, 3, 0))
        self.assertEqual(sorted(self.store()['blocks']), ids)

    def test_four_eyes_parks_each_host_and_says_so(self):
        self.api._needs_approval = lambda kind, cfg=None: True
        self.api._park_for_approval = lambda *a, **k: 'conf-1'
        st, d = self.ban(hosts='all')
        self.assertEqual((d['hosts']['queued'], d['hosts']['approval']), (0, 3))
        self.assertEqual([self.queue(k) for k in ('d1', 'd2', 'd3')], [[], [], []], 'nothing runs before approval')
        self.assertEqual(set(self.store()['blocks']), {'d1', 'd2', 'd3'})

    def test_a_role_is_confined_to_its_scope(self):
        st, d = self.ban(hosts='all', _role='web-op')
        self.assertEqual(st, 200)
        self.assertEqual({k for k in ('d1', 'd2', 'd3') if self.queue(k)}, {'d1', 'd2'}, 'db01 is outside web')
        st, d = self.ban(ip=OTHER, hosts=['d3'], _role='web-op')
        self.assertEqual((d['hosts']['queued'], d['hosts']['skipped']), (0, 1))
        self.assertEqual(self.queue('d3'), [])

    def test_a_role_without_the_command_permission_cannot(self):
        st, d = self.ban(hosts='all', _role='viewer')
        self.assertEqual(st, 403)
        self.assertEqual(self.queue('d1'), [])

    def test_a_tenant_never_reaches_another_tenants_hosts(self):
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['d2']['tenant'] = 't2'
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()
        self.api._tenant_filter_devices = lambda ds: {k: v for k, v in ds.items() if v.get('tenant') != 't2'}
        st, d = self.ban(hosts='all')
        self.assertEqual(d['hosts']['queued'], 2)
        self.assertEqual(self.queue('d2'), [])

    def test_both_at_once(self):
        st, d = self.ban(edge=True, hosts='seen')
        self.assertEqual(st, 200)
        self.assertEqual((d['edge']['state'], d['hosts']['queued']), ('ok', 1))
        self.assertIn(BAD, self.only_list()['items'])
        self.assertEqual(len(self.queue('d1')), 1)

    def test_it_must_name_a_place(self):
        self.assertEqual(self.ban()[0], 400)
        self.assertEqual(self.ban(hosts='nobody')[0], 400)

    def test_method_and_authentication(self):
        api = self.api
        self.assertEqual(self.call(api.handle_ip_intel_ban, {'ip': BAD, 'edge': True}, method='GET')[0], 405)
        api.verify_token = lambda _t=None: (None, None)
        self.cap.clear()
        try:
            api.get_json_obj = lambda: {'ip': BAD, 'edge': True}
            api.method = lambda: 'POST'
            api.handle_ip_intel_ban()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 401)
        self.assertNotIn('edgeban', self.store())

    def test_the_audit_line_names_the_action_and_no_secret(self):
        self.ban(edge=True, hosts='all', hours=6)
        line = ' '.join(str(x) for x in next(a for a in self.audit if a[1] == 'ip_intel_ban'))
        self.assertIn('ip=%s' % BAD, line)
        self.assertIn('edge=1', line)
        self.assertIn('hosts=3', line)
        self.assertNotIn('LISTtoken', line)


class TestLiftingIt(_Bans):
    def test_the_edge_ban_comes_out_of_the_list(self):
        self.ban(edge=True)
        self.assertIn(BAD, self.only_list()['items'])
        st, d = self.unban(edge=True, _at=T + 30)
        self.assertEqual(st, 200, d)
        self.assertTrue(d['edge']['removed'])
        self.assertNotIn(BAD, self.only_list()['items'])
        self.assertNotIn('in_list', self.store()['attackers'][BAD])
        self.assertNotIn(BAD, self.store().get('edgeban', {}))

    def test_removing_the_last_entry_is_held_like_any_emptying_sync(self):
        self.abuse = []
        self.ban(edge=True)
        st, d = self.unban(edge=True, _at=T + 30)
        self.assertEqual(d['edge']['state'], 'held')
        self.assertEqual(d['edge']['why'], 'Nothing would be left in the list.')
        self.assertIn(BAD, self.only_list()['items'], 'it stays until the operator says Sync anyway')

    def test_an_address_another_source_names_stays_listed(self):
        self.abuse = [BAD] + ips('203.9', 6)
        self.ban(edge=True)
        self.unban(edge=True, _at=T + 30)
        self.assertIn(BAD, self.only_list()['items'], 'AbuseIPDB still offers it')
        self.assertIn('in_list', self.store()['attackers'][BAD])

    def test_every_host_block_is_lifted_and_recorded_as_such(self):
        self.ban(hosts='all')
        st, d = self.unban(hosts='all', _at=T + 30)
        self.assertEqual(d['hosts']['lifted'], 3)
        unblock = 'exec:' + ip_intel.unblock_command(BAD)
        self.assertTrue(all(unblock in self.queue(k) for k in ('d1', 'd2', 'd3')))
        self.assertEqual(self.store().get('blocks', {}), {})

    def test_a_scoped_role_lifts_only_its_own_hosts(self):
        self.ban(hosts='all')
        st, d = self.unban(hosts='all', _role='web-op', _at=T + 30)
        self.assertEqual(d['hosts']['lifted'], 2)
        self.assertEqual(set(self.store()['blocks']), {'d3'})

    def test_lifting_what_was_never_set_is_quiet(self):
        st, d = self.unban(edge=True, hosts='all')
        self.assertEqual(st, 200)
        self.assertFalse(d['edge']['removed'])
        self.assertEqual(d['hosts']['lifted'], 0)
        self.assertEqual(self.writes(), [])


class TestExpiryAndTheMarker(_Bans):
    def test_an_expired_ban_leaves_the_list_without_waiting_for_the_schedule(self):
        self.ban(edge=True, hours=1)
        self.assertIn(BAD, self.only_list()['items'])
        # 61 minutes on: the 6-hour schedule is nowhere near due, the ban has run out
        self.tick(at=T + HOUR + 60)
        self.assertNotIn(BAD, self.only_list()['items'])
        self.assertNotIn(BAD, self.store().get('edgeban', {}), 'and the store forgets it')
        self.assertNotIn('in_list', self.store()['attackers'][BAD])

    def test_a_live_ban_does_not_make_the_sweep_run_early(self):
        self.ban(edge=True, hours=24)
        n = len(self.cf)
        self.tick(at=T + 600)
        self.assertEqual(len(self.cf), n)

    def test_addresses_other_sources_list_are_marked_too(self):
        self.abuse = [OTHER]
        st = self.store()
        st['attackers'][OTHER] = {'first_seen': T - 5, 'last_seen': T - 5, 'devices': {'d2': {'count': 9, 'at': T - 5}},
                                  'verdict': {'score': 10}}
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.tick()
        att = self.store()['attackers']
        self.assertEqual(att[OTHER]['in_list'], T)
        self.assertNotIn('in_list', att[BAD])

    def test_a_range_the_operator_listed_marks_what_is_inside_it(self):
        self.policy(edgelist_always=['185.220.0.0/16'])
        self.tick()
        self.assertIn('in_list', self.store()['attackers'][BAD])

    def test_a_held_sync_leaves_the_markers_as_they_were(self):
        self.ban(edge=True, hours=24 * 30)
        self.assertIn('in_list', self.store()['attackers'][BAD])
        # the ban is gone from the store while Cloudflare still holds the address, as
        # when the operator lifts it and the sync that follows is held
        st = self.store()
        st['edgeban'] = {}
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.abuse_status = 500                  # a source fails, and its copy is over three days old
        self.tick(at=T + 4 * 86400)
        self.assertEqual(self.store()['edgelist']['last']['state'], 'held')
        self.assertIn('in_list', self.store()['attackers'][BAD], 'nothing changed in Cloudflare, so nothing changes here')

    def test_a_preview_marks_nothing(self):
        st = self.store()
        st.setdefault('edgeban', {})[BAD] = {'at': T, 'until': T + 10 * HOUR, 'by': 'alice'}
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.call(self.api.handle_edge_list_preview, {})
        self.assertNotIn('in_list', self.store()['attackers'][BAD])
        self.assertEqual(self.writes(), [], 'a preview writes nothing to Cloudflare')

    def test_the_marker_is_for_the_operator_only(self):
        self.ban(edge=True)
        st, page = self.call(self.api.handle_ip_intel, method='GET', role='viewer')
        self.assertEqual(st, 200)
        for row in page['attackers']:
            self.assertIsNone(row['in_list'])
            self.assertIsNone(row['edge_ban'])
        self.assertIsNone(page['edge_list'])

    def test_the_dialog_is_told_how_many_hosts_all_means(self):
        st, page = self.call(self.api.handle_ip_intel, method='GET')
        self.assertEqual(page['ban_hosts'], 3, 'd1, d2 and d3: the Windows host and the agentless one do not count')


if __name__ == '__main__':
    unittest.main()
