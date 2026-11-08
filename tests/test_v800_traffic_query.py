#!/usr/bin/env python3
"""8.0.0 (data binding): what the hosts talk to is a fleet question.

The Traffic tab answers it for a person looking at a page. The Data Explorer has a `traffic` entity now (one row for each host, direction, remote address, port and program of
each host's last sample) and Fleet Query has a **Talks to** criterion (the hosts that have a connection to an address part, a port or service, or a program). Both read the
stored samples the Traffic routes read, for the hosts the caller may see, and neither answers while the module is off: they are outside the /api/traffic prefix, so the gate
that 404s that prefix does not reach them and each has to ask for itself.

Driven through the real handlers: the real heartbeat stores the samples, the real query engine and the real dispatcher answer, and two organisations on one installation read each other's
names in none of it.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-traffic-query-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v800_traffic import LAN, PUB, PUB2, _Server, device, row, sample  # noqa: E402

import traffic as T  # noqa: E402


class _Fleet(_Server):

    def setUp(self):
        super().setUp()
        self.watch = [{'kind': 'ip', 'value': PUB, 'label': 'operator note'}, {'kind': 'port', 'value': '23', 'label': ''}]
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2'), 'old': device(id='old', name='old', token='t3'),
                  'win01': device(id='win01', name='win01', os='Windows 11', token='tokw'), 'sw': device(id='sw', name='sw', agentless=True),
                  'gone': device(id='gone', name='gone', decommissioned=True, token='t4'), 'idle': device(id='idle', name='idle', token='t5')},
                 traffic_module_enabled=True, traffic_watch=self.watch)
        self.beat('web01', 'tok', traffic=sample([row(proc='curl'), row(d='in', ip=LAN, port=22, proc='sshd', tx=10, rx=20)]))
        self.beat('web02', 't2', traffic=sample([row(ip=PUB2, port=53, proc='unbound', tx=1, rx=1)]))
        self.beat('old', 't3', traffic=sample([row(ip='9.9.9.9', port=853, proc='stubby')]))
        rec = self.stored('old')
        rec['at'] -= 7200                                                         # stopped reporting two hours ago
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'old', rec)
        self.beat('gone', 't4', traffic=sample([row(ip='7.7.7.7')]))              # a host that is retired keeps its row in the store

    def rows(self, where=None, token='k'):
        body = {'entity': 'traffic', 'sort': 'device_name'}
        if where:
            body['where'] = where
        st, out = self.request('/api/query', 'POST', token=token, body=body)
        self.assertEqual(st, 200, out)
        return out['rows']

    def talks(self, text, token='k'):
        st, out = self.request('/api/fleet/query', token=token, query='talks=' + text)
        self.assertEqual(st, 200, out)
        return sorted(d['name'] for d in out['devices'])


class TestTheExplorerEntity(_Fleet):

    def test_one_row_for_each_host_direction_address_port_and_program_of_the_last_sample(self):
        rows = self.rows()
        got = sorted((r['device_name'], r['direction'], r['address'], r['port'], r['program']) for r in rows)
        self.assertEqual(got, sorted([('web01', 'out', PUB, 443, 'curl'), ('web01', 'in', LAN, 22, 'sshd'), ('web02', 'out', PUB2, 53, 'unbound'), ('old', 'out', '9.9.9.9', 853, 'stubby')]))
        by = {(r['device_name'], r['address']): r for r in rows}
        r = by[('web01', PUB)]
        self.assertEqual((r['service'], r['scope'], r['connections'], r['sent'], r['received']), ('https', 'public', 1, 1000, 5000))
        self.assertEqual((by[('web01', LAN)]['scope'], by[('web01', LAN)]['service']), ('private', 'ssh'))

    def test_the_population_is_not_empty(self):
        """Control: every comparison here passes against an empty row set."""
        self.assertGreaterEqual(len(self.rows()), 4)

    def test_only_hosts_that_have_a_sample_are_listed_and_a_host_that_stopped_says_so(self):
        names = {r['device_name'] for r in self.rows()}
        self.assertEqual(names, {'web01', 'web02', 'old'}, 'no row for a host that is waiting, not Linux, agentless or retired')
        self.assertEqual({r['state'] for r in self.rows() if r['device_name'] == 'old'}, {'stale'})
        self.assertEqual({r['state'] for r in self.rows() if r['device_name'] == 'web01'}, {'reporting'})

    def test_a_row_says_whether_a_watch_list_entry_matches_and_never_which_one(self):
        by = {(r['device_name'], r['address']): r for r in self.rows()}
        self.assertIs(by[('web01', PUB)]['watched'], True)
        self.assertIs(by[('web02', PUB2)]['watched'], False)
        for r in self.rows():
            self.assertFalse({'label', 'entry', 'value', 'kind'} & set(r), 'the entries and their notes are the operator\'s')
        self.assertNotIn('operator note', json.dumps(self.rows()))

    def test_a_row_says_whether_the_address_is_new_for_that_host(self):
        rec = self.stored('web02')
        rec['first'] -= T.LEARN_S + 100
        rec['seen'] = {PUB2: rec['first'] + T.LEARN_S + 50}
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web02', rec)
        by = {(r['device_name'], r['address']): r for r in self.rows()}
        self.assertIs(by[('web02', PUB2)]['new'], True)
        self.assertIs(by[('web01', PUB)]['new'], False)

    def test_a_predicate_and_a_sort_run_on_the_rows(self):
        out = self.rows({'and': [{'field': 'port', 'op': 'eq', 'value': 443}]})
        self.assertEqual([(r['device_name'], r['port']) for r in out], [('web01', 443)])
        out = self.rows({'and': [{'field': 'watched', 'op': 'eq', 'value': True}]})
        self.assertEqual([r['address'] for r in out], [PUB])
        st, body = self.request('/api/query', 'POST', body={'entity': 'traffic', 'where': {'and': [{'field': 'label', 'op': 'eq', 'value': 'x'}]}})
        self.assertEqual(st, 400, 'the operator\'s note is not a field to ask about')

    def test_a_viewer_reads_the_same_rows_as_an_administrator_and_a_stranger_reads_none(self):
        self.assertEqual(len(self.rows(token='v')), len(self.rows(token='k')))
        st, _ = self.request('/api/query', 'POST', token='nobody', body={'entity': 'traffic'})
        self.assertEqual(st, 401)


class TestTheCriterion(_Fleet):

    def test_an_address_part_a_port_a_service_and_a_program_each_find_the_hosts(self):
        self.assertEqual(self.talks('93.184'), ['web01'])
        self.assertEqual(self.talks('8.8.8'), ['web02'])
        self.assertEqual(self.talks('443'), ['web01'])
        self.assertEqual(self.talks('https'), ['web01'])
        self.assertEqual(self.talks('dns'), ['web02'], 'the service name of port 53')
        self.assertEqual(self.talks('CURL'), ['web01'], 'any case')
        self.assertEqual(self.talks('sshd'), ['web01'])
        self.assertEqual(self.talks('stubby'), ['old'], 'a host that stopped reporting still has its last sample')

    def test_a_port_is_matched_whole_so_443_is_not_8443_or_a_part_of_an_address(self):
        self.beat('web02', 't2', traffic=sample([row(ip='10.44.3.1', port=8443)]))
        self.assertEqual(self.talks('443'), ['web01'])
        self.assertEqual(self.talks('8443'), ['web02'])

    def test_nothing_matches_what_nobody_talks_to_and_an_empty_criterion_is_no_criterion(self):
        self.assertEqual(self.talks('203.0.113.99'), [])
        self.assertEqual(self.talks('7.7.7.7'), [], 'a retired host is not a host of the fleet')
        st, out = self.request('/api/fleet/query', query='talks=')
        self.assertEqual(st, 200)
        self.assertGreaterEqual(len(out['devices']), 5, 'with no criterion the question is not asked')

    def test_it_composes_with_the_other_criteria(self):
        st, out = self.request('/api/fleet/query', query='talks=93.184&os=ubuntu')
        self.assertEqual(sorted(d['name'] for d in out['devices']), ['web01'])
        st, out = self.request('/api/fleet/query', query='talks=93.184&os=windows')
        self.assertEqual(out['devices'], [], 'the host talks to the address, and is not a Windows host')


class TestWhileTheModuleIsOff(_Fleet):

    def setUp(self):
        super().setUp()
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, traffic_watch=self.watch)      # the module switch is off by default

    def test_the_stored_rows_are_not_answered(self):
        self.assertIsNotNone(self.stored('web01'), 'the rows are still stored')
        st, out = self.request('/api/query', 'POST', body={'entity': 'traffic'})
        self.assertEqual(st, 400)
        self.assertIn('unknown entity', out['error'])
        self.assertNotIn('traffic', out['error'].split('Choose from:')[1], 'the entity is not offered either')

    def test_the_loader_gives_nothing_even_when_something_other_than_the_query_route_calls_it(self):
        loader, _fields = self.api._QE_ENTITIES['traffic']
        self.assertEqual(loader(), [], 'saved queries, the MCP tools and the next caller go around the entity-name check')
        self.put({'web01': device()}, traffic_module_enabled=True)
        self.assertTrue(loader(), 'control: the same loader answers once the module is on')

    def test_the_entity_is_not_listed_and_comes_back_when_the_module_is_on(self):
        st, out = self.request('/api/query/fields')
        self.assertEqual(st, 200)
        self.assertNotIn('traffic', out['entities'])
        self.assertIn('apps', out['entities'], 'control: the others are listed')
        self.put({'web01': device()}, traffic_module_enabled=True)
        st, out = self.request('/api/query/fields')
        self.assertIn('traffic', out['entities'])
        self.assertIn('address', out['entities']['traffic'])
        self.assertNotIn('label', out['entities']['traffic'])

    def test_a_saved_query_cannot_name_the_entity_and_the_criterion_finds_no_host(self):
        st, out = self.request('/api/query/templates', 'POST', body={'name': 'talkers', 'entity': 'traffic', 'where': {'and': [{'field': 'port', 'op': 'eq', 'value': 443}]}})
        self.assertEqual((st, 'unknown entity' in out.get('error', '')), (400, True))
        self.assertEqual(self.talks('93.184'), [], 'with the module off the stored rows are not read')
        self.put({'web01': device()}, traffic_module_enabled=True)
        self.assertEqual(self.talks('93.184'), ['web01'])


class TestTenants(_Server):
    """Two organisations on one installation: only the caller's own hosts are in the rows and in the answer, whatever the question."""

    def setUp(self):
        super().setUp()
        self.api.verify_token = lambda token: {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin'), 'tv': ('vic', 'viewer')}.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: {'alice': 'acme', 'bob': 'globex', 'root': 'default', 'vic': 'acme'}[user]
        self.put({'web01': device(tenant='acme'), 'web02': device(id='web02', name='web02', token='t2', tenant='globex')},
                 traffic_module_enabled=True, tenancy_enforced=True, traffic_watch=[{'kind': 'port', 'value': '443', 'label': 'operator note'}])
        self.beat('web01', 'tok', traffic=sample([row(ip='9.9.9.1', proc='acme-app')]))
        self.beat('web02', 't2', traffic=sample([row(ip='9.9.9.2', proc='globex-app')]))

    def test_the_explorer_rows_are_the_callers_own_and_the_operators_are_everyones(self):
        for tok, mine, other in (('ta', 'web01', '9.9.9.2'), ('tb', 'web02', '9.9.9.1'), ('tv', 'web01', '9.9.9.2')):
            st, out = self.request('/api/query', 'POST', token=tok, body={'entity': 'traffic'})
            self.assertEqual(st, 200, out)
            self.assertEqual({r['device_name'] for r in out['rows']}, {mine}, tok)
            self.assertNotIn(other, json.dumps(out), tok)
            self.assertNotIn('operator note', json.dumps(out), tok)
        st, out = self.request('/api/query', 'POST', token='op', body={'entity': 'traffic'})
        self.assertEqual({r['device_name'] for r in out['rows']}, {'web01', 'web02'})

    def test_the_criterion_never_finds_another_organisations_host(self):
        for tok, own, other in (('ta', 'web01', 'globex-app'), ('tb', 'web02', 'acme-app')):
            st, out = self.request('/api/fleet/query', token=tok, query='talks=' + other)
            self.assertEqual((st, out['devices']), (200, []), tok)
            st, out = self.request('/api/fleet/query', token=tok, query='talks=9.9.9.')
            self.assertEqual([d['name'] for d in out['devices']], [own], tok)
        st, out = self.request('/api/fleet/query', token='op', query='talks=9.9.9.')
        self.assertEqual(sorted(d['name'] for d in out['devices']), ['web01', 'web02'])


if __name__ == '__main__':
    unittest.main()
