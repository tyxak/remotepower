#!/usr/bin/env python3
"""Hardware in the Data Explorer: what the agents already report about each host, as an entity that is queried like the others.

The Data Explorer had `kernel`, `chassis`, `cpu_count`, `mem_total_mb` and `disk_total_gb` for a host and nothing about what the host IS: its maker and
model, its processor, its memory modules, its disks. The agents have reported all of that for a long time (the DMI or WMI record, the CPU model, the
modules, the SMART list, the graphics cards) and the host's Hardware tab shows it. The `hardware` entity has one row for each host the caller may see.

Driven through the real dispatcher and the real query handler, and held to:

  * the fields are the registry's and the rows carry exactly those, as scalars, for a host with data and for one with none;
  * "hosts by CPU model", "hosts by make and model", a sort, an `in` and an `exists` run through `/api/query`, the batch and a saved query;
  * a host that never reported hardware, or reported something of the wrong kind, is a row of empty cells and not an error;
  * the serial number is shown to exactly the callers the host's Hardware tab shows it to (checked role by role against the real endpoint), and when
    a rule hides it from a role, the query, the batch and a saved query all hide it, a condition on it finds nothing and a sort on it orders nothing;
  * the serial numbers of memory modules and disks are not in any row;
  * a tenant's administrator and a role scoped to a group read their own hosts and no others, whichever way the question comes in.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-explorer-hw-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from request_harness import RequestCase  # noqa: E402

NOW = int(time.time())

FIELDS = ['device_id', 'device_name', 'group', 'site', 'os', 'monitored', 'vendor', 'model', 'serial', 'chassis', 'cpu_model', 'cpu_count', 'mem_total_mb',
          'memory_modules', 'memory_installed_mb', 'memory_type', 'memory_speed', 'disk_total_gb', 'disk_count', 'disk_models', 'raid_arrays', 'gpu_count',
          'gpu_models', 'reported_at']


def dimm(slot, size='16 GB', kind='DDR4', speed='2933 MT/s', maker='Samsung'):
    return {'locator': slot, 'size': size, 'type': kind, 'speed': speed, 'manufacturer': maker, 'serial': 'DIMM-SERIAL-' + slot}


def host(name, tenant=None, group='dev', cpu=None, cores=None, mem=None, disk=None, chassis=None, **extra):
    si = {}
    for k, v in (('cpu', cpu), ('cpu_count', cores), ('mem_total_mb', mem), ('disk_total_gb', disk), ('chassis', chassis)):
        if v is not None:
            si[k] = v
    rec = {'name': name, 'group': group, 'os': 'Ubuntu 24.04', 'monitored': True, 'last_seen': NOW, 'sysinfo': si}
    if tenant:
        rec['tenant'] = tenant
    rec.update(extra)
    return rec


XEON = 'Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz'
DEVICES = {
    'web01': host('web01', 'acme', 'prod', XEON, 32, 64000, 960, 'server'),
    'web02': host('web02', 'acme', 'dev', XEON, 16, 32000, 480, 'server'),
    'lap01': host('lap01', 'acme', 'dev', 'Intel(R) Core(TM) i7-1185G7 @ 3.00GHz', 8, 16000, 512, 'laptop'),
    'mac01': host('mac01', 'acme', 'dev', 'Apple M2', 8, 16384, 494, 'laptop'),
    'bare01': host('bare01', 'acme', 'dev'),
    'g01': host('g01', 'globex', 'prod', XEON, 32, 64000, 960, 'server'),
}
HARDWARE = {
    'web01': {'hardware': {'system': {'manufacturer': 'Dell Inc.', 'product': 'PowerEdge R640', 'serial': 'SN-WEB01'},
                           'memory': [dimm('A1'), dimm('A2'), dimm('B1'), dimm('B2')], 'raid': [{'name': 'md0', 'level': 'raid1', 'state': 'clean', 'devices': 'sda sdb'}]},
              'smart': [{'device': '/dev/sda', 'model': 'Samsung SSD 860', 'serial': 'DISK-SERIAL-1', 'health': 'PASSED'},
                        {'device': '/dev/sdb', 'model': 'WDC WD40EFRX', 'serial': 'DISK-SERIAL-2', 'health': 'PASSED'}],
              'gpus': [{'vendor': 'nvidia', 'name': 'NVIDIA T4'}], 'ts': NOW - 600},
    'web02': {'hardware': {'system': {'manufacturer': 'Dell Inc.', 'product': 'PowerEdge R740', 'serial': 'SN-WEB02'},
                           'memory': [dimm('A1', '8 GB', 'DDR4', '2666 MT/s'), dimm('A2', '8192 MB', 'DDR4', '2666 MT/s')]},
              'smart': [], 'ts': NOW - 300},
    'lap01': {'hardware': {'system': {'manufacturer': 'LENOVO', 'product': 'ThinkPad T14 Gen 2', 'serial': 'PF-LAP01'}}, 'ts': NOW - 100},
    'g01': {'hardware': {'system': {'manufacturer': 'Dell Inc.', 'product': 'PowerEdge R640', 'serial': 'SN-GLOBEX'}}, 'ts': NOW - 50},
}
ROLE_TOKENS = ('k', 'v', 'mc', 'au', 'fi', 'ops', 'rw', 'ro')           # every kind of caller of the default tenant, the scoped one last


class _Fleet(RequestCase):

    def setUp(self):
        super().setUp()
        self.put(DEVICES)
        for dev_id, rec in HARDWARE.items():
            self.api._entity_write_one(self.api.HARDWARE_FILE, dev_id, rec)
        self.api._LOAD_CACHE.clear()

    def rows(self, where=None, token='k', **kw):
        body = {'entity': 'hardware', 'limit': 2000}
        if where:
            body['where'] = where
        body.update(kw)
        st, out = self.request('/api/query', 'POST', token=token, body=body)
        self.assertEqual(st, 200, out)
        return out['rows']

    def names(self, where=None, token='k', **kw):
        return [r['device_name'] for r in self.rows(where, token, **kw)]


class TestTheEntity(_Fleet):

    def test_it_is_listed_with_the_fields_of_the_registry(self):
        st, out = self.request('/api/query/fields')
        self.assertEqual(st, 200, out)
        self.assertEqual(sorted(out['entities']['hardware']), sorted(FIELDS))
        self.assertIn('hardware', self.api._qe_entity_names())
        self.assertEqual(sorted(self.api._QE_HARDWARE_FIELDS), sorted(FIELDS))

    def test_the_population_is_not_empty(self):
        """Control: every comparison below passes against an empty row set."""
        self.assertEqual(sorted(self.names()), sorted(DEVICES))

    def test_a_row_carries_exactly_the_fields_as_scalars_for_a_host_with_data_and_for_one_without(self):
        for r in self.rows():
            self.assertEqual(sorted(r), sorted(FIELDS), r['device_name'])
            bad = {k: type(v).__name__ for k, v in r.items() if isinstance(v, (dict, list, tuple, set))}
            self.assertEqual(bad, {}, r['device_name'])

    def test_what_a_host_reported_is_in_its_row(self):
        r = {x['device_name']: x for x in self.rows()}['web01']
        self.assertEqual((r['vendor'], r['model'], r['serial'], r['chassis']), ('Dell Inc.', 'PowerEdge R640', 'SN-WEB01', 'server'))
        self.assertEqual((r['cpu_model'], r['cpu_count'], r['mem_total_mb'], r['disk_total_gb']), (XEON, 32, 64000, 960))
        self.assertEqual((r['memory_modules'], r['memory_installed_mb'], r['memory_type'], r['memory_speed']), (4, 4 * 16384, 'DDR4', '2933 MT/s'))
        self.assertEqual((r['disk_count'], r['disk_models'], r['raid_arrays']), (2, 'Samsung SSD 860, WDC WD40EFRX', 1))
        self.assertEqual((r['gpu_count'], r['gpu_models']), (1, 'NVIDIA T4'))
        self.assertEqual((r['group'], r['os'], r['monitored'], r['reported_at']), ('prod', 'Ubuntu 24.04', True, NOW - 600))

    def test_modules_of_two_sizes_in_two_units_add_up_and_a_list_the_host_sent_empty_is_zero_not_nothing(self):
        r = {x['device_name']: x for x in self.rows()}['web02']
        self.assertEqual((r['memory_modules'], r['memory_installed_mb']), (2, 16384), '8 GB and 8192 MB')
        self.assertEqual((r['disk_count'], r['disk_models'], r['raid_arrays'], r['gpu_count']), (0, '', None, None), 'smart was sent and empty; raid and gpus never were')

    def test_a_module_size_that_does_not_read_as_one_leaves_the_total_empty_and_the_count_alone(self):
        rec = dict(HARDWARE['web02'], hardware={'system': {'manufacturer': 'Dell Inc.'}, 'memory': [dimm('A1', '8 GB'), dimm('A2', 'Unknown')]})
        self.api._entity_write_one(self.api.HARDWARE_FILE, 'web02', rec)
        self.api._LOAD_CACHE.clear()
        r = {x['device_name']: x for x in self.rows()}['web02']
        self.assertEqual((r['memory_modules'], r['memory_installed_mb']), (2, None))

    def test_the_serial_numbers_of_modules_and_disks_are_in_no_row(self):
        text = json.dumps(self.rows())
        for secret in ('DIMM-SERIAL-', 'DISK-SERIAL-'):
            self.assertNotIn(secret, text)
        self.assertIn('SN-WEB01', text, 'control: the system serial is there')


class TestAHostWithNoHardwareData(_Fleet):

    def test_a_host_that_never_reported_anything_is_a_row_of_empty_cells(self):
        r = {x['device_name']: x for x in self.rows()}['bare01']
        text = {k: r[k] for k in ('vendor', 'model', 'serial', 'chassis', 'cpu_model', 'memory_type', 'memory_speed', 'disk_models', 'gpu_models')}
        self.assertEqual(text, dict.fromkeys(text, ''))
        counts = {k: r[k] for k in ('cpu_count', 'mem_total_mb', 'memory_modules', 'memory_installed_mb', 'disk_total_gb', 'disk_count', 'raid_arrays', 'gpu_count', 'reported_at')}
        self.assertEqual(counts, dict.fromkeys(counts), 'empty, not zero: the host never said')

    def test_a_host_with_no_hardware_record_still_has_what_its_own_report_said(self):
        r = {x['device_name']: x for x in self.rows()}['mac01']
        self.assertEqual((r['cpu_model'], r['chassis'], r['vendor'], r['memory_modules']), ('Apple M2', 'laptop', '', None))

    def test_the_conditions_run_over_such_a_row_without_an_error(self):
        for where in ({'field': 'vendor', 'op': 'eq', 'value': 'Dell Inc.'}, {'field': 'cpu_count', 'op': 'gt', 'value': 4}, {'field': 'memory_modules', 'op': 'lte', 'value': 2},
                      {'field': 'model', 'op': 'contains', 'value': 'poweredge'}, {'field': 'gpu_models', 'op': 'in', 'value': ['NVIDIA T4']},
                      {'field': 'serial', 'op': 'contains', 'value': 'SN-'}, {'not': {'field': 'vendor', 'op': 'exists'}}):
            self.rows(where)

    def test_exists_leaves_out_the_hosts_that_never_reported_and_a_gt_never_matches_an_empty_count(self):
        self.assertEqual(sorted(self.names({'field': 'vendor', 'op': 'exists'})), ['g01', 'lap01', 'web01', 'web02'])
        self.assertEqual(sorted(self.names({'field': 'cpu_model', 'op': 'exists'})), ['g01', 'lap01', 'mac01', 'web01', 'web02'])
        self.assertNotIn('bare01', self.names({'field': 'memory_modules', 'op': 'gte', 'value': 0}), 'an empty count is not zero')
        self.assertEqual(sorted(self.names({'not': {'field': 'vendor', 'op': 'exists'}})), ['bare01', 'mac01'])

    def test_a_record_of_the_wrong_kind_is_a_row_of_empty_cells_and_not_an_error(self):
        """The loader is defensive in depth: whatever the store holds reaches it as the store's shape check left it, and a hostile shape is read as nothing."""
        junk = {
            'web01': {'hardware': 'junk', 'smart': {'a': 1}, 'gpus': [1, None, {'name': 5}, {'name': ['x']}, 'x'], 'ts': 'now'},
            'web02': {'hardware': {'system': {'manufacturer': ['x'], 'product': {'a': 1}, 'serial': True}, 'memory': 'x', 'raid': {'a': 1}}, 'smart': [1, None, {'model': 7}], 'ts': float('inf')},
            'lap01': 'junk', 'g01': None, 'mac01': [1, 2],
        }
        real = self.api._load_ro
        self.api._load_ro = lambda path: junk if path == self.api.HARDWARE_FILE else real(path)
        self.addCleanup(setattr, self.api, '_load_ro', real)
        rows = {r['device_id']: r for r in self.api._qe_hardware_rows()}
        self.assertEqual(sorted(rows), sorted(DEVICES))
        self.assertEqual((rows['web01']['vendor'], rows['web01']['disk_count'], rows['web01']['gpu_count'], rows['web01']['gpu_models'], rows['web01']['reported_at']), ('', None, 2, '5', None))
        self.assertEqual((rows['web02']['vendor'], rows['web02']['model'], rows['web02']['serial'], rows['web02']['memory_modules'], rows['web02']['raid_arrays'],
                          rows['web02']['disk_count'], rows['web02']['disk_models'], rows['web02']['reported_at']), ('', '', '', None, None, 1, '7', None))
        for r in rows.values():
            self.assertEqual(sorted(r), sorted(FIELDS))


class TestQueriedLikeTheOthers(_Fleet):

    def test_hosts_by_cpu_model(self):
        self.assertEqual(sorted(self.names({'field': 'cpu_model', 'op': 'contains', 'value': 'gold 6130'})), ['g01', 'web01', 'web02'])
        self.assertEqual(self.names({'field': 'cpu_model', 'op': 'eq', 'value': 'Apple M2'}), ['mac01'])

    def test_hosts_by_make_and_model(self):
        both = {'and': [{'field': 'vendor', 'op': 'eq', 'value': 'Dell Inc.'}, {'field': 'model', 'op': 'contains', 'value': 'R640'}]}
        self.assertEqual(sorted(self.names(both)), ['g01', 'web01'])
        self.assertEqual(sorted(self.names({'field': 'vendor', 'op': 'in', 'value': ['LENOVO', 'Dell Inc.']})), ['g01', 'lap01', 'web01', 'web02'])
        self.assertEqual(self.names({'field': 'disk_models', 'op': 'contains', 'value': 'wdc'}), ['web01'])
        self.assertEqual(self.names({'field': 'memory_installed_mb', 'op': 'gte', 'value': 65536}), ['web01'])

    def test_a_sort_orders_the_rows(self):
        have = {'field': 'vendor', 'op': 'exists'}
        models = [r['model'] for r in self.rows(have, sort='model')]
        self.assertEqual(models, ['PowerEdge R640', 'PowerEdge R640', 'PowerEdge R740', 'ThinkPad T14 Gen 2'])
        models = [r['model'] for r in self.rows(have, sort='model', sort_desc=True)]
        self.assertEqual(models, ['ThinkPad T14 Gen 2', 'PowerEdge R740', 'PowerEdge R640', 'PowerEdge R640'])
        cores = [r['cpu_count'] for r in self.rows(have, sort='cpu_count', sort_desc=True)]
        self.assertEqual(cores, [32, 32, 16, 8])

    def test_the_batch_runs_a_hardware_query_beside_another_entity(self):
        st, out = self.request('/api/query/batch', 'POST', body={'queries': [
            {'entity': 'hardware', 'where': {'field': 'chassis', 'op': 'eq', 'value': 'laptop'}},
            {'entity': 'devices', 'where': {'field': 'name', 'op': 'eq', 'value': 'web01'}}]})
        self.assertEqual(st, 200, out)
        self.assertEqual(sorted(r['device_name'] for r in out['results'][0]['rows']), ['lap01', 'mac01'])
        self.assertEqual([r['name'] for r in out['results'][1]['rows']], ['web01'])

    def test_a_saved_query_names_the_entity_and_runs_through_the_same_loader(self):
        where = {'field': 'vendor', 'op': 'eq', 'value': 'Dell Inc.'}
        st, out = self.request('/api/query/templates', 'POST', body={'name': 'dell hosts', 'entity': 'hardware', 'where': where})
        self.assertEqual(st, 201, out)
        st, out = self.request('/api/query/templates')
        t = [x for x in out['templates'] if x['name'] == 'dell hosts'][0]
        self.assertEqual((t['entity'], t['where']), ('hardware', where))
        self.assertEqual(sorted(self.names(t['where'])), ['g01', 'web01', 'web02'])

    def test_an_unknown_field_is_a_400_and_a_serial_is_a_known_one(self):
        st, out = self.request('/api/query', 'POST', body={'entity': 'hardware', 'where': {'field': 'bios_version', 'op': 'exists'}})
        self.assertEqual(st, 400, out)
        self.assertIn('unknown field', out['error'])
        st, out = self.request('/api/query', 'POST', body={'entity': 'hardware', 'where': {'field': 'serial', 'op': 'exists'}})
        self.assertEqual(st, 200, out)

    def test_hostile_values_find_nothing_and_raise_nothing(self):
        for where in ({'field': 'cpu_count', 'op': 'gt', 'value': 'abc'}, {'field': 'cpu_model', 'op': 'contains', 'value': 7}, {'field': 'cpu_model', 'op': 'in', 'value': 'x'},
                      {'field': 'cpu_count', 'op': 'lt', 'value': None}, {'field': 'vendor', 'op': 'eq', 'value': {'a': 1}}, {'field': 'vendor', 'op': 'eq', 'value': '\u0000' * 50}):
            self.assertEqual(self.names(where), [], where)


class TestTheSerialRule(_Fleet):

    def drawer_serial(self, token):
        st, out = self.request('/api/devices/web01/hardware', token=token)
        self.assertEqual(st, 200, out)
        return ((out.get('hardware') or {}).get('system') or {}).get('serial', '')

    def explorer_serial(self, token):
        return {r['device_name']: r['serial'] for r in self.rows(token=token)}.get('web01', 'MISSING')

    def test_the_explorer_shows_the_serial_to_exactly_the_callers_the_hardware_tab_shows_it_to(self):
        """Read off the real endpoint, role by role: the rule is the tab's, whatever it is, and a tab that hides it from a role while the explorer keeps showing it fails here."""
        seen = {}
        for token in ROLE_TOKENS:
            seen[token] = (self.drawer_serial(token), self.explorer_serial(token))
        self.assertEqual({t: a == b for t, (a, b) in seen.items()}, dict.fromkeys(ROLE_TOKENS, True), seen)
        self.assertEqual(seen['k'], ('SN-WEB01', 'SN-WEB01'), 'control: the operator reads it in both')
        self.assertEqual(len({a for a, _ in seen.values()}), 1, 'the tab shows it to every one of the eight kinds of caller today')

    def test_a_rule_that_hides_it_from_a_role_is_followed_by_the_query_the_batch_and_a_saved_query(self):
        real = self.api._caller_role
        self.api._hardware_serials_visible = lambda: real() not in ('viewer', 'mcp')
        for token in ('v', 'mc'):
            # the query, the batch and the rows a saved query runs through are one loader
            self.assertEqual(self.explorer_serial(token), '', token)
            st, out = self.request('/api/query/batch', 'POST', token=token, body={'queries': [{'entity': 'hardware', 'where': {'field': 'vendor', 'op': 'exists'}}]})
            self.assertEqual({r['serial'] for r in out['results'][0]['rows']}, {''}, token)
            self.assertNotIn('SN-', json.dumps(out), token)
            # a condition on it finds nothing: it is not a way to read what is hidden, one character at a time
            for where in ({'field': 'serial', 'op': 'eq', 'value': 'SN-WEB01'}, {'field': 'serial', 'op': 'contains', 'value': 'SN-'}, {'field': 'serial', 'op': 'exists'},
                          {'field': 'serial', 'op': 'in', 'value': ['SN-WEB01', 'SN-WEB02']}):
                self.assertEqual(self.names(where, token), [], (token, where))
            # and a sort on it orders nothing
            a = self.names({'field': 'vendor', 'op': 'exists'}, token, sort='serial')
            b = self.names({'field': 'vendor', 'op': 'exists'}, token, sort='serial', sort_desc=True)
            self.assertEqual(a, b, token)
        for token in ('k', 'au', 'fi', 'ops', 'rw'):
            self.assertEqual(self.explorer_serial(token), 'SN-WEB01', token)
            self.assertEqual(sorted(self.names({'field': 'serial', 'op': 'contains', 'value': 'SN-'}, token)), ['g01', 'web01', 'web02'], token)

    def test_the_serial_is_asked_once_for_a_request_not_for_each_host(self):
        calls = []
        real = self.api._hardware_serials_visible
        self.api._hardware_serials_visible = lambda: (calls.append(1), real())[1]
        self.rows()
        self.assertEqual(len(calls), 1)


class TestWhoReadsWhat(_Fleet):

    def setUp(self):
        super().setUp()
        self.put(DEVICES, tenancy_enforced=True)

    def test_a_tenant_administrator_reads_its_own_hosts_and_no_others(self):
        for token, mine, other in (('ta', ['bare01', 'lap01', 'mac01', 'web01', 'web02'], 'SN-GLOBEX'), ('tb', ['g01'], 'SN-WEB01')):
            rows = self.rows(token=token)
            self.assertEqual(sorted(r['device_name'] for r in rows), mine, token)
            self.assertNotIn(other, json.dumps(rows), token)
            for where in ({'field': 'vendor', 'op': 'eq', 'value': 'Dell Inc.'}, {'field': 'cpu_model', 'op': 'contains', 'value': 'xeon'}):
                self.assertTrue(set(self.names(where, token)) <= set(mine), (token, where))

    def test_a_read_only_user_of_a_tenant_reads_that_tenant(self):
        self.assertEqual(sorted(self.names(token='tv')), ['bare01', 'lap01', 'mac01', 'web01', 'web02'])
        self.assertNotIn('SN-GLOBEX', json.dumps(self.rows(token='tv')))

    def test_the_operator_of_the_installation_reads_every_tenant(self):
        self.assertEqual(sorted(self.names()), sorted(DEVICES))

    def test_the_batch_and_a_saved_query_read_the_same_hosts_as_the_query(self):
        st, out = self.request('/api/query/batch', 'POST', token='ta', body={'queries': [{'entity': 'hardware'}]})
        self.assertEqual(sorted(r['device_name'] for r in out['results'][0]['rows']), ['bare01', 'lap01', 'mac01', 'web01', 'web02'])
        self.assertNotIn('SN-GLOBEX', json.dumps(out))

    def test_a_role_scoped_to_a_group_reads_the_hosts_of_that_group_only(self):
        self.put(DEVICES, tenancy_enforced=False)
        got = self.names(token='ro')
        self.assertEqual(sorted(got), ['g01', 'web01'], 'the prod group')
        self.assertNotIn('SN-WEB02', json.dumps(self.rows(token='ro')))

    def test_a_role_scoped_to_a_group_in_an_isolated_install_reads_the_overlap_of_both(self):
        self.assertEqual(self.names(token='ro'), [], 'the default tenant owns none of the prod hosts here')
        self.put(dict(DEVICES, d01=host('d01', None, 'prod', 'AMD EPYC 7452', 64, 128000, 2000, 'server')), tenancy_enforced=True)
        self.assertEqual(self.names(token='ro'), ['d01'])

    def test_a_caller_with_no_token_reads_nothing(self):
        st, out = self.request('/api/query', 'POST', token='nobody', body={'entity': 'hardware'})
        self.assertEqual(st, 401, out)


if __name__ == '__main__':
    unittest.main()
