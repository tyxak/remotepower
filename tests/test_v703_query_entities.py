#!/usr/bin/env python3
"""The Data Explorer could ask about three things.

`_QE_ENTITIES` held devices, cves and drift. Meanwhile the heartbeat persists
four more device-keyed inventories that other pages already render — the
package inventory, listening sockets, watched units, containers — plus the
alert inbox. So "which hosts run openssl 3.0.x", "who still listens on 3306
from the world", "which units are flapping" and "what is restarting" were
unaskable on the one page whose entire purpose is asking arbitrary questions,
though each store is one flatten away from a row set.

WHAT THIS PINS

* The entity registry and its field tuples agree in BOTH directions, per
  entity, against rows built from the REAL loaders over seeded stores — a
  field named with nothing behind it always reads empty, and a key in a row
  that the tuple omits is invisible. Both are silent.
* Every exposed field is a SCALAR. The predicate engine compares numbers,
  strings and booleans; a nested value gives the operator a field whose only
  working operator is `exists`.
* Each new entity is reachable END TO END through `_query_run_one` — the
  registry entry existing is not the point, the query working is.
* Visibility. Four of the five join `_scope_filter_devices`, so an
  out-of-scope device contributes no rows; `alerts` deliberately does not
  (a fleet-level alert carries no device, and a devices join would drop it),
  so it goes through `_filter_alerts_for_caller` instead.
* The package scan cap REPORTS itself. A silent truncation is how a partial
  answer gets read as a complete one.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-qent-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_qent', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_NEW = ('packages', 'ports', 'services', 'containers', 'alerts')

# The stores each new entity reads. The value is the ATTRIBUTE name on api, so
# the redirect below can take each temp path's basename from the attribute it
# replaces: on SQLite/Postgres the basename picks the TABLE, so inventing
# `packages_file.json` would quietly not be the package store.
_STORES = ('DEVICES_FILE', 'PACKAGES_FILE', 'SERVICES_FILE', 'CONTAINERS_FILE',
           'ALERTS_FILE', 'CVE_FINDINGS_FILE', 'DRIFT_STATE_FILE')


class _Seeded(unittest.TestCase):
    """Two devices and one of everything on each, written through save() so the
    rows come back out of the storage backend rather than out of the fixture."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='rp-qent-')
        tmp = Path(self._tmp.name)
        self._saved = {n: getattr(api, n) for n in _STORES}
        for n in _STORES:
            setattr(api, n, tmp / self._saved[n].name)
            api._invalidate_load_cache(getattr(api, n))

        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'group': 'prod', 'sysinfo': {
                'listening_ports': [
                    {'proto': 'tcp', 'port': 22, 'process': 'sshd',
                     'addr': '0.0.0.0', 'scope': 'world'},
                    {'proto': 'tcp', 'port': 3306, 'process': 'mariadbd',
                     'addr': '127.0.0.1', 'scope': 'local'},
                ]}},
            'd2': {'name': 'db01', 'group': 'db', 'sysinfo': {
                'listening_ports': [
                    {'proto': 'tcp', 'port': 3306, 'process': 'mariadbd',
                     'addr': '0.0.0.0', 'scope': 'world'},
                ]}},
        })
        api.save(api.PACKAGES_FILE, {
            'd1': {'ecosystem': 'deb', 'packages': [
                {'name': 'openssl', 'version': '3.0.11'},
                {'name': 'nginx', 'version': '1.24.0'}]},
            'd2': {'ecosystem': 'deb', 'packages': [
                {'name': 'openssl', 'version': '3.2.1'}]},
        })
        api.save(api.SERVICES_FILE, {
            'd1': {'services': [
                {'unit': 'nginx.service', 'active': 'active', 'sub': 'running',
                 'since': 1700000000, 'restarts': 9},
                {'unit': 'redis.service', 'active': 'failed', 'sub': 'dead',
                 'since': 1700000001, 'restarts': 0}],
                'flapping': ['nginx.service']},
        })
        api.save(api.CONTAINERS_FILE, {
            'd1': {'ts': 1700000000, 'items': [
                {'name': 'web', 'image': 'nginx', 'tag': '1.25',
                 'status': 'Up 3 days', 'runtime': 'docker', 'health': 'healthy',
                 'restart_count': 0},
                {'name': 'cache', 'image': 'redis', 'tag': '7',
                 'status': 'Exited (1) 2 hours ago', 'runtime': 'docker',
                 'health': '', 'restart_count': 12}]},
        })
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a-1', 'alertid': 'alertid_000001', 'event': 'device_offline',
             'severity': 'high', 'title': 'web01 is offline', 'device_id': 'd1',
             'device_name': 'web01', 'ts': 1700000000, 'first_seen': 1699999000,
             'source': 'internal', 'acknowledged_at': None, 'resolved_at': None},
            {'id': 'a-2', 'alertid': 'alertid_000002', 'event': 'backup_failed',
             'severity': 'critical', 'title': 'Nightly backup failed',
             'device_id': '', 'device_name': '', 'ts': 1700000100,
             'first_seen': 1700000100, 'source': 'internal',
             'acknowledged_at': 1700000200, 'acknowledged_by': 'alice',
             'resolved_at': None},
        ]})
        self.addCleanup(self._restore)

    def _restore(self):
        for n, v in self._saved.items():
            api._invalidate_load_cache(getattr(api, n))
            setattr(api, n, v)
        self._tmp.cleanup()

    def rows(self, entity):
        loader, _fields = api._QE_ENTITIES[entity]
        return loader()


class TestTheRegistryGrew(_Seeded):

    def test_the_five_new_entities_are_registered(self):
        missing = [e for e in _NEW if e not in api._QE_ENTITIES]
        self.assertEqual(missing, [], f'not queryable: {missing}')

    def test_the_old_three_survived(self):
        for e in ('devices', 'cves', 'drift'):
            self.assertIn(e, api._QE_ENTITIES)

    def test_every_new_entity_produced_rows(self):
        """Positive control. Every both-directions comparison below passes
        vacuously against an empty row set, which is exactly what a wrong
        store basename or a broken seed would produce."""
        empty = [e for e in _NEW if not self.rows(e)]
        self.assertEqual(empty, [], f'seeded but produced no rows: {empty}')


class TestTheTwoHalvesAgree(_Seeded):

    def test_every_exposed_field_is_carried_by_a_row(self):
        for entity in _NEW:
            with self.subTest(entity=entity):
                _loader, fields = api._QE_ENTITIES[entity]
                row = self.rows(entity)[0]
                missing = sorted(k for k in fields if k not in row)
                self.assertEqual(
                    missing, [],
                    f'{entity}: exposed as queryable but no row carries them, '
                    f'so a query against them reads empty: {missing}')

    def test_no_row_key_is_unexposed(self):
        for entity in _NEW:
            with self.subTest(entity=entity):
                _loader, fields = api._QE_ENTITIES[entity]
                extra = sorted(set(self.rows(entity)[0]) - set(fields))
                self.assertEqual(
                    extra, [],
                    f'{entity}: built for every row of every query and then '
                    f'not exposed, so the work is discarded: {extra}')

    def test_no_field_is_a_container(self):
        for entity in _NEW:
            for row in self.rows(entity):
                bad = {k: type(v).__name__ for k, v in row.items()
                       if isinstance(v, (dict, list, tuple, set))}
                self.assertEqual(bad, {}, f'{entity}: non-scalar fields {bad}')


class TestTheQueriesActuallyRun(_Seeded):
    """End to end through _query_run_one — the same function both the single
    and the batch endpoint call."""

    def run_q(self, entity, where=None, **kw):
        body = {'entity': entity}
        if where:
            body['where'] = where
        body.update(kw)
        status, payload = api._query_run_one(body)
        self.assertEqual(status, 200, payload)
        return payload

    def test_which_hosts_run_this_package_version(self):
        p = self.run_q('packages', {'and': [
            {'field': 'package', 'op': 'eq', 'value': 'openssl'},
            {'field': 'version', 'op': 'contains', 'value': '3.0.'}]})
        self.assertEqual([r['device_name'] for r in p['rows']], ['web01'])

    def test_who_listens_on_a_port_from_the_world(self):
        p = self.run_q('ports', {'and': [
            {'field': 'port', 'op': 'eq', 'value': 3306},
            {'field': 'scope', 'op': 'eq', 'value': 'world'}]})
        self.assertEqual([r['device_name'] for r in p['rows']], ['db01'])

    def test_a_flapping_unit_is_findable(self):
        p = self.run_q('services', {'field': 'flapping', 'op': 'eq', 'value': True})
        self.assertEqual([r['unit'] for r in p['rows']], ['nginx.service'])

    def test_a_unit_that_is_active_can_still_be_flapping(self):
        """The whole point of the restart delta: it reads 'active' at every
        sample, so an active/inactive predicate cannot find it."""
        row = [r for r in self.rows('services') if r['unit'] == 'nginx.service'][0]
        self.assertEqual(row['active'], 'active')
        self.assertIs(row['running'], True)
        self.assertIs(row['flapping'], True)

    def test_a_stopped_container_is_findable(self):
        p = self.run_q('containers', {'field': 'running', 'op': 'eq', 'value': False})
        self.assertEqual([r['name'] for r in p['rows']], ['cache'])

    def test_running_agrees_with_the_summarise_helper(self):
        """Two surfaces disagreeing about what counts as running is worse than
        either answer, so this reads containers.summarise rather than a second
        hand-written test."""
        sys.path.insert(0, str(_CGI))
        import containers as containers_mod
        items = (api.load(api.CONTAINERS_FILE) or {})['d1']['items']
        self.assertEqual(
            sum(1 for r in self.rows('containers') if r['running']),
            containers_mod.summarise(items)['running'])

    def test_open_criticals_are_findable(self):
        p = self.run_q('alerts', {'and': [
            {'field': 'severity', 'op': 'eq', 'value': 'critical'},
            {'field': 'status', 'op': 'eq', 'value': 'ack'}]})
        self.assertEqual([r['alertid'] for r in p['rows']], ['alertid_000002'])

    def test_status_is_derived_from_the_two_timestamps(self):
        by_id = {r['alertid']: r for r in self.rows('alerts')}
        self.assertEqual(by_id['alertid_000001']['status'], 'open')
        self.assertEqual(by_id['alertid_000002']['status'], 'ack')

    def test_sorting_works_on_a_new_field(self):
        p = self.run_q('packages', sort='version', sort_desc=True)
        self.assertEqual(p['rows'][0]['version'], '3.2.1')

    def test_an_unknown_field_is_refused_not_ignored(self):
        status, payload = api._query_run_one(
            {'entity': 'ports', 'where': {'field': 'nope', 'op': 'eq', 'value': 1}})
        self.assertEqual(status, 400)
        self.assertIn('error', payload)

    def test_the_field_registry_lists_the_new_entities(self):
        """The builder's dropdown is built from this endpoint's output, so an
        entity absent here is unreachable from the UI however well it runs."""
        entities = {name: sorted(fields)
                    for name, (_, fields) in api._QE_ENTITIES.items()}
        for e in _NEW:
            self.assertIn(e, entities)
            self.assertTrue(entities[e], f'{e} exposes no fields')


class TestVisibility(_Seeded):

    def test_an_out_of_scope_device_contributes_no_rows(self):
        """Four of the five join _scope_filter_devices. Stub the SCOPE, not the
        filter: stubbing the filter would pass a loader that never called it."""
        real = api._caller_scope
        api._caller_scope = lambda: {'type': 'groups', 'values': ['db']}
        try:
            for entity in ('packages', 'ports', 'services', 'containers'):
                with self.subTest(entity=entity):
                    ids = {r['device_id'] for r in self.rows(entity)}
                    self.assertNotIn(
                        'd1', ids,
                        f'{entity} returned rows for a device outside the '
                        f'caller scope')
        finally:
            api._caller_scope = real

    def test_the_scope_stub_actually_narrows_something(self):
        """Positive control for the test above: with the stub in place `ports`
        must still return d2's row. An assertion that a device is absent is
        satisfied just as well by a loader that returns nothing at all."""
        real = api._caller_scope
        api._caller_scope = lambda: {'type': 'groups', 'values': ['db']}
        try:
            ids = {r['device_id'] for r in self.rows('ports')}
        finally:
            api._caller_scope = real
        self.assertEqual(ids, {'d2'})

    def test_a_fleet_level_alert_survives(self):
        """It carries no device_id. A _scope_filter_devices join — the pattern
        every other entity uses — would silently drop it."""
        ids = [r['alertid'] for r in self.rows('alerts')]
        self.assertIn('alertid_000002', ids)


class TestTheScanCapIsHonest(_Seeded):

    def test_a_normal_answer_is_not_marked_truncated(self):
        _s, payload = api._query_run_one({'entity': 'packages'})
        self.assertIs(payload['meta']['truncated'], False)

    def test_hitting_the_cap_stops_the_scan_and_says_so(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01'}})
        api.save(api.PACKAGES_FILE, {'d1': {'ecosystem': 'deb', 'packages': [
            {'name': f'pkg{i}', 'version': '1'}
            for i in range(api._QE_SCAN_CAP + 25)]}})
        rows = self.rows('packages')
        self.assertEqual(len(rows), api._QE_SCAN_CAP)
        _s, payload = api._query_run_one({'entity': 'packages'})
        self.assertIs(payload['meta']['truncated'], True)


if __name__ == '__main__':
    unittest.main()
