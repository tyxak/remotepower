"""The ignore list keeps to the caller's tenant (v7.4.0).

/api/ignored is one store for the whole install, and its entries name hosts,
with the host name as the label. The body-device scope guard exempted the add
and remove handlers as "metadata, never reads/mutates/commands the device",
which was the wrong question: under tenancy a tenant admin could hide another
tenant's host from that tenant's Containers page and Needs attention, and GET
/api/ignored handed every signed-in user every tenant's hidden hosts by name.
Found when the exemption list was re-justified.

Drives the real handlers (only verify_token and the tenant lookup are stubbed),
in both directions: the other tenant's entries are gone, the caller's own and the
fleet-level ones stay, and an install without tenancy sees everything.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-ign-'))
CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


class _Base(unittest.TestCase):
    TENANCY = True

    def setUp(self):
        self._prev_dd = os.environ.get('RP_DATA_DIR')
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v740-ign-')
        spec = importlib.util.spec_from_file_location('api_v740_ign', CGI / 'api.py')
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        self.api = api
        api.save(api.CONFIG_FILE, {'tenancy_enforced': self.TENANCY})
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'a-host', 'tenant': 'tenantA', 'token': 'ta'},
            'devB': {'name': 'b-host', 'tenant': 'tenantB', 'token': 'tb'},
        })
        api.save(api.IGNORED_ITEMS_FILE, {
            'needs_attention': [
                {'key': 'na-a', 'label': 'a-host offline', 'device_id': 'devA', 'ts': 1},
                {'key': 'na-b', 'label': 'b-host offline', 'device_id': 'devB', 'ts': 1},
                {'key': 'na-fleet', 'label': 'fleet-level', 'ts': 1},
            ],
            'stale_containers': [
                {'device_id': 'devA', 'container': 'web', 'label': 'a-host/web', 'ts': 1},
                {'device_id': 'devB', 'container': 'db', 'label': 'b-host/db', 'ts': 1},
            ],
            'devices': [
                {'id': 'devA', 'label': 'a-host', 'ts': 1},
                {'id': 'devB', 'label': 'b-host', 'ts': 1},
                {'id': 'devGone', 'label': 'deleted host', 'ts': 1},
            ],
        })
        api._LOAD_CACHE.clear()
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'x'
        self.body = {}
        api.get_json_obj = lambda: dict(self.body)
        api.get_json_body = api.get_json_obj

        def _respond(status, data=None, headers=None):
            raise api.HTTPError(status, data)
        api.respond = _respond

    def tearDown(self):
        if self._prev_dd is None:
            os.environ.pop('RP_DATA_DIR', None)
        else:
            os.environ['RP_DATA_DIR'] = self._prev_dd

    def _as(self, tenant, role='admin'):
        self.api.verify_token = lambda tok=None, _r=role: ('alice', _r)
        self.api._caller_effective_tenant = lambda u, _t=tenant: _t

    def _call(self, fn, method='GET', body=None):
        self.api.method = lambda: method
        self.body = body or {}
        self.api._LOAD_CACHE.clear()
        try:
            fn()
        except self.api.HTTPError as e:
            return e.status, e.body
        self.fail('handler returned without responding')

    def _store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IGNORED_ITEMS_FILE)


class TestTheListKeepsToTheTenant(_Base):

    def test_a_tenant_sees_its_own_and_fleet_level_entries_only(self):
        self._as('tenantA')
        status, data = self._call(self.api.handle_ignored_list)
        self.assertEqual(status, 200)
        self.assertEqual(sorted(e['key'] for e in data['needs_attention']), ['na-a', 'na-fleet'])
        self.assertEqual([e['device_id'] for e in data['stale_containers']], ['devA'])
        self.assertEqual(sorted(e['id'] for e in data['devices']), ['devA', 'devGone'])
        self.assertNotIn('b-host', repr(data))

    def test_a_viewer_in_the_tenant_gets_the_same_view(self):
        self._as('tenantA', role='viewer')
        status, data = self._call(self.api.handle_ignored_list)
        self.assertEqual(status, 200)
        self.assertNotIn('b-host', repr(data))

    def test_the_platform_superadmin_sees_every_entry(self):
        self._as(self.api.DEFAULT_TENANT)
        status, data = self._call(self.api.handle_ignored_list)
        self.assertEqual(status, 200)
        self.assertEqual(len(data['needs_attention']), 3)
        self.assertEqual(len(data['devices']), 3)

    def test_suppressions_do_not_name_the_other_tenants_hidden_host(self):
        """The devices category keeps its host under `id`; the rollup read only
        `device_id`, so these rows passed as fleet-level for every tenant."""
        self._as('tenantA')
        status, data = self._call(self.api.handle_suppressions)
        self.assertEqual(status, 200)
        self.assertNotIn('devB', repr(data))
        self.assertIn('devA', repr(data), 'control: the caller\'s own entry is listed')


class TestChangesKeepToTheTenant(_Base):

    def test_hiding_another_tenants_host_is_refused(self):
        self._as('tenantA')
        for body in ({'category': 'devices', 'id': 'devB', 'label': 'b-host'},
                     {'category': 'stale_containers', 'device_id': 'devB', 'container': 'x'},
                     {'category': 'needs_attention', 'key': 'na-new', 'device_id': 'devB'}):
            before = self._store()
            status, _ = self._call(self.api.handle_ignored_add, 'POST', body)
            self.assertEqual(status, 403, body)
            self.assertEqual(self._store(), before, 'nothing was stored for ' + body['category'])

    def test_hiding_its_own_host_still_works(self):
        self._as('tenantA')
        status, _ = self._call(self.api.handle_ignored_add, 'POST',
                               {'category': 'stale_containers', 'device_id': 'devA', 'container': 'cache'})
        self.assertEqual(status, 200)
        self.assertIn(('devA', 'cache'), [(e['device_id'], e['container'])
                                          for e in self._store()['stale_containers']])

    def test_lifting_another_tenants_entry_is_refused(self):
        self._as('tenantA')
        status, _ = self._call(self.api.handle_ignored_remove, 'POST', {'category': 'devices', 'id': 'devB'})
        self.assertEqual(status, 403)
        self.assertIn('devB', [e['id'] for e in self._store()['devices']])

    def test_lifting_by_key_leaves_another_tenants_entry(self):
        self._as('tenantA')
        status, _ = self._call(self.api.handle_ignored_remove, 'POST', {'category': 'needs_attention', 'key': 'na-b'})
        self.assertEqual(status, 200)
        self.assertIn('na-b', [e['key'] for e in self._store()['needs_attention']])
        status, _ = self._call(self.api.handle_ignored_remove, 'POST', {'category': 'needs_attention', 'key': 'na-a'})
        self.assertEqual(status, 200)
        self.assertNotIn('na-a', [e['key'] for e in self._store()['needs_attention']],
                         'control: the caller lifts its own entry')


class TestWithoutTenancyNothingChanges(_Base):
    TENANCY = False

    def test_every_entry_is_listed_and_any_host_can_be_hidden(self):
        self._as(self.api.DEFAULT_TENANT)
        status, data = self._call(self.api.handle_ignored_list)
        self.assertEqual((status, len(data['needs_attention']), len(data['devices'])), (200, 3, 3))
        status, _ = self._call(self.api.handle_ignored_add, 'POST', {'category': 'devices', 'id': 'devB'})
        self.assertEqual(status, 200)


if __name__ == '__main__':
    unittest.main()
