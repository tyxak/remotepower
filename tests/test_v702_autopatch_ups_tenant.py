#!/usr/bin/env python3
"""Two more places a tenant admin reached across the tenant boundary.

**Auto-patch policies.** `create` and `update` stamp `tenant_gate` on the policy
(the sweep that fires them runs from cron with no request context, so the tenant
has to live on the object). `list`, `delete` and `run` never read it. So a
tenant admin could enumerate every tenant's policies, delete them, and fire one
— and `run` queues a root package upgrade on the policy's targets. `update` was
worse than ungated: it RE-STAMPED tenant_gate from the caller, so editing
another tenant's policy silently transferred ownership of it.

**UPS dependency.** `dev_id` rides main()'s `_enforce_device_scope` because the
route is under /api/devices/<id>/. `source_device_id` arrives in the BODY and
got no such cover, so a tenant admin could point one of their hosts at another
tenant's UPS device. Not only an existence oracle — `_ups_shutdown_dependents`
walks that link when the source UPS goes critical, which wires a cross-tenant
shutdown.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-apt-'))
_spec = importlib.util.spec_from_file_location('api_autopatch_ups', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-apt-run-'))
        self._files = {n: getattr(api, n) for n in
                       ('DATA_DIR', 'DEVICES_FILE', 'AUTOPATCH_FILE')}
        api.DATA_DIR = self.dir
        for n in ('DEVICES_FILE', 'AUTOPATCH_FILE'):
            setattr(api, n, self.dir / Path(self._files[n]).name)
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', '_tenant_gate',
                       'method', 'audit_log')}
        api.require_auth = lambda *a, **k: 'admin@acme'
        api.require_admin_auth = lambda *a, **k: 'admin@acme'
        api.audit_log = lambda *a, **k: None
        self.cap = {}
        self._resp = api.respond

        def _r(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise api.HTTPError(s, b)
        api.respond = _r

    def tearDown(self):
        for n, v in self._files.items():
            setattr(api, n, v)
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.respond = self._resp

    def _as(self, tenant):
        api._tenant_gate = lambda: tenant

    def _call(self, fn, *a, m='GET'):
        api.method = lambda: m
        self.cap.clear()
        try:
            fn(*a)
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get('s'), self.cap.get('b')


class TestAutopatchPolicies(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.AUTOPATCH_FILE, {'policies': [
            {'id': 'p-acme', 'name': 'acme nightly', 'tenant_gate': 'acme',
             'targets': {'kind': 'group', 'value': 'web'}, 'enabled': True},
            {'id': 'p-globex', 'name': 'globex nightly', 'tenant_gate': 'globex',
             'targets': {'kind': 'group', 'value': 'db'}, 'enabled': True},
        ]})

    def _policies(self):
        api._invalidate_load_cache(api.AUTOPATCH_FILE)
        return {p['id'] for p in (api.load(api.AUTOPATCH_FILE) or {}).get('policies', [])}

    def test_list_shows_only_this_tenants_policies(self):
        self._as('acme')
        _, body = self._call(api.handle_autopatch_list)
        self.assertEqual(['p-acme'], [p['id'] for p in body['policies']])

    def test_a_superadmin_still_sees_everything(self):
        """Positive control — a filter that dropped everything would satisfy
        the test above."""
        self._as(None)
        _, body = self._call(api.handle_autopatch_list)
        self.assertEqual({'p-acme', 'p-globex'},
                         {p['id'] for p in body['policies']})

    def test_delete_refuses_another_tenants_policy(self):
        self._as('acme')
        status, _ = self._call(api.handle_autopatch_delete, 'p-globex', m='DELETE')
        self.assertEqual(404, status)
        self.assertIn('p-globex', self._policies(), 'it was deleted anyway')

    def test_delete_still_works_on_your_own(self):
        self._as('acme')
        status, _ = self._call(api.handle_autopatch_delete, 'p-acme', m='DELETE')
        self.assertEqual(200, status)
        self.assertNotIn('p-acme', self._policies())

    def test_run_refuses_another_tenants_policy(self):
        """run queues a root package upgrade on the policy's targets."""
        self._as('acme')
        queued = []
        _q = api._autopatch_queue
        api._autopatch_queue = lambda pol, actor: queued.append(pol['id']) or 0
        try:
            status, _ = self._call(api.handle_autopatch_run, 'p-globex', m='POST')
        finally:
            api._autopatch_queue = _q
        self.assertEqual(404, status)
        self.assertEqual([], queued, 'commands were queued for another tenant')

    def test_update_cannot_take_ownership_of_another_tenants_policy(self):
        """The re-stamp is the hazard: ungated, editing another tenant's policy
        moved tenant_gate to the caller and the original owner lost it."""
        self._as('acme')
        api._read_valid = lambda m: {'name': 'stolen'}
        try:
            status, _ = self._call(api.handle_autopatch_update, 'p-globex', m='PUT')
        finally:
            del api._read_valid
        self.assertEqual(404, status)
        api._invalidate_load_cache(api.AUTOPATCH_FILE)
        pol = next(p for p in api.load(api.AUTOPATCH_FILE)['policies']
                   if p['id'] == 'p-globex')
        self.assertEqual('globex', pol['tenant_gate'])
        self.assertEqual('globex nightly', pol['name'])

    def test_the_gate_runs_before_the_restamp(self):
        """Order is the whole fix here — a check after the assignment leaves the
        policy already transferred."""
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  'handle_autopatch_update')
        self.assertLess(body.index('_autopatch_block(pol)'),
                        body.index("pol['tenant_gate'] = _tenant_gate()"))


class TestUpsDependency(_Base):

    def setUp(self):
        super().setUp()
        # The device tenant field is `tenant` — _device_tenant reads that, not
        # `tenant_id` (which is what an API-key record carries). Seeding the
        # wrong key makes every device resolve to DEFAULT_TENANT, so the gate
        # refuses the legitimate same-tenant link too and the cross-tenant
        # assertion passes for the wrong reason.
        api.save(api.DEVICES_FILE, {
            'acme1': {'name': 'acme-web', 'tenant': 'acme'},
            'acme2': {'name': 'acme-ups', 'tenant': 'acme'},
            'gx1':   {'name': 'globex-ups', 'tenant': 'globex'},
        })
        api._read_valid = lambda m: dict(self.body)

    def tearDown(self):
        if hasattr(api, '_read_valid'):
            try:
                del api._read_valid
            except AttributeError:
                pass
        super().tearDown()

    def _dep(self, dev_id):
        api._invalidate_load_cache(api.DEVICES_FILE)
        return (api.load(api.DEVICES_FILE)[dev_id].get('ups_dependency') or {})

    def test_a_cross_tenant_source_is_refused(self):
        self._as('acme')
        self.body = {'source_device_id': 'gx1', 'ups_name': 'ups0'}
        status, body = self._call(api.handle_device_ups_dependency, 'acme1',
                                  m='PATCH')
        self.assertEqual(400, status)
        self.assertEqual({}, self._dep('acme1'),
                         'a cross-tenant shutdown dependency was stored')

    def test_the_refusal_is_indistinguishable_from_a_missing_device(self):
        """Otherwise the 400 confirms which device ids exist."""
        self._as('acme')
        self.body = {'source_device_id': 'gx1', 'ups_name': 'u'}
        _, cross = self._call(api.handle_device_ups_dependency, 'acme1', m='PATCH')
        self.body = {'source_device_id': 'nosuchdev', 'ups_name': 'u'}
        _, absent = self._call(api.handle_device_ups_dependency, 'acme1', m='PATCH')
        self.assertEqual(cross, absent)

    def test_a_same_tenant_source_still_works(self):
        """Positive control. A handler that refused every source would pass
        both tests above."""
        self._as('acme')
        self.body = {'source_device_id': 'acme2', 'ups_name': 'ups0'}
        status, _ = self._call(api.handle_device_ups_dependency, 'acme1', m='PATCH')
        self.assertEqual(200, status)
        self.assertEqual('acme2', self._dep('acme1').get('source_device_id'))

    def test_a_superadmin_may_link_across_tenants(self):
        self._as(None)
        self.body = {'source_device_id': 'gx1', 'ups_name': 'ups0'}
        status, _ = self._call(api.handle_device_ups_dependency, 'acme1', m='PATCH')
        self.assertEqual(200, status)


if __name__ == '__main__':
    unittest.main()
