#!/usr/bin/env python3
"""Break-glass and the task board were tenant-blind.

Both are the same shape and it is the shape this codebase keeps producing: a
handler gates on `require_admin_auth()` / `require_write_role()`, which is a
ROLE check, and a tenant admin passes every role check by construction. Nothing
downstream asked which tenant the row belonged to.

BREAK-GLASS is the more interesting of the two, because the leak is not the
secret. `handle_cmdb_credentials_reveal` is properly gated by
`_scope_block_device`, so a foreign admin could never read the credential. What
they could do is APPROVE. Break-glass exists to enforce a two-person rule, and
the second person is meant to be an authorised peer; an admin from an unrelated
tenant supplying that signature means a tenant's own control could be satisfied
from outside the tenant entirely. `GET /api/cmdb/break-glass` separately
returned every tenant's open requests — never a secret, but `label` names the
credential ("prod-db root password") and `reason` is free text written at the
moment of an incident.

THE TASK BOARD leaked in three directions: list showed every tenant's tasks
(enriched with device NAMES), update could edit a foreign task, and update could
RETARGET a task onto a foreign device — which both plants a row on someone
else's board and hands the mover a device id they cannot otherwise see. Delete
was ungated too, and is the most destructive of the three.

Every test that asserts an absence is paired with a positive control asserting
the same-tenant case still works, because "nothing came back" is exactly what a
broken fixture produces.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-tenant-bg-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Base(unittest.TestCase):
    """Drives the REAL handlers. Only verify_token is stubbed — stubbing
    require_admin_auth/require_write_role would happily pass a handler with no
    gate at all, which is how this class of hole survives its own tests."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-tbg-'))
        self._saved = {}
        for name in ('USERS_FILE', 'DEVICES_FILE', 'TENANTS_FILE',
                     'CONFIG_FILE', 'BREAKGLASS_FILE', 'TASKS_FILE',
                     'AUDIT_LOG_FILE'):
            self._saved[name] = getattr(api, name)
            setattr(api, name, self.d / f'{name.lower()}.json')

        api.save(api.TENANTS_FILE, {
            'default': {'name': 'Default', 'status': 'active', 'builtin': True},
            'tenantA': {'name': 'A', 'status': 'active'},
            'tenantB': {'name': 'B', 'status': 'active'},
        })
        api.save(api.USERS_FILE, {
            'aadmin': {'role': 'admin', 'tenant_id': 'tenantA'},
            'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
        })
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'tenantA-prod-db', 'tenant': 'tenantA'},
            'devB': {'name': 'tenantB-box', 'tenant': 'tenantB'},
        })
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})

        self._real_vt = api.verify_token
        self._real_gt = api.get_token_from_request
        api.get_token_from_request = lambda: 'tok'
        self._who = 'badmin'
        api.verify_token = lambda tok: (self._who, 'admin')

        self._real_method = api.method
        self._real_env = api._env

    def tearDown(self):
        api.verify_token = self._real_vt
        api.get_token_from_request = self._real_gt
        api.method = self._real_method
        api._env = self._real_env
        for name, val in self._saved.items():
            setattr(api, name, val)

    def call(self, fn, *a):
        """Handlers signal via HTTPError; capture status+body from it."""
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            return None, None
        return None, None

    def as_user(self, who):
        self._who = who


class TestBreakGlassIsTenantScoped(_Base):

    def _open_request(self):
        api.save(api.BREAKGLASS_FILE, {'bg_deadbeefdeadbeef': {
            'id': 'bg_deadbeefdeadbeef', 'device_id': 'devA',
            'cred_id': 'cred_aaaa', 'label': 'prod-db root password',
            'reason': 'incident 4711 — customer outage',
            'requester': 'aadmin', 'created': int(__import__('time').time()),
            'status': 'pending', 'approved_by': None, 'approved_at': None}})

    def test_owning_tenant_admin_sees_the_request(self):
        """POSITIVE CONTROL for the list filter."""
        self._open_request()
        self.as_user('aadmin')
        api.method = lambda: 'GET'
        st, body = self.call(api.handle_breakglass_list)
        self.assertEqual(st, 200)
        self.assertEqual([r['id'] for r in body], ['bg_deadbeefdeadbeef'])

    def test_foreign_tenant_admin_sees_nothing(self):
        self._open_request()
        self.as_user('badmin')
        api.method = lambda: 'GET'
        st, body = self.call(api.handle_breakglass_list)
        self.assertEqual(st, 200)
        self.assertEqual(body, [],
                         f"tenant B's admin saw tenant A's break-glass "
                         f'request (label/reason leak): {body}')

    def test_foreign_tenant_admin_cannot_approve(self):
        """The two-person rule must not be satisfiable from another tenant."""
        self._open_request()
        self.as_user('badmin')
        api.method = lambda: 'POST'
        st, body = self.call(api.handle_breakglass_approve,
                             'bg_deadbeefdeadbeef')
        self.assertEqual(st, 404, f'expected 404, got {st} {body}')
        stored = (api.load(api.BREAKGLASS_FILE) or {})['bg_deadbeefdeadbeef']
        self.assertEqual(stored['status'], 'pending',
                         'a foreign-tenant admin approved the request')
        self.assertIsNone(stored['approved_by'])

    def test_same_tenant_second_admin_can_still_approve(self):
        """POSITIVE CONTROL: the control itself must keep working. A different
        admin in the OWNING tenant is exactly who is supposed to sign off."""
        self._open_request()
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE) or {},
                                      aadmin2={'role': 'admin',
                                               'tenant_id': 'tenantA'}))
        self.as_user('aadmin2')
        api.method = lambda: 'POST'
        st, _ = self.call(api.handle_breakglass_approve, 'bg_deadbeefdeadbeef')
        stored = (api.load(api.BREAKGLASS_FILE) or {})['bg_deadbeefdeadbeef']
        self.assertEqual(stored['status'], 'approved',
                         f'the legitimate approver was blocked (status={st})')


class TestTaskBoardIsTenantScoped(_Base):

    def _seed_tasks(self):
        api.save(api.TASKS_FILE, {'tasks': [
            {'id': 'tA', 'title': 'rotate tenantA db creds', 'device_id': 'devA',
             'state': 'upcoming', 'created_at': 100, 'updated_at': 100},
            {'id': 'tB', 'title': 'tenantB thing', 'device_id': 'devB',
             'state': 'upcoming', 'created_at': 100, 'updated_at': 100},
            {'id': 'tFleet', 'title': 'no device', 'device_id': '',
             'state': 'upcoming', 'created_at': 100, 'updated_at': 100},
        ]})

    def test_list_shows_only_own_tenant_plus_fleet_level(self):
        self._seed_tasks()
        self.as_user('badmin')
        api.method = lambda: 'GET'
        api._env = lambda k, d='': ''
        st, body = self.call(api.handle_tasks_list)
        self.assertEqual(st, 200)
        ids = sorted(t['id'] for t in body['tasks'])
        self.assertEqual(ids, ['tB', 'tFleet'],
                         f"tenant B saw tenant A's task board: {ids}")

    def test_list_positive_control_owning_tenant_sees_its_task(self):
        self._seed_tasks()
        self.as_user('aadmin')
        api.method = lambda: 'GET'
        api._env = lambda k, d='': ''
        st, body = self.call(api.handle_tasks_list)
        ids = sorted(t['id'] for t in body['tasks'])
        self.assertEqual(ids, ['tA', 'tFleet'],
                         'the owning tenant must still see its own task')

    def test_cannot_edit_foreign_task(self):
        self._seed_tasks()
        self.as_user('badmin')
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'title': 'pwned'}
        st, _ = self.call(api.handle_tasks_update, 'tA')
        self.assertEqual(st, 404)
        tasks = (api.load(api.TASKS_FILE) or {})['tasks']
        self.assertEqual([t for t in tasks if t['id'] == 'tA'][0]['title'],
                         'rotate tenantA db creds', 'foreign task was edited')

    def test_cannot_retarget_task_onto_foreign_device(self):
        self._seed_tasks()
        self.as_user('badmin')
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'device_id': 'devA'}
        st, _ = self.call(api.handle_tasks_update, 'tB')
        self.assertEqual(st, 404)
        tasks = (api.load(api.TASKS_FILE) or {})['tasks']
        self.assertEqual([t for t in tasks if t['id'] == 'tB'][0]['device_id'],
                         'devB', 'task was retargeted onto a foreign device')

    def test_cannot_delete_foreign_task(self):
        self._seed_tasks()
        self.as_user('badmin')
        api.method = lambda: 'DELETE'
        st, _ = self.call(api.handle_tasks_delete, 'tA')
        self.assertEqual(st, 404)
        tasks = (api.load(api.TASKS_FILE) or {})['tasks']
        self.assertIn('tA', [t['id'] for t in tasks],
                      "tenant A's task was deleted by tenant B")

    def test_positive_control_own_task_still_editable(self):
        self._seed_tasks()
        self.as_user('badmin')
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'title': 'legitimately renamed'}
        self.call(api.handle_tasks_update, 'tB')
        tasks = (api.load(api.TASKS_FILE) or {})['tasks']
        self.assertEqual([t for t in tasks if t['id'] == 'tB'][0]['title'],
                         'legitimately renamed',
                         'the gate blocked a legitimate same-tenant edit')


class TestTenancyOffIsUnaffected(_Base):
    """The common install has tenancy off; all of this must be a no-op there."""

    def test_task_list_unfiltered_when_tenancy_off(self):
        api.save(api.CONFIG_FILE, {'tenancy_enforced': False})
        api.save(api.TASKS_FILE, {'tasks': [
            {'id': 'tA', 'title': 'a', 'device_id': 'devA', 'state': 'upcoming',
             'created_at': 1, 'updated_at': 1},
            {'id': 'tB', 'title': 'b', 'device_id': 'devB', 'state': 'upcoming',
             'created_at': 1, 'updated_at': 1}]})
        self.as_user('badmin')
        api.method = lambda: 'GET'
        api._env = lambda k, d='': ''
        st, body = self.call(api.handle_tasks_list)
        self.assertEqual(sorted(t['id'] for t in body['tasks']), ['tA', 'tB'],
                         'tenancy off must not filter anything')


if __name__ == '__main__':
    unittest.main()
