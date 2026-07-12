"""Bug-hunt findings: cross-tenant command execution + fleet-aggregate read leaks.

Found during the v6.1.2 exhaustive bug hunt (pre-existing, not v6.1.2 regressions,
but real and confirmed). A tenant admin resolves to role 'admin' with scope=None, so
any handler that trusts _resolve_targets(body) or iterates load(DEVICES_FILE)
unfiltered — and is NOT under /api/devices/<id>/ (where the pre-dispatch
_enforce_device_scope would catch it) — leaked across tenants.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v612-tci-')
    spec = importlib.util.spec_from_file_location('api_v612_tci', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _TenantBase(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.api.save(self.api.CONFIG_FILE, {'tenancy_enforced': True})
        self.api._LOAD_CACHE.clear()
        self.api.save(self.api.DEVICES_FILE, {
            'devA': {'name': 'A-host', 'tenant': 'tenantA', 'token': 'ta',
                     'version': '1.0', 'tags': ['prod']},
            'devB': {'name': 'B-host', 'tenant': 'tenantB', 'token': 'tb',
                     'version': '2.0', 'tags': ['prod']},
        })
        self.api.audit_log = lambda *a, **k: None
        self.api.get_token_from_request = lambda: 'x'
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _respond

    def _as(self, tenant, role='admin'):
        self.api.verify_token = lambda tok=None, _r=role: ('alice', _r)
        self.api._caller_effective_tenant = lambda u, _t=tenant: _t


class TestCrossTenantCommandExecution(_TenantBase):
    """The highest-impact finding: a tenant admin could queue an arbitrary command
    on another tenant's host via a body-supplied device id (confirmed RCE)."""

    def _exec(self, target):
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'cmd': 'id', 'device_id': target}
        self.api.get_json_body = self.api.get_json_obj
        self.api.save(self.api.CMDS_FILE, {})
        self.api._invalidate_load_cache(self.api.CMDS_FILE)
        try:
            self.api.handle_custom_cmd()
        except (self.api.HTTPError, SystemExit):
            pass
        return (self.api.load(self.api.CMDS_FILE) or {})

    def test_tenant_admin_cannot_exec_on_another_tenants_host(self):
        self._as('tenantA')
        cmds = self._exec('devB')
        self.assertNotIn('devB', cmds,
                         'CROSS-TENANT RCE: a tenant admin queued a command on '
                         "another tenant's device")

    def test_tenant_admin_can_still_exec_on_its_own_host(self):
        self._as('tenantA')
        cmds = self._exec('devA')
        self.assertIn('devA', cmds, 'the fix must not break same-tenant commands')

    def test_superadmin_can_exec_on_any_host(self):
        self._as(self.api.DEFAULT_TENANT)
        self.assertIn('devB', self._exec('devB'),
                      'a platform superadmin must retain cross-tenant control')

    def test_tag_targeting_does_not_cross_tenants(self):
        """The tag/group branches expand across the whole fleet — the filter must
        catch those too, not only an explicit device_id."""
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'cmd': 'id', 'tag': 'prod'}
        self.api.get_json_body = self.api.get_json_obj
        self.api.save(self.api.CMDS_FILE, {})
        self.api._invalidate_load_cache(self.api.CMDS_FILE)
        try:
            self.api.handle_custom_cmd()
        except (self.api.HTTPError, SystemExit):
            pass
        cmds = self.api.load(self.api.CMDS_FILE) or {}
        self.assertEqual(sorted(cmds.keys()), ['devA'],
                         'tag=prod must resolve only to the caller-visible devices')

    def test_resolve_targets_filters_at_the_chokepoint(self):
        """Directly pin the shared chokepoint used by reboot/shutdown/exec/update/
        upgrade/install/ansible/scap — so a NEW command handler routed through it
        is covered automatically."""
        self._as('tenantA')
        self.assertEqual(self.api._resolve_targets({'device_id': 'devB'}), [])
        self.assertEqual(self.api._resolve_targets({'device_id': 'devA'}), ['devA'])
        self.assertEqual(
            sorted(self.api._resolve_targets({'device_ids': ['devA', 'devB']})),
            ['devA'])


class TestFleetAggregateReadIsolation(_TenantBase):
    """Lower impact (read, not write), but a tenant admin could enumerate another
    tenant's fleet through the /api/fleet/* and /api/agent-compat aggregates."""

    def _read(self, fn):
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        import json
        return json.dumps(self.cap.get('d') or {})

    def test_agent_compat_does_not_leak_other_tenants(self):
        self._as('tenantA')
        body = self._read(self.api.handle_agent_compat)
        self.assertIn('A-host', body)
        self.assertNotIn('B-host', body,
                         "agent-compat leaked another tenant's device")

    def test_superadmin_still_sees_the_whole_fleet(self):
        self._as(self.api.DEFAULT_TENANT)
        body = self._read(self.api.handle_agent_compat)
        self.assertIn('A-host', body)
        self.assertIn('B-host', body)


if __name__ == '__main__':
    unittest.main()
