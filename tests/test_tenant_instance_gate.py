#!/usr/bin/env python3
"""Instance-wide state is the platform operator's, not a tenant admin's.

`require_admin_auth()` is true for a tenant admin, and config.json plus the
stores beside it are one per install. v7.0.2 fixed the Settings save; the same
shape stayed open in the ~50 handlers that each own one slice of that store,
and in the shared infrastructure and libraries around it. Among them:

  * restoring a config revision, which could put `tenancy_enforced: false` back
    and turn every isolation helper in the product off;
  * the AI provider, whose base URL takes the stored provider key and every
    other tenant's prompts with it;
  * the agent-release signing key and its enforcement switch;
  * metrics push, GitOps and report definitions — destinations that receive
    fleet-wide data;
  * the KMIP server, relay satellites, WireGuard access, roles, the audit-log
    wipe and the CMDB vault passphrase.

Two shapes of fix, and both are tested here: a per-handler
`_require_platform_operator()` for the config-store slices, and the
`_PLATFORM_ROUTES` dispatcher table for everything else. The population is
DERIVED from the source, not listed, so a new handler cannot quietly join the
open set: the structural test fails until it makes a decision.

Single-tenant installs see no change, and that is asserted, not assumed.
"""
import ast
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-instgate-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_instgate', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

TENANCY_MARKERS = re.compile(
    r'_require_platform_operator|require_instance_admin_auth|_caller_is_superadmin|'
    r'require_superadmin_auth|_scope_block_device|_tenant_gate|_tenant_visible')

# Admin handlers that write config.json but touch only a per-device slice of it
# behind a check that already confines a tenant admin to its own devices.
REVIEWED = {
    # /api/devices/<id>/... — _enforce_device_scope() checks tenant + scope
    # before dispatch, so the device is the caller's.
    'handle_device_monitored': 'per-device, path-scoped by _enforce_device_scope',
    'handle_device_containers_clear': 'per-device, path-scoped by _enforce_device_scope',
    'handle_device_decommission': 'per-device, path-scoped by _enforce_device_scope',
    # Non-admin cache writes recorded by test_error_path_guards' REVIEWED set.
    'handle_monitor_run': 'monitor state cache written by a bounded run',
    'handle_version_check': 'update-check cache',
    # Returns the stored entry; the write is a one-time import of the existing
    # value into config, and the handler is admin-gated for the read itself.
    'handle_dns_import_status': 'polls a one-shot import the caller started',
}


_WRITERS = None


def _config_writers():
    # Line slicing, not ast.get_source_segment: the latter re-walks the whole
    # 74k-line api.py for every node, which made this scan take 45 seconds.
    global _WRITERS
    if _WRITERS is not None:
        return _WRITERS
    out = {}
    for f in sorted(_CGI.glob('*.py')):
        src = f.read_text()
        lines = src.splitlines()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef) and node.name.startswith('handle_'):
                body = '\n'.join(lines[node.lineno - 1:node.end_lineno])
                if re.search(r'(_LockedUpdate|_locked_update|\bsave)\(\s*(A\.)?CONFIG_FILE', body):
                    out[node.name] = (f.name, body)
    _WRITERS = out
    return out


class TestPopulationIsDecided(unittest.TestCase):
    def test_every_config_writer_is_gated_or_reviewed(self):
        writers = _config_writers()
        # Control: the detector found the population it was written against.
        self.assertGreater(len(writers), 45, 'config-writer detector collapsed')
        open_ = sorted(f'{f}: {n}' for n, (f, body) in writers.items()
                       if not TENANCY_MARKERS.search(body) and n not in REVIEWED)
        self.assertEqual(open_, [],
                         'handlers that change config.json with no tenancy decision. '
                         'Call _require_platform_operator() / require_instance_admin_auth() '
                         'on the branch that writes, or add the handler to REVIEWED with '
                         'the reason it cannot reach another tenant:\n  ' + '\n  '.join(open_))

    def test_reviewed_entries_still_exist(self):
        writers = _config_writers()
        stale = sorted(n for n in REVIEWED if n not in writers)
        self.assertEqual(stale, [], 'REVIEWED names a handler that no longer writes config')

    def test_every_platform_route_matches_a_real_route(self):
        src = (_CGI / 'api.py').read_text()
        dead = [p for p, _m, _s in api._PLATFORM_ROUTES if f"'{p}" not in src.split(
            '_PLATFORM_ROUTES = (', 1)[0] + src.split('_PLATFORM_ROUTES = (', 1)[1].split(')\n\n', 1)[1]]
        self.assertEqual(dead, [], 'a _PLATFORM_ROUTES prefix matches no route')


class _Base(unittest.TestCase):
    STORES = ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE', 'AUDIT_LOG_FILE',
              'CONFIG_REVS_FILE', 'DEVICES_FILE', 'ENROLL_TOKENS_FILE', 'PINS_FILE',
              'INBOUND_WEBHOOKS_FILE')
    FNS = ('respond', 'method', 'get_json_obj', 'get_json_body', 'audit_log',
           'get_token_from_request', 'verify_token', 'path_info')

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-ig-'))
        self._saved = {n: getattr(api, n) for n in self.STORES}
        for n in self.STORES:
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {n: getattr(api, n) for n in self.FNS}
        self.cap, self.body, self.m = {}, {}, 'POST'

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: self.m
        api.get_json_obj = lambda: dict(self.body)
        api.get_json_body = lambda: dict(self.body)
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        self.who = 'badmin'
        api.verify_token = lambda _t=None: (
            (self.who, (api._load_ro(api.USERS_FILE) or {}).get(self.who, {}).get('role'))
            if self.who else (None, None))
        api.save(api.TENANTS_FILE, {
            'default': {'name': 'Default', 'status': 'active', 'builtin': True},
            'tenantB': {'name': 'B', 'status': 'active'},
            'tenantC': {'name': 'C', 'status': 'active'}})
        api.save(api.USERS_FILE, {
            'platform': {'role': 'admin', 'tenant_id': 'default'},
            'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
            'cadmin': {'role': 'admin', 'tenant_id': 'tenantC'}})
        api.save(api.DEVICES_FILE, {
            'devB': {'name': 'b1', 'tenant': 'tenantB', 'token_hash': 'x'},
            'devC': {'name': 'c1', 'tenant': 'tenantC', 'token_hash': 'x'}})
        self.tenancy(True)

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def tenancy(self, on):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['tenancy_enforced'] = on
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def call(self, fn, *args, body=None, m='POST', who='badmin'):
        self.who, self.body, self.m = who, dict(body or {}), m
        self.cap.clear()
        api._LOAD_CACHE.clear()
        try:
            fn(*args)
        except api.HTTPError:
            pass
        except SystemExit:
            pass
        api._LOAD_CACHE.clear()
        data = self.cap.get('data')
        return self.cap.get('status'), ({} if data is None else data)

    def platform_refusal(self, status, data):
        return status == 403 and 'platform operator' in str((data or {}).get('error', ''))


class TestConfigSlices(_Base):
    def test_restoring_a_revision_cannot_switch_tenancy_off(self):
        api.save(api.CONFIG_REVS_FILE, {'revisions': [
            {'id': 'r1', 'ts': 1, 'user': 'platform', 'changed_keys': ['tenancy_enforced'],
             'config': {'tenancy_enforced': False}}]})
        st, d = self.call(api.handle_config_revision_restore, body={'id': 'r1'})
        self.assertTrue(self.platform_refusal(st, d), (st, d))
        self.assertTrue((api.load(api.CONFIG_FILE) or {}).get('tenancy_enforced'))
        st, d = self.call(api.handle_config_revisions_list, m='GET')
        self.assertTrue(self.platform_refusal(st, d), (st, d))

    def test_tenant_admin_cannot_repoint_the_ai_provider(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['ai'] = {'provider': 'openai', 'base_url': 'https://api.openai.com/v1',
                     'api_key': 'sk-platform-key'}
        api.save(api.CONFIG_FILE, cfg)
        st, d = self.call(api.handle_ai_config_set,
                          body={'base_url': 'https://collector.tenant-b.example/v1'})
        self.assertTrue(self.platform_refusal(st, d), (st, d))
        self.assertEqual((api.load(api.CONFIG_FILE) or {})['ai']['base_url'],
                         'https://api.openai.com/v1')

    def test_handlers_that_send_fleet_data_somewhere(self):
        for fn, m, body in (
                (api.handle_metrics_push_set, 'PUT', {'url': 'https://x.example/m', 'enabled': True}),
                (api.handle_gitops_set, 'PUT', {'enabled': True, 'repo': 'https://x.example/r.git'}),
                (api.handle_report_defs_save, 'POST', {'name': 'all', 'recipients': ['x@example.com']}),
                (api.handle_report_schedule_set, 'PUT', {'enabled': True}),
                (api.handle_dashboard_kinds_set, 'POST', {}),
                (api.handle_signing_toggle, 'POST', {'enabled': False}),
                (api.handle_signing_generate, 'POST', {}),
                (api.handle_maintenance_mode_set, 'POST', {'enabled': True}),
                (api.handle_status_token, 'POST', {}),
                (api.handle_ai_prompts_save, 'POST', {'key': 'chat', 'text': 'x'}),
                (api.handle_custom_checks_save, 'POST', {'type': 'file_present', 'param': '/x'}),
        ):
            with self.subTest(fn.__name__):
                before = api.load(api.CONFIG_FILE)
                st, d = self.call(fn, body=body, m=m)
                self.assertTrue(self.platform_refusal(st, d), (fn.__name__, st, d))
                self.assertEqual(api.load(api.CONFIG_FILE), before)

    def test_platform_operator_and_single_tenant_installs_unchanged(self):
        st, d = self.call(api.handle_maintenance_mode_set, body={'enabled': True}, who='platform')
        self.assertFalse(self.platform_refusal(st, d), (st, d))
        self.tenancy(False)
        st, d = self.call(api.handle_maintenance_mode_set, body={'enabled': False})
        self.assertFalse(self.platform_refusal(st, d), (st, d))

    def test_device_scoped_exposure_mute_stays_with_the_tenant(self):
        st, d = self.call(api.handle_exposure_mute, body={'device_id': 'devB', 'port': 22})
        self.assertEqual(st, 200, (st, d))
        st, d = self.call(api.handle_exposure_mute, body={'port': 22})
        self.assertTrue(self.platform_refusal(st, d), (st, d))


class TestPlatformRoutes(_Base):
    def gate(self, pi, m='POST', who='badmin'):
        self.who = who
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api._enforce_platform_routes(pi, m)
        except api.HTTPError:
            pass
        return self.cap.get('status')

    def test_tenant_admins_are_refused(self):
        for pi, m in (('/api/roles', 'POST'), ('/api/roles/operator', 'PUT'),
                      ('/api/audit-log', 'DELETE'), ('/api/history', 'DELETE'),
                      ('/api/kmip/config', 'POST'), ('/api/kmip/keys', 'GET'),
                      ('/api/satellites', 'GET'), ('/api/vpn-tunnels', 'POST'),
                      ('/api/cmdb/vault/change', 'POST'), ('/api/cmd-library/x', 'PUT'),
                      ('/api/ansible/playbooks/p1', 'PUT'), ('/api/privacy/erase', 'POST'),
                      ('/api/scan-targets', 'GET'), ('/api/db-maintenance', 'POST')):
            with self.subTest(pi=pi, m=m):
                self.assertEqual(self.gate(pi, m), 403)

    def test_what_stays_open(self):
        for pi, m, who in (
                ('/api/roles', 'GET', 'badmin'),                    # role names for the user form
                ('/api/audit-log', 'GET', 'badmin'),                # its own handler decides
                ('/api/ansible/playbooks/p1/run', 'POST', 'badmin'),  # device perms decide
                ('/api/provisioning/blueprints/b/render', 'POST', 'badmin'),
                ('/api/kmip/daemon/op', 'POST', None),              # the daemon: no user
                ('/api/roles', 'POST', 'platform'),                 # the platform operator
                ('/api/roles', 'POST', None)):                      # anonymous: handler 401s
            with self.subTest(pi=pi, m=m, who=who):
                self.assertIsNone(self.gate(pi, m, who))
        self.tenancy(False)
        self.assertIsNone(self.gate('/api/roles', 'POST'))


class TestEnrolmentLandsInTheRightTenant(_Base):
    def test_token_and_pin_carry_the_minting_tenant(self):
        st, d = self.call(api.handle_enroll_token_create, body={'label': 'b', 'ttl_seconds': 3600})
        self.assertEqual(st, 201, d)
        tok = d['token']
        meta = next(iter((api.load(api.ENROLL_TOKENS_FILE) or {}).values()))
        self.assertEqual(meta.get('tenant'), 'tenantB')
        # another tenant neither lists nor revokes it
        st, rows = self.call(api.handle_enroll_token_list, m='GET', who='cadmin')
        self.assertEqual(rows, [])
        st, _ = self.call(api.handle_enroll_token_revoke, tok[:8], m='DELETE', who='cadmin')
        self.assertEqual(st, 404)
        # the platform operator still sees everything
        st, rows = self.call(api.handle_enroll_token_list, m='GET', who='platform')
        self.assertEqual(len(rows), 1)
        # registration stamps the device
        self.who = None
        st, d = self.call(api.handle_enroll_register, who=None,
                          body={'enrollment_token': tok, 'hostname': 'newb', 'name': 'newb'})
        self.assertIn(st, (200, 201), d)
        dev = (api.load(api.DEVICES_FILE) or {})[d['device_id']]
        self.assertEqual(dev.get('tenant'), 'tenantB')
        # with tenancy off nothing is stamped
        self.tenancy(False)
        st, d = self.call(api.handle_enroll_pin)
        self.assertNotIn('tenant', next(iter((api.load(api.PINS_FILE) or {}).values())))


class TestInboundTokens(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [
            {'id': 'iwh_c', 'token': 'T' * 40, 'label': 'c', 'scope_device_id': 'devC'},
            {'id': 'iwh_fleet', 'token': 'F' * 40, 'label': 'fleet', 'scope_device_id': None}]})

    def test_one_tenant_cannot_see_or_revoke_anothers(self):
        st, d = self.call(api.handle_inbound_webhooks_list, m='GET')
        self.assertEqual(d.get('tokens'), [])
        for tid in ('iwh_c', 'iwh_fleet'):
            st, _ = self.call(api.handle_inbound_webhook_revoke, tid, m='DELETE')
            self.assertEqual(st, 404, tid)
            st, _ = self.call(api.handle_inbound_webhook_toggle, tid, m='PATCH',
                              body={'enabled': False})
            self.assertEqual(st, 404, tid)
        self.assertEqual(len((api.load(api.INBOUND_WEBHOOKS_FILE) or {})['tokens']), 2)
        st, d = self.call(api.handle_inbound_webhooks_list, m='GET', who='cadmin')
        self.assertEqual([t['id'] for t in d['tokens']], ['iwh_c'])

    def test_unpinned_tokens_are_the_platform_operators(self):
        st, d = self.call(api.handle_inbound_webhooks_create, body={'label': 'x'})
        self.assertEqual(st, 403, d)
        st, d = self.call(api.handle_inbound_webhooks_create,
                          body={'label': 'x', 'scope_device_id': 'devB'})
        self.assertEqual(st, 200, d)


if __name__ == '__main__':
    unittest.main()
