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
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-instgate-'))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_instgate', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

A_ROLL = api  # the rollout handlers are re-bound onto api
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
    STORES = ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE', 'AUDIT_LOG_FILE', 'TOKENS_FILE', 'SCHEDULE_FILE', 'ROLLOUTS_FILE', 'HISTORY_FILE', 'IMAGE_UPDATES_FILE',
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


class TestInstanceWideOperationsFoundIn749(_Base):
    """The authorization matrix (7.4.9) found a tenant administrator calling these and getting 2xx: the audit chain's HMAC key and
    the export-signing key rotated, a full backup of every tenant's data written, the server's TLS material generated, and
    instance-wide trackers wiped. Each handler asks for an administrator and has no tenant check, so they join the platform
    table."""

    def gate(self, pi, m, who='badmin'):
        self.who = who
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api._enforce_platform_routes(pi, m)
        except api.HTTPError:
            pass
        return self.cap.get('status')

    OPERATIONS = (
        ('/api/audit/rotate-hmac-key', 'POST'), ('/api/security/rotate-export-key', 'POST'),
        ('/api/self/backup-now', 'POST'), ('/api/self/backup-state', 'DELETE'), ('/api/self/backup-encrypt', 'POST'),
        ('/api/tls/gen-self-signed', 'POST'), ('/api/billing/config', 'POST'), ('/api/connectors/reload', 'POST'),
        ('/api/cve/refresh-feeds', 'POST'), ('/api/ai/rag/reindex', 'POST'), ('/api/exec/batch', 'DELETE'),
        ('/api/backup/download', 'GET'), ('/api/backup/restore', 'POST'), ('/api/backup/test-restore', 'POST'),
        ('/api/webhook/test', 'POST'), ('/api/push-daemon/test', 'POST'),
        ('/api/image-updates/ignore', 'DELETE'),
        # the sweep of handlers with no tenant test (7.4.9): operations on the installation and uses of the operator's accounts
        ('/api/server/restart', 'POST'), ('/api/server/self-update', 'POST'), ('/api/storage-backend/migrate', 'POST'),
        ('/api/tls/import-p12', 'POST'), ('/api/virt/i1/power', 'POST'), ('/api/virt/i1/snapshot', 'POST'),
        ('/api/dns/records', 'POST'), ('/api/dns/records/delete', 'POST'), ('/api/dns/zones', 'GET'),
        ('/api/dns-control/i1/blocking', 'POST'), ('/api/cloud/import', 'POST'), ('/api/gitops/sync', 'POST'),
        ('/api/gitops', 'PUT'), ('/api/ai/test', 'POST'), ('/api/audit/forward-test', 'POST'), ('/api/otlp/test', 'POST'),
        ('/api/otlp/traces-test', 'POST'), ('/api/siem/test', 'POST'), ('/api/posture-digest/test', 'POST'),
        ('/api/webhook/replay', 'POST'), ('/api/image-updates/scan', 'POST'), ('/api/software-policy', 'POST'),
        ('/api/software-policy', 'DELETE'))

    def test_a_tenant_administrator_is_refused_each_one(self):
        for pi, m in self.OPERATIONS:
            with self.subTest(pi=pi, m=m):
                self.assertEqual(self.gate(pi, m), 403)
                self.assertEqual(self.gate(pi, m, who='cadmin'), 403, 'another tenant, same answer')

    def test_the_platform_operator_still_may(self):
        for pi, m in self.OPERATIONS:
            with self.subTest(pi=pi, m=m):
                self.assertIsNone(self.gate(pi, m, who='platform'))

    def test_an_installation_with_tenancy_off_is_unchanged(self):
        self.tenancy(False)
        for pi, m in self.OPERATIONS:
            with self.subTest(pi=pi, m=m):
                self.assertIsNone(self.gate(pi, m))

    def test_the_reads_beside_them_stay_open_to_a_tenant_administrator(self):
        for pi, m in (('/api/self/status', 'GET'), ('/api/self/observability', 'GET'), ('/api/self/backup-state', 'GET'),
                      ('/api/exec/batch', 'GET'), ('/api/exec/batch', 'POST'), ('/api/image-updates/ignore', 'POST'),
                      ('/api/tls/targets', 'GET'), ('/api/billing/config', 'GET'),
                      # a tenant's pages still read the policy their hosts are judged by, the violations and the blockers' list
                      ('/api/software-policy', 'GET'), ('/api/software-policy/violations', 'GET'),
                      ('/api/virt/platforms', 'GET'), ('/api/dns-control/blockers', 'GET'), ('/api/gitops', 'GET')):
            with self.subTest(pi=pi, m=m):
                self.assertIsNone(self.gate(pi, m))

    def test_the_old_table_let_each_of_them_through(self):
        old = tuple(r for r in api._PLATFORM_ROUTES if r[0] != '/api/self'
                    and not any(pi == r[0] or pi.startswith(r[0] + '/') for pi, _m in self.OPERATIONS))
        saved = api._PLATFORM_ROUTES
        api._PLATFORM_ROUTES = old
        try:
            for pi, m in self.OPERATIONS:
                with self.subTest(pi=pi, m=m):
                    self.assertIsNone(self.gate(pi, m), 'the control: without the new rows nothing refuses')
        finally:
            api._PLATFORM_ROUTES = saved


class TestRevokingSessionsStaysInTheTenant(_Base):
    """POST /api/sessions/revoke ignored tenants (7.4.9, authorization matrix F2): a tenant administrator revoked the platform
    operator's session and, with no username, every session but its own across all tenants."""

    def setUp(self):
        super().setUp()
        api.save(api.USERS_FILE, {
            'platform': {'role': 'admin', 'tenant_id': 'default'},
            'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
            'bviewer': {'role': 'viewer', 'tenant_id': 'tenantB'},
            'cadmin': {'role': 'admin', 'tenant_id': 'tenantC'},
            'cviewer': {'role': 'viewer', 'tenant_id': 'tenantC'}})
        now = int(time.time())
        api.save(api.TOKENS_FILE, {h: {'user': u, 'created': now, 'ttl': 86400} for h, u in (
            ('hp1', 'platform'), ('hb1', 'badmin'), ('hb2', 'bviewer'), ('hb3', 'bviewer'),
            ('hc1', 'cadmin'), ('hc2', 'cviewer'))})
        api.get_token_from_request = lambda: 'raw-token-of-the-caller'

    def left(self):
        api._LOAD_CACHE.clear()
        return sorted(api.load(api.TOKENS_FILE))

    def test_a_tenant_administrator_cannot_revoke_the_platform_operator(self):
        st, d = self.call(api.handle_revoke_sessions, body={'username': 'platform'})
        self.assertEqual(st, 404)
        self.assertIn('hp1', self.left())

    def test_a_tenant_administrator_cannot_revoke_another_tenants_user(self):
        st, _ = self.call(api.handle_revoke_sessions, body={'username': 'cviewer'})
        self.assertEqual(st, 404)
        self.assertEqual(self.left(), ['hb1', 'hb2', 'hb3', 'hc1', 'hc2', 'hp1'])

    def test_revoking_one_of_its_own_users_works(self):
        st, d = self.call(api.handle_revoke_sessions, body={'username': 'bviewer'})
        self.assertEqual((st, d.get('revoked')), (200, 2))
        self.assertEqual(self.left(), ['hb1', 'hc1', 'hc2', 'hp1'])

    def test_revoke_all_reaches_only_the_callers_tenant(self):
        st, d = self.call(api.handle_revoke_sessions, body={})
        self.assertEqual(st, 200)
        self.assertEqual(self.left(), ['hc1', 'hc2', 'hp1'], 'tenant B is gone, tenant C and the platform operator stay')
        self.assertEqual(d.get('revoked'), 3)

    def test_the_platform_operator_still_revokes_across_tenants(self):
        st, d = self.call(api.handle_revoke_sessions, body={'username': 'cviewer'}, who='platform')
        self.assertEqual((st, d.get('revoked')), (200, 1))
        st, d = self.call(api.handle_revoke_sessions, body={}, who='platform')
        self.assertEqual(st, 200)
        self.assertEqual(self.left(), [], 'everything but the caller\'s own token, which is not in the store here')

    def test_a_single_tenant_installation_is_unchanged(self):
        self.tenancy(False)
        st, d = self.call(api.handle_revoke_sessions, body={'username': 'cviewer'})
        self.assertEqual((st, d.get('revoked')), (200, 1))

    def test_control_the_old_handler_revoked_across_tenants(self):
        # what the unfixed handler did: no tenant test at all
        tokens = api.load(api.TOKENS_FILE)
        pruned = {k: v for k, v in tokens.items() if v.get('user') != 'platform'}
        self.assertEqual(len(tokens) - len(pruned), 1, 'the platform operator\'s session was reachable by name')


class TestLinksStayInTheTenant(_Base):
    """connected-to, depends-on and an agentless host's connected_to took any host id from the body (7.4.9, authorization matrix
    F4). The stored edge makes alerts of the tenant's host wait on another tenant's host, and the answers told the caller which
    ids exist. A host outside the caller's view is now an unknown id, with the same answer as one that does not exist."""

    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {
            'devB': {'name': 'b1', 'tenant': 'tenantB', 'token_hash': 'x'},
            'devB2': {'name': 'b2', 'tenant': 'tenantB', 'token_hash': 'x'},
            'devC': {'name': 'c1', 'tenant': 'tenantC', 'token_hash': 'x'}})

    def stored(self, dev, key):
        api._LOAD_CACHE.clear()
        return api.load(api.DEVICES_FILE)[dev].get(key)

    def test_connected_to_refuses_another_tenants_host_like_an_unknown_one(self):
        foreign = self.call(api.handle_device_connected_to, 'devB', body={'connected_to': 'devC'}, m='PUT')
        unknown = self.call(api.handle_device_connected_to, 'devB', body={'connected_to': 'nope-xyz'}, m='PUT')
        self.assertEqual(foreign[0], 400)
        self.assertEqual(unknown[0], 400)
        self.assertEqual(foreign[1]['error'].replace('devC', 'X'), unknown[1]['error'].replace('nope-xyz', 'X'),
                         'the answer does not say which ids exist')
        self.assertFalse(self.stored('devB', 'connected_to'))

    def test_connected_to_works_inside_the_tenant(self):
        st, _ = self.call(api.handle_device_connected_to, 'devB', body={'connected_to': 'devB2'}, m='PUT')
        self.assertEqual(st, 200)
        self.assertEqual(self.stored('devB', 'connected_to'), 'devB2')

    def test_depends_on_keeps_only_hosts_the_caller_can_see(self):
        st, d = self.call(api.handle_device_depends_on, 'devB', body={'depends_on': ['devC', 'devB2', 'nope-xyz']}, m='PUT')
        self.assertEqual(st, 200)
        self.assertEqual(d['depends_on'], ['devB2'])
        self.assertEqual(self.stored('devB', 'depends_on'), ['devB2'])

    def test_an_agentless_host_cannot_be_wired_to_another_tenants_host(self):
        st, d = self.call(api.handle_agentless_create, body={'name': 'sw-b', 'connected_to': 'devC'})
        self.assertEqual(st, 400)
        self.assertIn('not found', d['error'])

    def test_the_platform_operator_still_links_across_tenants(self):
        st, _ = self.call(api.handle_device_connected_to, 'devB', body={'connected_to': 'devC'}, m='PUT', who='platform')
        self.assertEqual(st, 200)
        st, d = self.call(api.handle_device_depends_on, 'devB', body={'depends_on': ['devC']}, m='PUT', who='platform')
        self.assertEqual(d['depends_on'], ['devC'])

    def test_a_single_tenant_installation_is_unchanged(self):
        self.tenancy(False)
        st, _ = self.call(api.handle_device_connected_to, 'devB', body={'connected_to': 'devC'}, m='PUT')
        self.assertEqual(st, 200)


class TestSchedulesAndRolloutsStayInTheTenant(_Base):
    """The schedule list, edit and delete, and the rollout list, action and delete, had no tenant test (7.4.9, authorization matrix
    F3): a tenant administrator listed another tenant's jobs and host names and deleted or stopped them."""

    def setUp(self):
        super().setUp()
        api.save(api.SCHEDULE_FILE, {'jobs': [
            {'id': 'jobB', 'device_id': 'devB', 'device_name': 'b1', 'command': 'reboot', 'cron': '0 3 * * 0', 'recurring': True},
            {'id': 'jobC', 'device_id': 'devC', 'device_name': 'c1', 'command': 'reboot', 'cron': '0 4 * * 0', 'recurring': True}]})
        api.save(api.ROLLOUTS_FILE, {'rollouts': [
            {'id': 'rollB', 'name': 'b', 'state': 'draft', 'tenant_gate': 'tenantB', 'created_at': 2, 'rings': []},
            {'id': 'rollC', 'name': 'c', 'state': 'draft', 'tenant_gate': 'tenantC', 'created_at': 1, 'rings': []},
            {'id': 'rollP', 'name': 'p', 'state': 'draft', 'tenant_gate': None, 'created_at': 3, 'rings': []}]})
        api._rollout_tick = lambda *a, **k: None

    def jobs(self):
        api._LOAD_CACHE.clear()
        return sorted(j['id'] for j in api.load(api.SCHEDULE_FILE)['jobs'])

    def rolls(self):
        api._LOAD_CACHE.clear()
        return sorted(r['id'] for r in api.load(api.ROLLOUTS_FILE)['rollouts'])

    def test_the_schedule_list_shows_only_the_tenants_jobs(self):
        st, d = self.call(api.handle_schedule_list, m='GET')
        self.assertEqual(sorted(j['id'] for j in d), ['jobB'])

    def test_deleting_another_tenants_job_is_a_404_and_changes_nothing(self):
        st, _ = self.call(api.handle_schedule_delete, 'jobC', m='DELETE')
        self.assertEqual(st, 404)
        self.assertEqual(self.jobs(), ['jobB', 'jobC'])

    def test_deleting_its_own_job_works(self):
        st, _ = self.call(api.handle_schedule_delete, 'jobB', m='DELETE')
        self.assertEqual(st, 200)
        self.assertEqual(self.jobs(), ['jobC'])

    def test_editing_another_tenants_job_is_a_404(self):
        st, _ = self.call(api.handle_schedule_update, 'jobC', body={'device_id': 'devB', 'command': 'reboot', 'cron': '0 5 * * 0'}, m='PUT')
        self.assertEqual(st, 404)

    def test_the_platform_operator_sees_and_deletes_every_job(self):
        st, d = self.call(api.handle_schedule_list, m='GET', who='platform')
        self.assertEqual(sorted(j['id'] for j in d), ['jobB', 'jobC'])
        st, _ = self.call(api.handle_schedule_delete, 'jobC', m='DELETE', who='platform')
        self.assertEqual(st, 200)

    def test_the_rollout_list_shows_only_the_tenants_rollouts(self):
        st, d = self.call(A_ROLL.handle_rollouts_list, m='GET')
        self.assertEqual(sorted(r['id'] for r in d['rollouts']), ['rollB'])

    def test_deleting_or_stopping_another_tenants_rollout_is_a_404(self):
        for who_roll in ('rollC', 'rollP'):
            with self.subTest(roll=who_roll):
                st, _ = self.call(A_ROLL.handle_rollout_delete, who_roll, m='DELETE')
                self.assertEqual(st, 404)
                st, _ = self.call(A_ROLL.handle_rollout_action, who_roll, 'cancel')
                self.assertEqual(st, 404)
        self.assertEqual(self.rolls(), ['rollB', 'rollC', 'rollP'])

    def test_its_own_rollout_works(self):
        st, _ = self.call(A_ROLL.handle_rollout_delete, 'rollB', m='DELETE')
        self.assertEqual(st, 200)
        self.assertEqual(self.rolls(), ['rollC', 'rollP'])

    def test_the_platform_operator_and_a_single_tenant_install_are_unchanged(self):
        st, d = self.call(A_ROLL.handle_rollouts_list, m='GET', who='platform')
        self.assertEqual(sorted(r['id'] for r in d['rollouts']), ['rollB', 'rollC', 'rollP'])
        self.tenancy(False)
        st, d = self.call(A_ROLL.handle_rollouts_list, m='GET')
        self.assertEqual(len(d['rollouts']), 3)
        st, d = self.call(api.handle_schedule_list, m='GET')
        self.assertEqual(len(d), 2)


class TestHistoryImagesAndWebhookLogsStayInTheTenant(_Base):
    """The command history and the image-update view listed every tenant's hosts (7.4.9, authorization matrix F6), and the webhook
    delivery log and dead letters, whose writes were already the platform operator's, could be read by a tenant administrator."""

    def setUp(self):
        super().setUp()
        api.save(api.HISTORY_FILE, {'entries': [
            {'ts': 1, 'actor': 'u', 'device_id': 'devB', 'device_name': 'b1', 'command': 'reboot'},
            {'ts': 2, 'actor': 'u', 'device_id': 'devC', 'device_name': 'c1', 'command': 'reboot'},
            {'ts': 3, 'actor': 'schedule:ns', 'device_id': '', 'device_name': '', 'command': 'netscan:10.0.9.0/24'}]})
        api.save(api.IMAGE_UPDATES_FILE, {})
        api._image_update_view = lambda: [
            {'device_id': 'devB', 'device_name': 'b1', 'container': 'nginx', 'update_available': True, 'checked': True, 'local': False, 'ignored': False},
            {'device_id': 'devC', 'device_name': 'c1', 'container': 'redis', 'update_available': False, 'checked': True, 'local': False, 'ignored': False}]

    def test_history_shows_only_the_callers_hosts_and_no_platform_job(self):
        st, d = self.call(api.handle_history, m='GET')
        rows = d if isinstance(d, list) else d.get('items') or d.get('entries') or d
        self.assertEqual(sorted(e['device_id'] for e in rows), ['devB'])

    def test_the_platform_operator_sees_the_whole_history(self):
        st, d = self.call(api.handle_history, m='GET', who='platform')
        rows = d if isinstance(d, list) else d.get('items') or d.get('entries') or d
        self.assertEqual(len(rows), 3)

    def test_image_updates_shows_only_the_callers_hosts(self):
        st, d = self.call(api.handle_image_updates_get, m='GET')
        self.assertEqual([r['device_id'] for r in d['images']], ['devB'])
        self.assertEqual(d['summary']['total'], 1)

    def test_the_platform_operator_and_a_single_tenant_install_see_all_images(self):
        st, d = self.call(api.handle_image_updates_get, m='GET', who='platform')
        self.assertEqual(len(d['images']), 2)
        self.tenancy(False)
        st, d = self.call(api.handle_image_updates_get, m='GET')
        self.assertEqual(len(d['images']), 2)

    def test_the_webhook_log_and_dead_letters_are_the_platform_operators_to_read(self):
        for pi in ('/api/webhook/log', '/api/webhook/dlq'):
            for m in ('GET', 'DELETE', 'POST'):
                with self.subTest(pi=pi, m=m):
                    self.assertEqual(self.gate(pi, m), 403)
                    self.assertIsNone(self.gate(pi, m, who='platform'))

    def gate(self, pi, m, who='badmin'):
        self.who = who
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api._enforce_platform_routes(pi, m)
        except api.HTTPError:
            pass
        return self.cap.get('status')


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
