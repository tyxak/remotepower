"""v6.2.3 security audit — regression guards for the tenant-isolation and
secret-export findings fixed in the exhaustive bug-hunt/pentest sweep.

Same class as tests/test_v611.py / test_v612_tenant_cmd_isolation.py: a tenant
admin resolves to role 'admin' with scope=None, so any handler that resolves a
body device_id itself, or iterates load(DEVICES_FILE) unfiltered, and is NOT
under /api/devices/<id>/ leaked across tenants until these fixes.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
_API_SRC = (CGI / 'api.py').read_text()


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v623-sec-')
    spec = importlib.util.spec_from_file_location('api_v623_sec', CGI / 'api.py')
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
                     'version': '1.0', 'tags': ['prod'],
                     'sysinfo': {'secret': 'A-PORTS-PROCS'}},
            'devB': {'name': 'B-host', 'tenant': 'tenantB', 'token': 'tb',
                     'version': '2.0', 'tags': ['prod'],
                     'sysinfo': {'secret': 'B-PORTS-PROCS'}},
        })
        self.api.audit_log = lambda *a, **k: None
        self.api.log_command = lambda *a, **k: None
        self.api.get_token_from_request = lambda: 'x'
        self.cap = {}

        def _respond(s, d=None, headers=None):
            self.cap['s'], self.cap['d'] = s, d
            raise self.api.HTTPError(s, d)
        self.api.respond = _respond

    def _as(self, tenant, role='admin'):
        self.api.verify_token = lambda tok=None, _r=role: ('alice', _r)
        self.api._caller_effective_tenant = lambda u, _t=tenant: _t


class TestLongpollExecCrossTenant(_TenantBase):
    """CRITICAL: handle_longpoll_exec resolved device_id from the body without a
    tenant/scope gate → cross-tenant arbitrary command execution."""

    def _exec(self, target):
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'cmd': 'id', 'device_id': target}
        self.api.get_json_body = self.api.get_json_obj
        self.api.save(self.api.CMDS_FILE, {})
        self.api._invalidate_load_cache(self.api.CMDS_FILE)
        try:
            self.api.handle_longpoll_exec()
        except (self.api.HTTPError, SystemExit):
            pass
        return (self.api.load(self.api.CMDS_FILE) or {})

    def test_tenant_admin_cannot_exec_on_another_tenants_host(self):
        self._as('tenantA')
        cmds = self._exec('devB')
        self.assertNotIn('devB', cmds, 'cross-tenant command must not be queued')
        self.assertEqual(self.cap.get('s'), 403)


class TestSysinfoBatchScoped(_TenantBase):
    """HIGH: GET /api/devices/sysinfo (seg='sysinfo' dodges _enforce_device_scope)
    returned any device's sysinfo — cross-tenant AND cross-RBAC-scope IDOR."""

    def _batch(self, ids):
        self.api.method = lambda: 'GET'
        self.api._env = lambda k, d='': (f'ids={ids}' if k == 'QUERY_STRING' else d)
        try:
            self.api.handle_sysinfo_batch()
        except (self.api.HTTPError, SystemExit):
            pass
        return (self.cap.get('d') or {}).get('sysinfo', {})

    def test_tenant_admin_only_sees_own_sysinfo(self):
        self._as('tenantA')
        out = self._batch('devA,devB')
        self.assertIn('devA', out)
        self.assertNotIn('devB', out, 'other tenant sysinfo must not be returned')


class TestAlertsClearScoped(_TenantBase):
    """HIGH: DELETE /api/alerts?scope=all wiped every tenant's alerts."""

    def test_scope_all_keeps_other_tenants_alerts(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'device_id': 'devA', 'event': 'x'},
            {'id': 'b1', 'device_id': 'devB', 'event': 'y'},
        ]})
        self.api._invalidate_load_cache(self.api.ALERTS_FILE)
        self._as('tenantA')
        self.api.method = lambda: 'DELETE'
        self.api._env = lambda k, d='': ('scope=all' if k == 'QUERY_STRING' else d)
        try:
            self.api.handle_alerts_clear()
        except (self.api.HTTPError, SystemExit):
            pass
        left = {a['id'] for a in (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts', [])}
        self.assertIn('b1', left, "other tenant's alert must survive")
        self.assertNotIn('a1', left, "own tenant's alert should be cleared")


class TestWolAndSecretsHostMuteScoped(_TenantBase):
    def test_wol_cross_tenant_blocked(self):
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'device_id': 'devB'}
        self.api.get_json_body = self.api.get_json_obj
        try:
            self.api.handle_wol()
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 403)

    def test_secrets_host_mute_cross_tenant_blocked(self):
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'device_id': 'devB'}
        self.api.get_json_body = self.api.get_json_obj
        try:
            self.api.handle_secrets_host_mute()
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 403)


class TestBodyDeviceHandlerGaps(_TenantBase):
    """Cross-tenant gaps the structural body-device guardrail surfaced (beyond the
    handlers the adversarial audit reached). Drive the scariest ones."""

    def test_bulk_delete_cannot_remove_another_tenants_device(self):
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'device_ids': ['devA', 'devB']}
        self.api.get_json_body = self.api.get_json_obj
        try:
            self.api.handle_devices_bulk_delete()
        except (self.api.HTTPError, SystemExit):
            pass
        left = set(self.api.load(self.api.DEVICES_FILE) or {})
        self.assertIn('devB', left, "another tenant's device must not be deletable")

    def test_schedule_add_cannot_target_another_tenants_host(self):
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'device_id': 'devB', 'command': 'reboot',
                                         'run_at': 9999999999}
        self.api.get_json_body = self.api.get_json_obj
        self.api.save(self.api.SCHEDULE_FILE, {})
        self.api._invalidate_load_cache(self.api.SCHEDULE_FILE)
        try:
            self.api.handle_schedule_add()
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 403)
        jobs = self.api.load(self.api.SCHEDULE_FILE) or {}
        self.assertFalse(any(j.get('device_id') == 'devB' for j in jobs.values()),
                         'no schedule may be queued on another tenant host')


class TestExportSecretRedaction(unittest.TestCase):
    """MEDIUM: the diagnostics bundle, backup ZIP and declarative export each kept
    their own hand-list of non-name-caught secret fields and drifted. One shared
    _redact_nonname_config_secrets must strip the full union in every surface."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def _cfg(self):
        return {
            'siem_url': 'https://u:p@siem/i', 'audit_forward_url': 'https://u:p@a',
            'otlp_endpoint': 'https://u:p@o', 'warranty_lenovo_client_id': 'LEN-123',
            'agentless_ssh_key': '-----BEGIN KEY-----', 'webhook_url': 'https://slk/T',
            'metrics_push': {'url': 'https://u:p@push'},
            'gitops': {'auth_header': 'Bearer ghp_X'},
            'webhook_urls': [{'url': 'https://dsc/T', 'pushover_user': 'uKEY'}],
            'integrations': [{'url': 'https://u:p@pihole', 'secret': 'apisec'}],
            'cloud_accounts': [{'secret_key': 'wJalrXUEXAMPLE', 'access_key': 'AKIA'}],
        }

    _NEEDLES = ['u:p@', 'ghp_X', 'wJalrXUEXAMPLE', 'LEN-123', 'BEGIN KEY',
                'slk/T', 'dsc/T', 'uKEY', 'apisec']

    def test_mask_mode_leaves_no_credential(self):
        import json
        c = self._cfg()
        self.api._redact_config_secrets_inplace(c)
        self.api._redact_nonname_config_secrets(c, mask=True)
        blob = json.dumps(c)
        for n in self._NEEDLES:
            self.assertNotIn(n, blob, f'backup/declarative leak: {n}')

    def test_drop_mode_leaves_no_credential(self):
        import json
        c = self._cfg()
        self.api._scrub_config_secrets(c)
        self.api._redact_nonname_config_secrets(c, mask=False)
        blob = json.dumps(c)
        for n in self._NEEDLES:
            self.assertNotIn(n, blob, f'diagnostics-bundle leak: {n}')


class TestSourceLevelFixesPresent(unittest.TestCase):
    """Cheap source pins for the fixes that are awkward to drive end-to-end."""

    def _fn_src(self, name):
        i = _API_SRC.index('def ' + name + '(')
        return _API_SRC[i:_API_SRC.find('\ndef ', i + 1)]

    def test_aggregate_handlers_scope_filter(self):
        for fn in ('handle_patch_sla', 'handle_forecast', 'handle_reboot_plan',
                   'handle_digest', 'handle_maintenance_list', 'handle_discovery'):
            self.assertIn('_scope_filter_devices', self._fn_src(fn),
                          f'{fn} must scope-filter its device set')

    def test_collect_all_scope_filter(self):
        self.assertIn('_scope_filter_devices', self._fn_src('handle_host_config_collect_all'))

    def test_tls_internal_webhook_uses_real_client_ip(self):
        src = (CGI / 'tls_ct_handlers.py').read_text()
        i = src.index('def handle_tls_internal_webhook(')
        block = src[i:src.find('\ndef ', i + 1)]
        self.assertIn('_get_client_ip()', block,
                      'must not trust bare REMOTE_ADDR behind the proxy')

    def test_bundle_and_backup_use_shared_nonname_redactor(self):
        self.assertIn('_redact_nonname_config_secrets', self._fn_src('handle_diagnostics_bundle'))
        self.assertIn('_redact_nonname_config_secrets', self._fn_src('handle_export'))

    def test_sites_list_scopes_device_counts(self):
        # v6.2.3: the per-site device tally must be over the caller's VISIBLE
        # devices (like the sibling handle_sites_map), not the whole fleet —
        # else a scoped/tenant caller reads other tenants' true site sizes.
        self.assertIn('_scope_filter_devices', self._fn_src('handle_sites_list'))


if __name__ == '__main__':
    unittest.main()
