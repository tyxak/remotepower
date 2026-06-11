#!/usr/bin/env python3
"""Tests for the v4.2.0 post-release sweep (bind + bughunt + security + perf).

Covers the fixes from the full-project sweep:
  - sanitizer persists mailq / pkg_scan_ts (the proc_names bug-class)
  - service_up auto-resolves service_down alerts (phantom service_recover)
  - passkey users can't mint a session from password alone (MFA step-up)
  - webauthn_enabled actually gates the ceremonies (default ON)
  - login/begin is rate-limited and non-enumerating
  - audit_log is an atomic locked read-modify-write
  - users list exposes mfa / disabled / source
  - posture self-check gains the audit-chain row
  - scan schedules: pause/resume endpoint, cron-horizon park, stuck-scan sweep
  - failed_units routing-matrix row; container excludes cover restarts
  - nav-counts bundles the alerts + confirmations badges
  - lynis hardening_index survives agent → server → API
"""
import importlib.util
import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v420s", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_API_SRC   = (_CGI / 'api.py').read_text()
_APP_JS    = (_ROOT / 'server/html/static/js/app.js').read_text()
_CAL_JS    = (_ROOT / 'server/html/static/js/app-calendar.js').read_text()
_HTML      = (_ROOT / 'server/html/index.html').read_text()
_AGENT_SRC = (_ROOT / 'client/remotepower-agent.py').read_text()


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('AUDIT_LOG_FILE', 'USERS_FILE', 'CONFIG_FILE', 'TOKENS_FILE',
                  'ALERTS_FILE', 'DEVICES_FILE', 'SCAN_SCHEDULES_FILE',
                  'SCANS_FILE', 'CONFIRMATIONS_FILE', 'MON_HIST_FILE',
                  'CVE_FINDINGS_FILE'):
            self._files[a] = getattr(api, a)
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'get_json_body', 'require_admin_auth',
                       'require_auth', 'require_perm', 'verify_token',
                       '_caller_scope', '_scope_filter_devices', 'audit_log')}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_admin_auth = lambda: 'alice'
        api.require_auth = lambda require_admin=False: 'alice'
        api.require_perm = lambda *a, **k: 'alice'
        api._caller_scope = lambda: None
        api.method = lambda: 'GET'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestSanitizerBindings(unittest.TestCase):
    """The proc_names bug-class: a field read by checks/UI must be persisted
    by the heartbeat sanitizer or the consumer is silently dead fleet-wide."""

    def test_mailq_persisted(self):
        self.assertIn("safe_si['mailq']", _API_SRC,
                      'sanitizer must persist mailq — the Mail-queue check and '
                      'drawer pill read it')

    def test_pkg_scan_ts_persisted(self):
        self.assertIn("safe_si['pkg_scan_ts']", _API_SRC,
                      'Packages drawer "Last scan" pill reads sysinfo.pkg_scan_ts')


class TestMailqThresholds(unittest.TestCase):
    """The mailq check read a 'mailq_thresholds' device key with no writer."""

    def test_wired_into_metric_thresholds(self):
        self.assertEqual(api.DEFAULT_METRIC_THRESHOLDS['mailq_warn_count'], 50)
        self.assertEqual(api.DEFAULT_METRIC_THRESHOLDS['mailq_crit_count'], 500)
        self.assertIn("mailq_warn_count", inspect.getsource(api._host_checks))

    def test_modal_fields_exist(self):
        self.assertIn('thr-mailq-warn', _HTML)
        self.assertIn("'mailq_warn_count'", _APP_JS)


class TestServiceUpResolves(_Base):
    """service_recover was a phantom — the processor fires service_up."""

    def test_recover_map_has_service_up(self):
        self.assertEqual(api._ALERT_RECOVER.get('service_up'), 'service_down')

    def test_service_up_resolves_open_alert(self):
        now = int(api.time.time())
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'a1', 'event': 'service_down', 'severity': 'high',
            'device_id': 'd1', 'payload': {'unit': 'nginx.service'},
            'unit': 'nginx.service', 'created': now,
            'acknowledged_at': None, 'resolved_at': None,
        }]})
        api._auto_resolve_alerts('service_up', {'device_id': 'd1',
                                                'unit': 'nginx.service'})
        alerts = api.load(api.ALERTS_FILE)['alerts']
        self.assertTrue(alerts[0].get('resolved_at'),
                        'service_up must auto-resolve the service_down alert')


class TestPasskeyMfaStepUp(unittest.TestCase):
    """H1: a passkey-only user must not get a session from password alone."""

    def test_login_demands_webauthn(self):
        src = inspect.getsource(api.handle_login)
        self.assertIn("webauthn_required", src)
        self.assertIn("webauthn_credentials", src)

    def test_frontend_handles_webauthn_required(self):
        self.assertIn('data.webauthn_required', _APP_JS)

    def test_passkey_login_honours_remember_me(self):
        src = inspect.getsource(api.handle_webauthn_login_complete)
        self.assertIn('remember_me', src)
        self.assertIn('remember_me: remember', _APP_JS)


class TestWebauthnFeatureGate(_Base):
    """M1: webauthn_enabled used to gate nothing."""

    def test_default_on(self):
        api.save(api.CONFIG_FILE, {})
        self.assertTrue(api._webauthn_feature_on())

    def test_explicit_off(self):
        api.save(api.CONFIG_FILE, {'webauthn_enabled': False})
        self.assertFalse(api._webauthn_feature_on())

    def test_guard_checks_flag(self):
        self.assertIn('_webauthn_feature_on', inspect.getsource(api._webauthn_guard))

    def test_login_button_gated(self):
        # The button is hidden until /api/public-info confirms support.
        self.assertIn('login-btn login-btn-oidc d-none', _HTML)
        self.assertIn('webauthn_enabled', _CAL_JS)
        self.assertIn("'webauthn_enabled'", inspect.getsource(api.handle_public_info))


class TestLoginBeginHardening(unittest.TestCase):
    """L2: rate limit + anti-enumeration on the unauthenticated begin."""

    def test_rate_limited(self):
        self.assertIn('_ip_ratelimit', inspect.getsource(api.handle_webauthn_login_begin))

    def test_no_enumeration_404(self):
        src = inspect.getsource(api.handle_webauthn_login_begin)
        self.assertNotIn('respond(404', src,
                         'unknown users must get a normal-looking challenge, '
                         'not a distinguishable 404')
        self.assertIn("if creds:", src)   # challenge only stored for real users


class TestAuditLogLocking(_Base):
    def test_audit_log_is_locked(self):
        self.assertIn('_LockedUpdate(AUDIT_LOG_FILE)',
                      inspect.getsource(api.audit_log))

    def test_chain_still_intact_after_writes(self):
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        for i in range(4):
            api.audit_log('u', 'act', str(i))
        checked, broken = api._audit_chain_walk(
            api.load(api.AUDIT_LOG_FILE)['entries'])
        self.assertIsNone(broken)
        self.assertEqual(checked, 3)


class TestUsersListAuthState(_Base):
    def test_mfa_disabled_source_fields(self):
        api.save(api.USERS_FILE, {
            'pwonly':  {'role': 'admin', 'created': 1},
            'totp':    {'role': 'admin', 'created': 1, 'totp_secret': 'X'},
            'passkey': {'role': 'viewer', 'created': 1,
                        'webauthn_credentials': [{'id': 'c1'}]},
            'gone':    {'role': 'viewer', 'created': 1, 'disabled': True,
                        'scim_managed': True},
            'sso':     {'role': 'viewer', 'created': 1, 'oidc_subject': 's'},
        })
        rows = {r['username']: r for r in self.call(api.handle_users_list)}
        self.assertEqual(rows['pwonly']['mfa'], 'none')
        self.assertEqual(rows['totp']['mfa'], 'totp')
        self.assertEqual(rows['passkey']['mfa'], 'passkey')
        self.assertTrue(rows['gone']['disabled'])
        self.assertEqual(rows['gone']['source'], 'scim')
        self.assertEqual(rows['sso']['source'], 'oidc')
        self.assertEqual(rows['pwonly']['source'], 'local')
        for r in rows.values():   # no secrets in the payload
            self.assertNotIn('totp_secret', r)
            self.assertNotIn('webauthn_credentials', r)
            self.assertNotIn('password_hash', r)


class TestPostureChainRow(_Base):
    def test_audit_chain_row_present(self):
        api.save(api.CONFIG_FILE, {})
        api.save(api.USERS_FILE, {'a': {'role': 'admin', 'totp_secret': 'X'}})
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        api.audit_log('a', 'x', 'y')
        r = self.call(api.handle_security_posture)
        by = {c['key']: c for c in r['checks']}
        self.assertIn('audit_chain', by)
        self.assertEqual(by['audit_chain']['status'], 'ok')


class TestScanScheduleLifecycle(_Base):
    def _seed(self, **over):
        rec = {'id': 's1', 'name': 'n', 'device_id': 'd1', 'scan_target_id': '',
               'tool': 'nuclei', 'profile': 'passive', 'intensity': 'quick',
               'satellite_id': '', 'cron': '0 3 * * *', 'enabled': True,
               'created': 1, 'actor': 'a', 'last_run': 0, 'next_run': 99}
        rec.update(over)
        api.save(api.SCAN_SCHEDULES_FILE, {'s1': rec})
        return rec

    def test_toggle_pauses_and_resumes(self):
        self._seed()
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None
        r = self.call(api.handle_scan_schedule_toggle, 's1')
        self.assertFalse(r['enabled'])
        r = self.call(api.handle_scan_schedule_toggle, 's1')
        self.assertTrue(r['enabled'])
        self.assertGreater(api.load(api.SCAN_SCHEDULES_FILE)['s1']['next_run'], 0)

    def test_toggle_route_registered(self):
        self.assertIn("endswith('/toggle')", _API_SRC)

    def test_cron_horizon_parks_instead_of_dying(self):
        # After firing, a yearly cron whose next occurrence is beyond
        # _cron_next's ~45-day horizon must park a re-check, not die at 0.
        src = inspect.getsource(api.run_scheduled_scans_if_due)
        self.assertIn("_park", src)
        self.assertNotIn("_cron_next(s.get('cron', ''), now) or 0", src,
                         'next_run must never be parked at the dead value 0')

    def test_stuck_running_scans_age_out(self):
        src = inspect.getsource(api.run_scheduled_scans_if_due)
        self.assertIn("'running'", src)
        self.assertIn('claimed_at', src)

    def test_ui_renders_last_run_and_pause(self):
        self.assertIn('toggleScanSchedule', _APP_JS)
        self.assertIn('s.last_run', _APP_JS)


class TestRoutingMatrixAdditions(unittest.TestCase):
    def test_failed_units_kind(self):
        self.assertIn('failed_units', {k for k, *_ in api.CHANNEL_KINDS})

    def test_scan_perm_in_roles_ui(self):
        self.assertIn('class="role-perm" value="scan"', _HTML)
        self.assertIn('scan', api._RBAC_PERMS)

    def test_container_restart_exclude(self):
        self.assertIn("_container_alert_excluded(cur.get('name'", _API_SRC)

    def test_webhook_titles_added(self):
        for ev in ('image_update_available', 'image_updated', 'snmp_unreachable',
                   'snmp_dead', 'snmp_recover', 'mcp_confirmation_expired'):
            self.assertIn(f"'{ev}':", _API_SRC)


class TestNavCountsBundle(_Base):
    def setUp(self):
        super().setUp()
        api._scope_filter_devices = lambda d: d
        api.verify_token = lambda t: ('alice', 'admin')
        self._ttl = api.get_online_ttl
        api.get_online_ttl = lambda: 180

    def tearDown(self):
        api.get_online_ttl = self._ttl
        super().tearDown()

    def test_bundles_alerts_and_confirmations(self):
        now = int(api.time.time())
        api.save(api.DEVICES_FILE, {})
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'a1', 'severity': 'high', 'acknowledged_at': None,
             'resolved_at': None}]})
        api.save(api.CONFIRMATIONS_FILE, {'confirmations': [
            {'status': 'pending', 'requested_at': now},
            {'status': 'approved', 'requested_at': now},
            {'status': 'pending', 'requested_at': 1},   # long expired
        ]})
        out = self.call(api.handle_nav_counts)
        self.assertEqual(out['alerts']['open'], 1)
        self.assertEqual(out['confirmations_pending'], 1)

    def test_viewer_gets_no_confirmations_count(self):
        api.verify_token = lambda t: ('bob', 'viewer')
        api.save(api.DEVICES_FILE, {})
        out = self.call(api.handle_nav_counts)
        self.assertNotIn('confirmations_pending', out)

    def test_frontend_single_poll(self):
        self.assertIn('_paintAlertsBadge', _APP_JS)
        self.assertIn('_paintConfirmationsBadge', _APP_JS)
        self.assertIn('c.confirmations_pending', _APP_JS)


class TestHardeningIndex(unittest.TestCase):
    def test_agent_parses_it(self):
        self.assertIn("hardening_index=", _AGENT_SRC)
        self.assertIn("'hardening_index'", _AGENT_SRC)

    def test_agent_outbox_survives_failed_post(self):
        # Peek-then-pop: a finished lynis result must not be lost to one
        # network blip or busy-202.
        self.assertIn('_HOST_SCAN_OUTBOX[0]', _AGENT_SRC)

    def test_server_stores_and_exposes_it(self):
        self.assertEqual(api._scan_public({'hardening_index': 77})['hardening_index'], 77)
        self.assertIn('hardening_index',
                      inspect.getsource(api._apply_scan_results))

    def test_ui_shows_it(self):
        self.assertIn('hardening_index', _APP_JS)


class TestScanTargetVerifyNoLoopback(unittest.TestCase):
    def test_loopback_refused(self):
        src = inspect.getsource(api._verify_scan_target_file)
        self.assertIn('allow_loopback=False', src)
        self.assertNotIn('allow_loopback=True', src)


class TestDeviceCardMetricReads(unittest.TestCase):
    """M4: cards read si.mem.percent / si.cpu.percent — shapes the sanitizer
    never stores (it stores scalar mem_percent/cpu_percent)."""

    def test_no_stale_shape_reads(self):
        self.assertNotIn('si.mem.percent', _APP_JS)
        self.assertNotIn('si.cpu.percent', _APP_JS)
        self.assertIn('si.mem_percent', _APP_JS)


class TestPerfFixes(unittest.TestCase):
    def test_kev_refresh_claims_before_fetch(self):
        src = inspect.getsource(api.refresh_kev_epss_if_due)
        self.assertIn('_LockedUpdate(CONFIG_FILE)', src)
        self.assertIn('_run_detached', src)

    def test_offline_sweep_has_lockfree_prepass(self):
        self.assertIn('_offline_sweep_has_work',
                      inspect.getsource(api.check_offline_webhooks))

    def test_claim_agent_scan_peeks(self):
        src = inspect.getsource(api._claim_agent_scan)
        self.assertIn('peek', src)

    def test_refresh_bar_uses_transform(self):
        css = (_ROOT / 'server/html/static/css/styles.css').read_text()
        self.assertIn('transition: transform 1s linear', css)
        self.assertNotIn('transition: width 1s linear', css)
        self.assertIn('scaleX', _APP_JS)


if __name__ == '__main__':
    unittest.main()
