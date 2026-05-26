"""v3.2.0 release tests.

Strict version pins for v3.2.0 plus coverage for the four new features:
  * B1 — alerts inbox (mutable ledger with ack/resolve)
  * B2 — inbound webhooks endpoint
  * A1 — MCP write tools (Stage 4)
  * B3 — OIDC SSO

Following the same convention every prior release-bump test followed
(test_v303.py → … → test_v310.py): the strict EXPECTED pin lives here
until v3.3.0 ships, at which point this file's pins loosen to a regex
and test_v330.py takes the strict slot.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


def _clear_env(*names):
    for n in names:
        os.environ.pop(n, None)


class _ApiTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v320_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        for mod in ('api',):
            if mod in sys.modules:
                del sys.modules[mod]
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        _clear_env('RP_DATA_DIR')

    def _seed_admin_session(self, username='admin'):
        users = self.api.load(self.api.USERS_FILE)
        users[username] = {
            'password_hash': self.api.hash_password('x'),
            'role': 'admin',
        }
        self.api.save(self.api.USERS_FILE, users)
        token = 'admin-tok-' + os.urandom(8).hex()
        tokens = self.api.load(self.api.TOKENS_FILE)
        tokens[token] = {'user': username, 'created': int(time.time()),
                          'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, tokens)
        os.environ['HTTP_X_TOKEN'] = token
        return token


# ─── B1: alert ledger ───────────────────────────────────────────────────────

class TestAlertsLedger(_ApiTestBase):
    """The mutable alert inbox: every fire_webhook() of an actionable event
    appends a row; recover events auto-resolve the matching open row."""

    def setUp(self):
        # Fresh alerts file per test
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})

    def test_device_offline_creates_critical_alert(self):
        self.api.fire_webhook('device_offline',
            {'device_id': 'd-1', 'device_name': 'tviweb01'})
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['severity'], 'critical')
        self.assertEqual(rows[0]['event'], 'device_offline')
        self.assertEqual(rows[0]['device_id'], 'd-1')
        self.assertIsNone(rows[0]['acknowledged_at'])
        self.assertIsNone(rows[0]['resolved_at'])

    def test_device_online_auto_resolves_matching_offline(self):
        self.api.fire_webhook('device_offline',
            {'device_id': 'd-1', 'device_name': 'tviweb01'})
        self.api.fire_webhook('device_online',
            {'device_id': 'd-1', 'device_name': 'tviweb01'})
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1, 'recover must not create a new row')
        self.assertEqual(rows[0]['resolved_by'], 'auto')
        self.assertIsNotNone(rows[0]['resolved_at'])

    def test_non_actionable_event_does_not_create_alert(self):
        n_before = len(self.api.load(self.api.ALERTS_FILE).get('alerts', []))
        self.api.fire_webhook('command_executed',
            {'device_id': 'd-1', 'command': 'ls'})
        n_after = len(self.api.load(self.api.ALERTS_FILE).get('alerts', []))
        self.assertEqual(n_before, n_after)

    def test_cve_severity_promotion_from_payload(self):
        self.api.fire_webhook('cve_found',
            {'device_id': 'd-2', 'critical': 3, 'high': 5})
        self.api.fire_webhook('cve_found',
            {'device_id': 'd-3', 'critical': 0, 'high': 2})
        self.api.fire_webhook('cve_found',
            {'device_id': 'd-4', 'critical': 0, 'high': 0})
        sevs = [a['severity'] for a in
                self.api.load(self.api.ALERTS_FILE).get('alerts', [])
                if a['event'] == 'cve_found']
        self.assertEqual(sevs, ['critical', 'high', 'medium'])

    def test_tls_severity_from_days(self):
        self.api.fire_webhook('tls_expiring',
            {'host': 'a.example.com', 'days': 2})
        self.api.fire_webhook('tls_expiring',
            {'host': 'b.example.com', 'days': 10})
        self.api.fire_webhook('tls_expiring',
            {'host': 'c.example.com', 'days': 25})
        sevs = [a['severity'] for a in
                self.api.load(self.api.ALERTS_FILE).get('alerts', [])
                if a['event'] == 'tls_expiring']
        self.assertEqual(sevs, ['critical', 'high', 'medium'])

    def test_service_recover_only_resolves_matching_unit(self):
        self.api.fire_webhook('service_down',
            {'device_id': 'd-1', 'name': 'web1', 'unit': 'nginx.service'})
        self.api.fire_webhook('service_down',
            {'device_id': 'd-1', 'name': 'web1', 'unit': 'postfix.service'})
        # Recover only nginx
        self.api.fire_webhook('service_recover',
            {'device_id': 'd-1', 'unit': 'nginx.service'})
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        resolved = [a for a in rows if a.get('resolved_at')]
        open_ = [a for a in rows if not a.get('resolved_at')]
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]['payload']['unit'], 'nginx.service')
        self.assertEqual(len(open_), 1)
        self.assertEqual(open_[0]['payload']['unit'], 'postfix.service')


# ─── B1: alert HTTP endpoints ───────────────────────────────────────────────

class TestAlertEndpoints(_ApiTestBase):
    def setUp(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self._seed_admin_session('admin')
        os.environ['REQUEST_METHOD'] = 'GET'

    def _alert(self, event='device_offline', dev='d-1', name='x'):
        self.api.fire_webhook(event, {'device_id': dev, 'device_name': name})
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        return rows[-1]['id']

    def _respond_stub(self):
        """Patch respond() to raise HTTPError so we can inspect."""
        captured = {}
        orig = self.api.respond
        def _capture(status, body=None):
            captured['status'] = status
            captured['body'] = body
            raise self.api.HTTPError(status, body or {})
        self.api.respond = _capture
        return captured, orig

    def test_list_endpoint_returns_open_by_default(self):
        self._alert()
        self._alert()
        os.environ['QUERY_STRING'] = ''
        captured, orig = self._respond_stub()
        try:
            self.api.handle_alerts_list()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        self.assertEqual(len(captured['body']['alerts']), 2)
        self.assertEqual(captured['body']['summary']['open'], 2)

    def test_ack_then_unack(self):
        aid = self._alert()
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['QUERY_STRING'] = ''
        captured, orig = self._respond_stub()
        try:
            self.api.handle_alert_ack(aid)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(rows[0]['acknowledged_by'], 'admin')

        # Unack
        captured, orig = self._respond_stub()
        try:
            self.api.handle_alert_unack(aid)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertIsNone(rows[0]['acknowledged_by'])

    def test_resolve_endpoint(self):
        aid = self._alert()
        os.environ['REQUEST_METHOD'] = 'POST'
        captured, orig = self._respond_stub()
        try:
            self.api.handle_alert_resolve(aid)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(rows[0]['resolved_by'], 'admin')
        self.assertEqual(rows[0]['acknowledged_by'], 'admin',
            'resolve must imply ack')

    def test_unknown_alert_404(self):
        os.environ['REQUEST_METHOD'] = 'POST'
        captured, orig = self._respond_stub()
        try:
            self.api.handle_alert_ack('a-nonexistent')
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 404)


# ─── B2: inbound webhooks ───────────────────────────────────────────────────

class TestInboundWebhooks(_ApiTestBase):
    def setUp(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, {'tokens': []})

    def _respond_stub(self):
        captured = {}
        orig = self.api.respond
        def _capture(status, body=None):
            captured['status'] = status
            captured['body'] = body
            raise self.api.HTTPError(status, body or {})
        self.api.respond = _capture
        return captured, orig

    def _seed_token(self, label='grafana', scope_device_id=None):
        tok = 'rpwi_' + 'a' * 32
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, {'tokens': [{
            'id': 'iwh_test', 'label': label, 'token': tok,
            'scope_device_id': scope_device_id, 'enabled': True,
            'created_at': 0, 'hit_count': 0,
        }]})
        return tok

    def test_valid_inbound_creates_alert(self):
        tok = self._seed_token()
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {
            'severity': 'high', 'title': 'CPU 95%',
            'source': 'grafana', 'body': 'web01 hot',
        }
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook(tok)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['event'], 'inbound')
        self.assertEqual(rows[0]['severity'], 'high')
        self.assertEqual(rows[0]['source'], 'inbound')
        self.assertEqual(rows[0]['title'], 'CPU 95%')

    def test_invalid_token_returns_401(self):
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {'severity': 'high', 'title': 'x'}
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook('rpwi_nonexistent')
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 401)

    def test_missing_title_returns_400(self):
        tok = self._seed_token()
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {'severity': 'high'}
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook(tok)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 400)

    def test_disabled_token_returns_401(self):
        tok = self._seed_token()
        cfg = self.api.load(self.api.INBOUND_WEBHOOKS_FILE)
        cfg['tokens'][0]['enabled'] = False
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, cfg)
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {'severity': 'h', 'title': 't'}
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook(tok)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 401)

    def test_pinned_device_overrides_body_device(self):
        tok = self._seed_token(scope_device_id='d-pinned')
        # Seed a device named "other" so we can verify it does NOT win
        self.api.save(self.api.DEVICES_FILE, {
            'd-pinned': {'name': 'pinned-host'},
            'd-other':  {'name': 'other-host'},
        })
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {
            'severity': 'medium', 'title': 'x',
            'device': 'other-host',  # should be IGNORED
        }
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook(tok)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(rows[0]['device_id'], 'd-pinned')

    def test_token_format_must_start_with_rpwi(self):
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {'severity': 'h', 'title': 't'}
        captured, orig = self._respond_stub()
        try:
            self.api.handle_inbound_webhook('badtoken_no_prefix')
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 401)

    def test_hit_count_increments(self):
        tok = self._seed_token()
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {'severity': 'h', 'title': 't'}
        # Fire twice
        for _ in range(2):
            captured, orig = self._respond_stub()
            try:
                self.api.handle_inbound_webhook(tok)
            except self.api.HTTPError:
                pass
            finally:
                self.api.respond = orig
        cfg = self.api.load(self.api.INBOUND_WEBHOOKS_FILE)
        self.assertEqual(cfg['tokens'][0]['hit_count'], 2)


# ─── A1: MCP write tools (Stage 4) ──────────────────────────────────────────

class TestMcpWriteTools(_ApiTestBase):
    def setUp(self):
        # Reset all state files used by these tests
        self.api.save(self.api.DEVICES_FILE, {
            'd-confirm': {'name': 'confirm-host', 'require_confirmation': True},
            'd-auto':    {'name': 'auto-host',    'require_confirmation': False},
        })
        self.api.save(self.api.CMDS_FILE, {})
        self.api.save(self.api.CONFIRMATIONS_FILE, {'confirmations': []})
        self.api.save(self.api.SCRIPTS_FILE,
                      {'s1': {'name': 'uptime', 'body': 'uptime'}})

        # Admin session for confirmation-approval tests
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.admin_token = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.admin_token] = {'user': 'admin', 'created': int(time.time()),
                                  'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)

        # MCP API key
        ak = self.api.load(self.api.APIKEYS_FILE)
        ak['mcp1'] = {'name': 'mcp1', 'key': 'rpk_mcp_t', 'user': 'mcp1',
                       'role': 'mcp', 'created': int(time.time()),
                       'active': True, 'expires_at': None}
        self.api.save(self.api.APIKEYS_FILE, ak)

    def _respond_stub(self):
        captured = {}
        orig = self.api.respond
        def _capture(s, b=None):
            captured['status'] = s
            captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = _capture
        return captured, orig

    def _call(self, handler, body, headers=None):
        os.environ.setdefault('REQUEST_METHOD', 'POST')
        os.environ['REQUEST_METHOD'] = 'POST'
        if headers:
            for k, v in headers.items():
                os.environ[k] = v
        self.api.get_json_body = lambda: body
        captured, orig = self._respond_stub()
        try:
            handler()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured

    def _as_mcp(self):
        os.environ['HTTP_X_TOKEN'] = 'rpk_mcp_t'
        os.environ['HTTP_X_MCP_CLIENT'] = 'claude-desktop'
        os.environ['HTTP_X_MCP_PROMPT'] = 'test prompt'

    def _as_admin(self):
        os.environ['HTTP_X_TOKEN'] = self.admin_token
        os.environ.pop('HTTP_X_MCP_CLIENT', None)
        os.environ.pop('HTTP_X_MCP_PROMPT', None)

    def test_reboot_confirmation_required_returns_202(self):
        self._as_mcp()
        r = self._call(self.api.handle_mcp_reboot_device,
                        {'device_id': 'd-confirm'})
        self.assertEqual(r['status'], 202)
        self.assertEqual(r['body']['status'], 'pending_confirmation')

    def test_reboot_auto_executes_immediately(self):
        self._as_mcp()
        r = self._call(self.api.handle_mcp_reboot_device,
                        {'device_id': 'd-auto'})
        self.assertEqual(r['status'], 200)
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertIn('reboot', cmds.get('d-auto', []))

    def test_force_package_scan_no_confirmation_needed(self):
        self._as_mcp()
        # Even with require_confirmation=True, non-destructive runs immediately
        r = self._call(self.api.handle_mcp_force_package_scan,
                        {'device_id': 'd-confirm'})
        self.assertEqual(r['status'], 200)
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertTrue(devs['d-confirm'].get('force_package_scan'))

    def test_run_saved_script_unknown_script(self):
        self._as_mcp()
        r = self._call(self.api.handle_mcp_run_saved_script,
                        {'device_id': 'd-auto', 'script_id': 'nonexistent'})
        self.assertEqual(r['status'], 400)

    def test_run_saved_script_missing_script_id(self):
        # v3.2.0 follow-up: pre-validation rejects missing script_id BEFORE
        # queuing a confirmation (regression from live MCP test session)
        self._as_mcp()
        r = self._call(self.api.handle_mcp_run_saved_script,
                        {'device_id': 'd-confirm'})   # no script_id
        self.assertEqual(r['status'], 400)
        self.assertIn('script_id', r['body']['error'])

    def test_run_saved_script_bogus_script_id_rejected_before_confirmation(self):
        # Even when require_confirmation=true, bogus script_id should NOT
        # queue a doomed confirmation — 400 fires immediately.
        self._as_mcp()
        r = self._call(self.api.handle_mcp_run_saved_script,
                        {'device_id': 'd-confirm', 'script_id': 'nope'})
        self.assertEqual(r['status'], 400)
        # No confirmation should have been created
        confs = self.api.load(self.api.CONFIRMATIONS_FILE).get('confirmations', [])
        bogus = [c for c in confs if c.get('params', {}).get('script_id') == 'nope']
        self.assertEqual(bogus, [],
            'bogus script_id must not park a confirmation')

    def test_run_saved_script_queues_exec(self):
        self._as_mcp()
        r = self._call(self.api.handle_mcp_run_saved_script,
                        {'device_id': 'd-auto', 'script_id': 's1'})
        self.assertEqual(r['status'], 200)
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertIn('exec:uptime', cmds.get('d-auto', []))

    def test_viewer_blocked(self):
        # Viewer cannot use MCP write endpoints
        ak = self.api.load(self.api.APIKEYS_FILE)
        ak['v'] = {'name': 'v', 'key': 'rpk_v', 'user': 'v',
                    'role': 'viewer', 'created': int(time.time()),
                    'active': True, 'expires_at': None}
        self.api.save(self.api.APIKEYS_FILE, ak)
        os.environ['HTTP_X_TOKEN'] = 'rpk_v'
        r = self._call(self.api.handle_mcp_reboot_device,
                        {'device_id': 'd-auto'})
        self.assertEqual(r['status'], 403)

    def test_admin_blocked_from_mcp_endpoint(self):
        # Even admin tokens can't use MCP endpoints — separation of concerns
        self._as_admin()
        r = self._call(self.api.handle_mcp_reboot_device,
                        {'device_id': 'd-auto'})
        self.assertEqual(r['status'], 403)

    def test_confirmation_approve_executes(self):
        # 1. MCP requests a reboot on d-confirm → 202
        self._as_mcp()
        r1 = self._call(self.api.handle_mcp_reboot_device,
                         {'device_id': 'd-confirm'})
        conf_id = r1['body']['confirmation_id']
        # 2. Admin approves directly (handler takes the id arg)
        self._as_admin()
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {}
        captured, orig = self._respond_stub()
        try:
            self.api.handle_confirmation_approve(conf_id)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertIn('reboot', cmds.get('d-confirm', []))

    def test_confirmation_reject_does_not_execute(self):
        self._as_mcp()
        r1 = self._call(self.api.handle_mcp_reboot_device,
                         {'device_id': 'd-confirm'})
        conf_id = r1['body']['confirmation_id']
        self._as_admin()
        captured, orig = self._respond_stub()
        self.api.get_json_body = lambda: {'note': 'no thanks'}
        try:
            self.api.handle_confirmation_reject(conf_id)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        cmds = self.api.load(self.api.CMDS_FILE)
        self.assertNotIn('reboot', cmds.get('d-confirm', []),
            'reject must NOT execute the action')
        # Check status persisted
        c = next(x for x in self.api.load(self.api.CONFIRMATIONS_FILE)['confirmations']
                  if x['id'] == conf_id)
        self.assertEqual(c['status'], 'rejected')

    def test_mcp_allowlist_populated(self):
        # Stage 4 must have at least these four
        self.assertIn('reboot_device', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('run_saved_script', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('force_package_scan', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('force_acme_rescan', self.api.MCP_ACTION_ALLOWLIST)


# ─── B3: OIDC SSO ───────────────────────────────────────────────────────────

class TestOidcDecoder(_ApiTestBase):
    """Unit tests for the JWT decoder + role/username mappers."""

    def _make_id_token(self, payload):
        """Synthesize a JWT (header.payload.signature) with the given payload.
        Signature is junk — we don't verify it (back-channel trust)."""
        import base64
        def _b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
        return f"{_b64({'alg': 'RS256'})}.{_b64(payload)}.signature_unused"

    def test_decode_id_token_extracts_claims(self):
        tok = self._make_id_token({'sub': 'u1', 'email': 'a@b.com', 'groups': ['admins']})
        claims = self.api._decode_id_token(tok)
        self.assertEqual(claims['sub'], 'u1')
        self.assertEqual(claims['email'], 'a@b.com')
        self.assertEqual(claims['groups'], ['admins'])

    def test_decode_id_token_rejects_malformed(self):
        with self.assertRaises(ValueError):
            self.api._decode_id_token('not.a.jwt.with.extra')
        with self.assertRaises(ValueError):
            self.api._decode_id_token('only_one_segment')

    def test_role_mapping_with_admin_group(self):
        cfg = {'oidc_admin_group': 'remotepower-admins'}
        self.assertEqual(
            self.api._oidc_role_for({'groups': ['remotepower-admins']}, cfg),
            'admin')
        self.assertEqual(
            self.api._oidc_role_for({'groups': ['other']}, cfg),
            'viewer')

    def test_role_mapping_no_admin_group_defaults_viewer(self):
        # No admin_group configured → always viewer
        self.assertEqual(self.api._oidc_role_for({'groups': ['anything']}, {}),
                         'viewer')

    def test_username_picks_preferred_username(self):
        self.assertEqual(
            self.api._oidc_username_for({
                'preferred_username': 'alice', 'email': 'a@x.com', 'sub': 'u-1'}),
            'alice')

    def test_username_falls_back_to_email_then_sub(self):
        self.assertEqual(
            self.api._oidc_username_for({'email': 'a@x.com', 'sub': 'u-1'}),
            'a@x.com')
        self.assertEqual(
            self.api._oidc_username_for({'sub': 'u-1'}),
            'u-1')


class TestOidcStart(_ApiTestBase):
    """The /api/auth/oidc/start handler — 503 when unconfigured, 302
    with state stored when configured."""

    def setUp(self):
        # Reset config to no OIDC
        self.api.save(self.api.CONFIG_FILE, {})
        self.api.save(self.api.OIDC_STATES_FILE, {})

    def test_503_when_not_configured(self):
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s
            captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_oidc_start()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 503)

    def test_state_stored_when_configured(self):
        self.api.save(self.api.CONFIG_FILE, {
            'oidc_enabled':    True,
            'oidc_issuer':     'https://idp.example.com',
            'oidc_client_id':  'rp-client',
            'oidc_client_secret': 'sek',
        })
        # Mock the metadata discovery
        self.api._OIDC_METADATA_CACHE['https://idp.example.com'] = (
            int(time.time()) + 3600,
            {'authorization_endpoint': 'https://idp.example.com/authorize',
             'token_endpoint': 'https://idp.example.com/token'},
        )
        # Mock the redirect path: handle_oidc_start sys.exit(0)s on the
        # redirect — patch sys.exit + print capture
        os.environ['HTTP_HOST'] = 'remote.example.com'
        os.environ['HTTP_X_FORWARDED_PROTO'] = 'https'
        import io, contextlib
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()):
                self.api.handle_oidc_start()
        # State should be persisted
        states = self.api.load(self.api.OIDC_STATES_FILE)
        self.assertEqual(len(states), 1)
        state_id = next(iter(states))
        self.assertIn('nonce', states[state_id])
        self.assertEqual(states[state_id]['redirect_uri'],
                          'https://remote.example.com/api/auth/oidc/callback')


# ─── B6: syslog HTTP ingestion ──────────────────────────────────────────────

class TestSyslogIngestion(_ApiTestBase):
    def setUp(self):
        # Reset state
        self.api.save(self.api.DEVICES_FILE, {
            'd-sw': {'name': 'switch01', 'log_watch': [
                {'unit': 'syslog', 'pattern': 'ERROR', 'threshold': 2, 'severity': 'CRIT'},
            ]},
        })
        self.api.save(self.api.LOG_WATCH_FILE, {})
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, {'tokens': [{
            'id': 'iwh_sl', 'label': 'sw01-syslog', 'token': 'rpwi_' + 'c' * 32,
            'kind': 'syslog', 'scope_device_id': 'd-sw', 'enabled': True,
            'created_at': 0, 'hit_count': 0,
        }]})

    def _respond_stub(self):
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        return captured, orig

    def _call_syslog(self, token, body, content_type='application/json'):
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['CONTENT_TYPE'] = content_type
        self.api.get_json_body = lambda: body
        captured, orig = self._respond_stub()
        try:
            self.api.handle_syslog_in(token)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured

    def test_json_lines_stored_with_severity(self):
        r = self._call_syslog('rpwi_' + 'c' * 32, {'lines': [
            '<14>2026-05-26 sshd: Accepted publickey',
            '<11>2026-05-26 kernel: ERROR disk',
        ]})
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['body']['lines_received'], 2)
        buf = self.api.load(self.api.LOG_WATCH_FILE)['d-sw']['units']['syslog']
        self.assertEqual(len(buf), 2)
        # <14> = facility 1, severity 6 (info); <11> = facility 1, severity 3 (err)
        self.assertEqual(buf[0]['sev'], 6)
        self.assertEqual(buf[1]['sev'], 3)
        # PRI stripped from message
        self.assertNotIn('<14>', buf[0]['line'])

    def test_log_alert_fires_when_threshold_crossed(self):
        # 2 matching ERROR lines → threshold=2 fires
        self._call_syslog('rpwi_' + 'c' * 32, {'lines': [
            '<11>kernel: ERROR a',
            '<11>kernel: ERROR b',
            '<14>noise: ok',
        ]})
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        log_alerts = [a for a in alerts if a['event'] == 'log_alert']
        self.assertEqual(len(log_alerts), 1)
        self.assertEqual(log_alerts[0]['payload']['unit'], 'syslog')

    def test_wrong_kind_token_rejected(self):
        # An alert-kind token cannot post to /api/syslog/in/
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, {'tokens': [{
            'id': 'iwh_a', 'label': 'alert-token', 'token': 'rpwi_' + 'd' * 32,
            'kind': 'alert', 'scope_device_id': 'd-sw', 'enabled': True,
            'created_at': 0, 'hit_count': 0,
        }]})
        r = self._call_syslog('rpwi_' + 'd' * 32, {'lines': ['<11>x']})
        self.assertEqual(r['status'], 400)
        self.assertIn('token', r['body']['error'])

    def test_syslog_requires_pinned_device(self):
        self.api.save(self.api.INBOUND_WEBHOOKS_FILE, {'tokens': [{
            'id': 'iwh_unpinned', 'label': 'unpinned', 'token': 'rpwi_' + 'e' * 32,
            'kind': 'syslog', 'scope_device_id': None, 'enabled': True,
            'created_at': 0, 'hit_count': 0,
        }]})
        r = self._call_syslog('rpwi_' + 'e' * 32, {'lines': ['<11>x']})
        self.assertEqual(r['status'], 400)


# ─── B5: SNMP module + integration ──────────────────────────────────────────

class TestSnmpModule(unittest.TestCase):
    """Pure-Python BER encoder/decoder + message construction round trip."""

    def setUp(self):
        import importlib, sys
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        if 'snmp' in sys.modules:
            del sys.modules['snmp']
        self.snmp = importlib.import_module('snmp')

    def test_oid_round_trip(self):
        for oid in ['1.3.6.1.2.1.1.5.0', '1.3.6.1.4.1.99.1', '1.3']:
            enc = self.snmp._encode_oid(oid)
            tag, body, _ = self.snmp._decode_tlv(enc, 0)
            self.assertEqual(self.snmp._decode_oid(body), oid)

    def test_integer_signed_round_trip(self):
        for n in [0, 1, 127, 128, 255, 256, 65535, -1, -128, -65535]:
            enc = self.snmp._encode_integer(n)
            tag, body, _ = self.snmp._decode_tlv(enc, 0)
            self.assertEqual(self.snmp._decode_integer(body), n)

    def test_get_request_response_parse(self):
        msg = self.snmp._build_get_request('public', 42,
            ['1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.1.0'])
        # Construct a matching response
        vbs = (
            self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
                self.snmp._encode_oid('1.3.6.1.2.1.1.5.0') +
                self.snmp._encode_octet_string('sw-test')) +
            self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
                self.snmp._encode_oid('1.3.6.1.2.1.1.1.0') +
                self.snmp._encode_octet_string('Test Switch'))
        )
        pdu = self.snmp._encode_tlv(self.snmp.PDU_GET_RESPONSE,
            self.snmp._encode_integer(42) +
            self.snmp._encode_integer(0) +
            self.snmp._encode_integer(0) +
            self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE, vbs))
        resp = self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
            self.snmp._encode_integer(self.snmp.SNMP_V2C) +
            self.snmp._encode_octet_string('public') + pdu)
        parsed = self.snmp._parse_response(resp, 42)
        self.assertEqual(parsed['1.3.6.1.2.1.1.5.0'], 'sw-test')
        self.assertEqual(parsed['1.3.6.1.2.1.1.1.0'], 'Test Switch')

    def test_walk_returns_subtree(self):
        """End-to-end walk against a fake UDP server that serves 3 entries
        in the ifDescr subtree (.2.2.1.2.1 / .2 / .3) then walks off."""
        import socket, threading
        port_box = []
        ready = threading.Event()
        # Walk targets: GETNEXT 1.3.6.1.2.1.2.2.1.2 → returns .2.2.1.2.1
        # GETNEXT .2.2.1.2.1 → .2.2.1.2.2
        # GETNEXT .2.2.1.2.2 → .2.2.1.2.3
        # GETNEXT .2.2.1.2.3 → .2.2.1.3.1 (out of subtree → stop)
        responses = [
            ('1.3.6.1.2.1.2.2.1.2.1', 'eth0'),
            ('1.3.6.1.2.1.2.2.1.2.2', 'eth1'),
            ('1.3.6.1.2.1.2.2.1.2.3', 'eth2'),
            ('1.3.6.1.2.1.2.2.1.3.1', 6),    # Out of subtree
        ]
        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            port_box.append(sock.getsockname()[1])
            ready.set()
            sock.settimeout(5)
            try:
                for oid, value in responses:
                    data, addr = sock.recvfrom(65536)
                    tag, body, _ = self.snmp._decode_tlv(data, 0)
                    off = 0
                    _, _, off = self.snmp._decode_tlv(body, off)    # version
                    _, _, off = self.snmp._decode_tlv(body, off)    # community
                    pdu_tag, pdu_body, _ = self.snmp._decode_tlv(body, off)
                    _, rid_bytes, _ = self.snmp._decode_tlv(pdu_body, 0)
                    rid = self.snmp._decode_integer(rid_bytes)
                    if isinstance(value, str):
                        v_enc = self.snmp._encode_octet_string(value)
                    else:
                        v_enc = self.snmp._encode_integer(value)
                    vbs = self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
                        self.snmp._encode_oid(oid) + v_enc)
                    pdu = self.snmp._encode_tlv(self.snmp.PDU_GET_RESPONSE,
                        self.snmp._encode_integer(rid) +
                        self.snmp._encode_integer(0) +
                        self.snmp._encode_integer(0) +
                        self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE, vbs))
                    msg = self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
                        self.snmp._encode_integer(self.snmp.SNMP_V2C) +
                        self.snmp._encode_octet_string('public') + pdu)
                    sock.sendto(msg, addr)
            finally:
                sock.close()
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        ready.wait(timeout=2)
        results = self.snmp.snmp_walk('127.0.0.1', 'public',
            '1.3.6.1.2.1.2.2.1.2', port=port_box[0], timeout=2)
        t.join(timeout=3)
        # Should have 3 entries (stopped before the out-of-subtree one)
        self.assertEqual(len(results), 3)
        self.assertIn('1.3.6.1.2.1.2.2.1.2.1', results)
        self.assertEqual(results['1.3.6.1.2.1.2.2.1.2.1'], 'eth0')
        self.assertEqual(results['1.3.6.1.2.1.2.2.1.2.3'], 'eth2')
        self.assertNotIn('1.3.6.1.2.1.2.2.1.3.1', results,
                          'walk must stop at subtree boundary')

    def test_request_id_mismatch_raises(self):
        # Build a response for a different request_id
        vbs = self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
            self.snmp._encode_oid('1.3.6.1.2.1.1.5.0') +
            self.snmp._encode_null())
        pdu = self.snmp._encode_tlv(self.snmp.PDU_GET_RESPONSE,
            self.snmp._encode_integer(999) +
            self.snmp._encode_integer(0) + self.snmp._encode_integer(0) +
            self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE, vbs))
        resp = self.snmp._encode_tlv(self.snmp.TAG_SEQUENCE,
            self.snmp._encode_integer(self.snmp.SNMP_V2C) +
            self.snmp._encode_octet_string('public') + pdu)
        with self.assertRaises(self.snmp.SnmpError):
            self.snmp._parse_response(resp, expected_request_id=42)


class TestSnmpIntegration(_ApiTestBase):
    """SNMP polling integration with api.py — uses a fake in-process UDP server."""

    def _start_fake_snmp(self, response_overrides=None):
        """Return (port, thread). The fake responds to one request then exits."""
        import socket, threading
        port_box = []
        ready = threading.Event()
        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            port_box.append(sock.getsockname()[1])
            ready.set()
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(65536)
                import snmp as s
                tag, body, _ = s._decode_tlv(data, 0)
                off = 0
                _, _, off = s._decode_tlv(body, off)    # version
                _, _, off = s._decode_tlv(body, off)    # community
                pdu_tag, pdu_body, _ = s._decode_tlv(body, off)
                _, rid_bytes, _ = s._decode_tlv(pdu_body, 0)
                rid = s._decode_integer(rid_bytes)
                values = response_overrides or {
                    '1.3.6.1.2.1.1.1.0': ('octet', 'Test Switch v1'),
                    '1.3.6.1.2.1.1.5.0': ('octet', 'sw-fake'),
                }
                vbs = b''
                for oid, (typ, val) in values.items():
                    if typ == 'octet':
                        v_bytes = s._encode_octet_string(val)
                    else:
                        v_bytes = s._encode_null()
                    vbs += s._encode_tlv(s.TAG_SEQUENCE, s._encode_oid(oid) + v_bytes)
                pdu = s._encode_tlv(s.PDU_GET_RESPONSE,
                    s._encode_integer(rid) + s._encode_integer(0) +
                    s._encode_integer(0) + s._encode_tlv(s.TAG_SEQUENCE, vbs))
                msg = s._encode_tlv(s.TAG_SEQUENCE,
                    s._encode_integer(s.SNMP_V2C) +
                    s._encode_octet_string('public') + pdu)
                sock.sendto(msg, addr)
            except Exception:
                pass
            finally:
                sock.close()
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        ready.wait(timeout=2)
        return port_box[0], t

    def setUp(self):
        self.api.save(self.api.SNMP_DATA_FILE, {})

    def test_poll_stores_sysname_and_descr(self):
        port, t = self._start_fake_snmp()
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'fake', 'ip': '127.0.0.1', 'agentless': True,
                     'snmp': {'enabled': True, 'community': 'public', 'port': port}},
        })
        dev = self.api.load(self.api.DEVICES_FILE)['d-1']
        entry = self.api._do_snmp_poll('d-1', dev)
        t.join(timeout=3)
        self.assertEqual(entry['sysDescr'], 'Test Switch v1')
        self.assertEqual(entry['sysName'], 'sw-fake')
        self.assertIsNone(entry['last_error'])
        stored = self.api.load(self.api.SNMP_DATA_FILE)['d-1']
        self.assertEqual(stored['sysName'], 'sw-fake')

    def test_poll_timeout_records_error(self):
        # Device IP that won't respond
        self.api.save(self.api.DEVICES_FILE, {
            'd-2': {'name': 'no-host', 'ip': '127.0.0.1',
                     'snmp': {'enabled': True, 'community': 'public', 'port': 1}},
        })
        # Point at an unused port and 0.5s timeout via direct call
        import snmp
        with self.assertRaises(snmp.SnmpError):
            snmp.snmp_get('127.0.0.1', 'public', ['1.3.6.1.2.1.1.5.0'],
                          port=1, timeout=0.5, retries=0)

    def test_target_helper_rejects_missing_community(self):
        dev = {'name': 'x', 'ip': '1.2.3.4',
               'snmp': {'enabled': True, 'community': '', 'port': 161}}
        self.assertIsNone(self.api._device_snmp_target(dev))

    def test_target_helper_rejects_disabled(self):
        dev = {'name': 'x', 'ip': '1.2.3.4',
               'snmp': {'enabled': False, 'community': 'public'}}
        self.assertIsNone(self.api._device_snmp_target(dev))

    def test_get_endpoint_redacts_community(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'x', 'ip': '1.2.3.4',
                     'snmp': {'enabled': True, 'community': 'secretpub', 'port': 161}},
        })
        # Seed an admin session
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = tok
        os.environ['REQUEST_METHOD'] = 'GET'
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_device_snmp('d-1')
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        cfg = captured['body']['config']
        self.assertNotIn('community', cfg, 'raw community must not leak')
        self.assertIn('community_preview', cfg)
        self.assertTrue(cfg['has_community'])


# ─── Follow-up fixes (#1–#6 batch) ─────────────────────────────────────────

class TestSnmpValidation(_ApiTestBase):
    """Server-side validation guards on the PATCH SNMP endpoint."""

    def setUp(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'sw', 'ip': '10.0.0.1'},
            'd-2': {'name': 'no-ip'},   # No ip/hostname/host — disallow enable
        })
        # Admin session
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = self.tok

    def _patch(self, dev_id, body):
        os.environ['REQUEST_METHOD'] = 'PATCH'
        self.api.get_json_body = lambda: body
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_device_snmp(dev_id)
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured

    def test_enable_without_community_400(self):
        r = self._patch('d-1', {'enabled': True})
        self.assertEqual(r['status'], 400)
        self.assertIn('community', r['body']['error'])

    def test_enable_without_ip_400(self):
        r = self._patch('d-2', {'enabled': True, 'community': 'public'})
        self.assertEqual(r['status'], 400)
        self.assertIn('ip', r['body']['error'])

    def test_community_with_whitespace_400(self):
        r = self._patch('d-1', {'community': 'has space'})
        self.assertEqual(r['status'], 400)
        self.assertIn('whitespace', r['body']['error'])

    def test_port_out_of_range_400(self):
        r = self._patch('d-1', {'community': 'public', 'port': 99999})
        self.assertEqual(r['status'], 400)

    def test_valid_save_200(self):
        r = self._patch('d-1', {'enabled': True, 'community': 'public', 'port': 161})
        self.assertEqual(r['status'], 200)

    def test_disable_without_community_ok(self):
        # Disabling shouldn't require community
        r = self._patch('d-1', {'enabled': False})
        self.assertEqual(r['status'], 200)


class TestSyslogParser(unittest.TestCase):
    def setUp(self):
        import sys, importlib
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        if 'api' in sys.modules:
            del sys.modules['api']
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp_syslog_')
        import api
        self.api = api

    def test_pri_zero_emerg(self):
        sev, msg = self.api._parse_syslog_line('<0>kernel panic')
        self.assertEqual(sev, 0)
        self.assertEqual(msg, 'kernel panic')

    def test_pri_max_legal(self):
        # PRI 191 = facility 23 × 8 + severity 7
        sev, msg = self.api._parse_syslog_line('<191>foo')
        self.assertEqual(sev, 7)

    def test_pri_out_of_range_falls_back(self):
        sev, msg = self.api._parse_syslog_line('<999>weird')
        self.assertEqual(sev, 6)
        # Whole input preserved because the PRI was rejected
        self.assertEqual(msg, '<999>weird')

    def test_no_pri_defaults_to_info(self):
        sev, msg = self.api._parse_syslog_line('plain line no pri')
        self.assertEqual(sev, 6)
        self.assertEqual(msg, 'plain line no pri')

    def test_line_truncation(self):
        sev, msg = self.api._parse_syslog_line('<14>' + 'a' * 5000)
        # Truncated to MAX_SYSLOG_LINE (2048) - PRI prefix len = 2044
        self.assertLessEqual(len(msg), 2048)

    def test_crlf_stripped(self):
        sev, msg = self.api._parse_syslog_line('<14>foo\r\n')
        self.assertEqual(msg, 'foo')


class TestOidcValidationAndTest(_ApiTestBase):
    def setUp(self):
        self.api.save(self.api.CONFIG_FILE, {})
        # Admin session
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = self.tok

    def _save_config(self, body):
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: body
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_config_save()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured

    def test_enable_without_required_fields_400(self):
        r = self._save_config({'oidc_enabled': True, 'oidc_issuer': 'https://idp.example.com'})
        self.assertEqual(r['status'], 400)
        self.assertIn('oidc_client_id', r['body']['error'])

    def test_issuer_must_have_scheme(self):
        r = self._save_config({'oidc_issuer': 'idp.example.com'})
        self.assertEqual(r['status'], 400)
        self.assertIn('http', r['body']['error'])

    def test_issuer_must_have_hostname(self):
        r = self._save_config({'oidc_issuer': 'https://'})
        self.assertEqual(r['status'], 400)

    def test_issuer_whitespace_rejected(self):
        r = self._save_config({'oidc_issuer': 'https://idp.example.com /foo'})
        self.assertEqual(r['status'], 400)
        self.assertIn('whitespace', r['body']['error'])

    def test_save_clears_discovery_cache(self):
        # Pre-seed the cache to confirm save clears it
        self.api._OIDC_METADATA_CACHE['https://stale.example.com'] = (
            int(time.time()) + 999, {'authorization_endpoint': 'x'})
        r = self._save_config({'oidc_issuer': 'https://new.example.com',
                                'oidc_client_id': 'rp',
                                'oidc_client_secret': 'sek'})
        self.assertEqual(r['status'], 200)
        self.assertNotIn('https://stale.example.com',
                         self.api._OIDC_METADATA_CACHE)

    def test_test_endpoint_503_when_unconfigured(self):
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {}
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_oidc_test()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        # No issuer set → 400 not 503 (config is invalid, not the IdP)
        self.assertEqual(captured['status'], 400)

    def test_test_endpoint_returns_endpoints(self):
        # Pre-seed config + metadata cache so we don't actually make an HTTP call
        self.api.save(self.api.CONFIG_FILE, {
            'oidc_issuer':        'https://idp.example.com',
            'oidc_client_id':     'rp',
            'oidc_client_secret': 'sek',
        })
        # The cache is cleared on entry to handle_oidc_test; to skip the real
        # fetch we monkey-patch _oidc_discover.
        def fake_discover(_issuer):
            return {
                'issuer': 'https://idp.example.com',
                'authorization_endpoint': 'https://idp.example.com/authorize',
                'token_endpoint':         'https://idp.example.com/token',
                'jwks_uri':               'https://idp.example.com/jwks',
                'scopes_supported':       ['openid', 'profile', 'email'],
            }
        orig_discover = self.api._oidc_discover
        self.api._oidc_discover = fake_discover
        os.environ['HTTP_HOST'] = 'remote.example.com'
        os.environ['HTTPS'] = 'on'
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {}
        captured = {}
        orig_resp = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_oidc_test()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig_resp
            self.api._oidc_discover = orig_discover
        self.assertEqual(captured['status'], 200)
        self.assertTrue(captured['body']['ok'])
        self.assertEqual(captured['body']['endpoints']['token'],
                          'https://idp.example.com/token')
        # client_secret_set must be True
        self.assertTrue(captured['body']['client_secret_set'])

    def test_test_endpoint_warnings_for_missing_secret(self):
        self.api.save(self.api.CONFIG_FILE, {
            'oidc_issuer':    'https://idp.example.com',
            'oidc_client_id': 'rp',
            # client_secret deliberately missing
        })
        def fake_discover(_issuer):
            return {
                'issuer': 'https://idp.example.com',
                'authorization_endpoint': 'https://idp.example.com/authorize',
                'token_endpoint':         'https://idp.example.com/token',
                'scopes_supported':       ['openid', 'profile'],
            }
        orig_discover = self.api._oidc_discover
        self.api._oidc_discover = fake_discover
        os.environ['HTTP_HOST'] = 'r.x'
        os.environ['REQUEST_METHOD'] = 'POST'
        self.api.get_json_body = lambda: {}
        captured = {}
        orig_resp = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_oidc_test()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig_resp
            self.api._oidc_discover = orig_discover
        self.assertIn('oidc_client_secret not configured',
                      captured['body']['warnings'])


class TestSelfStatusWebhookRate(_ApiTestBase):
    """The webhook delivery rate must not count suppressed/disabled/filtered
    log entries as attempts. Regression for the v3.2.0 "1/10 = 10%" bug
    on dashboards where every event was suppressed."""

    def setUp(self):
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = self.tok
        os.environ['REQUEST_METHOD'] = 'GET'

    def _self_status(self):
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_self_status()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured['body']

    def test_suppressed_entries_not_counted_as_attempts(self):
        now = int(time.time())
        self.api.save(self.api.WEBHOOK_LOG_FILE, {'entries': [
            # 1 real successful attempt
            {'ts': now, 'event': 'device_offline', 'url': 'h://x', 'status': '200',  'detail': 'OK (200) [generic]'},
            # 9 suppressed (event disabled, in maintenance, etc.)
            *[{'ts': now, 'event': 'patch_alert', 'url': 'h://x',
               'status': 'disabled', 'detail': '...'} for _ in range(9)],
        ]})
        s = self._self_status()
        w24 = s['webhooks']['last_24h']
        self.assertEqual(w24['attempts'], 1, 'only the real POST counts as an attempt')
        self.assertEqual(w24['success'], 1)
        self.assertAlmostEqual(w24['rate'], 1.0)
        self.assertEqual(w24['skipped'], 9)

    def test_all_skipped_returns_none_rate(self):
        now = int(time.time())
        self.api.save(self.api.WEBHOOK_LOG_FILE, {'entries': [
            {'ts': now, 'event': 'x', 'url': 'h', 'status': 'disabled', 'detail': ''},
            {'ts': now, 'event': 'x', 'url': 'h', 'status': 'suppressed', 'detail': ''},
            {'ts': now, 'event': 'x', 'url': 'h', 'status': 'filtered',  'detail': ''},
        ]})
        s = self._self_status()
        w24 = s['webhooks']['last_24h']
        self.assertEqual(w24['attempts'], 0)
        self.assertIsNone(w24['rate'])
        self.assertEqual(w24['skipped'], 3)

    def test_real_failure_counted(self):
        now = int(time.time())
        self.api.save(self.api.WEBHOOK_LOG_FILE, {'entries': [
            {'ts': now, 'event': 'x', 'url': 'h', 'status': '200',   'detail': 'OK'},
            {'ts': now, 'event': 'x', 'url': 'h', 'status': '500',   'detail': 'fail'},
            {'ts': now, 'event': 'x', 'url': 'h', 'status': 'error', 'detail': 'TLS handshake'},
        ]})
        s = self._self_status()
        w24 = s['webhooks']['last_24h']
        self.assertEqual(w24['attempts'], 3)
        self.assertEqual(w24['success'], 1)


class TestBearerAuthParity(_ApiTestBase):
    """v3.2.0 generalised Bearer auth to every endpoint (was /api/metrics only).
    Confirm that `Authorization: Bearer <t>` is treated EXACTLY the same as
    `X-Token: <t>` — same role, same admin gate, same TTL. Regression for
    the security-review concern: no endpoint should treat the two headers
    differently."""

    def setUp(self):
        # Two API keys: one viewer, one admin
        apikeys = self.api.load(self.api.APIKEYS_FILE)
        apikeys['v'] = {'name': 'v', 'key': 'rpk_v_test', 'user': 'v',
                         'role': 'viewer', 'created': int(time.time()),
                         'active': True, 'expires_at': None}
        apikeys['a'] = {'name': 'a', 'key': 'rpk_a_test', 'user': 'a',
                         'role': 'admin', 'created': int(time.time()),
                         'active': True, 'expires_at': None}
        self.api.save(self.api.APIKEYS_FILE, apikeys)
        # Clear both headers between tests
        for k in ('HTTP_X_TOKEN', 'HTTP_AUTHORIZATION'):
            os.environ.pop(k, None)

    def test_x_token_resolves(self):
        os.environ['HTTP_X_TOKEN'] = 'rpk_v_test'
        u, r = self.api.verify_token(self.api.get_token_from_request())
        self.assertEqual(u, 'v')
        self.assertEqual(r, 'viewer')

    def test_bearer_resolves_identically(self):
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer rpk_v_test'
        u, r = self.api.verify_token(self.api.get_token_from_request())
        self.assertEqual(u, 'v')
        self.assertEqual(r, 'viewer')

    def test_bearer_case_insensitive(self):
        # The RFC says the scheme name is case-insensitive
        for prefix in ('Bearer ', 'BEARER ', 'bearer ', 'BeArEr '):
            os.environ['HTTP_AUTHORIZATION'] = prefix + 'rpk_v_test'
            u, r = self.api.verify_token(self.api.get_token_from_request())
            self.assertEqual(u, 'v', f'Bearer prefix {prefix!r} failed')

    def test_x_token_wins_when_both_set(self):
        """Documented behaviour: X-Token has priority. Helps the dashboard
        keep working when an external proxy injects a stray Authorization
        header."""
        os.environ['HTTP_X_TOKEN']      = 'rpk_v_test'
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer rpk_a_test'
        u, r = self.api.verify_token(self.api.get_token_from_request())
        self.assertEqual(u, 'v',  'X-Token must take priority')
        self.assertEqual(r, 'viewer')

    def test_admin_gate_applies_to_bearer(self):
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer rpk_v_test'
        # Viewer can't pass admin gate regardless of header used
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_admin_auth()
        self.assertEqual(ctx.exception.status, 403)

    def test_admin_via_bearer_succeeds(self):
        os.environ['HTTP_AUTHORIZATION'] = 'Bearer rpk_a_test'
        self.assertEqual(self.api.require_admin_auth(), 'a')

    def test_malformed_authorization_falls_through_to_401(self):
        for bad in ('Basic dXNlcjpwYXNz', 'rpk_v_test', 'Token rpk_v_test', ''):
            os.environ['HTTP_AUTHORIZATION'] = bad
            tok = self.api.get_token_from_request()
            # No X-Token, malformed Authorization → empty token
            self.assertEqual(tok, '', f'malformed {bad!r} should not auth')


class TestSnmpThresholdAlerting(_ApiTestBase):
    """SNMP-derived metrics flow through the same threshold pipeline as
    agent metrics. metric_warning / metric_critical / metric_recovered
    events fire when polled values cross thresholds — and the row lands
    in the alerts inbox (because metric_warning is _ALERT_RULES-mapped)."""

    def setUp(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.api.save(self.api.DEVICES_FILE, {
            'd-sw': {
                'name': 'switch01', 'monitored': True,
                'metric_state': {},
                # default thresholds — snmp_cpu warn=75 crit=90, temp warn=70 crit=85
            },
        })

    def test_snmp_cpu_threshold_fires(self):
        # Build a synthetic SNMP entry with high CPU
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        snmp_entry = {
            'processors': [
                {'index': 1, 'load_pct': 80},
                {'index': 2, 'load_pct': 85},
            ],   # avg 82.5 → above warn=75
            'storage': [],
            'vendor': {},
        }
        self.api.process_snmp_metric_thresholds('d-sw', dev, snmp_entry)
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        metric_alerts = [a for a in alerts if a['event'] == 'metric_warning']
        self.assertEqual(len(metric_alerts), 1)
        self.assertEqual(metric_alerts[0]['payload'].get('metric'), 'snmp_cpu')

    def test_snmp_cpu_critical_at_90(self):
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        snmp_entry = {
            'processors': [{'index': 1, 'load_pct': 95}],
            'storage': [], 'vendor': {},
        }
        self.api.process_snmp_metric_thresholds('d-sw', dev, snmp_entry)
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        crits = [a for a in alerts if a['event'] == 'metric_critical']
        self.assertEqual(len(crits), 1)

    def test_temperature_threshold_fires(self):
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        # Mikrotik returns temp in tenths-of-deg: 800 = 80°C → above warn=70
        snmp_entry = {
            'processors': [], 'storage': [],
            'vendor': {'mtxrHlBoardTemp': 800},
        }
        self.api.process_snmp_metric_thresholds('d-sw', dev, snmp_entry)
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        # 80°C is above warn=70 but below crit=85 → warning
        warns = [a for a in alerts if a['event'] == 'metric_warning']
        self.assertEqual(len(warns), 1)
        self.assertEqual(warns[0]['payload'].get('metric'), 'temp_board')

    def test_unmonitored_no_threshold_alert(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-sw': {'name': 'sw', 'monitored': False, 'metric_state': {}},
        })
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        snmp_entry = {
            'processors': [{'index': 1, 'load_pct': 99}],
            'storage': [], 'vendor': {},
        }
        self.api.process_snmp_metric_thresholds('d-sw', dev, snmp_entry)
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(alerts), 0,
            'unmonitored devices must not page on SNMP thresholds')

    def test_recovery_clears_state(self):
        # First poll: high → fires warning
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        self.api.process_snmp_metric_thresholds('d-sw', dev,
            {'processors': [{'index': 1, 'load_pct': 85}],
             'storage': [], 'vendor': {}})
        # Reload dev (state was persisted)
        dev = self.api.load(self.api.DEVICES_FILE)['d-sw']
        # Second poll: drops well below warn-buffer (75-5=70)
        self.api.process_snmp_metric_thresholds('d-sw', dev,
            {'processors': [{'index': 1, 'load_pct': 50}],
             'storage': [], 'vendor': {}})
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        # Should have one warning AND one recovered event in the fleet log
        # (but only the warning makes it into alerts inbox since
        #  metric_recovered isn't in _ALERT_RULES)
        warns = [a for a in alerts if a['event'] == 'metric_warning']
        self.assertEqual(len(warns), 1)


class TestAlertsClear(_ApiTestBase):
    """Bulk-purge endpoints for the Alerts page."""

    def setUp(self):
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        # Seed three alerts in different states
        self.api.save(self.api.ALERTS_FILE, {'alerts': [
            {'id': 'a-1', 'event': 'x', 'severity': 'high',
             'ts': 1, 'title': 'open', 'payload': {},
             'acknowledged_at': None, 'resolved_at': None,
             'acknowledged_by': None, 'resolved_by': None},
            {'id': 'a-2', 'event': 'x', 'severity': 'high',
             'ts': 2, 'title': 'ack', 'payload': {},
             'acknowledged_at': 100, 'resolved_at': None,
             'acknowledged_by': 'u', 'resolved_by': None},
            {'id': 'a-3', 'event': 'x', 'severity': 'high',
             'ts': 3, 'title': 'resolved', 'payload': {},
             'acknowledged_at': 100, 'resolved_at': 200,
             'acknowledged_by': 'u', 'resolved_by': 'u'},
        ]})
        os.environ['HTTP_X_TOKEN'] = self.tok

    def _delete(self, qs=''):
        os.environ['REQUEST_METHOD'] = 'DELETE'
        os.environ['QUERY_STRING'] = qs
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_alerts_clear()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        return captured

    def test_clear_resolved_keeps_open_and_ack(self):
        r = self._delete('scope=resolved')
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['body']['removed'], 1)
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual({a['id'] for a in rows}, {'a-1', 'a-2'})

    def test_clear_all_wipes_everything(self):
        r = self._delete('scope=all')
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['body']['removed'], 3)
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(rows, [])

    def test_clear_invalid_scope_400(self):
        r = self._delete('scope=bogus')
        self.assertEqual(r['status'], 400)

    def test_clear_default_is_resolved(self):
        r = self._delete('')
        self.assertEqual(r['status'], 200)
        self.assertEqual(r['body']['removed'], 1)


class TestUnmonitoredAlertSuppression(_ApiTestBase):
    """Regression: alerts.json must not gain rows for unmonitored devices.

    Reported on the live v3.2.0 deploy: a log_alert on host `jaove` showed
    up in the Open inbox even though that device is monitored=false. The
    fix puts the same monitored-gate inside _record_alert that fire_webhook
    already has on its outbound fan-out path.

    Suppression scope:
      * device-scoped events on unmonitored devices → skip
      * fleet-wide events (no device_id) → still record
      * inbound webhooks / syslog (different code paths) → still record
        (those have their own scope_device_id pinning but the alert
        record itself doesn't go through _record_alert with device_id
        from a monitored host)
    """

    def setUp(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})

    def test_unmonitored_device_alert_skipped(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-unmon': {'name': 'jaove', 'monitored': False},
        })
        self.api.fire_webhook('log_alert', {
            'device_id': 'd-unmon', 'device_name': 'jaove',
            'unit':      'system',
            'pattern':   'error',
            'level':     'warning',
            'count':     3,
        })
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(rows, [],
            'unmonitored device log_alert must not enter alerts inbox')

    def test_monitored_device_alert_still_recorded(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd-mon': {'name': 'web01', 'monitored': True},
        })
        self.api.fire_webhook('log_alert', {
            'device_id': 'd-mon', 'device_name': 'web01',
            'unit':      'nginx',
            'pattern':   '5[0-9][0-9]',
            'level':     'warning',
            'count':     5,
        })
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['event'], 'log_alert')

    def test_fleetwide_event_still_recorded(self):
        # No device_id → not a per-device event, must record
        self.api.fire_webhook('cve_found', {
            'critical': 0, 'high': 2,
            # no device_id
        })
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1)

    def test_unknown_device_id_still_recorded(self):
        # device_id present but devices.json doesn't have it (e.g. deleted)
        # → fall through and record. Operators can still see orphan alerts.
        self.api.save(self.api.DEVICES_FILE, {})
        self.api.fire_webhook('log_alert', {
            'device_id': 'd-ghost', 'device_name': 'gone',
            'unit':      'x', 'pattern': 'y', 'level': 'warning', 'count': 1,
        })
        rows = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len(rows), 1)


class TestSnmpAlertsMonitored(_ApiTestBase):
    """SNMP failure/recovery events must respect the monitored flag and
    fire exactly once on the transition."""

    def setUp(self):
        self.api.save(self.api.SNMP_DATA_FILE, {})
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        # v3.2.0 follow-up: _record_alert re-reads DEVICES_FILE to apply
        # the monitored gate. Clear DEVICES_FILE per-test so prior tests
        # that set monitored=False on the same dev_id can't leak through.
        self.api.save(self.api.DEVICES_FILE, {})

    def _patch_poll(self, dev_id, dev, raises=None, sysname='sw'):
        """Stub the SNMP module to either return synthetic data or raise."""
        import snmp
        orig_poll = snmp.poll_system
        def fake_poll(*a, **kw):
            if raises:
                raise raises
            return {'sysDescr': 'Test', 'sysName': sysname,
                    'sysUpTime': 100000, 'sysContact': '', 'sysLocation': '',
                    'sysObjectID': '1.3.6.1.4.1.1', '_oids': {}}
        snmp.poll_system = fake_poll
        try:
            return self.api._do_snmp_poll(dev_id, dev)
        finally:
            snmp.poll_system = orig_poll

    def test_unreachable_fires_only_on_second_fail(self):
        dev = {'name': 'sw', 'ip': '10.0.0.1', 'monitored': True,
               'snmp': {'enabled': True, 'community': 'public', 'port': 161}}
        # First failure — no alert yet
        self._patch_poll('d-1', dev, raises=RuntimeError('timeout'))
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len([a for a in alerts if a['event'] == 'snmp_unreachable']), 0,
                          'first failure must not page')
        # Second failure — single alert fires
        self._patch_poll('d-1', dev, raises=RuntimeError('timeout'))
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        unreach = [a for a in alerts if a['event'] == 'snmp_unreachable']
        self.assertEqual(len(unreach), 1)
        # Third failure — still just one (edge-triggered)
        self._patch_poll('d-1', dev, raises=RuntimeError('timeout'))
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len([a for a in alerts if a['event'] == 'snmp_unreachable']), 1,
                          'edge-triggered: subsequent fails must not repeat')

    def test_unmonitored_device_no_alert(self):
        dev = {'name': 'sw', 'ip': '10.0.0.1', 'monitored': False,
               'snmp': {'enabled': True, 'community': 'public', 'port': 161}}
        # Two consecutive failures
        self._patch_poll('d-1', dev, raises=RuntimeError('x'))
        self._patch_poll('d-1', dev, raises=RuntimeError('x'))
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        self.assertEqual(len([a for a in alerts if a['event'] == 'snmp_unreachable']), 0,
                          'unmonitored devices must not page')
        # But the failure DATA should be stored — operator can still see it
        stored = self.api.load(self.api.SNMP_DATA_FILE).get('d-1', {})
        self.assertEqual(stored.get('consecutive_fails'), 2,
                          'unmonitored devices still collect data')
        self.assertIsNotNone(stored.get('last_error'))

    def test_unmonitored_device_polled_in_sweep(self):
        """run_snmp_polls_if_due() must include unmonitored devices —
        we collect data but skip the alert fire. Same posture as the
        agent's metric pipeline."""
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'unmon', 'ip': '127.0.0.1', 'monitored': False,
                    'snmp': {'enabled': True, 'community': 'public', 'port': 1}},
        })
        # Stub the SNMP module to count invocations
        import snmp
        calls = []
        orig = snmp.poll_system
        def counting_poll(*a, **kw):
            calls.append((a, kw))
            raise RuntimeError('simulated timeout')
        snmp.poll_system = counting_poll
        try:
            # Force the sweep to run by clearing last_snmp_poll
            cfg = self.api.load(self.api.CONFIG_FILE)
            cfg['last_snmp_poll'] = 0
            self.api.save(self.api.CONFIG_FILE, cfg)
            self.api.run_snmp_polls_if_due()
        finally:
            snmp.poll_system = orig
        self.assertEqual(len(calls), 1,
                          'unmonitored device must still be polled')

    def test_recover_resolves_existing_alert(self):
        dev = {'name': 'sw', 'ip': '10.0.0.1', 'monitored': True,
               'snmp': {'enabled': True, 'community': 'public', 'port': 161}}
        # Two fails → unreachable alert created
        self._patch_poll('d-1', dev, raises=RuntimeError('x'))
        self._patch_poll('d-1', dev, raises=RuntimeError('x'))
        # Recovery — the matching alert auto-resolves via _auto_resolve_alerts
        self._patch_poll('d-1', dev)
        alerts = self.api.load(self.api.ALERTS_FILE).get('alerts', [])
        unreach = [a for a in alerts if a['event'] == 'snmp_unreachable']
        self.assertEqual(len(unreach), 1)
        self.assertEqual(unreach[0]['resolved_by'], 'auto')


class TestSelfStatusPerformance(_ApiTestBase):
    """The performance block on /api/self/status."""

    def setUp(self):
        users = self.api.load(self.api.USERS_FILE)
        users['admin'] = {'password_hash': self.api.hash_password('x'), 'role': 'admin'}
        self.api.save(self.api.USERS_FILE, users)
        self.tok = 'admin_' + os.urandom(8).hex()
        toks = self.api.load(self.api.TOKENS_FILE)
        toks[self.tok] = {'user': 'admin', 'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, toks)
        os.environ['HTTP_X_TOKEN'] = self.tok

    def test_self_status_includes_performance(self):
        os.environ['REQUEST_METHOD'] = 'GET'
        captured = {}
        orig = self.api.respond
        def cap(s, b=None):
            captured['status'] = s; captured['body'] = b
            raise self.api.HTTPError(s, b or {})
        self.api.respond = cap
        try:
            self.api.handle_self_status()
        except self.api.HTTPError:
            pass
        finally:
            self.api.respond = orig
        self.assertEqual(captured['status'], 200)
        self.assertIn('performance', captured['body'])
        perf = captured['body']['performance']
        # On Linux these should be present
        if os.path.exists('/proc/loadavg'):
            self.assertIn('load_avg', perf)
            self.assertIn('1m', perf['load_avg'])
        if os.path.exists('/proc/meminfo'):
            self.assertIn('memory', perf)
            self.assertIn('used_pct', perf['memory'])
        self.assertIn('sessions', perf)
        self.assertIn('health', perf)
        self.assertIsInstance(perf.get('health_flags'), list)


# ─── v3.2.0 strict version pins ─────────────────────────────────────────────

class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.2.1 now holds the strict pin (test_v321.py)."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.2.0's release notes file MUST stay present
        path = REPO_ROOT / 'docs' / 'v3.2.0.md'
        self.assertTrue(path.exists(), 'docs/v3.2.0.md is missing')
        self.assertIn('3.2.0', path.read_text())


if __name__ == '__main__':
    unittest.main()
