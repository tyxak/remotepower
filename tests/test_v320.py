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


# ─── v3.2.0 strict version pins ─────────────────────────────────────────────

class TestVersionBumps(unittest.TestCase):
    """v3.2.0 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.2.0'

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertIn(f"'remotepower-shell-v{self.EXPECTED}'", sw,
            f'sw.js CACHE_NAME must be bumped to remotepower-shell-v{self.EXPECTED}')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn(f'?v={self.EXPECTED}', html,
            f'index.html cache-bust ?v= must be {self.EXPECTED}')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertIn(f'version-{self.EXPECTED}-blue.svg', text,
            'README.md version badge not bumped')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v<x.y.z> header')
        self.assertEqual(m.group(1), self.EXPECTED,
            f'CHANGELOG.md top entry is v{m.group(1)}, expected v{self.EXPECTED}')

    def test_release_notes_doc_present(self):
        path = REPO_ROOT / 'docs' / f'v{self.EXPECTED}.md'
        self.assertTrue(path.exists(), f'docs/v{self.EXPECTED}.md is missing')
        self.assertIn(self.EXPECTED, path.read_text())


if __name__ == '__main__':
    unittest.main()
