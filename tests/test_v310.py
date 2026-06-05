"""v3.1.0 Stage 1 — MCP role + audit-log shape + per-device require_confirmation.

This stage lays foundation only:
  * the 'mcp' role exists and is accepted by API-key creation;
  * user accounts still reject 'mcp' (humans don't log in as MCP);
  * require_admin treats 'mcp' the same as 'viewer' (blocked);
  * require_mcp_action() exists, 403s while MCP_ACTION_ALLOWLIST is empty;
  * get_mcp_attribution() reads X-MCP-Client / X-MCP-Prompt headers;
  * audit_log() accepts ai_host / ai_prompt without breaking old call sites;
  * devices.json carries a require_confirmation flag (default True) and
    PATCH /api/devices/<id>/require_confirmation flips it.

No MCP write tools yet — those land in Stage 4.
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
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v310_')
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
        """Create an admin user + session token, return the token string.
        Sets HTTP_X_TOKEN and REQUEST_METHOD env vars."""
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


# ─── Role enum constants ────────────────────────────────────────────────────

class TestRoleConstants(_ApiTestBase):
    def test_valid_roles_includes_mcp(self):
        self.assertIn('mcp', self.api.VALID_ROLES)
        self.assertIn('admin', self.api.VALID_ROLES)
        self.assertIn('viewer', self.api.VALID_ROLES)

    def test_user_roles_excludes_mcp(self):
        """Human accounts may not hold the MCP role — only API keys can."""
        self.assertNotIn('mcp', self.api.USER_ROLES)
        self.assertEqual(self.api.USER_ROLES, frozenset({'admin', 'viewer'}))

    def test_apikey_roles_includes_mcp(self):
        self.assertEqual(self.api.APIKEY_ROLES,
                          frozenset({'admin', 'viewer', 'mcp'}))

    def test_mcp_action_allowlist_populated_in_stage_4(self):
        """v3.2.0 Stage 4 landed the initial set of write tools. The
        allowlist must now contain at least the four documented ones.
        See test_v320.TestMcpWriteTools for full end-to-end coverage."""
        self.assertIn('reboot_device', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('run_saved_script', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('force_package_scan', self.api.MCP_ACTION_ALLOWLIST)
        self.assertIn('force_acme_rescan', self.api.MCP_ACTION_ALLOWLIST)


# ─── User vs API-key role assignment ───────────────────────────────────────

class TestUserCreateRejectsMcpRole(_ApiTestBase):
    def setUp(self):
        self._seed_admin_session()
        os.environ['REQUEST_METHOD'] = 'POST'

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD', 'CONTENT_LENGTH')

    def _post(self, body_dict):
        body = json.dumps(body_dict).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            self.api.handle_user_create()
        finally:
            sys.stdin = old_stdin

    def test_admin_role_accepted(self):
        try:
            self._post({'username': 'alice', 'password': 'pw', 'role': 'admin'})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 201, f'expected 201, got {e.body}')

    def test_viewer_role_accepted(self):
        try:
            self._post({'username': 'bob', 'password': 'pw', 'role': 'viewer'})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 201)

    def test_mcp_role_rejected_for_user(self):
        try:
            self._post({'username': 'carol', 'password': 'pw', 'role': 'mcp'})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 400)
            self.assertIn('mcp', e.body['error'].lower(),
                'error message should explain that mcp is reserved for API keys')
            self.assertIn('reserved', e.body['error'].lower())

    def test_garbage_role_rejected(self):
        try:
            self._post({'username': 'dave', 'password': 'pw', 'role': 'root'})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 400)


class TestApiKeyCreateAcceptsMcpRole(_ApiTestBase):
    def setUp(self):
        self._seed_admin_session()
        os.environ['REQUEST_METHOD'] = 'POST'

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD', 'CONTENT_LENGTH')

    def _post(self, body_dict):
        body = json.dumps(body_dict).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            self.api.handle_apikeys_create()
        finally:
            sys.stdin = old_stdin

    def test_mcp_role_accepted(self):
        try:
            self._post({'name': 'claude-desktop', 'role': 'mcp'})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 201,
                f'expected 201, got {e.status}: {e.body}')
            # Stored role on the new key is 'mcp'
            apikeys = self.api.load(self.api.APIKEYS_FILE)
            roles = {k['role'] for k in apikeys.values()}
            self.assertIn('mcp', roles)


# ─── require_auth + require_mcp_action behaviour ────────────────────────────

class TestMcpRoleGating(_ApiTestBase):
    def setUp(self):
        # Seed three API keys: admin, viewer, mcp
        apikeys = {}
        for role in ('admin', 'viewer', 'mcp'):
            apikeys[role + '-id'] = {
                'name': role + '-key',
                'key': f'rpk_test_{role}',
                'user': role + '-user',
                'role': role,
                'created': int(time.time()),
                'active': True,
                'expires_at': None,
            }
        self.api.save(self.api.APIKEYS_FILE, apikeys)

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN')

    def _set_token(self, role):
        os.environ['HTTP_X_TOKEN'] = f'rpk_test_{role}'

    def test_admin_required_blocks_mcp(self):
        """Admin-only endpoints stay admin-only — mcp keys get 403."""
        self._set_token('mcp')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_admin_auth()
        self.assertEqual(ctx.exception.status, 403)

    def test_admin_required_blocks_viewer(self):
        self._set_token('viewer')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_admin_auth()
        self.assertEqual(ctx.exception.status, 403)

    def test_admin_required_allows_admin(self):
        self._set_token('admin')
        # Should NOT raise
        username = self.api.require_admin_auth()
        self.assertEqual(username, 'admin-user')

    def test_require_mcp_action_no_token_401(self):
        _clear_env('HTTP_X_TOKEN')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_mcp_action('run_saved_script')
        self.assertEqual(ctx.exception.status, 401)

    def test_require_mcp_action_admin_token_403(self):
        """Admins explicitly cannot call MCP write tools through this gate;
        they have their own direct endpoints."""
        self._set_token('admin')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_mcp_action('run_saved_script')
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn('mcp', ctx.exception.body['error'].lower())

    def test_require_mcp_action_viewer_token_403(self):
        self._set_token('viewer')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_mcp_action('run_saved_script')
        self.assertEqual(ctx.exception.status, 403)

    def test_require_mcp_action_mcp_token_action_not_in_allowlist(self):
        """v3.2.0: allowlist is populated but only with the 4 documented
        actions. An action name outside that set still 403s."""
        self._set_token('mcp')
        with self.assertRaises(self.api.HTTPError) as ctx:
            self.api.require_mcp_action('drop_database')
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn('allowed_actions', ctx.exception.body)
        # All four Stage-4 actions are in the response
        self.assertIn('reboot_device', ctx.exception.body['allowed_actions'])


# ─── audit_log() shape ──────────────────────────────────────────────────────

class TestAuditLogShape(_ApiTestBase):
    def setUp(self):
        # Reset audit log so test starts clean
        self.api.save(self.api.AUDIT_LOG_FILE, {'entries': []})
        os.environ['REMOTE_ADDR'] = '203.0.113.5'

    def tearDown(self):
        _clear_env('REMOTE_ADDR', 'HTTP_USER_AGENT')

    def test_legacy_call_site_signature_unchanged(self):
        """Every existing audit_log() call in api.py uses the 4-arg form.
        Stage 1 must not break those — ai_host / ai_prompt are optional."""
        self.api.audit_log('alice', 'login', 'successful login')
        al = self.api.load(self.api.AUDIT_LOG_FILE)
        entries = al['entries']
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e['actor'], 'alice')
        self.assertEqual(e['action'], 'login')
        self.assertEqual(e['detail'], 'successful login')
        # AI fields must NOT be present when not supplied — keeps the
        # entry compact and visually distinct from MCP entries.
        self.assertNotIn('ai_host', e)
        self.assertNotIn('ai_prompt', e)

    def test_ai_host_and_prompt_recorded_when_supplied(self):
        self.api.audit_log(
            'mcp-user', 'mcp_run_saved_script',
            detail='script=rotate-nginx-logs dev=d-1',
            ai_host='claude-desktop',
            ai_prompt='User asked to rotate nginx logs on the web server',
        )
        e = self.api.load(self.api.AUDIT_LOG_FILE)['entries'][-1]
        self.assertEqual(e['ai_host'], 'claude-desktop')
        self.assertEqual(e['ai_prompt'],
            'User asked to rotate nginx logs on the web server')

    def test_ai_prompt_is_truncated_not_dropped(self):
        """A pathologically long prompt is truncated to fit the audit entry,
        not dropped entirely — the goal is forensic value when something
        goes wrong, not bytewise honesty about prompt length."""
        long_prompt = 'A' * 5000
        self.api.audit_log(
            'mcp-user', 'mcp_reboot',
            ai_host='claude-desktop',
            ai_prompt=long_prompt,
        )
        e = self.api.load(self.api.AUDIT_LOG_FILE)['entries'][-1]
        self.assertIn('ai_prompt', e)
        self.assertLessEqual(len(e['ai_prompt']), 2048)
        self.assertTrue(e['ai_prompt'].startswith('A'))


class TestMcpAttributionHeaders(_ApiTestBase):
    def tearDown(self):
        _clear_env('HTTP_X_MCP_CLIENT', 'HTTP_X_MCP_PROMPT')

    def test_returns_none_when_headers_absent(self):
        host, prompt = self.api.get_mcp_attribution()
        self.assertIsNone(host)
        self.assertIsNone(prompt)

    def test_reads_x_mcp_client_header(self):
        os.environ['HTTP_X_MCP_CLIENT'] = 'cursor'
        os.environ['HTTP_X_MCP_PROMPT'] = 'check disk usage on backup host'
        host, prompt = self.api.get_mcp_attribution()
        self.assertEqual(host, 'cursor')
        self.assertEqual(prompt, 'check disk usage on backup host')

    def test_empty_header_treated_as_unset(self):
        """An empty header is logically the same as absent — better None
        than the empty string so callers can branch on `is None`."""
        os.environ['HTTP_X_MCP_CLIENT'] = ''
        host, _ = self.api.get_mcp_attribution()
        self.assertIsNone(host)


# ─── per-device require_confirmation ────────────────────────────────────────

class TestDeviceRequireConfirmation(_ApiTestBase):
    def setUp(self):
        self._seed_admin_session('admin')
        # Seed one device
        self.api.save(self.api.DEVICES_FILE, {
            'd-1': {'name': 'web-01', 'monitored': True,
                     'last_seen': int(time.time()), 'token': 'devtok'},
        })

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD', 'CONTENT_LENGTH')

    def _patch(self, dev_id, body_dict):
        os.environ['REQUEST_METHOD'] = 'PATCH'
        body = json.dumps(body_dict).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            self.api.handle_device_require_confirmation(dev_id)
        finally:
            sys.stdin = old_stdin

    def test_default_is_true_for_existing_devices(self):
        """Existing devices that pre-date v3.1.0 have no field; reads default
        to True (the conservative behaviour — always ask before MCP-driven
        mutations)."""
        os.environ['REQUEST_METHOD'] = 'GET'
        try:
            self.api.handle_devices_list()
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
            d = next(x for x in e.body if x['id'] == 'd-1')
            self.assertTrue(d['require_confirmation'],
                'devices without the field must default to require_confirmation=True')

    def test_patch_flips_field(self):
        try:
            self._patch('d-1', {'require_confirmation': False})
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
            self.assertFalse(e.body['require_confirmation'])
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertFalse(devs['d-1']['require_confirmation'])

    def test_patch_writes_audit_log_entry(self):
        before = len(self.api.load(self.api.AUDIT_LOG_FILE).get('entries', []))
        try:
            self._patch('d-1', {'require_confirmation': False})
        except self.api.HTTPError:
            pass
        after = self.api.load(self.api.AUDIT_LOG_FILE)['entries']
        self.assertEqual(len(after), before + 1)
        self.assertEqual(after[-1]['action'], 'device_require_confirmation')
        self.assertIn('require_confirmation=False', after[-1]['detail'])

    def test_patch_unknown_device_404(self):
        try:
            self._patch('does-not-exist', {'require_confirmation': False})
            self.fail('expected HTTPError')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 404)

    def test_viewer_cannot_patch(self):
        """require_confirmation flips are admin-only — viewer keys can't
        opt a host out of confirmation."""
        # Replace the admin session with a viewer one
        apikeys = self.api.load(self.api.APIKEYS_FILE)
        apikeys['v'] = {'name': 'v', 'key': 'rpk_viewer', 'user': 'v',
                         'role': 'viewer', 'created': int(time.time()),
                         'active': True, 'expires_at': None}
        self.api.save(self.api.APIKEYS_FILE, apikeys)
        os.environ['HTTP_X_TOKEN'] = 'rpk_viewer'
        try:
            self._patch('d-1', {'require_confirmation': False})
            self.fail('viewer should not be allowed')
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 403)


# ─── ai_provider: _http_post_json regression ────────────────────────────────


# ─── v3.1.0 strict version pins ─────────────────────────────────────────────

class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.2.0 now holds the strict pin (see test_v320.py)."""

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
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'",
            'sw.js CACHE_NAME must carry a v3.x.x marker')

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+',
            'index.html cache-bust ?v= must be a 3.x.x version')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg',
            'README.md version badge missing 3.x.x marker')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.1.0 docs must stay present (we shipped a GitHub release for it)
        # notes recorded in CHANGELOG.md; per-version docs pruned to last 5
        self.assertIn('3.1.0', (REPO_ROOT / 'CHANGELOG.md').read_text())

