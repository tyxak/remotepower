"""Strict version-surface + feature pins for v5.4.1 — a follow-up patch on the
RackMatters line. Loosen TestVersionBumps to dynamic on the next bump.

Covers the six v5.4.1 features:
  F1  av_warning event (rkhunter warnings / stale AV DB now reach the Alerts inbox)
  F2  ticket attachments (in/out) — store, download/inline endpoint, SMTP support
  F3  ticket auto-reply (loop-safe one-time acknowledgement)
  F4  "View email thread" window (frontend; CSP-safe)
  F5  Billing page gated behind a Settings -> Advanced checkbox (billing_enabled)
  F6  small ticket glyph in front of a ticketed host on the Devices page
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v541_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _appjs():
    return (_ROOT / "server/html/static/js/app.js").read_text()


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "5.4.1"

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{self.V}",
                      (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={self.V}", _html())

    def test_no_stale_cachebust(self):
        self.assertEqual(set(re.findall(r"\?v=(5\.4\.0[^\"&]*)", _html())), set(),
                         "stale ?v=5.4.0 cache-busts left")

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())


class TestF1AvWarning(unittest.TestCase):
    def test_event_registered_everywhere(self):
        self.assertIn('av_warning', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('av_warning', api._ALERT_RULES)
        self.assertEqual(api._ALERT_RULES['av_warning'][0], 'medium')
        # routed under the existing av_posture channel kind
        kinds = {k[0]: k[3] for k in api.CHANNEL_KINDS}
        self.assertIn('av_warning', kinds['av_posture'])

    def test_fleet_event_and_routing_in_js(self):
        js = _appjs()
        self.assertIn("'av_warning'", js)
        self.assertIn("case 'av_warning'", js)

    def test_ingest_fires_on_rising_warnings(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("fire_webhook('av_warning'", src)


class TestF2Attachments(unittest.TestCase):
    def test_helpers_and_handler_exist(self):
        for name in ('_attach_safe_name', '_attach_safe_ct', '_ticket_store_attachment',
                     '_attach_blob_path', '_email_attachments', 'handle_ticket_attachment'):
            self.assertTrue(hasattr(api, name), name)

    def test_safe_name_strips_path_and_ctrl(self):
        self.assertEqual(api._attach_safe_name('../../etc/passwd'), 'passwd')
        self.assertNotIn('\n', api._attach_safe_name('a\nb"c'))
        self.assertEqual(api._attach_safe_name(''), 'attachment')

    def test_blob_path_rejects_traversal(self):
        self.assertIsNone(api._attach_blob_path('../etc'))
        self.assertIsNone(api._attach_blob_path('zz'))
        p = api._attach_blob_path('a' * 32)
        self.assertIsNotNone(p)

    def test_safe_ct_clamps(self):
        self.assertEqual(api._attach_safe_ct('image/png; charset=x'), 'image/png')
        self.assertEqual(api._attach_safe_ct('garbage'), 'application/octet-stream')

    def test_route_registered_before_generic(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("'/attachments/' in pi", src)
        # must come before the generic ticket GET
        self.assertLess(src.index("'/attachments/' in pi"),
                        src.index("pi.startswith('/api/tickets/') and m == 'GET'"))

    def test_smtp_send_email_accepts_attachments(self):
        import inspect
        import smtp_notifier
        self.assertIn('attachments', inspect.signature(smtp_notifier.send_email).parameters)

    def test_frontend_attachment_helpers(self):
        js = _appjs()
        for fn in ('_tkAttachHtml', '_tkAttachDl', '_tkAttachView', '_tkAttachPick'):
            self.assertIn(fn, js, fn)


class TestF3Autoreply(unittest.TestCase):
    def test_handler_and_route(self):
        self.assertTrue(hasattr(api, 'handle_ticket_autoreply'))
        self.assertTrue(hasattr(api, '_send_ticket_autoreply'))
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/tickets/autoreply'), routes)
        self.assertIn(('POST', '/api/tickets/autoreply'), routes)

    def test_skip_regex_blocks_automated_senders(self):
        for bad in ('no-reply@x.com', 'noreply@x.com', 'mailer-daemon@x.com',
                    'postmaster@x.com', 'bounces@x.com'):
            self.assertTrue(api._AUTOREPLY_SKIP_RE.search(bad), bad)
        self.assertFalse(api._AUTOREPLY_SKIP_RE.search('jane@customer.com'))

    def test_settings_ui_and_js(self):
        self.assertIn('tkar-enabled', _html())
        self.assertIn('saveTicketAutoreply', _appjs())


class TestF4EmailThread(unittest.TestCase):
    def test_thread_window_function(self):
        js = _appjs()
        self.assertIn('function openTicketThread', js)
        self.assertIn('openTicketThread', _appjs())


class TestF5BillingGate(unittest.TestCase):
    def test_billing_gate_helper(self):
        self.assertTrue(hasattr(api, '_billing_enabled'))

    def test_nav_and_checkbox(self):
        html = _html()
        self.assertIn('id="nav-billing"', html)
        self.assertIn('class="nav-btn d-none" id="nav-billing"', html)
        self.assertIn('cfg-billing-enabled', html)

    def test_config_persists_flag(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("cfg['billing_enabled'] = bool(body['billing_enabled'])", src)
        self.assertIn("'billing_enabled': bool(cfg.get('billing_enabled'))", src)


class TestF6DeviceTicketIcon(unittest.TestCase):
    def test_ticket_icon_in_registry_and_used(self):
        js = _appjs()
        self.assertIn("ticket:", js)          # _ICONS registry entry
        self.assertIn("dev-ticket-ic", js)    # the in-front-of-hostname marker
        self.assertIn("_icon('ticket'", js)


class TestEnterpriseHardening(unittest.TestCase):
    """v5.4.1 enterprise-hardening batch (gap IDs D1/D2/D3/D4/E4/A7/H2/H3).
    All security knobs are OPT-IN — default behaviour must be unchanged."""

    def setUp(self):
        import tempfile
        self._d = tempfile.mkdtemp()
        self._orig_cfg = api.CONFIG_FILE
        api.CONFIG_FILE = api.Path(self._d) / 'config.json'

    def tearDown(self):
        api.CONFIG_FILE = self._orig_cfg

    # D1 — password policy
    def test_password_policy_off_by_default(self):
        api.save(api.CONFIG_FILE, {})
        ok, _ = api._validate_password_policy('x', 'bob')
        self.assertTrue(ok, 'policy must be off by default (1-char ok)')

    def test_password_policy_enforced_when_configured(self):
        api.save(api.CONFIG_FILE, {'password_min_length': 12, 'password_require_classes': True})
        self.assertFalse(api._validate_password_policy('short', 'bob')[0])
        self.assertFalse(api._validate_password_policy('alllowercaseletters', 'b')[0])  # classes
        self.assertTrue(api._validate_password_policy('LongEnough1!', 'bob')[0])

    def test_password_not_equal_username(self):
        api.save(api.CONFIG_FILE, {'password_min_length': 1})
        self.assertFalse(api._validate_password_policy('alice', 'alice')[0])

    # D2 — SSO-only
    def test_sso_only_blocks_logic(self):
        api.save(api.CONFIG_FILE, {'sso_only': True, 'oidc_enabled': True})
        self.assertTrue(api._sso_only_blocks({'role': 'admin'}))
        self.assertFalse(api._sso_only_blocks({'local_login': True}))   # break-glass
        api.save(api.CONFIG_FILE, {'sso_only': True})                   # no IdP live
        self.assertFalse(api._sso_only_blocks({}))
        api.save(api.CONFIG_FILE, {})
        self.assertFalse(api._sso_only_blocks({}))

    # D3 — idle timeout (config surface)
    def test_idle_timeout_in_config_defaults(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("idle_timeout_minutes", src)
        self.assertIn("now - int(entry.get('last_seen') or entry.get('created') or 0) > _idle * 60", src)

    # D4 — config-change audit
    def test_config_change_audit_wired(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_cfg_before = dict(cfg or {})", src)
        self.assertIn("'config_changed'", src)

    # E4 — webhook schema_version
    def test_webhook_schema_version(self):
        self.assertEqual(api.WEBHOOK_SCHEMA_VERSION, '1')
        self.assertEqual(api._siem_record('x', {'name': 'h'}).get('schema_version'), '1')
        self.assertIn("'schema_version': WEBHOOK_SCHEMA_VERSION", (_CGI / "api.py").read_text())

    # A7 — MAX_DEVICES cap
    def test_max_devices_cap(self):
        self.assertTrue(isinstance(api.MAX_DEVICES, int) and api.MAX_DEVICES > 0)
        src = (_CGI / "api.py").read_text()
        self.assertIn("denied_cap", src)
        self.assertIn("get('max_devices') or MAX_DEVICES", src)

    # config persistence + GET exposure of the new knobs
    def test_new_config_keys_persisted_and_exposed(self):
        src = (_CGI / "api.py").read_text()
        for k in ('password_min_length', 'password_require_classes', 'password_breach_check',
                  'sso_only', 'idle_timeout_minutes', 'max_devices'):
            self.assertIn(f"'{k}' in body", src, f'{k} not in config-save whitelist')
            self.assertIn(f"safe.setdefault('{k}'", src, f'{k} not exposed on GET /api/config')

    # H2 — Intl helpers
    def test_intl_helpers_present(self):
        js = _appjs()
        for fn in ('function fmtMoney', 'function _localeTag', 'function fmtDateTime'):
            self.assertIn(fn, js, fn)
        self.assertIn('fmtMoney', (_ROOT / "server/html/static/js/app-billing.js").read_text())

    # H3 — WCAG fixes
    def test_wcag_fixes(self):
        html = _html()
        self.assertIn('id="toast-container" role="status" aria-live="polite"', html)
        self.assertIn('class="skip-link"', html)
        self.assertIn('id="main-content"', html)
        self.assertIn('aria-labelledby="drawer-device-name"', html)
        js = _appjs()
        self.assertIn("setAttribute('aria-current', 'page')", js)
        self.assertIn('_drawerReturnFocus', js)


class TestEnterpriseHardening2(unittest.TestCase):
    """v5.4.1 batch 2 — credential hashing (C1), API versioning (E2),
    correlation IDs (F1), frontend error reporting (F4)."""

    # C1 — API-key hashing at rest
    def test_apikey_hash_deterministic(self):
        self.assertEqual(api._apikey_hash('abc'), api._apikey_hash('abc'))
        self.assertNotEqual(api._apikey_hash('abc'), api._apikey_hash('abd'))
        self.assertEqual(len(api._apikey_hash('x')), 64)  # sha256 hex

    def test_apikey_create_stores_hash_not_plaintext(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("'key_hash': _apikey_hash(key_value)", src)
        # the list handler must not echo key/key_hash
        self.assertNotIn("'key': v.get('key'", src)

    def test_apikey_legacy_plaintext_migrates(self):
        import tempfile
        d = tempfile.mkdtemp()
        orig = api.APIKEYS_FILE
        try:
            api.APIKEYS_FILE = api.Path(d) / 'apikeys.json'
            api.save(api.APIKEYS_FILE, {'k': {'name': 'o', 'key': 'PLAINKEY0001',
                                              'user': 'api', 'role': 'admin', 'active': True}})
            self.assertEqual(api.verify_token('PLAINKEY0001'), ('api', 'admin'))
            rec = api.load(api.APIKEYS_FILE)['k']
            self.assertNotIn('key', rec)            # plaintext gone
            self.assertTrue(rec.get('key_hash'))    # migrated to hash
            self.assertEqual(api.verify_token('PLAINKEY0001'), ('api', 'admin'))  # hash path
            self.assertEqual(api.verify_token('WRONGKEY'), (None, None))
        finally:
            api.APIKEYS_FILE = orig

    # E2 — /api/v1 alias
    def test_api_v1_alias(self):
        import os
        old = os.environ.get('PATH_INFO')
        try:
            os.environ['PATH_INFO'] = '/api/v1/devices'
            self.assertEqual(api.path_info(), '/api/devices')
            os.environ['PATH_INFO'] = '/api/v1'
            self.assertEqual(api.path_info(), '/api')
            os.environ['PATH_INFO'] = '/api/devices'
            self.assertEqual(api.path_info(), '/api/devices')
        finally:
            if old is None:
                os.environ.pop('PATH_INFO', None)
            else:
                os.environ['PATH_INFO'] = old

    # F1 — correlation IDs + structured logging
    def test_request_id_and_log_helper(self):
        import os
        api._REQUEST_ID = None
        os.environ['HTTP_X_REQUEST_ID'] = 'trace-abc_123'
        self.assertEqual(api._request_id(), 'trace-abc_123')
        api._REQUEST_ID = None
        os.environ['HTTP_X_REQUEST_ID'] = 'bad id !!'
        self.assertRegex(api._request_id(), r'^[0-9a-f]{16}$')   # minted
        os.environ.pop('HTTP_X_REQUEST_ID', None)
        self.assertTrue(callable(api.log_json))
        src = (_CGI / "api.py").read_text()
        self.assertIn('print(f"X-Request-Id: {_request_id()}")', src)

    # F4 — frontend error reporting
    def test_client_error_endpoint(self):
        self.assertTrue(hasattr(api, 'handle_client_error'))
        routes = api._build_exact_routes()
        self.assertIn(('POST', '/api/client-error'), routes)
        self.assertIn(('GET', '/api/client-error'), routes)
        self.assertTrue(isinstance(api.MAX_CLIENT_ERRORS, int))
        js = _appjs()
        self.assertIn("fetch('/api/client-error'", js)
        self.assertIn("addEventListener('error'", js)
        self.assertIn("addEventListener('unhandledrejection'", js)


if __name__ == "__main__":
    unittest.main()
