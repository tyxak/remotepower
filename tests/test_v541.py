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

    # H4 — branded email
    def test_branded_email(self):
        import importlib.util as _u
        _s = _u.spec_from_file_location("smtp_notifier_b", _CGI / "smtp_notifier.py")
        sn = _u.module_from_spec(_s); _s.loader.exec_module(sn)
        h = sn.brand_html({'brand_name': 'Acme RMM', 'brand_accent': 'emerald'}, 'Subj', 'line1\nline2')
        self.assertIn('Acme RMM', h)
        self.assertIn('#10b981', h)             # emerald accent
        # body HTML is escaped (no injection)
        self.assertNotIn('<script>', sn.brand_html({}, 't', '<script>x</script>'))
        # default brand + accent
        self.assertIn('RemotePower', sn.brand_html(None, 't', 'b'))
        # alert + digest emails pass a branded html_body
        src = (_CGI / "api.py").read_text()
        self.assertIn('html_body=smtp_notifier.brand_html(cfg, subject, body)', src)


class TestEnterpriseHardening3(unittest.TestCase):
    """v5.4.1 batch 4 — pagination convention (E3), signed exports (C4)."""

    def setUp(self):
        self._qs = __import__('os').environ.get('QUERY_STRING')

    def tearDown(self):
        import os
        if self._qs is None:
            os.environ.pop('QUERY_STRING', None)
        else:
            os.environ['QUERY_STRING'] = self._qs

    # E3 — pagination / sort / filter convention
    def test_paginate_backward_compatible(self):
        import os
        data = [{'n': i} for i in range(5)]
        os.environ['QUERY_STRING'] = ''
        self.assertEqual(api._paginate_list(data), data)   # bare list unchanged

    def test_paginate_slice_and_envelope(self):
        import os
        data = [{'n': i} for i in range(10)]
        os.environ['QUERY_STRING'] = 'limit=3&offset=2'
        self.assertEqual(api._paginate_list(data), data[2:5])
        os.environ['QUERY_STRING'] = 'limit=3&meta=1'
        env = api._paginate_list(data)
        self.assertEqual((env['total'], env['limit'], env['offset'], env['next']), (10, 3, 0, 3))

    def test_paginate_sort_and_filter(self):
        import os
        data = [{'n': i, 'name': f'h{i}'} for i in range(5)]
        os.environ['QUERY_STRING'] = 'sort=n&order=desc'
        self.assertEqual([x['n'] for x in api._paginate_list(data)], [4, 3, 2, 1, 0])
        os.environ['QUERY_STRING'] = 'q=h3'
        r = api._paginate_list(data)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]['n'], 3)

    def test_paginate_applied_to_list_endpoints(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("respond(200, _paginate_list([{'id': kid", src)  # apikeys list

    # C4 — signed exports
    def test_export_sign_deterministic_and_keyed(self):
        import tempfile
        d = tempfile.mkdtemp()
        orig = api.DATA_DIR
        try:
            api.DATA_DIR = api.Path(d)
            a, b = api._export_sign(b'x'), api._export_sign('x')
            self.assertEqual(a, b)
            self.assertEqual(len(a), 64)
            self.assertNotEqual(api._export_sign(b'x'), api._export_sign(b'y'))
            import os
            import stat as _st
            kf = api.DATA_DIR / 'export_sign.key'
            self.assertTrue(kf.exists())
            self.assertEqual(_st.S_IMODE(os.stat(kf).st_mode), 0o600)
        finally:
            api.DATA_DIR = orig

    def test_evidence_pack_and_archive_signed(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("pack['signature'] = {", src)
        self.assertIn('X-RP-Signature: hmac-sha256=', src)


class TestEnterpriseHardening5(unittest.TestCase):
    """v5.4.1 batch 5 — export-key rotation (C9) + posture surfacing of the new
    v5.4.1 controls."""

    def test_rotate_export_key_endpoint(self):
        self.assertTrue(hasattr(api, 'handle_rotate_export_key'))
        self.assertIn(('POST', '/api/security/rotate-export-key'), api._build_exact_routes())
        # rotation changes the key
        import tempfile
        d = tempfile.mkdtemp()
        orig = api.DATA_DIR
        try:
            api.DATA_DIR = api.Path(d)
            k1 = api._export_signing_key()
            (api.DATA_DIR / 'export_sign.key').unlink()
            self.assertNotEqual(k1, api._export_signing_key())
        finally:
            api.DATA_DIR = orig

    def test_posture_surfaces_new_controls(self):
        src = (_CGI / "api.py").read_text()
        for key in ("'password_policy'", "'idle_timeout'", "'sso_only'", "'signed_exports'"):
            self.assertIn(key, src, f'posture row {key} missing')

    def test_settings_button_and_handler(self):
        self.assertIn('data-action="rotateExportKey"', _html())
        self.assertIn('async function rotateExportKey', _appjs())

    def test_cache_busted_for_asset_changes(self):
        # The SW cache name must have moved past the original v5.4.1 so the
        # enterprise-hardening asset changes actually reach browsers.
        sw = (_ROOT / "server/html/sw.js").read_text()
        self.assertRegex(sw, r"remotepower-shell-v5\.4\.1-\d+")


class TestE1OpenApiCoverage(unittest.TestCase):
    """v5.4.1 (E1): the OpenAPI spec covers the whole literal-route surface, not
    just the ~28 hand-documented endpoints."""

    def setUp(self):
        import importlib.util as _u
        _s = _u.spec_from_file_location("openapi_spec_t", _CGI / "openapi_spec.py")
        self.osp = _u.module_from_spec(_s)
        _s.loader.exec_module(self.osp)

    def test_every_literal_exact_route_is_in_spec(self):
        routes = list(api._build_exact_routes().keys())
        spec = self.osp.build_spec("5.4.1", routes=routes)
        paths = spec["paths"]
        missing = []
        for m, full in routes:
            if not isinstance(m, str):
                continue   # agent-only None-method routes are intentionally excluded
            rel = full[4:] if full.startswith("/api") else full
            if not rel or "{" in rel:
                continue
            if rel not in paths or m.lower() not in paths[rel]:
                missing.append((m, rel))
        self.assertEqual(missing, [], f"routes missing from OpenAPI spec: {missing[:10]}")
        self.assertGreater(len(paths), 200, "spec should now cover the whole surface")

    def test_spec_advertises_v1_server(self):
        spec = self.osp.build_spec("5.4.1", routes=[])
        urls = [s["url"] for s in spec["servers"]]
        self.assertIn("/api/v1", urls)
        # every operation declares responses (valid-ish OpenAPI)
        full = self.osp.build_spec("5.4.1", routes=list(api._build_exact_routes().keys()))
        for p, ops in full["paths"].items():
            for verb, op in ops.items():
                if verb in ("get", "post", "put", "patch", "delete"):
                    self.assertIn("responses", op, f"{verb} {p} has no responses")

    def test_handler_passes_routes(self):
        self.assertIn("routes=list(_build_exact_routes().keys())", (_CGI / "api.py").read_text())


if __name__ == "__main__":
    unittest.main()
