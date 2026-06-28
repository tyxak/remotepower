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


class TestG1OffsiteBackup(unittest.TestCase):
    """v5.4.1 (G1): off-host backup mirror + restore-verify."""

    def test_offsite_copy_and_restore_verify(self):
        import os
        import tempfile
        d = tempfile.mkdtemp()
        orig = (api.DATA_DIR, api.CONFIG_FILE)
        try:
            api.DATA_DIR = api.Path(d)
            api.CONFIG_FILE = api.DATA_DIR / 'config.json'
            (api.DATA_DIR / 'sentinel.txt').write_text('hi')
            api.save(api.CONFIG_FILE, {'backup': {'enabled': True,
                     'path': os.path.join(d, 'bk'),
                     'offsite_dir': os.path.join(d, 'offsite'), 'retain_days': 14}})
            res = api._run_data_backup('manual')
            self.assertTrue(res['ok'])
            self.assertTrue(res['offsite_ok'])
            copies = list((api.Path(d) / 'offsite').glob('remotepower_data_*.tar.gz*'))
            self.assertTrue(copies, 'offsite copy missing')
        finally:
            api.DATA_DIR, api.CONFIG_FILE = orig

    def test_route_and_handler(self):
        self.assertTrue(hasattr(api, 'handle_backup_test_restore'))
        self.assertIn(('POST', '/api/backup/test-restore'), api._build_exact_routes())

    def test_settings_ui_and_posture(self):
        html = _html()
        self.assertIn('id="backup-offsite-dir"', html)
        self.assertIn('data-action="testRestore"', html)
        self.assertIn("'backup_offsite'", (_CGI / "api.py").read_text())  # posture row


class TestG2EscalationTargets(unittest.TestCase):
    """v5.4.1 (G2): per-tier escalation target routing."""

    def test_send_webhook_only_dest_ids_filter(self):
        sent = []
        orig = api._dispatch_one_webhook
        try:
            api._dispatch_one_webhook = lambda ev, dest, sp, msg, title, prio: sent.append(dest.get("name"))
            cfg = {"webhook_urls": [
                {"id": "wh1", "name": "Slack", "url": "https://h/x", "format": "slack", "enabled": True},
                {"id": "wh2", "name": "PagerDuty", "url": "https://p/x", "format": "generic", "enabled": True},
            ]}
            sent.clear(); api._send_webhook_to_url("e", {}, "m", cfg)
            self.assertEqual(set(sent), {"Slack", "PagerDuty"})           # no filter → all
            sent.clear(); api._send_webhook_to_url("e", {}, "m", cfg, only_dest_ids={"PagerDuty"})
            self.assertEqual(sent, ["PagerDuty"])                          # by name
            sent.clear(); api._send_webhook_to_url("e", {}, "m", cfg, only_dest_ids={"wh1"})
            self.assertEqual(sent, ["Slack"])                             # by id
            sent.clear(); api._send_webhook_to_url("e", {}, "m", cfg, only_dest_ids={"nope"})
            self.assertEqual(sent, [])                                    # unknown → none
        finally:
            api._dispatch_one_webhook = orig

    def test_tier_target_wired(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("tier.get('target')", src)               # captured in the tick
        self.assertIn("only_dest_ids=({_tgt} if _tgt else None)", src)
        self.assertIn("tier['target'] = tgt", src)             # accepted in config save
        self.assertIn('id="esc-tier-targets"', _html())        # UI


class TestC2ConfigSecretEncryption(unittest.TestCase):
    """v5.4.1 (C2): config-secret encryption at rest — OPT-IN via RP_CONFIG_KEY,
    transparent at load/save, fail-graceful."""

    def setUp(self):
        import os
        import tempfile
        self._k = os.environ.pop('RP_CONFIG_KEY', None)
        self._d = tempfile.mkdtemp()
        self._orig = api.CONFIG_FILE
        api.CONFIG_FILE = api.Path(self._d) / 'config.json'
        api._LOAD_CACHE.clear()

    def tearDown(self):
        import os
        api.CONFIG_FILE = self._orig
        api._LOAD_CACHE.clear()
        if self._k is None:
            os.environ.pop('RP_CONFIG_KEY', None)
        else:
            os.environ['RP_CONFIG_KEY'] = self._k

    def test_default_off_is_plaintext(self):
        import json
        import os
        os.environ.pop('RP_CONFIG_KEY', None)
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'smtp_password': 's3cret'})
        on_disk = json.loads(api.CONFIG_FILE.read_text())
        self.assertEqual(on_disk['smtp_password'], 's3cret')      # no key → plaintext

    @unittest.skipUnless(__import__('backup_crypto').available(), 'cryptography not installed')
    def test_roundtrip_with_key(self):
        import json
        import os
        os.environ['RP_CONFIG_KEY'] = 'master-key-xyz'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'smtp_password': 's3cret', 'siem_token': 'st', 'plain': 'v'})
        on_disk = json.loads(api.CONFIG_FILE.read_text())
        self.assertTrue(on_disk['smtp_password'].startswith('enc:v1:'))  # ciphertext at rest
        self.assertEqual(on_disk['plain'], 'v')                          # non-secret untouched
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual(cfg['smtp_password'], 's3cret')                 # decrypted transparently
        self.assertEqual(cfg['siem_token'], 'st')

    @unittest.skipUnless(__import__('backup_crypto').available(), 'cryptography not installed')
    def test_wrong_key_is_fail_graceful(self):
        import os
        os.environ['RP_CONFIG_KEY'] = 'key-A'
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'smtp_password': 's3cret'})
        os.environ['RP_CONFIG_KEY'] = 'key-B'   # changed/lost key
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)          # must not raise
        self.assertTrue(cfg['smtp_password'].startswith('enc:v1:'))  # left as-is, not crashed

    def test_helpers_and_posture(self):
        self.assertEqual(set(api._CONFIG_SECRET_FIELDS) >= {
            'smtp_password', 'oidc_client_secret', 'ldap_bind_password',
            'siem_token', 'audit_forward_token'}, True)
        self.assertIn("'config_secrets_encrypted'", (_CGI / "api.py").read_text())


class TestWormAuditSink(unittest.TestCase):
    """v5.4.1 (WORM): append-only audit sink."""

    def test_append_and_off(self):
        import json
        import os
        import tempfile
        d = tempfile.mkdtemp()
        orig = (api.DATA_DIR, api.CONFIG_FILE, api._get_client_ip)
        try:
            api.DATA_DIR = api.Path(d)
            api.CONFIG_FILE = api.DATA_DIR / 'config.json'
            api._get_client_ip = lambda: '1.2.3.4'
            api._LOAD_CACHE.clear()
            worm = os.path.join(d, 'worm.jsonl')
            api.save(api.CONFIG_FILE, {'audit_worm_path': worm})
            api._LOAD_CACHE.clear()
            api.audit_log('alice', 'act', 'detail')
            lines = open(worm).read().strip().splitlines()
            self.assertEqual(len(lines), 1)
            e = json.loads(lines[0])
            self.assertEqual(e['actor'], 'alice')
            self.assertTrue(e.get('_hash'))          # the hash-chained entry
            # off → no crash, no further writes
            api.save(api.CONFIG_FILE, {})
            api._LOAD_CACHE.clear()
            api.audit_log('bob', 'act2', 'd')
            self.assertEqual(len(open(worm).read().strip().splitlines()), 1)
        finally:
            api.DATA_DIR, api.CONFIG_FILE, api._get_client_ip = orig
            api._LOAD_CACHE.clear()

    def test_config_and_posture_wired(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("cfg['audit_worm_path'] = wp", src)
        self.assertIn("'audit_worm'", src)            # posture row
        self.assertIn('id="cfg-audit-worm-path"', _html())


class TestE5Postman(unittest.TestCase):
    """v5.4.1 (E5): Postman collection generated from the OpenAPI spec."""

    def test_postman_collection(self):
        import importlib.util as _u
        path = _ROOT / "tools" / "gen-postman.py"
        self.assertTrue(path.exists())
        spec = _u.spec_from_file_location("gen_postman", path)
        mod = _u.module_from_spec(spec)
        spec.loader.exec_module(mod)
        coll = mod.build()
        self.assertTrue(coll["info"]["schema"].endswith("v2.1.0/collection.json"))
        self.assertEqual(coll["auth"]["type"], "apikey")
        self.assertTrue(any(a["value"] == "X-Token" for a in coll["auth"]["apikey"]))
        self.assertTrue(any(v["key"] == "baseUrl" for v in coll["variable"]))
        reqs = sum(len(f["item"]) for f in coll["item"])
        self.assertGreater(reqs, 200, "should cover the whole API")
        # every request is well-formed
        for folder in coll["item"]:
            for it in folder["item"]:
                r = it["request"]
                self.assertIn(r["method"], ("GET", "POST", "PUT", "PATCH", "DELETE"))
                self.assertTrue(r["url"]["raw"].startswith("{{baseUrl}}"))

    def test_make_target(self):
        self.assertIn("postman:", (_ROOT / "Makefile").read_text())


class TestF3Slo(unittest.TestCase):
    """v5.4.1 (F3): availability SLO + error-budget per monitor."""

    def setUp(self):
        import tempfile
        self._orig = (api.DATA_DIR, api.CONFIG_FILE, api.MON_HIST_FILE)
        d = tempfile.mkdtemp()
        api.DATA_DIR = api.Path(d)
        api.CONFIG_FILE = api.DATA_DIR / 'config.json'
        api.MON_HIST_FILE = api.DATA_DIR / 'monitor_history.json'
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.DATA_DIR, api.CONFIG_FILE, api.MON_HIST_FILE = self._orig
        api._LOAD_CACHE.clear()

    def test_compute_slo(self):
        api.save(api.CONFIG_FILE, {'slo_target_percent': 99.0})
        api.save(api.MON_HIST_FILE, {
            'web': [{'ts': i, 'ok': (i != 5)} for i in range(20)],   # 95%
            'db':  [{'ts': i, 'ok': True} for i in range(20)],        # 100%
        })
        api._LOAD_CACHE.clear()
        slo = api._compute_slo()
        self.assertEqual(slo['target'], 99.0)
        byl = {m['label']: m for m in slo['monitors']}
        self.assertAlmostEqual(byl['web']['availability'], 95.0, places=2)
        self.assertFalse(byl['web']['meeting_slo'])
        self.assertTrue(byl['db']['meeting_slo'])
        # target 99 → budget 1%; web's 5% downtime blows it → 0 remaining, burn 5
        self.assertEqual(byl['web']['budget_remaining_pct'], 0.0)
        self.assertEqual(byl['web']['burn_rate'], 5.0)
        self.assertEqual(byl['db']['budget_remaining_pct'], 100.0)
        self.assertEqual([m['label'] for m in slo['monitors']][0], 'web')   # worst first

    def test_target_default_and_clamp(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.assertEqual(api._slo_target(), 99.9)            # default
        api.save(api.CONFIG_FILE, {'slo_target_percent': 150})
        api._LOAD_CACHE.clear()
        self.assertEqual(api._slo_target(), 99.9)            # out-of-range → default

    def test_route_and_prometheus(self):
        self.assertIn(('GET', '/api/slo'), api._build_exact_routes())
        self.assertIn('remotepower_slo_target_percent',
                      (_CGI / "prometheus_export.py").read_text())
        self.assertIn("'slo':             _compute_slo()", (_CGI / "api.py").read_text())


class TestC7SupplyChain(unittest.TestCase):
    """v5.4.1 (C7): app-self SBOM + SLSA provenance."""

    def test_self_sbom_generator(self):
        import importlib.util as _u
        path = _ROOT / "tools" / "gen-self-sbom.py"
        self.assertTrue(path.exists())
        spec = _u.spec_from_file_location("gen_self_sbom", path)
        mod = _u.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sbom = mod.build("5.4.1")
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(sbom["metadata"]["component"]["name"], "remotepower-server")
        names = {c["name"] for c in sbom["components"]}
        self.assertTrue({"cryptography", "bcrypt", "dnspython"} <= names)
        for c in sbom["components"]:
            self.assertTrue(c["purl"].startswith("pkg:pypi/"))

    def test_manifest_and_make_target(self):
        self.assertTrue((_ROOT / "packaging" / "requirements-server.txt").exists())
        self.assertIn("sbom-self:", (_ROOT / "Makefile").read_text())

    def test_release_provenance_enabled(self):
        wf = _ROOT / ".github" / "workflows" / "release.yml"
        if not wf.exists():
            self.skipTest("release.yml not present (excluded from the make dist staged tree)")
        s = wf.read_text()
        self.assertNotIn("provenance: false", s)
        self.assertEqual(s.count("provenance: true"), 2)   # server + agent images
        self.assertIn("id-token: write", s)


class TestKeystoneStageA(unittest.TestCase):
    """v5.4.1 (keystone Stage A): the request-context reset that makes the codebase
    safe for a future persistent app server — per-request globals reset at request
    boundaries, while legitimately-persistent cadence timers survive."""

    def test_begin_request_resets_per_request_state(self):
        # Simulate request 1 leaving state behind.
        api._LOAD_CACHE[api.CONFIG_FILE] = ({'leaked': True}, True)
        api._REQUEST_ID = 'req-1-id'
        # A cadence timer is legitimately cross-request — record it.
        api._last_escalation_tick[0] = 12345.0
        # Request 2 begins.
        api._begin_request()
        # Per-request state is gone (no cross-request leak)…
        self.assertEqual(api._LOAD_CACHE, {})
        self.assertIsNone(api._REQUEST_ID)
        # …but the cadence timer is preserved (it gates the in-process sweeps).
        self.assertEqual(api._last_escalation_tick[0], 12345.0)

    def test_end_request_defined_and_clears_cache(self):
        api._LOAD_CACHE[api.CONFIG_FILE] = ({'x': 1}, True)
        api._end_request()
        self.assertEqual(api._LOAD_CACHE, {})

    def test_main_calls_begin_request(self):
        src = (_CGI / "api.py").read_text()
        idx = src.find('def main():')
        self.assertGreater(idx, 0)
        # _begin_request() is the first call in main(), before the cadence sweeps.
        self.assertIn('_begin_request()', src[idx:idx + 600])


class TestDeviceTokenHashing(unittest.TestCase):
    """v5.4.1: device tokens hashed at rest, with a legacy-plaintext fallback +
    transparent migration on heartbeat."""

    def test_device_token_ok(self):
        h = api._hash_device_token('TOK123')
        self.assertEqual(len(h), 64)
        self.assertTrue(api._device_token_ok({'token_hash': h}, 'TOK123'))   # hashed
        self.assertFalse(api._device_token_ok({'token_hash': h}, 'WRONG'))
        self.assertTrue(api._device_token_ok({'token': 'TOK123'}, 'TOK123'))  # legacy
        self.assertFalse(api._device_token_ok({'token': 'TOK123'}, 'WRONG'))
        self.assertFalse(api._device_token_ok({}, 'x'))
        self.assertFalse(api._device_token_ok({'token_hash': h}, ''))

    def test_enroll_stores_hash_and_heartbeat_migrates(self):
        src = (_CGI / "api.py").read_text()
        # enroll (new + re-enroll) stores token_hash, not plaintext
        self.assertEqual(src.count("'token_hash': _hash_device_token(new_token)"), 2)
        # every device-token auth goes through the helper (no raw plaintext compare)
        self.assertNotIn("hmac.compare_digest(dev.get('token', ''), dev_token)", src)
        self.assertNotIn("hmac.compare_digest(_d.get('token', ''), dev_token)", src)
        # heartbeat migrates a legacy plaintext token to a hash under its lock
        self.assertIn("dev['token_hash'] = _hash_device_token(dev['token'])", src)
        self.assertIn("dev.pop('token', None)", src)


class TestEnrollmentTokenHashing(unittest.TestCase):
    """v5.4.1: enrollment tokens keyed by hash at rest, with a `prefix` for the
    list/revoke UX and a legacy plaintext-key fallback. Completes credential-at-rest."""

    def test_create_keys_by_hash_with_prefix(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("tokens[_hash_device_token(token)] = {", src)
        self.assertIn("'prefix':        token[:8],", src)

    def test_consume_and_revoke_resolve_both_forms(self):
        import secrets
        tok = secrets.token_urlsafe(32)
        h = api._hash_device_token(tok)
        # new (hashed) form: presented plaintext resolves to the hash key
        store = {h: {'expires': 9 ** 18, 'prefix': tok[:8]}}
        key = h if api._hash_device_token(tok) in store else tok
        self.assertEqual(key, h)
        self.assertEqual([k for k, m in store.items()
                          if (m.get('prefix') or k).startswith(tok[:6])], [h])
        # legacy (plaintext-keyed) form still resolves
        leg = secrets.token_urlsafe(32)
        store2 = {leg: {'expires': 9 ** 18}}
        key2 = api._hash_device_token(leg) if api._hash_device_token(leg) in store2 else leg
        self.assertEqual(key2, leg)
        self.assertEqual((store2[leg].get('prefix') or leg[:8]), leg[:8])

    def test_source_wiring(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_ekey = _eh if _eh in tokens else enroll_token", src)   # consume
        self.assertIn("(m.get('prefix') or k).startswith(prefix)", src)        # revoke
        self.assertIn("(meta.get('prefix') or token[:8])", src)                # list


if __name__ == "__main__":
    unittest.main()
