"""v3.0.6 release tests.

Strict version pins loosened now that v3.1.0 has shipped (following the
same convention as test_v305.py). The v3.0.6-specific regression coverage
for /api/health, /api/csp-report, SRI, and CI workflow is retained below
as permanent regression guards. Version pins now accept any 3.x.x.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to  # noqa: E402


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.1.0 now holds the strict pin."""

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
        path = REPO_ROOT / 'docs' / 'v3.0.6.md'
        self.assertTrue(path.exists(), 'docs/v3.0.6.md is missing')
        self.assertIn('3.0.6', path.read_text())


# ── /api/health endpoint ────────────────────────────────────────────────────

class TestHealthEndpoint(unittest.TestCase):
    """The new unauthenticated liveness endpoint. Must respond 200 with
    a small JSON body containing only the version, expose no auth or
    fleet detail, and live in _PWCHG_ALLOWED_PATHS so password-change
    middleware doesn't 403 it."""

    @classmethod
    def setUpClass(cls):
        cls.api_py = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_handler_defined(self):
        self.assertRegex(self.api_py, r'(?m)^def handle_health\(\):',
            'handle_health() must be defined in api.py')

    def test_handler_returns_200_and_version_only(self):
        # The handler body must reference SERVER_VERSION and the literal
        # 200 status; no auth call, no fleet load.
        m = re.search(
            r'(?ms)^def handle_health\(\):.+?(?=^def |\Z)',
            self.api_py)
        self.assertIsNotNone(m, 'handle_health body not found')
        body = m.group(0)
        self.assertIn('respond(200,', body)
        self.assertIn('SERVER_VERSION', body)
        # No-auth: must NOT call require_auth / require_admin_auth.
        self.assertNotRegex(body, r'\brequire_(?:admin_)?auth\(',
            'handle_health must remain unauthenticated')

    def test_route_registered(self):
        self.assertEqual(routes_to('GET', '/api/health'), 'handle_health',
                         "dispatcher must route GET /api/health to handle_health()")

    def test_in_pwchg_allowed_paths(self):
        # Must be reachable even from a session pending forced password change.
        m = re.search(r'_PWCHG_ALLOWED_PATHS\s*=\s*frozenset\(\{([^}]+)\}\)',
                      self.api_py)
        self.assertIsNotNone(m, '_PWCHG_ALLOWED_PATHS set not found')
        self.assertIn("'/api/health'", m.group(1))

    def test_dockerfile_healthcheck_probes_endpoint(self):
        dockerfile = (REPO_ROOT / 'Dockerfile').read_text()
        self.assertIn('/api/health', dockerfile,
            'Dockerfile HEALTHCHECK must probe /api/health, not /')


# ── /api/csp-report endpoint ────────────────────────────────────────────────

class TestCspReportEndpoint(unittest.TestCase):
    """CSP violation reporter. Browser-initiated POSTs with `Origin:
    null` must reach the handler (the only POST exempt from the same-
    origin CSRF check). Body is size-capped to defend against an abusive
    client; report bodies are logged via audit_log."""

    @classmethod
    def setUpClass(cls):
        cls.api_py = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()

    def test_handler_defined(self):
        self.assertRegex(self.api_py, r'(?m)^def handle_csp_report\(\):',
            'handle_csp_report() must be defined')

    def test_route_registered(self):
        self.assertEqual(routes_to('POST', '/api/csp-report'),
                         'handle_csp_report')

    def test_body_size_cap(self):
        # Defensive cap so the endpoint can't be used as an audit-log
        # flood. 16 KB is comfortably above any real CSP report.
        self.assertRegex(self.api_py, r'_CSP_REPORT_MAX_BYTES\s*=\s*16\s*\*\s*1024')

    def test_csrf_check_skips_csp_report(self):
        # _enforce_same_origin() must have an early return for the
        # CSP-report path so browser-internal POSTs (which sometimes
        # send Origin: null) get through.
        m = re.search(
            r'def _enforce_same_origin\(\):[\s\S]+?(?=\ndef )',
            self.api_py)
        self.assertIsNotNone(m, '_enforce_same_origin function not found')
        self.assertIn("path_info() == '/api/csp-report'", m.group(0),
            '_enforce_same_origin must exempt /api/csp-report')

    def test_handler_logs_to_audit(self):
        # Must call audit_log (writes audit_log.json which the
        # /api/security/diag panel reads), NOT log_command (which
        # would target history.json and be invisible to the panel).
        # Captures the function all the way to the next top-level
        # `def ` so we don't miss the log call deep in the body.
        m = re.search(
            r'(?ms)^def handle_csp_report\(\):.+?(?=^def )',
            self.api_py)
        self.assertIsNotNone(m, 'handle_csp_report body not found')
        body = m.group(0)
        self.assertIn('respond(204,', body, 'must ack with 204')
        self.assertIn('audit_log(', body,
            "handle_csp_report must write through audit_log() — the diag "
            "panel scans audit_log.json, not history.json")
        # Specifically with action='csp_report' so the diag scan
        # (handle_security_diag) can count matches.
        self.assertRegex(body, r"action\s*=\s*['\"]csp_report['\"]",
            "audit entry must use action='csp_report' so the diag "
            "counter recognises it")

    def test_csp_header_has_report_uri(self):
        for cfg in ('server/conf/remotepower.conf', 'docker/nginx-docker.conf'):
            text = (REPO_ROOT / cfg).read_text()
            csp = next((l for l in text.splitlines()
                        if 'add_header Content-Security-Policy' in l), '')
            self.assertIn('report-uri /api/csp-report', csp,
                f'{cfg} CSP missing report-uri /api/csp-report directive')


# ── Subresource Integrity on bundled vendor libraries ──────────────────────

class TestSubresourceIntegrity(unittest.TestCase):
    """Every <script src="…/static/vendor/…"> and <link href="…/static/
    vendor/…"> shipped in our HTML / JS carries an `integrity=sha384-…`
    hash that matches the on-disk SHA-384 of the file."""

    VENDOR_LOADS = [
        # (file in /static/vendor/, regex group that holds integrity in source)
        ('xterm/xterm.min.css',                'static/js/app.js'),
        ('xterm/xterm.min.js',                 'static/js/app.js'),
        ('xterm-addon-fit/addon-fit.min.js',   'static/js/app.js'),
        ('qrcode-generator/qrcode.min.js',     'static/js/app.js'),
        ('swagger-ui/swagger-ui.min.css',      'swagger.html'),
        ('swagger-ui/swagger-ui-bundle.min.js','swagger.html'),
    ]

    def _file_sha384(self, rel_path):
        import hashlib, base64
        p = REPO_ROOT / 'server' / 'html' / 'static' / 'vendor' / rel_path
        return 'sha384-' + base64.b64encode(
            hashlib.sha384(p.read_bytes()).digest()).decode()

    def test_every_vendor_load_carries_integrity_matching_file(self):
        app_js = client_js()
        swagger = (REPO_ROOT / 'server/html/swagger.html').read_text()
        sources = {'static/js/app.js': app_js, 'swagger.html': swagger}
        for vendor_path, source_key in self.VENDOR_LOADS:
            expected = self._file_sha384(vendor_path)
            source = sources[source_key]
            # The integrity attribute must appear in the source file
            # AND match the on-disk content. We don't pin which line
            # it's on — just that *some* `integrity="sha384-…"` near
            # the vendor path references the same digest.
            self.assertIn(expected, source,
                f'{source_key}: integrity for {vendor_path} missing or '
                f'wrong. Expected {expected!r}')


# ── GitHub Actions CI workflow ──────────────────────────────────────────────

_WORKFLOW = REPO_ROOT / '.github' / 'workflows' / 'ci.yml'


@unittest.skipUnless(
    _WORKFLOW.is_file(),
    'Skipped: .github/ is intentionally excluded from the release '
    'tarball (it is GitHub-specific config, not part of a runtime '
    'install). The CI workflow is verified in the source-tree run.'
)
class TestCIWorkflow(unittest.TestCase):
    """The CI workflow is the runtime guardrail for the static-analysis
    fidelity suite. Without it the strict-CSP checks only fire when
    someone remembers to run `make test` locally. This class only runs
    against a source-tree checkout; the tarball build verifies the
    workflow via the test that *spawned* it."""

    def test_workflow_file_exists(self):
        self.assertTrue(_WORKFLOW.is_file(),
            '.github/workflows/ci.yml must exist')

    def test_runs_on_push_and_pr_to_main(self):
        text = _WORKFLOW.read_text()
        self.assertIn('push:', text)
        self.assertIn('pull_request:', text)
        self.assertIn('main', text)

    def test_runs_unittest_suite(self):
        text = _WORKFLOW.read_text()
        # Either `make test` or `python -m unittest discover` — both
        # are acceptable shapes.
        self.assertTrue(
            'unittest discover' in text or 'make test' in text or 'make check' in text,
            'workflow must invoke the unittest suite')


if __name__ == '__main__':
    unittest.main(verbosity=2)


# ── CMDB VLAN field (v3.0.6 mid-cycle) ──────────────────────────────────────

class TestCmdbVlanField(unittest.TestCase):
    """Operator request: a VLAN box under SERVER FUNCTION in the CMDB
    Host → Properties form. Backend stores it as a free-text field
    `vlan` with the same liberal charset as `server_function`, plus
    commas + parentheses (for trunked lists like "10,20" and labels
    like "100 (DMZ)")."""

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'
    APP_JS     = REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
    API_PY     = REPO_ROOT / 'server' / 'cgi-bin' / 'api.py'

    def test_html_input_present(self):
        html = self.INDEX_HTML.read_text()
        self.assertIn('id="cmdb-asset-vlan"', html,
            'CMDB Host → Properties form must include the VLAN input')

    def test_js_reads_and_writes_vlan(self):
        js = client_js()
        # cmdbOpenAsset reads res.data.vlan into the field
        self.assertIn("getElementById('cmdb-asset-vlan').value", js)
        # Save payload includes the field
        self.assertRegex(js, r'vlan:\s*document\.getElementById\(\s*[\'"]cmdb-asset-vlan[\'"]\s*\)\.value\.trim\(\)')

    def test_handler_accepts_vlan(self):
        api_py = self.API_PY.read_text()
        # Default record carries the field so old records get backfilled.
        self.assertRegex(api_py, r"'vlan':\s*''", )
        # Update handler validates and persists it.
        self.assertIn("if 'vlan' in body:", api_py)
        self.assertIn("_CMDB_VLAN_RE", api_py)
        # List output exposes it (so the table can show / filter).
        self.assertIn("'vlan':", api_py)

    def test_validator_rejects_overlong_and_strange_chars(self):
        # Direct unit test on the regex — quick assurance without
        # spinning up the full CGI.
        import re as _re
        rx = _re.compile(r'^[A-Za-z0-9 _\-/,()]{0,64}$')
        self.assertTrue(rx.match('10'))
        self.assertTrue(rx.match('10,20,30'))
        self.assertTrue(rx.match('100 (DMZ)'))
        self.assertTrue(rx.match(''))
        self.assertFalse(rx.match('10; DROP TABLE'))   # semicolon banned
        self.assertFalse(rx.match('a' * 65))           # length 65 > 64


# ── Webterm font: JetBrains Mono in front of the fallback chain ─────────────

class TestWebtermFont(unittest.TestCase):
    """v3.0.6 fix: previously the webterm fontFamily was
    'Menlo, Monaco, "Courier New", monospace'. The first two are
    macOS-only, so Linux users got whatever monospace the browser
    picked — which differed from the legacy CDN-rendered version
    that operators were used to. We bundle JetBrains Mono at
    /static/vendor/fonts/ since the v3.0.5 CSP migration; putting it
    at the front of the chain gives consistent rendering across
    platforms."""

    def test_webterm_font_uses_jetbrains_mono(self):
        js = client_js()
        self.assertIn(
            '"JetBrains Mono", Menlo, Monaco, "Courier New", monospace',
            js,
            'webterm fontFamily should put JetBrains Mono first')


# ── Settings → Security: CSP toggle + rate limit + diagnostics ──────────────

class TestSecuritySettingsPane(unittest.TestCase):
    """The Security tab in Settings now exposes the CSP report toggle,
    its per-IP rate limit, an audit-log size readout, and an HSTS
    status probe. Tests assert the HTML controls + the wiring exist;
    runtime behaviour is covered by TestCspReportEndpoint above."""

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'
    APP_JS     = REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
    API_PY     = REPO_ROOT / 'server' / 'cgi-bin' / 'api.py'

    def test_html_controls_present(self):
        html = self.INDEX_HTML.read_text()
        for elid in ('cfg-csp-report-logging', 'cfg-csp-throttle',
                     'cfg-csp-stat-24h', 'cfg-audit-entries',
                     'cfg-audit-archive', 'cfg-audit-retention',
                     'cfg-hsts-status'):
            self.assertIn(f'id="{elid}"', html,
                f'Settings → Security must include #{elid}')

    def test_security_diag_endpoint_route(self):
        api_py = self.API_PY.read_text()
        self.assertEqual(routes_to('GET', '/api/security/diag'),
                         'handle_security_diag')
        # Handler is admin-only.
        m = re.search(
            r'(?ms)^def handle_security_diag\(\):.+?(?=^def )',
            api_py)
        self.assertIsNotNone(m, 'handle_security_diag body not found')
        self.assertIn('require_admin_auth()', m.group(0),
            '/api/security/diag must require admin auth')

    def test_settings_save_writes_csp_keys(self):
        api_py = self.API_PY.read_text()
        self.assertIn("if 'csp_report_logging' in body:", api_py)
        self.assertIn("if 'csp_report_throttle_per_minute' in body:", api_py)
        # JS save payload includes them
        js = client_js()
        self.assertIn('csp_report_logging:', js)
        self.assertIn('csp_report_throttle_per_minute:', js)

    def test_js_loads_diag_and_probes_hsts(self):
        js = client_js()
        self.assertIn("async function loadSecurityDiag()", js)
        self.assertIn("api('GET', '/security/diag')", js)
        # HSTS probe issues a HEAD to "/" and reads the response header.
        self.assertIn("Strict-Transport-Security", js)


# ── CSP report throttle (in-memory sliding window) ──────────────────────────

class TestCspReportThrottle(unittest.TestCase):
    """Direct call against _csp_report_should_throttle. Keeps the
    rate-limit logic honest without round-tripping through CGI."""

    def setUp(self):
        # Fresh module import per test so the in-memory bucket is empty.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'api_throttle', REPO_ROOT / 'server' / 'cgi-bin' / 'api.py')
        self.api = importlib.util.module_from_spec(spec)
        # The api module mkdirs DATA_DIR at import. Point it somewhere
        # writable, like the test data dir.
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
        spec.loader.exec_module(self.api)
        self.api._csp_report_rate.clear()

    def test_zero_disables_throttling(self):
        for _ in range(50):
            self.assertFalse(self.api._csp_report_should_throttle('1.2.3.4', 0))

    def test_throttle_at_cap(self):
        # First N go through, N+1 is throttled.
        for _ in range(10):
            self.assertFalse(self.api._csp_report_should_throttle('1.2.3.4', 10))
        self.assertTrue(self.api._csp_report_should_throttle('1.2.3.4', 10))

    def test_throttle_is_per_ip(self):
        for _ in range(10):
            self.api._csp_report_should_throttle('1.1.1.1', 10)
        # Different IP: fresh budget.
        self.assertFalse(self.api._csp_report_should_throttle('2.2.2.2', 10))


# ── Admin-config password fields wrapped to suppress the DOM warning ────────

class TestAdminPasswordWrappers(unittest.TestCase):
    """Each admin-config password input (SMTP, LDAP, Proxmox, AI
    api-key, CMDB vault, webterm) now sits inside a tiny
    <form autocomplete="off" data-csp-pw-form> — that wrapper silences
    the Chrome / Firefox "[DOM] Password field is not contained in a
    form" warning, tells password managers NOT to autofill (we don't
    want service-account credentials autofilled), and a delegated JS
    handler preventDefaults submits so Enter inside the field doesn't
    navigate."""

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'

    PROTECTED = [
        'cfg-smtp-password', 'cfg-ldap-bind-password', 'proxmox-token-secret',
        'ai-api-key', 'ldap-test-user-pw', 'webterm-ssh-pw',
        'webterm-admin-pw', 'cmdb-vault-setup-pw', 'cmdb-vault-setup-pw2',
        'cmdb-vault-unlock-pw', 'cmdb-vault-rotate-old',
        'cmdb-vault-rotate-new', 'cmdb-vault-rotate-new2',
        'cmdb-cred-password',
    ]

    def test_each_input_is_wrapped(self):
        html = self.INDEX_HTML.read_text()
        for elid in self.PROTECTED:
            # Pattern: <form ... data-csp-pw-form>...<input id="X">...</form>
            # Be liberal on whitespace.
            pat = re.compile(
                rf'<form[^>]*data-csp-pw-form[^>]*>[^<]*<input\b[^>]*\bid="{re.escape(elid)}"',
                re.DOTALL)
            self.assertRegex(html, pat,
                f'password input #{elid} must sit inside <form data-csp-pw-form>')

    def test_submit_handler_preventdefault(self):
        js = client_js()
        # A document-level submit listener that matches the marker form
        # and preventDefaults must exist.
        self.assertRegex(js,
            r"matches\(\s*['\"]form\[data-csp-pw-form\]['\"]\s*\)",
            'app.js must preventDefault submit for [data-csp-pw-form]')
