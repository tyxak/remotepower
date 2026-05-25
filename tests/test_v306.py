"""v3.0.6 release tests.

Strict version pins for v3.0.6, plus regression coverage for the four
production-readiness additions: /api/health, /api/csp-report,
Subresource Integrity on bundled vendor libraries, and the GitHub
Actions workflow.

Following the same convention every prior release-bump test followed
(test_v303.py → test_v304.py → test_v305.py): the strict EXPECTED pin
lives here until v3.0.7 ships, at which point this file's pins
loosen to a regex and test_v307.py takes the strict slot.
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.0.6 takes the strict version pin."""
    EXPECTED = '3.0.6'

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
            f'index.html source ?v= must be {self.EXPECTED}')

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
        self.assertIn(
            "elif pi == '/api/health' and m == 'GET': handle_health()",
            self.api_py,
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
        self.assertIn(
            "elif pi == '/api/csp-report' and m == 'POST': handle_csp_report()",
            self.api_py)

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
        # Must call log_command on the audit log. Captures the function
        # all the way to the next top-level `def ` so we don't miss the
        # log call further into the body. The first regex hit was too
        # short and stopped at _CSP_REPORT_MAX_BYTES.
        m = re.search(
            r'(?ms)^def handle_csp_report\(\):.+?(?=^def )',
            self.api_py)
        self.assertIsNotNone(m, 'handle_csp_report body not found')
        body = m.group(0)
        self.assertIn('respond(204,', body, 'must ack with 204')
        self.assertIn('log_command(', body,
            'handle_csp_report must append to the audit log via log_command()')

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
        app_js = (REPO_ROOT / 'server/html/static/js/app.js').read_text()
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
