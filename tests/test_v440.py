#!/usr/bin/env python3
"""Strict version-surface pins + security-regression tests for v4.4.0
"FortifyMatters".

Loosen the TestVersionBumps strict pins to regex on the next bump (see
tests/test_v430.py for the pattern). The security tests below are permanent
regression guards for the fixes shipped in this release.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v440", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import prometheus_export   # noqa: E402


class TestVersionBumps(unittest.TestCase):
    V = '4.4.0'

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / 'client/remotepower-agent.py').read_text())
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f'remotepower-shell-v{self.V}',
                      (_ROOT / 'server/html/sw.js').read_text())
        self.assertIn(f'?v={self.V}', (_ROOT / 'server/html/index.html').read_text())

    def test_readme_and_changelog(self):
        self.assertIn(f'version-{self.V}-blue', (_ROOT / 'README.md').read_text())
        self.assertIn(f'v{self.V}', (_ROOT / 'CHANGELOG.md').read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f'docs/v{self.V}.md').exists())

    def test_security_review_doc_exists(self):
        self.assertTrue((_ROOT / f'docs/security-review-{self.V}.md').exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_security_reviews_keep_three(self):
        revs = sorted(p.name for p in (_ROOT / 'docs').glob('security-review-*.md'))
        self.assertEqual(len(revs), 3, f'expected exactly 3 security reviews, got {revs}')

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}",
                      (_ROOT / 'server/html/index.html').read_text())

    def test_manual_version(self):
        self.assertIn(f'Version {self.V} —', (_ROOT / 'docs/Manual.html').read_text())


class TestAdminGateEscalation(unittest.TestCase):
    """CRITICAL fix: require_admin must reject custom operator roles, not just
    the built-in viewer/mcp by name."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._roles = api.ROLES_FILE
        api.ROLES_FILE = self.d / 'roles.json'
        api.save(api.ROLES_FILE, {'roles': [
            {'name': 'operator', 'permissions': ['command'],
             'scope': {'type': 'all'}}]})
        self._orig = {n: getattr(api, n) for n in
                      ('verify_token', 'get_token_from_request', 'respond')}
        api.get_token_from_request = lambda: 't'
        self.cap = {}

        def _resp(s, b=None):
            self.cap['s'] = s
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        api.ROLES_FILE = self._roles
        for n, v in self._orig.items():
            setattr(api, n, v)

    def _require_admin_as(self, role):
        api.verify_token = lambda t: ('u', role)
        self.cap.clear()
        try:
            api.require_auth(require_admin=True)
        except api.HTTPError:
            pass
        return self.cap.get('s')

    def test_custom_role_is_denied_admin(self):
        self.assertEqual(self._require_admin_as('operator'), 403)

    def test_unknown_role_is_denied_admin(self):
        self.assertEqual(self._require_admin_as('whatever'), 403)

    def test_viewer_and_mcp_still_denied(self):
        self.assertEqual(self._require_admin_as('viewer'), 403)
        self.assertEqual(self._require_admin_as('mcp'), 403)

    def test_admin_still_passes(self):
        # admin must NOT trigger a 403 respond()
        self.assertIsNone(self._require_admin_as('admin'))

    def test_resolve_role_marks_custom_non_admin(self):
        self.assertFalse(api._resolve_role('operator')['admin'])
        self.assertTrue(api._resolve_role('admin')['admin'])


class TestMetricsResilience(unittest.TestCase):
    """MEDIUM fix: a single malformed store record must not blow up the whole
    Prometheus scrape."""

    def _ctx(self, devices):
        return {
            'server_version': '4.4.0', 'now': 1_700_000_000, 'online_ttl': 300,
            'devices': devices, 'monitors': [], 'monitor_state': {},
            'schedule': [], 'pending_cmds': {}, 'webhook_log': [],
            'webhook_log_cap': 100, 'cve_findings': {}, 'cve_ignore': {},
            'services': {}, 'maintenance_active_count': 0, 'health': {},
            'fleet_events': {}, 'cve_fixable_total': 0,
        }

    def test_non_dict_device_record_skipped(self):
        body = prometheus_export.generate_metrics(
            self._ctx({'good': {'name': 'web1', 'last_seen': 1_700_000_000},
                       'bad': 'not-a-dict'}))
        self.assertIn('remotepower_info', body)
        self.assertIn('web1', body)

    def test_devices_not_a_dict(self):
        body = prometheus_export.generate_metrics(self._ctx([1, 2, 3]))
        self.assertIn('remotepower_info', body)

    def test_malformed_cve_finding_skipped(self):
        ctx = self._ctx({'d1': {'name': 'h', 'last_seen': 1}})
        ctx['cve_findings'] = {'d1': {'findings': ['oops', {'severity': 'high'}]}}
        body = prometheus_export.generate_metrics(ctx)
        self.assertIn('remotepower_device_cve_findings', body)


class TestRouterosSsrfGuard(unittest.TestCase):
    """MEDIUM fix: _routeros_target must refuse loopback/link-local/metadata
    hosts while still allowing the RFC1918 LAN address a router lives on."""

    def _dev(self, ip):
        return {'ip': ip, 'routeros': {'enabled': True, 'username': 'admin',
                                       'password': 'x', 'port': 443}}

    def test_metadata_host_refused(self):
        self.assertIsNone(api._routeros_target(self._dev('169.254.169.254')))

    def test_loopback_refused(self):
        self.assertIsNone(api._routeros_target(self._dev('127.0.0.1')))

    def test_rfc1918_allowed(self):
        tgt = api._routeros_target(self._dev('10.0.0.1'))
        self.assertIsNotNone(tgt)
        self.assertEqual(tgt[0], '10.0.0.1:443')


class TestCommandQuotingSource(unittest.TestCase):
    """HIGH fix: the drift file-fetch and ACME command builders must use
    shlex.quote rather than hand-rolled single-quoting."""

    def test_api_imports_shlex(self):
        self.assertRegex((_CGI / 'api.py').read_text(), r'\nimport shlex\b')

    def test_drift_fetch_uses_shlex_quote(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn('exec:cat {shlex.quote(', src)
        self.assertNotIn("exec:cat '{p}'", src)

    def test_acme_uses_shlex_quote(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("shlex.quote(f'{home}/acme.sh')", src)


class TestAgentTransportParity(unittest.TestCase):
    """HIGH/LOW fix: the Windows and macOS agents must enforce HTTPS and a TLS
    1.2 floor, matching the Linux agent."""

    def test_win_mac_reject_plain_http(self):
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            src = (_ROOT / rel).read_text()
            self.assertIn("url.startswith('https://')", src, rel)
            self.assertIn('TLSVersion.TLSv1_2', src, rel)

    def test_win_mac_pass_ssl_context(self):
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertIn('context=_SSL_CTX', (_ROOT / rel).read_text(), rel)


class TestLynisTempfile(unittest.TestCase):
    """HIGH fix: the agent's lynis report must use a private temp file, not a
    fixed predictable /tmp path."""

    def test_no_fixed_tmp_report_path(self):
        src = (_ROOT / 'client/remotepower-agent.py').read_text()
        # the dangerous fixed-path *assignment* must be gone (the substring may
        # still appear in the explanatory comment, which is fine)
        self.assertNotIn("report = '/tmp/rp-lynis-report.dat'", src)
        self.assertIn("tempfile.mkstemp(prefix='rp-lynis-'", src)


class TestReleaseTarballExcludes(unittest.TestCase):
    """v4.4.0: the `make dist` tarball must never ship environment-specific or
    internal files — the gitignored deploy/ tree (real hostnames, cert paths,
    the IP allowlist) and the docs/*-internal.md planning notes leaked into the
    release archive until this was fixed. Pin the exclude list."""

    def test_makefile_dist_excludes_sensitive(self):
        mk = (_ROOT / 'Makefile').read_text()
        # isolate the dist: target body
        dist = mk.split('\ndist:', 1)[1].split('\n\n', 1)[0]
        for needle in ("--exclude='./deploy'",
                       "--exclude='./docs/*-internal.md'",
                       "--exclude='./site'",
                       "--exclude='./CLAUDE.md'"):
            self.assertIn(needle, dist, f'dist target missing {needle}')


if __name__ == '__main__':
    unittest.main()
