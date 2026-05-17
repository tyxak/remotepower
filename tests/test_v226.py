#!/usr/bin/env python3
"""
Tests for v2.2.6 — correctness + agent telemetry release.

Covers:
  - CVE scanner: _already_patched suppresses already-fixed packages
    (the lua5.1 false-positive regression), keeps genuine vulns,
    multi-candidate fixed lists, fail-safe on uncertainty.
  - Drift: dormant handling for files absent from the host;
    expanded default watch list; overview excludes dormant.
  - Agent: get_host_health collects reboot-required / failed units /
    listening ports etc. (smoke test — runs on the test host).
  - Docker entrypoint: random password path present.
  - Frontend / asset presence for the v2.2.6 UI additions.
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec_cve = importlib.util.spec_from_file_location("cve_v226", _CGI_BIN / "cve_scanner.py")
cve = importlib.util.module_from_spec(_spec_cve)
_spec_cve.loader.exec_module(cve)


# ─── CVE comparator ──────────────────────────────────────────────────────


class TestAlreadyPatched(unittest.TestCase):
    """The core fix — version comparison gating CVE findings."""

    def test_lua_false_positive_suppressed(self):
        # The exact case from the field report: installed package is
        # NEWER than the ESM fix, dpkg confirms it. Must be suppressed.
        self.assertTrue(
            cve._already_patched('5.1.5-9build2',
                                 '5.1.5-8.1ubuntu0.22.04.1~esm1', 'Ubuntu'),
            "installed > fixed ESM version should be suppressed")

    def test_genuine_vuln_kept(self):
        # Installed is OLDER than the fix — a real exposure, keep it.
        self.assertFalse(
            cve._already_patched('5.1.5-7',
                                 '5.1.5-8.1ubuntu0.22.04.1~esm1', 'Ubuntu'),
            "installed < fixed should NOT be suppressed")

    def test_no_fixed_version_kept(self):
        # OSV gave no fixed version — can't tell, keep the finding.
        self.assertFalse(cve._already_patched('5.1.5-9build2', '', 'Ubuntu'))
        self.assertFalse(cve._already_patched('5.1.5-9build2', None, 'Ubuntu'))

    def test_multi_candidate_fixed_list(self):
        # _extract_fixed_versions joins up to 3 fixed versions with ', '.
        # Patched if installed >= ANY one of them.
        self.assertTrue(
            cve._already_patched('2.0', '1.5, 3.0', 'Ubuntu'),
            "installed >= one of the fixed candidates")
        self.assertFalse(
            cve._already_patched('1.0', '1.5, 3.0', 'Ubuntu'),
            "installed below all candidates → keep")

    def test_equal_version_is_patched(self):
        # installed == fixed means the fix is in — suppress.
        self.assertTrue(
            cve._already_patched('1.2.3-4', '1.2.3-4', 'Ubuntu'))

    def test_debian_ecosystem_uses_dpkg(self):
        # Debian:12 ecosystem also routes through dpkg comparison.
        self.assertTrue(
            cve._already_patched('2.0-3', '2.0-1', 'Debian:12'))

    def test_non_debian_falls_back_to_tuple(self):
        # PyPI etc. — tuple comparator. 2.0 >= 1.5 → patched.
        self.assertTrue(cve._already_patched('2.0', '1.5', 'PyPI'))
        self.assertFalse(cve._already_patched('1.0', '1.5', 'PyPI'))

    def test_tuple_comparator_basic(self):
        self.assertTrue(cve._tuple_ge('1.2.3', '1.2.0'))
        self.assertTrue(cve._tuple_ge('2.0.0', '1.9.9'))
        self.assertFalse(cve._tuple_ge('1.0.0', '1.0.1'))
        self.assertTrue(cve._tuple_ge('1.0', '1.0'))


# ─── Drift: dormant handling + expanded watch list ──────────────────────


class TestDriftV226(unittest.TestCase):

    def setUp(self):
        _spec = importlib.util.spec_from_file_location(
            "api_v226_drift", _CGI_BIN / "api.py")
        self.api = importlib.util.module_from_spec(_spec)
        # api.py imports cleanly without exec side effects? It does CGI
        # dispatch at bottom guarded by __name__; safe to exec.
        import os
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _spec.loader.exec_module(self.api)
        self._tmp = Path(tempfile.mkdtemp())
        self.api.DATA_DIR         = self._tmp
        self.api.DRIFT_STATE_FILE = self._tmp / 'drift_state.json'
        self.api.DEVICES_FILE     = self._tmp / 'devices.json'
        self.api.CONFIG_FILE      = self._tmp / 'config.json'
        self.api.FLEET_EVENTS_FILE = self._tmp / 'fleet_events.json'
        self._calls = []
        self.api.fire_webhook = lambda ev, p: self._calls.append((ev, p))
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})

    def test_expanded_default_watch_list(self):
        # v2.2.6 added passwd / group / login.defs / common-auth / apt sources
        wf = self.api.DEFAULT_WATCHED_FILES
        for expected in ('/etc/passwd', '/etc/group', '/etc/login.defs',
                         '/etc/pam.d/common-auth', '/etc/apt/sources.list'):
            self.assertIn(expected, wf, f'{expected} missing from watch list')
        # The originals are still there
        self.assertIn('/etc/ssh/sshd_config', wf)
        self.assertIn('/etc/sudoers', wf)

    def test_missing_file_goes_dormant(self):
        api = self.api
        api._ingest_drift_report('d1', {
            '/etc/x': {'hash': 'sha256:a', 'size': 1, 'mtime': 1, 'exists': True},
        })
        # Below threshold — not dormant yet
        api._ingest_drift_report('d1', {
            '/etc/x': {'hash': None, 'size': 0, 'mtime': 0, 'exists': False},
        })
        st = api.load(api.DRIFT_STATE_FILE)
        self.assertFalse(st['d1']['files']['/etc/x'].get('dormant'))
        # Reach the threshold
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER - 1):
            api._ingest_drift_report('d1', {
                '/etc/x': {'hash': None, 'size': 0, 'mtime': 0, 'exists': False},
            })
        st = api.load(api.DRIFT_STATE_FILE)
        self.assertTrue(st['d1']['files']['/etc/x']['dormant'])

    def test_dormant_file_revives(self):
        api = self.api
        api._ingest_drift_report('d1', {
            '/etc/x': {'hash': 'sha256:a', 'size': 1, 'mtime': 1, 'exists': True},
        })
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER):
            api._ingest_drift_report('d1', {
                '/etc/x': {'hash': None, 'size': 0, 'mtime': 0, 'exists': False},
            })
        self.assertTrue(api.load(api.DRIFT_STATE_FILE)['d1']['files']['/etc/x']['dormant'])
        # File comes back
        api._ingest_drift_report('d1', {
            '/etc/x': {'hash': 'sha256:a', 'size': 1, 'mtime': 9, 'exists': True},
        })
        f = api.load(api.DRIFT_STATE_FILE)['d1']['files']['/etc/x']
        self.assertFalse(f['dormant'])
        self.assertEqual(f.get('missing_streak'), 0)
        self.assertIn('revived_at', f)

    def test_dormant_excluded_from_overview_drift_count(self):
        api = self.api
        # Make a file dormant
        api._ingest_drift_report('d1', {
            '/etc/x': {'hash': 'sha256:a', 'size': 1, 'mtime': 1, 'exists': True},
        })
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER):
            api._ingest_drift_report('d1', {
                '/etc/x': {'hash': None, 'size': 0, 'mtime': 0, 'exists': False},
            })
        # Drift overview must not count the dormant file as drifted
        captured = {}
        def fake_respond(status, body):
            captured['status'] = status
            captured['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_auth = lambda **kw: 'admin'
        try:
            api.handle_drift_overview()
        except SystemExit:
            pass
        row = captured['body']['devices'][0] if 'devices' in captured['body'] else captured['body'][0]
        self.assertEqual(row['drifted'], 0, 'dormant file must not count as drift')
        self.assertEqual(row['dormant'], 1, 'dormant counted separately')


# ─── Agent host-health collector ─────────────────────────────────────────


class TestAgentHostHealth(unittest.TestCase):
    """Smoke test — get_host_health runs on the test host without raising
    and returns the documented shape. Values themselves vary by host."""

    @classmethod
    def setUpClass(cls):
        # The agent file has no .py extension — spec_from_file_location
        # can't infer a loader, so build one explicitly.
        import importlib.machinery
        loader = importlib.machinery.SourceFileLoader(
            "agent_v226", str(_ROOT / "client" / "remotepower-agent"))
        _spec = importlib.util.spec_from_loader("agent_v226", loader)
        cls.agent = importlib.util.module_from_spec(_spec)
        loader.exec_module(cls.agent)

    def test_get_host_health_runs(self):
        result = self.agent.get_host_health()
        self.assertIsInstance(result, dict)

    def test_get_host_health_keys_are_documented(self):
        result = self.agent.get_host_health()
        allowed = {'reboot_required', 'reboot_reason', 'failed_units',
                   'logged_in', 'listening_ports', 'last_boot'}
        for k in result:
            self.assertIn(k, allowed, f'undocumented key {k!r}')

    def test_listening_ports_shape(self):
        result = self.agent.get_host_health()
        if 'listening_ports' in result:
            for p in result['listening_ports']:
                self.assertIn('proto', p)
                self.assertIn('port', p)
                self.assertIsInstance(p['port'], int)


# ─── Docker / asset presence ─────────────────────────────────────────────


class TestV226Assets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.entrypoint = (_ROOT / 'docker/entrypoint.sh').read_text()
        cls.dockerfile = (_ROOT / 'Dockerfile').read_text()
        cls.nginx      = (_ROOT / 'docker/nginx-docker.conf').read_text()
        cls.js         = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.css        = (_ROOT / 'server/html/static/css/styles.css').read_text()

    def test_entrypoint_generates_random_password(self):
        self.assertIn('token_urlsafe', self.entrypoint,
                      'entrypoint should generate a random password')
        self.assertIn('GENERATED ADMIN CREDENTIALS', self.entrypoint,
                      'should print a credentials banner')

    def test_dockerfile_healthcheck_not_curl(self):
        # curl was never installed — healthcheck must use Python
        self.assertNotIn('curl -sf', self.dockerfile)
        self.assertIn('urllib.request', self.dockerfile)

    def test_nginx_no_duplicate_html_mime(self):
        # text/html removed from gzip_types (nginx gzips it implicitly)
        gzip_line = [l for l in self.nginx.splitlines()
                     if 'gzip_types' in l and not l.strip().startswith('#')]
        self.assertTrue(gzip_line)
        self.assertNotIn('text/html', gzip_line[0])

    def test_zindex_normalisation_present(self):
        self.assertIn('z-index normalisation', self.css)
        self.assertIn('body.modal-open', self.css)

    def test_modal_helpers_close_mobile_nav(self):
        # openModal closes the mobile nav drawer
        idx = self.js.find('function openModal')
        chunk = self.js[idx:idx + 400]
        self.assertIn('mobile-nav-open', chunk)
        self.assertIn('modal-open', chunk)

    def test_host_health_renderer_present(self):
        self.assertIn('function _renderHostHealth', self.js)
        self.assertIn('reboot_required', self.js)
        self.assertIn('listening_ports', self.js)

    def test_container_resource_display(self):
        # Container card shows CPU/mem + health badge
        self.assertIn('cpu_percent', self.js)
        self.assertIn('healthBadge', self.js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
