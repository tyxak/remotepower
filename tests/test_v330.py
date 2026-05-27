"""v3.3.0 release tests.

Strict version pins for v3.3.0. The v3.2.2 strict pin loosens to regex
when this file ships, following the same convention every prior
release-bump test followed.

v3.3.0 is a substantial feature + audit release:
  - Phase A: surgical correctness fixes (service-report locking,
    operator-precedence bug, device-delete cleanup races, dedup of
    duplicate CONFIG_FILE loads in _compute_attention).
  - Phase B: performance — slim /api/devices, consolidated /api/home,
    batch sysinfo endpoint, file-backed attention cache, brute-force
    state short-circuit.
  - Phase C: security — per-IP rate limits on enrollment + login,
    SSRF defaults flipped, alert-mutation flag, re-enrollment audit
    logging + token rotation.
  - Phase D: hash-based agent self-update (PRIMARY signal — version
    string is informational only), fleet-events archive write moved
    out of the flock, optional /api/devices pagination.
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestVersionBumps(unittest.TestCase):
    """v3.3.0 takes the strict version pin (following prior convention)."""
    EXPECTED = '3.3.0'

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

    # ── Audit feature regression tests ──────────────────────────────────

    def test_process_service_report_uses_lockedupdate(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # The function must use _LockedUpdate to scope the services.json
        # mutation — bare load/save races on concurrent heartbeats.
        m = re.search(
            r'def process_service_report\(.*?\n(?:.*?\n){0,80}',
            text, re.DOTALL)
        self.assertIsNotNone(m, 'process_service_report missing')
        self.assertIn('_LockedUpdate(SERVICES_FILE)', m.group(0),
            'process_service_report must use _LockedUpdate(SERVICES_FILE)')

    def test_record_service_transition_uses_lockedupdate(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(
            r'def _record_service_transition\(.*?\n(?:.*?\n){0,15}',
            text, re.DOTALL)
        self.assertIsNotNone(m, '_record_service_transition missing')
        self.assertIn('_LockedUpdate(SERVICE_HIST_FILE)', m.group(0),
            '_record_service_transition must use _LockedUpdate')

    def test_home_endpoint_registered(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'/api/home'", text,
            '/api/home consolidation endpoint must be registered')
        self.assertIn('def handle_home(', text,
            'handle_home implementation missing')

    def test_batch_sysinfo_endpoint_registered(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'/api/devices/sysinfo'", text,
            'batch sysinfo endpoint must be registered')
        self.assertIn('def handle_sysinfo_batch(', text)

    def test_attention_cache_helper(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def _attention_payload(', text,
            '_attention_payload (file-backed cache) must exist')

    def test_ip_ratelimit_helper(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def _ip_ratelimit(', text,
            '_ip_ratelimit helper must exist for per-IP throttling')

    def test_enroll_register_rate_limited(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(
            r'def handle_enroll_register\(.*?\n(?:.*?\n){0,15}',
            text, re.DOTALL)
        self.assertIsNotNone(m, 'handle_enroll_register missing')
        self.assertIn("_ip_ratelimit('enroll'", m.group(0),
            'handle_enroll_register must apply per-IP rate limit')

    def test_login_rate_limited(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(
            r'def handle_login\(.*?\n(?:.*?\n){0,20}',
            text, re.DOTALL)
        self.assertIsNotNone(m, 'handle_login missing')
        self.assertIn("_ip_ratelimit('login'", m.group(0),
            'handle_login must apply per-IP rate limit')

    def test_webhook_block_local_default_on(self):
        # The default reads `cfg.get('webhook_block_local', True)`
        # (default True; flipped from prior default False).
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertRegex(text,
            r"cfg\.get\(['\"]webhook_block_local['\"],\s*True\)",
            'webhook_block_local must default to True')

    def test_alert_mutation_uses_perm_check(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def _check_alert_mutation_perm(', text,
            'alert ack/unack/resolve must share _check_alert_mutation_perm')
        # All three handlers must use the helper, not bare require_auth().
        for fn in ('handle_alert_ack', 'handle_alert_unack', 'handle_alert_resolve'):
            m = re.search(
                rf'def {fn}\(.*?\n(?:.*?\n){{0,5}}',
                text, re.DOTALL)
            self.assertIsNotNone(m, f'{fn} missing')
            self.assertIn('_check_alert_mutation_perm', m.group(0),
                f'{fn} must call _check_alert_mutation_perm')

    def test_agent_update_is_hash_driven(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(
            r'def check_for_update\(.*?\n(?:.*?\n){0,80}',
            text, re.DOTALL)
        self.assertIsNotNone(m, 'check_for_update missing')
        # The decision must NOT pivot on a tuple version comparison.
        body = m.group(0)
        self.assertNotIn('vt(remote_version) <= vt(VERSION)', body,
            'v3.3.0 dropped version-tuple comparison from update check')
        self.assertIn('hashlib.sha256(AGENT_BINARY.read_bytes())', body,
            'check_for_update must compute local sha256')
        self.assertIn('compare_digest', body,
            'check_for_update must use constant-time hash comparison')

    def test_agent_sha256_cache_helper(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn('def _get_agent_sha256(', text,
            'server must cache the canonical agent binary sha256')

    def test_fleet_event_archive_outside_lock(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        # Find the _record_fleet_event body and confirm the gzip block
        # follows (rather than is nested inside) the _LockedUpdate
        # context manager.
        m = re.search(
            r'def _record_fleet_event\(.*?(?=\ndef )',
            text, re.DOTALL)
        self.assertIsNotNone(m, '_record_fleet_event missing')
        body = m.group(0)
        with_idx = body.find('with _LockedUpdate(FLEET_EVENTS_FILE)')
        gzip_idx = body.find('import gzip')
        self.assertGreater(with_idx, 0, 'no _LockedUpdate scope found')
        self.assertGreater(gzip_idx, with_idx,
            'gzip archive write must follow (not nest inside) the flock scope')


if __name__ == '__main__':
    unittest.main()
