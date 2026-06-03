"""v3.10.0 release tests.

v3.10.0 is a third bind-it-together / security sweep on top of v3.9.0. These
tests pin the new fixes so they can't silently regress:

  * Security — image-registry SSRF (opener + url_guard routed through every
    fetch incl. the bearer-token realm; realm forced to HTTPS), the
    GET /api/config recursive secret-scrub backstop, the TCP-monitor IP-class
    check, and the Healthchecks.io SSRF-safe opener.
  * Bind — docker/podman restart_count + start time via batched docker inspect;
    ClamAV last-scan timestamp; per-interface MAC in the drawer.
  * Fixes — config-drift alert title (names file/sections, not "? file(s)") and
    the Devices table-view Hostname sort key.

Strict version pins live here until v3.11.0 ships, at which point this file's
pins loosen to a regex (see test_v380.py / test_v390.py for the loosened form).
"""
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
from clientjs import client_js

API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
IMGREG = (REPO_ROOT / 'server' / 'cgi-bin' / 'image_registry.py').read_text()
APP = client_js()


# ─── version bump (strict) ───────────────────────────────────────────────────

class TestVersionBumps(unittest.TestCase):
    EXPECTED = '3.10.0'

    def test_versions(self):
        # v3.11.0: loosened from the exact 3.10.0 pin (the live strict pin
        # moved to tests/test_v3110.py) so a later bump doesn't fail this file.
        self.assertRegex(API, r"SERVER_VERSION\s*=\s*'3\.\d+\.\d+'")
        self.assertRegex((REPO_ROOT / 'client' / 'remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'3\.\d+\.\d+'")
        self.assertRegex((REPO_ROOT / 'server' / 'html' / 'sw.js').read_text(),
                         r"remotepower-shell-v3\.\d+\.\d+")
        self.assertRegex(HTML, r'\?v=3\.\d+\.\d+')
        self.assertRegex((REPO_ROOT / 'README.md').read_text(), r'version-3\.\d+\.\d+-blue\.svg')

    def test_agent_extensionless_matches(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b)

    def test_changelog_and_docs(self):
        # v3.11.0: the top changelog entry now tracks the current version;
        # assert it's a valid version line and that this release's docs remain.
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertRegex(m.group(1), r'\d+\.\d+\.\d+')
        self.assertTrue((REPO_ROOT / 'docs' / 'v3.10.0.md').exists())
        self.assertTrue((REPO_ROOT / 'docs' / 'security-review-3.10.0.md').exists())

    def test_whats_new_card_present(self):
        # loosened: any What's-new card for a 3.1x release satisfies this.
        self.assertRegex(HTML, r"What's new — v3\.\d+\.\d+")


# ─── F1: image-registry SSRF ─────────────────────────────────────────────────

class TestImageRegistrySSRF(unittest.TestCase):
    def setUp(self):
        # Load a pristine module instance under a unique name: test_image_updates
        # monkeypatches the shared `image_registry.remote_digest` with a network
        # stub and never restores it, which would mask the guard we're pinning.
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader(
            'image_registry_v3100',
            str(REPO_ROOT / 'server' / 'cgi-bin' / 'image_registry.py'))
        spec = importlib.util.spec_from_loader('image_registry_v3100', loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        self.ir = mod

    def test_blocked_manifest_url_raises_before_fetch(self):
        # url_guard blocking the manifest must raise BlockedURL (no network).
        with self.assertRaises(self.ir.BlockedURL):
            self.ir.remote_digest('registry-1.docker.io', 'library/nginx', 'latest',
                                  url_guard=lambda u: True)

    def test_bearer_realm_must_be_https(self):
        with self.assertRaises(self.ir.BlockedURL):
            self.ir._build_auth('Bearer realm="http://evil.example/token"', None, 1.0)

    def test_bearer_realm_guarded(self):
        # An https realm that the guard rejects (local/meta) must raise, not fetch.
        with self.assertRaises(self.ir.BlockedURL):
            self.ir._build_auth('Bearer realm="https://evil.example/token"', None, 1.0,
                                url_guard=lambda u: True)

    def test_caller_passes_opener_and_guard(self):
        # The scanner must hand the SSRF-safe opener + url_guard to the client.
        self.assertIn('opener=_img_opener', API)
        self.assertIn('url_guard=_img_guard', API)
        self.assertIn('no_redirect=True', API)

    def test_module_uses_opener_not_bare_urlopen_for_fetches(self):
        # Both fetch sites go through _open(...), not a bare urlopen.
        self.assertIn('def _open(req, timeout, opener)', IMGREG)
        self.assertIn('_open(req, timeout, opener)', IMGREG)


# ─── F2: /api/config secret scrub ────────────────────────────────────────────

class TestConfigSecretScrub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp_v3100_'))
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    def test_scrub_strips_secrets_at_depth(self):
        d = {
            'ai': {'api_key': 'sk-secret', 'model': 'gpt', 'enabled': True},
            'registry_credentials': {'ghcr.io': {'username': 'u', 'password': 'p'}},
            'smtp_password': 'hunter2',
            'webhook_urls': [{'token': 'tok', 'format': 'slack'}],
        }
        self.api._scrub_config_secrets(d)
        self.assertNotIn('api_key', d['ai'])
        self.assertEqual(d['ai']['model'], 'gpt')        # non-secret kept
        self.assertNotIn('registry_credentials', d)       # whole map dropped
        self.assertNotIn('smtp_password', d)
        self.assertNotIn('token', d['webhook_urls'][0])
        self.assertEqual(d['webhook_urls'][0]['format'], 'slack')

    def test_scrub_keeps_indicators_and_ids(self):
        d = {
            'proxmox_token_id': 'root@pam!rp',
            'oidc_client_id': 'abc',
            'smtp_password_set': True,
            'audit_forward_token_set': False,
            'proxmox_token_secret_from_env': True,
            'monitor_interval': 300,
        }
        self.api._scrub_config_secrets(d)
        self.assertEqual(d['proxmox_token_id'], 'root@pam!rp')
        self.assertEqual(d['oidc_client_id'], 'abc')
        self.assertTrue(d['smtp_password_set'])
        self.assertIn('audit_forward_token_set', d)
        self.assertTrue(d['proxmox_token_secret_from_env'])
        self.assertEqual(d['monitor_interval'], 300)

    def test_handler_surfaces_booleans_and_runs_scrub(self):
        self.assertIn("safe['ai_configured']", API)
        self.assertIn("safe['registry_credentials_set']", API)
        self.assertIn('_scrub_config_secrets(safe)', API)


# ─── F3: TCP monitor + healthchecks SSRF ─────────────────────────────────────

class TestMonitorSSRF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp_v3100m_'))
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    def test_tcp_blocks_loopback_and_metadata(self):
        san = self.api._sanitize_monitor_target
        self.assertIsNone(san('tcp', '127.0.0.1:22'))
        self.assertIsNone(san('tcp', '169.254.169.254:80'))

    def test_tcp_allows_rfc1918_lan(self):
        # RFC1918 LAN is the normal monitoring case — allowed by design.
        self.assertEqual(self.api._sanitize_monitor_target('tcp', '192.168.1.10:22'),
                         '192.168.1.10:22')

    def test_tcp_executor_rechecks_peer(self):
        self.assertIn("ok = False; detail = 'blocked'", API)

    def test_healthchecks_uses_safe_opener(self):
        m = re.search(r'def ping_healthchecks_if_due\(\).*?\n\n\ndef ', API, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertIn('_ssrf_safe_opener(', body)
        self.assertNotIn('urllib.request.urlopen(', body)


# ─── F4 / fixes: drift alert title ───────────────────────────────────────────

class TestDriftAlertTitle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp_v3100d_'))
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    def test_drift_detected_names_path(self):
        t = self.api._alert_title('drift_detected',
                                  {'name': 'web01', 'path': '/etc/nginx/nginx.conf',
                                   'exists': True})
        self.assertIn('/etc/nginx/nginx.conf', t)
        self.assertNotIn('? file', t)

    def test_config_drift_counts_sections(self):
        t = self.api._alert_title('config_drift',
                                  {'name': 'web01', 'sections': ['repos', 'users']})
        self.assertIn('2 section', t)
        self.assertNotIn('? file', t)

    def test_config_drift_singular(self):
        t = self.api._alert_title('config_drift', {'name': 'w', 'sections': ['x']})
        self.assertIn('1 section', t)
        self.assertNotIn('sections', t)


# ─── fixes: devices table Hostname sort ──────────────────────────────────────

class TestDevicesHostnameSort(unittest.TestCase):
    def test_hostname_in_columns_and_getcolumns(self):
        self.assertIn("'name', 'hostname', 'group'", APP)
        self.assertRegex(APP, r'hostname:\s*d\.hostname')

    def test_dead_enrolled_key_removed(self):
        # 'enrolled' had no header — it should no longer be a phantom sort column.
        self.assertNotIn("'last_seen', 'enrolled'", APP)


# ─── bind: docker restart_count + start time ─────────────────────────────────

class TestContainerRestartBind(unittest.TestCase):
    def test_agent_has_batched_inspect(self):
        self.assertIn('def _docker_inspect_meta(', AGENT)
        self.assertIn('{{.Id}} {{.RestartCount}} {{.State.StartedAt}}', AGENT)

    def test_listing_uses_inspect_meta(self):
        self.assertIn("im.get('restart_count', 0)", AGENT)
        self.assertIn("im.get('started_at', 0)", AGENT)
        self.assertIn("im.get('uptime_seconds', 0)", AGENT)

    def test_iso_parse_handles_zero_value(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader(
            'rp_agent_v3100', str(REPO_ROOT / 'client' / 'remotepower-agent'))
        spec = importlib.util.spec_from_loader('rp_agent_v3100', loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        self.assertEqual(mod._parse_iso_to_epoch('0001-01-01T00:00:00Z'), 0)
        self.assertEqual(mod._parse_iso_to_epoch(''), 0)
        # Exact UTC epoch — pins that the Z/offset is honoured (not parsed as
        # local time) and that 9-digit fractional seconds don't break it.
        self.assertEqual(mod._parse_iso_to_epoch('2024-01-15T10:30:00Z'), 1705314600)
        self.assertEqual(mod._parse_iso_to_epoch('2024-01-15T10:30:00.123456789Z'), 1705314600)
        # A non-UTC offset resolves to the same instant.
        self.assertEqual(mod._parse_iso_to_epoch('2024-01-15T11:30:00+01:00'), 1705314600)


# ─── bind: clamav last-scan + per-iface MAC ──────────────────────────────────

class TestClamavAndMacBind(unittest.TestCase):
    def test_agent_parses_clamav_scan_date(self):
        self.assertIn("c['last_scan_ts']", AGENT)
        self.assertIn('SCAN SUMMARY', open(REPO_ROOT / 'docs' / 'v3.10.0.md').read())

    def test_ui_renders_clamav_last_scan(self):
        self.assertIn('last scan ${timeAgo(c.last_scan_ts)}', APP)

    def test_ui_renders_iface_mac(self):
        self.assertIn('n.mac', APP)


if __name__ == '__main__':
    unittest.main()
