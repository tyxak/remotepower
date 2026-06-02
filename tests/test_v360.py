"""v3.6.0 release tests.

Strict version pins for v3.6.0 (the v3.5.0 strict pins loosen to regex when this
file ships, per the standing convention).

v3.6.0 is a seven-feature batch: SFTP file manager, backup orchestration, host
user/SSH-key management, endpoint AV posture, host firewall management,
auto-patch policy, and a Proxmox per-guest backup recency check.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import os
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to  # noqa: E402


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.7.0 now holds the strict pin (test_v370.py)."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertRegex(text, r"SERVER_VERSION\s*=\s*'3\.\d+\.\d+'")

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertRegex(text, r"\nVERSION\s*=\s*'3\.\d+\.\d+'")

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b)

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        self.assertRegex((REPO_ROOT / 'README.md').read_text(), r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m)

    def test_release_notes_doc_present(self):
        path = REPO_ROOT / 'docs' / 'v3.6.0.md'
        self.assertTrue(path.exists())
        self.assertIn('3.6.0', path.read_text())


class TestV360Routes(unittest.TestCase):
    def test_all_routes(self):
        cases = [
            ('POST',   '/api/devices/d1/user-action',     'handle_device_user_action'),
            ('POST',   '/api/devices/d1/firewall-action', 'handle_device_firewall_action'),
            ('GET',    '/api/devices/d1/av',              'handle_av_status'),
            ('POST',   '/api/devices/d1/av-scan',         'handle_av_scan'),
            ('GET',    '/api/backup-jobs',                'handle_backup_jobs_list'),
            ('POST',   '/api/backup-jobs',                'handle_backup_job_create'),
            ('PUT',    '/api/backup-jobs/j1',             'handle_backup_job_update'),
            ('DELETE', '/api/backup-jobs/j1',             'handle_backup_job_delete'),
            ('POST',   '/api/backup-jobs/j1/run',         'handle_backup_job_run'),
            ('GET',    '/api/autopatch',                  'handle_autopatch_list'),
            ('POST',   '/api/autopatch',                  'handle_autopatch_create'),
            ('PUT',    '/api/autopatch/p1',               'handle_autopatch_update'),
            ('DELETE', '/api/autopatch/p1',               'handle_autopatch_delete'),
            ('POST',   '/api/autopatch/p1/run',           'handle_autopatch_run'),
            ('GET',    '/api/proxmox/backups',            'handle_proxmox_backups_get'),
            ('POST',   '/api/proxmox/backups/threshold',  'handle_proxmox_backup_threshold'),
        ]
        for method, path, handler in cases:
            self.assertEqual(routes_to(method, path), handler, f'{method} {path}')


class TestV360UserFirewall(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_handlers_exec_gated(self):
        for fn in ('handle_device_user_action', 'handle_device_firewall_action', 'handle_av_scan'):
            m = re.search(rf'def {fn}\(.*?\n(.*?)\ndef ', self.API, re.DOTALL)
            self.assertIsNotNone(m, f'{fn} not found')
            self.assertIn("require_perm('exec'", m.group(1), f'{fn} must be exec-gated')

    def test_input_validation_present(self):
        # username + ssh key validators must exist
        self.assertIn('_SAFE_UNIX_USER', self.API)
        self.assertIn('_SSH_PUBKEY_RE', self.API)

    def test_frontend(self):
        for fn in ('function openUserMgmt(', 'function userAction(',
                   'function openFirewall(', 'function firewallAction(',
                   'function openAvScan(', 'function avScan('):
            self.assertIn(fn, self.APP)
        self.assertIn('id="usermgmt-modal"', self.HTML)
        self.assertIn('id="firewall-modal"', self.HTML)


class TestV360FileManager(unittest.TestCase):
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    DAEMON = (REPO_ROOT / 'server' / 'webterm' / 'remotepower-webterm.py').read_text()

    def test_daemon_sftp_mode(self):
        self.assertIn('async def _run_sftp(', self.DAEMON)
        self.assertIn("if mode == 'sftp':", self.DAEMON)
        self.assertIn("('pty', 'vnc', 'sftp')", self.DAEMON)
        self.assertIn('start_sftp_client()', self.DAEMON)

    def test_frontend(self):
        for fn in ('function openFiles(', 'function filesConnect(', 'function _sftpList(',
                   'function sftpUploadFile(', 'function _sftpDlBtn('):
            self.assertIn(fn, self.APP)
        self.assertIn("mode: 'sftp'", self.APP)
        self.assertIn('id="files-browser"', self.HTML)


class TestV360BackupOrchestration(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_sweep_wired(self):
        self.assertIn('def process_backup_jobs(', self.API)
        self.assertIn("_safe(process_backup_jobs", self.API)

    def test_run_is_exec_gated_create_is_admin(self):
        run = re.search(r'def handle_backup_job_run\(.*?\n(.*?)\ndef ', self.API, re.DOTALL)
        self.assertIn("require_perm('exec'", run.group(1))
        create = re.search(r'def handle_backup_job_create\(.*?\n(.*?)\ndef ', self.API, re.DOTALL)
        self.assertIn('require_admin_auth()', create.group(1))

    def test_frontend(self):
        self.assertIn('data-page="backups"', self.HTML)
        self.assertIn('function loadBackupJobs(', self.APP)
        self.assertIn("name === 'backups'", self.APP)


class TestV360AutoPatch(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_sweep_and_targeting(self):
        self.assertIn('def process_autopatch(', self.API)
        self.assertIn("_safe(process_autopatch", self.API)
        self.assertIn('def _autopatch_target_devices(', self.API)

    def test_create_admin_gated(self):
        m = re.search(r'def handle_autopatch_create\(.*?\n(.*?)\ndef ', self.API, re.DOTALL)
        self.assertIn('require_admin_auth()', m.group(1))

    def test_frontend(self):
        self.assertIn('data-page="autopatch"', self.HTML)
        self.assertIn('function loadAutopatch(', self.APP)
        self.assertIn("name === 'autopatch'", self.APP)


class TestV360AvAndProxmoxBackup(unittest.TestCase):
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
    PCLIENT = (REPO_ROOT / 'server' / 'cgi-bin' / 'proxmox_client.py').read_text()

    def test_av_collector_and_ingest(self):
        self.assertIn('def get_av_status(', self.AGENT)
        self.assertIn('get_av_status()', self.AGENT)
        self.assertIn("payload['av']", self.AGENT)
        self.assertIn('def _ingest_av(', self.API)
        self.assertIn("if 'av' in body", self.API)

    def test_proxmox_backup_query_and_cache(self):
        self.assertIn('def list_backups(', self.PCLIENT)
        self.assertIn('content=backup', self.PCLIENT)
        self.assertIn('def _refresh_proxmox_backup_cache(', self.API)

    def test_proxmox_backup_page_surface(self):
        # vzdump backup recency is surfaced + adjustable on the Backups page,
        # and kept distinct from the snapshot check.
        self.assertIn('def handle_proxmox_backups_get(', self.API)
        self.assertIn('def handle_proxmox_backup_threshold(', self.API)
        app = client_js()
        self.assertIn('function loadProxmoxBackups(', app)
        self.assertIn('function saveProxmoxBackupThreshold(', app)
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="pmbackup-card"', html)
        self.assertIn('id="pmbackup-threshold"', html)

    def test_channel_kinds_registered(self):
        import importlib
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        keys = {k for k, *_ in api.CHANNEL_KINDS}
        self.assertIn('av_posture', keys)
        self.assertIn('proxmox_backup', keys)

    def test_attention_blocks_present(self):
        self.assertIn("'kind': 'av_posture'", self.API)
        self.assertIn("'kind': 'proxmox_backup'", self.API)


if __name__ == '__main__':
    unittest.main()
