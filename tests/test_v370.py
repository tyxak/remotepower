"""v3.7.0 release tests.

Strict version pins for v3.7.0 (the v3.6.0 strict pins loosen to regex when this
ships). v3.7.0: 2FA recovery codes, audit→SIEM forwarding, credential rotation
reminders, desired-state enforcement, change-approval (maker-checker), Proxmox
QEMU VM create, and an Ansible playbook runner.
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

API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
PCLIENT = (REPO_ROOT / 'server' / 'cgi-bin' / 'proxmox_client.py').read_text()
AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()


class TestVersionBumps(unittest.TestCase):
    # v3.8.0: loosened to regex — v3.8.0 holds the strict pin (test_v380.py).
    def test_api_server_version(self):
        self.assertRegex(API, r"SERVER_VERSION\s*=\s*'3\.\d+\.\d+'")

    def test_agent_version(self):
        self.assertRegex(AGENT, r"\nVERSION\s*=\s*'3\.\d+\.\d+'")

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b)

    def test_sw_cache_name(self):
        self.assertRegex((REPO_ROOT / 'server' / 'html' / 'sw.js').read_text(),
                         r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        self.assertRegex(HTML, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        self.assertRegex((REPO_ROOT / 'README.md').read_text(), r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        self.assertRegex(chlog, r'## v3\.\d+\.\d+')

    def test_release_notes_doc_present(self):
        # v3.7.0 release notes must stay present forever
        p = REPO_ROOT / 'docs' / 'v3.7.0.md'
        self.assertTrue(p.exists()); self.assertIn('3.7.0', p.read_text())


class TestV370Routes(unittest.TestCase):
    def test_routes(self):
        cases = [
            ('POST', '/api/totp/recovery-codes',       'handle_totp_regenerate_codes'),
            ('POST', '/api/audit/forward-test',        'handle_audit_forward_test'),
            ('POST', '/api/proxmox/qemu/create',       'handle_proxmox_qemu_create'),
            ('GET',  '/api/proxmox/qemu/create-options','handle_proxmox_qemu_create_options'),
            ('GET',  '/api/ansible/status',            'handle_ansible_status'),
            ('GET',  '/api/ansible/playbooks',         'handle_ansible_playbooks_list'),
            ('POST', '/api/ansible/playbooks',         'handle_ansible_playbook_create'),
            ('PUT',  '/api/ansible/playbooks/p1',      'handle_ansible_playbook_update'),
            ('DELETE','/api/ansible/playbooks/p1',     'handle_ansible_playbook_delete'),
            ('POST', '/api/ansible/playbooks/p1/run',  'handle_ansible_playbook_run'),
        ]
        for method, path, handler in cases:
            self.assertEqual(routes_to(method, path), handler, f'{method} {path}')

    def test_qemu_create_not_shadowed_by_action_prefix(self):
        # /api/proxmox/qemu/create must hit create, not handle_proxmox_action
        self.assertEqual(routes_to('POST', '/api/proxmox/qemu/create'),
                         'handle_proxmox_qemu_create')


class TestV370RecoveryCodes(unittest.TestCase):
    APP = client_js()
    def test_backend(self):
        self.assertIn('def _generate_recovery_codes(', API)
        self.assertIn('def _consume_recovery_code(', API)
        self.assertIn("users[username]['recovery_codes'] = hashed", API)
        # login accepts a recovery code as TOTP fallback
        self.assertIn('_consume_recovery_code(urec, totp_code)', API)
    def test_frontend(self):
        self.assertIn('function regenerateRecoveryCodes(', self.APP)
        self.assertIn('function _showRecoveryCodes(', self.APP)


class TestV370AuditForward(unittest.TestCase):
    APP = client_js()
    def test_backend(self):
        self.assertIn('def _forward_audit(', API)
        self.assertIn("if cfg.get('audit_forward_enabled')", API)
        # SSRF guard uses a parsed URL
        self.assertIn('_url_targets_local_or_meta(urllib.parse.urlparse(url)', API)
    def test_settings(self):
        self.assertIn('cfg-audit-forward-enabled', HTML)
        self.assertIn('function testAuditForward(', self.APP)


class TestV370CredRotation(unittest.TestCase):
    def test_backend(self):
        self.assertIn("'rotate_after_days'", API)
        self.assertIn("'rotated_at'", API)
        self.assertIn("'kind': 'cred_rotation'", API)
        import importlib
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        self.assertIn('cred_rotation', {k for k, *_ in api.CHANNEL_KINDS})
    def test_frontend(self):
        self.assertIn('cmdb-cred-rotate', HTML)
        self.assertIn('rotation_due', client_js())


class TestV370Enforce(unittest.TestCase):
    def test_backend(self):
        # corrective enforcement hook in the heartbeat
        self.assertIn("_hc.get('enforce')", API)
        self.assertIn('host_config_enforce', API)
        self.assertIn("hc['enforce'] = bool(enforce_on_drift)", API)
    def test_frontend(self):
        self.assertIn('hc-enforce-drift', HTML)


class TestV370MakerChecker(unittest.TestCase):
    def test_backend(self):
        self.assertIn("elif action == 'exec_command'", API)
        # self-approval guard
        self.assertIn("entry.get('requested_by') == actor", API)
        self.assertIn("change_approval_enabled", API)
    def test_exec_path_gated(self):
        self.assertIn("get('change_approval_enabled')", API)
        self.assertIn("'approval_required': True", API)


class TestV370ProxmoxVm(unittest.TestCase):
    def test_backend(self):
        self.assertIn('def create_qemu(', PCLIENT)
        self.assertIn('def list_isos(', PCLIENT)
        self.assertIn("content=iso", PCLIENT)
        self.assertIn('def handle_proxmox_qemu_create(', API)
    def test_frontend(self):
        self.assertIn('function openVmCreateWizard(', client_js())
        self.assertIn('id="vm-create-modal"', HTML)


class TestV370Ansible(unittest.TestCase):
    APP = client_js()
    def test_backend(self):
        self.assertIn('def _ansible_available(', API)
        self.assertIn('def handle_ansible_playbook_run(', API)
        self.assertIn("require_perm('script', ids)", API)   # v3.12.0: was 'exec'
        self.assertIn('ansible-playbook', API)
    def test_frontend(self):
        self.assertIn('data-page="ansible"', HTML)
        self.assertIn('function loadAnsible(', self.APP)
        self.assertIn('function runAnsiblePlaybook(', self.APP)
        self.assertIn("name === 'ansible'", self.APP)


if __name__ == '__main__':
    unittest.main()
