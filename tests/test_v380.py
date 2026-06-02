"""v3.8.0 release tests.

v3.8.0 is a hardening / bind-it-together / polish sweep (not new headline
features). It fixes security findings, binds dropped agent data into the UI,
adds AI-investigate playbooks for more attention kinds, and relocates two
settings sections. These tests pin the fixes so they can't silently regress.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re, sys, unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
AIP = (REPO_ROOT / 'server' / 'cgi-bin' / 'ai_provider.py').read_text()
DAEMON = (REPO_ROOT / 'server' / 'webterm' / 'remotepower-webterm.py').read_text()
HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
APP = client_js()


class TestVersionBumps(unittest.TestCase):
    EXPECTED = '3.8.0'

    def test_versions(self):
        self.assertRegex(API, r"SERVER_VERSION\s*=\s*'3\.8\.0'")
        self.assertRegex((REPO_ROOT / 'client' / 'remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'3\.8\.0'")
        self.assertIn("'remotepower-shell-v3.8.0'", (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text())
        self.assertIn('?v=3.8.0', HTML)
        self.assertIn('version-3.8.0-blue.svg', (REPO_ROOT / 'README.md').read_text())

    def test_agent_extensionless_matches(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b)

    def test_changelog_and_doc(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertEqual(m.group(1), self.EXPECTED)
        self.assertTrue((REPO_ROOT / 'docs' / 'v3.8.0.md').exists())


class TestV380Security(unittest.TestCase):
    def test_maker_checker_enforces_allowlist(self):
        # submit path: confirmation only created after _check_exec_allowlist
        block = API[API.index("change_approval_enabled')"):]
        block = block[:block.index('respond(202')]
        self.assertIn('_check_exec_allowlist(dev_id, cmd_str, devices)', block)
        # execute path: re-check at approval time
        ex = API[API.index("elif action == 'exec_command'"):]
        ex = ex[:ex.index('queued =')]
        self.assertIn('_check_exec_allowlist(device_id', ex)

    def test_ansible_inventory_safe(self):
        # host alias sanitised; password not in INI but in a JSON extra-vars file
        seg = API[API.index('inv_lines = ['):API.index('argv = [')]
        self.assertIn("re.sub(r'[^A-Za-z0-9_.\\-]', '', str(dev.get('name'", seg)
        self.assertNotIn('ansible_password={ssh_password}', API)
        self.assertIn("json.dump({'ansible_password'", API)

    def test_ansible_skips_quarantine(self):
        self.assertIn('not _device_quarantined(devices[i])', API)

    def test_recovery_code_atomic(self):
        seg = API[API.index('fall back to a one-time recovery code'):]
        seg = seg[:seg.index('cleanup_tokens()')]
        self.assertIn('with _LockedUpdate(USERS_FILE) as users_rc:', seg)

    def test_audit_forward_no_redirect_and_syslog_ssrf(self):
        self.assertIn('class _NoRedirect', API)
        self.assertIn('build_opener(_NoRedirect())', API)
        # syslog target SSRF-guarded
        seg = API[API.index("elif mode == 'syslog'"):API.index('use_tcp = bool')]
        self.assertIn('_url_targets_local_or_meta(urllib.parse.urlparse', seg)

    def test_sftp_size_check_before_decode(self):
        seg = DAEMON[DAEMON.index("if op == 'write'"):DAEMON.index("if op == 'delete'")]
        # the encoded-length guard appears before base64.b64decode
        self.assertIn('len(b64) >', seg)
        self.assertIn('base64.b64decode', seg)
        self.assertLess(seg.index('len(b64) >'), seg.index('base64.b64decode'))


class TestV380Bugs(unittest.TestCase):
    def test_delete_handlers_stringify_id(self):
        for fn in ('deleteSite', 'deleteAutopatch', 'deleteBackupJob', 'deleteAnsiblePlaybook'):
            m = re.search(rf'function {fn}\([^)]*\)\s*\{{([^\n]*)', APP)
            self.assertIsNotNone(m, fn)
            self.assertIn('id = String(id)', m.group(1), f'{fn} must stringify id')

    def test_raid_devices_string_or_array(self):
        self.assertIn("typeof r.devices === 'string'", APP)


class TestV380Bind(unittest.TestCase):
    def test_boot_reason_ingested_and_served(self):
        self.assertIn("'boot_reason' in body", API)
        self.assertIn("dev['last_boot_reason']", API)
        self.assertIn("'last_boot_reason': dev.get('last_boot_reason'", API)
        self.assertIn("['Boot reason', data?.last_boot_reason", APP)


class TestV380AiButtons(unittest.TestCase):
    def test_new_mitigation_kinds(self):
        seg = API[API.index('_MITIGATE_PLAYBOOKS = {'):]
        seg = seg[:seg.index('\n}\n')]
        self.assertIn("'av_posture': {", seg)
        self.assertIn("'agent_version': {", seg)
        # prompts exist so the AI step doesn't KeyError
        self.assertIn("'mitigate_av':", AIP)
        self.assertIn("'mitigate_agent_version':", AIP)


class TestV380Polish(unittest.TestCase):
    def test_settings_moved_to_security(self):
        sec = HTML[HTML.index('id="settings-pane-security"'):HTML.index('id="settings-pane-advanced"')]
        self.assertIn('cfg-audit-forward-enabled', sec)
        self.assertIn('cfg-change-approval-enabled', sec)

    def test_confirmations_relabelled(self):
        nav = HTML[HTML.index('data-page="confirmations"'):]
        nav = nav[:nav.index('</button>')]
        self.assertIn('<span>Confirmations</span>', nav)


if __name__ == '__main__':
    unittest.main()
