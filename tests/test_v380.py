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
        # v3.8.0: audit-forward (http) now uses the connect-time SSRF-guarded
        # opener with no-redirect-follow (anti DNS-rebinding).
        seg_http = API[API.index('def _forward_audit'):API.index("elif mode == 'syslog'")]
        self.assertIn('_ssrf_safe_opener(', seg_http)
        self.assertIn('no_redirect=True', seg_http)
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

    def test_mitigate_fix_reveals_confirm_field(self):
        # The /fix "confirmation required" 400 must un-hide the confirm row,
        # not dead-end on the raw error (AI-suggested commands always need RUN
        # server-side, even when the client heuristic thought them routine).
        seg = APP[APP.index('async function mitigateRunFix'):
                  APP.index('async function _mitigatePollFix')]
        self.assertIn('destructive_or_unverified', seg)
        self.assertIn("mitigate-fix-confirm-row", seg)
        self.assertIn("row.style.display = 'block'", seg)
        # And the live preview reveals it proactively for an AI-suggested cmd.
        prev = APP[APP.index('function _mitigateUpdateSafety'):
                   APP.index('// Wire the textarea')]
        self.assertIn('cmd === aiFix', prev)
        self.assertIn("confirmRow.style.display = 'block'", prev)

    def test_proxmox_backup_table_sortable(self):
        # CLAUDE.md: every table wires sort. The pm-backup table was inline.
        seg = APP[APP.index('async function loadProxmoxBackups'):]
        seg = seg[:seg.index('async function saveProxmoxBackupThreshold')]
        self.assertIn("tableCtl.sortRows('pmbackup'", seg)
        self.assertIn("tableCtl.wireSortOnly('pmbackup-thead', 'pmbackup'", seg)
        self.assertIn('data-col="name"', seg)

    def test_makerchecker_rejects_deleted_or_quarantined_device(self):
        seg = API[API.index('def _mcp_execute'):API.index("if action == 'reboot_device'")]
        self.assertIn('device not found', seg)
        self.assertIn('_device_quarantined(devs[device_id])', seg)


class TestV380Bind(unittest.TestCase):
    def test_boot_reason_ingested_and_served(self):
        self.assertIn("'boot_reason' in body", API)
        self.assertIn("dev['last_boot_reason']", API)
        self.assertIn("'last_boot_reason': dev.get('last_boot_reason'", API)
        self.assertIn("['Boot reason', data?.last_boot_reason", APP)

    def test_failed_units_and_logged_in_persisted(self):
        # The sanitiser must now copy failed_units + logged_in into safe_si,
        # else the Fleet Query filter / cis-failed check / drawer stay dead.
        seg = API[API.index("dev['sysinfo'] = safe_si") - 1200:API.index("dev['sysinfo'] = safe_si")]
        self.assertIn("safe_si['failed_units']", seg)
        self.assertIn("safe_si['logged_in']", seg)

    def test_failed_units_and_logged_in_rendered(self):
        self.assertIn("['Logged in', (si.logged_in", APP)
        self.assertIn('si.failed_units', APP)

    def test_orphan_host_health_renderer_removed(self):
        self.assertNotIn('function _renderHostHealth', APP)

    def test_failed_units_attention_and_investigate_wired(self):
        # emitted as an attention item...
        self.assertIn("'kind': 'failed_units'", API)
        # ...investigable: playbook + prompt + JS label/kind
        self.assertIn("'failed_units': {", API)
        self.assertIn("'mitigate_failed_units'", API)
        self.assertIn("mitigate_failed_units", AIP)
        self.assertIn("failed_units:    'Failed systemd units'", APP)
        self.assertIn("'failed_units',", APP)


class TestV380SSRF(unittest.TestCase):
    AGENT = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()

    def test_connect_time_peer_revalidation(self):
        # anti DNS-rebinding: connection subclasses re-check the peer IP.
        self.assertIn('class _SSRFGuardHTTPConnection', API)
        self.assertIn('class _SSRFGuardHTTPSConnection', API)
        self.assertIn('def _ssrf_safe_opener', API)
        self.assertIn('def _ip_class_blocked', API)
        self.assertIn('getpeername()', API)

    def test_outbound_senders_use_guarded_opener(self):
        # webhook, audit-forward, and both OIDC fetches route through it.
        self.assertGreaterEqual(API.count('_ssrf_safe_opener('), 4)

    def test_audit_forward_pins_tls_context(self):
        seg = API[API.index('def _forward_audit'):API.index("elif mode == 'syslog'")]
        self.assertIn('ssl_ctx=_ctx', seg)

    def test_agent_require_signed_updates_fail_closed(self):
        self.assertIn('def _require_signed_updates', self.AGENT)
        self.assertIn('require-signed-updates', self.AGENT)
        seg = self.AGENT[self.AGENT.index('pubkey = _release_pubkey()'):]
        seg = seg[:seg.index('if pubkey:')]
        self.assertIn('_require_signed_updates()', seg)
        self.assertIn('return False', seg)


class TestV380TokenSafety(unittest.TestCase):
    """Non-ASCII status tokens used to 500 the public status/calendar endpoints
    (hmac.compare_digest raises TypeError on a non-ASCII str). The query-string
    token endpoints must compare via the safe _ct_token_eq helper."""

    @classmethod
    def setUpClass(cls):
        import os, tempfile
        # Be self-sufficient when run in isolation: ensure server/cgi-bin is
        # importable rather than relying on another test module to add it.
        cgi_bin = str(REPO_ROOT / 'server' / 'cgi-bin')
        if cgi_bin not in sys.path:
            sys.path.insert(0, cgi_bin)
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v380tok_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        import os, shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)
        sys.modules.pop('api', None)

    def test_query_string_token_sites_use_safe_compare(self):
        # public/status, status, schedule.ics, and the public-POST status auth
        # must not call raw compare_digest on the (Unicode) query-string token.
        for needle in (
            "given = (qs.get('token') or [''])[0]\n    if not _ct_token_eq(given",
            "authed = _ct_token_eq(qs_token, cfg_token)",
            "if _ct_token_eq(qs_token, cfg_token):",
        ):
            self.assertIn(needle, API, f'missing safe compare: {needle!r}')

    def test_cpu_load_warning_can_recover(self):
        # Regression: METRIC_RECOVERY_BUFFER is an absolute (0–100) value, so for
        # the CPU load-ratio threshold (~1.5) `warn - buffer` went negative and a
        # cpu warning could never clear. A near-idle ratio must now be below the
        # recovery point, while percentage metrics keep the absolute buffer.
        eq = self.api._below_recovery
        self.assertTrue(eq(0.02, 1.5))     # idle cpu must be able to recover
        self.assertTrue(eq(0.0, 1.5))
        self.assertFalse(eq(1.45, 1.5))    # still hysteretic just under warn
        self.assertFalse(eq(76, 80))       # memory: absolute buffer unchanged
        self.assertTrue(eq(74, 80))

    def test_process_thresholds_clears_stuck_cpu_warning(self):
        dev = {'name': 'x', 'metric_state': {'cpu:': 'warning'}}
        self.api.process_metric_thresholds('d1', dev, {'loadavg_1m': 0.06, 'cpu_count': 4})
        self.assertEqual(dev['metric_state'].get('cpu:'), 'ok')

    def test_cpu_attention_reads_loadavg_1m(self):
        # the cpu attention summary must read loadavg_1m (the stored scalar),
        # not a non-existent `loadavg` list (which left the value blank).
        seg = API[API.index("elif kind == 'cpu':"):]
        seg = seg[:seg.index('_resolve_metric_thresholds')]
        self.assertIn("si.get('loadavg_1m')", seg)

    def test_ct_token_eq_never_raises_on_non_ascii(self):
        eq = self.api._ct_token_eq
        self.assertTrue(eq('realtok_ABC123', 'realtok_ABC123'))
        self.assertFalse(eq('wrong', 'realtok_ABC123'))
        # the inputs that used to 500 the endpoint:
        self.assertFalse(eq('…', 'realtok_ABC123'))         # ellipsis …
        self.assertFalse(eq('\udcff\udcfe', 'realtok_ABC123'))   # surrogate bytes
        self.assertFalse(eq('', 'realtok_ABC123'))               # empty
        self.assertFalse(eq('x', None))                          # no token set


class TestV380AiButtons(unittest.TestCase):
    NEW_KINDS = ['av_posture', 'agent_version', 'os_eol', 'hardware', 'backup',
                 'ssh_key', 'new_port', 'agent_integrity', 'log_alert']

    def test_new_mitigation_kinds(self):
        seg = API[API.index('_MITIGATE_PLAYBOOKS = {'):]
        seg = seg[:seg.index('\n}\n')]
        for k in self.NEW_KINDS:
            self.assertIn(f"'{k}': {{", seg, f'{k} missing from _MITIGATE_PLAYBOOKS')

    def test_prompts_exist_for_each(self):
        # every playbook's ai_prompt_key must resolve to a non-empty prompt,
        # else the AI step gets an empty system prompt.
        prompt_keys = ['mitigate_av', 'mitigate_agent_version', 'mitigate_os_eol',
                       'mitigate_hardware', 'mitigate_backup', 'mitigate_ssh_key',
                       'mitigate_new_port', 'mitigate_agent_integrity', 'mitigate_log']
        for key in prompt_keys:
            self.assertIn(f"'{key}':", AIP, f'prompt {key} missing')

    def test_js_registries_cover_new_kinds(self):
        for k in self.NEW_KINDS:
            self.assertIn(f"'{k}'", APP)


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
