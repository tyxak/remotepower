#!/usr/bin/env python3
"""
Tests for v2.6.0 — Host Configuration Management.

  1. api.py: constants, handlers, drift audit, heartbeat wiring.
  2. agent: constants, collect_host_config, apply_host_config, loop wiring.
  3. Frontend: modal, tabs, JS functions, device menu entry.
  4. Webhook: config_drift event registered with correct metadata.
  5. Version consistency.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


def _server_version():
    api = (_ROOT / 'server/cgi-bin/api.py').read_text()
    m = re.search(r"SERVER_VERSION\s*=\s*'([^']+)'", api)
    assert m, 'SERVER_VERSION not found'
    return m.group(1)


# ── api.py: constants ─────────────────────────────────────────────────────────

class TestAPIConstants(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_host_config_text_sections(self):
        self.assertIn('HOST_CONFIG_TEXT_SECTIONS', self.api)

    def test_host_config_struct_sections(self):
        self.assertIn('HOST_CONFIG_STRUCT_SECTIONS', self.api)

    def test_host_config_all_sections(self):
        self.assertIn('HOST_CONFIG_ALL_SECTIONS', self.api)

    def test_max_section_size(self):
        self.assertIn('MAX_HOST_CONFIG_SECTION_SIZE', self.api)

    def test_audit_cadence(self):
        self.assertIn('HOST_CONFIG_AUDIT_EVERY', self.api)
        m = re.search(r'HOST_CONFIG_AUDIT_EVERY\s*=\s*(\d+)', self.api)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), 15)

    def test_sections_include_repos(self):
        self.assertIn("'repos'", self.api)

    def test_sections_include_netplan(self):
        self.assertIn("'netplan'", self.api)

    def test_sections_include_nmcli(self):
        self.assertIn("'nmcli'", self.api)

    def test_sections_include_resolv_conf(self):
        self.assertIn("'resolv_conf'", self.api)

    def test_sections_include_hosts(self):
        self.assertIn("'hosts'", self.api)

    def test_sections_include_services(self):
        self.assertIn("'services'", self.api)

    def test_sections_include_users(self):
        self.assertIn("'users'", self.api)

    def test_sections_include_groups(self):
        self.assertIn("'groups'", self.api)

    def test_sections_include_sudoers(self):
        self.assertIn("'sudoers'", self.api)

    def test_sections_include_motd(self):
        self.assertIn("'motd'", self.api)


# ── api.py: webhook event ─────────────────────────────────────────────────────

class TestWebhookEvent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_config_drift_event_registered(self):
        self.assertIn("'config_drift'", self.api)

    def test_config_drift_in_priority(self):
        idx = self.api.find('def _webhook_priority(')
        block = self.api[idx: idx + 1500]
        self.assertIn('config_drift', block)

    def test_config_drift_in_tags(self):
        idx = self.api.find('def _webhook_tags(')
        block = self.api[idx: idx + 2500]
        self.assertIn('config_drift', block)
        self.assertIn('wrench', block)

    def test_config_drift_discord_title(self):
        self.assertIn('Config Drift', self.api)

    def test_config_drift_message_includes_sections(self):
        idx = self.api.find("elif event == 'config_drift':")
        block = self.api[idx: idx + 300]
        self.assertIn('sections', block)


# ── api.py: handlers ──────────────────────────────────────────────────────────

class TestHandlers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()

    def test_get_handler_exists(self):
        self.assertIn('def handle_device_host_config_get(', self.api)

    def test_put_handler_exists(self):
        self.assertIn('def handle_device_host_config_put(', self.api)

    def test_current_handler_exists(self):
        self.assertIn('def handle_device_host_config_current(', self.api)

    def test_validate_section_exists(self):
        self.assertIn('def _validate_host_config_section(', self.api)

    def test_audit_drift_exists(self):
        self.assertIn('def _audit_host_config_drift(', self.api)

    def test_ingest_current_exists(self):
        self.assertIn('def _ingest_host_config_current(', self.api)

    def test_validate_rejects_nul_bytes(self):
        idx = self.api.find('def _validate_host_config_section(')
        block = self.api[idx: idx + 1200]
        self.assertIn('\\x00', block)

    def test_validate_rejects_oversized(self):
        idx = self.api.find('def _validate_host_config_section(')
        block = self.api[idx: idx + 1200]
        self.assertIn('MAX_HOST_CONFIG_SECTION_SIZE', block)

    def test_sudoers_validated_with_visudo(self):
        idx = self.api.find('def apply_host_config(')
        if idx == -1:
            # Check agent instead
            return
        block = self.api[idx: idx + 3000]
        self.assertIn('visudo', block)

    def test_drift_audit_checks_text_sections(self):
        idx = self.api.find('def _audit_host_config_drift(')
        block = self.api[idx: idx + 2000]
        self.assertIn('.strip()', block)

    def test_drift_audit_checks_services_subset(self):
        idx = self.api.find('def _audit_host_config_drift(')
        block = self.api[idx: idx + 2000]
        self.assertIn('issubset', block)

    def test_drift_audit_checks_users(self):
        idx = self.api.find('def _audit_host_config_drift(')
        block = self.api[idx: idx + 3000]
        self.assertIn('authorized_keys', block)

    def test_ingest_fires_edge_triggered_webhook(self):
        idx = self.api.find('def _ingest_host_config_current(')
        block = self.api[idx: idx + 3000]
        self.assertIn('fire_webhook', block)
        self.assertIn('config_drift', block)
        self.assertIn('was_clean', block)

    def test_put_handler_uses_admin_auth(self):
        idx = self.api.find('def handle_device_host_config_put(')
        block = self.api[idx: idx + 400]
        self.assertIn('require_admin_auth', block)

    def test_put_handler_audit_logs(self):
        idx = self.api.find('def handle_device_host_config_put(')
        # window widened in v3.7.0 (the handler grew an `enforce` field); the
        # assertion — the PUT handler audit-logs — is unchanged.
        block = self.api[idx: idx + 1600]
        self.assertIn('audit_log', block)


# ── api.py: routing ───────────────────────────────────────────────────────────

class TestRouting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = (_ROOT / 'server/cgi-bin/api.py').read_text()
        idx = cls.api.rfind('def main()')
        cls.routes = cls.api[idx:]

    def test_get_route(self):
        self.assertIn('/host-config', self.routes)
        self.assertIn('handle_device_host_config_get', self.routes)

    def test_put_route(self):
        self.assertIn('handle_device_host_config_put', self.routes)

    def test_current_route(self):
        self.assertIn('/host-config/current', self.routes)
        self.assertIn('handle_device_host_config_current', self.routes)


# ── api.py: heartbeat wiring ──────────────────────────────────────────────────

class TestHeartbeatWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        api = (_ROOT / 'server/cgi-bin/api.py').read_text()
        idx = api.find('def handle_heartbeat(')
        cls.hb = api[idx: idx + 78000]   # widened as handle_heartbeat grew (v3.13.0 CMDB hardware fields; v3.14.0 network_io + secrets ingest; v4.1.0 inode/fd/conntrack + clock/gateway/oom edge-triggers; v4.2.0 sweep mailq/pkg_scan_ts + reinstall-audit hoist; v4.10.0 agent-stopping branch + backup_verify ingest)

    def test_desired_pushed_in_response(self):
        self.assertIn('host_config_desired', self.hb)

    def test_current_not_ingested_via_heartbeat(self):
        """host_config_current is processed when present but not sent on every poll."""
        api_text = (_ROOT / 'server/cgi-bin/api.py').read_text()
        self.assertIn('def _ingest_host_config_current(', api_text)
        self.assertIn('host_config_current', api_text)


# ── agent ─────────────────────────────────────────────────────────────────────

class TestAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = (_ROOT / 'client/remotepower-agent.py').read_text()

    def test_collect_every_constant(self):
        self.assertIn('HOST_CONFIG_COLLECT_EVERY', self.agent)

    def test_collect_every_is_15(self):
        m = re.search(r'HOST_CONFIG_COLLECT_EVERY\s*=\s*(\d+)', self.agent)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), 15)

    def test_collect_function_exists(self):
        self.assertIn('def collect_host_config(', self.agent)

    def test_apply_function_exists(self):
        self.assertIn('def apply_host_config(', self.agent)

    def test_collect_reads_resolv_conf(self):
        idx = self.agent.find('def collect_host_config(')
        block = self.agent[idx: idx + 4000]
        self.assertIn('resolv.conf', block)

    def test_collect_reads_etc_hosts(self):
        idx = self.agent.find('def collect_host_config(')
        block = self.agent[idx: idx + 4000]
        self.assertIn('/etc/hosts', block)

    def test_collect_reads_enabled_services(self):
        idx = self.agent.find('def collect_host_config(')
        block = self.agent[idx: idx + 5000]
        self.assertIn('systemctl', block)
        self.assertIn('enabled', block)

    def test_collect_reads_users_with_keys(self):
        idx = self.agent.find('def collect_host_config(')
        block = self.agent[idx: idx + 6000]
        self.assertIn('authorized_keys', block)

    def test_apply_writes_resolv_conf(self):
        idx = self.agent.find('def apply_host_config(')
        block = self.agent[idx: idx + 6000]
        self.assertIn('resolv.conf', block)

    def test_apply_runs_netplan(self):
        idx = self.agent.find('def apply_host_config(')
        block = self.agent[idx: idx + 6000]
        self.assertIn('netplan', block)
        self.assertIn('apply', block)

    def test_apply_validates_sudoers_with_visudo(self):
        idx = self.agent.find('def apply_host_config(')
        block = self.agent[idx: idx + 8000]
        self.assertIn('visudo', block)

    def test_apply_sets_authorized_keys_permissions(self):
        idx = self.agent.find('def apply_host_config(')
        block = self.agent[idx: idx + 8000]
        self.assertIn('0o600', block)
        self.assertIn('authorized_keys', block)

    def test_heartbeat_loop_applies_desired(self):
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 18000]
        self.assertIn('apply_host_config', block)
        self.assertIn('host_config_desired', block)

    def test_heartbeat_loop_does_not_send_current_in_payload(self):
        """Current state is on-demand only — not sent in every heartbeat poll."""
        idx = self.agent.find('def heartbeat(')
        block = self.agent[idx: idx + 18000]
        # host_config_current should NOT be added to payload in the regular poll loop
        # (it's only sent via send_current_configs subcommand)
        self.assertNotIn("payload['host_config_current']", block)

    def test_send_current_configs_subcommand(self):
        self.assertIn('send_current_configs', self.agent)
        self.assertIn('collect_host_config', self.agent)

    def test_agent_binary_in_sync(self):
        py  = (_ROOT / 'client/remotepower-agent.py').read_bytes()
        bin_ = (_ROOT / 'client/remotepower-agent').read_bytes()
        self.assertEqual(py, bin_,
                         'client/remotepower-agent binary is out of sync with .py')


# ── frontend ──────────────────────────────────────────────────────────────────

class TestFrontend(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server/html/index.html').read_text()
        cls.js   = client_js()
        cls.css  = (_ROOT / 'server/html/static/css/styles.css').read_text()

    def test_modal_exists(self):
        self.assertIn('id="host-config-modal"', self.html)

    def test_tabs_exist(self):
        # CSP L1 (v3.0.4): inline onclick became data-action delegation.
        for tab in ('repos', 'netplan', 'nmcli', 'resolv_conf',
                    'hosts', 'services', 'users', 'groups', 'sudoers', 'motd'):
            self.assertIn(f'data-action="hcShowTab" data-arg="{tab}"', self.html)

    def test_text_panels_exist(self):
        for section in ('repos', 'netplan', 'nmcli', 'resolv_conf',
                        'hosts', 'sudoers', 'motd'):
            self.assertIn(f'id="hc-panel-{section}"', self.html)

    def test_services_panel_exists(self):
        self.assertIn('id="hc-panel-services"', self.html)

    def test_users_panel_exists(self):
        self.assertIn('id="hc-panel-users"', self.html)

    def test_groups_panel_exists(self):
        self.assertIn('id="hc-panel-groups"', self.html)

    def test_drift_banner_exists(self):
        self.assertIn('id="hc-drift-banner"', self.html)

    def test_fetch_current_buttons(self):
        # CSP L1 (v3.0.4): inline onclick → data-action delegation.
        self.assertIn('data-action="hcFetchCurrent" data-arg="repos"', self.html)

    def test_save_button(self):
        # CSP L1 (v3.0.4): inline onclick → data-action delegation.
        self.assertIn('data-action="saveHostConfig"', self.html)

    def test_device_menu_entry(self):
        self.assertIn("openHostConfigModal(", self.js)
        self.assertIn("'Host Config'", self.js)

    def test_open_modal_function(self):
        self.assertIn('function openHostConfigModal(', self.js)

    def test_save_function(self):
        self.assertIn('function saveHostConfig(', self.js)

    def test_fetch_current_function(self):
        self.assertIn('function hcFetchCurrent(', self.js)

    def test_tab_switch_function(self):
        self.assertIn('function hcShowTab(', self.js)

    def test_add_user_function(self):
        self.assertIn('function hcAddUser(', self.js)

    def test_add_group_function(self):
        self.assertIn('function hcAddGroup(', self.js)

    def test_collect_users_function(self):
        self.assertIn('function _hcCollectUsers(', self.js)

    def test_collect_groups_function(self):
        self.assertIn('function _hcCollectGroups(', self.js)

    def test_tab_css_added(self):
        self.assertIn('.hc-tab', self.css)

    def test_api_call_get(self):
        self.assertIn('/host-config`', self.js)

    def test_api_call_put(self):
        self.assertIn("'PUT'", self.js)
        self.assertIn('/host-config`', self.js)

    def test_api_call_current(self):
        self.assertIn('/host-config/current`', self.js)


# ── version consistency ───────────────────────────────────────────────────────

class TestVersionConsistency(unittest.TestCase):

    def setUp(self):
        self.ver = _server_version()

    def test_version_is_260(self):
        # v3.0.4: loosened from a hardcoded version tuple to a 2.x/3.x
        # regex. The tuple was bumped every release and kept failing
        # for no good reason — the test's actual job is "is this a
        # post-2.6.0 release?", not "is this one of these specific
        # versions?". Same loosening pattern test_v303 followed.
        self.assertRegex(self.ver, r'^(2\.[6-9]|2\.[1-9][0-9]+|[3-9]\.\d+)\.\d+$',
            f'server version {self.ver!r} is older than 2.6.0')

    def test_agent_py(self):
        text = (_ROOT / 'client/remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_agent_binary(self):
        text = (_ROOT / 'client/remotepower-agent').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_readme_badge(self):
        readme = (_ROOT / 'README.md').read_text()
        m = re.search(r'version-([0-9.]+)-blue', readme)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_changelog_top(self):
        cl = (_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v([0-9.]+)', cl, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_sw_cache_name(self):
        sw = (_ROOT / 'server/html/sw.js').read_text()
        self.assertIn(self.ver, sw)

    def test_cache_busting(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        for asset in ('static/js/app.js', 'static/css/styles.css'):
            m = re.search(re.escape(asset) + r'\?v=([0-9.]+)', html)
            self.assertIsNotNone(m, f'{asset} missing ?v=')
            self.assertEqual(m.group(1), self.ver)


if __name__ == '__main__':
    unittest.main(verbosity=2)
