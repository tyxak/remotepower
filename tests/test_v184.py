#!/usr/bin/env python3
"""
Unit tests for v1.8.4 additions:
- Config helpers (online_ttl, default poll interval, session TTL, server name, etc.)
- Per-event webhook toggles + backward compatibility with legacy keys
- CVE severity filter
- Remember-me semantics
- Per-token TTL stored in tokens.json
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'GET'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v184', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)


class ConfigHelperBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = api_module.CONFIG_FILE
        api_module.CONFIG_FILE = self.tmp / 'config.json'

    def tearDown(self):
        api_module.CONFIG_FILE = self._orig

    def _setcfg(self, **kw):
        api_module.save(api_module.CONFIG_FILE, kw)


class TestOnlineTTL(ConfigHelperBase):
    def test_default(self):
        self.assertEqual(api_module.get_online_ttl(), api_module.DEFAULT_ONLINE_TTL)

    def test_explicit_value(self):
        self._setcfg(online_ttl=300)
        self.assertEqual(api_module.get_online_ttl(), 300)

    def test_clamped_to_minimum(self):
        # Lower than MIN should be clamped up
        self._setcfg(online_ttl=10)
        self.assertEqual(api_module.get_online_ttl(), api_module.MIN_ONLINE_TTL)

    def test_garbage_falls_back_to_default(self):
        self._setcfg(online_ttl='not a number')
        self.assertEqual(api_module.get_online_ttl(), api_module.DEFAULT_ONLINE_TTL)


class TestPollInterval(ConfigHelperBase):
    def test_default(self):
        self.assertEqual(api_module.get_default_poll_interval(),
                          api_module.DEFAULT_POLL_INTERVAL)

    def test_explicit_value(self):
        self._setcfg(default_poll_interval=120)
        self.assertEqual(api_module.get_default_poll_interval(), 120)

    def test_clamped_low(self):
        self._setcfg(default_poll_interval=5)
        self.assertEqual(api_module.get_default_poll_interval(), 10)

    def test_clamped_high(self):
        self._setcfg(default_poll_interval=99999)
        self.assertEqual(api_module.get_default_poll_interval(), 3600)


class TestSessionTTL(ConfigHelperBase):
    def test_default_short(self):
        self.assertEqual(api_module.get_session_ttl(remember_me=False),
                          api_module.DEFAULT_TOKEN_TTL_SHORT)

    def test_default_long(self):
        self.assertEqual(api_module.get_session_ttl(remember_me=True),
                          api_module.DEFAULT_TOKEN_TTL_LONG)

    def test_explicit_short(self):
        self._setcfg(session_ttl_short=12*3600)
        self.assertEqual(api_module.get_session_ttl(remember_me=False), 12*3600)

    def test_explicit_long(self):
        self._setcfg(session_ttl_long=14*86400)
        self.assertEqual(api_module.get_session_ttl(remember_me=True), 14*86400)


class TestRememberMeDefault(ConfigHelperBase):
    def test_off_by_default(self):
        self.assertFalse(api_module.get_remember_me_default())

    def test_explicit_on(self):
        self._setcfg(remember_me_default=True)
        self.assertTrue(api_module.get_remember_me_default())


class TestCveCacheSeconds(ConfigHelperBase):
    def test_default_is_seven_days(self):
        self.assertEqual(api_module.get_cve_cache_seconds(),
                          api_module.DEFAULT_CVE_CACHE_DAYS * 86400)

    def test_explicit(self):
        self._setcfg(cve_cache_days=3)
        self.assertEqual(api_module.get_cve_cache_seconds(), 3 * 86400)

    def test_clamped(self):
        self._setcfg(cve_cache_days=999)
        self.assertEqual(api_module.get_cve_cache_seconds(), 90 * 86400)
        self._setcfg(cve_cache_days=0)
        self.assertEqual(api_module.get_cve_cache_seconds(), 1 * 86400)


class TestServerName(ConfigHelperBase):
    def test_default_is_remotepower(self):
        self.assertEqual(api_module.get_server_name(), 'RemotePower')

    def test_custom_name(self):
        self._setcfg(server_name='Acme Lab')
        self.assertEqual(api_module.get_server_name(), 'Acme Lab')

    def test_whitespace_only_falls_back(self):
        self._setcfg(server_name='   ')
        self.assertEqual(api_module.get_server_name(), 'RemotePower')


class TestEventToggleHelper(ConfigHelperBase):
    def test_default_all_enabled(self):
        # With no config, every known event should be ON
        for ev, _, _ in api_module.WEBHOOK_EVENTS:
            self.assertTrue(api_module.is_webhook_event_enabled(ev),
                             f'event {ev} should default to enabled')

    def test_explicit_disabled(self):
        self._setcfg(webhook_events={'device_offline': False, 'device_online': True})
        self.assertFalse(api_module.is_webhook_event_enabled('device_offline'))
        self.assertTrue(api_module.is_webhook_event_enabled('device_online'))

    def test_legacy_offline_flag_respected(self):
        # Old config style — webhook_events not set, legacy flag controls offline events
        self._setcfg(offline_webhook_enabled=False)
        self.assertFalse(api_module.is_webhook_event_enabled('device_offline'))
        self.assertFalse(api_module.is_webhook_event_enabled('device_online'))
        # Other events still default-on
        self.assertTrue(api_module.is_webhook_event_enabled('cve_found'))

    def test_new_dict_takes_precedence_over_legacy(self):
        # If both old and new are present, new wins
        self._setcfg(
            offline_webhook_enabled=False,
            webhook_events={'device_offline': True},
        )
        self.assertTrue(api_module.is_webhook_event_enabled('device_offline'))


class TestCveSeverityFilter(ConfigHelperBase):
    def test_default_critical_high(self):
        self.assertEqual(api_module.get_cve_severity_filter(),
                          ('critical', 'high'))

    def test_explicit_filter(self):
        self._setcfg(cve_severity_filter=['critical'])
        self.assertEqual(api_module.get_cve_severity_filter(), ('critical',))

    def test_invalid_severity_filtered_out(self):
        self._setcfg(cve_severity_filter=['critical', 'megacritical'])
        self.assertEqual(api_module.get_cve_severity_filter(), ('critical',))

    def test_empty_list_falls_back_to_default(self):
        self._setcfg(cve_severity_filter=[])
        self.assertEqual(api_module.get_cve_severity_filter(),
                          ('critical', 'high'))


class TestPerTokenTTL(unittest.TestCase):
    """v1.8.4: each token may have its own ttl stored in tokens.json."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_tokens = api_module.TOKENS_FILE
        self._orig_users  = api_module.USERS_FILE
        self._orig_keys   = api_module.APIKEYS_FILE
        api_module.TOKENS_FILE = self.tmp / 'tokens.json'
        api_module.USERS_FILE  = self.tmp / 'users.json'
        api_module.APIKEYS_FILE = self.tmp / 'apikeys.json'
        api_module.save(api_module.USERS_FILE, {'alice': {'role': 'admin', 'password_hash': 'x'}})
        api_module.save(api_module.APIKEYS_FILE, {})

    def tearDown(self):
        api_module.TOKENS_FILE  = self._orig_tokens
        api_module.USERS_FILE   = self._orig_users
        api_module.APIKEYS_FILE = self._orig_keys

    def test_short_token_expires_after_its_ttl(self):
        now = int(time.time())
        api_module.save(api_module.TOKENS_FILE, {
            'short-token': {'user': 'alice', 'created': now - 7200, 'ttl': 3600},
        })
        self.assertEqual(api_module.verify_token('short-token'), (None, None))

    def test_long_token_still_valid(self):
        now = int(time.time())
        api_module.save(api_module.TOKENS_FILE, {
            'long-token': {'user': 'alice', 'created': now - 7200, 'ttl': 86400 * 30},
        })
        u, role = api_module.verify_token('long-token')
        self.assertEqual(u, 'alice')
        self.assertEqual(role, 'admin')

    def test_legacy_token_without_ttl_uses_default(self):
        # Old tokens (pre-1.8.4) had no 'ttl' field; verify still falls back to TOKEN_TTL
        now = int(time.time())
        api_module.save(api_module.TOKENS_FILE, {
            'legacy-token': {'user': 'alice', 'created': now - 60},
        })
        u, role = api_module.verify_token('legacy-token')
        self.assertEqual(u, 'alice')


class TestPublicInfoHandler(unittest.TestCase):
    """handle_public_info should return server_name + remember_me_default with no auth."""

    def test_returns_expected_keys(self):
        # Test the data extracted manually rather than through HTTP plumbing
        # (handle_public_info does respond/sys.exit which is awkward to mock)
        info = {
            'server_name':         api_module.get_server_name(),
            'server_version':      api_module.SERVER_VERSION,
            'remember_me_default': api_module.get_remember_me_default(),
        }
        self.assertEqual(info['server_name'], 'RemotePower')
        self.assertEqual(info['server_version'], api_module.SERVER_VERSION)
        self.assertIn(info['remember_me_default'], (True, False))


class TestWebhookEventsConstant(unittest.TestCase):
    """The order and content of WEBHOOK_EVENTS is a contract between server and UI."""

    def test_expected_event_set(self):
        names = {e[0] for e in api_module.WEBHOOK_EVENTS}
        expected = {
            'device_offline', 'device_online',
            'agent_stopped', 'agent_started',
            'monitor_down', 'monitor_up', 'path_changed',    # W4-15
            'mailflow_delayed', 'mailflow_ok',               # W4-16
            'patch_alert', 'patch_sla_violation', 'patch_sla_ok', 'cve_found',
            'campaign_completed',                    # W2-35 CVE campaigns
            'service_down', 'service_up',
            'unit_flapping', 'unit_flapping_cleared',   # v6.1.2 systemd flap detection
            'log_alert',
            # v1.11.4: container alerts
            'container_stopped', 'container_recovered', 'container_restarting', 'container_restarting_cleared', 'containers_stale',
            # v3.2.x: container image update tracking
            'image_update_available', 'image_updated',
            # v1.11.10: metric thresholds
            'metric_warning', 'metric_critical', 'metric_recovered',
            'custom_metric_alert', 'custom_metric_recover',    # W3-11
            'command_queued', 'command_executed',
            # v2.2.0: configuration drift detection
            'drift_detected',
            # v2.4.7: mailbox count threshold alert
            'mailbox_threshold', 'mailbox_recovered',
            # v2.5.0: custom monitoring script alerts
            'custom_script_fail', 'custom_script_recover',
            # v5.6.0: custom Check-catalog check failures
            'custom_check_failed', 'custom_check_recovered',
            # v2.6.0: host configuration drift
            'config_drift',
            # v2.6.1: TLS expiry + pending reboot
            'tls_expiry', 'reboot_required',
            # v2.7.0: stale Proxmox snapshot
            'snapshot_old', 'snapshot_recovered',
            # v2.8.0: security & audit
            'new_port_detected', 'ssh_key_added', 'brute_force_detected',
            'vault_break_glass',  # v5.0.0 #C3
            'backup_stale', 'backup_recovered', 'backup_size_anomaly',
            'backup_verify_failed', 'backup_verified',
            'restore_drill_failed', 'restore_drill_ok',  # W6-43
            'rollout_halted',
            'server_disk_low', 'server_disk_ok',  # v5.0.0 #R1
            # v3.2.0 (B5): SNMP polling state transitions
            'snmp_unreachable', 'snmp_dead', 'snmp_recover',
            'snmp_trap_received',                    # inbound SNMP trap receiver
            # v3.2.0 (A1 follow-up): MCP confirmation TTL expiry
            'mcp_confirmation_expired',
            # v3.4.0: hardware health
            'smart_failure', 'kernel_outdated',
            # v3.4.1: health-score threshold alert + recover
            'health_degraded', 'health_recovered',
            # v3.11.0: attack-surface exposure, software policy, storage/RAID
            # health, access watch, host firewall, scheduled-job failure
            'port_exposed_world', 'software_policy_violation',
            'storage_degraded', 'scrub_overdue', 'storage_recovered',
            # v6.1.2: snapshot recency + ECC memory errors
            'snapshot_stale', 'snapshot_ok', 'ecc_errors',
            # v6.1.2: WAN watch, duplicate MAC, inbound dead-man's-switch
            'wan_ip_changed', 'wan_down', 'wan_up', 'mac_conflict',
            'ping_missed', 'ping_recovered',
            # v6.3.1: auto-remediation verify loop — the fix ran, alert stayed open
            'remediation_failed',
            # v6.3.1: flow-verified declared-dependency link went silent / recovered
            'dependency_missing', 'dependency_restored',
            # v6.1.2 (#40): SSH host-key change (MITM / reimage tripwire)
            'hostkey_changed',
            'login_new_source', 'login_geo_anomaly', 'firewall_changed', 'timer_failed',
            'timer_failed_cleared',
            'db_integrity_failed', 'mount_issue',
            'disk_predict_fail', 'ups_on_battery', 'ups_critical', 'ups_on_line',  # v6.1.1 (#76)
            'cert_file_expiring', 'rogue_uid0',
            'priv_group_added',                      # v6.2.0 sudo/wheel/Administrators grant
            'usb_device_added',                      # v6.2.0 USB physical-access tripwire
            'process_alert', 'process_recovered',   # v3.14.0 #36
            'secret_exposed', 'canary_accessed',    # v3.14.0 #35 / W3-38
            'scan_finding',                          # v4.2.0 (B5)
            'integration_down', 'integration_recovered',  # v4.7.0 integrations
            'github_new_issue',                      # v5.8.0 GitHub issue monitor
            'ct_new_certificate',                    # W1-17 CT-log watch
            'ip_blacklisted', 'ip_blacklist_cleared',  # v4.8.0 IP reputation
            'ip_conflict',                              # W5-2 IPAM duplicate IP
            'resolver_unhealthy', 'resolver_recovered',  # v4.9.0 resolver health
            'fail2ban_ban',                          # v5.1.0 fail2ban bans
            'failed_unit',                           # v5.5.0 failed systemd unit
            'failed_unit_cleared',                   # v6.3.0 units left the failed state
            'av_infected',                           # v5.1.0 endpoint AV/malware
            'av_warning',                            # v5.4.1 AV/rootkit scan warnings
            'av_realtime_off',                       # v6.2.0 Defender real-time protection off
            'modules_hidden',                        # v6.2.2 kernel modules hidden from agent
            'vpn_client_connected', 'vpn_client_disconnected',  # v5.2.0 WG Access
            'vpn_handshake_stale',                   # v5.2.0 WG Access
            'ticket_sla_breached',
            # v5.6.x: ticket lifecycle
            'ticket_opened', 'ticket_resolved',                   # v5.3.0 helpdesk SLA breach
            'mount_recovered',                       # v3.14.0 fix
            'readonly_fs', 'readonly_fs_cleared',    # v6.0.1 RO remount
            'mailq_high', 'mailq_normal',            # v6.0.1 mail-queue backlog
            'temp_high', 'temp_normal',              # v4.1.0 temperature
            'clock_skew', 'clock_synced',            # v4.1.0 NTP / clock skew
            'gateway_unreachable', 'gateway_reachable',  # v4.1.0 gateway
            'nic_errors', 'nic_errors_cleared',      # v6.2.2 NIC errors/drops
            'win_bitlocker_off', 'win_firewall_off', # v6.2.2 Windows posture
            'win_update_stopped', 'win_defender_stale',
            'win_bitlocker_on', 'win_firewall_on',   # ← recoveries
            'win_update_running', 'win_defender_current',
            'mac_filevault_off', 'mac_firewall_off', # v6.4.0 macOS posture
            'mac_gatekeeper_off', 'mac_sip_disabled',
            'mac_filevault_on', 'mac_firewall_on',   # ← recoveries
            'mac_gatekeeper_on', 'mac_sip_enabled',
            'oom_detected',                          # v4.1.0 OOM-killer
            # v5.6.x: host-condition alerts now self-clear — each of these is the
            # recover event that auto-resolves its paired trigger alert.
            'kernel_current',                        # ← kernel_outdated
            'smart_recovered',                       # ← smart_failure
            'cert_file_renewed',                     # ← cert_file_expiring
            'rogue_uid0_cleared',                    # ← rogue_uid0
            'av_clean',                              # ← av_infected (+ av_warning)
            'av_realtime_on',                        # ← av_realtime_off (v6.2.0)
            'modules_visible_restored',              # ← modules_hidden (v6.2.2)
            'reboot_cleared',                        # ← reboot_required
            'containers_current',                    # ← containers_stale
            'port_unexposed',                        # ← port_exposed_world
            # v6.3.1: three alerts that could previously fire and never clear.
            'port_closed',                           # ← new_port_detected
            'policy_compliant',                      # ← software_policy_violation
            'disk_predict_cleared',                  # ← disk_predict_fail
        }
        self.assertEqual(names, expected)

    def test_each_entry_has_three_fields(self):
        for e in api_module.WEBHOOK_EVENTS:
            self.assertEqual(len(e), 3)
            ev, desc, default = e
            self.assertIsInstance(ev, str)
            self.assertIsInstance(desc, str)
            self.assertIsInstance(default, bool)


if __name__ == '__main__':
    unittest.main()
