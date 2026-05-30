#!/usr/bin/env python3
"""
Unit tests for RemotePower api.py
Run: python3 -m pytest tests/test_api.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Bootstrap: mock CGI environment before importing api ──────────────────────
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

import importlib.util
spec = importlib.util.spec_from_file_location(
    'api',
    Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py'
)
api_module = importlib.util.module_from_spec(spec)

# Prevent ensure_default_user() from running at import time
with tempfile.TemporaryDirectory() as tmpdir:
    os.environ['RP_DATA_DIR'] = tmpdir
    spec.loader.exec_module(api_module)


class ApiTestBase(unittest.TestCase):
    """Base class — creates a fresh temp data dir for each test."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.data_dir = Path(self.tmpdir)
        # Patch all file paths
        for attr in ('DATA_DIR', 'USERS_FILE', 'DEVICES_FILE', 'PINS_FILE',
                     'TOKENS_FILE', 'CMDS_FILE', 'CONFIG_FILE', 'HISTORY_FILE'):
            if attr == 'DATA_DIR':
                patcher = patch.object(api_module, attr, self.data_dir)
            else:
                suffix = attr.lower().replace('_file', '.json').replace('cmds', 'commands')
                patcher = patch.object(
                    api_module, attr,
                    self.data_dir / suffix
                )
            patcher.start()
            self.addCleanup(patcher.stop)

    def _save(self, filename: str, data):
        (self.data_dir / filename).write_text(json.dumps(data))

    def _load(self, filename: str):
        p = self.data_dir / filename
        return json.loads(p.read_text()) if p.exists() else {}


class TestPasswordHashing(ApiTestBase):
    def test_legacy_sha256_rejected(self):
        # Pre-2.3.2 bare unsalted SHA-256 hashes are no longer accepted (the
        # weak-hashing verify path was removed). Such an account must be reset
        # via remotepower-passwd.
        stored = hashlib.sha256(b'secret').hexdigest()
        self.assertFalse(api_module.verify_password('secret', stored))
        self.assertFalse(api_module.verify_password('wrong', stored))

    def test_hash_is_not_plaintext(self):
        h = api_module.hash_password('mysecret')
        self.assertNotEqual(h, 'mysecret')
        self.assertGreater(len(h), 20)

    def test_verify_bcrypt_if_available(self):
        try:
            import bcrypt
            h = bcrypt.hashpw(b'testpass', bcrypt.gensalt()).decode()
            self.assertTrue(api_module.verify_password('testpass', h))
            self.assertFalse(api_module.verify_password('wrong', h))
        except ImportError:
            self.skipTest('bcrypt not installed')


class TestStorageHelpers(ApiTestBase):
    def test_save_and_load(self):
        data = {'key': 'value', 'num': 42}
        path = self.data_dir / 'test.json'
        api_module.save(path, data)
        loaded = api_module.load(path)
        self.assertEqual(loaded, data)

    def test_load_missing_returns_empty_dict(self):
        result = api_module.load(self.data_dir / 'missing.json')
        self.assertEqual(result, {})

    def test_save_is_atomic(self):
        """save() uses .tmp then replace() — no partial writes."""
        path = self.data_dir / 'atomic.json'
        api_module.save(path, {'x': 1})
        tmp = path.with_suffix('.tmp')
        self.assertFalse(tmp.exists())
        self.assertTrue(path.exists())


class TestTokenVerification(ApiTestBase):
    def _make_token(self, username='admin', offset=0):
        token = f'tok_{username}_{offset}'
        tokens = {token: {'user': username, 'created': int(time.time()) + offset}}
        self._save('tokens.json', tokens)
        return token

    def test_valid_token_returns_username(self):
        token = self._make_token('alice')
        # Create a users.json so role lookup succeeds
        self._save('users.json', {'alice': {'role': 'admin', 'password_hash': 'x'}})
        with patch.object(api_module, 'TOKENS_FILE', self.data_dir / 'tokens.json'), \
             patch.object(api_module, 'USERS_FILE', self.data_dir / 'users.json'), \
             patch.object(api_module, 'APIKEYS_FILE', self.data_dir / 'apikeys.json'):
            username, role = api_module.verify_token(token)
            self.assertEqual(username, 'alice')
            self.assertEqual(role, 'admin')

    def test_expired_token_returns_none(self):
        token = self._make_token('bob', offset=-(api_module.TOKEN_TTL + 1))
        with patch.object(api_module, 'TOKENS_FILE', self.data_dir / 'tokens.json'), \
             patch.object(api_module, 'APIKEYS_FILE', self.data_dir / 'apikeys.json'):
            self.assertEqual(api_module.verify_token(token), (None, None))

    def test_unknown_token_returns_none(self):
        self._save('tokens.json', {})
        with patch.object(api_module, 'TOKENS_FILE', self.data_dir / 'tokens.json'), \
             patch.object(api_module, 'APIKEYS_FILE', self.data_dir / 'apikeys.json'):
            self.assertEqual(api_module.verify_token('nonexistent'), (None, None))

    def test_empty_token_returns_none(self):
        self.assertEqual(api_module.verify_token(''), (None, None))


class TestCommandHistory(ApiTestBase):
    def test_log_command_creates_entry(self):
        with patch.object(api_module, 'HISTORY_FILE', self.data_dir / 'history.json'), \
             patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'):
            api_module.log_command('admin', 'dev123', 'mypc', 'shutdown')
            history = self._load('history.json')
            self.assertEqual(len(history['entries']), 1)
            entry = history['entries'][0]
            self.assertEqual(entry['actor'], 'admin')
            self.assertEqual(entry['command'], 'shutdown')
            self.assertEqual(entry['device_name'], 'mypc')

    def test_history_capped_at_max(self):
        with patch.object(api_module, 'HISTORY_FILE', self.data_dir / 'history.json'), \
             patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'):
            for i in range(api_module.MAX_HISTORY + 10):
                api_module.log_command('admin', f'dev{i}', f'pc{i}', 'reboot')
            history = self._load('history.json')
            self.assertEqual(len(history['entries']), api_module.MAX_HISTORY)


class TestWolMagicPacket(ApiTestBase):
    def test_magic_packet_structure(self):
        """Magic packet = 6x FF + MAC repeated 16 times."""
        mac = 'aa:bb:cc:dd:ee:ff'
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        magic = b'\xff' * 6 + mac_bytes * 16
        self.assertEqual(len(magic), 102)
        self.assertEqual(magic[:6], b'\xff' * 6)
        self.assertEqual(magic[6:12], mac_bytes)

    def test_mac_validation_accepts_valid(self):
        import re
        valid = ['aa:bb:cc:dd:ee:ff', 'AA:BB:CC:DD:EE:FF', 'aa-bb-cc-dd-ee-ff']
        pattern = r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$'
        for mac in valid:
            self.assertIsNotNone(re.match(pattern, mac), f"Should accept: {mac}")

    def test_mac_validation_rejects_invalid(self):
        import re
        invalid = ['aa:bb:cc:dd:ee', 'gg:hh:ii:jj:kk:ll', 'aabbccddeeff', '']
        pattern = r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$'
        for mac in invalid:
            self.assertIsNone(re.match(pattern, mac), f"Should reject: {mac}")


class TestOfflineWebhooks(ApiTestBase):
    def test_fires_webhook_for_offline_device(self):
        now = int(time.time())
        devices = {
            'dev1': {
                'name': 'mypc', 'hostname': 'mypc',
                'last_seen': now - (api_module.DEFAULT_ONLINE_TTL + 60),
            }
        }
        self._save('devices.json', devices)
        self._save('config.json', {'webhook_url': 'https://example.com/hook'})

        with patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'), \
             patch.object(api_module, 'CONFIG_FILE',  self.data_dir / 'config.json'), \
             patch.object(api_module, 'fire_webhook') as mock_fire:
            # OFFLINE is debounced: the first sweep only arms a candidate.
            api_module.check_offline_webhooks()
            mock_fire.assert_not_called()
            # Age the candidate past the debounce window, then re-sweep.
            cfg = api_module.load(api_module.CONFIG_FILE)
            cfg['offline_pending']['dev1'] = now - 9999
            api_module.save(api_module.CONFIG_FILE, cfg)
            api_module.check_offline_webhooks()
            mock_fire.assert_called_once()
            args = mock_fire.call_args[0]
            self.assertEqual(args[0], 'device_offline')

    def test_no_webhook_for_online_device(self):
        now = int(time.time())
        devices = {'dev1': {'name': 'mypc', 'hostname': 'mypc', 'last_seen': now}}
        self._save('devices.json', devices)
        self._save('config.json', {'webhook_url': 'https://example.com/hook'})

        with patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'), \
             patch.object(api_module, 'CONFIG_FILE',  self.data_dir / 'config.json'), \
             patch.object(api_module, 'fire_webhook') as mock_fire:
            api_module.check_offline_webhooks()
            mock_fire.assert_not_called()

    def test_no_webhook_when_url_not_configured(self):
        now = int(time.time())
        devices = {
            'dev1': {
                'name': 'mypc', 'hostname': 'mypc',
                'last_seen': now - (api_module.DEFAULT_ONLINE_TTL + 60),
            }
        }
        self._save('devices.json', devices)
        self._save('config.json', {})  # no webhook_url key

        with patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'), \
             patch.object(api_module, 'CONFIG_FILE',  self.data_dir / 'config.json'), \
             patch('urllib.request.urlopen') as mock_urlopen:
            api_module.check_offline_webhooks()
            # No HTTP call should be made when webhook_url is empty
            mock_urlopen.assert_not_called()


class TestDeviceOnlineStatus(ApiTestBase):
    def test_online_within_ttl(self):
        # v1.8.4: ONLINE_TTL is now a config-driven helper (DEFAULT_ONLINE_TTL is the unconfigured default)
        ttl = api_module.DEFAULT_ONLINE_TTL
        now = int(time.time())
        last_seen = now - (ttl - 10)
        is_online = (now - last_seen) < ttl
        self.assertTrue(is_online)

    def test_offline_beyond_ttl(self):
        ttl = api_module.DEFAULT_ONLINE_TTL
        now = int(time.time())
        last_seen = now - (ttl + 10)
        is_online = (now - last_seen) < ttl
        self.assertFalse(is_online)

    def test_helper_clamps_to_minimum(self):
        # If someone sets online_ttl below MIN_ONLINE_TTL in config, the helper clamps it
        api_module.save(api_module.CONFIG_FILE, {'online_ttl': 30})
        try:
            self.assertEqual(api_module.get_online_ttl(), api_module.MIN_ONLINE_TTL)
        finally:
            api_module.save(api_module.CONFIG_FILE, {})


class TestUsernameValidation(ApiTestBase):
    def test_valid_usernames(self):
        import re
        pattern = r'^[a-zA-Z0-9_\-]{2,32}$'
        for name in ['admin', 'john_doe', 'user-1', 'AB']:
            self.assertIsNotNone(re.match(pattern, name))

    def test_invalid_usernames(self):
        import re
        pattern = r'^[a-zA-Z0-9_\-]{2,32}$'
        for name in ['a', '', 'a' * 33, 'user name', 'user@host']:
            self.assertIsNone(re.match(pattern, name))


class TestVersionComparison(ApiTestBase):
    def _vt(self, v):
        try:
            return tuple(int(x) for x in v.split('.'))
        except Exception:
            return (0,)

    def test_update_available(self):
        self.assertTrue(self._vt('1.2.0') > self._vt('1.1.2'))

    def test_no_update_same_version(self):
        self.assertFalse(self._vt('1.2.0') > self._vt('1.2.0'))

    def test_no_update_older(self):
        self.assertFalse(self._vt('1.0.0') > self._vt('1.2.0'))


class TestChannelRouting(ApiTestBase):
    """v3.2.3: channel routing matrix — kind × channel toggling that
    governs which surfaces (Needs Attention, Recent Activity, Alerts,
    Webhook) each event reaches."""

    def test_kind_map_covers_alert_rules(self):
        """Every event in _ALERT_RULES must have a kind so _record_alert
        can gate it. A missing entry means alerts for that event would
        ignore the matrix and always flow through."""
        missing = [e for e in api_module._ALERT_RULES
                   if e not in api_module.EVENT_KIND_MAP]
        self.assertEqual(missing, [],
            f'_ALERT_RULES events without a kind: {missing}')

    def test_default_routes_everywhere(self):
        """No saved config → routing matches each kind's default slot. Most
        kinds default all-on; v3.4.0 added per-kind overrides (new_port is
        informational by default), so compare against _kind_default."""
        for kind, *_ in api_module.CHANNEL_KINDS:
            expected = api_module._kind_default(kind)
            for ch in api_module.CHANNELS:
                self.assertEqual(
                    api_module._channel_allowed(kind, ch), expected[ch],
                    f'default routing for {kind}/{ch} should be {expected[ch]}')

    def test_unknown_event_routes_through(self):
        """Brand-new events that haven't been mapped yet must default to
        delivery — otherwise a code change silently drops events."""
        for ch in api_module.CHANNELS:
            self.assertTrue(
                api_module._channel_allowed('__never_seen__', ch))

    def test_saved_routing_respected(self):
        """Saving channel_routing in config silences the chosen surface."""
        cfg = {'channel_routing': {
            'log_alert': {'needs_attention': False, 'recent_activity': True,
                          'alerts': True, 'webhook': True}}}
        api_module.save(api_module.CONFIG_FILE, cfg)
        self.assertFalse(api_module._channel_allowed('log_alert', 'needs_attention'))
        self.assertTrue(api_module._channel_allowed('log_alert', 'webhook'))

    def test_legacy_hidden_kinds_migrated(self):
        """When channel_routing is absent but the legacy
        dashboard_hidden_attention_kinds list is present, the migration
        derives the matrix on-the-fly so behavior is preserved."""
        cfg = {'dashboard_hidden_attention_kinds': ['log_alert']}
        api_module.save(api_module.CONFIG_FILE, cfg)
        # Hidden attention kind → NA and RA both silenced; alerts +
        # webhook unaffected (legacy schema never controlled those).
        self.assertFalse(api_module._channel_allowed('log_alert', 'needs_attention'))
        self.assertFalse(api_module._channel_allowed('log_alert', 'recent_activity'))
        self.assertTrue(api_module._channel_allowed('log_alert', 'alerts'))
        self.assertTrue(api_module._channel_allowed('log_alert', 'webhook'))

    def test_event_to_kind_resolution(self):
        """_channel_allowed accepts a raw event type and resolves via
        EVENT_KIND_MAP so callers don't need to look up the kind."""
        cfg = {'channel_routing': {
            'tls': {'needs_attention': False, 'recent_activity': True,
                    'alerts': True, 'webhook': True}}}
        api_module.save(api_module.CONFIG_FILE, cfg)
        # tls_expiry → kind 'tls' → needs_attention=false
        self.assertFalse(api_module._channel_allowed('tls_expiry', 'needs_attention'))

    def test_na_kind_alias(self):
        """_compute_attention emits NA items with kinds like service_down,
        monitor_down, custom_script_fail — the matrix uses shorter
        names (service, monitor, script). The NA_KIND_ALIAS table maps
        the former onto the latter so toggling 'service' in the matrix
        actually silences service_down NA cards."""
        self.assertEqual(api_module.NA_KIND_ALIAS.get('service_down'), 'service')
        self.assertEqual(api_module.NA_KIND_ALIAS.get('monitor_down'), 'monitor')
        self.assertEqual(api_module.NA_KIND_ALIAS.get('custom_script_fail'), 'script')

    def test_newly_wired_events_create_alerts(self):
        """v3.2.3: previously these events fired webhooks but were absent
        from _ALERT_RULES, so they never landed in the Alerts inbox.
        Each call below should produce one open alert entry."""
        cases = [
            ('monitor_down',         {'label': 'web1', 'target': 'https://x'}),
            ('brute_force_detected', {'device_id': 'd', 'name': 'h',
                                      'source_ip': '1.2.3.4', 'count': 25,
                                      'unit': 'sshd'}),
            ('ssh_key_added',        {'device_id': 'd', 'name': 'h',
                                      'user': 'root', 'fingerprint': 'SHA256:abc'}),
            ('backup_stale',         {'device_id': 'd', 'name': 'h',
                                      'path': '/var/backups/db.sql',
                                      'label': 'nightly db', 'age_hours': 26}),
            ('snapshot_old',         {'vm_name': 'vm1', 'snap_name': 'pre-upgrade',
                                      'days_old': 90}),
            ('reboot_required',      {'device_id': 'd', 'name': 'h'}),
        ]
        for event, payload in cases:
            result = api_module._record_alert(event, payload)
            self.assertIsNotNone(result,
                f'{event} should now create an alert (was None)')
            self.assertIn('title', result)
            self.assertTrue(result['title'].strip(),
                f'{event} alert title must not be empty')
        # v3.4.0: new_port_detected is informational by default — its alerts
        # channel is off, so _record_alert must NOT create an inbox alert.
        self.assertIsNone(
            api_module._record_alert('new_port_detected', {
                'device_id': 'd', 'name': 'h',
                'proto': 'tcp', 'port': 9999, 'process': 'foo'}),
            'new_port should not create an alert by default (informational)')

    def test_monitor_up_resolves_monitor_down(self):
        """monitor_up has no device_id but should still resolve the
        matching monitor_down alert via label+target sub-match."""
        api_module._record_alert('monitor_down',
            {'label': 'web1', 'target': 'https://x', 'detail': 'timeout'})
        api_module._auto_resolve_alerts('monitor_up',
            {'label': 'web1', 'target': 'https://x'})
        alerts = api_module.load(api_module.ALERTS_FILE).get('alerts', [])
        self.assertTrue(alerts, 'monitor_down should have produced an alert')
        self.assertTrue(alerts[0].get('resolved_at'),
            'monitor_up should have auto-resolved the monitor_down alert')
        self.assertEqual(alerts[0].get('resolved_by'), 'auto')

    def test_state_derived_kinds_present(self):
        """NA-only kinds emitted from device state (no firing event)
        must have matrix rows so operators can silence them. Without
        these, disk/memory/swap/cpu/agent_version/acme cards would be
        unsilenceable."""
        matrix_keys = {k for k, *_ in api_module.CHANNEL_KINDS}
        for needed in ('disk', 'memory', 'swap', 'cpu',
                       'agent_version', 'acme'):
            self.assertIn(needed, matrix_keys,
                f'state-derived NA kind {needed!r} missing from CHANNEL_KINDS')

    def test_record_alert_honours_routing(self):
        """A kind with alerts=false must not append to alerts.json."""
        cfg = {'channel_routing': {
            'log_alert': {'needs_attention': True, 'recent_activity': True,
                          'alerts': False, 'webhook': True}}}
        api_module.save(api_module.CONFIG_FILE, cfg)
        result = api_module._record_alert('log_alert', {
            'device_id': 'dev1', 'name': 'host1',
            'unit': 'nginx', 'pattern': 'error', 'count': 5,
            'level': 'warning',
        })
        self.assertIsNone(result, 'alert should have been suppressed by routing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
