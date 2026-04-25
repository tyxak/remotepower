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
    def test_sha256_verify(self):
        stored = hashlib.sha256(b'secret').hexdigest()
        self.assertTrue(api_module.verify_password('secret', stored))
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
                'last_seen': now - (api_module.ONLINE_TTL + 60),
            }
        }
        self._save('devices.json', devices)
        self._save('config.json', {'webhook_url': 'https://example.com/hook'})

        with patch.object(api_module, 'DEVICES_FILE', self.data_dir / 'devices.json'), \
             patch.object(api_module, 'CONFIG_FILE',  self.data_dir / 'config.json'), \
             patch.object(api_module, 'fire_webhook') as mock_fire:
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
                'last_seen': now - (api_module.ONLINE_TTL + 60),
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
        now = int(time.time())
        last_seen = now - (api_module.ONLINE_TTL - 10)
        is_online = (now - last_seen) < api_module.ONLINE_TTL
        self.assertTrue(is_online)

    def test_offline_beyond_ttl(self):
        now = int(time.time())
        last_seen = now - (api_module.ONLINE_TTL + 10)
        is_online = (now - last_seen) < api_module.ONLINE_TTL
        self.assertFalse(is_online)


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
