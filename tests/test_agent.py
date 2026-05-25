#!/usr/bin/env python3
"""
Unit tests for remotepower-agent
Run: python3 -m pytest tests/test_agent.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# ── Load agent module ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / 'client'))
import importlib.machinery
import importlib.util
_agent_path = str(Path(__file__).parent.parent / 'client' / 'remotepower-agent')
_loader = importlib.machinery.SourceFileLoader('agent', _agent_path)
_spec   = importlib.util.spec_from_loader('agent', _loader)
agent   = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class TestVersionComparison(unittest.TestCase):
    def _vt(self, v):
        try:
            return tuple(int(x) for x in v.split('.'))
        except Exception:
            return (0,)

    def test_newer_version_detected(self):
        self.assertGreater(self._vt('1.2.0'), self._vt('1.1.2'))

    def test_same_version_not_newer(self):
        self.assertEqual(self._vt('1.1.2'), self._vt('1.1.2'))

    def test_older_version_not_newer(self):
        self.assertLess(self._vt('1.0.0'), self._vt('1.1.0'))

    def test_major_version_bump(self):
        self.assertGreater(self._vt('2.0.0'), self._vt('1.9.9'))


class TestCredentials(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials'
            with patch.object(agent, 'CREDS_FILE', creds_file), \
                 patch.object(agent, 'CONF_DIR', Path(tmpdir)):
                creds = {
                    'server_url': 'https://example.com',
                    'device_id':  'abc123',
                    'token':      'secret',
                    'name':       'testhost',
                }
                agent.save_credentials(creds)
                loaded = agent.load_credentials()
                self.assertEqual(loaded['server_url'], 'https://example.com')
                self.assertEqual(loaded['device_id'], 'abc123')
                self.assertEqual(oct(creds_file.stat().st_mode)[-3:], '600')

    def test_load_missing_returns_none(self):
        with patch.object(agent, 'CREDS_FILE', Path('/nonexistent/path')):
            self.assertIsNone(agent.load_credentials())

    def test_load_incomplete_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / 'credentials'
            creds_file.write_text(json.dumps({'server_url': 'https://x.com'}))
            with patch.object(agent, 'CREDS_FILE', creds_file):
                self.assertIsNone(agent.load_credentials())


class TestGetMac(unittest.TestCase):
    def test_returns_mac_from_sys(self):
        fake_output = "10.0.0.1 via 10.0.0.254 dev eth0 src 10.0.0.2\n"
        with patch('subprocess.check_output', return_value=fake_output), \
             tempfile.TemporaryDirectory() as tmpdir:
            mac_path = Path(tmpdir) / 'address'
            mac_path.write_text('aa:bb:cc:dd:ee:ff\n')
            with patch('pathlib.Path.exists', return_value=True), \
                 patch('pathlib.Path.read_text', return_value='aa:bb:cc:dd:ee:ff\n'):
                # Just verify it doesn't raise
                result = agent.get_mac()
                self.assertIsInstance(result, str)

    def test_returns_empty_on_failure(self):
        with patch('subprocess.check_output', side_effect=Exception("fail")):
            self.assertEqual(agent.get_mac(), '')


class TestGetLocalIp(unittest.TestCase):
    def test_returns_ip_string(self):
        ip = agent.get_local_ip()
        self.assertRegex(ip, r'^\d+\.\d+\.\d+\.\d+$')

    def test_returns_fallback_on_error(self):
        with patch('socket.socket') as mock_sock:
            mock_sock.return_value.__enter__ = mock_sock
            mock_sock.return_value.connect = MagicMock(side_effect=Exception)
            result = agent.get_local_ip()
            self.assertEqual(result, '127.0.0.1')


class TestGetUptime(unittest.TestCase):
    def test_returns_string(self):
        with patch('subprocess.check_output', return_value='up 2 hours, 5 minutes\n'):
            result = agent.get_uptime()
            self.assertEqual(result, 'up 2 hours, 5 minutes')

    def test_returns_empty_on_failure(self):
        with patch('subprocess.check_output', side_effect=Exception):
            self.assertEqual(agent.get_uptime(), '')


class TestGetJournal(unittest.TestCase):
    def test_returns_lines(self):
        fake = "2026-01-01T10:00:00+00:00 systemd[1]: Started test\n"
        with patch('subprocess.check_output', return_value=fake):
            result = agent.get_journal(10)
            self.assertEqual(len(result), 1)

    def test_returns_empty_on_failure(self):
        with patch('subprocess.check_output', side_effect=Exception):
            self.assertEqual(agent.get_journal(), [])


class TestGetPatchInfo(unittest.TestCase):
    def test_apt_counts_inst_lines(self):
        fake_output = "Inst nginx [1.0] (2.0)\nInst curl [7.0] (8.0)\nNot an inst line\n"
        with patch('pathlib.Path.exists', return_value=True), \
             patch('subprocess.check_output', return_value=fake_output):
            # Patch only apt path
            original_exists = Path.exists
            def mock_exists(self):
                if str(self) == '/usr/bin/apt-get':
                    return True
                return False
            with patch.object(Path, 'exists', mock_exists):
                result = agent.get_patch_info()
                self.assertEqual(result['manager'], 'apt')
                self.assertEqual(result['upgradable'], 2)

    def test_returns_unknown_on_no_package_manager(self):
        with patch.object(Path, 'exists', return_value=False):
            result = agent.get_patch_info()
            self.assertEqual(result['manager'], 'unknown')
            self.assertIsNone(result['upgradable'])


class TestSelfUpdate(unittest.TestCase):
    def test_skips_if_same_version(self):
        with patch.object(agent, 'http_get', return_value={
            'version': agent.VERSION,
            'sha256': 'abc',
        }):
            result = agent.check_for_update('https://example.com')
            self.assertFalse(result)

    def test_skips_if_older_version(self):
        with patch.object(agent, 'http_get', return_value={
            'version': '0.0.1',
            'sha256': 'abc',
        }):
            result = agent.check_for_update('https://example.com')
            self.assertFalse(result)

    def test_skips_on_server_error(self):
        with patch.object(agent, 'http_get', side_effect=Exception("timeout")):
            result = agent.check_for_update('https://example.com')
            self.assertFalse(result)

    def test_skips_on_sha256_mismatch(self):
        with patch.object(agent, 'http_get', return_value={
            'version': '99.0.0',
            'sha256': 'expected_sha',
        }), patch.object(agent, 'http_get_binary', return_value=b'fake binary data'):
            result = agent.check_for_update('https://example.com')
            self.assertFalse(result)


class TestExecuteCommand(unittest.TestCase):
    def test_shutdown_calls_systemctl(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            agent.execute_command('shutdown')
            mock_run.assert_called_once_with(
                ['systemctl', 'poweroff'], check=True
            )

    def test_reboot_calls_systemctl(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            agent.execute_command('reboot')
            mock_run.assert_called_once_with(
                ['systemctl', 'reboot'], check=True
            )

    def test_unknown_command_logs_warning(self):
        with patch.object(agent.log, 'warning') as mock_warn:
            agent.execute_command('explode')
            mock_warn.assert_called_once()

    def test_update_triggers_check(self):
        mock_creds = {
            'server_url': 'https://example.com',
            'device_id': 'x', 'token': 't', 'name': 'n'
        }
        with patch.object(agent, 'load_credentials', return_value=mock_creds), \
             patch.object(agent, 'check_for_update', return_value=False) as mock_update:
            agent.execute_command('update')
            mock_update.assert_called_once_with('https://example.com')


class TestGetNetworkInfo(unittest.TestCase):
    def test_parses_ip_json(self):
        fake_json = json.dumps([{
            'ifname': 'eth0',
            'address': 'aa:bb:cc:dd:ee:ff',
            'addr_info': [{'family': 'inet', 'local': '192.168.1.10'}],
        }, {
            'ifname': 'lo',
            'address': '00:00:00:00:00:00',
            'addr_info': [{'family': 'inet', 'local': '127.0.0.1'}],
        }])
        with patch('subprocess.check_output', return_value=fake_json):
            result = agent.get_network_info()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['iface'], 'eth0')
            self.assertEqual(result[0]['ip'], '192.168.1.10')
            self.assertEqual(result[0]['mac'], 'aa:bb:cc:dd:ee:ff')

    def test_returns_empty_on_failure(self):
        with patch('subprocess.check_output', side_effect=Exception):
            self.assertEqual(agent.get_network_info(), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
