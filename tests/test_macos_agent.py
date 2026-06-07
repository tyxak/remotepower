#!/usr/bin/env python3
"""Tests for the minimal macOS agent (client/remotepower-agent-mac.py).

Stdlib-only; its pure functions (command mapping, payload assembly, redacting
secrets scan) run on Linux — no Mac needed. v3.14.0 (#50).
"""
import importlib.util
import json
import tempfile
import os
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "rp_mac_agent", _ROOT / "client" / "remotepower-agent-mac.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class TestVersion(unittest.TestCase):
    def test_version_matches_server(self):
        api_txt = (_ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn(f"VERSION = '{agent.VERSION}'", api_txt.replace('SERVER_', ''))


class TestCommandMapping(unittest.TestCase):
    def test_reboot_shutdown_are_macos_form(self):
        self.assertEqual(agent.command_argv('reboot'), ['shutdown', '-r', '+1'])
        self.assertEqual(agent.command_argv('shutdown'), ['shutdown', '-h', '+1'])

    def test_exec_uses_sh(self):
        argv = agent.command_argv('exec:ls -la')
        self.assertEqual(argv[:2], ['/bin/sh', '-c'])
        self.assertEqual(argv[-1], 'ls -la')

    def test_unknown_returns_none(self):
        self.assertIsNone(agent.command_argv('poll_interval:60'))
        self.assertIsNone(agent.command_argv('definitely-not-a-command'))


class TestHeartbeatPayload(unittest.TestCase):
    REQUIRED = {'device_id', 'token', 'ip', 'os', 'version', 'agent_sha256'}

    def test_required_fields(self):
        p = agent.build_heartbeat({'device_id': 'd1', 'token': 't'}, poll_count=2)
        self.assertTrue(self.REQUIRED.issubset(p), self.REQUIRED - set(p))
        self.assertEqual(p['device_id'], 'd1')

    def test_sysinfo_cadence(self):
        self.assertIn('sysinfo', agent.build_heartbeat({}, poll_count=1))
        self.assertIn('sysinfo', agent.build_heartbeat({}, poll_count=12))
        self.assertNotIn('sysinfo', agent.build_heartbeat({}, poll_count=2))

    def test_cmd_output_threaded_back(self):
        out = {'cmd': 'reboot', 'output': 'ok', 'rc': 0}
        p = agent.build_heartbeat({}, poll_count=2, pending_output=out)
        self.assertEqual(p['cmd_output'], out)
        self.assertEqual(p['executed_command'], 'reboot')


class TestSecretsRedaction(unittest.TestCase):
    def test_scan_never_emits_raw_secret(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__('shutil').rmtree, d, ignore_errors=True)
        (Path(d) / 'creds.env').write_text(
            "AWS_KEY = AKIAIOSFODNN7EXAMPLE\npassword = supersecret12345\n")
        findings = agent.collect_secret_findings([d])
        self.assertTrue(findings)
        for f in findings:
            blob = json.dumps(f)
            self.assertNotIn('AKIAIOSFODNN7EXAMPLE', blob)
            self.assertNotIn('supersecret12345', blob)
            self.assertEqual(len(f['fingerprint']), 16)


if __name__ == '__main__':
    unittest.main(verbosity=2)
