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


class TestMacPosture(unittest.TestCase):
    """v6.3.0: macOS security-posture collector (FileVault/firewall/Gatekeeper/
    SIP/auto-update). The parse is pure, so it runs on Linux without a Mac."""

    def test_parse_all_on(self):
        p = agent._parse_mac_posture(
            "FileVault is On.",
            "Firewall is enabled. (State = 1)",
            "assessments enabled",
            "System Integrity Protection status: enabled.",
            "1")
        self.assertEqual(p, {"filevault": True, "firewall": True, "gatekeeper": True,
                             "sip": True, "auto_security_update": True})

    def test_parse_all_off(self):
        p = agent._parse_mac_posture(
            "FileVault is Off.",
            "Firewall is disabled. (State = 0)",
            "assessments disabled",
            "System Integrity Protection status: disabled.",
            "0")
        self.assertEqual(p["filevault"], False)
        self.assertEqual(p["firewall"], False)
        self.assertEqual(p["gatekeeper"], False)
        self.assertEqual(p["sip"], False)
        self.assertEqual(p["auto_security_update"], False)

    def test_parse_undeterminable_omits(self):
        # empty outputs (tool missing / no permission) → the key is absent, never a
        # false "off" (which would raise a spurious warning check).
        p = agent._parse_mac_posture("", "", "", "", "")
        self.assertEqual(p, {})

    def test_off_mac_returns_empty(self):
        # get_mac_posture is darwin-gated; on the Linux CI box it returns {}.
        self.assertEqual(agent.get_mac_posture(), {})

    def test_sysinfo_includes_posture_key_path(self):
        # collect_sysinfo must route the posture dict into info['mac_posture'];
        # off-Mac it's simply absent (get_mac_posture → {}), never a crash.
        si = agent.collect_sysinfo()
        self.assertIsInstance(si, dict)
        self.assertNotIn("mac_posture", si)  # Linux box → no posture


if __name__ == '__main__':
    unittest.main(verbosity=2)
