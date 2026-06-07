#!/usr/bin/env python3
"""Tests for the minimal Windows agent (client/remotepower-agent-win.py).

The agent is stdlib-only and its pure functions (command mapping, payload
assembly) are exercised here on Linux — no Windows needed. Network calls are
monkeypatched.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "rp_win_agent", _ROOT / "client" / "remotepower-agent-win.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class TestVersion(unittest.TestCase):
    def test_version_matches_server(self):
        # keep the Windows agent pinned to the same release as the server
        api_txt = (_ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn(f"VERSION = '{agent.VERSION}'", api_txt.replace('SERVER_', ''))


class TestCommandMapping(unittest.TestCase):
    def test_reboot_shutdown(self):
        self.assertEqual(agent.command_argv('reboot')[:3], ['shutdown', '/r', '/t'])
        self.assertEqual(agent.command_argv('shutdown')[:3], ['shutdown', '/s', '/t'])

    def test_exec_uses_powershell(self):
        argv = agent.command_argv('exec:Get-Service')
        self.assertEqual(argv[0], 'powershell')
        self.assertEqual(argv[-1], 'Get-Service')

    def test_unknown_returns_none(self):
        self.assertIsNone(agent.command_argv('poll_interval:60'))
        self.assertIsNone(agent.command_argv('definitely-not-a-command'))


class TestHeartbeatPayload(unittest.TestCase):
    REQUIRED = {'device_id', 'token', 'ip', 'os', 'version', 'agent_sha256'}

    def test_required_fields_present(self):
        p = agent.build_heartbeat({'device_id': 'd1', 'token': 't'}, poll_count=2)
        self.assertTrue(self.REQUIRED.issubset(p), self.REQUIRED - set(p))
        self.assertEqual(p['version'], agent.VERSION)
        self.assertEqual(p['device_id'], 'd1')

    def test_sysinfo_on_first_and_slow_cadence(self):
        self.assertIn('sysinfo', agent.build_heartbeat({}, poll_count=1))   # first
        self.assertIn('sysinfo', agent.build_heartbeat({}, poll_count=12))  # cadence
        self.assertNotIn('sysinfo', agent.build_heartbeat({}, poll_count=2))

    def test_cmd_output_threaded_back(self):
        out = {'cmd': 'reboot', 'output': 'ok', 'rc': 0}
        p = agent.build_heartbeat({}, poll_count=2, pending_output=out)
        self.assertEqual(p['cmd_output'], out)
        self.assertEqual(p['executed_command'], 'reboot')


class TestWindowsUpdatePatches(unittest.TestCase):
    def test_parse_wu_titles(self):
        out = "2024-05 Cumulative Update\n\n  Security Intelligence Update  \nDefender Update\n"
        self.assertEqual(agent._parse_wu_titles(out),
                         ['2024-05 Cumulative Update', 'Security Intelligence Update', 'Defender Update'])

    def test_parse_wu_titles_empty(self):
        self.assertEqual(agent._parse_wu_titles(''), [])
        self.assertEqual(agent._parse_wu_titles(None), [])

    def test_pending_none_off_windows(self):
        # On Linux (CI), the COM search is never invoked.
        self.assertIsNone(agent.windows_update_pending())

    def test_sysinfo_includes_packages_when_pending(self):
        orig = agent.windows_update_pending
        agent.windows_update_pending = lambda: {'manager': 'windows-update', 'upgradable': 3,
                                                'upgradable_names': ['KB1', 'KB2', 'KB3']}
        try:
            info = agent.collect_sysinfo()
        finally:
            agent.windows_update_pending = orig
        self.assertEqual(info['packages']['manager'], 'windows-update')
        self.assertEqual(info['packages']['upgradable'], 3)


class TestParityCollectors(unittest.TestCase):
    """v3.14.0 (#21): Windows agent parity — listening ports + Event Log journal,
    in the same shapes the Linux agent sends so the existing UI renders them."""

    def test_port_scope_buckets(self):
        self.assertEqual(agent._port_scope('0.0.0.0'), 'world')
        self.assertEqual(agent._port_scope('::'), 'world')
        self.assertEqual(agent._port_scope('8.8.8.8'), 'world')
        self.assertEqual(agent._port_scope('127.0.0.1'), 'local')
        self.assertEqual(agent._port_scope('::1'), 'local')
        self.assertEqual(agent._port_scope(''), 'local')
        self.assertEqual(agent._port_scope('192.168.1.10'), 'lan')
        self.assertEqual(agent._port_scope('10.0.0.5'), 'lan')
        self.assertEqual(agent._port_scope('172.16.5.5'), 'lan')
        self.assertEqual(agent._port_scope('172.32.0.1'), 'world')   # outside 16-31

    def test_listening_ports_shape(self):
        ports = agent.collect_listening_ports()
        self.assertIsInstance(ports, list)
        for p in ports:
            self.assertEqual(set(p), {'proto', 'port', 'process', 'addr', 'scope'})
            self.assertIn(p['proto'], ('tcp', 'udp'))
            self.assertIn(p['scope'], ('world', 'lan', 'local'))

    def test_parse_eventlog(self):
        raw = "Jun 06 10:00:00 Error Foo: bad thing\n\n  Jun 06 10:01:00 Warning Bar: meh  \n"
        out = agent._parse_eventlog(raw)
        self.assertEqual(out, ['Jun 06 10:00:00 Error Foo: bad thing',
                               'Jun 06 10:01:00 Warning Bar: meh'])

    def test_parse_eventlog_caps_lines_and_length(self):
        many = "\n".join(f"line {i} " + "x" * 600 for i in range(150))
        out = agent._parse_eventlog(many)
        self.assertEqual(len(out), 100)            # capped at 100 lines
        self.assertTrue(all(len(l) <= 512 for l in out))

    def test_event_log_journal_empty_off_windows(self):
        self.assertEqual(agent.get_event_log_journal(), [])

    def test_parse_local_accounts(self):
        raw = ("Administrator|1|1700000000|1\n"
               "Guest|0|0|0\n"
               "svc|1|1690000000|0\n"
               "garbage line without pipes\n")
        out = agent._parse_local_accounts(raw, 1700000000 + 10 * 86400)
        self.assertEqual(len(out), 3)
        admin = out[0]
        self.assertEqual(admin['user'], 'Administrator')
        self.assertTrue(admin['login'] and admin['sudo'])
        self.assertIn('admin', admin['flags'])
        self.assertEqual(admin['uid'], -1)            # Windows has no numeric uid
        self.assertEqual(admin['age_days'], 10)
        guest = out[1]
        self.assertFalse(guest['login'])
        self.assertTrue(guest['locked'])
        self.assertIn('disabled', guest['flags'])
        self.assertIsNone(guest['age_days'])           # no PasswordLastSet

    def test_local_accounts_empty_off_windows(self):
        self.assertEqual(agent.get_local_accounts(), [])

    def test_heartbeat_adds_accounts_on_cadence(self):
        orig = agent.get_local_accounts
        agent.get_local_accounts = lambda: [{'user': 'x', 'uid': -1, 'sudo': True,
                                             'login': True, 'locked': False, 'flags': ['admin']}]
        try:
            on = agent.build_heartbeat({'device_id': 'd', 'token': 't'}, 1)
            off = agent.build_heartbeat({'device_id': 'd', 'token': 't'}, 2)
        finally:
            agent.get_local_accounts = orig
        self.assertEqual(on['accounts'][0]['user'], 'x')
        self.assertNotIn('accounts', off)

    def test_sysinfo_includes_listening_ports_when_present(self):
        orig = agent.collect_listening_ports
        agent.collect_listening_ports = lambda: [
            {'proto': 'tcp', 'port': 22, 'process': 'sshd', 'addr': '0.0.0.0', 'scope': 'world'}]
        try:
            info = agent.collect_sysinfo()
        finally:
            agent.collect_listening_ports = orig
        self.assertEqual(info['listening_ports'][0]['port'], 22)

    def test_heartbeat_adds_journal_on_sysinfo_cadence(self):
        orig = agent.get_event_log_journal
        agent.get_event_log_journal = lambda: ['Jun 06 Error svc: boom']
        try:
            on = agent.build_heartbeat({'device_id': 'd', 'token': 't'}, 1)   # cadence poll
            off = agent.build_heartbeat({'device_id': 'd', 'token': 't'}, 2)  # non-cadence
        finally:
            agent.get_event_log_journal = orig
        self.assertEqual(on.get('journal'), ['Jun 06 Error svc: boom'])
        self.assertNotIn('journal', off)   # only on the slow sysinfo cadence


class TestHostFacts(unittest.TestCase):
    def test_os_info_nonempty(self):
        self.assertTrue(agent.get_os_info())

    def test_fmt_uptime(self):
        self.assertEqual(agent._fmt_uptime(0), '0m')
        self.assertEqual(agent._fmt_uptime(90), '1m')
        self.assertEqual(agent._fmt_uptime(3700), '1h 1m')
        self.assertTrue(agent._fmt_uptime(200000).startswith('2d'))


class TestCredsAndCommands(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.environ['RP_DATA_DIR'] = self.d

    def tearDown(self):
        os.environ.pop('RP_DATA_DIR', None)

    def test_poll_interval_command_updates_creds(self):
        agent.save_creds({'device_id': 'd1', 'token': 't', 'poll_interval': 60})
        self.assertIsNone(agent.handle_command('poll_interval:120'))
        self.assertEqual(agent.load_creds()['poll_interval'], 120)

    def test_poll_interval_clamped(self):
        agent.save_creds({'poll_interval': 60})
        agent.handle_command('poll_interval:99999')
        self.assertLessEqual(agent.load_creds()['poll_interval'], 3600)

    def test_enroll_sends_contract_fields_and_saves(self):
        captured = {}

        def fake_post(url, payload, timeout=20):
            captured['url'] = url
            captured['payload'] = payload
            return {'ok': True, 'device_id': 'devX', 'token': 'tokX'}
        orig = agent._post_json
        agent._post_json = fake_post
        try:
            agent.enroll('https://rp.example.com/', pin='123456', name='HostA')
        finally:
            agent._post_json = orig
        self.assertTrue(captured['url'].endswith('/api/enroll/register'))
        pl = captured['payload']
        for k in ('pin', 'hostname', 'name', 'os', 'ip', 'mac', 'version'):
            self.assertIn(k, pl)
        self.assertEqual(pl['version'], agent.VERSION)
        creds = agent.load_creds()
        self.assertEqual(creds['device_id'], 'devX')
        self.assertEqual(creds['token'], 'tokX')


if __name__ == "__main__":
    unittest.main()
