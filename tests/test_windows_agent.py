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
        # v6.1.3: JSON-per-line in → (lines, max_rid), each line carrying [EventID]
        # so a server-side log_watch rule can key on it.
        import json as _json
        raw = "\n".join([
            _json.dumps({"rid": 10, "id": 4625, "lvl": "Information",
                         "prov": "Security-Auditing", "t": "Jun 06 10:00:00",
                         "msg": "An account failed to log on"}),
            _json.dumps({"rid": 11, "id": 7036, "lvl": "Information",
                         "prov": "Service Control Manager", "t": "Jun 06 10:01:00",
                         "msg": "The Spooler service stopped"}),
        ])
        lines, max_rid = agent._parse_eventlog(raw)
        self.assertEqual(max_rid, 11)
        self.assertIn("[4625]", lines[0])          # event id present → rules can match
        self.assertIn("An account failed to log on", lines[0])

    def test_parse_eventlog_caps_line_length(self):
        import json as _json
        raw = _json.dumps({"rid": 1, "id": 1, "lvl": "Error", "prov": "P",
                           "t": "Jun 06 10:00:00", "msg": "x" * 2000})
        lines, _ = agent._parse_eventlog(raw)
        self.assertTrue(all(len(l) <= 512 for l in lines))

    def test_parse_eventlog_ignores_garbage_lines(self):
        # A non-JSON line (a PowerShell warning that leaked to stdout) is skipped,
        # not crashed on.
        lines, mx = agent._parse_eventlog("not json\n{bad\n")
        self.assertEqual((lines, mx), ([], 0))

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


# ── v6.1.3: Windows parity — the buildout that closed the "Windows, kind of" gap ─

class TestSelfUpdateIsHonest(unittest.TestCase):
    """The headline bug: the old `update` stub returned rc=0 ('not supported'),
    so a fleet-wide agent-update rollout recorded SUCCESS on every Windows host
    while nothing happened."""

    def test_update_never_reports_a_false_success(self):
        # No server on record → the update cannot succeed, and it must NOT lie
        # about that with rc=0. (Frozen-exe and audit paths also return rc!=0.)
        d = tempfile.mkdtemp()
        os.environ['RP_DATA_DIR'] = d
        agent.save_creds({'device_id': 'x', 'token': 't'})   # no server_url
        r = agent._self_update()
        self.assertNotEqual(r['rc'], 0)
        self.assertEqual(r['cmd'], 'update')

    def test_audit_mode_refuses_self_update(self):
        d = tempfile.mkdtemp()
        os.environ['RP_DATA_DIR'] = d
        open(os.path.join(d, 'audit-mode'), 'w').close()
        try:
            r = agent._self_update()
            self.assertEqual(r['rc'], 126)
        finally:
            os.remove(os.path.join(d, 'audit-mode'))


class TestBinaryHijackHardening(unittest.TestCase):
    """System binaries are resolved by ABSOLUTE PATH, never bare name — the
    agent runs as SYSTEM and a writable %PATH% entry would be a hijack."""

    def test_powershell_resolver_returns_a_path_or_the_bare_fallback(self):
        # Off-Windows the canonical path is absent, so it falls back to the bare
        # name; the point is the FUNCTION is used, so on Windows the absolute path
        # wins. Either way it is never an arbitrary PATH lookup of something else.
        self.assertIn(agent._powershell_bin(), (agent._POWERSHELL, 'powershell'))

    def test_command_argv_uses_the_resolver_not_a_bare_name(self):
        # The exec/reboot argvs must go through the resolver so a hijacked PATH
        # can't substitute the interpreter.
        self.assertEqual(agent.command_argv('exec:x')[0], agent._powershell_bin())
        self.assertEqual(agent.command_argv('reboot')[0], agent._system_bin('shutdown'))


class TestRebootRequired(unittest.TestCase):
    def test_off_windows_is_false_not_error(self):
        # winreg is absent off-Windows → must degrade to False, never raise.
        self.assertIs(agent._reboot_required(), False)

    def test_sysinfo_always_carries_the_flag(self):
        # The server edge-triggers reboot_required off sysinfo; the key must
        # always be present (the -IgnoreReboot updater left it silently missing).
        self.assertIn('reboot_required', agent.collect_sysinfo())


class TestExplicitInterpreters(unittest.TestCase):
    """exec: on Windows always ran as PowerShell; a bash/cmd body was silently
    misinterpreted. ps:/cmd: make the interpreter deterministic."""

    def test_ps_verb_is_powershell(self):
        argv = agent.command_argv('ps:Get-Service')
        self.assertEqual(argv[0], agent._powershell_bin())
        self.assertEqual(argv[-1], 'Get-Service')

    def test_cmd_verb_is_cmd_exe(self):
        argv = agent.command_argv('cmd:dir /b')
        self.assertEqual(argv[0], agent._system_bin('cmd'))
        self.assertEqual(argv[1], '/c')
        self.assertEqual(argv[-1], 'dir /b')


class TestServiceControl(unittest.TestCase):
    def test_state_mapping_never_fabricates_failed(self):
        # Windows has no 'failed' state; a stopped watched service is a WARNING
        # (inactive), not the CRITICAL the server escalates 'failed' to.
        self.assertEqual(agent._WIN_SVC_STATE['running'], 'active')
        self.assertEqual(agent._WIN_SVC_STATE['stopped'], 'inactive')
        self.assertNotIn('failed', agent._WIN_SVC_STATE.values())

    def test_service_name_is_a_single_quoted_ps_literal(self):
        # Injection guard: the name goes into PowerShell as a '' -escaped literal.
        self.assertEqual(agent._ps_single_quote("a'b"), "'a''b'")

    def test_bad_action_is_refused(self):
        self.assertEqual(agent._run_service_action_win('svc:frobnicate:x')['rc'], 2)

    def test_get_services_empty_without_watched(self):
        self.assertEqual(agent.get_services([]), [])


class TestProcessKill(unittest.TestCase):
    def test_system_pids_are_refused(self):
        # PIDs 0-4 (System/Idle/csrss range) must never be killable.
        for pid in (0, 1, 2, 4):
            self.assertEqual(agent._run_process_kill_win(f'kill:TERM:{pid}')['rc'], 2)

    def test_malformed_is_refused(self):
        self.assertEqual(agent._run_process_kill_win('kill:TERM')['rc'], 2)


class TestFileManager(unittest.TestCase):
    import base64 as _b64

    def _b(self, s):
        import base64
        return base64.urlsafe_b64encode(s.encode()).decode()

    def test_path_outside_roots_is_refused(self):
        import json as _json
        r = agent._handle_file_op_win('files:read:' + self._b(r'C:\Windows\System32\config\SAM'))
        self.assertEqual(r['rc'], 1)
        self.assertIn('allowlisted', _json.loads(r['output'])['error'])

    def test_denied_prefix_beats_an_allowed_root(self):
        import json as _json
        # Even if C:\ were allowed, C:\Windows is always denied.
        r = agent._handle_file_op_win('files:list:' + self._b(r'C:\Windows'))
        self.assertEqual(r['rc'], 1)

    def test_relative_path_is_refused(self):
        r = agent._handle_file_op_win('files:read:' + self._b(r'..\..\secret'))
        self.assertEqual(r['rc'], 1)

    def test_write_is_refused_in_audit_mode(self):
        # The allowlist uses Windows path semantics, so on Linux we stub it to
        # True to reach the audit-mode gate that sits AFTER it — the ordering
        # under test is "allowlist first, then audit-mode refusal for mutations".
        d = tempfile.mkdtemp()
        os.environ['RP_DATA_DIR'] = d
        open(os.path.join(d, 'audit-mode'), 'w').close()
        orig = agent._file_mgr_allowed_win
        agent._file_mgr_allowed_win = lambda p: True
        try:
            # Use an OS-absolute path (isabs is platform-native) with the
            # allowlist stubbed, so we reach the audit-mode gate.
            r = agent._handle_file_op_win(
                'files:write:' + self._b(os.path.join(d, 'x.txt')) + ':' + self._b('hi'))
            self.assertEqual(r['rc'], 126)
        finally:
            agent._file_mgr_allowed_win = orig
            os.remove(os.path.join(d, 'audit-mode'))


class TestLoggingExists(unittest.TestCase):
    def test_the_agent_has_a_logger(self):
        # The audit's maintainability finding: the agent had NO logger, so a
        # broken collector was invisible. It now has one.
        # Point the data dir at a temp so the file handler doesn't create a
        # C:\ProgramData tree under CWD when this runs off-Windows.
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp()
        agent.log.handlers.clear()
        agent._init_logging()
        self.assertTrue(agent.log.handlers)


class TestWinAgentUndefinedNames(unittest.TestCase):
    """A JS-style latent bug guard for the agent: an undefined name in a branch
    nobody exercises off-Windows would ship. symtable catches it statically."""

    def test_no_undefined_names(self):
        import symtable
        src = (_ROOT / "client" / "remotepower-agent-win.py").read_text()
        table = symtable.symtable(src, "remotepower-agent-win.py", "exec")

        def _walk(t, undefined):
            if t.get_type() == "function":
                for sym in t.get_symbols():
                    if sym.is_global() and not sym.is_assigned():
                        undefined.add(sym.get_name())
            for child in t.get_children():
                _walk(child, undefined)

        undefined = set()
        _walk(table, undefined)
        # Filter to names that are also not module-level globals or builtins.
        import builtins
        mod_globals = {s.get_name() for s in table.get_symbols()}
        # __file__/__name__/__doc__ are module dunders available in every scope.
        _dunders = {'__file__', '__name__', '__doc__', '__spec__', '__loader__'}
        real = {n for n in undefined
                if n not in mod_globals and n not in _dunders
                and not hasattr(builtins, n)}
        self.assertEqual(real, set(), f"undefined names in win agent: {sorted(real)}")


if __name__ == "__main__":
    unittest.main()
