#!/usr/bin/env python3
"""Tests for the minimal Windows agent (client/remotepower-agent-win.py).

The agent is stdlib-only and its pure functions (command mapping, payload
assembly) are exercised here on Linux — no Windows needed. Network calls are
monkeypatched.
"""
import importlib.util
import json
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


class TestEnrollErrorUX(unittest.TestCase):
    """A bad PIN/token at enroll must give a READABLE error, not a raw Python
    traceback (which is what a live operator hit: HTTP 400 from passing a 6-digit
    PIN to --token surfaced as a urllib stack trace)."""

    def test_six_digit_token_is_caught_as_a_pin_hint(self):
        import io
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = agent.main(['--enroll', '--server', 'https://h', '--token', '356177'])
        self.assertEqual(rc, 2)                      # refused before any network call
        self.assertIn('PIN', err.getvalue())
        self.assertIn('--pin', err.getvalue())

    def test_post_json_surfaces_server_error_message(self):
        # _post_json must turn a 4xx into a RuntimeError carrying the server's
        # {"error": "..."} text, not let the raw HTTPError traceback escape.
        import io
        import urllib.error

        class _Opener:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(
                    req.full_url, 400, 'BAD REQUEST', {},
                    io.BytesIO(json.dumps({'error': 'Invalid enrollment token format'}).encode()))

        orig = agent._OPENER
        agent._OPENER = _Opener()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                agent._post_json('https://h/api/enroll/register', {'x': 1})
            self.assertIn('Invalid enrollment token format', str(ctx.exception))
        finally:
            agent._OPENER = orig


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
        # v6.1.3: JSON-per-line in → (entries, max_rid) where each entry is a
        # (record_id, line) tuple. The Python-side cursor filter keys on
        # record_id; the line carries [EventID] so a log_watch rule can match.
        import json as _json
        raw = "\n".join([
            _json.dumps({"rid": 10, "id": 4625, "lvl": "Information",
                         "prov": "Security-Auditing", "t": "Jun 06 10:00:00",
                         "msg": "An account failed to log on"}),
            _json.dumps({"rid": 11, "id": 7036, "lvl": "Information",
                         "prov": "Service Control Manager", "t": "Jun 06 10:01:00",
                         "msg": "The Spooler service stopped"}),
        ])
        entries, max_rid = agent._parse_eventlog(raw)
        self.assertEqual(max_rid, 11)
        self.assertEqual(entries[0][0], 10)        # record_id preserved for cursor filter
        self.assertIn("[4625]", entries[0][1])     # event id present → rules can match
        self.assertIn("An account failed to log on", entries[0][1])

    def test_parse_eventlog_caps_line_length(self):
        import json as _json
        raw = _json.dumps({"rid": 1, "id": 1, "lvl": "Error", "prov": "P",
                           "t": "Jun 06 10:00:00", "msg": "x" * 2000})
        entries, _ = agent._parse_eventlog(raw)
        self.assertTrue(all(len(line) <= 512 for _rid, line in entries))

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


# ── v6.1.3 wave 2: SMART / hardware / drift / containers / posture / checks ──

class TestSmart(unittest.TestCase):
    def test_warning_maps_to_failed(self):
        # A Windows 'Warning' disk is degraded → the server's FAILED (alerts),
        # never left as PASSED.
        out = agent._parse_smart(json.dumps(
            {"device": "1", "model": "WD", "serial": "W", "health": "Warning",
             "wear": 12, "temperature_c": 40, "power_on_hours": 9000, "read_errors": 2}))
        self.assertEqual(out[0]["health"], "FAILED")
        self.assertEqual(out[0]["wear_pct"], 12)
        self.assertEqual(out[0]["temperature_c"], 40)
        self.assertEqual(out[0]["crc_errors"], 2)   # read errors → the trended counter

    def test_healthy_maps_to_passed(self):
        out = agent._parse_smart(json.dumps(
            {"device": "0", "model": "S", "serial": "x", "health": "Healthy"}))
        self.assertEqual(out[0]["health"], "PASSED")

    def test_off_windows_empty(self):
        self.assertEqual(agent.get_smart_status(), [])

    def test_garbage_lines_skipped(self):
        self.assertEqual(agent._parse_smart("not json\n"), [])


class TestHardwareInventory(unittest.TestCase):
    def test_shape_matches_server(self):
        hw = agent._parse_hwinv(json.dumps(
            {"manufacturer": "Dell", "product": "OptiPlex", "serial": "ABC",
             "memory": [{"locator": "DIMM0", "size": "16 GB", "speed": "3200 MHz"}]}))
        self.assertEqual(hw["system"]["manufacturer"], "Dell")
        self.assertEqual(hw["memory"][0]["locator"], "DIMM0")

    def test_single_dimm_object_is_wrapped(self):
        # ConvertTo-Json renders a single DIMM as an object, not a 1-element array.
        hw = agent._parse_hwinv(json.dumps(
            {"manufacturer": "X", "memory": {"locator": "DIMM0", "size": "8 GB"}}))
        self.assertEqual(len(hw["memory"]), 1)

    def test_off_windows_empty(self):
        self.assertEqual(agent.get_hardware_inventory(), {})


class TestDrift(unittest.TestCase):
    def test_hashes_existing_and_flags_missing(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "f.txt")
        open(p, "w").write("hello")
        rep = agent.compute_drift_report([p, os.path.join(d, "gone")])
        self.assertTrue(rep[p]["exists"])
        self.assertTrue(rep[p]["hash"].startswith("sha256:"))
        self.assertFalse(rep[os.path.join(d, "gone")]["exists"])

    def test_bounded(self):
        d = tempfile.mkdtemp()
        paths = []
        for i in range(agent.MAX_DRIFT_FILES + 50):
            p = os.path.join(d, f"f{i}")
            open(p, "w").write("x")
            paths.append(p)
        self.assertLessEqual(len(agent.compute_drift_report(paths)), agent.MAX_DRIFT_FILES)


class TestWinPosture(unittest.TestCase):
    def test_parse_shape(self):
        wp = agent._parse_win_posture(json.dumps({
            "firewall": [{"name": "Public", "enabled": False}],
            "bitlocker": [{"mount": "C:", "status": "On"}],
            "defender_realtime": False, "defender_sig_age_days": 9,
            "wu_service": "Running"}))
        self.assertEqual(wp["defender_realtime"], False)
        self.assertEqual(wp["defender_sig_age_days"], 9)
        self.assertEqual(wp["firewall"][0]["enabled"], False)

    def test_single_firewall_profile_object_wrapped(self):
        wp = agent._parse_win_posture(json.dumps(
            {"firewall": {"name": "Domain", "enabled": True}}))
        self.assertEqual(len(wp["firewall"]), 1)

    def test_off_windows_empty(self):
        self.assertEqual(agent.get_win_posture(), {})


class TestAgentSideChecks(unittest.TestCase):
    """The Windows agent evaluated NO agent-side checks before v6.1.3 — every
    file/job/service custom check silently reported 'unknown' on Windows."""

    def test_file_present_absent(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x")
        open(p, "w").write("x")
        r = agent.eval_agent_checks([
            {"id": "a", "type": "file_present", "param": p},
            {"id": "b", "type": "file_present", "param": os.path.join(d, "nope")},
            {"id": "c", "type": "file_absent", "param": p},
        ])
        self.assertEqual(r["a"]["status"], "ok")
        self.assertEqual(r["b"]["status"], "critical")
        self.assertEqual(r["c"]["status"], "critical")

    def test_job_fresh(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "stamp")
        open(p, "w").write("x")
        r = agent.eval_agent_checks([{"id": "j", "type": "job_fresh", "param": p, "max_age_hours": 24}])
        self.assertEqual(r["j"]["status"], "ok")

    def test_systemd_unit_is_not_applicable_on_windows(self):
        r = agent.eval_agent_checks([{"id": "u", "type": "systemd_unit", "param": "nginx.service"}])
        self.assertEqual(r["u"]["status"], "unknown")

    def test_windows_service_check_off_windows_reports_cleanly(self):
        # Off-Windows the PowerShell call fails → 'unknown', never a crash.
        r = agent.eval_agent_checks([{"id": "s", "type": "windows_service", "param": "wuauserv"}])
        self.assertIn(r["s"]["status"], ("unknown", "critical"))

    def test_log_errors_bad_pattern(self):
        r = agent.eval_agent_checks([{"id": "l", "type": "log_errors", "param": "(unclosed"}])
        # An invalid regex reports 'unknown' rather than raising.
        self.assertEqual(r["l"]["status"], "unknown")


_PWSH = None
for _cand in ("/home/jaove/.claude/jobs/2bd1277d/tmp/pwsh/pwsh", "pwsh"):
    import shutil as _sh
    _p = _cand if os.path.exists(_cand) else _sh.which(_cand)
    if _p:
        _PWSH = _p
        break


@unittest.skipUnless(_PWSH, "PowerShell not available to parse-validate the agent's PS")
class TestPowerShellSnippetsParse(unittest.TestCase):
    """Validate every PowerShell string the agent builds actually PARSES, using a
    real pwsh. This caught a `@{{…}}` double-brace bug in the Event Log template
    (str.replace, not str.format) that would have failed on every Windows host."""

    def _parses(self, ps_text):
        import subprocess
        # PARSE ONLY — never execute. The snippet path travels via an env var so
        # it can't be interpreted as a trailing command (which would run it).
        f = tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False)
        f.write(ps_text)
        f.close()
        script = (
            "$e=$null;$t=$null;"
            "$null=[System.Management.Automation.Language.Parser]::ParseInput("
            "[System.IO.File]::ReadAllText($env:RP_PS_FILE),[ref]$t,[ref]$e);"
            "if($e.Count){'ERR:'+$e[0].Message}else{'OK'}"
        )
        out = subprocess.run([_PWSH, "-NoProfile", "-Command", script],
                             capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, RP_PS_FILE=f.name))
        return (out.stdout or "").strip()

    def test_all_agent_ps_snippets_parse(self):
        snippets = {
            "_SMART_PS": agent._SMART_PS,
            "_HWINV_PS": agent._HWINV_PS,
            "_SVC_PS": agent._SVC_PS.replace("{NAMES}", "@()"),
            "_WU_PS": agent._WU_PS,
            "_DEFENDER_PS": agent._DEFENDER_PS,
            "_LOCAL_USERS_PS": agent._LOCAL_USERS_PS,
            "_WIN_POSTURE_PS": agent._WIN_POSTURE_PS,
            "_EVENTLOG_PS_TMPL(System)": (agent._EVENTLOG_PS_TMPL
                .replace("{CHANNEL}", "System").replace("{LEVEL}", ";Level=1,2,3")
                .replace("{MAX}", "10").replace("{SINCE}", "0")),
            "_EVENTLOG_PS_TMPL(Security)": (agent._EVENTLOG_PS_TMPL
                .replace("{CHANNEL}", "Security").replace("{LEVEL}", "")
                .replace("{MAX}", "10").replace("{SINCE}", "5")),
        }
        for name, ps in snippets.items():
            with self.subTest(snippet=name):
                self.assertEqual(self._parses(ps), "OK", f"{name} did not parse")


class TestWinPostureChecks(unittest.TestCase):
    """The check-catalog rows derived from win_posture (server-side checks.py)."""

    def setUp(self):
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        import checks
        self.checks = checks

    def _rows(self, wp, extra_si=None):
        si = {"win_posture": wp}
        si.update(extra_si or {})
        import time
        dev = {"last_seen": time.time(), "sysinfo": si}
        return {r["key"]: r for r in self.checks._host_checks("d1", dev)}

    def test_defender_off_is_critical(self):
        rows = self._rows({"defender_realtime": False})
        self.assertEqual(rows["win_av_realtime"]["status"], "critical")

    def test_stale_signatures_escalate(self):
        self.assertEqual(self._rows({"defender_sig_age_days": 9})["win_av_signatures"]["status"], "critical")
        self.assertEqual(self._rows({"defender_sig_age_days": 1})["win_av_signatures"]["status"], "ok")

    def test_firewall_profile_off_warns(self):
        rows = self._rows({"firewall": [{"name": "Public", "enabled": False}]})
        self.assertEqual(rows["win_firewall"]["status"], "warning")

    def test_bitlocker_unprotected_warns(self):
        rows = self._rows({"bitlocker": [{"mount": "C:", "status": "Off"}]})
        self.assertEqual(rows["win_bitlocker"]["status"], "warning")

    def test_update_service_stopped_warns(self):
        rows = self._rows({"wu_service": "Stopped"})
        self.assertEqual(rows["win_update_service"]["status"], "warning")

    def test_cpu_percent_fallback_on_windows(self):
        # Windows has no loadavg; the CPU check must still render from cpu_percent.
        rows = self._rows({}, {"cpu_percent": 97.0})
        self.assertEqual(rows["cpu"]["status"], "critical")

    def test_linux_host_gets_no_windows_rows(self):
        import time
        dev = {"last_seen": time.time(), "sysinfo": {"loadavg_1m": 0.2, "cpu_count": 4}}
        keys = {r["key"] for r in self.checks._host_checks("d1", dev)}
        self.assertFalse(keys & {"win_av_realtime", "win_bitlocker", "win_firewall"})


if __name__ == "__main__":
    unittest.main()
