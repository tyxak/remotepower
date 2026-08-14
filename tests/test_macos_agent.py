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


class TestAgentChecks(unittest.TestCase):
    """v6.4.1: the mac agent never read `agent_checks`, so EVERY file/job/log
    custom check assigned to a Mac reported "unknown" forever while the server
    and UI showed it as configured. Portable types are evaluated here on Linux."""

    def test_file_present_and_absent(self):
        with tempfile.NamedTemporaryFile() as f:
            r = agent.eval_agent_checks([
                {'id': 'a', 'type': 'file_present', 'param': f.name},
                {'id': 'b', 'type': 'file_absent', 'param': f.name},
                {'id': 'c', 'type': 'file_present', 'param': f.name + '.nope'},
                {'id': 'd', 'type': 'file_absent', 'param': f.name + '.nope'},
            ])
        self.assertEqual(r['a']['status'], 'ok')
        self.assertEqual(r['b']['status'], 'critical')
        self.assertEqual(r['c']['status'], 'critical')
        self.assertEqual(r['d']['status'], 'ok')

    def test_job_fresh_uses_mtime(self):
        with tempfile.NamedTemporaryFile() as f:
            os.utime(f.name, (0, 0))   # epoch → very stale
            r = agent.eval_agent_checks(
                [{'id': 'j', 'type': 'job_fresh', 'param': f.name,
                  'max_age_hours': 1}])
            self.assertEqual(r['j']['status'], 'critical')
            os.utime(f.name, None)     # now → fresh
            r = agent.eval_agent_checks(
                [{'id': 'j', 'type': 'job_fresh', 'param': f.name,
                  'max_age_hours': 1}])
            self.assertEqual(r['j']['status'], 'ok')

    def test_job_fresh_missing_file_is_critical_not_unknown(self):
        r = agent.eval_agent_checks(
            [{'id': 'j', 'type': 'job_fresh', 'param': '/nonexistent/stamp'}])
        self.assertEqual(r['j']['status'], 'critical')

    def test_launchd_label_is_validated_before_argv(self):
        # A label is never anything but a single reverse-DNS token. There is no
        # shell, so this is defence in depth — but a rejected label must report
        # `unknown`, never run, and never crash.
        for bad in ('', 'a b', 'foo;rm -rf /', '../etc/passwd', 'x' * 200):
            st, out = agent._launchd_status(bad)
            self.assertEqual(st, 'unknown', bad)
            self.assertEqual(out, 'invalid label', bad)
        self.assertTrue(agent._LAUNCHD_LABEL_RE.match('com.apple.sshd'))
        self.assertTrue(agent._LAUNCHD_LABEL_RE.match('homebrew.mxcl.nginx'))

    def test_launchd_status_maps_launchctl_output(self):
        class _R:
            def __init__(self, rc, out):
                self.returncode, self.stdout = rc, out
        cases = [
            (_R(0, '{\n\t"PID" = 431;\n}'), 'ok'),
            (_R(0, '{\n\t"LastExitStatus" = 1;\n}'), 'critical'),
            (_R(0, '{\n\t"LastExitStatus" = 0;\n}'), 'warning'),  # loaded, idle
            (_R(1, ''), 'critical'),                              # not loaded
        ]
        orig = agent.subprocess.run
        try:
            for fake, want in cases:
                agent.subprocess.run = lambda *a, **k: fake
                self.assertEqual(agent._launchd_status('com.apple.sshd')[0], want)
        finally:
            agent.subprocess.run = orig

    def test_unsupported_types_say_so_rather_than_pass_or_fail(self):
        # A Linux-only guard type must NOT report ok (silently green) or
        # critical (a fake alert) on a Mac.
        for t in ('systemd_unit', 'windows_service', 'dir_baseline',
                  'egress_flagged', 'auth_new_source'):
            r = agent.eval_agent_checks([{'id': 'x', 'type': t, 'param': 'p'}])
            self.assertEqual(r['x']['status'], 'unknown', t)
            self.assertIn('macOS', r['x']['output'], t)

    def test_bad_check_shapes_are_skipped_not_fatal(self):
        r = agent.eval_agent_checks([None, 'nope', {}, {'type': 'file_present'},
                                     {'id': 'ok1', 'type': 'file_present',
                                      'param': '/'}])
        self.assertEqual(list(r), ['ok1'])

    def test_output_is_truncated(self):
        r = agent.eval_agent_checks(
            [{'id': 'a', 'type': 'file_present', 'param': 'x' * 5000}])
        self.assertLessEqual(len(r['a']['output']), 200)

    def test_log_errors_applies_the_regex_in_python(self):
        # The operator pattern must never reach the `log show` argv — it is
        # compiled and matched here, so there is nothing to inject through it.
        seen = {}

        class _R:
            returncode, stdout = 0, 'boom failure here\nquiet line\nboom again\n'
        orig = agent.subprocess.run
        try:
            def _fake(argv, *a, **k):
                seen['argv'] = argv
                return _R()
            agent.subprocess.run = _fake
            r = agent.eval_agent_checks([{'id': 'l', 'type': 'log_errors',
                                          'param': 'boom', 'warn': 1, 'crit': 3}])
        finally:
            agent.subprocess.run = orig
        self.assertEqual(r['l']['status'], 'warning')   # 2 matches: >=warn, <crit
        self.assertIn('2 match(es)', r['l']['output'])
        self.assertNotIn('boom', ' '.join(seen['argv']))
        self.assertEqual(seen['argv'][0], 'log')

    def test_log_errors_bad_regex_is_unknown(self):
        r = agent.eval_agent_checks(
            [{'id': 'l', 'type': 'log_errors', 'param': '([unclosed'}])
        self.assertEqual(r['l']['status'], 'unknown')

    def test_log_errors_window_is_clamped(self):
        seen = {}

        class _R:
            returncode, stdout = 0, ''
        orig = agent.subprocess.run
        try:
            def _fake(argv, *a, **k):
                seen['argv'] = argv
                return _R()
            agent.subprocess.run = _fake
            agent.eval_agent_checks([{'id': 'l', 'type': 'log_errors',
                                      'param': 'x', 'window_min': 999999}])
        finally:
            agent.subprocess.run = orig
        self.assertIn('1440m', seen['argv'])


class TestDriftReport(unittest.TestCase):
    """v6.4.1: `watched_files` was dropped too, so a Mac in the fleet produced no
    config-drift report at all while the watch list showed as applied."""

    def test_hashes_present_files_and_flags_missing(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'hello')
            path = f.name
        try:
            out = agent.compute_drift_report([path, '/nonexistent/file'])
        finally:
            os.unlink(path)
        self.assertTrue(out[path]['exists'])
        self.assertTrue(out[path]['hash'].startswith('sha256:'))
        self.assertEqual(out[path]['size'], 5)
        self.assertFalse(out['/nonexistent/file']['exists'])
        self.assertIsNone(out['/nonexistent/file']['hash'])

    def test_capped_at_max_drift_files(self):
        out = agent.compute_drift_report(['/etc/hostname'] * 500)
        self.assertLessEqual(len(out), agent.MAX_DRIFT_FILES)

    def test_empty_list_is_empty_dict(self):
        self.assertEqual(agent.compute_drift_report([]), {})
        self.assertEqual(agent.compute_drift_report(None), {})


class TestHeartbeatWiringForNewSignals(unittest.TestCase):
    """The collectors existing is not enough — the heartbeat must actually carry
    them, and the response handler must actually store the pushed config. This is
    the wiring that was missing, so it is what the guardrail pins."""

    def setUp(self):
        self._ac = agent._watched_agent_checks
        self._wf = agent._watched_files
        agent._watched_agent_checks = []
        agent._watched_files = []

    def tearDown(self):
        agent._watched_agent_checks = self._ac
        agent._watched_files = self._wf

    def test_check_results_land_under_sysinfo_every_beat(self):
        agent._watched_agent_checks = [{'id': 'a', 'type': 'file_present',
                                        'param': '/'}]
        # poll_count=2 is an off-cadence beat with no sysinfo of its own — the
        # results must still be delivered, so sysinfo has to be created.
        p = agent.build_heartbeat({}, poll_count=2)
        self.assertEqual(p['sysinfo']['custom_check_results']['a']['status'], 'ok')

    def test_check_results_do_not_clobber_a_real_sysinfo(self):
        agent._watched_agent_checks = [{'id': 'a', 'type': 'file_present',
                                        'param': '/'}]
        p = agent.build_heartbeat({}, poll_count=1)   # full-sysinfo beat
        self.assertIn('custom_check_results', p['sysinfo'])
        self.assertIn('hostname', p['sysinfo'])       # the real sysinfo survived

    def test_no_checks_means_no_key(self):
        p = agent.build_heartbeat({}, poll_count=2)
        self.assertNotIn('sysinfo', p)

    def test_drift_rides_the_sysinfo_cadence(self):
        agent._watched_files = ['/etc/hostname']
        self.assertIn('drift', agent.build_heartbeat({}, poll_count=1))
        self.assertNotIn('drift', agent.build_heartbeat({}, poll_count=2))

    def test_response_handler_stores_pushed_config(self):
        orig = agent._post_json
        try:
            agent._post_json = lambda *a, **k: {
                'ok': True,
                'agent_checks': [{'id': 'c1', 'type': 'file_present', 'param': '/'},
                                 {'no_id': 1}, 'junk'],
                'watched_files': ['/etc/hosts', '  ', '/etc/hostname'],
            }
            agent.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            agent._post_json = orig
        self.assertEqual([c['id'] for c in agent._watched_agent_checks], ['c1'])
        self.assertEqual(agent._watched_files, ['/etc/hosts', '/etc/hostname'])

    def test_pushed_config_is_capped(self):
        orig = agent._post_json
        try:
            agent._post_json = lambda *a, **k: {
                'ok': True,
                'agent_checks': [{'id': f'c{i}', 'type': 'file_present',
                                  'param': '/'} for i in range(500)],
                'watched_files': [f'/f{i}' for i in range(500)],
            }
            agent.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            agent._post_json = orig
        self.assertEqual(len(agent._watched_agent_checks), 100)
        self.assertEqual(len(agent._watched_files), agent.MAX_DRIFT_FILES)

    def test_non_list_response_values_are_ignored(self):
        agent._watched_files = ['/keep']
        orig = agent._post_json
        try:
            agent._post_json = lambda *a, **k: {'ok': True, 'watched_files': 'oops',
                                                'agent_checks': {'not': 'a list'}}
            agent.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            agent._post_json = orig
        self.assertEqual(agent._watched_files, ['/keep'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
