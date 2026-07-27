#!/usr/bin/env python3
"""v6.4.1: custom monitoring scripts on the Windows and macOS agents.

`_get_custom_scripts_for_device` assigns by DEVICE ID with no OS awareness, and
the heartbeat pushes `custom_scripts` to every agent — but only the Linux agent
ever read the key. So an operator could assign a script to a Mac or a Windows
box, get a success toast, and watch the Custom Scripts results page stay empty
forever. The same silent-failure class as the agent-checks and canary gaps.

The two platforms are deliberately NOT handled the same way:

  * macOS ships /bin/bash, so it runs the body exactly like Linux does.
  * Windows cannot run a /bin/bash body at all. Guessing an interpreter would
    push an operator's shell script through PowerShell and report the wreckage,
    so the body must declare itself with a `#!ps` / `#!cmd` first line. A body
    with no marker is reported as a FAILED run carrying an actionable message —
    an explicit red result tells the operator what to fix; silence does not.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
# Keep the macOS agent's logger off any real /var/log path when it imports.
# RESTORED in tearDownModule: under `unittest discover` a module-level env var
# leaks into every later module in the same process, and this one made
# test_v641_mac_log_rotation's "defaults" assertions read our temp path instead
# of the real default. Same class as the RP_STORAGE_BACKEND leak that blocked
# the v6.3.0 gate — set it, but always put it back.
_PRIOR_AGENT_LOG = os.environ.get("RP_AGENT_LOG")
os.environ["RP_AGENT_LOG"] = os.path.join(tempfile.mkdtemp(), "a.log")


def tearDownModule():
    if _PRIOR_AGENT_LOG is None:
        os.environ.pop("RP_AGENT_LOG", None)
    else:
        os.environ["RP_AGENT_LOG"] = _PRIOR_AGENT_LOG
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _ScriptContract:
    """Behaviour both agents must share: receive, cadence, report, audit-mode."""

    AGENT_REL = None

    def setUp(self):
        self.ag = _load(f'cs_{self.__class__.__name__}', self.AGENT_REL)
        self.ag._custom_scripts = []
        self.ag._pending_script_results = {}

    def test_receives_scripts_from_the_heartbeat_response(self):
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {'ok': True, 'custom_scripts': [
                {'id': 's1', 'name': 'a', 'body': 'x', 'timeout': 5},
                {'no_id': 1}, 'junk']}
            self.ag.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            self.ag._post_json = orig
        self.assertEqual([s['id'] for s in self.ag._custom_scripts], ['s1'])

    def test_a_non_list_is_ignored(self):
        self.ag._custom_scripts = [{'id': 'keep'}]
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {'ok': True,
                                                  'custom_scripts': 'nope'}
            self.ag.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            self.ag._post_json = orig
        self.assertEqual([s['id'] for s in self.ag._custom_scripts], ['keep'])

    def test_backstop_cap_is_above_the_server_limit(self):
        # A cap AT the server's number would silently drop assigned scripts the
        # day the server's limit rises — the exact silent-failure class this
        # whole change is removing.
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {'ok': True, 'custom_scripts': [
                {'id': f's{i}', 'body': 'x'} for i in range(60)]}
            self.ag.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            self.ag._post_json = orig
        self.assertEqual(len(self.ag._custom_scripts), 20)
        self.assertGreater(20, api.MAX_CUSTOM_SCRIPTS_PER_DEVICE)

    def test_results_ride_the_payload_and_are_cleared(self):
        self.ag._pending_script_results = {'s1': {'ok': True, 'output': 'x',
                                                  'rc': 0, 'ran_at': 1,
                                                  'duration_ms': 1}}
        p = self.ag.build_heartbeat({'device_id': 'd', 'token': 't'}, poll_count=2)
        self.assertIn('custom_script_results', p)
        # Cleared after handing them over, so a result is reported exactly once.
        p2 = self.ag.build_heartbeat({'device_id': 'd', 'token': 't'}, poll_count=2)
        self.assertNotIn('custom_script_results', p2)

    def test_no_scripts_means_no_key(self):
        p = self.ag.build_heartbeat({'device_id': 'd', 'token': 't'}, poll_count=5)
        self.assertNotIn('custom_script_results', p)

    def test_audit_mode_refuses_to_run_them(self):
        # Custom scripts run server-supplied script text as root/SYSTEM, which
        # is precisely what observe-only mode exists to block. The Linux agent
        # guards this; both of these must too.
        orig = self.ag._audit_mode
        try:
            self.ag._audit_mode = lambda: True
            self.assertEqual(
                self.ag.run_custom_scripts([{'id': 's', 'body': 'echo hi'}]), {})
        finally:
            self.ag._audit_mode = orig

    def test_malformed_script_entries_are_skipped(self):
        self.assertEqual(self.ag.run_custom_scripts(
            [{'id': '', 'body': 'x'}, {'id': 's', 'body': ''}, {}]), {})
        self.assertEqual(self.ag.run_custom_scripts([]), {})
        self.assertEqual(self.ag.run_custom_scripts(None), {})

    def test_result_shape_matches_what_the_server_ingests(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': self.RUNNABLE_BODY, 'timeout': 20}])
        self.assertEqual(set(res['s1']),
                         {'ok', 'output', 'rc', 'ran_at', 'duration_ms'})
        self.assertIsInstance(res['s1']['ok'], bool)
        self.assertIsInstance(res['s1']['rc'], int)

    def test_builder_and_response_handler_are_wired(self):
        src = (_ROOT / self.AGENT_REL).read_text()
        build = src[src.index('def build_heartbeat('):]
        build = build[:build.index('\ndef ', 1)]
        self.assertIn('run_custom_scripts(', build)
        self.assertIn('custom_script_results', build)
        hb = src[src.index('def heartbeat_once('):]
        hb = hb[:hb.index('\ndef ', 1)]
        self.assertIn("resp.get('custom_scripts')", hb)


class TestMacCustomScripts(_ScriptContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-mac.py'
    RUNNABLE_BODY = 'echo hello-from-script'

    def test_runs_the_body_with_bash_like_linux(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'echo hello-from-script', 'timeout': 20}])
        self.assertTrue(res['s1']['ok'])
        self.assertEqual(res['s1']['rc'], 0)
        self.assertEqual(res['s1']['output'], 'hello-from-script')

    def test_nonzero_exit_is_not_ok(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'exit 3', 'timeout': 20}])
        self.assertFalse(res['s1']['ok'])
        self.assertEqual(res['s1']['rc'], 3)

    def test_stderr_is_merged_into_the_output(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'echo oops >&2; exit 1', 'timeout': 20}])
        self.assertIn('oops', res['s1']['output'])

    def test_output_is_capped(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'head -c 20000 /dev/zero | tr "\\0" "a"',
              'timeout': 20}])
        self.assertLessEqual(len(res['s1']['output']), self.ag.MAX_SCRIPT_OUTPUT)

    def test_timeout_is_enforced_and_reported(self):
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'sleep 5', 'timeout': 1}])
        self.assertFalse(res['s1']['ok'])
        self.assertIn('TIMEOUT', res['s1']['output'])

    def test_the_temp_script_is_not_left_behind(self):
        before = set(os.listdir(tempfile.gettempdir()))
        self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'echo x', 'timeout': 20}])
        leaked = {f for f in set(os.listdir(tempfile.gettempdir())) - before
                  if f.startswith('rp_cs_')}
        self.assertEqual(leaked, set())


class TestWindowsCustomScripts(_ScriptContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-win.py'
    RUNNABLE_BODY = '#!cmd\n@echo hi'

    def test_interpreter_marker_is_recognised(self):
        for tag, want in (('#!ps', 'ps'), ('#!powershell', 'ps'),
                          ('#!cmd', 'cmd'), ('#!bat', 'cmd'), ('#!batch', 'cmd'),
                          ('  #!PS  ', 'ps')):
            kind, rest = self.ag._script_interpreter(f'{tag}\nbody here')
            self.assertEqual(kind, want, tag)
            self.assertEqual(rest, 'body here')

    def test_unmarked_body_fails_loudly_instead_of_silently(self):
        # THE point of this change: a bash body assigned to a Windows host used
        # to do nothing at all. It must now produce a red result that says why.
        res = self.ag.run_custom_scripts(
            [{'id': 's1', 'body': 'echo hi\nuname -a', 'timeout': 20}])
        self.assertFalse(res['s1']['ok'])
        self.assertEqual(res['s1']['rc'], -1)
        self.assertIn('interpreter', res['s1']['output'])
        self.assertIn('#!ps', res['s1']['output'])
        self.assertIn('#!cmd', res['s1']['output'])

    def test_unmarked_body_is_reported_not_skipped(self):
        # It must appear in the results dict — a skipped id is invisible to the
        # operator, which is the bug, not the fix.
        res = self.ag.run_custom_scripts([{'id': 's1', 'body': 'echo hi'}])
        self.assertIn('s1', res)

    def test_marker_is_stripped_before_execution(self):
        # The marker must not reach the interpreter as a stray line.
        kind, rest = self.ag._script_interpreter('#!ps\nWrite-Host 1')
        self.assertEqual((kind, rest), ('ps', 'Write-Host 1'))


class TestEndToEndOnMac(unittest.TestCase):
    """assign -> push -> run -> report -> store, through the real server."""

    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ('respond', 'get_json_obj', 'method')}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: 'POST'
        self.dev = 'mac-cs-host'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': self.dev, 'token': 'devtoken', 'os': 'macOS 15',
            'last_seen': int(time.time()), 'enrolled': int(time.time()),
            'tags': [], 'group': '', 'sysinfo': {}, 'agentless': False}})
        api.save(api.CUSTOM_SCRIPTS_FILE, {'s1': {
            'id': 's1', 'name': 'probe', 'body': 'echo hello-from-script',
            'timeout': 20, 'assigned_devices': [self.dev]}})
        self.ag = _load('cs_e2e', 'client/remotepower-agent-mac.py')
        self.ag._custom_scripts = []
        self.ag._pending_script_results = {}

    def test_the_whole_chain(self):
        pushed = api._get_custom_scripts_for_device(self.dev)
        self.assertEqual([s['id'] for s in pushed], ['s1'],
                         'the server does not offer the script to this device')

        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {'ok': True,
                                                  'custom_scripts': pushed}
            self.ag.heartbeat_once(
                {'server_url': 'http://x', 'device_id': self.dev}, 2)
        finally:
            self.ag._post_json = orig
        self.assertEqual([s['id'] for s in self.ag._custom_scripts], ['s1'])

        payload = self.ag.build_heartbeat(
            {'device_id': self.dev, 'token': 'devtoken'}, poll_count=5)
        self.assertIn('custom_script_results', payload,
                      'the 5th poll did not run the script')
        self.assertTrue(payload['custom_script_results']['s1']['ok'])

        body = {'device_id': self.dev, 'token': 'devtoken',
                'custom_script_results': payload['custom_script_results']}
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
        stored = (api.load(api.DEVICES_FILE)[self.dev]
                  .get('custom_script_results') or {})
        self.assertTrue(stored.get('s1', {}).get('ok'),
                        f'the server did not store the result: {stored}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
