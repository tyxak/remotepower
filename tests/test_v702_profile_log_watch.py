#!/usr/bin/env python3
"""A device profile with a log watch killed the Linux agent on every poll.

The Device Profile modal's "Log watches (one per line)" textarea posts one PATH
per line — a list of STRINGS. The profile validator handled `log_watch` in the
same loop as `services_watched`, which IS a list of strings, so it stored them
that way; `_apply_profile_to_device` stamped them onto every selected device and
the heartbeat handed them to the agent, which does `r.get('path')`.

On Linux that loop sits outside any `try` inside `heartbeat()`, and `heartbeat()`
is called with no wrapper — so `'str' object has no attribute 'get'` ended the
process. On every poll. The device still read ONLINE because the heartbeat POST
lands before the crash, so the symptom was not "agent down" but "this host
stopped drifting, stopped running custom scripts and stopped self-updating",
since all of those are gated on a poll count that never got past 1.

The Windows and macOS agents both guard with `isinstance(r, dict)`. Only the
majority platform did not — the half-applied rule again.

Fixed at both ends and in the modal's read-back:
  - the validator normalises a path line to the `{'path': …}` rule the agents
    tail, so the field does what its placeholder advertises;
  - the Linux agent skips a non-dict rule, because an older or hand-edited
    store can still hold one;
  - the modal maps rules back to text rather than joining objects.
"""
import ast
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702lw-'))
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702lw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api_v702lw'] = api
_spec.loader.exec_module(api)


class TestTheProfileStoresRulesTheAgentCanRead(unittest.TestCase):

    def test_a_path_line_becomes_a_path_rule(self):
        out = api._validate_device_profile(
            {'log_watch': ['/var/log/nginx/error.log']})
        self.assertEqual(out['log_watch'], [{'path': '/var/log/nginx/error.log'}])

    def test_no_rule_is_left_as_a_bare_string(self):
        """The shape that killed the agent."""
        out = api._validate_device_profile(
            {'log_watch': ['/var/log/a.log', '/var/log/b.log']})
        for r in out['log_watch']:
            self.assertIsInstance(r, dict)

    def test_a_dict_rule_passes_through(self):
        """A profile written by any other path keeps working."""
        for given in ({'path': '/var/log/x.log'},
                      {'unit': 'sshd', 'pattern': 'Failed password'}):
            out = api._validate_device_profile({'log_watch': [given]})
            self.assertEqual(out['log_watch'], [given])

    def test_a_relative_path_is_dropped_not_stored(self):
        self.assertEqual(
            api._validate_device_profile({'log_watch': ['relative/path']})['log_watch'],
            [])

    def test_services_watched_is_still_a_list_of_strings(self):
        """The control. These two shared a loop; splitting them must not change
        the field that was correct."""
        out = api._validate_device_profile(
            {'services_watched': ['sshd', 'nginx']})
        self.assertEqual(out['services_watched'], ['sshd', 'nginx'])

    def test_what_reaches_the_device_is_what_the_agent_expects(self):
        """End to end through the real apply step, which is what the heartbeat
        then ships."""
        prof = api._validate_device_profile(
            {'log_watch': ['/var/log/nginx/error.log']})
        dev = api._apply_profile_to_device({'id': 'd1'}, prof)
        for r in dev['log_watch']:
            self.assertIsInstance(r, dict, 'the device would crash a Linux agent')


class TestTheLinuxAgentSurvivesABareString(unittest.TestCase):
    """Belt and braces: the store can still hold an old rule, and the twins have
    always tolerated one."""

    @staticmethod
    def _run_loop(rules):
        src = (_ROOT / 'client' / 'remotepower-agent.py').read_text()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == 'heartbeat')
        blk = next(n for n in ast.walk(fn)
                   if isinstance(n, ast.For)
                   and getattr(n.iter, 'id', '') == 'log_watch_rules')
        ns = {'log_watch_rules': rules, '_file_paths': [], 'log_units': set(),
              'str': str, 'isinstance': isinstance, 'dict': dict}
        exec(compile(ast.Module([blk], []), 'agent.py', 'exec'), ns)
        return ns['_file_paths'], ns['log_units']

    def test_a_bare_string_no_longer_raises(self):
        paths, units = self._run_loop(['/var/log/nginx/error.log'])
        self.assertEqual((paths, units), ([], set()),
                         'a string rule is skipped, not acted on')

    def test_a_path_rule_is_still_tailed(self):
        """Control — the guard must not make the loop do nothing."""
        paths, _u = self._run_loop([{'path': '/var/log/nginx/error.log'}])
        self.assertEqual(paths, ['/var/log/nginx/error.log'])

    def test_a_unit_rule_is_still_collected(self):
        _p, units = self._run_loop([{'unit': 'sshd', 'pattern': 'x'}])
        self.assertEqual(units, {'sshd'})

    def test_all_three_agents_guard_the_same_way(self):
        """The twins have always had this; Linux was the odd one out."""
        for rel in ('client/remotepower-agent.py',
                    'client/remotepower-agent-win.py',
                    'client/remotepower-agent-mac.py'):
            src = (_ROOT / rel).read_text()
            self.assertIn('isinstance(r, dict)', src, rel)


class TestTheModalCanStillShowThem(unittest.TestCase):

    def test_the_read_side_maps_rules_back_to_text(self):
        """Joining objects with newlines printed [object Object] the moment the
        server started storing the correct shape."""
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        m = re.search(r"set\('dp-logs',(.{0,400})", js, re.S)
        self.assertTrue(m, "the profile modal's log field moved")
        seg = m.group(1)
        self.assertIn('.path', seg)
        self.assertNotRegex(seg, r"^\s*\(p\.log_watch \|\| \[\]\)\.join")


if __name__ == '__main__':
    unittest.main()
