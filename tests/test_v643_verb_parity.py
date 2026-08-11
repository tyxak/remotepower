#!/usr/bin/env python3
"""The server must not queue a command the target's agent cannot run.

The macOS agent implements 7 of the 18 verbs the server can send; the Windows
agent implements 14. Every UI button that queues one of the missing verbs
returned 200, toasted success, and produced nothing — the agent answered
"unsupported command: X" into a command-result row nobody was looking at. This
is CLAUDE.md's success-toast-then-silence class arriving through the command
channel instead of a heartbeat flag.

api._VERB_OS_SUPPORT is the server's model of that gap. A hand-written table
describing three files that change independently is exactly the sort of thing
that drifts, so this test does not restate it: it DERIVES the matrix from the
three agent sources and fails on a disagreement in EITHER direction.

  • table says supported, agent doesn't implement  → the silent-failure bug is
    back for that verb
  • agent implements, table still restricts        → the verb is refused on a
    platform that grew support, which is quieter and more irritating than the
    bug it was meant to prevent

Deriving from source text has a known weakness — it proves a literal appears in
a dispatch position, not that the branch works. That is acceptable here because
the alternative (no check at all) is what shipped, and because the failure mode
this guards is precisely "nobody updated the other file".
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_CLIENT = _ROOT / 'client'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643verb-'))

_spec = importlib.util.spec_from_file_location('api_v643_verb', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

AGENTS = {
    'linux':   _CLIENT / 'remotepower-agent.py',
    'windows': _CLIENT / 'remotepower-agent-win.py',
    'darwin':  _CLIENT / 'remotepower-agent-mac.py',
}


def _implements(src, verb):
    """True when `verb` appears in a command-dispatch position in this agent.

    Two shapes only — an equality test against the whole command, or a
    startswith on the prefix. Deliberately narrow: a match anywhere in the file
    would count the module docstrings, which LIST the verbs each agent does not
    implement, and would report every gap as covered.
    """
    v = re.escape(verb)
    pats = [
        r"""(?:cmd|command|c)\s*==\s*['"]%s['"]""" % v,
        r"""startswith\(\s*['"]%s['"]""" % v,
        r"""startswith\(\s*\([^)]*['"]%s['"]""" % v,     # startswith(('a:', 'b:'))
    ]
    return any(re.search(p, src) for p in pats)


class TestVerbSupportTableMatchesTheAgents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = {fam: p.read_text() for fam, p in AGENTS.items()}

    def test_every_listed_verb_matches_what_the_agents_implement(self):
        mismatches = []
        for verb, families in sorted(api._VERB_OS_SUPPORT.items()):
            for fam, src in self.src.items():
                claimed = fam in families
                actual = _implements(src, verb)
                if claimed != actual:
                    mismatches.append(
                        f'{verb!r} on {fam}: table says '
                        f'{"supported" if claimed else "unsupported"}, agent '
                        f'{"implements" if actual else "does not implement"} it')
        self.assertEqual(mismatches, [], '\n'.join([
            'api._VERB_OS_SUPPORT and the agents disagree:', *mismatches,
            '', 'Update the table when an agent gains or loses a verb — a stale '
            'entry either re-opens the silent-failure bug or blocks a verb that '
            'now works.']))

    def test_the_derivation_can_actually_tell_the_two_apart(self):
        """A test that reports agreement is worthless if its detector answers
        the same thing everywhere. Pin one known-true and one known-false."""
        self.assertTrue(_implements(self.src['linux'], 'suspend'))
        self.assertFalse(_implements(self.src['darwin'], 'suspend'))
        # And it must not be fooled by a verb NAMED in prose. The mac agent's
        # only occurrence of 'uninstall' is a comment saying it has no uninstall
        # path — a plain substring search reads that as support and reports the
        # gap closed. (CLAUDE.md's "assert against code, not comments".)
        self.assertIn('uninstall', self.src['darwin'],
                      'precondition changed: the mac agent no longer mentions '
                      'uninstall at all, so this case proves nothing')
        self.assertFalse(_implements(self.src['darwin'], 'uninstall'))


class TestTheGateRefusesRatherThanQueue(unittest.TestCase):
    """The behavioural half — the table is only useful if something reads it."""

    def _dev(self, os_str):
        return {'name': 'h1', 'os': os_str}

    def test_a_mac_host_refuses_a_verb_its_agent_lacks(self):
        blocked = api._command_block_reason(self._dev('macOS 14.5 (23F79)'), 'svc:nginx:restart')
        self.assertIsNotNone(blocked, 'a macOS host still accepts svc: — the '
                                      'operator gets a success toast and nothing runs')
        status, msg = blocked
        self.assertEqual(status, 409)
        self.assertIn('macOS', msg)
        self.assertIn('svc', msg)

    def test_the_same_verb_is_accepted_on_linux(self):
        """The positive control. Without it a gate that refused EVERYTHING would
        pass the test above."""
        self.assertIsNone(
            api._command_block_reason(self._dev('Ubuntu 22.04'), 'svc:nginx:restart'))

    def test_universally_supported_verbs_are_untouched(self):
        for os_str in ('Ubuntu 22.04', 'Windows 11 (Build 22631)', 'macOS 14.5'):
            for cmd in ('reboot', 'shutdown', 'update', 'exec:uptime',
                        'poll_interval:120'):
                with self.subTest(os=os_str, cmd=cmd):
                    self.assertIsNone(
                        api._command_block_reason(self._dev(os_str), cmd))

    def test_a_verb_absent_from_the_table_is_never_blocked(self):
        """New verbs must default to allowed — a table that has to be updated
        before a feature works is a table that will ship a broken feature."""
        for os_str in ('Ubuntu 22.04', 'Windows 11', 'macOS 14.5'):
            self.assertIsNone(
                api._command_block_reason(self._dev(os_str), 'brandnewverb:arg'))

    def test_prefix_and_argument_forms_both_resolve(self):
        win = self._dev('Windows 11 (Build 22631)')
        self.assertIsNotNone(api._command_block_reason(win, 'compose:up'))
        self.assertIsNotNone(api._command_block_reason(win, 'speedtest'))
        # 'upgrade:<pkg>' must resolve through the bare 'upgrade' entry
        self.assertIsNone(api._command_block_reason(win, 'upgrade:git'))
        self.assertIsNotNone(
            api._command_block_reason(self._dev('Ubuntu 22.04'), 'upgrade:git'))

    def test_an_unknown_os_string_is_treated_as_linux_and_not_blocked(self):
        """_device_os_family defaults to linux for unclassifiable hosts, which
        is the right default here too — never refuse on a host we cannot read."""
        self.assertIsNone(api._command_block_reason({'name': 'h', 'os': ''}, 'files:ls:/'))


if __name__ == '__main__':
    unittest.main()
