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

import srcpin

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


# The command-dispatch functions in each agent. Deriving verbs from the WHOLE
# file picks up every `startswith('x:')` in the module — URL schemes, IPv6
# prefixes, output parsers — and reports eight verbs that do not exist. Scoped
# to the dispatchers, the same derivation returns exactly the real set.
DISPATCHERS = {
    'linux':   ('execute_command',),
    'windows': ('handle_command', 'command_argv'),
    'darwin':  ('handle_command', 'command_argv'),
}


def _dispatch_body(fam):
    src = AGENTS[fam].read_text()
    return '\n'.join(srcpin.py_function(src, fn) for fn in DISPATCHERS[fam])


def _verbs_implemented(body):
    """Every verb this dispatcher branches on."""
    out = set()
    for pat in (r"""(?:cmd|command|c)\s*==\s*['"]([a-z_][a-z_0-9]*)['"]""",
                r"""startswith\(\s*['"]([a-z_][a-z_0-9]*:)['"]"""):
        out.update(m.group(1) for m in re.finditer(pat, body))
    for m in re.finditer(r"""startswith\(\s*\(([^)]*)\)""", body):
        out.update(q.group(1) for q in
                   re.finditer(r"""['"]([a-z_][a-z_0-9]*:)['"]""", m.group(1)))
    return out


class TestTheTablesPopulationIsEveryPlatformSpecificVerb(unittest.TestCase):
    """The gate below iterates api._VERB_OS_SUPPORT, so a verb that is missing
    from the table is not failing it — it is invisible to it. That is how
    `cron:` shipped: implemented only on Linux, absent from the table, and the
    table's own comment says an absent verb is treated as universally
    supported. The Cron page's host picker has no OS filter, so a Windows host
    was selectable, the queue accepted it, and the operator got "Crontab for
    root queued" for a command that answered rc 1.

    So measure the POPULATION, not just the rule: any verb some dispatchers
    implement and others do not must be described by the table."""

    @classmethod
    def setUpClass(cls):
        cls.impl = {fam: _verbs_implemented(_dispatch_body(fam))
                    for fam in AGENTS}

    def test_the_derivation_found_a_plausible_dispatcher(self):
        """Positive control. An empty or tiny set would make the assertion
        below pass while measuring nothing — which is the failure this class
        exists to catch, so it must not commit it itself."""
        self.assertGreaterEqual(len(self.impl['linux']), 12, self.impl['linux'])
        for fam in ('windows', 'darwin'):
            self.assertGreaterEqual(len(self.impl[fam]), 4, self.impl[fam])
        # And it must not be picking up the whole module: a scan of the entire
        # linux agent finds these, the dispatcher does not.
        for noise in ('fe80:', 'sha256:', 'pool:'):
            self.assertNotIn(noise, self.impl['linux'],
                             'the derivation escaped the dispatcher body')

    def test_every_platform_specific_verb_is_in_the_table(self):
        missing = []
        for verb in sorted(set().union(*self.impl.values())):
            fams = [f for f in AGENTS if verb in self.impl[f]]
            if len(fams) == len(AGENTS):
                continue                       # universal — the table skips it
            if verb in api._VERB_OS_SUPPORT:
                continue
            if verb.rstrip(':') in api._VERB_OS_SUPPORT:
                continue                       # 'upgrade:pkg' resolves via 'upgrade'
            missing.append(f'{verb!r} implemented on {fams} only')
        self.assertEqual(missing, [], '\n'.join([
            'verbs the agents disagree about that api._VERB_OS_SUPPORT does '
            'not describe. An absent verb is treated as universally supported, '
            'so each of these queues on a platform that cannot run it and '
            'reports success:', *missing]))


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
