#!/usr/bin/env python3
"""A field the agent sends that `safe_si` does not name is dropped in silence.

CLAUDE.md states the trap plainly: "a field the agent sends but safe_si drops
silently never reaches the server-side check or the UI". It has produced dead
signals repeatedly — proc_names, mailq, last_oom_proc, hostname, psutil. Each
time the fix was a whitelist line, and each time nothing stopped the next one.

This is that gate. It enumerates the keys each agent puts into its sysinfo
payload and fails on any that safe_si does not persist and no agent declares as
deliberately local.

THE EXTRACTION IS THE HARD PART, and three earlier attempts at this analysis
were wrong before this one was right — which is the reason for the narrowness
below rather than a broader sweep:

  - matching `sysinfo[...] =` alone found 33 keys on Linux and ZERO on the other
    two agents, which build the dict inside collect_sysinfo() under a different
    variable name;
  - widening to any dict named `si` or `out` found 94 on Linux, because those
    are ordinary local names all over a 12,000-line file;
  - a third pass reported three keys as dropped that were nested fields of a
    disk entry, never top-level sysinfo keys at all.

An instrument that over-reports is worse than none here: a gate with false
positives gets switched off, and takes the true findings with it. So the
extraction is anchored on the two shapes that actually flow into the heartbeat —
the Linux agent's `sysinfo = {...}` literal plus its explicit `sysinfo[k] =`
stores, and the dict collect_sysinfo() returns on Windows and macOS — and the
test asserts the extraction found a plausible number before trusting it.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
AGENTS = {
    'linux': _ROOT / 'client' / 'remotepower-agent.py',
    'windows': _ROOT / 'client' / 'remotepower-agent-win.py',
    'macos': _ROOT / 'client' / 'remotepower-agent-mac.py',
}

# Keys an agent computes into its payload for its OWN use, or which the server
# reads from somewhere other than the persisted sysinfo. Each needs a reason.
# EMPTY, and that is the finding: every field all three agents put into sysinfo
# today is persisted by safe_si. The dict exists so the next exemption has to be
# written down with a reason rather than absorbed silently.
#
# It started with three entries — delta / delta_keys / delta_base — which I
# added on the assumption they were agent-local. test_the_exemptions_are_not_stale
# rejected all three: they live on the payload, not inside sysinfo, so no agent
# sends them here and exempting them was inventing debt. The staleness check
# earning its place on its first run is the reason it is in the file.
DELIBERATELY_NOT_PERSISTED = {}


def _linux_keys():
    """`sysinfo = {...}` plus every `sysinfo['k'] =` store."""
    tree = ast.parse(AGENTS['linux'].read_text())
    keys = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id == 'sysinfo' and isinstance(n.value, ast.Dict):
                    keys |= {k.value for k in n.value.keys
                             if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                        and t.value.id == 'sysinfo'
                        and isinstance(t.slice, ast.Constant)
                        and isinstance(t.slice.value, str)):
                    keys.add(t.slice.value)
    return keys


def _collect_sysinfo_keys(path):
    """The dict collect_sysinfo() builds and returns, plus later stores into it."""
    tree = ast.parse(path.read_text())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == 'collect_sysinfo'), None)
    if fn is None:
        return set()
    ret = next((n.value.id for n in ast.walk(fn)
                if isinstance(n, ast.Return) and isinstance(n.value, ast.Name)), None)
    keys = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if (isinstance(t, ast.Name) and t.id == ret
                        and isinstance(n.value, ast.Dict)):
                    keys |= {k.value for k in n.value.keys
                             if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                        and t.value.id == ret and isinstance(t.slice, ast.Constant)
                        and isinstance(t.slice.value, str)):
                    keys.add(t.slice.value)
    return keys


def _agent_keys():
    return {
        'linux': _linux_keys(),
        'windows': _collect_sysinfo_keys(AGENTS['windows']),
        'macos': _collect_sysinfo_keys(AGENTS['macos']),
    }


def _safe_si_persisted():
    """Keys safe_si writes — it is a local dict inside handle_heartbeat, not a
    function, so this reads the handler body."""
    hb = re.search(r'def handle_heartbeat\(.*?\n(?=def |class )', _API, re.S).group(0)
    keys = set(re.findall(r"safe_si\[['\"]([a-z_0-9]+)['\"]\]\s*=", hb))
    # the copy-through loops: `for _k in ('a', 'b', ...)`
    for m in re.finditer(r"for \w+ in \(([^)]*)\):", hb):
        keys |= set(re.findall(r"['\"]([a-z_0-9]+)['\"]", m.group(1)))
    return keys


class TestEveryCollectedFieldSurvives(unittest.TestCase):
    def setUp(self):
        self.agent = _agent_keys()
        self.persisted = _safe_si_persisted()

    def test_the_extraction_is_plausible(self):
        """Positive control, and the one that would have caught all three of
        the earlier broken instruments: each agent must yield a believable
        count, and the whitelist must be bigger than any single agent."""
        for name, keys in self.agent.items():
            with self.subTest(agent=name):
                self.assertGreaterEqual(len(keys), 4,
                                        f'{name}: extraction found almost nothing')
                self.assertLess(len(keys), 90,
                                f'{name}: extraction is over-matching — it is '
                                'picking up local dicts that never reach the '
                                'heartbeat')
        self.assertGreater(len(self.persisted), 30)

    def test_the_extraction_finds_known_fields(self):
        """Anchor it to fields that certainly exist, so a silently-empty result
        cannot masquerade as a clean run."""
        self.assertIn('hostname', self.agent['linux'])
        self.assertIn('uptime', self.agent['linux'])
        for expect in ('hostname', 'kernel', 'cpu'):
            self.assertIn(expect, self.persisted)

    def test_no_collected_field_is_silently_dropped(self):
        """The load-bearing assertion. A field an agent sends that safe_si does
        not name never reaches a check, a page or an alert — and nothing about
        the code reads as broken."""
        problems = []
        for name, keys in self.agent.items():
            for k in sorted(keys):
                if k not in self.persisted and k not in DELIBERATELY_NOT_PERSISTED:
                    problems.append(f'{name}: {k}')
        self.assertEqual(problems, [], '\n'.join([
            'These fields are collected by an agent and dropped by safe_si, so '
            'every consumer behaves as though the agent never sent them:',
            *('  ' + p for p in problems),
            '',
            'Add the key to safe_si in handle_heartbeat, or — if the agent '
            'computes it for its own use and it is not meant to be stored — '
            'record it in DELIBERATELY_NOT_PERSISTED with the reason.']))

    def test_the_exemptions_are_not_stale(self):
        """An exemption for a field no agent sends any more is a line nobody
        can act on, and a real one hides among them."""
        every = set().union(*self.agent.values())
        stale = sorted(k for k in DELIBERATELY_NOT_PERSISTED if k not in every)
        self.assertEqual(stale, [], f'no agent sends these any more: {stale}')

    def test_an_exemption_never_shadows_a_persisted_key(self):
        """If safe_si persists it, the exemption is wrong and misleading."""
        both = sorted(k for k in DELIBERATELY_NOT_PERSISTED if k in self.persisted)
        self.assertEqual(both, [], f'declared unpersisted but safe_si stores: {both}')


if __name__ == '__main__':
    unittest.main()
