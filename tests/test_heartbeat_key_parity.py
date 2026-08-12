#!/usr/bin/env python3
"""The inverse of test_force_flag_wiring: a key the SERVER sends that no agent reads.

test_force_flag_wiring catches a flag the AGENT honours that the server never
sets — an opt-in job with no trigger. This is the other direction, and it is the
one that produces the worse symptom: the server accepts the action, returns 200,
the UI shows a green toast, and the target silently drops the key. The v6.4.0
audit found the macOS and Windows agents ignoring ~17 Linux-only heartbeat flags
exactly this way.

The fix for a genuinely Linux-only feature is not to make it universal — oscap
and lynis do not exist on Windows. It is to make the omission DECLARED, so a key
that was forgotten looks different from one that was excluded on purpose. Both
non-Linux agents carry `HEARTBEAT_KEYS_NOT_HONOURED`, next to the prose
docstring that explains each entry.

Why the list lives in the AGENTS and not in this file: a table maintained only
in a test is a second registry, and every recurring bug in this project's notes
is two registries drifting apart (FLEET_EVENTS vs the server set, DASH_WIDGETS
vs DASHBOARD_WIDGETS, the scheduler CADENCE tuple vs main()). Here the
declaration is the thing the agent author edits, and the test reads it.

Enforced in BOTH directions, because a declaration that is never checked for
staleness rots into a permanent exemption:
  - a server key an agent neither reads nor declares      -> fail (the bug)
  - a declared key the agent actually reads               -> fail (stale)
  - a declared key the server no longer sends             -> fail (stale)
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / 'server' / 'cgi-bin' / 'api.py'
AGENTS = {
    'linux': ROOT / 'client' / 'remotepower-agent.py',
    'windows': ROOT / 'client' / 'remotepower-agent-win.py',
    'macos': ROOT / 'client' / 'remotepower-agent-mac.py',
}


def _heartbeat_response_keys():
    """Every key handle_heartbeat puts into the response dict the agent sees."""
    src = API.read_text()
    tree = ast.parse(src)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == 'handle_heartbeat')
    body = '\n'.join(src.splitlines()[fn.lineno - 1:fn.end_lineno])
    keys = set(re.findall(r"common_resp\[['\"]([a-z_0-9]+)['\"]\]\s*=", body))
    m = re.search(r"common_resp\s*=\s*\{(.*?)\n\s{4}\}", body, re.S)
    if m:
        keys |= set(re.findall(r"['\"]([a-z_0-9]+)['\"]\s*:", m.group(1)))
    # Transport/bookkeeping keys every agent handles structurally rather than
    # by name lookup.
    return keys - {'ok', 'command', 'command_sig'}


def _declared_not_honoured(path):
    """HEARTBEAT_KEYS_NOT_HONOURED, read from the agent source without importing
    it (the agents are scripts with side effects at import)."""
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == 'HEARTBEAT_KEYS_NOT_HONOURED':
                    return set(ast.literal_eval(node.value))
    return set()


def _reads(path, key):
    """Does this agent actually consume the key?

    BOTH access shapes, because they are both in live use and matching only one
    manufactures findings: the Linux agent reads `resp['backup_monitors']` as a
    subscript while everything else uses `.get(...)`. A first cut of this test
    checked `.get(` alone and reported that key as silently dropped on the
    reference agent, which was wrong — the instrument was too narrow, not the
    code. Deliberately NOT a bare substring search: the Windows and macOS
    docstrings name every exempt key in backticks, so a plain `'key' in src`
    would count the declaration itself as a read and the gate would pass on
    exactly the agents it exists to check.
    """
    src = path.read_text()
    k = re.escape(key)
    return bool(re.search(r"\.get\(\s*['\"]%s['\"]" % k, src)
                or re.search(r"\w\[\s*['\"]%s['\"]\s*\]" % k, src))


class TestEveryServerKeyIsReadOrDeclared(unittest.TestCase):
    def setUp(self):
        self.keys = _heartbeat_response_keys()

    def test_the_extraction_found_the_response(self):
        """Positive control. If the regex drifts off `common_resp`, every
        assertion below passes over an empty set and this file becomes a
        30-line no-op that reports success."""
        self.assertGreater(len(self.keys), 25,
                           'heartbeat response key extraction found almost '
                           'nothing — has the response dict been renamed?')
        for expect in ('agent_checks', 'force_package_scan', 'live_until'):
            self.assertIn(expect, self.keys)

    def test_every_key_is_read_or_declared_by_every_agent(self):
        """The load-bearing assertion. A new heartbeat key that Windows and
        macOS silently drop is a 200 + success toast + nothing happening."""
        problems = []
        for name, path in AGENTS.items():
            declared = _declared_not_honoured(path)
            for k in sorted(self.keys):
                if not _reads(path, k) and k not in declared:
                    problems.append(f'{name}: {k}')
        self.assertEqual(
            problems, [],
            'The server sends these heartbeat keys and the agent neither reads '
            'nor declares them. Either honour the key in that agent, or — if '
            'the feature genuinely cannot exist there — add it to that agent\'s '
            'HEARTBEAT_KEYS_NOT_HONOURED with a reason, and gate it server-side '
            'so the operator is told rather than getting a success toast for a '
            'no-op:\n  ' + '\n  '.join(problems))

    def test_the_linux_agent_declares_nothing(self):
        """Linux is the reference implementation. If it ever needs an exemption,
        the feature belongs somewhere other than the heartbeat."""
        self.assertEqual(_declared_not_honoured(AGENTS['linux']), set())


class TestTheDeclarationsAreNotStale(unittest.TestCase):
    """An exemption nobody re-checks becomes permanent. Both directions."""

    def setUp(self):
        self.keys = _heartbeat_response_keys()

    def test_no_agent_declares_a_key_it_actually_reads(self):
        stale = []
        for name, path in AGENTS.items():
            for k in sorted(_declared_not_honoured(path)):
                if _reads(path, k):
                    stale.append(f'{name}: {k} is declared unread but IS read')
        self.assertEqual(stale, [], '\n  '.join(stale))

    def test_no_agent_declares_a_key_the_server_no_longer_sends(self):
        stale = []
        for name, path in AGENTS.items():
            for k in sorted(_declared_not_honoured(path) - self.keys):
                stale.append(f'{name}: {k} is declared but the server never sends it')
        self.assertEqual(stale, [], '\n  '.join(stale))

    def test_the_prose_and_the_tuple_agree(self):
        """The docstring is what a human reads; the tuple is what the build
        reads. A key in one and not the other is how this drifts back into
        prose nobody trusts."""
        for name in ('windows', 'macos'):
            path = AGENTS[name]
            doc = ast.get_docstring(ast.parse(path.read_text())) or ''
            for k in sorted(_declared_not_honoured(path)):
                # scap_profile rides with force_scap_scan; du_scan_paths with du_scan_*
                stem = k.replace('force_', '').replace('_enabled', '').replace('_paths', '')
                with self.subTest(agent=name, key=k):
                    self.assertTrue(
                        k in doc or stem in doc,
                        f'{name}: {k} is in HEARTBEAT_KEYS_NOT_HONOURED but the '
                        f'docstring never mentions it — a reader is told the '
                        f'agent honours something it does not')


class TestItCatchesTheRealBug(unittest.TestCase):
    """Positive controls: prove each direction fires, so a green run means the
    instrument works rather than that it looked away."""

    def test_an_undeclared_unread_key_is_caught(self):
        keys = _heartbeat_response_keys() | {'force_teleport_zzz'}
        path = AGENTS['windows']
        declared = _declared_not_honoured(path)
        missing = [k for k in keys if not _reads(path, k) and k not in declared]
        self.assertIn('force_teleport_zzz', missing)

    def test_a_stale_declaration_is_caught(self):
        """A declared key the server stopped sending."""
        keys = _heartbeat_response_keys()
        self.assertIn('mdns_enabled', _declared_not_honoured(AGENTS['windows']))
        self.assertEqual(sorted({'mdns_enabled_gone_zzz'} - keys),
                         ['mdns_enabled_gone_zzz'])


if __name__ == '__main__':
    unittest.main()
