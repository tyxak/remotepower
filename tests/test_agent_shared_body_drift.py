#!/usr/bin/env python3
"""Functions that are the SAME code in two agents must stay the same code.

There are three agents — Linux, Windows, macOS — and a large amount of what
they do is not platform-specific at all: a Luhn checksum, a path allowlist, a
JSON state file, a redaction helper. Those bodies were copied, and nothing has
been holding them together since. A bug fixed in one is fixed in one.

That is the success-toast-then-silence class wearing a different hat. The
operator enables a feature, two of three platforms behave, and the third fails
in a way that produces no error anywhere — CLAUDE.md's `resp.get('<key>')`
parity greps exist for the heartbeat-flag version of exactly this.

WHY IT COMPARES SEMANTICS, NOT BYTES. A byte comparison fires on 16 pairs
today, and every one of them is a reworded docstring or a comment somebody
tightened on one side ("matches the server's exposure buckets so listeners
render like Linux ones" vs "…like Linux/Windows ones"). A gate whose first run
reports 16 findings of which 16 are noise gets switched off, and takes the real
ones with it. So comments and docstrings are stripped and the code is
round-tripped through `ast.unparse`, which also normalises formatting: what is
left is what the interpreter will actually do.

DELIBERATE DIVERGENCE IS EXPECTED AND IS NOT A FAILURE. 32 shared names already
differ for real reasons — the User-Agent string, macOS's `utun`/`awdl`
interfaces vs Windows's `isatap`/`teredo`, `credentials.json` vs `agent.json`,
`_eval_one_agent_check_mac` vs `_eval_one_agent_check_win`. Those are simply
absent from the lists below. If you need to diverge one that IS listed, delete
its name and say why in the commit — the point is that it becomes a decision
someone made rather than a copy that quietly rotted.

Two of the sixteen looked like real drift and were checked rather than assumed:
`compute_drift_report` catches `FileNotFoundError` separately on Windows and
only `OSError` on macOS (the first is a subclass of the second — identical
behaviour), and `_save_secrets_scan_ts` differs by a local variable. Neither is
a bug. The rule that produced that check is worth more than the result: a
divergence is evidence of nothing until you read both sides.
"""
import ast
import pathlib
import unittest

_CLIENT = pathlib.Path(__file__).resolve().parent.parent / 'client'
_AGENTS = {
    'linux': _CLIENT / 'remotepower-agent.py',
    'windows': _CLIENT / 'remotepower-agent-win.py',
    'macos': _CLIENT / 'remotepower-agent-mac.py',
}

# Identical in ALL THREE agents. Pure logic with no OS surface whatsoever.
SHARED_BY_ALL = (
    '_canary_status',
    '_luhn_ok',
    '_stable_hash',
    'redirect_request',
)

# Identical in the Windows and macOS agents. Both were written from the Linux
# agent at the same time and inherited the same helpers; Linux has since moved
# on in places for reasons that are genuinely Linux-shaped (procfs, systemd),
# which is why this pair is tracked separately rather than as a three-way.
SHARED_BY_WIN_MAC = (
    '_apply_sysinfo_delta',
    '_burst_live_samples',
    '_canary_path_ok',
    '_check_canaries',
    '_commit_sysinfo_delta',
    '_exec_timeout_override',
    '_file_log_state_path',
    '_fmt_uptime',
    '_load_file_log_state',
    '_load_pii_scan_ts',
    '_load_secrets_scan_ts',
    '_plant_canaries',
    '_port_scope',
    '_redact_secret',
    '_save_file_log_state',
    '_save_pii_scan_ts',
    '_spent',
    '_submit_file_logs',
    'collect_backup_status',
    'collect_file_log',
    'collect_listening_ports',
    'collect_pii_findings',
    'collect_secret_findings',
    'enroll',
)


def _normalise(node):
    """A function's source with comments, docstrings and formatting removed.

    `ast.unparse` re-emits from the tree, which drops comments and normalises
    layout; the docstring walk removes the one thing unparse preserves. What
    survives is what the interpreter will actually do.
    """
    clone = ast.parse(ast.unparse(node)).body[0]
    for sub in ast.walk(clone):
        if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef,
                                ast.ClassDef)):
            continue
        body = sub.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body.pop(0)
    return ast.unparse(clone)


def _semantic_bodies_from_text(text):
    """{name: normalised source} for every function in `text`."""
    return {n.name: _normalise(n)
            for n in ast.walk(ast.parse(text))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _semantic_bodies(path):
    return _semantic_bodies_from_text(path.read_text(encoding='utf-8'))


class TestAgentSharedBodiesDoNotDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fns = {k: _semantic_bodies(v) for k, v in _AGENTS.items()}

    def _assert_same(self, names, agents):
        missing, drifted = [], []
        base = agents[0]
        for name in names:
            for other in agents[1:]:
                if name not in self.fns[base] or name not in self.fns[other]:
                    missing.append(f'{name}: absent from '
                                   f'{base if name not in self.fns[base] else other}')
                    continue
                if self.fns[base][name] != self.fns[other][name]:
                    drifted.append(f'{name}: {base} and {other} differ')
        self.assertEqual(missing, [], '\n'.join([
            'a tracked shared function no longer exists in one agent:', *missing,
            '', 'If it was renamed, rename it in both. If it was deliberately '
            'dropped from one platform, remove the name from this list.']))
        self.assertEqual(drifted, [], '\n'.join([
            'these functions are meant to be the same code in both agents and '
            'are no longer:', *drifted,
            '',
            'Either apply the change to both agents, or — if the difference is '
            'a real platform requirement — delete the name from the list in '
            f'{pathlib.Path(__file__).name} and say why in the commit message. '
            'What must not happen is a fix landing on one platform and being '
            'reported to the operator as if it landed on all of them.']))

    def test_functions_shared_by_all_three_agents(self):
        self._assert_same(SHARED_BY_ALL, ['linux', 'windows', 'macos'])

    def test_functions_shared_by_the_windows_and_macos_agents(self):
        self._assert_same(SHARED_BY_WIN_MAC, ['windows', 'macos'])

    def test_the_comparison_ignores_comments_and_docstrings(self):
        """The reason this gate is usable at all. Prove the normalisation
        actually collapses a reworded comment, or the lists above would have to
        carry 16 exclusions that mean nothing."""
        a = _semantic_bodies_from_text(
            'def f(x):\n'
            '    """One wording."""\n'
            '    # a note\n'
            '    return x + 1\n')
        b = _semantic_bodies_from_text(
            'def f(x):\n'
            '    """A different wording entirely."""\n'
            '    return x + 1\n')
        self.assertEqual(a['f'], b['f'])

    def test_the_comparison_still_sees_a_real_change(self):
        """Guard the guard. Normalisation that collapsed everything would make
        every test above pass forever while measuring nothing — which is the
        failure this release is named after."""
        a = _semantic_bodies_from_text('def f(x):\n    return x + 1\n')
        b = _semantic_bodies_from_text('def f(x):\n    return x + 2\n')
        self.assertNotEqual(a['f'], b['f'])

    def test_the_tracked_lists_are_not_silently_empty(self):
        self.assertGreaterEqual(len(SHARED_BY_ALL), 4)
        self.assertGreaterEqual(len(SHARED_BY_WIN_MAC), 20)
        self.assertEqual(sorted(SHARED_BY_ALL), list(SHARED_BY_ALL))
        self.assertEqual(sorted(SHARED_BY_WIN_MAC), list(SHARED_BY_WIN_MAC))


if __name__ == '__main__':
    unittest.main()
