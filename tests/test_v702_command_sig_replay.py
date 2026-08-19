#!/usr/bin/env python3
"""A signed command could be replayed for fifteen minutes.

`require-signed-commands` makes an agent refuse any command without a valid
detached signature binding the command text to that device and an issue
timestamp. The header comment on that feature said replaying a captured command
"to another host / at a later time no longer executes anything". The first half
was true. The second was true only past the 900-second freshness window — inside
it, the same signature verified every time it arrived, so a captured or
re-queued command ran again on every poll for fifteen minutes. Ten identical
reboots is a different event from one.

The agents now remember what they have accepted. The server signs fresh on each
dispatch with a new timestamp, so a legitimate re-issue has a different digest
and is unaffected — which is the control this file spends most of its
assertions on, because a replay guard that also blocks real commands is worse
than the gap it closes.
"""
import ast
import hashlib
import sys
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CLIENT = _ROOT / 'client'
sys.path.insert(0, str(Path(__file__).parent))
import srcpin  # noqa: E402

_AGENTS = (
    ('remotepower-agent.py', '_cmd_sig_replayed', 'CMD_SIG_MAX_AGE_S'),
    ('remotepower-agent-mac.py', '_cmd_sig_replayed_mac', '_CMD_SIG_MAX_AGE_S'),
    ('remotepower-agent-win.py', '_cmd_sig_replayed_win', '_CMD_SIG_MAX_AGE_S'),
)


def _lift(agent_file, fn_name, const_name):
    """The real replay function out of an agent, with a stub namespace."""
    src = (_CLIENT / agent_file).read_text()
    ns = {'time': time, 'hashlib': hashlib}
    tree = ast.parse(src)
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], 'id', '') in (const_name,)):
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
        if isinstance(node, ast.Assign) and getattr(
                node.targets[0], 'id', '').startswith('_CMD_SIG_SEEN'):
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
    assert const_name in ns, f'{agent_file}: {const_name} not found'
    seen = next(v for k, v in ns.items() if k.startswith('_CMD_SIG_SEEN'))
    return ns[fn_name], ns[const_name], seen


class TestTheSameSignatureIsAcceptedOnce(unittest.TestCase):

    def test_a_second_delivery_is_refused(self):
        for agent, fn_name, const in _AGENTS:
            fn, _max, _seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            self.assertFalse(fn('d1', now, 'reboot', now), agent)
            self.assertTrue(fn('d1', now, 'reboot', now), agent)
            self.assertTrue(fn('d1', now, 'reboot', now + 60), agent)

    def test_a_fresh_dispatch_of_the_same_command_still_runs(self):
        """The control that matters. The server re-signs with a new timestamp
        on every dispatch, so "reboot twice" is a real thing an operator can
        ask for and must keep working."""
        for agent, fn_name, const in _AGENTS:
            fn, _max, _seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            self.assertFalse(fn('d1', now, 'reboot', now), agent)
            self.assertFalse(fn('d1', now + 1, 'reboot', now + 1), agent)
            self.assertFalse(fn('d1', now + 2, 'reboot', now + 2), agent)

    def test_the_same_timestamp_on_another_device_is_not_a_replay(self):
        for agent, fn_name, const in _AGENTS:
            fn, _max, _seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            self.assertFalse(fn('d1', now, 'reboot', now), agent)
            self.assertFalse(fn('d2', now, 'reboot', now), agent)

    def test_a_different_command_at_the_same_instant_is_not_a_replay(self):
        for agent, fn_name, const in _AGENTS:
            fn, _max, _seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            self.assertFalse(fn('d1', now, 'reboot', now), agent)
            self.assertFalse(fn('d1', now, 'upgrade', now), agent)

    def test_memory_is_dropped_once_the_signature_could_not_verify_anyway(self):
        """Past twice the freshness window the timestamp check refuses it on
        its own, so holding the digest buys nothing and would grow forever."""
        for agent, fn_name, const in _AGENTS:
            fn, maxage, _seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            self.assertFalse(fn('d1', now, 'reboot', now), agent)
            self.assertFalse(fn('d1', now, 'reboot', now + maxage * 2 + 1), agent)

    def test_it_does_not_grow_without_bound(self):
        """An agent runs for months. Measured on the dict itself, not on the
        cap written in the source — a trim that never fires reads identically."""
        for agent, fn_name, const in _AGENTS:
            fn, _max, seen = _lift(agent, fn_name, const)
            now = 1_700_000_000
            for i in range(5000):
                fn('d1', now + i, f'cmd-{i}', now)
            self.assertGreater(len(seen), 0, agent)
            self.assertLessEqual(len(seen), 512, f'{agent}: {len(seen)} entries')


class TestEveryVerifierConsultsIt(unittest.TestCase):

    def test_the_replay_check_is_in_the_signature_path(self):
        for agent, fn_name, _const in _AGENTS:
            verifier = {'remotepower-agent.py': '_command_sig_ok',
                        'remotepower-agent-mac.py': '_command_sig_ok_mac',
                        'remotepower-agent-win.py': '_command_sig_ok_win'}[agent]
            body = srcpin.py_function((_CLIENT / agent).read_text(), verifier)
            code = '\n'.join(ln for ln in body.splitlines()
                             if not ln.lstrip().startswith('#'))
            self.assertIn(fn_name + '(', code, agent)

    def test_it_runs_after_the_signature_verifies_not_before(self):
        """Order is load-bearing: recording a digest for a signature that did
        not verify would let an attacker burn a legitimate command by sending a
        forgery with its timestamp first."""
        for agent, fn_name, _const in _AGENTS:
            verifier = {'remotepower-agent.py': '_command_sig_ok',
                        'remotepower-agent-mac.py': '_command_sig_ok_mac',
                        'remotepower-agent-win.py': '_command_sig_ok_win'}[agent]
            body = srcpin.py_function((_CLIENT / agent).read_text(), verifier)
            self.assertLess(body.index('_verify_detached_sig'),
                            body.index(fn_name + '('), agent)
            self.assertIn('if not _ok:', body, agent)


class TestTheServerSignsFreshEachTime(unittest.TestCase):
    """If the server ever cached a signature alongside a queued command, the
    replay guard would start refusing legitimate re-deliveries."""

    def test_the_signature_is_produced_at_dispatch(self):
        src = (_ROOT / 'server/cgi-bin/api.py').read_text()
        self.assertIn('_cmd_sig, _cmd_sig_ts = _sign_command_for_agent('
                      'dev_id, dispatch_cmd)', src)

    def test_the_timestamp_is_taken_at_signing_time(self):
        body = srcpin.py_function((_ROOT / 'server/cgi-bin/api.py').read_text(),
                                  '_sign_command_for_agent')
        self.assertIn('ts = int(time.time())', body)


if __name__ == '__main__':
    unittest.main()
