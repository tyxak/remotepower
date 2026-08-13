#!/usr/bin/env python3
"""require-signed-commands must cover every channel that runs code, not just one.

The flag is opt-in and fail-closed, and it exists for exactly one threat: a
server or database an attacker now controls. It gated `resp['command']` and
nothing else — while two other channels in the same heartbeat response run code
with the agent's privileges:

  * `custom_scripts` — server-supplied bash, executed AS ROOT. The function's own
    docstring says so.
  * `host_config_desired` — writes system files and calls systemctl as root. Its
    docstring said it shares "the same trust boundary as the existing exec:
    command channel", which was true when written and stopped being true in
    v6.3.1, when that channel gained a signature gate this one never got.

So an attacker who could not push a command could push a script instead, and the
control had a hole the width of the thing it was protecting.

WHY REFUSAL RATHER THAN SIGNATURES. The signature format binds one command
string ('rp-cmd\\nv1\\n{dev_id}\\n{ts}\\n{cmd}') and the server produces it by
shelling out to gpg. That is affordable for a dispatched command, which is rare,
and not affordable for these payloads, which ride EVERY heartbeat for every
device. Extending signing to them needs sign-on-change with a cached signature —
a protocol change, recorded as follow-up rather than half-built here. Until then
the agent refuses them, loudly, because honouring unsigned arbitrary root code
from a server you have just declared untrusted is incoherent.

`host_config_desired` is checked on Linux only, and that is not an oversight:
HEARTBEAT_KEYS_NOT_HONOURED in both the Windows and macOS agents lists it as
deliberately unimplemented there. This test reads that registry rather than
assuming, so if either agent ever starts honouring it the requirement applies
automatically.

WHAT THIS FILE DOES NOT PROVE, stated because a source test that reads as
stronger than it is becomes the next false green. These assertions check that
the gate is CALLED in the region that ingests each payload — not that it is
EFFECTIVE. Demonstrating the failure showed exactly that limit: neutralising the
condition to `if False and _require_signed_commands():` left every assertion
here green, because the name was still present. Only deleting the block turned
it red.

That is an accepted trade rather than an unnoticed hole. The alternative is
driving a full heartbeat against a live agent with a signing key, which these
agents are not structured for, and the runtime behaviour of the gate itself is
already covered where the command channel is tested. The value here is that the
call cannot QUIETLY DISAPPEAR from a channel, or be missed on a new agent — the
way it was missed on these two for an entire release.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_AGENTS = {
    'linux': _ROOT / 'client' / 'remotepower-agent.py',
    'win': _ROOT / 'client' / 'remotepower-agent-win.py',
    'mac': _ROOT / 'client' / 'remotepower-agent-mac.py',
}
# Each agent names its own gate, and its own heartbeat function.
_GATE = {
    'linux': '_require_signed_commands',
    'win': '_require_signed_commands_win',
    'mac': '_require_signed_commands_mac',
}
_HEARTBEAT = {'linux': 'heartbeat', 'win': 'heartbeat_once', 'mac': 'heartbeat_once'}

sys.path.insert(0, str(Path(__file__).resolve().parent))
from srcpin import py_function  # noqa: E402


def _src(which):
    return _AGENTS[which].read_text()


def _not_honoured(which):
    """The agent's own HEARTBEAT_KEYS_NOT_HONOURED registry, parsed not guessed."""
    src = _src(which)
    m = re.search(r'HEARTBEAT_KEYS_NOT_HONOURED\s*=\s*\(', src)
    if not m:
        return set()
    start = m.end() - 1
    depth, i = 0, start
    while i < len(src):
        if src[i] == '(':
            depth += 1
        elif src[i] == ')':
            depth -= 1
            if depth == 0:
                break
        i += 1
    return set(re.findall(r"'([a-z_]+)'", src[start:i + 1]))


class TestEveryCodeChannelIsGated(unittest.TestCase):

    def test_all_three_agents_parse(self):
        """Positive control for every source assertion below."""
        for which, path in _AGENTS.items():
            ast.parse(path.read_text())

    def test_custom_scripts_is_gated_on_every_agent(self):
        for which in _AGENTS:
            src = _src(which)
            self.assertIn('custom_scripts', src, which)
            gate = _GATE[which]
            # The heartbeat function itself, bounded by indentation rather than
            # a guessed character count. A fixed [i:i+N] window is a guess about
            # how long the surrounding code is and silently stops covering its
            # target when that code grows — which is why this repo's ratchet
            # forbids them, and it caught this file doing exactly that.
            window = py_function(src, _HEARTBEAT[which])
            self.assertIn("resp.get('custom_scripts')", window, which)
            self.assertIn(f'{gate}()', window,
                          f'{which}: custom_scripts is accepted without '
                          f'consulting {gate}() — server-supplied code runs '
                          'while require-signed-commands is set')

    def test_host_config_is_gated_wherever_it_is_honoured(self):
        for which in _AGENTS:
            if 'host_config_desired' in _not_honoured(which):
                continue        # deliberately unimplemented on this platform
            src = _src(which)
            window = py_function(src, _HEARTBEAT[which])
            self.assertIn("resp.get('host_config_desired')", window, which)
            self.assertIn(f'{_GATE[which]}()', window,
                          f'{which}: host_config_desired is applied without '
                          f'consulting {_GATE[which]}() — it writes system '
                          'files and calls systemctl as root')

    def test_the_not_honoured_registry_is_readable(self):
        """If this parse silently returned an empty set, the test above would
        skip nothing and quietly demand a gate that cannot exist — or, worse,
        pass for the wrong reason."""
        for which in ('win', 'mac'):
            keys = _not_honoured(which)
            self.assertGreater(len(keys), 5,
                               f'{which}: HEARTBEAT_KEYS_NOT_HONOURED did not '
                               'parse — the exemption logic is unreliable')
            self.assertIn('host_config_desired', keys, which)

    def test_the_refusal_is_reported_not_silent(self):
        """A silent drop is the failure mode this project keeps fixing: the
        operator must be told why nothing ran."""
        for which in _AGENTS:
            src = _src(which)
            self.assertIn('REFUSED', src,
                          f'{which}: no refusal is logged, so a blocked script '
                          'would look identical to no script being assigned')

    def test_the_refusal_is_logged_once_not_every_poll(self):
        """A per-heartbeat error line buries the journal and trains the operator
        to ignore it."""
        for which in _AGENTS:
            self.assertIn('_warned_unsigned_scripts', _src(which), which)


class TestTheExtensionlessTwinStaysInSync(unittest.TestCase):
    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        b = (_ROOT / 'client' / 'remotepower-agent').read_bytes()
        self.assertEqual(a, b, 'the extensionless agent drifted from the .py')


if __name__ == '__main__':
    unittest.main()
