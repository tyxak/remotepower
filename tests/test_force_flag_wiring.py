"""Structural guardrail for the "feature that can never fire" class.

An opt-in agent job is triggered by a one-shot `force_*` flag the SERVER sets in
the heartbeat response and the AGENT reads and acts on. Several features shipped
DEAD because the agent honoured a flag the server never set (trivy image scan,
and the v6.1.2 batch found more). This test enumerates every `force_*` flag the
agent reads and fails if the server never sets it — turning "did we wire both
ends?" into a build check instead of a bug hunt.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = [
    ROOT / "client" / "remotepower-agent.py",
    ROOT / "client" / "remotepower-agent-win.py",
    ROOT / "client" / "remotepower-agent-mac.py",
]
SERVER = ROOT / "server" / "cgi-bin" / "api.py"

# The agent READS a flag off the heartbeat response dict: resp.get('force_x') /
# response.get('force_x') / hb.get('force_x') …
_AGENT_READ = re.compile(r"""\.get\(\s*['"](force_[a-z_]+)['"]""")
# The server SETS it as a dict key (literal `'force_x': …` or `dev['force_x'] =`).
_SERVER_KEY = re.compile(r"""['"](force_[a-z_]+)['"]""")


def _agent_read_flags():
    flags = set()
    for p in AGENTS:
        try:
            flags |= set(_AGENT_READ.findall(p.read_text()))
        except FileNotFoundError:
            continue
    return flags


def _server_set_flags():
    return set(_SERVER_KEY.findall(SERVER.read_text()))


class TestForceFlagWiring(unittest.TestCase):
    def test_every_agent_force_flag_is_set_by_the_server(self):
        reads = _agent_read_flags()
        self.assertTrue(reads, "no force_* flags found in the agents — regex drift?")
        sets = _server_set_flags()
        dead = sorted(reads - sets)
        self.assertEqual(
            dead, [],
            "Agent reads these force_* flags but the SERVER never sets them — the "
            "feature can never fire (opt-in job with no trigger). Wire the server "
            "side, or stop reading the flag:\n  " + "\n  ".join(dead))

    def test_guardrail_actually_catches_a_dead_flag(self):
        # self-test: a fabricated agent-read with no server-set must be flagged.
        reads = _agent_read_flags() | {"force_nonexistent_zzz"}
        sets = _server_set_flags()
        self.assertIn("force_nonexistent_zzz", reads - sets)


if __name__ == "__main__":
    unittest.main()
