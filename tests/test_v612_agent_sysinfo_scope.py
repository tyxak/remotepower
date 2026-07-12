"""Guardrail for a real bug found in the v6.1.2 bug hunt.

The agent's ECC / zram / auto-update / SSH-host-key collectors were written to
`sysinfo[...]` from a block that ran BEFORE `sysinfo` was assigned later in the same
function. Python makes `sysinfo` a local throughout `heartbeat()`, so each write
raised UnboundLocalError — which the surrounding `try/except Exception` swallowed at
debug level. Net effect: those four host signals were NEVER sent (dead since batch A,
d2d57eb), and the hostkey_changed MITM tripwire could never fire.

This pins the invariant directly on the source: inside `heartbeat()`, no `sysinfo[k]`
subscript-STORE may textually precede the `sysinfo = {...}` assignment. It's an
AST/line-order check because `heartbeat()` is the live poll loop, not unit-drivable.
"""
import ast
import unittest
from pathlib import Path

AGENT = Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py'


def _heartbeat_fn(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'heartbeat':
            return node
    return None


class TestAgentSysinfoScope(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(AGENT.read_text())
        self.hb = _heartbeat_fn(self.tree)
        self.assertIsNotNone(self.hb, "heartbeat() not found in the agent")

    def _first_assign_line(self, name):
        """First line where `name = ...` (a plain Name target) happens in heartbeat."""
        best = None
        for node in ast.walk(self.hb):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == name:
                        best = node.lineno if best is None else min(best, node.lineno)
        return best

    def _subscript_store_lines(self, name):
        """Lines where `name[...] = ...` (a subscript STORE) happens in heartbeat."""
        out = []
        for node in ast.walk(self.hb):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if (isinstance(t, ast.Subscript)
                            and isinstance(t.value, ast.Name)
                            and t.value.id == name):
                        out.append(node.lineno)
        return sorted(out)

    def test_sysinfo_is_never_written_before_it_is_assigned(self):
        assign = self._first_assign_line('sysinfo')
        self.assertIsNotNone(assign, "heartbeat() must build a `sysinfo` dict")
        early = [ln for ln in self._subscript_store_lines('sysinfo') if ln < assign]
        self.assertEqual(
            early, [],
            "sysinfo[...] is written at line(s) "
            f"{early} BEFORE `sysinfo = {{...}}` at line {assign} — an "
            "UnboundLocalError swallowed by try/except, so those fields are "
            "silently never sent (the batch-A/hostkey scope bug).")

    def test_the_four_signals_are_actually_stored_into_sysinfo(self):
        """The positive assertion: the fix must leave the four fields being written
        to sysinfo somewhere (not merely removed)."""
        src = AGENT.read_text()
        for key in ('ecc', 'zram', 'autoupdate', 'ssh_hostkeys'):
            self.assertIn(f"sysinfo['{key}']", src,
                          f"agent no longer stores sysinfo['{key}'] at all")


if __name__ == '__main__':
    unittest.main()
