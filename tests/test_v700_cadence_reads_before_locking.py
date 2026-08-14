#!/usr/bin/env python3
"""A cadence gate must not take a write lock to discover it is not due.

Both metric exporters ran on every heartbeat with their feature enabled, and
each opened a WRITE LOCK on its state file — flock, read one integer, unlock —
purely to find out the interval had not elapsed. On a 100-device fleet polling
every 60 seconds that is ~100 lock acquisitions a minute spent deciding to do
nothing, on the request path.

The lock was there for a real reason: the slot has to be claimed atomically or
two concurrent heartbeats both push. That reason survives a cheap read in front
of it, because the comparison is REPEATED inside the lock — the read decides
whether to bother, the locked re-check is what actually keeps the claim atomic.
`refresh_kev_epss_if_due` has used that shape since v4.2.0.

CLAUDE.md states the rule: "a daily-sampler gate must run a cheap read BEFORE
`_LockedUpdate` — else it rewrites a cold blob + takes a write lock every
request". Three of the five cadence gates that lock already followed it. These
two did not, which is the half-applied shape again.

WHAT THIS PINS. Not "the code contains a `_load_ro` call" — that is satisfied by
a read anywhere in the function, including after the lock. It pins the ORDER: the
read-only read comes before the lock, and the locked re-check still exists. A fix
that removed the second comparison would be faster and would reintroduce the
double-push this lock exists to prevent.
"""
import ast
import unittest
from pathlib import Path

_API = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'

# The two gates this is about, and the state file each claims its slot in.
GATES = {
    '_maybe_export_otlp': 'OTLP_STATE_FILE',
    '_maybe_push_metrics': 'METRICS_PUSH_STATE_FILE',
}


def _fn_source(name):
    src = _API.read_text(encoding='utf-8')
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ''
    return ''


class TestTheGatesExist(unittest.TestCase):
    """Every assertion below is about text inside a function body. If the
    function is not found the body is '' and the ordering checks pass
    vacuously."""

    def test_both_functions_are_found(self):
        for name in GATES:
            body = _fn_source(name)
            self.assertGreater(len(body), 300,
                               f'{name} not found or trivially short')

    def test_a_known_good_gate_is_found_too(self):
        """The gate that has had this shape since v4.2.0, used as the control
        for the pattern itself."""
        body = _fn_source('refresh_kev_epss_if_due')
        self.assertIn('_config_ro()', body)
        self.assertLess(body.index('_config_ro()'), body.index('_LockedUpdate'))


class TestTheCheapReadComesFirst(unittest.TestCase):

    def test_the_read_only_read_precedes_the_lock(self):
        for name, store in GATES.items():
            with self.subTest(gate=name):
                body = _fn_source(name)
                self.assertIn('_load_ro(', body,
                              f'{name} has no read-only state read at all')
                ro = body.index('_load_ro(')
                lock = min(i for i in (body.find('_locked_update('),
                                       body.find('_LockedUpdate(')) if i != -1)
                self.assertLess(
                    ro, lock,
                    f'{name} takes its write lock on {store} before reading the '
                    f'state read-only, so every heartbeat pays a lock to decide '
                    f'it is not due')

    def test_the_locked_recheck_survives(self):
        """The read alone is not enough: without the comparison inside the lock,
        two concurrent heartbeats both claim the slot and both push.

        Checked as "the lock body can ABANDON the claim" — an `if` with a
        `return` or a guarded assignment — via the AST. A first version asserted
        the string `last_push` appeared inside the lock, and the fail-demo
        exposed it as worthless: deleting the whole re-check leaves
        `st['last_push'] = now` behind, which satisfies a substring search while
        being the exact bug.
        """
        src = _API.read_text(encoding='utf-8')
        tree = ast.parse(src)
        for name in GATES:
            with self.subTest(gate=name):
                fn = next((n for n in ast.walk(tree)
                           if isinstance(n, ast.FunctionDef) and n.name == name), None)
                self.assertIsNotNone(fn, name)
                withs = [n for n in ast.walk(fn) if isinstance(n, ast.With)]
                self.assertTrue(withs, f'{name} has no lock scope at all')
                guarded = False
                for w in withs:
                    for stmt in ast.walk(w):
                        # the claim must be conditional: an `if` whose body can
                        # leave the scope, or whose body holds the assignment
                        if isinstance(stmt, ast.If):
                            inner = ast.dump(stmt)
                            if 'Return' in inner or 'last_push' in inner:
                                guarded = True
                self.assertTrue(
                    guarded,
                    f"{name} claims the slot unconditionally inside its lock — "
                    f"the interval is no longer re-checked there, so two "
                    f"concurrent heartbeats can both push")

    def test_no_cadence_gate_reads_the_whole_config_before_its_due_check(self):
        """The sibling rule, checked over every cadence function rather than a
        named pair: reading CONFIG_FILE mutably deep-copies monitors,
        thresholds and integrations, and on the not-due path that is pure
        waste. `_config_ro()` exists for exactly this."""
        src = _API.read_text(encoding='utf-8')
        tree = ast.parse(src)
        bad = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not (node.name.startswith('run_') and node.name.endswith('_if_due')) \
                    and not node.name.startswith('_maybe_'):
                continue
            body = ast.get_source_segment(src, node) or ''
            i = body.find('load(CONFIG_FILE')
            if i == -1:
                continue
            head = body[:i]
            # A `return` before it means the expensive read is behind a gate.
            if 'return' not in head:
                bad.append(node.name)
        self.assertEqual(
            sorted(bad), [],
            'these cadence functions deep-copy the whole config before any '
            'early return, so every request pays for it even when the feature '
            'is off:\n' + '\n'.join('  ' + b for b in sorted(bad)))


if __name__ == '__main__':
    unittest.main()
