#!/usr/bin/env python3
"""One operator-authored regex could stop an agent reporting, permanently.

The `file_contains` check compiles a regex from the check definition and runs it
over every matching file in a subtree. Python's `re` has no timeout, and a
pattern with nested quantifiers — `(a+)+$` and its relatives — backtracks for
effectively forever against a 256 KB file.

That runs on the agent's single poll loop. So the host stops beating: it goes
silent, shows offline, collects no commands, and no amount of restarting the
server fixes it, because the pattern is re-fetched with the next heartbeat that
never comes. The existing 2000-file and 50-hit caps do not help — the blow-up is
inside ONE call.

A deadline cannot interrupt a running `re.search`; Python offers no mechanism.
So the budget is checked before each file. That bounds the many-files case
outright, and caps a pathological file at one search rather than one per file in
the tree — the difference between a check that is slow once and an agent that
never reports again.
"""
import importlib.util
import re
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_AGENT = _ROOT / 'client' / 'remotepower-agent.py'


def _load():
    spec = importlib.util.spec_from_loader(
        'rp_agent_regex_budget',
        importlib.machinery.SourceFileLoader('rp_agent_regex_budget',
                                             str(_AGENT)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestTheBudgetExists(unittest.TestCase):

    def setUp(self):
        self.m = _load()

    def test_it_is_declared(self):
        self.assertGreater(self.m.FILE_CONTAINS_BUDGET_S, 0)

    def test_it_is_well_under_the_poll_interval(self):
        """A budget at or above POLL_INTERVAL still stalls every beat. It has to
        cost one slow beat, not all of them."""
        self.assertLess(self.m.FILE_CONTAINS_BUDGET_S, self.m.POLL_INTERVAL)

    def test_it_is_generous_enough_for_an_honest_scan(self):
        """A budget a real subtree scan trips is a broken check, not a fix."""
        self.assertGreaterEqual(self.m.FILE_CONTAINS_BUDGET_S, 10)

    def test_the_check_is_the_one_that_takes_a_pattern(self):
        """Premise: if file_contains stops compiling an operator regex, this
        whole file is about nothing."""
        # Bounded by the NEXT check's branch, not a character count — the
        # file_contains body grows and a fixed window silently stops covering
        # the line it is asserting about.
        src = _AGENT.read_text()
        i = src.index("if ctype == 'file_contains':")
        j = src.index("if ctype == 'auth_new_source':", i)
        self.assertIn('re.compile(pat)', src[i:j])


class TestAPathologicalPatternDoesNotWedgeTheLoop(unittest.TestCase):

    def setUp(self):
        self.m = _load()
        self.dir = Path(tempfile.mkdtemp(prefix='rp-fcx-'))
        # Enough files that an unbounded scan would run the killer pattern many
        # times over, and long enough input that each run is expensive.
        for i in range(12):
            (self.dir / f'f{i}.txt').write_text('a' * 3000 + '!')
        self.m.host_path = lambda p: p
        self.m.FILE_CONTAINS_BUDGET_S = 1      # keep the test quick

    def test_the_killer_pattern_really_is_catastrophic(self):
        """Positive control. If this pattern were fast on this Python, the
        timing assertion below would pass for the wrong reason."""
        rx = re.compile(r'(a+)+$')
        # Small inputs, three doublings apart. Each extra character doubles the
        # work, so 18 -> 22 is a 16x step — enough to prove the shape without
        # the 88 SECONDS that measuring at 30 characters costs. This file has no
        # "e2e" in its name, so it runs in make test-fast AND the serial gate;
        # its wall-clock is added to every gate run by everyone, forever.
        def _t(n):
            t = time.monotonic()
            rx.search('a' * n + '!')
            return time.monotonic() - t
        cheap, dearer = _t(18), _t(22)
        self.assertGreater(dearer, cheap * 4,
                           'backtracking is not exponential here — this Python '
                           'has a different regex engine and the premise of '
                           'this test no longer holds')

    def _run(self, pattern):
        c = {'type': 'file_contains', 'pattern': pattern,
             'param': str(self.dir)}
        t = time.monotonic()
        status, detail = self.m._eval_one_agent_check(c)
        return status, detail, time.monotonic() - t

    def test_it_gives_up_inside_the_budget(self):
        status, detail, elapsed = self._run(r'(a+)+$')
        self.assertLess(elapsed, self.m.FILE_CONTAINS_BUDGET_S + 5,
                        f'the check ran {elapsed:.1f}s against a {self.m.FILE_CONTAINS_BUDGET_S}s '
                        f'budget — the agent poll loop is still blocked')
        self.assertEqual('unknown', status)
        self.assertIn('too slow', detail)

    def test_a_normal_pattern_still_finds_its_match(self):
        """The positive control that matters most: a budget that made every
        check return `unknown` would satisfy the test above and silently break
        Integrity Guard."""
        (self.dir / 'evil.txt').write_text('eval(base64_decode(')
        status, detail, _ = self._run(r'eval\(base64_decode')
        self.assertEqual('critical', status)
        self.assertIn('evil.txt', detail)

    def test_a_normal_pattern_with_no_match_is_ok(self):
        status, detail, _ = self._run(r'no-such-string-anywhere')
        self.assertEqual('ok', status)
        self.assertIn('scanned', detail)


class TestTheExtensionlessCopyIsInSync(unittest.TestCase):
    def test_bytes_match(self):
        self.assertEqual(_AGENT.read_bytes(),
                         (_ROOT / 'client' / 'remotepower-agent').read_bytes())


if __name__ == '__main__':
    unittest.main()
