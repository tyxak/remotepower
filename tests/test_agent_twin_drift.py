#!/usr/bin/env python3
"""21 function bodies are byte-identical across the Windows and macOS agents.

They are separate files on purpose — the Windows agent's own docstring says it
is "kept as a separate file from the Linux agent so it can't destabilise it,
converging over time" — and that is the right call. The cost is that a fix
applied to one copy is eventually missed on the other, silently, and the two
drift until nobody can say which is correct.

This makes divergence an EXPLICIT edit. The declared list below is the set of
functions that must stay byte-identical. Fixing one copy and not the other now
fails the build; deliberately diverging one means deleting its entry here, which
is a visible line in a diff a reviewer can question.

The invariant is exact equality in both directions:

  - a declared function whose bodies differ  -> somebody patched one copy
  - a declared function missing from either  -> renamed or deleted on one side
  - an identical pair that is NOT declared   -> newly converged, declare it,
                                                or it silently drifts later

That last one is why the list cannot rot: convergence is as loud as divergence.

WHY THE LIST LIVES HERE and not in the agents, unlike
HEARTBEAT_KEYS_NOT_HONOURED: that one is a property OF an agent — what this
build honours — so the agent owns it. This is a property of the PAIR, owned by
neither file, and a copy in each would be the two-registry bug this is meant to
prevent.

Byte-identical, not AST-identical, deliberately: a comment that explains WHY a
line is the way it is has to travel with the code, and a fix whose only trace is
a corrected comment is exactly the kind that gets applied to one copy.
"""
import ast
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
WIN = _ROOT / 'client' / 'remotepower-agent-win.py'
MAC = _ROOT / 'client' / 'remotepower-agent-mac.py'

# Must stay byte-identical between the Windows and macOS agents.
TWINNED = {
    # heartbeat delta protocol
    '_apply_sysinfo_delta', '_commit_sysinfo_delta',
    # canary / honeytoken files
    '_canary_path_ok', '_canary_status', '_plant_canaries',
    # file-log tailing state
    '_file_log_state_path', '_load_file_log_state', '_save_file_log_state',
    '_submit_file_logs',
    # scan cadence stamps
    '_load_pii_scan_ts', '_save_pii_scan_ts', '_load_secrets_scan_ts',
    # secret / PII detection — the highest-consequence pair here: a false
    # negative fixed on one platform and not the other means one half of the
    # fleet keeps leaking the pattern that was just fixed.
    '_luhn_ok', '_redact_secret', 'collect_pii_findings', 'collect_secret_findings',
    # misc shared helpers
    '_exec_timeout_override', '_fmt_uptime', '_spent', '_stable_hash',
    # no-redirect opener — security-critical, must not diverge
    'redirect_request',
}


def _functions(path):
    src = path.read_text()
    lines = src.splitlines()
    out = {}
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[n.name] = '\n'.join(lines[n.lineno - 1:n.end_lineno])
    return out


class TestTheTwinsDoNotDrift(unittest.TestCase):
    def setUp(self):
        self.win = _functions(WIN)
        self.mac = _functions(MAC)

    def test_the_parse_found_both_agents(self):
        """Positive control: an empty parse makes every assertion below
        vacuously true, and this file would report success while comparing
        nothing."""
        self.assertGreater(len(self.win), 40)
        self.assertGreater(len(self.mac), 40)

    def test_every_declared_function_exists_in_both(self):
        missing = sorted(n for n in TWINNED
                         if n not in self.win or n not in self.mac)
        self.assertEqual(
            missing, [],
            'declared twinned but absent from one agent (renamed? deleted?):\n  '
            + '\n  '.join(missing))

    def test_every_declared_function_is_byte_identical(self):
        """The bug this exists for: a fix landed on one agent only."""
        drifted = sorted(n for n in TWINNED
                         if n in self.win and n in self.mac
                         and self.win[n] != self.mac[n])
        self.assertEqual(
            drifted, [],
            'These are declared as twins and their bodies now DIFFER — a fix was '
            'applied to one agent and not the other. Port it across, or, if the '
            'divergence is deliberate, delete the name from TWINNED so the '
            'decision is visible in the diff:\n  ' + '\n  '.join(drifted))

    def test_no_identical_pair_is_left_undeclared(self):
        """Convergence must be as loud as divergence, or the list rots: a pair
        that becomes identical today and is never declared drifts apart later
        with nothing watching."""
        shared = set(self.win) & set(self.mac)
        identical = {n for n in shared if self.win[n] == self.mac[n]}
        undeclared = sorted(identical - TWINNED)
        self.assertEqual(
            undeclared, [],
            'These function bodies are byte-identical across the two agents but '
            'are not declared in TWINNED, so a later one-sided fix would pass '
            'silently. Add them:\n  ' + '\n  '.join(undeclared))

    def test_nothing_declared_has_silently_stopped_being_shared(self):
        """The reverse rot: a name kept in TWINNED after both copies were
        deleted reads as coverage and is none."""
        self.assertTrue(TWINNED <= (set(self.win) | set(self.mac)))


class TestNoUncappedNetworkRead(unittest.TestCase):
    """Both agents post their token before the server is trusted; an error body
    read without a bound lets a hostile or wedged endpoint hand back an
    arbitrarily large response. The success path was already capped."""

    def test_error_bodies_are_bounded(self):
        for path in (WIN, MAC):
            with self.subTest(agent=path.name):
                src = path.read_text()
                self.assertNotIn('e.read().decode', src)
                self.assertIn('e.read(MAX_JSON_RESP)', src)
                self.assertIn('MAX_JSON_RESP =', src)


if __name__ == '__main__':
    unittest.main()
