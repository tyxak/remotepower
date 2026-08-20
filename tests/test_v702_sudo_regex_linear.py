#!/usr/bin/env python3
"""One long auth.log line stalled the heartbeat for a minute and a half.

`_SUDO_LINE_RE` was a single expression with three lazy `.*?` segments separated
by OPTIONAL groups. On a line containing `COMMAND=` — the only pre-filter — that
does NOT satisfy the `USER=<word> ; COMMAND=` tail, the engine explores every
split of those wildcards, which is cubic in line length:

    250 chars     15 ms
    850 chars    1.0 s
   1650 chars    6.0 s
   4 KB         ~87 s

Only FAILURES blow up; a matching line was always fast, which is why it never
showed up in testing. `collect_sudo_events` runs it over up to 400 journal
lines, or up to 800 read straight from /var/log/auth.log on a host without
journalctl (Alpine, Devuan, non-systemd containers), on every sysinfo heartbeat.
Any local user can put a long line in auth.log by invoking sudo with a long
argument.

Replaced with four small anchored patterns — head, tail, and the two optional
fields looked up independently. The timing assertion is the point of this file:
a rewrite that reintroduced a nested wildcard would still parse every line
correctly and pass a correctness-only test.
"""
import ast
import pathlib
import re
import time
import unittest

_AGENT = pathlib.Path(__file__).resolve().parent.parent / 'client' / 'remotepower-agent.py'


def _patterns():
    ns = {'re': re}
    for node in ast.parse(_AGENT.read_text()).body:
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], 'id', '').startswith('_SUDO_')
                and 're.compile' in ast.unparse(node.value)):
            exec(compile(ast.Module([node], []), 'agent', 'exec'), ns)
    return {k: v for k, v in ns.items() if k.startswith('_SUDO_')}


def _scan(pats, line):
    """What the collector does per line."""
    head = pats['_SUDO_HEAD_RE'].search(line)
    tail = pats['_SUDO_TAIL_RE'].search(line)
    pats['_SUDO_TTY_RE'].search(line)
    pats['_SUDO_PWD_RE'].search(line)
    return head, tail


class TestItIsStillCorrect(unittest.TestCase):
    """First — a fast expression that parses nothing is not a fix."""

    def setUp(self):
        self.p = _patterns()

    def test_a_full_line_yields_every_field(self):
        line = ('Aug 20 09:00:00 host sudo[4242]:    alice : TTY=pts/0 ; '
                'PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update')
        head, tail = _scan(self.p, line)
        self.assertEqual(head.group('user'), 'alice')
        self.assertEqual(tail.group('target'), 'root')
        self.assertEqual(tail.group('cmd'), '/usr/bin/apt-get update')
        self.assertEqual(self.p['_SUDO_TTY_RE'].search(line).group('tty'), 'pts/0')
        self.assertEqual(self.p['_SUDO_PWD_RE'].search(line).group('pwd'), '/home/alice')

    def test_a_line_without_tty_or_pwd_still_parses(self):
        """Those two are optional in the log and were optional in the old
        expression — which is exactly what made it backtrack."""
        line = ('Aug 20 09:00:00 h sudo: bob : USER=root ; '
                'COMMAND=/bin/systemctl restart nginx')
        head, tail = _scan(self.p, line)
        self.assertEqual(head.group('user'), 'bob')
        self.assertEqual(tail.group('cmd'), '/bin/systemctl restart nginx')
        self.assertIsNone(self.p['_SUDO_TTY_RE'].search(line))

    def test_a_non_sudo_line_is_rejected(self):
        head, _t = _scan(self.p, 'Aug 20 09:00:00 h sshd[1]: Accepted password')
        self.assertIsNone(head)

    def test_a_sudo_line_with_no_command_is_rejected(self):
        _h, tail = _scan(
            self.p, 'Aug 20 09:00:00 h sudo[1]: alice : 3 incorrect password attempts')
        self.assertIsNone(tail)


class TestItIsLinear(unittest.TestCase):

    def _worst_case(self, n):
        """Contains COMMAND= so it passes the pre-filter, never satisfies the
        tail — the shape that used to explode."""
        return 'Aug 20 09:00:00 h sudo[1]: alice : ' + ('x' * n) + ' COMMAND=/bin/ls'

    def test_a_four_kilobyte_line_is_not_slow(self):
        p = _patterns()
        line = self._worst_case(4000)
        start = time.perf_counter()
        _scan(p, line)
        took = time.perf_counter() - start
        self.assertLess(took, 0.25,
                        f'a 4 KB non-matching line took {took*1000:.0f} ms — '
                        f'it took ~87 s before this was rewritten, on a path '
                        f'that runs 400-800 times per heartbeat')

    def test_cost_does_not_explode_with_length(self):
        """The property, not a single measurement: quadrupling the line must
        not multiply the time by more than a small factor. Cubic growth fails
        this by orders of magnitude."""
        p = _patterns()
        def t(n):
            line = self._worst_case(n)
            best = min(_timeit(p, line) for _ in range(3))
            return best
        small, large = t(500), t(2000)
        self.assertLess(large, max(small * 12, 0.05),
                        f'4x the length cost {large/max(small, 1e-9):.0f}x the '
                        f'time — the wildcards are nested again')

    def test_the_old_shape_is_gone(self):
        src = _AGENT.read_text()
        self.assertNotIn('_SUDO_LINE_RE', src,
                         'the single nested-wildcard expression is back')


def _timeit(p, line):
    start = time.perf_counter()
    _scan(p, line)
    return time.perf_counter() - start


if __name__ == '__main__':
    unittest.main()
