#!/usr/bin/env python3
"""The README advertised Python 3.8+ and the server has not run on it for years.

Five server modules and the Linux agent annotate with `X | Y`, and none of them
carries `from __future__ import annotations`, so those annotations are evaluated
when the module is imported. On 3.8 and 3.9 that is a TypeError at import — not
a subtle degradation, a server that does not start.

An operator reading the badge and provisioning a 3.9 host gets that on first
request, with nothing pointing back at the version they chose.

The floor is derived from the sources here rather than restated, so the badge
cannot drift from the code in either direction: raising it silently strands
supported hosts, and lowering it silently promises something that fails on
import.

The Windows and macOS agents are separately 3.8-safe and docs/windows-client.md
says so; that claim is checked here too, since they are the reason a low floor
is documented anywhere.
"""
import ast
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _runtime_evaluated_features(path):
    """Syntax that raises on an older interpreter at IMPORT time.

    A `X | Y` annotation is only evaluated at runtime when the module lacks
    `from __future__ import annotations`; with it, the same source is fine on
    3.8. That distinction is the whole point, so it is checked per file.
    """
    src = path.read_text()
    has_future = 'from __future__ import annotations' in src
    out = []
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Match):
            out.append(('match statement (3.10+)', n.lineno))
            continue
        if has_future:
            continue
        ann = getattr(n, 'annotation', None) or getattr(n, 'returns', None)
        if ann is not None and 'BitOr' in ast.dump(ann):
            out.append(('X | Y annotation evaluated at import (3.10+)', n.lineno))
    return out


def _server_files():
    for d in ('server/cgi-bin', 'server/push', 'server/kmip', 'server/syslog',
              'server/flow', 'server/webterm'):
        yield from sorted((_ROOT / d).glob('*.py'))
    yield _ROOT / 'client' / 'remotepower-agent.py'


class TestTheBadgeMatchesTheCode(unittest.TestCase):

    def setUp(self):
        self.readme = (_ROOT / 'README.md').read_text()

    def _badge(self):
        m = re.search(r'badge/python-(\d+)\.(\d+)\+-', self.readme)
        self.assertTrue(m, 'the Python badge is gone from README.md')
        return (int(m.group(1)), int(m.group(2)))

    def test_the_scan_finds_the_features_it_is_looking_for(self):
        """Positive control. A parser that found nothing would make the floor
        check below pass at any advertised version."""
        found = {p.name: _runtime_evaluated_features(p)
                 for p in _server_files()}
        total = sum(len(v) for v in found.values())
        self.assertGreater(total, 0,
                           'no 3.10-only construct found anywhere — either the '
                           'code was modernised away from them, in which case '
                           'lower the badge, or this scan broke')

    def test_the_advertised_floor_is_not_below_what_the_code_needs(self):
        offenders = []
        for p in _server_files():
            for why, line in _runtime_evaluated_features(p):
                offenders.append(f'{p.relative_to(_ROOT)}:{line} — {why}')
        if offenders:
            self.assertGreaterEqual(
                self._badge(), (3, 10),
                'README advertises %d.%d but the server cannot import on it:\n  %s'
                % (*self._badge(), '\n  '.join(sorted(offenders)[:6])))

    def test_the_floor_is_not_higher_than_it_needs_to_be(self):
        """The other direction. A badge raised past the real requirement turns
        away hosts that would have worked, and nothing would catch it."""
        self.assertLessEqual(self._badge(), (3, 10),
                             'the badge claims a floor above 3.10 — if that is '
                             'real, this test should say why; if not, lower it')


class TestTheAgentDocsStillHold(unittest.TestCase):
    """The Windows and macOS agents are the reason a low floor is documented at
    all. If they gain 3.10-only syntax, that doc becomes wrong too."""

    def test_the_windows_and_mac_agents_are_still_3_8_safe(self):
        for rel in ('client/remotepower-agent-win.py',
                    'client/remotepower-agent-mac.py'):
            with self.subTest(agent=rel):
                self.assertEqual(
                    [], _runtime_evaluated_features(_ROOT / rel),
                    f'{rel} now needs 3.10+, but docs/windows-client.md still '
                    f'says 3.8+')

    def test_the_windows_doc_states_a_floor(self):
        p = _ROOT / 'docs' / 'windows-client.md'
        if not p.exists():
            self.skipTest('excluded from dist tree')
        self.assertRegex(p.read_text(), r'\(3\.\d+\+\)')


if __name__ == '__main__':
    unittest.main()
