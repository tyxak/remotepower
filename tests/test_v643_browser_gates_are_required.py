#!/usr/bin/env python3
"""The four browser gates must not be able to skip their way through a release.

The rendered box-overflow walk, the dialog walk, the icon-to-label gap
measurement and the accessibility sweep all need a real Chromium, and all four
self-skip without one. That is right on a contributor's laptop and wrong in the
release pipeline: `ci.yml` installs bcrypt, cryptography, dnspython, webauthn,
pysaml2, flask, gunicorn, pydantic and psycopg — no playwright, no axe-core — so
on production CI every one of them skips, every time. They have only ever run on
a dev box that happens to have a browser.

That is the same shape as the Postgres gate before `RP_PG_REQUIRE`: 28 tests
written for the enterprise default, sitting in the tree skipping themselves, with
absence indistinguishable from success. The remedy here is deliberately the same
one — `RP_BROWSER_REQUIRE=1` turns the skip into a failure — and `make
pre-release`, which runs on a box that has Chromium, sets it.

This file guards the wiring, not the browser: it is the part that can rot
silently, because a gate that stops honouring the flag looks exactly like a gate
that had nothing to report.
"""
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tests'))

import browser_required  # noqa: E402

_GATES = (
    'test_v643_box_overflow_rendered.py',
    'test_v643_box_overflow_modals.py',
    'test_v643_icon_label_gap.py',
    'test_a11y_axe.py',
)


class TestTheHelperBehaves(unittest.TestCase):

    def setUp(self):
        self._env = browser_required.os.environ.get('RP_BROWSER_REQUIRE')

    def tearDown(self):
        if self._env is None:
            browser_required.os.environ.pop('RP_BROWSER_REQUIRE', None)
        else:
            browser_required.os.environ['RP_BROWSER_REQUIRE'] = self._env

    def test_it_skips_by_default(self):
        """A contributor without Chromium must still get a green suite."""
        browser_required.os.environ.pop('RP_BROWSER_REQUIRE', None)
        with self.assertRaises(unittest.SkipTest):
            browser_required.skip_or_fail('no browser here')

    def test_it_fails_when_required(self):
        browser_required.os.environ['RP_BROWSER_REQUIRE'] = '1'
        with self.assertRaises(AssertionError):
            browser_required.skip_or_fail('no browser here')

    def test_the_failure_is_not_a_skip_subclass(self):
        """unittest.SkipTest is not an AssertionError, and the distinction is
        the entire point — if this ever inverted, the flag would silently do
        nothing while still appearing to be honoured."""
        self.assertFalse(issubclass(unittest.SkipTest, AssertionError))

    def test_common_truthy_spellings_all_work(self):
        for val in ('1', 'true', 'yes', 'on', 'TRUE'):
            browser_required.os.environ['RP_BROWSER_REQUIRE'] = val
            with self.assertRaises(AssertionError, msg=val):
                browser_required.skip_or_fail('x')

    def test_an_unset_or_empty_value_does_not_require(self):
        for val in ('', '0', 'false', 'no'):
            browser_required.os.environ['RP_BROWSER_REQUIRE'] = val
            with self.assertRaises(unittest.SkipTest, msg=val):
                browser_required.skip_or_fail('x')


class TestEveryGateHonoursTheFlag(unittest.TestCase):

    def test_no_gate_still_raises_a_bare_browser_skip(self):
        """A gate that keeps its own `raise unittest.SkipTest('playwright …')`
        opts itself out of the flag while looking identical to one that honours
        it."""
        offenders = []
        for name in _GATES:
            src = (_ROOT / 'tests' / name).read_text()
            for m in re.finditer(
                    r"raise unittest\.SkipTest\(\s*f?['\"]([^'\"]*)", src):
                reason = m.group(1).lower()
                if 'playwright' in reason or 'chromium' in reason:
                    offenders.append(f'{name}: {m.group(1)}')
        self.assertEqual(offenders, [],
                         'these skip on a missing browser without consulting '
                         'RP_BROWSER_REQUIRE:\n' + '\n'.join('  ' + o for o in offenders))

    def test_every_gate_imports_the_helper(self):
        for name in _GATES:
            src = (_ROOT / 'tests' / name).read_text()
            self.assertIn('browser_required', src, name)

    def test_the_gate_list_here_matches_what_exists(self):
        """A renamed gate would silently drop out of this check."""
        for name in _GATES:
            self.assertTrue((_ROOT / 'tests' / name).is_file(), name)


class TestPreReleaseSetsIt(unittest.TestCase):

    def test_the_pre_tag_gate_requires_a_browser(self):
        mk = (_ROOT / 'Makefile').read_text()
        if 'pre-release:' not in mk:
            self.skipTest('Makefile excluded from this tree')
        self.assertRegex(
            mk, r'pre-release:\s*export\s+RP_BROWSER_REQUIRE\s*=\s*1',
            'make pre-release does not set RP_BROWSER_REQUIRE, so a release can '
            'be cut with all four rendered gates silently switched off')


if __name__ == '__main__':
    unittest.main()
