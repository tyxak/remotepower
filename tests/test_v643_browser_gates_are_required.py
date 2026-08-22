#!/usr/bin/env python3
"""No browser gate may skip its way through a release.

Eighteen test modules need a real Chromium — the rendered box-overflow walk, the
dialog walk, the icon-to-label gap measurement, the accessibility sweep, the
click sweep, the page smokes, the v430 e2e walk and the rest — and every one of
them self-skips without one. That is right on a contributor's laptop and wrong in
the release pipeline: `ci.yml` installs bcrypt, cryptography, dnspython, webauthn,
pysaml2, flask, gunicorn, pydantic and psycopg — no playwright, no axe-core — so
on production CI every one of them skips, every time. They have only ever run on
a dev box that happens to have a browser.

The population here is DERIVED, not listed. This file used to name four files,
and by v7.0.2 fourteen drove a browser: RP_BROWSER_REQUIRE covered four and ten
suites could vanish without a word. A hardcoded list of what to protect can only
lose relevance, and the check that "the list still matches" asked whether the
four named files still exist — never whether every browser suite was in it.

That is the same shape as the Postgres gate before `RP_PG_REQUIRE`: 28 tests
written for the enterprise default, sitting in the tree skipping themselves, with
absence indistinguishable from success. The remedy here is deliberately the same
one — `RP_BROWSER_REQUIRE=1` turns the skip into a failure — and `make
pre-release`, which runs on a box that has Chromium, sets it.

This file guards the wiring, not the browser: it is the part that can rot
silently, because a gate that stops honouring the flag looks exactly like a gate
that had nothing to report.
"""
import ast
import io
import re
import sys
import tokenize
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tests'))

import browser_required  # noqa: E402

_TESTS = _ROOT / 'tests'

# The four gates this file was written for. They are no longer THE list — see
# _browser_gate_files() — they are the positive control on the derivation: if a
# glob-and-parse ever stops finding these four, it is broken, and a broken
# derivation must fail rather than quietly return a small set.
_KNOWN_GATES = (
    'test_v643_box_overflow_rendered.py',
    'test_v643_box_overflow_modals.py',
    'test_v643_icon_label_gap.py',
    'test_a11y_axe.py',
)

# What it means to drive a browser, in CODE. Matching raw source instead pulls
# in files that only MENTION the harness in a docstring — test_ci_green_parity
# names e2e_harness.py in a filename filter, and test_a11y_axe_modals describes
# start_stack() in its module docstring while inheriting the real one.
_DRIVES = re.compile(r'\bsync_playwright\b|\be2e_harness\b|\bstart_stack\b')


def _code_only(src):
    """Source with comments and string literals removed."""
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            out.append(tok.string)
    except (tokenize.TokenError, IndentationError):     # pragma: no cover
        return src
    return ' '.join(out)


def _module_level_imports(src):
    """Sibling test modules imported at MODULE level.

    Module level, not anywhere: test_v642_docs imports test_a11y_axe inside a
    test method purely to read its `_AXE_OPTIONS` dict. That is a source-level
    fact check, not a browser walk, and counting it would put a file with no
    browser in the population and then demand it honour a browser flag.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:                                 # pragma: no cover
        return set()
    names = set()

    def visit(body):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                continue                                # not module level
            if isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split('.')[0])
            elif isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.name.split('.')[0])
            for field in ('body', 'orelse', 'finalbody'):
                inner = getattr(node, field, None)
                if isinstance(inner, list):
                    visit(inner)
            for h in getattr(node, 'handlers', []):
                visit(h.body)

    visit(tree.body)
    return names


def _browser_gate_files():
    """Every test module that drives a real browser, DERIVED from the tree.

    The hand-written 4-tuple this replaced was the whole weakness: it could only
    lose relevance as files were added, and its companion check asked whether
    the four named files still EXIST — never whether every browser suite was in
    the list. 14 files drove a browser while RP_BROWSER_REQUIRE protected four,
    so the click sweep, the page smokes, the v430 walk, living-tiles,
    sidebar-autohide, aria-runtime, lazy-integrations, the alert wall, the toast
    gate and the accumulator caps could all vanish without a word. Same rot the
    Makefile already fixed on the other side with
    `E2E_TESTS := $(wildcard tests/*e2e*.py)`.
    """
    raw = {p.name: p.read_text() for p in sorted(_TESTS.glob('test_*.py'))}
    gates = {n for n, s in raw.items() if _DRIVES.search(_code_only(s))}
    imports = {n: _module_level_imports(s) for n, s in raw.items()}
    # A module can inherit the entire harness — setUpClass, the browser
    # lifecycle, the flag — from another gate. test_a11y_axe_modals subclasses
    # TestAccessibilityAxe and never names playwright itself.
    changed = True
    while changed:
        changed = False
        for name in raw:
            if name in gates:
                continue
            if imports[name] & {g[:-3] for g in gates}:
                gates.add(name)
                changed = True
    return gates


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


class TestTheDerivationIsSound(unittest.TestCase):
    """A derived population can fail in a way a hardcoded one cannot: it can
    come back empty or tiny and every check over it then passes. These are its
    controls."""

    def test_it_finds_the_gates_it_was_written_for(self):
        gates = _browser_gate_files()
        missing = sorted(g for g in _KNOWN_GATES if g not in gates)
        self.assertEqual(missing, [],
                         'the derivation no longer finds the original four '
                         'browser gates, so it is broken: %s' % missing)

    def test_it_finds_the_whole_population(self):
        gates = _browser_gate_files()
        self.assertGreaterEqual(
            len(gates), 12,
            'only %d browser suites derived (%s). 18 exist. A derivation that '
            'shrinks silently is exactly the failure this replaced.'
            % (len(gates), sorted(gates)))

    def test_it_does_not_sweep_in_files_that_only_mention_the_harness(self):
        """Negative control. Comments and docstrings are stripped before
        matching; without that, any file naming e2e_harness.py in prose joins
        the population and then has to be exempted from every check."""
        gates = _browser_gate_files()
        self.assertNotIn('test_ci_green_parity.py', gates)


class TestEveryGateHonoursTheFlag(unittest.TestCase):

    def test_no_gate_still_raises_a_bare_browser_skip(self):
        """A gate that keeps its own `raise unittest.SkipTest('playwright …')`
        opts itself out of the flag while looking identical to one that honours
        it."""
        offenders = []
        for name in sorted(_browser_gate_files()):
            src = (_TESTS / name).read_text()
            for m in re.finditer(
                    r"raise unittest\.SkipTest\(\s*f?['\"]([^'\"]*)", src):
                reason = m.group(1).lower()
                if 'playwright' in reason or 'chromium' in reason:
                    offenders.append(f'{name}: {m.group(1)}')
        self.assertEqual(offenders, [],
                         'these skip on a missing browser without consulting '
                         'RP_BROWSER_REQUIRE:\n' + '\n'.join('  ' + o for o in offenders))

    def test_every_gate_reaches_the_helper(self):
        """Either the file consults browser_required itself, or it inherits the
        whole harness from a gate that does (test_a11y_axe_modals)."""
        gates = _browser_gate_files()
        offenders = []
        for name in sorted(gates):
            src = (_TESTS / name).read_text()
            if 'browser_required' in src:
                continue
            code = _code_only(src)
            if any(re.search(r'\b(?:from\s+%s\s+import|import\s+%s)\b'
                             % (g[:-3], g[:-3]), code)
                   for g in gates if g != name):
                continue
            offenders.append(name)
        self.assertEqual(
            offenders, [],
            'browser suites that never consult RP_BROWSER_REQUIRE — they can '
            'vanish from a release run without a word:\n'
            + '\n'.join('  ' + o for o in offenders))


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
