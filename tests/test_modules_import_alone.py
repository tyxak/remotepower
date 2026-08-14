#!/usr/bin/env python3
"""Every test module must import on its own, not only inside the whole suite.

`unittest discover -s tests` puts `tests/` on `sys.path` for free, so a module
that does `import browser_required` or `from clientjs import client_js` works
there. `python3 -m unittest tests.test_thing` — the command anyone actually
types while iterating on one file — does not, and the module fails to import at
all. Twenty-five modules were in that state.

That is the same import-order-luck family as the RP_DATA_DIR guard next door,
and it is the benign end of it: `make test` and `make test-fast` both worked
throughout, so nothing shipped broken. What it cost was the ability to run a
single file, which is how most of the debugging in this repo happens.

WHY A SUBPROCESS PER MODULE, and why only some modules. Importing them all in
ONE process gives false greens: the first module that inserts `tests/` into
sys.path fixes it for every module imported after it, which is precisely the
mechanism being tested. So each candidate needs its own interpreter.

The candidate set is every module that imports a tests/ sibling — about a
quarter of the suite. Two attempts to narrow it further are recorded in
`_candidates()`, and the second is the instructive one: it ran in 3.6 seconds
and measured NOTHING, because the fix for every affected module is itself a
sys.path line, so each one left the candidate set the moment it was fixed. A
gate that goes green by having nothing to look at is the exact failure this file
exists to prevent, so the cost is paid instead.

WHAT THIS CANNOT SEE, stated plainly because a gate whose blind spot is
undocumented gets trusted for more than it covers: a sibling import written
INSIDE a test method. The module imports fine and the method fails when it runs,
so no amount of importing finds it. Four modules were in that state
(test_improvements_w1, test_v642_knowledge_search, test_v643_lazy_integrations,
test_v643_ux_reported) and were found by running the suite one module at a time.

`make test-import-isolation` does both — imports every module in its own
interpreter, then RUNS every module in its own interpreter — and is the authority
when this needs auditing. It takes about ten minutes, which is why it is a target
and this is the gate.
"""
import ast
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_ROOT = _TESTS.parent
_SIBLINGS = {p.stem for p in _TESTS.glob('*.py')}


def _imports_a_sibling(path):
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except SyntaxError:
        return False
    for n in ast.walk(tree):
        names = []
        if isinstance(n, ast.Import):
            names = [a.name.split('.')[0] for a in n.names]
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            names = [n.module.split('.')[0]]
        if any(nm in _SIBLINGS for nm in names):
            return True
    return False


def _candidates():
    """Every module that imports a tests/ sibling. No cleverer filter.

    Two narrower filters were tried and both were wrong in a way that mattered:

      * deciding STATICALLY whether a module's `sys.path.insert` points at the
        tests directory reported 89 modules where 25 were real — the entire
        difference was inserts written in forms the heuristic did not recognise;
      * "skip modules that touch sys.path at all" ran in 3.6s and measured
        NOTHING, because the fix for all 25 modules IS a sys.path line, so every
        one of them left the candidate set the moment it was fixed. The gate
        went green by having nothing to look at, which is the failure mode this
        whole file is written in reaction to.

    So it spawns for all of them. ~20s, paid on every run, for a check that is
    exact and needs no judgement.
    """
    return sorted(p for p in _TESTS.glob('test_*.py')
                  if p.name != Path(__file__).name and _imports_a_sibling(p))


def _import_alone(mod):
    """(module, error) after importing it in a FRESH interpreter."""
    code = ('import importlib, os, sys; sys.path.insert(0, os.getcwd());'
            f'importlib.import_module({mod!r})')
    r = subprocess.run([sys.executable, '-c', code], cwd=str(_ROOT),
                       capture_output=True, text=True, timeout=180)
    if r.returncode == 0:
        return None
    tail = (r.stderr or '').strip().split('\n')[-1]
    return f'{mod}: {tail}'


class TestTheSweepHasSomethingToMeasure(unittest.TestCase):
    """The assertion below is "no module failed", which a candidate list of
    zero produces just as happily."""

    def test_the_static_pass_finds_sibling_importers(self):
        """The candidate list is allowed to be EMPTY — that is the healthy
        state — so the control is on the wider set it is filtered from."""
        sib = [p for p in _TESTS.glob('test_*.py') if _imports_a_sibling(p)]
        self.assertGreater(len(sib), 40,
                           f'only {len(sib)} modules import a tests/ sibling — '
                           f'the static pass is broken')

    def test_the_sibling_set_was_found(self):
        self.assertIn('browser_required', _SIBLINGS)
        self.assertIn('srcpin', _SIBLINGS)

    def test_a_module_with_a_broken_import_is_detected(self):
        """Positive control for the subprocess half: without it, "no failures"
        could mean the runner never reports anything."""
        self.assertIsNotNone(_import_alone('tests.definitely_not_a_module'))


class TestEveryModuleImportsAlone(unittest.TestCase):

    def test_none_fail_in_a_fresh_interpreter(self):
        mods = [f'tests.{p.stem}' for p in _candidates()]
        with ThreadPoolExecutor(max_workers=16) as ex:
            fails = [f for f in ex.map(_import_alone, mods) if f]
        self.assertEqual(
            fails, [],
            'these modules import only because another test module happened to '
            'put tests/ on sys.path first, so `python3 -m unittest '
            'tests.<name>` cannot load them. Add above the sibling import:\n'
            '    sys.path.insert(0, str(Path(__file__).resolve().parent))\n'
            + '\n'.join('  ' + f for f in fails))


if __name__ == '__main__':
    unittest.main()
