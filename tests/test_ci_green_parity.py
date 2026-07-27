"""CI-green parity guards (v6.2.3).

Prod CI (`.github/workflows/ci.yml`) runs Python 3.14 with a FIXED pip list
and `python -m unittest discover`. Historically every "red CI on the release
push" came from a local/CI environment delta:

  * a new hard runtime import not in the ci.yml pip list (flask in v6.1.0,
    pydantic in v6.1.2),
  * a test module importing a package CI doesn't install (unittest discover
    IMPORTS every test module, so a module-level `import pytest` is an
    instant CI ImportError even if the test itself would be skipped),
  * `make ci-parity` drifting away from what ci.yml actually does.

These tests make each of those a local failure instead of a prod surprise.
Everything is source-level (AST) — nothing is imported or executed.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
CI_YML = ROOT / '.github' / 'workflows' / 'ci.yml'
MAKEFILE = ROOT / 'Makefile'

# import-name (what `import X` sees) → pip-name (what ci.yml installs).
IMPORT_TO_PIP = {
    'bcrypt': 'bcrypt',
    'cryptography': 'cryptography',
    'dns': 'dnspython',
    'webauthn': 'webauthn',
    'saml2': 'pysaml2',
    'flask': 'flask',
    'gunicorn': 'gunicorn',
    'pydantic': 'pydantic',
}

STDLIB = set(sys.stdlib_module_names)


def _require_sources(test):
    """ci.yml (and .github/ generally) is EXCLUDED from the release tarball,
    so under `make dist`'s staged-tree suite these files don't exist — the
    documented skip-don't-error class (CLAUDE.md pre-tag gate, item 1)."""
    if not CI_YML.exists() or not MAKEFILE.exists():
        test.skipTest('ci.yml/Makefile excluded from the dist tree')


def _ci_pip_deps():
    """The package list from ci.yml's `pip install …` step (excluding pip)."""
    m = re.search(r'pip install (?!--)(.+)', CI_YML.read_text())
    assert m, 'ci.yml: could not find the pip install line'
    return set(m.group(1).split())


def _top_level_imports(path):
    """Module-level, UNCONDITIONAL imports of `path` (nothing nested in
    try/if/def — those are the guarded-optional pattern and CI-safe)."""
    tree = ast.parse(path.read_text(), filename=str(path))
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(a.name.split('.')[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split('.')[0])
    return names


def _local_module_names():
    """Module names that resolve to files in server/cgi-bin (sibling imports),
    server/flow + server/syslog (sidecar modules a test adds to sys.path before
    importing), or tests/ (test helpers like apisrc/srcpin)."""
    names = {p.stem for p in CGI.glob('*.py')}
    names |= {p.stem for p in (ROOT / 'tests').glob('*.py')}
    for extra in ('server/flow', 'server/syslog'):
        d = ROOT / extra
        if d.is_dir():
            names |= {p.stem for p in d.glob('*.py')}
    return names


class TestCiListsInSync(unittest.TestCase):
    def test_makefile_ci_deps_equals_ci_yml(self):
        """make ci-parity must install EXACTLY what ci.yml installs — extra
        local packages (pytest, hypothesis, …) hide import errors CI will hit,
        missing ones fake failures CI won't."""
        _require_sources(self)
        m = re.search(r'^CI_DEPS\s*:=\s*(.+)$', MAKEFILE.read_text(), re.M)
        assert m, 'Makefile: CI_DEPS not found'
        self.assertEqual(set(m.group(1).split()), _ci_pip_deps())

    def test_ci_parity_uses_the_ci_runner(self):
        """ci-parity must run `python -m unittest discover` (the ci.yml
        runner), not pytest — the two differ in collection AND in which
        module-level imports they tolerate."""
        _require_sources(self)
        recipe = MAKEFILE.read_text()
        i = recipe.index('ci-parity:')
        block = recipe[i:i + 1200]
        self.assertIn('unittest discover', block)
        self.assertNotIn('pytest', block.split('unittest discover')[1][:200])


class TestServerImportClosureMatchesCi(unittest.TestCase):
    """Every module the test suite imports on CI (api.py + wsgi.py + their
    unconditional local-import closure) may only unconditionally import
    stdlib or packages ci.yml installs. A new hard third-party import fails
    HERE, not on the release push."""

    def _closure(self):
        seen, queue = set(), ['api', 'wsgi']
        local = {p.stem for p in CGI.glob('*.py')}
        while queue:
            mod = queue.pop()
            if mod in seen or mod not in local:
                continue
            seen.add(mod)
            for name in _top_level_imports(CGI / f'{mod}.py'):
                if name in local:
                    queue.append(name)
        return seen

    def test_no_unlisted_hard_imports(self):
        _require_sources(self)
        ci = _ci_pip_deps()
        local = {p.stem for p in CGI.glob('*.py')}
        problems = []
        for mod in sorted(self._closure()):
            for name in sorted(_top_level_imports(CGI / f'{mod}.py')):
                if name in STDLIB or name in local:
                    continue
                pip = IMPORT_TO_PIP.get(name)
                if pip is None:
                    problems.append(
                        f'{mod}.py imports {name!r} unconditionally — unknown '
                        f'to tests/test_ci_green_parity.IMPORT_TO_PIP; if this '
                        f'is a NEW hard dep, add it to ci.yml + Makefile '
                        f'CI_DEPS + install*.sh + Dockerfile + AUR depends, '
                        f'then map it here')
                elif pip not in ci:
                    problems.append(
                        f'{mod}.py imports {name!r} ({pip}) unconditionally '
                        f'but ci.yml does not install it — prod CI will '
                        f'ImportError on the release push')
        self.assertEqual(problems, [], '\n'.join(problems))


class TestTestModulesImportableOnCi(unittest.TestCase):
    def test_no_test_module_hard_imports_a_non_ci_package(self):
        """`unittest discover` imports EVERY tests/*.py on CI, where only the
        ci.yml packages exist. A module-level `import pytest` /
        `import hypothesis` / `import playwright` red-Xs CI at import time —
        such imports must be guarded (try/except or inside the test)."""
        _require_sources(self)
        ci = _ci_pip_deps()
        local = _local_module_names()
        problems = []
        for path in sorted((ROOT / 'tests').glob('*.py')):
            if path.name == 'conftest.py':
                # pytest-only by definition: unittest discover imports test*.py
                # patterns only, so CI never loads it — and pytest, the only
                # loader that does, is by construction installed when it runs.
                continue
            for name in sorted(_top_level_imports(path)):
                if name in STDLIB or name in local:
                    continue
                pip = IMPORT_TO_PIP.get(name)
                if pip is None or pip not in ci:
                    problems.append(
                        f'tests/{path.name} unconditionally imports {name!r}, '
                        f'which ci.yml does not install — unittest discover '
                        f'on CI fails at import; guard it (try/except '
                        f'ImportError + skip)')
        self.assertEqual(problems, [], '\n'.join(problems))


class TestE2eSuiteCannotRedTheGate(unittest.TestCase):
    """An e2e file must SKIP when the environment can't run it, and must be
    excluded from `make test-fast`. Both broke at once before v6.4.1:

      * every e2e file guarded on `import playwright` alone, which is a
        different question from "is a browser installed" — `pip install
        playwright` gives you the module, `playwright install chromium` gives
        you the binary. On a box with the first and not the second, setUpClass
        ERRORED instead of skipping and the whole serial gate exited non-zero.
      * `test-fast` hand-listed two e2e files to ignore and three more had been
        added since, so the fast suite was red on every single run — which
        quietly trains you to ignore exactly the signal CLAUDE.md says to trust.
    """

    E2E = sorted(p for p in (ROOT / 'tests').glob('*e2e*.py')
                 if p.name != 'e2e_harness.py')

    def test_there_are_e2e_files_to_check(self):
        self.assertTrue(self.E2E, 'glob found no e2e test files — did they move?')

    def test_every_e2e_file_guards_on_the_shared_probe(self):
        bad = []
        for p in self.E2E:
            src = p.read_text()
            if 'browser_available()' not in src:
                bad.append(f'{p.name}: no browser_available() guard')
                continue
            for m in re.finditer(r'@unittest\.skipUnless\(\s*([^,]+),', src):
                if m.group(1).strip() != 'browser_available()':
                    bad.append(f'{p.name}: skipUnless({m.group(1).strip()}) — '
                               f'use browser_available(), an import check does '
                               f'not prove a browser exists')
        self.assertEqual(bad, [], '\n'.join(bad))

    def test_every_e2e_class_is_actually_guarded(self):
        # A new unguarded class in an otherwise-guarded file is the regression
        # this catches: the file imports the probe, one class forgets it.
        bad = []
        for p in self.E2E:
            tree = ast.parse(p.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if not any(isinstance(b, ast.Attribute) and b.attr == 'TestCase'
                           for b in node.bases):
                    continue
                decorated = any(
                    isinstance(d, ast.Call)
                    and getattr(d.func, 'attr', '') == 'skipUnless'
                    for d in node.decorator_list)
                if not decorated:
                    bad.append(f'{p.name}::{node.name} has no skipUnless guard')
        self.assertEqual(bad, [], '\n'.join(bad))

    def test_make_test_fast_excludes_every_e2e_file(self):
        _require_sources(self)
        mk = MAKEFILE.read_text()
        m = re.search(r'^test-fast:\n((?:\t.*\n|.*\\\n)+)', mk, re.M)
        self.assertIsNotNone(m, 'test-fast target not found in the Makefile')
        recipe = m.group(1)
        # Globbed, not hand-listed — a literal per-file list goes stale silently.
        self.assertIn('E2E_TESTS', recipe,
                      'test-fast must exclude $(E2E_TESTS) (the tests/*e2e*.py '
                      'glob), not a hand-maintained list that goes stale')
        self.assertRegex(mk, r'E2E_TESTS\s*:?=\s*\$\(wildcard tests/\*e2e\*\.py\)')


if __name__ == '__main__':
    unittest.main()
