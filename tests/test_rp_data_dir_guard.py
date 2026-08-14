#!/usr/bin/env python3
"""A test module that executes api.py must pin RP_DATA_DIR at import time.

api.py calls `ensure_default_user()` at import, which WRITES to `DATA_DIR`. So
a test module that execs it without first setting `RP_DATA_DIR` targets
whatever the default is — `/var/lib/remotepower` — and on a machine with a live
install that means the test suite overwrites the install's admin user.

Thirteen modules were missing the guard and the suite was green, because
`unittest discover` runs everything in ONE process: whichever module set the
variable first set it for all of them, and the order that produced happened to
be a working one. Run any of those on its own, or under xdist where each worker
is a separate process, and it reaches for the real directory. That is how it
surfaced — a targeted run of the release-pin files raised `PermissionError:
/var/lib/remotepower/users.json.lock`, which on this dev box is a refusal and
on a server would have been a successful write.

EVERYTHING HERE IS AST-BASED, and that is the interesting part of the file.
Three earlier drafts scanned source TEXT, and each produced a confident result
that was wrong:

* `'RP_DATA_DIR' in src` was satisfied by the explanatory COMMENT above the
  guard — so the fail-demo, deleting a guard, changed nothing, and the gate
  looked like it worked;
* anchoring on `spec_from_file_location` flagged test_api.py, which sets the
  variable in the two lines between creating the spec and executing it;
* matching any spec call flagged test_v500_perf (loads storage.py) and
  test_windows_agent (loads the Windows agent), and matching raw text flagged
  test_v642_config_secret_at_rest, whose api.py exec lives inside a subprocess
  PROBE STRING that carries its own correct guard.

A string literal's contents are not AST nodes of the module containing them,
which is exactly the distinction all three drafts needed.
"""
import ast
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent


def _tree(src):
    try:
        return ast.parse(src)
    except SyntaxError:
        return None


def _spec_loads_api(node):
    """A `spec_from_file_location(..., <something ending in api.py>)` call."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '')
    if name != 'spec_from_file_location':
        return False
    for arg in node.args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and sub.value.endswith('api.py'):
                return True
    return False


def _imports_api(node):
    if isinstance(node, ast.Import):
        return any(a.name == 'api' for a in node.names)
    if isinstance(node, ast.ImportFrom):
        return node.module == 'api'
    if isinstance(node, ast.Call):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', '')
        if name == 'import_module' and node.args:
            a = node.args[0]
            return isinstance(a, ast.Constant) and a.value == 'api'
    return False


def _api_exec_lineno(src):
    """Line where api.py's module body actually RUNS, or None."""
    tree = _tree(src)
    if tree is None:
        return None
    spec_lines, exec_lines, direct = [], [], []
    for node in ast.walk(tree):
        if _spec_loads_api(node):
            spec_lines.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == 'exec_module':
            exec_lines.append(node.lineno)
        if _imports_api(node):
            direct.append(node.lineno)
    out = list(direct)
    for s in spec_lines:
        after = [e for e in exec_lines if e >= s]
        out.append(min(after) if after else s)
    return min(out) if out else None


def _guard_lineno(src):
    """Line where RP_DATA_DIR is SET at module scope, or None."""
    tree = _tree(src)
    if tree is None:
        return None

    def _is_rp(n):
        return isinstance(n, ast.Constant) and n.value == 'RP_DATA_DIR'

    best = None
    for node in ast.walk(tree):
        ln = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ('setdefault', 'putenv') \
                and node.args and _is_rp(node.args[0]):
            ln = node.lineno
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and _is_rp(t.slice):
                    ln = node.lineno
        if ln is not None:
            best = ln if best is None else min(best, ln)
    return best


def _modules():
    me = Path(__file__).name
    return sorted(p for p in _TESTS.glob('test_*.py') if p.name != me)


class TestTheDetectorWorks(unittest.TestCase):
    """Both assertions in the class below are "this list is empty", which a
    detector that matches nothing produces just as happily."""

    def test_it_finds_the_modules_that_run_api(self):
        hits = [p.name for p in _modules()
                if _api_exec_lineno(p.read_text(encoding='utf-8')) is not None]
        self.assertGreater(len(hits), 100,
                           f'only {len(hits)} modules detected as running '
                           f'api.py — the detector is broken')

    def test_it_recognises_each_idiom(self):
        for src in ("spec = spec_from_file_location('api', p / 'api.py')\n"
                    "spec.loader.exec_module(m)\n",
                    "importlib.import_module('api')\n",
                    'import api\n',
                    'from api import respond\n'):
            self.assertIsNotNone(_api_exec_lineno(src), src)

    def test_it_ignores_a_sibling_module_load(self):
        self.assertIsNone(_api_exec_lineno(
            "spec = spec_from_file_location('storage', p / 'storage.py')\n"
            "spec.loader.exec_module(m)\n"))

    def test_it_ignores_code_inside_a_string(self):
        """test_v642_config_secret_at_rest execs api.py in a SUBPROCESS, from a
        probe string that carries its own guard. Scanning raw text called that
        an unguarded module."""
        self.assertIsNone(_api_exec_lineno("PROBE = '''\nimport api\n'''\n"))

    def test_the_guard_finder_reads_code_not_comments(self):
        """The bug this file's own fail-demo caught: a substring search is
        satisfied by the comment that explains the guard, so deleting the guard
        changed nothing and the gate still passed."""
        self.assertIsNone(_guard_lineno('# sets RP_DATA_DIR below\nx = 1\n'))
        self.assertIsNone(_guard_lineno('s = "RP_DATA_DIR"\n'))
        self.assertEqual(
            _guard_lineno("os.environ.setdefault('RP_DATA_DIR', '/t')\n"), 1)
        self.assertEqual(_guard_lineno("os.environ['RP_DATA_DIR'] = '/t'\n"), 1)


class TestEveryExecutingModuleIsGuarded(unittest.TestCase):

    def test_none_are_missing_the_guard(self):
        bad = [p.name for p in _modules()
               for src in [p.read_text(encoding='utf-8')]
               if _api_exec_lineno(src) is not None and _guard_lineno(src) is None]
        self.assertEqual(
            bad, [],
            'these modules execute api.py without pinning RP_DATA_DIR first, '
            "so api.py's import-time ensure_default_user() writes to the REAL "
            'data directory. Add at module scope, ABOVE the import:\n'
            "    os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())\n"
            + '\n'.join('  ' + b for b in bad))

    def test_the_guard_precedes_the_execution(self):
        """Setting it after api.py has already run is no guard at all."""
        late = []
        for p in _modules():
            src = p.read_text(encoding='utf-8')
            g, i = _guard_lineno(src), _api_exec_lineno(src)
            if g is not None and i is not None and i < g:
                late.append(f'{p.name} (guard line {g}, api.py runs at line {i})')
        self.assertEqual(
            late, [],
            'the RP_DATA_DIR guard appears AFTER api.py is executed, so the '
            'import-time write already went to the default directory:\n'
            + '\n'.join('  ' + x for x in late))


if __name__ == '__main__':
    unittest.main()
