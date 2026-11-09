#!/usr/bin/env python3
"""8.0.0: a test module puts the request variables back, and never writes one at import time.

`api._env()` reads the process environment for a request that sets none of its own, so a module that left REQUEST_METHOD, PATH_INFO or QUERY_STRING behind was read by the next
module that did not set its own. Two modules failed a later test that way in a subset run (test_v500_features and tests/routing_harness.py, found at 8.0.0). Counted by syntax tree
at 8.0.0: 167 test files write a request variable, 79 of them never put it back, and 72 write one at import time (216 writes), where discovery runs them all before the first test,
so the last module imported decided what every module saw until it set its own. They now write in setUpModule and `tests/env_guard.py` puts the variables back in tearDownModule.

The population here is every tests/test_*.py, read by syntax tree, and two rules hold at ceiling zero: no module-level write, and no module that writes without a way back. Each
rule has a control that fails when the scan finds nothing, and the guard has its own cases.
"""

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))

import env_guard  # noqa: E402


def is_env(node):
    return isinstance(node, ast.Attribute) and node.attr == 'environ' and isinstance(node.value, ast.Name) and node.value.id == 'os'


def writes_in(node):
    """The request variables a statement writes into os.environ: os.environ[K] = ..., os.environ.setdefault(K, ...), os.environ.update({K: ...})."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and is_env(t.value) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str) and env_guard.REQUEST_VAR.match(t.slice.value):
                    out.append(t.slice.value)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and is_env(n.func.value):
            if n.func.attr == 'setdefault' and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and env_guard.REQUEST_VAR.match(n.args[0].value):
                out.append(n.args[0].value)
            if n.func.attr == 'update' and n.args and isinstance(n.args[0], ast.Dict):
                out += [k.value for k in n.args[0].keys if isinstance(k, ast.Constant) and isinstance(k.value, str) and env_guard.REQUEST_VAR.match(k.value)]
    return out


def has_a_way_back(tree):
    """A call to env_guard.restore inside tearDownModule, or any construct in the file that can undo a write (pop, clear, del, patch.dict, monkeypatch, an assignment by a variable key)."""
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == 'tearDownModule':
            if any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'env_guard.restore' for c in ast.walk(n)):
                return True
    for n in ast.walk(tree):
        if isinstance(n, ast.Delete) and any(isinstance(t, ast.Subscript) and is_env(t.value) for t in n.targets):
            return True
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if is_env(t) or (isinstance(t, ast.Subscript) and is_env(t.value) and not isinstance(t.slice, ast.Constant)):
                    return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if is_env(n.func.value) and (n.func.attr in ('pop', 'clear') or (n.func.attr == 'update' and not (n.args and isinstance(n.args[0], ast.Dict)))):
                return True
            if n.func.attr == 'dict' and n.args and (is_env(n.args[0]) or (isinstance(n.args[0], ast.Constant) and n.args[0].value == 'os.environ')):
                return True
            if n.func.attr in ('setenv', 'delenv'):
                return True
    return False


def scan(source):
    """(request variables written at module level, request variables written anywhere, whether there is a way back)."""
    tree = ast.parse(source)
    at_import = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            at_import += writes_in(stmt)
    return at_import, writes_in(tree), has_a_way_back(tree)


def population():
    return {p.name: scan(p.read_text(errors='replace')) for p in sorted(_TESTS.glob('test_*.py'))}


LEAKS_AT_IMPORT = "import os\nos.environ['REQUEST_METHOD'] = 'GET'\n\nclass T:\n    pass\n"
LEAKS_IN_A_TEST = "import os\n\nclass T:\n    def test_x(self):\n        os.environ['PATH_INFO'] = '/x'\n"
GUARDED = ("import os\n\ndef setUpModule():\n    import env_guard\n    env_guard.save(__name__)\n    os.environ['REQUEST_METHOD'] = 'GET'\n\n"
           "def tearDownModule():\n    import env_guard\n    env_guard.restore(__name__)\n")


class TestTheScan(unittest.TestCase):

    def test_it_sees_a_write_at_import_a_write_in_a_test_and_a_module_that_puts_it_back(self):
        self.assertEqual(scan(LEAKS_AT_IMPORT), (['REQUEST_METHOD'], ['REQUEST_METHOD'], False), 'control: a module-level write is found')
        self.assertEqual(scan(LEAKS_IN_A_TEST), ([], ['PATH_INFO'], False), 'control: a write inside a test is found, and is not an import-time write')
        self.assertEqual(scan(GUARDED), ([], ['REQUEST_METHOD'], True), 'control: the hooks are a way back, and a write in setUpModule is not an import-time write')
        self.assertEqual(scan("import os\nos.environ['RP_DATA_DIR'] = '/x'\n"), ([], [], False), 'control: a variable that is not a request variable is not counted')

    def test_the_population_is_the_whole_suite(self):
        pop = population()
        self.assertGreater(len(pop), 1000, 'the population was read')
        writers = [n for n, (_, w, _) in pop.items() if w]
        self.assertGreater(len(writers), 150, 'control: the modules that write a request variable were found (167 at 8.0.0)')
        guarded = [n for n, (_, w, _) in pop.items() if w and 'env_guard' in (_TESTS / n).read_text()]
        self.assertGreater(len(guarded), 90, 'control: the modules that were given the hooks were found (102 at 8.0.0)')


class TestEveryTestModule(unittest.TestCase):

    def test_no_module_writes_a_request_variable_at_import(self):
        bad = {n: at for n, (at, _, _) in population().items() if at}
        self.assertEqual(bad, {}, 'a request variable written at import runs at discovery, before any test, and stays for every module: write it in setUpModule and use tests/env_guard.py')

    def test_every_module_that_writes_one_has_a_way_back(self):
        bad = sorted(n for n, (_, w, back) in population().items() if w and not back)
        self.assertEqual(bad, [], 'these modules write a request variable and never put it back; give them setUpModule/tearDownModule as tests/env_guard.py shows')


class TestTheGuard(unittest.TestCase):

    def setUp(self):
        self._before = dict(os.environ)
        for k in env_guard.request_vars():
            del os.environ[k]
        os.environ['QUERY_STRING'] = 'by=site'
        os.environ['REQUEST_METHOD'] = 'PUT'

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._before)

    def test_a_variable_set_since_is_removed_and_one_that_was_changed_is_reset(self):
        env_guard.save('m')
        os.environ['PATH_INFO'] = '/api/x'
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ['HTTP_X_TOKEN'] = 'secret'
        os.environ['RP_DATA_DIR'] = tempfile.gettempdir()          # not a request variable: left alone
        env_guard.restore('m')
        self.assertEqual(env_guard.request_vars(), {'QUERY_STRING': 'by=site', 'REQUEST_METHOD': 'PUT'})
        self.assertEqual(os.environ['RP_DATA_DIR'], tempfile.gettempdir())

    def test_a_variable_that_was_removed_comes_back(self):
        env_guard.save('m')
        del os.environ['QUERY_STRING']
        env_guard.restore('m')
        self.assertEqual(os.environ['QUERY_STRING'], 'by=site')

    def test_restoring_a_module_that_was_not_saved_changes_nothing(self):
        os.environ['PATH_INFO'] = '/kept'
        env_guard.restore('never-saved')
        self.assertEqual(os.environ['PATH_INFO'], '/kept')

    def test_two_modules_keep_their_own_state(self):
        env_guard.save('a')
        os.environ['PATH_INFO'] = '/a'
        env_guard.save('b')
        os.environ['PATH_INFO'] = '/b'
        env_guard.restore('b')
        self.assertEqual(os.environ['PATH_INFO'], '/a')
        env_guard.restore('a')
        self.assertNotIn('PATH_INFO', os.environ)


if __name__ == '__main__':
    unittest.main()
