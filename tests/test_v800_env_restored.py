#!/usr/bin/env python3
"""8.0.0: a test module puts the request variables back, and never writes one at import time.

`api._env()` reads the process environment for a request that sets none of its own, so a module that left REQUEST_METHOD, PATH_INFO or QUERY_STRING behind was read by the next
module that did not set its own. Two modules failed a later test that way in a subset run (test_v500_features and tests/routing_harness.py, found at 8.0.0). Counted by syntax tree
at 8.0.0: 167 test files write a request variable, 79 of them never put it back, and 72 write one at import time (216 writes), where discovery runs them all before the first test,
so the last module imported decided what every module saw until it set its own. They now write in setUpModule and `tests/env_guard.py` puts the variables back in tearDownModule.

The population here is every tests/test_*.py, read by syntax tree, and two rules hold at ceiling zero: no module-level write, and no module that writes without a way back. Each
rule has a control that fails when the scan finds nothing, and the guard has its own cases.

8.0.2: the scan followed the name `os` only. A module that imports it under another name (`import os as _os` in a helper, 61 of the modules import it that way or import `environ`
itself) was not in the population at all, and five of them wrote request variables and never put them back: test_improvements_w1 and test_improvements_w3 and test_v410 (QUERY_STRING,
and HTTP_HOST), test_v342 (REQUEST_METHOD) and test_synology (three variables, written at import). The next module that did not set its own QUERY_STRING read the one left behind:
tests.test_v640_client_errors answered a list instead of an object after test_improvements_w1, in a shared process only. The scan follows every name `os` is imported as, and
`from os import environ [as ...]`.
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


def os_names(tree):
    """(the names `os` is imported as anywhere in the module, the names `environ` is imported as). A function-level `import os as _os` counts: it is where the aliases are."""
    names, environ = {'os'}, set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.asname or a.name for a in n.names if a.name == 'os'}
        elif isinstance(n, ast.ImportFrom) and n.module == 'os':
            environ |= {a.asname or a.name for a in n.names if a.name == 'environ'}
    return names, environ


def is_env(node, names=('os',), environ=()):
    if isinstance(node, ast.Attribute) and node.attr == 'environ' and isinstance(node.value, ast.Name) and node.value.id in names:
        return True
    return isinstance(node, ast.Name) and node.id in environ


def writes_in(node, names=('os',), environ=()):
    """The request variables a statement writes into os.environ: os.environ[K] = ..., os.environ.setdefault(K, ...), os.environ.update({K: ...}), under any name `os` has."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and is_env(t.value, names, environ) and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str) and env_guard.REQUEST_VAR.match(t.slice.value):
                    out.append(t.slice.value)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and is_env(n.func.value, names, environ):
            if n.func.attr == 'setdefault' and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and env_guard.REQUEST_VAR.match(n.args[0].value):
                out.append(n.args[0].value)
            if n.func.attr == 'update' and n.args and isinstance(n.args[0], ast.Dict):
                out += [k.value for k in n.args[0].keys if isinstance(k, ast.Constant) and isinstance(k.value, str) and env_guard.REQUEST_VAR.match(k.value)]
    return out


def has_a_way_back(tree, names=('os',), environ=()):
    """Whether the module gives the request variables back with the hooks of tests/env_guard.py: `env_guard.save` in setUpModule and `env_guard.restore` in tearDownModule.

    8.0.2: the rule used to take any pop, del, clear, update by a variable or patch.dict in the file as a way back, and then a pop of the constants a module wrote. Every module that writes a
    request variable was then run in a process of its own and the variables compared before and after (173 modules, `dev-tools/sweep-8.0.2/env_census2.py`): 22 left some behind, among them
    ones that popped a variable, cleared the environment in a helper or patched it with a dictionary. A construct that looks like a way back is not one until it is run, so the only way
    back this accepts is the one that was run and measured: the hooks, which restore what the module found whatever it did in between."""
    saved = restored = False
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == 'setUpModule':
            saved = any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'env_guard.save' for c in ast.walk(n))
        elif isinstance(n, ast.FunctionDef) and n.name == 'tearDownModule':
            restored = any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'env_guard.restore' for c in ast.walk(n))
    return saved and restored


def scan(source):
    """(request variables written at module level, request variables written anywhere, whether there is a way back)."""
    tree = ast.parse(source)
    names, environ = os_names(tree)
    at_import = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            at_import += writes_in(stmt, names, environ)
    return at_import, writes_in(tree, names, environ), has_a_way_back(tree, names, environ)


def population():
    return {p.name: scan(p.read_text(errors='replace')) for p in sorted(_TESTS.glob('test_*.py'))}


# A module that writes request variables and is let off the hooks, with the reason. Its own subject: the tests of the guard save the whole environment in setUp and put it back in tearDown.
EXEMPT = {
    'test_v800_env_restored.py': 'the tests of env_guard itself: TestTheGuard saves the whole environment in setUp and restores it in tearDown, which is the thing under test',
}


LEAKS_AT_IMPORT = "import os\nos.environ['REQUEST_METHOD'] = 'GET'\n\nclass T:\n    pass\n"
LEAKS_IN_A_TEST = "import os\n\nclass T:\n    def test_x(self):\n        os.environ['PATH_INFO'] = '/x'\n"
LEAKS_BY_AN_ALIAS = "class T:\n    def test_x(self):\n        import os as _os\n        _os.environ['QUERY_STRING'] = 'q=1'\n"
LEAKS_BY_AN_ALIAS_AT_IMPORT = "import os as _os\n_os.environ.setdefault('REQUEST_METHOD', 'GET')\n"
LEAKS_BY_AN_IMPORTED_ENVIRON = "from os import environ as E\n\nclass T:\n    def test_x(self):\n        E['PATH_INFO'] = '/x'\n"
PARTIAL_POP = "import os\n\ndef f():\n    os.environ['REQUEST_METHOD'] = 'GET'\n    os.environ['PATH_INFO'] = '/x'\n    os.environ.pop('HTTP_X_TOKEN', None)\n"
FULL_POP = "import os\n\ndef f():\n    os.environ['REQUEST_METHOD'] = 'GET'\n    os.environ['PATH_INFO'] = '/x'\n    os.environ.pop('REQUEST_METHOD', None)\n    del os.environ['PATH_INFO']\n"
GUARDED = ("import os\n\ndef setUpModule():\n    import env_guard\n    env_guard.save(__name__)\n    os.environ['REQUEST_METHOD'] = 'GET'\n\n"
           "def tearDownModule():\n    import env_guard\n    env_guard.restore(__name__)\n")


class TestTheScan(unittest.TestCase):

    def test_it_sees_a_write_at_import_a_write_in_a_test_and_a_module_that_puts_it_back(self):
        self.assertEqual(scan(LEAKS_AT_IMPORT), (['REQUEST_METHOD'], ['REQUEST_METHOD'], False), 'control: a module-level write is found')
        self.assertEqual(scan(LEAKS_IN_A_TEST), ([], ['PATH_INFO'], False), 'control: a write inside a test is found, and is not an import-time write')
        self.assertEqual(scan(GUARDED), ([], ['REQUEST_METHOD'], True), 'control: the hooks are a way back, and a write in setUpModule is not an import-time write')
        self.assertEqual(scan("import os\nos.environ['RP_DATA_DIR'] = '/x'\n")[:2], ([], []), 'control: a variable that is not a request variable is not counted')

    def test_a_pop_of_another_variable_is_not_a_way_back(self):
        self.assertEqual(scan(PARTIAL_POP), ([], ['REQUEST_METHOD', 'PATH_INFO'], False), 'control: popping HTTP_X_TOKEN does not put REQUEST_METHOD and PATH_INFO back')
        self.assertEqual(scan(FULL_POP), ([], ['REQUEST_METHOD', 'PATH_INFO'], False), 'control: nor is a pop and a del of exactly what is written, which is only as good as the code that runs it')
        self.assertEqual(scan(PARTIAL_POP + "    os.environ.clear()\n")[2], False, 'control: nor a clear')
        self.assertEqual(scan("import os\nfrom unittest import mock\n\ndef f():\n    os.environ['REQUEST_METHOD'] = 'GET'\n    with mock.patch.dict(os.environ, {}):\n        pass\n")[2], False, 'control: nor a patch.dict')
        self.assertEqual(scan(GUARDED)[2], True, 'control: the hooks are')
        only_save = "import os\n\ndef setUpModule():\n    import env_guard\n    env_guard.save(__name__)\n    os.environ['REQUEST_METHOD'] = 'GET'\n"
        only_restore = "import os\n\ndef tearDownModule():\n    import env_guard\n    env_guard.restore(__name__)\n\ndef f():\n    os.environ['REQUEST_METHOD'] = 'GET'\n"
        self.assertEqual((scan(only_save)[2], scan(only_restore)[2]), (False, False), 'control: the two hooks are needed together: a restore with no save undoes nothing, a save with no restore is a leak')

    def test_it_follows_the_other_names_of_os_and_environ(self):
        self.assertEqual(scan(LEAKS_BY_AN_ALIAS), ([], ['QUERY_STRING'], False), 'control: a write through `import os as _os` inside a test is found (it was not, until 8.0.2)')
        self.assertEqual(scan(LEAKS_BY_AN_ALIAS_AT_IMPORT), (['REQUEST_METHOD'], ['REQUEST_METHOD'], False), 'control: so is a write at import through an alias')
        self.assertEqual(scan(LEAKS_BY_AN_IMPORTED_ENVIRON), ([], ['PATH_INFO'], False), 'control: and one through `from os import environ as E`')
        self.assertEqual(scan("import os as _os\n_os.environ['RP_DATA_DIR'] = '/x'\n")[:2], ([], []), 'control: an alias does not make every variable a request variable')

    def test_the_population_is_the_whole_suite(self):
        pop = population()
        self.assertGreater(len(pop), 1000, 'the population was read')
        writers = [n for n, (_, w, _) in pop.items() if w]
        self.assertGreater(len(writers), 150, 'control: the modules that write a request variable were found (167 at 8.0.0)')
        guarded = [n for n, (_, w, back) in pop.items() if w and back]
        self.assertGreater(len(guarded), 150, 'control: the modules that have the hooks were found (102 at 8.0.0, 172 at 8.0.2, when the census made every writer have them)')
        trees = {p.name: ast.parse(p.read_text(errors='replace')) for p in sorted(_TESTS.glob('test_*.py'))}
        aliased = [n for n, t in trees.items() if os_names(t) != ({'os'}, set())]
        self.assertGreater(len(aliased), 50, 'control: the modules that import os or environ under another name were found (61 at 8.0.2)')
        only_by_alias = [n for n in aliased if len(writes_in(trees[n], *os_names(trees[n]))) > len(writes_in(trees[n]))]
        self.assertGreater(len(only_by_alias), 4, 'control: the modules that write a request variable only under another name of os were found (five at 8.0.2, each now given the hooks)')


class TestEveryTestModule(unittest.TestCase):

    def test_no_module_writes_a_request_variable_at_import(self):
        bad = {n: at for n, (at, _, _) in population().items() if at}
        self.assertEqual(bad, {}, 'a request variable written at import runs at discovery, before any test, and stays for every module: write it in setUpModule and use tests/env_guard.py')

    def test_every_module_that_writes_one_has_a_way_back(self):
        bad = sorted(n for n, (_, w, back) in population().items() if w and not back and n not in EXEMPT)
        self.assertEqual(bad, [], 'these modules write a request variable and do not give it back with the hooks: give them setUpModule/tearDownModule as tests/env_guard.py shows')

    def test_the_exemptions_are_still_needed(self):
        pop = population()
        for name, why in EXEMPT.items():
            self.assertTrue(why.strip(), name)
            self.assertIn(name, pop, 'the exemption names a module that is not there: remove it')
            self.assertTrue(pop[name][1] and not pop[name][2], 'the module writes a request variable and has the hooks now, or writes none: remove the exemption: ' + name)


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
