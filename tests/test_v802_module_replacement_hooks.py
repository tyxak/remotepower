#!/usr/bin/env python3
"""8.0.2: a test module that changes an entry of sys.modules while it runs has the hooks of tests/api_guard.py.

Thirteen modules (test_audit_log_wrapped, test_mitigate, test_v302 ...) take `api` or `storage` out of sys.modules in a test and import it again, and leave the new copy under the name.
A module that was imported earlier keeps the first copy in its own `api`, so what the guard restored was not the copy that module used. The export test of
`test_tenant_password_reset_and_export` then found five stores in other modules' directories and the archive had no users.json, in some large shared runs only. A census of every non-browser
module, one process each, found the thirteen (dev-tools/sweep-8.0.2/full_census.py).

The scan reads every tests/test_*.py by syntax tree for an assignment to, a deletion from, or a pop / popitem / setdefault / update / clear on sys.modules inside a function, under any name `sys`
is imported as (and `from sys import modules`). The key is not looked at: in half of the modules it is a variable (`for mod in ('api', 'storage'): del sys.modules[mod]`), so a rule on the key
would be a rule on one spelling. `mock.patch.dict(sys.modules, ...)` is left out because it puts the dictionary back itself, and so is a change at import time, which the hooks run too late to undo.

The only accepted way back is the hooks: `api_guard.save` in setUpModule and `api_guard.restore` in tearDownModule. They put back every copy of `api` and `storage` the module can reach, the
entries of sys.modules for them and the RP_* variables. A module that sets some other entry (a stub of `yaml`) gets the hooks too, which cost nothing: the scan cannot tell which entry a
variable names, and a module that is let off for the key it uses is the one that changes the key.
"""

import ast
import functools
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent

_MUTATORS = ('pop', 'popitem', 'setdefault', 'update', 'clear')


def sys_names(tree):
    """(the names `sys` is imported as anywhere in the module, the names `modules` is imported as from it). A function-level `import sys as _sys` counts."""
    names, modules = {'sys'}, set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.asname or a.name for a in n.names if a.name == 'sys'}
        elif isinstance(n, ast.ImportFrom) and n.module == 'sys':
            modules |= {a.asname or a.name for a in n.names if a.name == 'modules'}
    return names, modules


def _is_modules(node, names, modules):
    if isinstance(node, ast.Attribute) and node.attr == 'modules' and isinstance(node.value, ast.Name) and node.value.id in names:
        return True
    return isinstance(node, ast.Name) and node.id in modules


def changes_in_functions(source):
    """The kinds of change a module makes to sys.modules inside a function: 'assign', 'del', or the name of the method called."""
    tree = ast.parse(source)
    names, modules = sys_names(tree)
    found = []

    def visit(node, in_function):
        for child in ast.iter_child_nodes(node):
            inside = in_function or isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            if inside:
                if isinstance(child, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    for t in (child.targets if isinstance(child, ast.Assign) else [child.target]):
                        if isinstance(t, ast.Subscript) and _is_modules(t.value, names, modules):
                            found.append('assign')
                elif isinstance(child, ast.Delete):
                    for t in child.targets:
                        if isinstance(t, ast.Subscript) and _is_modules(t.value, names, modules):
                            found.append('del')
                elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in _MUTATORS and _is_modules(child.func.value, names, modules):
                    found.append(child.func.attr)
            visit(child, inside)

    visit(tree, False)
    return found


def has_the_hooks(source):
    """`api_guard.save` in setUpModule and `api_guard.restore` in tearDownModule, both at the top level of the module."""
    saved = restored = False
    for n in ast.parse(source).body:
        if isinstance(n, ast.FunctionDef) and n.name == 'setUpModule':
            saved = any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'api_guard.save' for c in ast.walk(n))
        elif isinstance(n, ast.FunctionDef) and n.name == 'tearDownModule':
            restored = any(isinstance(c, ast.Call) and ast.unparse(c.func) == 'api_guard.restore' for c in ast.walk(n))
    return saved and restored


@functools.lru_cache(maxsize=None)
def population():
    """{module file name: (the kinds of change, whether it has the hooks)} for every tests/test_*.py that changes sys.modules in a function. Parsed once: 1,300 files."""
    out = {}
    for p in sorted(_TESTS.glob('test_*.py')):
        try:
            source = p.read_text(encoding='utf-8')
            changes = changes_in_functions(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        if changes:
            out[p.name] = (changes, has_the_hooks(source))
    return out


# A module that changes sys.modules in a function and is let off the hooks, with the reason.
EXEMPT = {
    'test_api_guard.py': 'the tests of api_guard itself: each puts fake modules into sys.modules for one test and takes them out again in a cleanup, which is the thing under test',
}

DELETES_BY_NAME = "import sys\n\nclass T:\n    def setUp(self):\n        if 'api' in sys.modules:\n            del sys.modules['api']\n"
POPS_BY_A_VARIABLE = "import sys\n\ndef f():\n    for mod in ('api', 'storage'):\n        sys.modules.pop(mod, None)\n"
DELETES_BY_A_VARIABLE = "import sys\n\ndef f(mod):\n    del sys.modules[mod]\n"
ASSIGNS = "import sys\n\ndef f(m):\n    sys.modules['api'] = m\n"
ASSIGNS_BY_AN_ALIAS = "def f(m):\n    import sys as _sys\n    _sys.modules['api'] = m\n"
ASSIGNS_BY_AN_IMPORTED_NAME = "from sys import modules as M\n\ndef f(m):\n    M['api'] = m\n"
UPDATES = "import sys\n\ndef f(d):\n    sys.modules.update(d)\n"
AT_IMPORT_ONLY = "import sys\nsys.modules['api'] = object()\n\nclass T:\n    def test_x(self):\n        pass\n"
PATCHES_THE_DICT = "import sys\nfrom unittest import mock\n\ndef f():\n    with mock.patch.dict(sys.modules, {'api': None}):\n        pass\n"
ONLY_READS = "import sys\n\ndef f():\n    a = sys.modules['api']\n    b = sys.modules.get('storage')\n    return 'api' in sys.modules, a, b\n"
GUARDED = ("import sys\n\ndef setUpModule():\n    import api_guard\n    api_guard.save(__name__)\n\n"
           "def tearDownModule():\n    import api_guard\n    api_guard.restore(__name__)\n")


class TestTheScan(unittest.TestCase):

    def test_what_it_finds(self):
        for label, source, kinds in (
            ('a delete by name', DELETES_BY_NAME, ['del']),
            ('a pop with a variable for the key', POPS_BY_A_VARIABLE, ['pop']),
            ('a delete with a variable for the key', DELETES_BY_A_VARIABLE, ['del']),
            ('an assignment', ASSIGNS, ['assign']),
            ('an assignment under an alias of sys', ASSIGNS_BY_AN_ALIAS, ['assign']),
            ('an assignment through `from sys import modules`', ASSIGNS_BY_AN_IMPORTED_NAME, ['assign']),
            ('an update', UPDATES, ['update']),
        ):
            with self.subTest(label):
                self.assertEqual(changes_in_functions(source), kinds)

    def test_what_it_leaves_alone(self):
        for label, source in (
            ('a change at import time: the hooks run too late to undo it', AT_IMPORT_ONLY),
            ('mock.patch.dict, which puts the dictionary back itself', PATCHES_THE_DICT),
            ('reads only', ONLY_READS),
        ):
            with self.subTest(label):
                self.assertEqual(changes_in_functions(source), [])

    def test_the_hooks_are_found_only_as_a_pair_at_the_top_of_the_module(self):
        self.assertTrue(has_the_hooks(GUARDED))
        self.assertFalse(has_the_hooks(DELETES_BY_NAME))
        self.assertFalse(has_the_hooks(GUARDED.replace('api_guard.restore(__name__)', 'pass')), 'a save with no restore is not a way back')
        self.assertFalse(has_the_hooks(GUARDED.replace('api_guard.save(__name__)', 'pass')), 'a restore with no save puts back nothing')
        self.assertFalse(has_the_hooks("import sys\n\nclass T:\n    @classmethod\n    def setUpModule(cls):\n        import api_guard\n        api_guard.save(__name__)\n"
                                       "    def tearDownModule(cls):\n        import api_guard\n        api_guard.restore(__name__)\n"),
                         'the hooks of a class are not module fixtures')


class TestEveryTestModule(unittest.TestCase):

    def test_the_population_is_not_empty(self):
        pop = population()
        self.assertGreaterEqual(len(pop), 25, 'the scan found %d modules that change sys.modules in a function; a scan that finds nothing is a broken scan' % len(pop))
        for known in ('test_audit_log_wrapped.py', 'test_mitigate.py', 'test_v302.py', 'test_acme.py'):
            self.assertIn(known, pop, '%s replaces api in sys.modules while it runs and must be in the population' % known)

    def test_every_module_that_changes_sys_modules_in_a_function_has_the_hooks(self):
        bad = sorted('%s: %s' % (name, ', '.join(sorted(set(changes)))) for name, (changes, hooked) in population().items() if not hooked and name not in EXEMPT)
        self.assertEqual(bad, [], '\n\nthese modules change an entry of sys.modules in a function and have no api_guard hooks, so the next module of the process meets what they left '
                                  '(tests/api_guard.py, the module docstring above): give each setUpModule `api_guard.save(__name__)` and tearDownModule `api_guard.restore(__name__)`, '
                                  'or run dev-tools/sweep-8.0.2/add_api_hooks.py <stem>')

    def test_an_exemption_that_stops_applying_fails_so_the_list_only_shrinks(self):
        pop = population()
        for name in EXEMPT:
            self.assertIn(name, pop, '%s is exempt and no longer changes sys.modules in a function: remove it from EXEMPT' % name)
            self.assertFalse(pop[name][1], '%s is exempt and has the hooks now: remove it from EXEMPT' % name)


if __name__ == '__main__':
    unittest.main()
