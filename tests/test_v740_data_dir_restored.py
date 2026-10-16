"""A test that points RP_DATA_DIR somewhere puts back what was there.

Eleven test classes set RP_DATA_DIR to their own temporary directory in
setUpClass and ended with os.environ.pop('RP_DATA_DIR') in tearDownClass. That
removed the value the session had, too. unittest discover is one process: every
module's own setdefault ran when the modules were loaded, before any test, so
after one of those classes there was no RP_DATA_DIR at all. A later test that
imported api afresh (26 test functions do) then ran api.py's import-time
ensure_default_user() against the product's default, /var/lib/remotepower: a
permission error on a dev box, and a write into a real install on a machine that
has one. It showed as test_v360 failing after test_v380 in a shuffled order.

The rule: remember the previous value before setting yours, and in cleanup
restore it; remove the variable only when there was none before.
"""
import ast
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent


def _is_env_data_dir(node):
    """os.environ['RP_DATA_DIR'] (a Subscript), as an assignment target or del."""
    return (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
            and node.value.attr == 'environ' and isinstance(node.slice, ast.Constant)
            and node.slice.value == 'RP_DATA_DIR')


def _call_of(node, method):
    """os.environ.<method>('RP_DATA_DIR', ...)"""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == method and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == 'environ' and node.args
            and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'RP_DATA_DIR')


def violations(src, name='<src>'):
    """Unconditional removals of RP_DATA_DIR. A removal counts as a restore only
    inside an `if ... is None:` branch (the previous value was absent)."""
    tree = ast.parse(src)
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    out = []
    for node in ast.walk(tree):
        removal = _call_of(node, 'pop') or (isinstance(node, ast.Delete) and any(_is_env_data_dir(t) for t in node.targets))
        if not removal:
            continue
        p, guarded = parents.get(node), False
        while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            if isinstance(p, ast.If) and any(isinstance(c, ast.Compare) and any(isinstance(o, ast.Is) for o in c.ops)
                                              for c in ast.walk(p.test)):
                guarded = True
                break
            p = parents.get(p)
        if not guarded:
            out.append('%s:%d' % (name, node.lineno))
    return out


class TestTheDataDirIsRestored(unittest.TestCase):

    def test_the_scanner_sees_a_pop_and_accepts_a_restore(self):
        """Control: the shape it exists for, and the restore idiom it allows."""
        bad = "import os\ndef tearDownClass(cls):\n    os.environ.pop('RP_DATA_DIR', None)\n"
        good = ("import os\ndef tearDownClass(cls):\n    if cls._prev_dd is None:\n"
                "        os.environ.pop('RP_DATA_DIR', None)\n    else:\n"
                "        os.environ['RP_DATA_DIR'] = cls._prev_dd\n")
        deleted = "import os\ndef f():\n    del os.environ['RP_DATA_DIR']\n"
        self.assertEqual(violations(bad), ['<src>:3'])
        self.assertEqual(violations(good), [])
        self.assertEqual(violations(deleted), ['<src>:3'])

    def test_no_test_removes_the_sessions_data_dir(self):
        files = sorted(_TESTS.glob('test_*.py'))
        self.assertGreater(len(files), 500, 'control: the test files were found')
        bad = []
        for p in files:
            try:
                bad += violations(p.read_text(errors='replace'), p.name)
            except SyntaxError:
                continue
        self.assertEqual(bad, [], 'remember the previous RP_DATA_DIR and restore it; '
                                  'pop only when there was none (see tests/test_pg.py)')


if __name__ == '__main__':
    unittest.main()
