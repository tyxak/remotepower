#!/usr/bin/env python3
"""8.0.0: a test that changes process-wide state hands it back, for the two kinds that decided other modules' results.

`unittest discover` runs the whole suite in one process, so what one module leaves behind is what the next one starts from. Two kinds of leftover turned up while tracing two
interactions that had reproduced since round 12 (each module green alone, red when a particular module ran first):

* the request context. `api._env()` reads `api._RCTX.environ` before `os.environ` whenever it is set, and twelve modules set it to drive a handler and never cleared it. The next
  module, which writes its request variables to `os.environ`, was then answered from the leftover: a 401 in `test_v800_drawer_settings`, a failed list in
  `test_v749_upgrade_mode_drawer`. `tests/conftest.py` clears the context between modules, but conftest is pytest-only and the gate runs `unittest discover`.
* `RP_DATA_DIR`. Two base classes pointed it at a scratch directory, removed the directory and then unset the variable. A module that executes api.py after that, with only the
  import-time pin it had set at import, reaches for `/var/lib/remotepower`: a PermissionError on a development box, a write into the real data directory on a machine with an
  install. The twelve other modules that unset it do so correctly, by putting back the value they replaced; those are the shape to copy.

Both rules are read off the syntax tree of every test module, with a non-empty population and a detector that is shown a leaking source and a clean one first.
"""
import ast
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_ME = Path(__file__).name


def _modules():
    for p in sorted(_TESTS.glob("test_*.py")):
        if p.name == _ME:
            continue
        try:
            yield p.name, ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue


# ── the request context ─────────────────────────────────────────────────────────────

def _is_ctx(node):
    return isinstance(node, ast.Attribute) and node.attr == "environ" and ast.unparse(node).endswith("_RCTX.environ")


def _ctx_state(tree):
    """(sets, resets): `sets` are the line numbers where the context is given a value that is not a restore; `resets` are the restores that sit where a scope ends."""
    saved = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            reads = any(_is_ctx(x) for x in ast.walk(n.value)) or (
                isinstance(n.value, ast.Call) and ast.unparse(n.value.func) == "getattr" and "_RCTX" in ast.unparse(n.value) and "'environ'" in ast.unparse(n.value).replace('"', "'"))
            if reads and not any(_is_ctx(t) for t in n.targets):
                saved.update(ast.unparse(t) for t in n.targets)

    def is_restore(assign):
        v = assign.value
        return (isinstance(v, ast.Constant) and v.value is None) or ast.unparse(v) in saved

    sets, restores = [], []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(_is_ctx(t) for t in n.targets):
            (restores if is_restore(n) else sets).append(n)

    # where a scope ends: tearDown*, a finally block, or a cleanup call
    ends = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name.startswith(("tearDown", "doCleanups")):
            ends.update(id(x) for x in ast.walk(n))
        if isinstance(n, ast.Try):
            for stmt in n.finalbody:
                ends.update(id(x) for x in ast.walk(stmt))
        if isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] in ("addCleanup", "addClassCleanup", "addModuleCleanup") and "_RCTX" in ast.unparse(n):
            ends.update(id(x) for x in ast.walk(n))
    placed = [r for r in restores if id(r) in ends]
    cleanup_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] in ("addCleanup", "addClassCleanup", "addModuleCleanup") and "_RCTX" in ast.unparse(n)]
    return [s.lineno for s in sets], [r.lineno for r in placed] + [c.lineno for c in cleanup_calls]


def _leaves_the_context_set(src):
    sets, resets = _ctx_state(ast.parse(src))
    return bool(sets) and not resets


class TestTheRequestContextIsGivenBack(unittest.TestCase):
    def test_every_module_that_sets_it_clears_it_where_its_scope_ends(self):
        with_sets, offenders = [], []
        for name, tree in _modules():
            sets, resets = _ctx_state(tree)
            if sets:
                with_sets.append(name)
                if not resets:
                    offenders.append(name)
        self.assertGreater(len(with_sets), 15, f"only {len(with_sets)} modules detected as setting the request context: the detector is broken")
        self.assertEqual(offenders, [], f"{len(offenders)} of {len(with_sets)} modules that set api._RCTX.environ never clear it in a tearDown, a finally or a cleanup "
                                        "(add `def tearDownModule(): api._RCTX.environ = None`): " + ", ".join(offenders))

    def test_the_detector_tells_a_leak_from_a_restore(self):
        leaks = [
            "def t():\n    api._RCTX.environ = {'REQUEST_METHOD': 'GET'}\n",
            "class T:\n    def setUp(self):\n        api._RCTX.environ = {}\n",
            "class T:\n    def tearDown(self):\n        pass\n    def go(self):\n        api._RCTX.environ = {}\n",
            "def t():\n    api._RCTX.environ = other\n",                                  # a name that was not read from the context is a value, not a restore
        ]
        clean = [
            "def tearDownModule():\n    api._RCTX.environ = None\n\ndef t():\n    api._RCTX.environ = {}\n",
            "class T:\n    def tearDown(self):\n        api._RCTX.environ = None\n    def go(self):\n        api._RCTX.environ = {}\n",
            "def t():\n    saved = api._RCTX.environ\n    api._RCTX.environ = {}\n    try:\n        pass\n    finally:\n        api._RCTX.environ = saved\n",
            "class T:\n    def setUp(self):\n        self._env = api._RCTX.environ\n        api._RCTX.environ = {}\n    def tearDown(self):\n        api._RCTX.environ = self._env\n",
            "class T:\n    def setUp(self):\n        self.addCleanup(setattr, api._RCTX, 'environ', None)\n        api._RCTX.environ = {}\n",
            "def t():\n    x = 1\n",                                                     # sets nothing
        ]
        for src in leaks:
            with self.subTest(leak=src):
                self.assertTrue(_leaves_the_context_set(src))
        for src in clean:
            with self.subTest(clean=src):
                self.assertFalse(_leaves_the_context_set(src))


# ── RP_DATA_DIR ─────────────────────────────────────────────────────────────────────

def _is_rp(node):
    return isinstance(node, ast.Constant) and node.value == "RP_DATA_DIR"


def _is_unset(n):
    if isinstance(n, ast.Call) and n.args and _is_rp(n.args[0]):
        f = ast.unparse(n.func)
        return f.endswith("environ.pop") or f.split(".")[-1] in ("_clear_env", "unsetenv")
    if isinstance(n, ast.Delete):
        return any(isinstance(t, ast.Subscript) and ast.unparse(t.value).endswith("environ") and _is_rp(t.slice) for t in n.targets)
    return False


def _is_rp_set(n):
    return isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) and ast.unparse(t.value).endswith("environ") and _is_rp(t.slice) for t in n.targets)


def _scope_nodes(root):
    """The nodes of one scope: a function's body, or the module's top-level statements, without descending into the functions and classes inside."""
    stack = list(ast.iter_child_nodes(root))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))


def _put_back_for(unset, root, parents):
    """The variable gets a value again where it is unset: under mock.patch.dict(os.environ, ...), anywhere in the same if/try, or in a later statement of the scope.
    An earlier assignment is not a put-back; it is the value being replaced."""
    cur = unset
    while cur is not root and cur in parents:
        cur = parents[cur]
        if isinstance(cur, ast.With) and any("patch" in ast.unparse(i.context_expr) and "environ" in ast.unparse(i.context_expr) for i in cur.items):
            return True
        if isinstance(cur, (ast.If, ast.Try)) and any(_is_rp_set(x) for x in ast.walk(cur)):
            return True
    return any(_is_rp_set(x) and x.lineno > unset.lineno for x in _scope_nodes(root))


def _unset_sites(tree):
    """[(scope name, line, puts_back)] for every place that unsets RP_DATA_DIR. The scope is the function it sits in, or the module's own top-level statements
    when it sits outside any function (test_v702_seeder_contracts hands the variable back at import time)."""
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    out = []
    roots = [("<module>", tree)] + [(fn.name, fn) for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for name, root in roots:
        for n in _scope_nodes(root):
            if _is_unset(n):
                out.append((name, n.lineno, _put_back_for(n, root, parents)))
    return sorted(set(out))


def _unsets_without_putting_back(src):
    return any(not back for _name, _ln, back in _unset_sites(ast.parse(src)))


class TestRpDataDirIsPutBackNotJustUnset(unittest.TestCase):
    def test_every_unset_is_followed_by_a_value_again(self):
        sites, offenders = [], []
        for name, tree in _modules():
            for fn, ln, back in _unset_sites(tree):
                sites.append(name)
                if not back:
                    offenders.append(f"{name}:{ln} ({fn})")
        self.assertGreater(len(sites), 20, f"only {len(sites)} places detected as unsetting RP_DATA_DIR: the detector is broken")
        self.assertEqual(offenders, [], f"{len(offenders)} of {len(sites)} places unset RP_DATA_DIR and never give it a value again, so the next module that executes "
                                        "api.py with only an import-time pin falls through to /var/lib/remotepower: " + ", ".join(offenders))

    def test_the_detector_tells_unset_from_put_back(self):
        leaks = [
            "import os\ndef down():\n    os.environ.pop('RP_DATA_DIR', None)\n",
            "def _clear_env(*n):\n    pass\ndef down():\n    _clear_env('RP_DATA_DIR')\n",
            "import os\ndef down():\n    del os.environ['RP_DATA_DIR']\n",
            "import os\nos.environ.pop('RP_DATA_DIR', None)\n",                          # at import time, outside any function
            "import os\nos.environ['RP_DATA_DIR'] = 'x'\nos.environ.pop('RP_DATA_DIR', None)\n",   # the earlier set is the value being replaced
            "import os\ndef down():\n    os.environ['RP_DATA_DIR'] = 'x'\n    os.environ.pop('RP_DATA_DIR', None)\n",
            # the capture sits in another function, which is how test_v320 read until it was fixed: reading the old value is not putting it back
            "import os\ndef up(cls):\n    cls.prev = os.environ.get('RP_DATA_DIR')\ndef down(cls):\n    os.environ.pop('RP_DATA_DIR', None)\n",
        ]
        clean = [
            "import os\ndef down(prev):\n    if prev is None:\n        os.environ.pop('RP_DATA_DIR', None)\n    else:\n        os.environ['RP_DATA_DIR'] = prev\n",
            "from unittest import mock\nimport os\ndef t():\n    with mock.patch.dict(os.environ, {}, clear=True):\n        os.environ.pop('RP_DATA_DIR', None)\n",
            "import os\ndef up():\n    os.environ['RP_DATA_DIR'] = 'x'\n",                       # sets, never unsets
            "import os\nprev = os.environ.get('RP_DATA_DIR')\nif prev is None:\n    os.environ.pop('RP_DATA_DIR', None)\nelse:\n    os.environ['RP_DATA_DIR'] = prev\n",
        ]
        for src in leaks:
            with self.subTest(leak=src):
                self.assertTrue(_unsets_without_putting_back(src))
        for src in clean:
            with self.subTest(clean=src):
                self.assertFalse(_unsets_without_putting_back(src))


if __name__ == "__main__":
    unittest.main()
