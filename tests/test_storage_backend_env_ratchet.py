"""RP_STORAGE_BACKEND must be RESTORED by every test that mutates it.

`unittest discover` — what `make test`, `make test-sqlite`, `make check`,
`make pre-release` and prod CI all run — executes the whole suite in ONE
process, in filename order. A test that pops or reassigns
`RP_STORAGE_BACKEND` and does not put it back changes the storage backend for
every module that runs after it, and the run keeps reporting OK because the
assertions are all still true on JSON.

That is not hypothetical: `tests/test_v3120.py` popped the variable to assert
the default and restored only the marker path, so from that file onward
`make test-sqlite` was exercising the JSON backend — 9,324 of 12,836 verdicts
in a measured run, 72% of the gate, testing the wrong thing.

`tests/conftest.py` already guards this variable, but conftest is pytest-only
and none of the gates use pytest. So the guard has to live in the suite
itself, and it has to enumerate the POPULATION rather than spot-check: this
walks every test module, finds the ones that mutate the variable at all, and
requires each of them to capture the prior value and write it back.

Recognised restore shape: bind the prior value out of `os.environ`
(`x = os.environ.pop('RP_STORAGE_BACKEND', None)` or `os.environ.get(...)`)
and later assign that captured name back into `os.environ` — in a `finally`,
a `tearDown*`, or at module scope. A constant reassignment
(`os.environ['RP_STORAGE_BACKEND'] = 'sqlite'`) is a mutation, never a
restore.

Mutations written inside a string that a child interpreter runs are not in
the population, and correctly so — a subprocess cannot leak into this one.
Parsing the AST rather than grepping is what keeps them out.
"""

import ast
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_VAR = "RP_STORAGE_BACKEND"

# Every offender must be fixed; this exists to make a regression loud, and it
# may only ever shrink.
_CEILING = 0


def _is_os_environ(node):
    """True for the `os.environ` expression (or a bare `environ`)."""
    if isinstance(node, ast.Attribute) and node.attr == "environ":
        return isinstance(node.value, ast.Name) and node.value.id == "os"
    return isinstance(node, ast.Name) and node.id == "environ"


def _dotted(node):
    """'self._env' / 'saved' for a name-ish target, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _root_name(node):
    """The identifier a restore's right-hand side is rooted at."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class _Scan(ast.NodeVisitor):
    """Collect mutations and restores, each tagged with the scope it sits in.

    Scope is the nearest enclosing class, or None for module level. A class's
    mutation may be undone in any of its own methods (setUp/tearDown is the
    common pair) or by a module-level tearDownModule; a module-level mutation
    needs a module-level restore, since one class's tearDown does not run for
    the rest of the file.
    """

    def __init__(self, captured=()):
        self.scope = None
        self.mutations = []          # (lineno, form, scope)
        self.captured = set(captured)   # names holding a value read out of os.environ
        self.restores = set()        # scopes that write a captured value back

    # --- helpers -------------------------------------------------------
    @staticmethod
    def _reads_environ(value):
        for sub in ast.walk(value):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr in ("get", "pop")
                    and _is_os_environ(sub.func.value)):
                return True
        return False

    # --- visitors ------------------------------------------------------
    def visit_ClassDef(self, node):
        outer, self.scope = self.scope, node.name
        self.generic_visit(node)
        self.scope = outer

    def visit_Call(self, node):
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "pop"
                and _is_os_environ(node.func.value) and node.args
                and _const_str(node.args[0]) == _VAR):
            self.mutations.append((node.lineno, "os.environ.pop", self.scope))
        self.generic_visit(node)

    def visit_Delete(self, node):
        for t in node.targets:
            if (isinstance(t, ast.Subscript) and _is_os_environ(t.value)
                    and _const_str(t.slice) == _VAR):
                self.mutations.append((t.lineno, "del os.environ", self.scope))
        self.generic_visit(node)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Subscript) and _is_os_environ(t.value):
                key = _const_str(t.slice)
                # A literal-keyed write to some OTHER variable is none of our
                # business; a variable key may well be ours (a loop over a
                # saved env dict), so treat it as in-scope.
                if key is not None and key != _VAR:
                    continue
                if isinstance(node.value, ast.Constant):
                    self.mutations.append(
                        (node.lineno, "os.environ[...] = <literal>", self.scope))
                elif _root_name(node.value) in self.captured:
                    self.restores.add(self.scope)
                else:
                    self.mutations.append(
                        (node.lineno, "os.environ[...] = <uncaptured value>", self.scope))
        if self._reads_environ(node.value):
            for t in node.targets:
                name = _dotted(t)
                if name:
                    self.captured.add(name)
                    self.captured.add(name.split(".")[0])
        self.generic_visit(node)

    def visit_For(self, node):
        # `for k, v in _SAVED.items():` — the loop vars carry saved values.
        it = node.iter
        base = it.func.value if (isinstance(it, ast.Call)
                                 and isinstance(it.func, ast.Attribute)) else it
        if _root_name(base) in self.captured:
            for sub in ast.walk(node.target):
                if isinstance(sub, ast.Name):
                    self.captured.add(sub.id)
        self.generic_visit(node)


def _scan(path):
    tree = ast.parse(path.read_text())
    # Two passes: a capture can sit BELOW the restore that uses it (a
    # module-level `_PRIOR = os.environ.get(...)` is written under its own
    # tearDownModule in several files), and a single walk would not have seen
    # the binding yet.
    first = _Scan()
    first.visit(tree)
    second = _Scan(first.captured)
    second.visit(tree)
    return second


def _unrestored(scan):
    """Mutations whose scope never writes the saved value back."""
    out = []
    for lineno, form, scope in scan.mutations:
        if scope in scan.restores or None in scan.restores:
            continue
        out.append((lineno, form, scope))
    return out


class TestStorageBackendEnvIsAlwaysRestored(unittest.TestCase):
    def _population(self):
        pop = {}
        for f in sorted(_TESTS.glob("test_*.py")):
            if f.name == Path(__file__).name:
                continue
            if _VAR not in f.read_text():
                continue
            scan = _scan(f)
            if scan.mutations:
                pop[f.name] = scan
        return pop

    def test_population_is_not_empty(self):
        """A derivation that finds nothing would pass this gate vacuously."""
        pop = self._population()
        self.assertGreaterEqual(
            len(pop), 5,
            "the scanner found almost no test module mutating "
            f"{_VAR} — that is an instrument failure, not a clean tree")

    def test_every_mutator_restores(self):
        pop = self._population()
        offenders = {n: bad for n, s in pop.items() if (bad := _unrestored(s))}
        detail = []
        for name, bad in sorted(offenders.items()):
            where = ", ".join(
                f"line {ln} ({form}, scope {scope or 'module'})"
                for ln, form, scope in bad)
            detail.append(f"  {name}: {where}")
        self.assertLessEqual(
            len(offenders), _CEILING,
            f"{len(offenders)} of {len(pop)} test modules that mutate {_VAR} "
            f"never restore it ({len(pop) - len(offenders)} do).\n"
            "unittest discover shares ONE process, so an unrestored mutation "
            "silently switches the storage backend for every module that runs "
            "after it and the gate keeps reporting OK.\n"
            "Capture the prior value and write it back in a finally / "
            "tearDown / tearDownModule:\n"
            + "\n".join(detail))


if __name__ == "__main__":
    unittest.main()
