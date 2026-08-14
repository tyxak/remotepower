#!/usr/bin/env python3
"""A self-locking helper must not be called from inside another lock scope.

Under the SQLite and Postgres backends every file in DATA_DIR shares ONE
per-directory connection, so a helper that opens its own ``_LockedUpdate``
while a caller already holds one issues a nested ``BEGIN IMMEDIATE``. On SQLite
that raises ``OperationalError``, historically swallowed by a surrounding
``except Exception`` so the row simply vanished. On Postgres it is worse and
quieter: a nested ``BEGIN`` is a silent no-op, so the inner block's COMMIT ends
the OUTER transaction early and drops its advisory lock while the outer handler
is still mutating — a lost-update race with no error anywhere.

CLAUDE.md records this class recurring across releases (``_prune_confirmations``
firing a webhook under a lock; ``_ingest_hardware`` calling the SMART/GPU
samplers under one, where SQLite dropped the sample silently). The three
recorders — fire_webhook / audit_log / log_command — were made safe by
construction with a thread-local scope stack, and ``verify_token`` later joined
them. Nothing enforced the rule for the next helper.

THE EXEMPTION IS STRUCTURAL, DELIBERATELY. A call is accepted when the callee
itself consults ``_locks_held()`` — that is the mechanism all four safe helpers
use, and it is the only thing that actually makes such a call safe. A name list
would have to be extended by hand every time a helper is fixed, and — as the
eager/lazy gate learned the expensive way — a name-level exemption can end up
skipping the exact call it was written to catch.

Adding a helper to the safe set therefore means implementing the deferral, not
editing this file.
"""
import ast
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
_LOCKS = ('_LockedUpdate', '_locked_update', '_DeviceUpdate')


def _strip_docstrings(tree):
    """Docstrings are prose ABOUT locking and must not be read as locking.

    Left in, they classified `_prune_confirmations` as self-locking purely
    because its docstring explains the bug it was fixed for, and produced three
    confident false findings out of five.
    """
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                          ast.ClassDef, ast.Module)):
            body = getattr(n, 'body', None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                n.body = body[1:] or [ast.Pass()]
    return tree


def _sources():
    return {p: _strip_docstrings(ast.parse(p.read_text(encoding='utf-8')))
            for p in sorted(_CGI.glob('*.py'))}


def _functions(tree):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def _self_locking(sources):
    """name -> handles-its-own-nesting, for every function that takes a lock."""
    out = {}
    for tree in sources.values():
        for fn in _functions(tree):
            src = ast.unparse(fn)
            if any(lock + '(' in src for lock in _LOCKS):
                # A function may appear twice across modules; safe only if the
                # definition we are looking at defers. Prefer the safe verdict
                # only when every definition of the name defers.
                defers = '_locks_held' in src
                out[fn.name] = out.get(fn.name, True) and defers
    return out


def _callee(node):
    """The called name, for both `foo()` and the bound modules' `A.foo()`."""
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


class _Walker(ast.NodeVisitor):
    def __init__(self, path, selflock):
        self.path, self.selflock, self.depth, self.hits = path, selflock, 0, []

    def visit_With(self, node):
        held = any(any(lock in ast.unparse(item.context_expr) for lock in _LOCKS)
                   for item in node.items)
        self.depth += held
        for child in node.body:
            self.visit(child)
        self.depth -= held

    visit_AsyncWith = visit_With

    def visit_FunctionDef(self, node):
        """A nested def is a CLOSURE — it runs later, outside this scope.

        That is precisely the deferral pattern (`_defer_after_locks(fn)`), so
        counting its body as inside the lock would flag the fix as the bug.
        """
        saved, self.depth = self.depth, 0
        self.generic_visit(node)
        self.depth = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        name = _callee(node)
        if self.depth and name in self.selflock and not self.selflock[name]:
            self.hits.append((self.path, node.lineno, name))
        self.generic_visit(node)


def _nested_calls(sources, selflock):
    hits = []
    for path, tree in sources.items():
        for fn in _functions(tree):
            w = _Walker(path.name, selflock)
            for child in fn.body:
                w.visit(child)
            hits += [(p, ln, callee, fn.name) for p, ln, callee in w.hits]
    return sorted(set(hits))


class TestTheScanCanSeeWhatItClaimsTo(unittest.TestCase):
    """The assertion below is "this list is empty", which a scan that looks at
    nothing satisfies perfectly. Four controls, each for one way the earlier
    hand-run version of this scan was wrong."""

    def setUp(self):
        self.sources = _sources()
        self.selflock = _self_locking(self.sources)

    def test_it_finds_the_self_locking_helpers(self):
        self.assertGreater(len(self.selflock), 100,
                           f'only {len(self.selflock)} — the scan is not reading '
                           'the server')
        # audit_log and verify_token open a lock in their own body. fire_webhook
        # and log_command deliberately are NOT asserted here: they defer, but
        # they reach the store through helpers rather than locking directly, so
        # they are simply absent from the set. Asserting them present was a
        # guess about the code that the code did not share, and it failed.
        for name in ('audit_log', 'verify_token'):
            self.assertIn(name, self.selflock)

    def test_a_risky_helper_is_classified_as_risky(self):
        """The exemption must be narrow enough to still report something.

        `_record_alert` takes a lock and does NOT consult _locks_held, so it is
        exactly what this gate exists to notice if someone calls it under one.
        If the classifier ever marks it safe, the assertion below goes vacuous.
        """
        self.assertIn('_record_alert', self.selflock)
        self.assertFalse(self.selflock['_record_alert'])

    def test_the_known_safe_helpers_are_recognised_as_deferring(self):
        for name in ('audit_log', 'verify_token'):
            self.assertTrue(self.selflock[name],
                            f'{name} defers via _locks_held but was not '
                            'recognised — every call to it would be reported')

    def test_docstrings_do_not_count_as_locking(self):
        """`_prune_confirmations` explains the bug in its docstring and takes no
        lock. Reading prose as code made it three false findings."""
        self.assertNotIn('_prune_confirmations', self.selflock)

    def test_it_would_catch_a_bound_module_call(self):
        """Bound handler modules reach every api global as `A.name`, so a scan
        matching only bare `Name` calls is blind to 31 files."""
        tree = _strip_docstrings(ast.parse(
            'def h():\n'
            '    with _LockedUpdate(F) as s:\n'
            '        A.unsafe_helper(1)\n'))
        w = _Walker('ctl', {'unsafe_helper': False})
        for fn in _functions(tree):
            for child in fn.body:
                w.visit(child)
        self.assertEqual([h[2] for h in w.hits], ['unsafe_helper'])

    def test_a_deferred_closure_is_not_a_hit(self):
        """The fix for this whole class is to wrap the call in a closure and
        hand it to _defer_after_locks. Flagging that would flag the cure."""
        tree = _strip_docstrings(ast.parse(
            'def h():\n'
            '    with _LockedUpdate(F) as s:\n'
            '        def later():\n'
            '            unsafe_helper(1)\n'
            '        _defer_after_locks(later)\n'))
        w = _Walker('ctl', {'unsafe_helper': False})
        for fn in _functions(tree):
            for child in fn.body:
                w.visit(child)
        self.assertEqual(w.hits, [])


class TestNoNestedSelfLockingCall(unittest.TestCase):

    def test_no_helper_opens_a_second_lock_under_an_open_one(self):
        sources = _sources()
        hits = _nested_calls(sources, _self_locking(sources))
        pretty = [f'{p}:{ln}  {caller}() calls {callee}() while holding a lock'
                  for p, ln, callee, caller in hits]
        self.assertEqual(
            pretty, [],
            'a self-locking helper is called from inside an open lock scope. '
            'On SQLite that raises OperationalError (usually swallowed, so the '
            'write silently vanishes); on Postgres the nested BEGIN is a no-op '
            'and the inner COMMIT ends the OUTER transaction early, releasing '
            'its advisory lock mid-update. Fix it the way fire_webhook did: '
            'have the callee check _locks_held() and defer itself, or collect '
            'the work inside the lock and run it after the block exits.\n'
            + '\n'.join('  ' + p for p in pretty))


if __name__ == '__main__':
    unittest.main()
