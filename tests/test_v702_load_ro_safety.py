#!/usr/bin/env python3
"""No handler may write through a `_load_ro` result.

`load()` deepcopies on every read so a mutating caller cannot corrupt the shared
cache. `_load_ro()` hands back the shared object — which is a real saving
(~36 ms per request on a 500-device fleet, ~147 ms at 2,000, paid entirely in
copying) and a real obligation: a caller that writes through it, or through
anything reached from it, corrupts the cache for every later reader in the same
request. That failure is silent and order-dependent, which is the worst kind.

v7.0.2 converted 71 read-only handlers in one pass. This is the gate that keeps
them honest, and it is the same analysis the conversion used — so a handler that
later grows a write fails here rather than corrupting a cache in production.

ALIASES are the whole difficulty. `dev = devices[id]` followed by `dev['x'] = 1`
writes through the shared object exactly as `devices[id] = x` does. A first
version of the conversion analysis tracked only the top-level name and called 26
unsafe handlers safe.
"""
import ast
import pathlib
import unittest

_API = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'

_PURE = {'len', 'sorted', 'set', 'list', 'dict', 'sum', 'any', 'all', 'max',
         'min', 'enumerate', 'bool', 'int', 'float', 'str', 'repr', 'isinstance',
         '_scope_filter_devices', '_tenant_filter_devices'}
_MUTATORS = {'pop', 'setdefault', 'update', 'clear', 'popitem', 'append',
             'extend', 'insert', 'remove', 'sort'}


def _root(n):
    while isinstance(n, (ast.Subscript, ast.Attribute, ast.Call)):
        n = n.func if isinstance(n, ast.Call) else n.value
    return getattr(n, 'id', None)


def _value_targets(target, iter_node):
    """The loop targets that can reach the iterated object.

    For `.items()` that is the VALUE only; the key is a string.
    """
    if isinstance(target, ast.Name):
        return [target]
    elts = list(getattr(target, 'elts', []))
    src = ast.unparse(iter_node)
    if src.endswith('.items()') and len(elts) == 2:
        return [elts[1]]
    return elts


def _aliases(fn, seed):
    """Every name that can reach the same object as `seed`."""
    tracked = {seed}
    for _ in range(6):
        added = False
        for node in ast.walk(fn):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and _root(node.value) in tracked
                    and node.targets[0].id not in tracked):
                tracked.add(node.targets[0].id); added = True
            if isinstance(node, ast.For) and _root(node.iter) in tracked:
                # `for k, v in d.items()` — only v reaches the object; k is a
                # KEY. Tracking the key made every `d.get(key)` look like the
                # object escaping, which is what made escapes unusable as a gate.
                tgts = _value_targets(node.target, node.iter)
                for el in tgts:
                    if isinstance(el, ast.Name) and el.id not in tracked:
                        tracked.add(el.id); added = True
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                                 ast.GeneratorExp)):
                for gen in node.generators:
                    if _root(gen.iter) in tracked:
                        for el in _value_targets(gen.target, gen.iter):
                            if isinstance(el, ast.Name) and el.id not in tracked:
                                tracked.add(el.id); added = True
                # the comprehension's RESULT, when it yields the elements
                # themselves rather than a projection of them
                elt = getattr(node, 'elt', None)
                if isinstance(elt, ast.Name) and elt.id in tracked:
                    for outer in ast.walk(fn):
                        if (isinstance(outer, ast.Assign) and len(outer.targets) == 1
                                and isinstance(outer.targets[0], ast.Name)
                                and outer.value is node
                                and outer.targets[0].id not in tracked):
                            tracked.add(outer.targets[0].id); added = True
        if not added:
            break
    return tracked


def _violations(fn, seed):
    tracked = _aliases(fn, seed)
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, (ast.Subscript, ast.Attribute)) and _root(t) in tracked:
                    out.append(f'line {node.lineno}: writes into {_root(t)}')
        if isinstance(node, ast.AugAssign) and _root(node.target) in tracked:
            out.append(f'line {node.lineno}: augments {_root(node.target)}')
        if isinstance(node, ast.Delete):
            for t in node.targets:
                if _root(t) in tracked:
                    out.append(f'line {node.lineno}: del {_root(t)}')
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and _root(f) in tracked and f.attr in _MUTATORS:
                out.append(f'line {node.lineno}: {_root(f)}.{f.attr}()')
    return out


def _is_ro_expr(node):
    """True when this expression IS the shared object, not merely one that
    mentions it.

    `_home_resp = {'devices': devices, ...}` builds a FRESH dict that happens to
    contain a shared sub-object; adding a key to it is harmless, and matching on
    "the source text contains _load_ro(" reported exactly that as a violation.
    A container literal therefore stops the walk.
    """
    if isinstance(node, ast.Call):
        f = node.func
        if getattr(f, 'id', '') == '_load_ro' or getattr(f, 'attr', '') == '_load_ro':
            return True
        # a pure wrapper such as _scope_filter_devices(_load_ro(X) or {})
        return any(_is_ro_expr(a) for a in node.args)
    if isinstance(node, ast.BoolOp):
        return any(_is_ro_expr(v) for v in node.values)
    if isinstance(node, (ast.Dict, ast.List, ast.Set, ast.Tuple, ast.ListComp,
                         ast.DictComp, ast.SetComp)):
        return False              # a new container, not the shared one
    return False


def _ro_bindings():
    """(function, bound name, line) for every name bound TO a _load_ro result."""
    tree = ast.parse(_API.read_text())
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and _is_ro_expr(node.value)):
                yield fn, node.targets[0].id, node.lineno


class TestTheAnalysisWorks(unittest.TestCase):
    """Checked first — every assertion below is produced by it."""

    _SHAPES = {
        'direct write': "def f():\n d = _load_ro(X)\n d['a'] = 1\n",
        'alias write': "def f():\n d = _load_ro(X)\n one = d['a']\n one['b'] = 1\n",
        'loop variable': "def f():\n d = _load_ro(X)\n for v in d.values():\n  v['b'] = 1\n",
        'comprehension': "def f():\n d = _load_ro(X)\n r = [v for v in d.values()]\n for x in r:\n  x['b'] = 1\n",
        'nested alias': "def f():\n d = _load_ro(X)\n a = d['k']\n b = a['s']\n b['c'] = 1\n",
        'mutating method': "def f():\n d = _load_ro(X)\n a = d.get('k')\n a.pop('z')\n",
    }

    # NOT gated: passing the object to a helper. Whether that is a write depends
    # on the helper, and treating every call as unsafe reported 17 long-standing
    # _load_ro sites — all of them read-only — as violations. The v7.0.2
    # conversion used the stricter rule (an escape disqualified a handler), which
    # is the right asymmetry: conservative about what to convert, provable about
    # what to enforce.


    def test_it_catches_every_way_of_writing_through(self):
        for label, code in self._SHAPES.items():
            fn = ast.parse(code).body[0]
            self.assertTrue(_violations(fn, 'd'), f'missed: {label}')

    def test_it_passes_a_read_only_control(self):
        """A checker that flagged everything would satisfy the test above."""
        code = ("def f():\n d = _load_ro(X)\n n = 0\n"
                " for v in d.values():\n  n += len(v.get('tags') or [])\n"
                " names = [v.get('name') for v in d.values()]\n return n, names\n")
        fn = ast.parse(code).body[0]
        self.assertEqual(_violations(fn, 'd'), [])

    def test_the_population_is_not_empty(self):
        found = list(_ro_bindings())
        self.assertGreater(len(found), 60,
                           f'only {len(found)} _load_ro bindings — the '
                           f'extraction broke, and every check below is vacuous')


class TestNoHandlerWritesThroughTheSharedObject(unittest.TestCase):

    def test_every_load_ro_result_is_read_only(self):
        bad = []
        for fn, name, ln in _ro_bindings():
            v = _violations(fn, name)
            if v:
                bad.append(f'{fn.name} (api.py:{ln}, binds {name}): {v[:2]}')
        self.assertEqual(bad, [],
                         '_load_ro hands back the SHARED cached object. Writing '
                         'through it — or through anything reached from it — '
                         'corrupts the cache for every later reader in the same '
                         'request. Use load() here, or stop mutating:\n  '
                         + '\n  '.join(bad))


if __name__ == '__main__':
    unittest.main()
