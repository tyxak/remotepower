"""A `load()` that runs once per loop iteration, on the same store every time, is a defect until shown otherwise.

`load()` deep-copies the whole store on every call. A loop that calls it per item turns a list into
items x store: GET /api/backup-jobs took 9.7 s for 70 jobs on a 2,000-device fleet, the per-host SBOM
build never finished, and the schedule sweep copied the fleet for every job that came due. A route-by-route
count of load() calls per request found them; this is the static half, so the next one is caught at review.

What it reports: a call to load() or _load_tenants() that sits in a loop body, a comprehension's element or
condition, or a later generator's iterable (so it runs per item), whose arguments do not mention a loop
variable, and which is not a lazy cache (`if cached is None: cached = load(...)`). A call in a for-loop's
own iterable or a comprehension's first iterable runs once and is fine.

Each reported site in the tree today is listed below with the reason it stays. The list can only shrink:
a new site fails, and so does an entry whose code no longer matches (it was fixed, so remove the entry).
The loop-over-a-helper variant (a loop calls a function that itself loads) is not covered here because most
of its hits are write-path recorders that load, edit and save by design; the per-request counter is the
tool for that one.
"""
import ast
import functools
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'

_COPYING = {'load', '_load_tenants'}

# (file, function) -> why a per-iteration load is right there.
KNOWN = {
    ('api.py', '_migrate_storage_pg'): 'one store file per iteration; the argument is built from the loop',
    ('api.py', 'handle_export'): 'writes one store per iteration; config.json keeps load() because it is edited in place',
    ('api.py', 'handle_host_config_export'): 'one config file per path in the loop',
    ('api.py', '_longpoll_wait'): 'a poll loop must re-read each pass; see "In-request poll loops MUST bust _LOAD_CACHE"',
    ('api.py', 'handle_longpoll_exec'): 'same poll loop, same reason',
    ('api.py', 'process_schedule'): 'the command queue is a private copy, edited before it is persisted, per due job',
    ('api.py', 'run_mitigate_verify_if_due'): 'one device read per unverified mitigation, which is rare; device_get() would also do',
    ('storage.py', 'verify_migration'): 'one store file per iteration',
}


def _regions(loop):
    """The AST sub-trees of `loop` that run once per iteration."""
    if isinstance(loop, (ast.For, ast.AsyncFor)):
        return list(loop.body) + list(loop.orelse)
    if isinstance(loop, ast.While):
        return [loop.test] + list(loop.body) + list(loop.orelse)
    out = [loop.key, loop.value] if isinstance(loop, ast.DictComp) else [loop.elt]
    for i, g in enumerate(loop.generators):
        if i > 0:
            out.append(g.iter)
        out += list(g.ifs)
    return out


def _inside(node, roots):
    return any(node is d for r in roots for d in ast.walk(r))


def _loop_vars(loop):
    names = set()
    target = getattr(loop, 'target', None)
    if target is not None:
        names |= {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
    for g in getattr(loop, 'generators', []):
        names |= {n.id for n in ast.walk(g.target) if isinstance(n, ast.Name)}
    return names


def _is_lazy_cache(call, fn, parents):
    """`if x is None: x = load(...)` (or `if not x:`): the load runs at most once."""
    cur, target = parents.get(call), None
    while cur is not None and cur is not fn:
        if isinstance(cur, ast.Assign) and len(cur.targets) == 1 and isinstance(cur.targets[0], ast.Name):
            target = cur.targets[0].id
        if isinstance(cur, ast.If) and target:
            tests = cur.test.values if isinstance(cur.test, ast.BoolOp) else [cur.test]
            for t in tests:
                if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == target \
                        and any(isinstance(o, ast.Is) for o in t.ops):
                    return True
                if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) \
                        and isinstance(t.operand, ast.Name) and t.operand.id == target:
                    return True
        cur = parents.get(cur)
    return False


def scan(source):
    """[(function name, line of the load, text of its first argument)] for per-iteration loads of one store."""
    tree = ast.parse(source)
    parents = {ch: n for n in ast.walk(tree) for ch in ast.iter_child_nodes(n)}
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        loops = [n for n in ast.walk(fn) if isinstance(n, (ast.For, ast.AsyncFor, ast.While, ast.ListComp,
                                                          ast.SetComp, ast.DictComp, ast.GeneratorExp))]
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            f = call.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else '')
            if name not in _COPYING:
                continue
            for loop in loops:
                if loop is call or not _inside(call, _regions(loop)):
                    continue
                depends = any(isinstance(n, ast.Name) and n.id in _loop_vars(loop) for n in ast.walk(call))
                if not depends and not _is_lazy_cache(call, fn, parents):
                    hits.append((fn.name, call.lineno, ast.unparse(call.args[0]) if call.args else ''))
                break
    return hits


@functools.lru_cache(maxsize=1)
def _tree():
    files = sorted(_CGI.glob('*.py'))
    found = {}
    for f in files:
        for fn, line, arg in scan(f.read_text(encoding='utf-8')):
            found.setdefault((f.name, fn), []).append((line, arg))
    return files, found


@unittest.skipUnless(_CGI.exists(), 'server/cgi-bin is not in this tree')
class TestNoLoadPerIteration(unittest.TestCase):

    def test_the_scan_looked_at_the_whole_server(self):
        """Control: an empty population would pass every check below."""
        files, found = _tree()
        self.assertGreater(len(files), 50)
        self.assertGreaterEqual(len(found), 6, 'the scan found almost nothing: the analysis is probably broken')

    def test_every_site_in_the_tree_is_known_and_justified(self):
        _files, found = _tree()
        new = sorted(set(found) - set(KNOWN))
        self.assertEqual([], new,
                         'a load() now runs once per loop iteration, copying the whole store each time. Read it once before '
                         'the loop, or use _load_ro() if the loop only reads, or add it to KNOWN with the reason: %s'
                         % [(k, found[k]) for k in new])

    def test_no_entry_in_the_known_list_is_stale(self):
        _files, found = _tree()
        stale = sorted(set(KNOWN) - set(found))
        self.assertEqual([], stale, 'these sites no longer load per iteration; remove them from KNOWN: %s' % stale)


class TestTheScannerSeesWhatItShould(unittest.TestCase):
    """Fail-direction controls on synthetic sources: each one is a shape the real tree has had."""

    def test_a_load_in_the_loop_body_is_reported(self):
        src = "def f(items):\n    for j in items:\n        devs = load(DEVICES_FILE)\n        use(devs, j)\n"
        self.assertEqual([('f', 3, 'DEVICES_FILE')], scan(src))

    def test_a_load_in_a_helper_call_chain_is_not_this_scanners_job(self):
        src = "def f(items):\n    for j in items:\n        visible(j)\n"
        self.assertEqual([], scan(src))

    def test_a_load_in_the_loops_own_iterable_runs_once(self):
        self.assertEqual([], scan("def f():\n    for j in load(F):\n        use(j)\n"))
        self.assertEqual([], scan("def f():\n    return [j for j in load(F)]\n"))

    def test_a_comprehension_element_or_condition_runs_per_item(self):
        self.assertEqual(1, len(scan("def f(items):\n    return [load(F) for j in items]\n")))
        self.assertEqual(1, len(scan("def f(items):\n    return [j for j in items if j in load(F)]\n")))

    def test_a_later_generator_iterable_runs_per_item(self):
        self.assertEqual(1, len(scan("def f(items):\n    return [k for j in items for k in load(F)]\n")))

    def test_a_load_keyed_on_the_loop_variable_is_per_item_by_design(self):
        self.assertEqual([], scan("def f(names):\n    for n in names:\n        d = load(DATA_DIR / n)\n"))

    def test_a_lazy_cache_loads_once(self):
        src = "def f(items):\n    cache = None\n    for j in items:\n        if cache is None:\n            cache = load(F)\n"
        self.assertEqual([], scan(src))
        src = "def f(items):\n    cache = None\n    for j in items:\n        if not cache:\n            cache = load(F)\n"
        self.assertEqual([], scan(src))

    def test_the_mutation_that_makes_the_demo_fail_is_really_there(self):
        """The demo for test_every_site_in_the_tree_is_known_and_justified: add one bad function to a copy of a
        real module and the tree-level check must see a new site."""
        real = (_CGI / 'tickets_handlers.py').read_text(encoding='utf-8')
        mutated = real + "\n\ndef _demo_bad(rows):\n    for r in rows:\n        cfg = load(CONFIG_FILE)\n"
        self.assertIn('_demo_bad', mutated)
        self.assertEqual(['_demo_bad'], [h[0] for h in scan(mutated) if h[0] == '_demo_bad'])
        self.assertEqual([], [h for h in scan(real) if h[0] == '_demo_bad'])


if __name__ == '__main__':
    unittest.main()
