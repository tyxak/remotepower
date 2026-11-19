#!/usr/bin/env python3
"""A store that several requests write is saved inside its lock, never from a snapshot read before it.

A write that reads the whole store, changes one thing and saves the whole store without a lock held across the pair puts back what a concurrent request changed in
between. The rule is old and the server applies it nearly everywhere; the findings of 8.0.2 were the places that missed it, and every one of them sat among sites that
kept it: the session store had 9 functions under `_LockedUpdate(TOKENS_FILE)` and 3 that saved a snapshot (a revoked session came back), the command queue 27 and 3 (a
command a host was just handed was queued again, one an administrator had just queued was lost), the settings document 81 and 1 (a host's heartbeat reverted an
administrator's save), the backup freshness state one more whose path was held in a variable. `tests/test_users_write_locks.py` and `tests/test_device_write_locks.py` hold
the same rule for two other stores, by the name of the constant and by `save` alone, which is why these were outside them.

This module enumerates, by syntax tree over every module of the server, each call that saves a store (`save`, `_save_nb`, `_save_held`, `_save_nonblocking`, with the
store named directly or through a local variable that holds it) and requires it to sit inside a `with _LockedUpdate(<the same store>)` block of that function. A site that
has a reason to write without it is listed in the store's exemption table with the reason. Controls: each shape the scan has to see (a bare save, a save through a variable,
`_save_nb`, a save outside the block of a function that also locks elsewhere) is flagged, the shape it has to pass is passed, and the population of each store is measured so
that a scan that sees nothing fails.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
SAVES = {'save', '_save_nb', '_save_held', '_save_nonblocking'}
LOCKS = {'_LockedUpdate', '_locked_update'}

# store constant -> {(file, function): reason it may save without the lock}. Each store is added by the change that closed the finding for it.
STORES = {
    'TOKENS_FILE': {},
    'CMDS_FILE': {},
}
# the least number of functions under the lock a store has today: a scan that finds fewer is not looking at the server
MIN_LOCKED = {'TOKENS_FILE': 6, 'CMDS_FILE': 20}


def _callee(n):
    f = n.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ''


def _names(expr):
    out = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


class _Scan(ast.NodeVisitor):
    """For each function: the saves of a store that are outside a lock block of that store, and whether the function locks the store at all."""

    def __init__(self, consts):
        self.consts, self.fn, self.aliases, self.held, self.rows = set(consts), [], [], [], {}

    def _stores_of(self, arg):
        found = _names(arg) & self.consts
        if isinstance(arg, ast.Name) and self.aliases:
            found |= self.aliases[-1].get(arg.id, set())
        return found

    def _visit_fn(self, node):
        al = {}
        for n in ast.walk(node):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                hit = _names(n.value) & self.consts
                if hit:
                    al.setdefault(n.targets[0].id, set()).update(hit)
        self.fn.append(node.name)
        self.aliases.append(al)
        outer_held, self.held = self.held, []
        self.generic_visit(node)
        self.held = outer_held
        self.aliases.pop()
        self.fn.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _visit_fn

    def visit_With(self, node):
        locked = []
        for item in node.items:
            c = item.context_expr
            if isinstance(c, ast.Call) and _callee(c) in LOCKS and c.args:
                locked.append(self._stores_of(c.args[0]))
                for s in locked[-1]:
                    self._row(s)['locks'] += 1
        self.held.append(set().union(*locked) if locked else set())
        self.generic_visit(node)
        self.held.pop()

    visit_AsyncWith = visit_With

    def _row(self, store):
        return self.rows.setdefault((self.fn[-1] if self.fn else '<module>', store), {'locks': 0, 'bare': []})

    def visit_Call(self, node):
        if _callee(node) in SAVES and node.args:
            under = set().union(*self.held) if self.held else set()
            for s in self._stores_of(node.args[0]):
                if s not in under:
                    self._row(s)['bare'].append(node.lineno)
        self.generic_visit(node)


def scan_source(src, consts):
    v = _Scan(consts)
    v.visit(ast.parse(src))
    return v.rows


def scan_tree(consts):
    """{store: {'locked': [(file, function)], 'bare': [(file, function, [lineno])]}} over every module of the server."""
    out = {c: {'locked': [], 'bare': []} for c in consts}
    for p in sorted(CGI.glob('*.py')):
        for (fn, store), row in scan_source(p.read_text(), consts).items():
            if row['locks']:
                out[store]['locked'].append((p.name, fn))
            if row['bare']:
                out[store]['bare'].append((p.name, fn, row['bare']))
    return out


class TestEveryWriteOfTheseStoresHoldsTheLock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = scan_tree(list(STORES))

    def test_the_scan_sees_each_store_the_way_the_server_writes_it(self):
        for store, floor in MIN_LOCKED.items():
            n = len(self.found[store]['locked'])
            self.assertGreaterEqual(n, floor, '%s: only %d functions under the lock were found; the scan is not looking at the server' % (store, n))

    def test_no_function_saves_a_store_outside_its_lock(self):
        for store, exempt in STORES.items():
            bare = [(f, fn, lines) for f, fn, lines in self.found[store]['bare'] if (f, fn) not in exempt]
            self.assertEqual(bare, [], '%s is saved from a snapshot, with no lock held across the read and the write. A concurrent request that changed the store in '
                                       'between is put back as it was. Take `with _LockedUpdate(%s) as store:` around the read, the change and the save.' % (store, store))

    def test_every_exemption_still_occurs_and_says_why(self):
        for store, exempt in STORES.items():
            seen = {(f, fn) for f, fn, _ in self.found[store]['bare']}
            for key, why in exempt.items():
                self.assertIn(key, seen, '%s: %s no longer saves the store without the lock; delete its entry' % (store, key))
                self.assertGreater(len(why), 30, '%s: %s is exempt without a reason' % (store, key))


class TestControls(unittest.TestCase):
    """The scan finds what it is for. Each of these is a shape a finding was in, or the shape that the rule asks for."""

    def rows(self, src, store='TOKENS_FILE'):
        return {k: v for k, v in scan_source(src, [store]).items()}

    def test_a_snapshot_saved_bare_is_flagged(self):
        r = self.rows('def f():\n    t = load(TOKENS_FILE)\n    t["x"] = 1\n    save(TOKENS_FILE, t)\n')
        self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'])

    def test_a_save_through_a_variable_is_flagged(self):
        r = self.rows('def f():\n    p = TOKENS_FILE\n    t = load(p)\n    save(p, t)\n')
        self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'])

    def test_save_nb_and_save_held_are_saves(self):
        for name in ('_save_nb', '_save_held', '_save_nonblocking'):
            r = self.rows('def f():\n    %s(TOKENS_FILE, {})\n' % name)
            self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'], name)

    def test_an_attribute_spelling_is_flagged(self):
        r = self.rows('def f():\n    A.save(A.TOKENS_FILE, {})\n')
        self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'])

    def test_a_save_outside_the_block_of_a_function_that_also_locks_is_flagged(self):
        src = ('def f():\n'
               '    with _LockedUpdate(TOKENS_FILE) as t:\n'
               '        t["a"] = 1\n'
               '    u = load(TOKENS_FILE)\n'
               '    save(TOKENS_FILE, u)\n')
        r = self.rows(src)
        self.assertEqual(r[('f', 'TOKENS_FILE')]['locks'], 1)
        self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'], 'a function that locks once is not a function that always locks')

    def test_a_locked_update_is_not_flagged(self):
        r = self.rows('def f():\n    with _LockedUpdate(TOKENS_FILE) as t:\n        t["x"] = 1\n')
        self.assertFalse(r[('f', 'TOKENS_FILE')]['bare'])
        self.assertEqual(r[('f', 'TOKENS_FILE')]['locks'], 1)

    def test_a_lock_on_another_store_does_not_cover_this_one(self):
        r = self.rows('def f():\n    with _LockedUpdate(USERS_FILE) as u:\n        save(TOKENS_FILE, {})\n')
        self.assertTrue(r[('f', 'TOKENS_FILE')]['bare'])

    def test_the_old_verify_token_is_flagged(self):
        """The shape that was live: a snapshot saved after the read, with the expiry, the eviction and the stamp each doing it."""
        old = ('def verify_token(token):\n'
               '    tokens = load(TOKENS_FILE)\n'
               '    entry = tokens.get(token)\n'
               '    if entry:\n'
               '        entry["last_seen"] = 1\n'
               '        try:\n'
               '            save(TOKENS_FILE, tokens)\n'
               '        except Exception:\n'
               '            pass\n')
        self.assertTrue(self.rows(old)[('verify_token', 'TOKENS_FILE')]['bare'])


if __name__ == '__main__':
    unittest.main()
