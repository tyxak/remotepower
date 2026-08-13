#!/usr/bin/env python3
"""Every write to USERS_FILE holds the lock across the read-modify-write.

`tests/test_device_write_locks.py` has enforced exactly this for DEVICES_FILE
since issue #8. The user store had the same hazard and no such gate, and it had
drifted: sixteen call sites used `_LockedUpdate(USERS_FILE)` correctly while
fourteen others did a bare `load()` … mutate … `save(USERS_FILE, …)`. A half-
migrated invariant is worse than an unknown one, because the correct sites make
the file read as though the rule is already enforced.

What the bare pattern costs, given `save()` writes back the WHOLE users dict:

  * an account deleted by an admin is RESURRECTED — with its old password hash,
    role and tokens — by any concurrent writer holding an older snapshot;
  * a rotated password, a TOTP enrolment, or a 2FA disable is silently reverted
    the same way;
  * the "cannot delete last admin" check was not atomic with the delete, so two
    concurrent deletes could each see two admins and leave zero.

The window is not theoretical. `POST /api/ui-prefs` writes the whole users dict
and fires whenever any logged-in operator changes a filter or a sort order, so
the store is being rewritten from a stale snapshot constantly on a busy install.

This is a SOURCE-level gate, which is a real limitation: it proves the call
shape, not the runtime behaviour. That is the right trade here — the failure
needs two concurrent requests to observe, and a source rule that cannot be
quietly violated is worth more than a timing test that passes by luck. The
runtime half is covered where it matters by the handlers' own tests.
"""
import ast
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'

# A write that is genuinely NOT a read-modify-write may be listed here. Each
# entry needs a reason: an undeclared exemption is indistinguishable from a site
# nobody has looked at. Empty on purpose — every site was convertible.
EXEMPT_FUNCTIONS: dict[str, str] = {}


def _functions_writing_users_file(tree):
    """{function name: [lineno]} for every `save(USERS_FILE, …)` call."""
    out = {}

    class V(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def _visit_fn(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _visit_fn
        visit_AsyncFunctionDef = _visit_fn

        def visit_Call(self, node):
            fn = getattr(node.func, 'id', None)
            if fn == 'save' and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Name) and a0.id == 'USERS_FILE':
                    key = self.stack[-1] if self.stack else '<module>'
                    out.setdefault(key, []).append(node.lineno)
            self.generic_visit(node)

    V().visit(tree)
    return out


class TestNoBareUsersFileWrite(unittest.TestCase):

    def setUp(self):
        self.src = _API.read_text()
        self.tree = ast.parse(self.src)

    def test_the_scan_can_see_a_write_at_all(self):
        """POSITIVE CONTROL. The assertion below is 'nothing was found', which is
        what a broken AST walk produces too. Parse a known-bad snippet and
        require the walker to report it."""
        bad = ast.parse(
            'def handler():\n'
            '    users = load(USERS_FILE)\n'
            "    users['x'] = 1\n"
            '    save(USERS_FILE, users)\n')
        found = _functions_writing_users_file(bad)
        self.assertIn('handler', found,
                      'the walker cannot see a save(USERS_FILE, …) it is '
                      'looking straight at — every result here is meaningless')

    def test_every_users_write_goes_through_the_lock(self):
        offenders = {
            fn: lines
            for fn, lines in _functions_writing_users_file(self.tree).items()
            if fn not in EXEMPT_FUNCTIONS
        }
        self.assertEqual(
            offenders, {},
            'These write USERS_FILE with a bare save() instead of holding\n'
            '`with _LockedUpdate(USERS_FILE) as users:` across the\n'
            'read-modify-write. save() writes back the WHOLE users dict, so a\n'
            'stale snapshot resurrects deleted accounts and reverts rotated\n'
            'passwords:\n' + '\n'.join(
                f'  {fn}  (api.py:{", ".join(str(x) for x in lines)})'
                for fn, lines in sorted(offenders.items())))

    def test_the_lock_is_actually_used_somewhere(self):
        """Guards against the degenerate pass: if every write were deleted the
        test above would also be green."""
        self.assertGreater(
            self.src.count('_LockedUpdate(USERS_FILE)'), 10,
            'almost no locked user writes remain — the store is not being '
            'written at all, which is not what this file is asserting')

    def test_every_exemption_states_a_reason(self):
        for fn, why in EXEMPT_FUNCTIONS.items():
            self.assertGreater(len(why), 30, f'{fn} is exempt without a reason')


if __name__ == '__main__':
    unittest.main()
