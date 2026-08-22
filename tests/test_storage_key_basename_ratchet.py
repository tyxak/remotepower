#!/usr/bin/env python3
"""A test's storage filename is an IDENTIFIER, not a location.

`server/cgi-bin/storage.py` picks a row's table from the BASENAME of the path
(`DEVICES_FILE_NAME = 'devices.json'`, `WRAPPED_LIST_FILES`), so a fixture that
repoints a storage key at a made-up basename is not repointing that store at
all. On the JSON backend a path is a path and nothing notices; on SQLite and
Postgres the seeded rows land in a table nobody reads.

Two shapes produce a wrong basename, and both were live in this tree:

    setattr(api, n, tmp / f'{n.lower()}.json')   # DEVICES_FILE -> devices_file.json
    api.CMDS_FILE = tmp / 'cmds.json'            # the real name is commands.json

`tests/test_v643_tenant_breakglass_tasks.py` had the first one. Under SQLite it
was 5 failures out of 11 — and the five were its POSITIVE CONTROLS. Every
"a foreign tenant sees nothing" assertion in a file written to close a
cross-tenant approval hole was satisfied by a fixture that returned nothing to
anyone. The rule the file enforces was right; the fixture put the whole
population out of reach.

CLAUDE.md records six files being fixed at v7.0.2 by hand. Nothing stopped the
seventh, so this is the guard: take the basename from the attribute you are
replacing.

    self._saved[n] = getattr(api, n)
    setattr(api, n, tmp / self._saved[n].name)
"""
import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-basename-'))

_ROOT = Path(__file__).resolve().parent.parent
_TESTS = _ROOT / 'tests'
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

# Every module-level storage key api.py exposes, mapped to the basename the
# storage backend dispatches on. Derived from the module, not a list here — a
# hand-kept list is the thing this file exists to stop.
REAL_BASENAMES = {
    n: getattr(api, n).name
    for n in dir(api)
    if n.isupper() and isinstance(getattr(api, n, None), Path)
    and getattr(api, n).name.endswith('.json')
}

# This file quotes both wrong shapes in its docstring and in its own controls.
EXEMPT_FILES = {
    'test_storage_key_basename_ratchet.py':
        'quotes the shapes it bans, in the docstring and in the controls that '
        'prove the detectors are not blind',
}

# Shrink-only, and each entry names the attribute that actually lands in the
# wrong table. Delete the entry with the fix; never add one to get a push out.
KNOWN_DERIVED = {
    ('test_authz_mitigate_scope.py', 'a'):
        'builds the basename as a.lower().replace("_file", ""), which is right '
        'for DEVICES_FILE and AUDIT_LOG_FILE and wrong for CMDS_FILE '
        '(commands.json). Left as-is here only because another change was in '
        'flight in that file; the fix is the same one line, '
        'self.tmp / self._saved[a].name.',
}


def _mentions(node, name):
    """True if `name` is read anywhere inside this expression."""
    return any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(node))


def _is_real_name(node):
    """`saved[n].name` / `getattr(api, n).name` — the correct idiom reads the
    basename off the Path it is replacing, so it mentions the attribute too."""
    return isinstance(node, ast.Attribute) and node.attr == 'name'


def _derived_sites(tree):
    """setattr(<mod>, <var>, <dir> / <something built from <var>>)."""
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'setattr' and len(node.args) == 3):
            continue
        attr_arg, value = node.args[1], node.args[2]
        if not isinstance(attr_arg, ast.Name):
            continue
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div) \
           and _mentions(value.right, attr_arg.id) \
           and not _is_real_name(value.right):
            out.append((node.lineno, attr_arg.id))
    return out


def _literal_sites(tree):
    """api.X_FILE = <dir> / 'literal.json' where the literal is the wrong name."""
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute)):
            continue
        name = node.targets[0].attr
        real = REAL_BASENAMES.get(name)
        v = node.value
        if real and isinstance(v, ast.BinOp) and isinstance(v.op, ast.Div) \
           and isinstance(v.right, ast.Constant) \
           and isinstance(v.right.value, str) \
           and v.right.value.endswith('.json') and v.right.value != real:
            out.append((node.lineno, name, v.right.value, real))
    return out


def _scan():
    derived, literal, scanned = [], [], 0
    for f in sorted(_TESTS.glob('test_*.py')):
        if f.name in EXEMPT_FILES:
            continue
        try:
            tree = ast.parse(f.read_text())
        except SyntaxError:
            continue
        scanned += 1
        derived += [(f.name, ln, n) for ln, n in _derived_sites(tree)
                    if (f.name, n) not in KNOWN_DERIVED]
        literal += [(f.name, ln, n, got, want)
                    for ln, n, got, want in _literal_sites(tree)]
    return derived, literal, scanned


class TestTheDetectorsSeeSomething(unittest.TestCase):
    """A count assertion over an empty population passes just as happily as one
    over a clean population. Prove the instrument first."""

    def test_the_storage_key_map_is_populated(self):
        self.assertGreater(
            len(REAL_BASENAMES), 150,
            'api.py exposes ~230 storage keys; a near-empty map means the '
            'derivation broke and every literal below is unchecked')
        self.assertEqual(REAL_BASENAMES.get('DEVICES_FILE'), 'devices.json')
        self.assertEqual(REAL_BASENAMES.get('CMDS_FILE'), 'commands.json')

    def test_it_scans_the_whole_suite(self):
        _, _, scanned = _scan()
        self.assertGreater(scanned, 300, 'the test glob stopped matching')

    def test_it_matches_the_derived_form(self):
        for bad in ("setattr(api, n, self.d / f'{n.lower()}.json')",
                    "setattr(api, attr, tmp / (attr.lower() + '.json'))",
                    "setattr(m, k, d / (k.lower().replace('_file', '') + '.json'))"):
            self.assertEqual(len(_derived_sites(ast.parse(bad))), 1, bad)

    def test_it_does_not_match_the_correct_form(self):
        for ok in ("setattr(api, n, self.d / self._saved[n].name)",
                   "setattr(api, n, self.d / getattr(api, n).name)",
                   "setattr(api, 'DEVICES_FILE', self.d / 'devices.json')"):
            self.assertEqual(_derived_sites(ast.parse(ok)), [], ok)

    def test_it_matches_a_wrong_literal_and_spares_a_right_one(self):
        bad = "api.CMDS_FILE = tmp / 'cmds.json'"
        self.assertEqual(len(_literal_sites(ast.parse(bad))), 1, bad)
        ok = "api.CMDS_FILE = tmp / 'commands.json'"
        self.assertEqual(_literal_sites(ast.parse(ok)), [], ok)


class TestNoTestDerivesAStorageBasename(unittest.TestCase):

    def test_no_derived_basenames(self):
        derived, _, _ = _scan()
        self.assertEqual(
            derived, [],
            'a fixture is building a storage basename out of the attribute '
            'NAME, so the store it repoints is a different table on SQLite and '
            'Postgres:\n'
            + '\n'.join(f'  {f}:{ln}  {n}' for f, ln, n in derived)
            + '\nTake the name from the attribute you replaced: '
              'setattr(api, n, tmp / saved[n].name)')

    def test_no_wrong_literal_basenames(self):
        _, literal, _ = _scan()
        self.assertEqual(
            literal, [],
            'a fixture repoints a storage key at a basename that is not its '
            'own, which is a different table on SQLite and Postgres:\n'
            + '\n'.join(f'  {f}:{ln}  {n} -> {got!r}, real name is {want!r}'
                        for f, ln, n, got, want in literal))

    def test_every_exemption_states_a_reason(self):
        for f, why in EXEMPT_FILES.items():
            self.assertGreater(len(why), 20, f)
        for key, why in KNOWN_DERIVED.items():
            self.assertGreater(len(why), 40, key)

    def test_known_offenders_are_still_offenders(self):
        """A stale entry silently exempts a file that no longer needs it, and
        the next one written there is invisible."""
        for (fname, var), why in KNOWN_DERIVED.items():
            path = _TESTS / fname
            self.assertTrue(path.exists(), fname)
            found = [n for _, n in _derived_sites(ast.parse(path.read_text()))]
            self.assertIn(var, found,
                          f'{fname} no longer derives a basename from {var!r} '
                          '— drop the KNOWN_DERIVED entry')


if __name__ == '__main__':
    unittest.main()
