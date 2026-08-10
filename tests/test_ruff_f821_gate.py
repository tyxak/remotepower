#!/usr/bin/env python3
"""The F821 gate must stay POINTED AT SOMETHING.

CLAUDE.md names `ruff check --select F821` as the mechanical detector for its
first false-green class — a source-TEXT test proves a line exists, never that
the names in it resolve. The agent's `apply_host_config` shipped with an
undefined `_re` that killed the entire apply (swallowed by the heartbeat's
`except Exception`) while every substring assertion in its test passed.

That detector worked on the agent and was DEAD on the server. api.py binds 513
names at runtime from its 30 `*_handlers.py` modules, which static analysis
cannot see, so the check reported 238 undefined names — every one a false
positive. Nobody reads a list that is 100% noise, so a real typo in the largest
file in the project would have sat there unnoticed. (CLAUDE.md recorded the
exemption as "~88 false positives"; it had grown to 238 with no one noticing.)

`tools/gen_ruff_builtins.py` generates the exemption straight from the bind
blocks. This file is what stops it from rotting: if a future carve adds, moves
or removes a bound name and the generated config is not refreshed, ruff starts
reporting that name as undefined in api.py — 1 hit today, 30 after the next
extraction — and the gate slides back toward noise.

Deliberately SOURCE-LEVEL ONLY: no subprocess, no `import ruff`. A test that
skips when its tool is missing is the false-green shape this repo keeps getting
bitten by. Running ruff is the Makefile `lint` target's job (a hard dependency,
like black and mypy); proving the gate is still wired and still accurate is
this file's job, and it works with nothing installed.
"""
import ast
import importlib.util
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / 'server' / 'cgi-bin' / 'api.py'
CONFIG = ROOT / 'tools' / 'ruff-api-builtins.toml'
GENERATOR = ROOT / 'tools' / 'gen_ruff_builtins.py'
MAKEFILE = ROOT / 'Makefile'


def _load_generator():
    """Import tools/gen_ruff_builtins.py without touching sys.path.

    The extraction lives in the generator, not duplicated here — a guard that
    reimplements the thing it guards drifts from it, which is the same
    two-hand-lists failure this whole change is about."""
    spec = importlib.util.spec_from_file_location('gen_ruff_builtins', GENERATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRuffF821Exemption(unittest.TestCase):
    def setUp(self):
        for p in (API, CONFIG, GENERATOR):
            if not p.exists():
                self.skipTest(f'{p.name} not present (dist tree?)')

    def test_config_matches_the_live_bind_lists(self):
        """The committed exemption == the names api.py actually binds."""
        gen = _load_generator()
        live = gen.bound_names(API.read_text())
        committed = set(tomllib.loads(CONFIG.read_text())['builtins'])

        missing = sorted(live - committed)
        extra = sorted(committed - live)
        self.assertEqual(
            (missing, extra), ([], []),
            'tools/ruff-api-builtins.toml is STALE — regenerate it:\n'
            '    python3 tools/gen_ruff_builtins.py\n'
            f'bound but not exempt (ruff will report these as undefined in '
            f'api.py): {missing}\n'
            f'exempt but no longer bound (a real typo of one of these would '
            f'now be invisible): {extra}')

    def test_the_exemption_is_not_empty_or_absurd(self):
        """A generator bug that emitted `builtins = []` would make the api.py
        pass report 238 errors again; one that emitted every identifier in the
        file would silence the check entirely. Both fail here."""
        committed = tomllib.loads(CONFIG.read_text())['builtins']
        self.assertGreater(len(committed), 300)
        self.assertLess(len(committed), 2000)
        self.assertEqual(len(committed), len(set(committed)), 'duplicate entries')
        self.assertEqual(committed, sorted(committed), 'list is not sorted — regenerate')

    def test_every_exempt_name_is_defined_by_some_handler_module(self):
        """Cross-check against the OTHER side of the bind: each exempt name
        must actually exist as a top-level def/assignment in one of the
        *_handlers.py modules. A name in the bind tuple that no module defines
        is a latent AttributeError at import time, and exempting it would hide
        that from F821 too."""
        defined = set()
        for mod in sorted((ROOT / 'server' / 'cgi-bin').glob('*_handlers.py')):
            for node in ast.parse(mod.read_text()).body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    defined.add(node.name)
                elif isinstance(node, ast.Assign):
                    defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    defined.add(node.target.id)

        committed = set(tomllib.loads(CONFIG.read_text())['builtins'])
        orphans = sorted(committed - defined)
        self.assertEqual(
            orphans, [],
            f'api.py binds {len(orphans)} name(s) that no *_handlers.py module '
            f'defines at top level — getattr() would raise at import: {orphans}')


class TestTheGateIsStillWired(unittest.TestCase):
    """Source-pin the Makefile invocation. Regenerating the exemption keeps the
    check ACCURATE; this keeps it RUN. Deleting the lint lines would otherwise
    be a silent, green-looking change."""

    def setUp(self):
        if not MAKEFILE.exists():
            self.skipTest('Makefile excluded from the dist tree')
        self.mk = MAKEFILE.read_text()
        m = re.search(r'^lint:\n((?:\t.*\n|.*\\\n)+)', self.mk, re.M)
        self.assertIsNotNone(m, 'lint target not found in the Makefile')
        self.recipe = m.group(1)

    def test_lint_runs_f821_on_api_py_with_the_exemption(self):
        self.assertIn('--select F821', self.recipe)
        self.assertIn('tools/ruff-api-builtins.toml', self.recipe)
        self.assertIn('server/cgi-bin/api.py', self.recipe)

    def test_lint_runs_f821_on_everything_else_WITHOUT_the_exemption(self):
        """The second pass is the important one: `builtins` is global, so if
        the exemption were applied repo-wide a typo of any of the 513 names
        would be silently accepted in every other file."""
        self.assertIn('--exclude server/cgi-bin/api.py', self.recipe)
        m = re.search(r'^RUFF_F821_SRC\s*:=\s*((?:.*\\\n)*.*)$', self.mk, re.M)
        self.assertIsNotNone(m, 'RUFF_F821_SRC not found')
        scope = m.group(1).replace('\\', ' ').split()
        # The shipped Python that a runtime NameError would actually break,
        # plus tests/ — where an undefined name hides best, since a typo in a
        # rarely-taken branch is never executed.
        for required in ('server/cgi-bin', 'client', 'server/flow',
                         'server/syslog', 'server/push', 'server/kmip', 'tests'):
            self.assertIn(required, scope,
                          f'{required} dropped out of the F821 scope')

    def test_ruff_is_pinned_in_install_dev(self):
        """An unpinned linter drifts with every release and starts flagging
        code its predecessor accepted — exactly how `make lint` silently broke
        between v4.2.0 and v4.3.0 (see the pin note in pyproject.toml)."""
        self.assertRegex(self.mk, r"install-dev:.*\n.*'ruff==\d+\.\d+\.\d+'")


if __name__ == '__main__':
    unittest.main()
