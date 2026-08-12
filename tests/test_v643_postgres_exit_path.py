#!/usr/bin/env python3
"""Postgres is the enterprise default; the way OUT has to be real.

storage_pg carried `export_to_json` and `verify_against_json` with zero call
sites. The tempting read is "dead code, delete it" — but if they had been the
only way off Postgres, deleting them would have made an unreferenced function
into permanent lock-in, and the hygiene commit would have removed a capability
while claiming to remove duplication.

They were not. `api._migrate_storage_pg()` handles BOTH directions generically
through load()/save() — its own docstring says "target or source is 'postgres'"
— and `tools/migrate_storage.py --to json` is the operator-facing surface. The
two helpers were a second, unreferenced implementation of a path that already
works.

So this test does not check that the helpers are gone. It checks the thing that
made deleting them safe, and would fail if that ever stopped being true.
"""
import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_API = (_CGI / 'api.py').read_text()
_TOOL = _ROOT / 'tools' / 'migrate_storage.py'


class TestTheExitFromPostgresExists(unittest.TestCase):
    def test_the_cli_offers_json_as_a_target(self):
        self.assertTrue(_TOOL.is_file())
        src = _TOOL.read_text()
        self.assertIn('--to json', src)
        # and it must actually accept it, not merely document it
        m = re.search(r"add_argument\('--to'.*?\)", src, re.S)
        self.assertIsNotNone(m, 'the --to argument is gone')
        self.assertIn('json', m.group(0))

    def test_the_migrator_handles_postgres_as_the_SOURCE(self):
        """Not just as a destination. A one-way migrator is lock-in with a
        friendly name."""
        m = re.search(r'def _migrate_storage_pg\(.*?\n(?=def |class )', _API, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertRegex(body, r"src == 'postgres'")

    def test_the_migration_verifies_before_switching_backends(self):
        """The property that makes an exit trustworthy: the source stays
        authoritative until the round-trip is proven."""
        m = re.search(r'def _migrate_storage_pg\(.*?\n(?=def |class )', _API, re.S)
        body = m.group(0)
        self.assertIn('verify', body)

    def test_the_cli_routes_postgres_through_that_function(self):
        self.assertIn('_migrate_storage_pg', _TOOL.read_text())

    def test_the_removed_helpers_have_no_surviving_callers(self):
        """If anything still referenced them, the deletion was the bug."""
        for name in ('export_to_json', 'verify_against_json'):
            with self.subTest(helper=name):
                hits = []
                for p in list(_CGI.glob('*.py')) + list((_ROOT / 'tools').glob('*.py')):
                    if name in p.read_text():
                        hits.append(p.name)
                self.assertEqual(hits, [], f'{name} still referenced by {hits}')

    def test_import_from_json_survives(self):
        """The sibling that IS load-bearing — the restore path calls it by name
        to rehydrate an extracted archive into the DB backend. Deleting the
        wrong one of the three would break restore silently."""
        src = (_CGI / 'storage_pg.py').read_text()
        self.assertIn('def import_from_json(', src)
        self.assertIn("getattr(mod, 'import_from_json', None)", _API)


if __name__ == '__main__':
    unittest.main()
