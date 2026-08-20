#!/usr/bin/env python3
"""`install.sh --with-postgres` pointed the install at a database it could not
reach.

The flag runs `packaging/postgres-setup.sh --install --write-marker`, which
provisions the database and writes `storage_backend.json`. That marker makes
Postgres the ACTIVE backend for every request.

Nothing installed psycopg. `storage_pg._pg()` imports it lazily on the first
storage call, so with the marker written and no driver every request raised
ImportError — while install.sh printed "PostgreSQL provisioned + storage marker
written" and told the operator to go and migrate their data.

install-server.sh had a psycopg block; install.sh did not, and neither did
postgres-setup.sh, which is the script that actually writes the marker. The gap
was therefore in the one place both paths pass through.

Same shape as the push daemon's missing websockets: the capability was switched
on before the thing it needs existed, and the switch-on reported success. Fixed
the same way — install the driver, and if it is still not importable, refuse to
write the marker rather than leave the install pointing at a dead backend.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _text(rel):
    p = _ROOT / rel
    return p.read_text() if p.exists() else None


class TestTheDriverIsStillRequired(unittest.TestCase):
    """Premise. If storage_pg stops importing psycopg lazily, the rest of this
    file is asserting about nothing."""

    def test_storage_pg_imports_psycopg_lazily(self):
        src = _text('server/cgi-bin/storage_pg.py')
        self.assertIsNotNone(src)
        self.assertRegex(src, re.compile(r'^\s*import psycopg', re.M))

    def test_the_marker_is_what_selects_the_backend(self):
        src = _text('server/cgi-bin/api.py')
        self.assertIn('STORAGE_MARKER_FILE', src)


class TestTheMarkerIsNotWrittenWithoutTheDriver(unittest.TestCase):

    def setUp(self):
        self.sh = _text('packaging/postgres-setup.sh')
        self.assertIsNotNone(self.sh)
        self.block = self.sh[self.sh.index('if [ -n "$WRITE_MARKER" ]; then'):]

    def test_it_installs_psycopg_before_writing(self):
        head = self.block[:self.block.index('mkdir -p "$WRITE_MARKER"')]
        self.assertIn('psycopg', head,
                      'the marker is written without the driver being installed')
        for mgr in ('apt-get', 'dnf', 'pacman'):
            self.assertIn(mgr, head, f'no {mgr} arm')

    def test_it_refuses_to_write_the_marker_if_the_import_still_fails(self):
        """Installing can fail — behind a proxy, on an air-gapped host. Writing
        the marker anyway is what turned a missing package into a server that
        answers nothing."""
        head = self.block[:self.block.index('mkdir -p "$WRITE_MARKER"')]
        self.assertIn('exit 3', head,
                      'a failed driver install must abort before the marker')
        self.assertIn('NOT writing the storage marker', head)

    def test_the_guard_is_before_the_write_not_after(self):
        """Order is the whole fix. A check after the write leaves the marker on
        disk, which is the state that breaks the install."""
        i_guard = self.block.index('exit 3')
        i_write = self.block.index('storage_backend.json')
        self.assertLess(i_guard, i_write)


class TestTheCallerHandlesTheRefusal(unittest.TestCase):

    def test_install_sh_falls_back_instead_of_claiming_success(self):
        sh = _text('install.sh')
        # Anchor on the flags, not on a path that carries a shell quote.
        i = sh.index('--install --write-marker')
        seg = sh[i:i + 700]
        self.assertIn('continuing on the default backend', seg,
                      'a non-zero exit must not be reported as provisioned')
        # The success note tells the operator to go and migrate. It must be on
        # the success arm only.
        self.assertLess(seg.index('step_ok'), seg.index('step_no'))


if __name__ == '__main__':
    unittest.main()
