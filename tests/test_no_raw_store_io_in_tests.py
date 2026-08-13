#!/usr/bin/env python3
"""A test that reads or writes a storage key as a FILE only works on one backend.

A `DATA_DIR`-relative `*.json` is a LOGICAL storage key. Under the JSON backend
it happens to be a file; under SQLite and Postgres — and Postgres is the
enterprise default — it is a row in a table and there is no file at all. So a
fixture that does

    (d / 'roles.json').write_text(json.dumps({...}))

writes somewhere no loader will ever look, the code under test sees an empty
store, and the assertion fails for a reason that has nothing to do with the
behaviour being tested.

`tests/test_v342.py` had 28 of these. On SQLite it reported 8 failures and 2
errors, including `_scope_block_device` raising no HTTPError — which reads
exactly like an RBAC scope gate failing open on one backend. It was not: the
device fixture simply was not visible, so there was nothing to block. A test
that fails for a fake reason is worse than one that does not exist, because
somebody has to spend the afternoon proving it is fake, and until they do, the
whole SQLite suite is a known-red wall nobody reads.

The fix is always the same: go through the storage layer.

    api.save(api.ROLES_FILE, {...})        instead of  path.write_text(...)
    api.load(api.ROLES_FILE) or {}         instead of  json.loads(path.read_text())

This guard is a shrink-only ceiling rather than a hard zero, because a handful of
files legitimately touch real files — the storage marker read before a backend is
chosen, the `.backup_in_progress` sentinel, tarball and PEM fixtures. Those are
not storage keys. What it stops is the count growing.
"""
import re
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent

# Shrink-only. Every remaining site was reviewed and is either a real file or a
# non-store artefact. Lower this when a site is converted; never raise it
# without saying why in the commit message.
RAW_STORE_IO_CEILING = 36

# `<something>.json` handled as a filesystem path.
_PATTERNS = (
    re.compile(r"/ '[a-z_]+\.json'\)\s*\.\s*(?:read|write)_text\("),
    re.compile(r"\b[A-Z_]+_FILE\s*\.\s*(?:read|write)_text\("),
    re.compile(r"json\.loads\(\s*\([^)]*/ '[a-z_]+\.json'\)\.read_text\(\)"),
)

# Files that legitimately do filesystem IO on something that is NOT a storage
# key. Each needs a reason; an undeclared exemption is indistinguishable from a
# site nobody checked.
EXEMPT_FILES = {
    'test_no_raw_store_io_in_tests.py': 'this file quotes the patterns it bans',
}


def _offenders():
    out = []
    for f in sorted(_TESTS.glob('test_*.py')):
        if f.name in EXEMPT_FILES:
            continue
        src = f.read_text()
        n = sum(len(p.findall(src)) for p in _PATTERNS)
        if n:
            out.append((f.name, n))
    return out


class TestTheScanWorks(unittest.TestCase):
    """Positive controls — a count assertion passes just as happily when the
    patterns match nothing at all."""

    def test_it_matches_the_shape_it_bans(self):
        for snippet in ("(d / 'roles.json').write_text(json.dumps(x))",
                        "(_P(d) / 'devices.json').read_text()",
                        "api.CONFIG_FILE.write_text('{}')"):
            self.assertTrue(any(p.search(snippet) for p in _PATTERNS), snippet)

    def test_it_does_not_match_the_replacement(self):
        """The whole point is that the storage-layer form is fine."""
        for ok in ("api.save(api.ROLES_FILE, {})",
                   "api.load(api.DEVICES_FILE) or {}",
                   "(tmp / 'bundle.tar.gz').write_bytes(b'x')"):
            self.assertFalse(any(p.search(ok) for p in _PATTERNS), ok)


class TestRawStoreIoDoesNotGrow(unittest.TestCase):

    def test_count_is_at_or_under_the_ceiling(self):
        total = sum(n for _, n in _offenders())
        self.assertLessEqual(
            total, RAW_STORE_IO_CEILING,
            'tests are reading/writing storage keys as FILES, which only works '
            'on the JSON backend — on SQLite/Postgres the store is a table and '
            'the fixture writes into a void:\n'
            + '\n'.join(f'  {f}: {n}' for f, n in _offenders())
            + '\nUse api.save(api.X_FILE, data) / api.load(api.X_FILE).')

    def test_the_ceiling_tracks_the_real_count(self):
        """Shrink-only: converting sites must lower the ceiling, or it quietly
        buys room for new ones."""
        total = sum(n for _, n in _offenders())
        self.assertEqual(
            RAW_STORE_IO_CEILING, total,
            f'ceiling is {RAW_STORE_IO_CEILING} but the real count is {total} '
            '— lower it to match')

    def test_the_file_that_had_28_is_clean(self):
        """tests/test_v342.py is the reason this guard exists."""
        self.assertEqual(
            [n for f, n in _offenders() if f == 'test_v342.py'], [],
            'test_v342.py has regained raw store IO — it was 28 sites and 10 '
            'red tests on SQLite')

    def test_every_exemption_states_a_reason(self):
        for f, why in EXEMPT_FILES.items():
            self.assertGreater(len(why), 20, f)


if __name__ == '__main__':
    unittest.main()
