#!/usr/bin/env python3
"""A store written for the FIRST time during a backend migration was lost.

`_migrate_storage_pg` snapshotted `backend_iter_files()` once, before the copy
loop. The source backend stays active until verification passes, so a live
request can write during the migration. The catch-up loop existed for exactly
that — but it iterated the opening snapshot, so it only ever re-copied files
that already existed. A store created mid-run was in none of the three passes:
not copied, not caught up, not verified. The marker then flipped and it was
gone.

That is different from the memoised-read bug the catch-up loop's own comment
documents. That one lost an UPDATE to a known file. This one lost the file.

How a store gets created mid-migration on a live install: the first alert of
the day creating alerts.json, a first CVE scan creating cve_findings.json, a
first webhook delivery creating webhook_log.json. Roughly 150 logical stores
exist and most are created lazily on first write, so on any install that has
not yet exercised every feature the window is real.

Driven through the real function with a real backend on both sides, because a
hand-built file list would assert against the fixture rather than the code.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-mig-'))
_spec = importlib.util.spec_from_file_location('api_mig_new_store', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestAStoreCreatedDuringMigrationSurvives(unittest.TestCase):
    """JSON -> SQLite, which `_migrate_storage_pg` also handles (target may be
    sqlite). No database server needed, and the defect is in the shared file-list
    logic, not in either backend."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-mig-run-'))
        self._saved = {k: getattr(api, k) for k in ('DATA_DIR', 'STORAGE_MARKER_FILE')}
        api.DATA_DIR = self.dir
        api.STORAGE_MARKER_FILE = self.dir / '.storage-backend'
        import storage
        self.storage = storage
        api._invalidate_load_cache(self.dir / 'devices.json')

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def _seed(self):
        self.storage._write_json_atomic(self.dir / 'devices.json',
                                        {'d1': {'name': 'web01'}})
        self.storage._write_json_atomic(self.dir / 'config.json', {'poll': 60})

    def _migrate(self, during=None):
        """Run the migration, optionally creating a NEW store partway through.

        The hook fires from inside the log callback, which the copy loop calls
        once per file — the same point in the run a concurrent request would
        land, without needing a second process."""
        fired = []

        def _log(msg):
            if during and not fired and msg.strip().startswith('json ->'):
                fired.append(True)
                during()

        return api._migrate_storage_pg('sqlite', dsn='', log=_log)

    def test_the_control_migrates_what_was_already_there(self):
        """Positive control. Without this, a migration that silently did
        nothing would satisfy the test below by accident."""
        self._seed()
        res = self._migrate()
        self.assertTrue(res.get('ok'), res)
        self.assertEqual({'d1': {'name': 'web01'}},
                         self.storage.load(self.dir / 'devices.json'))

    def test_a_store_created_mid_migration_is_not_lost(self):
        self._seed()

        def _first_alert_of_the_day():
            # A store that did not exist when the file list was taken.
            self.storage._write_json_atomic(
                self.dir / 'alerts.json',
                {'alerts': [{'id': 'a1', 'event': 'device_offline',
                             'device_id': 'd1', 'status': 'open'}]})

        res = self._migrate(during=_first_alert_of_the_day)
        self.assertTrue(res.get('ok'), res)

        got = self.storage.load(self.dir / 'alerts.json')
        self.assertTrue(
            got and (got.get('alerts') if isinstance(got, dict) else got),
            'the alert written during the migration is absent from the target '
            'backend — it was copied by no pass and caught by no check, and '
            'the marker flipped anyway')
        self.assertEqual('a1', got['alerts'][0]['id'])

    def test_the_created_store_is_also_verified(self):
        """Copying it is half the fix. If it is not in the verify loop, a
        partial write during the migration still flips the marker."""
        self._seed()
        seen = {}

        def _create():
            self.storage._write_json_atomic(self.dir / 'alerts.json', {'alerts': []})

        real_norm = self.storage._norm

        def _spy(v):
            seen['n'] = seen.get('n', 0) + 1
            return real_norm(v)

        self.storage._norm = _spy
        try:
            res = self._migrate(during=_create)
        finally:
            self.storage._norm = real_norm
        self.assertTrue(res.get('ok'), res)
        # 2 comparisons per file: source and target.
        self.assertGreaterEqual(seen.get('n', 0), 6,
                                'alerts.json was not in the verify loop')


if __name__ == '__main__':
    unittest.main()
