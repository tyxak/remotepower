#!/usr/bin/env python3
"""One row of an entity store is read, changed and written as one step (`api._entity_update_one`).

`_entity_read_one` followed by `_entity_write_one` is two steps. Two requests of one host that arrive together can both read the same row, each compute the next one and each
act on what it read: the Windows inventory raised its alert twice for one new entry that way. `_entity_update_one(store, id, fn)` hands the stored row to `fn` and writes what
`fn` returns without another writer getting in between: one transaction on SQLite and Postgres (`storage.entity_update`, `storage_pg.entity_update`), the store's lock on the JSON
backend. These tests run on whichever backend the process was started with (`make test` JSON, `make test-sqlite` SQLite), with real threads.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-eu-'))

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_entity_update_one', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestEntityUpdateOne(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-eu-store-'))
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self.saved = api.PERSISTENCE_FILE
        api.PERSISTENCE_FILE = self.d / self.saved.name          # the file name is the storage key: keep it
        self.addCleanup(lambda: setattr(api, 'PERSISTENCE_FILE', self.saved))
        api._LOAD_CACHE.clear()
        self.store = api.PERSISTENCE_FILE

    def row(self, key='h1'):
        api._LOAD_CACHE.clear()
        return api._entity_read_one(self.store, key, None)

    def test_it_creates_a_row_that_is_not_there_and_hands_fn_none(self):
        seen = []
        self.assertTrue(api._entity_update_one(self.store, 'h1', lambda row: seen.append(row) or {'n': 1}))
        self.assertEqual((seen, self.row()), ([None], {'n': 1}))

    def test_it_hands_fn_the_stored_row_and_writes_what_fn_returns(self):
        api._entity_write_one(self.store, 'h1', {'n': 1})
        self.assertTrue(api._entity_update_one(self.store, 'h1', lambda row: {'n': row['n'] + 1}))
        self.assertEqual(self.row(), {'n': 2})

    def test_fn_returning_none_leaves_the_row_and_says_nothing_was_written(self):
        api._entity_write_one(self.store, 'h1', {'n': 1})
        self.assertFalse(api._entity_update_one(self.store, 'h1', lambda row: None))
        self.assertEqual(self.row(), {'n': 1})

    def test_an_error_in_fn_writes_nothing_and_reaches_the_caller(self):
        api._entity_write_one(self.store, 'h1', {'n': 1})

        def boom(row):
            raise ValueError('no')
        with self.assertRaises(ValueError):
            api._entity_update_one(self.store, 'h1', boom)
        self.assertEqual(self.row(), {'n': 1})
        self.assertFalse(api._locks_held(), 'the lock was released')

    def test_other_rows_are_not_touched(self):
        api._entity_write_one(self.store, 'h2', {'keep': True})
        api._entity_update_one(self.store, 'h1', lambda row: {'n': 1})
        self.assertEqual(self.row('h2'), {'keep': True})

    def test_a_row_of_the_wrong_shape_reaches_fn_as_no_row_on_the_database_backends(self):
        if api._dbmod() is None:
            self.skipTest('the JSON backend yields the whole store; the shape registry repairs a row when the store is read')
        api._dbmod().entity_set(self.store, 'h1', 'text, not a map')
        seen = []
        api._entity_update_one(self.store, 'h1', lambda row: seen.append(row) or {'n': 1})
        self.assertEqual(seen, [None], 'the repair every single-row read gets (a row that is not a map is left out)')

    def test_many_threads_changing_one_row_lose_no_update(self):
        """The read-then-write pair loses updates under threads; the single step does not."""
        api._entity_write_one(self.store, 'h1', {'n': 0})
        threads_n, each = 8, 15
        errors, skipped = [], []

        def bump(row):
            time.sleep(0.002)                                          # a window between the read and the write that every thread meets
            return {'n': row['n'] + 1}

        def work():
            for _ in range(each):
                for _attempt in range(400):
                    try:
                        if api._entity_update_one(self.store, 'h1', bump, non_blocking=True):
                            break
                    except Exception as e:                           # pragma: no cover - a failure here is a finding
                        errors.append(repr(e))
                        return
                    time.sleep(0.002)                                  # a lock that was held: the caller tries again, as the next report would
                else:
                    skipped.append(1)
        threads = [threading.Thread(target=work) for _ in range(threads_n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual((errors, skipped), ([], []))
        self.assertEqual(self.row()['n'], threads_n * each, 'every one of the %d changes is in the row' % (threads_n * each))

    def test_the_unsafe_pair_does_lose_updates_so_the_test_above_can_fail(self):
        """The control: the same work done as read, compute, write loses updates when two threads read before either writes."""
        api._entity_write_one(self.store, 'h1', {'n': 0})
        barrier = threading.Barrier(2)

        def work():
            row = api._entity_read_one(self.store, 'h1', None)
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
            api._entity_write_one(self.store, 'h1', {'n': row['n'] + 1}, non_blocking=False)
        threads = [threading.Thread(target=work) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(self.row()['n'], 1, 'two increments, one survives')

    def test_a_lock_that_is_held_is_not_waited_for_when_the_caller_says_not_to(self):
        api._entity_write_one(self.store, 'seed', {})                # this thread has its connection (and the schema) before another thread holds the lock
        held, release, result = threading.Event(), threading.Event(), {}

        def holder():
            with api._LockedUpdate(self.store):
                held.set()
                release.wait(20)
        t = threading.Thread(target=holder)
        t.start()
        self.assertTrue(held.wait(10))
        started = time.time()
        try:
            result['done'] = api._entity_update_one(self.store, 'h1', lambda row: {'n': 1}, non_blocking=True)
        finally:
            release.set()
            t.join(30)
        self.assertFalse(result['done'], 'nothing was written while the lock was held')
        self.assertLess(time.time() - started, 5, 'and it did not wait for the lock')
        self.assertIsNone(self.row())
        self.assertTrue(api._entity_update_one(self.store, 'h1', lambda row: {'n': 1}))
        self.assertEqual(self.row(), {'n': 1})


if __name__ == '__main__':
    unittest.main()
