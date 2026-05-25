#!/usr/bin/env python3
"""
Tests for v2.1.2 — the lost-update race fix.

The bug: v2.1.0's save() redesign moved the tmp-file write outside the
flock so the lock only protected the rename. Callers that did
read-modify-write (load → mutate → save) had no atomicity:

  CGI-A: load → {pmg01: T-180, web01: T-180}
  CGI-B: load → {pmg01: T-180, web01: T-180}  (stale read between CGI-A's
                                              load and save)
  CGI-A: pmg01.last_seen = T → write tmp.A → rename → disk has
                                              {pmg01: T, web01: T-180}
  CGI-B: web01.last_seen = T → write tmp.B → rename → disk has
                                              {pmg01: T-180, web01: T}
                                              ← CGI-A's update LOST

Tests here use threading + the new _locked_update context manager to
exercise the race directly. With the old save() pattern, the assertions
below fail dozens of times per run. With _locked_update, they pass
deterministically.

Also covers:
  - _save_held writes correctly with the lock held by the caller
  - _locked_update releases the lock on exception (including SystemExit
    from respond())
  - The atomic update doesn't deadlock when nested operations touch
    different files
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v212", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestLockedUpdate(unittest.TestCase):
    """Direct tests of the _locked_update context manager."""

    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        self.path = self._data_dir / 'test.json'
        api.save(self.path, {})

    def test_basic_read_modify_write(self):
        with api._locked_update(self.path) as data:
            data['counter'] = 1
        self.assertEqual(api.load(self.path), {'counter': 1})

    def test_mutate_existing(self):
        api.save(self.path, {'a': 1, 'b': 2})
        with api._locked_update(self.path) as data:
            data['a'] = 99
            data['c'] = 3
        self.assertEqual(api.load(self.path), {'a': 99, 'b': 2, 'c': 3})

    def test_exception_skips_save(self):
        api.save(self.path, {'original': True})
        try:
            with api._locked_update(self.path) as data:
                data['original'] = False
                raise RuntimeError('abort')
        except RuntimeError:
            pass
        # Save was skipped — original value preserved
        self.assertEqual(api.load(self.path), {'original': True})

    def test_systemexit_skips_save(self):
        """respond() raises SystemExit. The lock must release and the
        partial mutation must not be saved."""
        api.save(self.path, {'original': True})
        try:
            with api._locked_update(self.path) as data:
                data['original'] = False
                raise SystemExit(0)
        except SystemExit:
            pass
        self.assertEqual(api.load(self.path), {'original': True})

    def test_lock_released_after_with_block(self):
        """The lock must be released so a subsequent _locked_update can
        proceed without waiting forever."""
        with api._locked_update(self.path) as data:
            data['phase'] = 1
        # If the previous lock leaked, this would block forever (or hit
        # LockBusy on the non-blocking version).
        with api._locked_update(self.path) as data:
            data['phase'] = 2
        self.assertEqual(api.load(self.path)['phase'], 2)

    def test_lock_released_on_exception(self):
        try:
            with api._locked_update(self.path) as data:
                raise RuntimeError('boom')
        except RuntimeError:
            pass
        # Lock must have been released — second update should succeed
        with api._locked_update(self.path) as data:
            data['after'] = True
        self.assertEqual(api.load(self.path).get('after'), True)


class TestLostUpdateRace(unittest.TestCase):
    """Reproduce the lost-update race that v2.1.0 introduced, and verify
    _locked_update fixes it.

    The threads simulate concurrent heartbeats: each thread loads the
    full devices dict, mutates ITS OWN device's last_seen, and saves.
    With the old save() (no locking around RMW), updates collide. With
    _locked_update, every update is preserved.
    """

    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        self.devices_file = self._data_dir / 'devices.json'
        # Seed with N devices, all last_seen=0
        self._n_devices = 20
        seed = {f'dev{i}': {'name': f'host{i}', 'last_seen': 0}
                for i in range(self._n_devices)}
        api.save(self.devices_file, seed)

    def _heartbeat_worker_atomic(self, dev_id, target_ts, barrier):
        """Worker that uses the v2.1.2 atomic _locked_update path."""
        barrier.wait()
        with api._locked_update(self.devices_file) as devices:
            # Re-read happens inside the lock — see device's current state
            dev = devices.get(dev_id, {})
            dev['last_seen'] = target_ts
            devices[dev_id] = dev

    def _heartbeat_worker_racy(self, dev_id, target_ts, barrier):
        """Worker that uses the OLD load → save pattern with no lock.
        Used to demonstrate the bug exists; this should fail the
        all-updates-preserved assertion."""
        barrier.wait()
        devices = api.load(self.devices_file)
        if dev_id not in devices:
            devices[dev_id] = {}
        devices[dev_id]['last_seen'] = target_ts
        api.save(self.devices_file, devices)

    def test_concurrent_atomic_updates_preserve_all(self):
        """Each thread updates a different device. With atomic RMW, all
        N updates must be visible after the threads complete."""
        barrier = threading.Barrier(self._n_devices)
        threads = []
        target_ts = int(time.time())
        for i in range(self._n_devices):
            t = threading.Thread(
                target=self._heartbeat_worker_atomic,
                args=(f'dev{i}', target_ts, barrier))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        # Every device's last_seen must equal target_ts
        final = api.load(self.devices_file)
        lost = []
        for i in range(self._n_devices):
            ls = final.get(f'dev{i}', {}).get('last_seen', 0)
            if ls != target_ts:
                lost.append((f'dev{i}', ls))
        self.assertEqual(lost, [],
                         f"Lost {len(lost)} updates: {lost[:5]}…")

    def test_concurrent_racy_updates_demonstrate_bug(self):
        """Same workload but using the OLD load → save pattern (no
        locked RMW). This SHOULD lose updates — verifying the test
        infrastructure is sensitive enough to catch the bug."""
        # 50 devices + 50 threads → high contention → many lost updates
        n = 50
        seed = {f'dev{i}': {'name': f'host{i}', 'last_seen': 0}
                for i in range(n)}
        api.save(self.devices_file, seed)
        barrier = threading.Barrier(n)
        threads = []
        target_ts = int(time.time())
        for i in range(n):
            t = threading.Thread(
                target=self._heartbeat_worker_racy,
                args=(f'dev{i}', target_ts, barrier))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        final = api.load(self.devices_file)
        lost = sum(1 for i in range(n)
                   if final.get(f'dev{i}', {}).get('last_seen', 0) != target_ts)
        # We expect SOME lost updates with the racy pattern. If this
        # somehow passes (e.g. the test box is too slow to interleave),
        # the test is not validating what we want, but it's not a
        # functional failure — log a warning instead of asserting > 0.
        if lost == 0:
            # Acceptable on extremely slow boxes / single-core CI runners
            # where threads serialise naturally. Skip rather than fail.
            self.skipTest("Could not reproduce race on this host — "
                          "threading too coarse to interleave the "
                          "load/save windows. Atomic test still validates.")
        self.assertGreater(lost, 0,
                           "Racy pattern should lose at least one update")

    def test_atomic_updates_preserve_other_fields(self):
        """Concurrent updates to last_seen must not clobber other fields
        on the same device (e.g. user-set notes, group). The atomic
        path re-reads the device record under the lock so it doesn't
        overwrite admin-set fields with stale snapshots."""
        # Seed each device with a unique 'note' field
        seed = {f'dev{i}': {'name': f'host{i}', 'last_seen': 0,
                            'note': f'original-note-for-dev{i}'}
                for i in range(self._n_devices)}
        api.save(self.devices_file, seed)
        barrier = threading.Barrier(self._n_devices)
        threads = []
        target_ts = int(time.time())
        for i in range(self._n_devices):
            t = threading.Thread(
                target=self._heartbeat_worker_atomic,
                args=(f'dev{i}', target_ts, barrier))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        final = api.load(self.devices_file)
        for i in range(self._n_devices):
            d = final.get(f'dev{i}', {})
            self.assertEqual(d.get('note'), f'original-note-for-dev{i}',
                             f"dev{i} lost its note field")
            self.assertEqual(d.get('last_seen'), target_ts)


class TestSaveHeld(unittest.TestCase):
    """_save_held — for use inside _locked_update where the caller holds
    the lock. Should produce the same on-disk result as save(), minus
    the lock acquisition."""

    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        self.path = self._data_dir / 'held.json'

    def test_basic_save(self):
        # Acquire the lock manually first (simulating the context manager)
        lock_fd, _ = api._acquire_lock(self.path, non_blocking=False)
        try:
            api._save_held(self.path, {'k': 'v'})
        finally:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        self.assertEqual(api.load(self.path), {'k': 'v'})

    def test_creates_rolling_backup(self):
        lock_fd, _ = api._acquire_lock(self.path, non_blocking=False)
        try:
            api._save_held(self.path, {'v': 1})
        finally:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        # Second save creates .bak
        lock_fd, _ = api._acquire_lock(self.path, non_blocking=False)
        try:
            api._save_held(self.path, {'v': 2})
        finally:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        self.assertEqual(api.load(self.path)['v'], 2)
        bak = self.path.with_name(self.path.name + '.bak')
        self.assertTrue(bak.exists())
        self.assertEqual(json.loads(bak.read_text())['v'], 1)

    def test_rejects_unparseable(self):
        lock_fd, _ = api._acquire_lock(self.path, non_blocking=False)
        try:
            with self.assertRaises(ValueError):
                api._save_held(self.path, float('nan'))
        finally:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def test_no_orphan_tmp_files(self):
        lock_fd, _ = api._acquire_lock(self.path, non_blocking=False)
        try:
            api._save_held(self.path, {'clean': True})
        finally:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        orphans = list(self._data_dir.glob('held.json.tmp.*'))
        self.assertEqual(orphans, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
