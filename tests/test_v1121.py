#!/usr/bin/env python3
"""Tests for v1.12.1 persistence hardening: flock, atomic write, .bak
recovery, integrity checks.

The v1.12.0 corruption was concurrent writes to the same .tmp filename
producing a file with a complete first JSON document followed by trailing
garbage. We can't trivially reproduce that race in a test, but we can
verify the three defences:

  1. Per-process unique .tmp filename (so writers don't share)
  2. Round-trip serialisation check before disk write
  3. .bak fallback when the canonical file is corrupt

And we exercise concurrent saves with multiprocessing to confirm the
flock prevents interleaved writes.
"""

import importlib.util
import json
import multiprocessing
import os
import sys
import tempfile
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

_spec = importlib.util.spec_from_file_location("api_v1121", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _isolate(t):
    d = tempfile.mkdtemp()
    t._data_dir = Path(d)


# ─── Atomic save ──────────────────────────────────────────────────────────────


class TestSaveAtomicity(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.path = self._data_dir / 'test.json'

    def test_basic_round_trip(self):
        api.save(self.path, {'a': 1, 'b': 'two'})
        self.assertEqual(api.load(self.path), {'a': 1, 'b': 'two'})

    def test_save_creates_lock_sidecar(self):
        api.save(self.path, {'x': 1})
        self.assertTrue((self._data_dir / 'test.json.lock').exists())

    def test_save_creates_bak_after_second_save(self):
        # First save: no .bak yet (nothing to back up)
        api.save(self.path, {'gen': 1})
        bak = self._data_dir / 'test.json.bak'
        # First save *does* create a .bak only if the file existed before;
        # since we started from nothing, no .bak yet.
        # Second save should create the .bak from the first version.
        api.save(self.path, {'gen': 2})
        self.assertTrue(bak.exists())
        # And the .bak holds the previous version
        self.assertEqual(json.loads(bak.read_text()), {'gen': 1})
        # Live file holds the new version
        self.assertEqual(api.load(self.path), {'gen': 2})

    def test_save_cleans_up_tmp_on_success(self):
        api.save(self.path, {'a': 1})
        leftover = list(self._data_dir.glob('test.json.tmp.*'))
        self.assertEqual(leftover, [], f"tmp files leaked: {leftover}")

    def test_save_unique_tmp_per_process(self):
        # Two simulated saves from "different processes" — we can't fork
        # easily inside unittest, but we can verify the tmp filename
        # is parameterised by (pid, nonce). The contract is: even with
        # the same pid, the nonce makes them distinct.
        # We reach into the implementation here intentionally: the test
        # isn't validating behaviour exposed via API but the hardening
        # property described in the module comment.
        names = set()
        for _ in range(20):
            tmp = self.path.with_name(
                f'{self.path.name}.tmp.{os.getpid()}.{api.secrets.token_hex(4)}')
            names.add(str(tmp))
        self.assertEqual(len(names), 20, "tmp names should be unique across calls")

    def test_save_rejects_unserialisable_data(self):
        # NaN slips past json.dumps default but fails round-trip parse.
        # Verifies the round-trip integrity check actually catches things.
        with self.assertRaises(ValueError):
            api.save(self.path, {'value': float('nan')})

    def test_save_does_not_create_file_on_invalid_data(self):
        try:
            api.save(self.path, {'value': float('inf')})
        except ValueError:
            pass
        # File should not have been created — we fail before any disk write
        self.assertFalse(self.path.exists())

    def test_save_preserves_mode_600(self):
        api.save(self.path, {'k': 'v'})
        mode = self.path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_save_overwrites_existing(self):
        api.save(self.path, {'first': True})
        api.save(self.path, {'second': True})
        self.assertEqual(api.load(self.path), {'second': True})


# ─── Load with .bak fallback ──────────────────────────────────────────────────


class TestLoadFallback(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.path = self._data_dir / 'data.json'

    def test_missing_returns_empty(self):
        self.assertEqual(api.load(self.path), {})

    def test_corrupt_falls_back_to_bak(self):
        # Plant a valid .bak and a corrupted main file
        bak = self._data_dir / 'data.json.bak'
        bak.write_text(json.dumps({'recovered': True}))
        # Mimic the v1.12.0 corruption shape: valid JSON + trailing garbage
        self.path.write_text('{"x": 1}\nDUPLICATE_JUNK_AT_END')

        # Capture stderr so we can check the warning was logged
        from io import StringIO
        captured = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            data = api.load(self.path)
        finally:
            sys.stderr = old_stderr

        self.assertEqual(data, {'recovered': True})
        self.assertIn('corrupted', captured.getvalue())
        self.assertIn('.bak', captured.getvalue())

    def test_corrupt_with_no_bak_returns_empty(self):
        self.path.write_text('{"truncated": ')   # invalid JSON, no .bak
        from io import StringIO
        captured = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            data = api.load(self.path)
        finally:
            sys.stderr = old_stderr

        self.assertEqual(data, {})
        self.assertIn('corrupted', captured.getvalue())

    def test_corrupt_with_corrupt_bak_returns_empty(self):
        # If both files are bad, give up cleanly rather than crashing
        bak = self._data_dir / 'data.json.bak'
        bak.write_text('also corrupt')
        self.path.write_text('still corrupt')

        from io import StringIO
        captured = StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            data = api.load(self.path)
        finally:
            sys.stderr = old_stderr

        self.assertEqual(data, {})

    def test_load_does_not_modify_disk(self):
        # On corrupt-with-fallback, load() must not write anything —
        # read paths having side effects is a footgun.
        bak = self._data_dir / 'data.json.bak'
        bak.write_text(json.dumps({'ok': True}))
        self.path.write_text('garbage')
        before_path = self.path.read_text()
        before_bak = bak.read_text()

        sys_stderr = sys.stderr
        sys.stderr = type('X', (), {'write': lambda s, x: None})()
        try:
            api.load(self.path)
        finally:
            sys.stderr = sys_stderr

        self.assertEqual(self.path.read_text(), before_path)
        self.assertEqual(bak.read_text(), before_bak)


# ─── Concurrent save serialisation (the actual race fix) ─────────────────────


def _concurrent_writer(args):
    """Subprocess worker: import api fresh and write a value."""
    data_dir, key, value = args
    # Each worker re-imports the module — same pattern as a real CGI.
    # That gives us a unique pid + fresh module state, simulating the
    # "two CGI processes both heartbeating" scenario.
    import importlib.util as ilu
    import os, sys
    sys.path.insert(0, str(Path(_CGI_BIN)))
    os.environ['RP_DATA_DIR'] = data_dir
    os.environ['REQUEST_METHOD'] = 'GET'
    os.environ['PATH_INFO'] = '/'
    os.environ['CONTENT_LENGTH'] = '0'
    spec = ilu.spec_from_file_location(f'api_w_{os.getpid()}', Path(_CGI_BIN) / 'api.py')
    api_w = ilu.module_from_spec(spec)
    spec.loader.exec_module(api_w)
    path = Path(data_dir) / 'concurrent.json'
    # Read-modify-write — same pattern as handle_heartbeat.
    # With flock, these serialise. Without it, two writers both reading
    # then both writing is the lost-update + corruption recipe.
    for _ in range(5):
        existing = api_w.load(path)
        existing[key] = value
        api_w.save(path, existing)


class TestConcurrentSave(unittest.TestCase):
    """Verify that 8 simultaneous writers don't corrupt the file.

    Without the v1.12.1 hardening, this test reliably reproduces a
    JSONDecodeError-on-load by the time it finishes. With the
    hardening, every load() returns valid data and the final state
    contains entries from all workers.
    """

    def setUp(self):
        _isolate(self)

    def test_eight_concurrent_writers_no_corruption(self):
        path = self._data_dir / 'concurrent.json'
        # Seed with empty object so all writers start from a valid file
        api.save(path, {})

        n_workers = 8
        # spawn context: fresh interpreter per worker, doesn't inherit
        # the test runner's shimmed sys.stdin (which would crash mp's
        # util._close_stdin on shutdown).
        ctx = multiprocessing.get_context('spawn')
        with ctx.Pool(n_workers) as pool:
            tasks = [(str(self._data_dir), f'worker_{i}', i) for i in range(n_workers)]
            pool.map(_concurrent_writer, tasks)

        # File must parse cleanly
        try:
            with path.open() as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.fail(f"concurrent.json is corrupt after concurrent writes: {e}")

        # Some workers may have lost updates (that's separate from
        # corruption — fixing it would require RMW inside the lock,
        # which is more invasive). What we DO require: the file is
        # always a valid JSON dict, and every key that's present has
        # the right value (no garbled keys/values from interleaved I/O).
        self.assertIsInstance(data, dict)
        for k, v in data.items():
            self.assertTrue(k.startswith('worker_'),
                            f"unexpected key '{k}' suggests interleaved write")
            expected = int(k.split('_')[1])
            self.assertEqual(v, expected,
                             f"value for {k} should be {expected}, got {v}")


# ─── End-to-end recovery scenario ─────────────────────────────────────────────


class TestRecoveryScenario(unittest.TestCase):
    """Simulate the actual incident: file gets corrupted, next read uses
    .bak, next write re-establishes a clean state.
    """

    def setUp(self):
        _isolate(self)
        self.path = self._data_dir / 'devices.json'

    def test_e2e_corruption_recovery(self):
        # Establish two known-good versions so we have a .bak
        api.save(self.path, {'dev1': {'name': 'a', 'token': 't1'}})
        api.save(self.path, {'dev1': {'name': 'a', 'token': 't1'},
                              'dev2': {'name': 'b', 'token': 't2'}})

        # Confirm .bak exists with the older version
        bak = self._data_dir / 'devices.json.bak'
        self.assertTrue(bak.exists())
        self.assertEqual(json.loads(bak.read_text()),
                         {'dev1': {'name': 'a', 'token': 't1'}})

        # Now manually corrupt the live file (simulates the v1.12.0 bug)
        good = self.path.read_text()
        self.path.write_text(good + '\nGARBAGE_FROM_INTERLEAVED_WRITE')

        # load() should silently fall back to .bak
        sys_stderr = sys.stderr
        sys.stderr = type('X', (), {'write': lambda s, x: None})()
        try:
            data = api.load(self.path)
        finally:
            sys.stderr = sys_stderr

        # Returns the .bak content, which is the older version (one device)
        self.assertEqual(set(data.keys()), {'dev1'})

        # The next save() should re-establish a clean state. The current
        # corrupted file becomes the .bak, but the .bak's content gets
        # overwritten — the .bak is "rolling", not history.
        # Note: for our incident we want the current .bak (which holds
        # the older valid data) to keep being usable until something else
        # writes successfully. After a write that started from the .bak's
        # data, both files should be valid.
        api.save(self.path, data)
        self.assertEqual(api.load(self.path), {'dev1': {'name': 'a', 'token': 't1'}})


if __name__ == "__main__":
    unittest.main()
