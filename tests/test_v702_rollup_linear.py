#!/usr/bin/env python3
"""The metric roll-up was O(fleet squared), with the write lock held throughout.

`run_metric_rollup_if_due` calls `_raw_metric_samples(dev_id, …)` once per
device, inside `with _LockedUpdate(METRICS_ROLLUP_FILE)`. On the JSON backend
that function did `load(METRICS_FILE)` — the WHOLE fleet's high-resolution
series — so the store was read and deep-copied once per device.

Measured on this machine, driving the real sweep:

     100 devices    0.78 s  ->  0.07 s
     500 devices   21.93 s  ->  0.29 s
    2000 devices   ~343 s   (reported by the sweep that found it)

For minutes at a time on a mid-size fleet, with the roll-up lock held, on a
sweep that fires from the cadence block.

Its own thermal twin, six lines further down the same file, reads its history
once above its loop and costs 52 ms / 305 ms / 1.0 s for the same shape. The
fix is the hoist the twin already had.

This file asserts the SHAPE — cost must grow about linearly with fleet size —
because a correctness-only test passes at either complexity, and the version
that shipped was correct.
"""
import importlib.util
import os
import pathlib
import sys
import tempfile
import time
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v702ru-'))
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('api_v702ru', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api_v702ru'] = api
_spec.loader.exec_module(api)


def _seed(n):
    d = pathlib.Path(tempfile.mkdtemp(prefix=f'rp-ru{n}-'))
    # DATA_DIR too, not just the three paths.
    #
    # Under `make test-sqlite` the basename IS the storage key and the database
    # lives under DATA_DIR — so rebinding the paths alone left this sharing one
    # database with every other module in the run. run_metric_rollup_if_due
    # reads a `_meta` row for its is-it-due check, another test had already
    # stamped last_run there, and the sweep returned immediately having rolled
    # up nothing. The failure read as "the roll-up skipped devices".
    api.DATA_DIR = d
    for k in ('DEVICES_FILE', 'METRICS_FILE', 'METRICS_ROLLUP_FILE'):
        setattr(api, k, d / getattr(api, k).name)
    now = int(time.time())
    api.save(api.DEVICES_FILE, {f'd{i}': {'name': f'h{i}'} for i in range(n)})
    api.save(api.METRICS_FILE, {f'd{i}': [
        {'ts': now - 60 * j, 'cpu': 10.0, 'mem': 20.0, 'swap': 0.0, 'disk': 30.0}
        for j in range(30)] for i in range(n)})
    api.save(api.METRICS_ROLLUP_FILE, {})
    api._LOAD_CACHE.clear()
    return now


def _run(n):
    _seed(n)
    start = time.perf_counter()
    api.run_metric_rollup_if_due()
    return time.perf_counter() - start


_DB_BACKEND = os.environ.get('RP_STORAGE_BACKEND') in ('sqlite', 'postgres')


@unittest.skipIf(_DB_BACKEND,
                 'the raw series lives in a dedicated metrics table on a DB '
                 'backend, written by the heartbeat — save(METRICS_FILE, ...) '
                 'seeds the entity store, which metric_range does not read. '
                 'The behaviour under test (hoisting the whole-fleet read out '
                 'of the per-device loop) is the JSON path by construction: on '
                 'a DB backend _raw_metric_samples already answers per device '
                 'and ignores the hoisted store, which the class below asserts '
                 'directly.')
class TestItStillRollsUp(unittest.TestCase):
    """First: a sweep that did nothing would be very fast."""

    def test_it_produces_rollups_for_every_device(self):
        _seed(20)
        api.run_metric_rollup_if_due()
        api._LOAD_CACHE.clear()
        state = api.load(api.METRICS_ROLLUP_FILE) or {}
        rows = [k for k in state if k != '_meta']
        self.assertEqual(len(rows), 20, 'the roll-up skipped devices')
        one = state['d0']
        for band in ('fivemin', 'hourly', 'daily'):
            self.assertTrue(one.get(band), f'{band} is empty')
        self.assertGreater(one.get('last_ts', 0), 0)

    def test_it_claims_its_slot_so_a_second_worker_skips(self):
        _seed(10)
        api.run_metric_rollup_if_due()
        api._LOAD_CACHE.clear()
        first = (api.load(api.METRICS_ROLLUP_FILE) or {}).get('_meta', {}).get('last_run')
        api.run_metric_rollup_if_due()
        api._LOAD_CACHE.clear()
        second = (api.load(api.METRICS_ROLLUP_FILE) or {}).get('_meta', {}).get('last_run')
        self.assertEqual(first, second, 'the interval gate stopped working')


@unittest.skipIf(_DB_BACKEND, 'see TestItStillRollsUp — JSON-path timing')
class TestItIsLinearInFleetSize(unittest.TestCase):

    def test_quadrupling_the_fleet_does_not_square_the_cost(self):
        small, large = _run(50), _run(200)
        # Quadratic would be ~16x plus the constant; linear is ~4x. A generous
        # ceiling keeps this from flaking on a loaded machine while still
        # failing by an order of magnitude if the per-device read comes back.
        self.assertLess(
            large, max(small * 9, 0.5),
            f'50 devices took {small*1000:.0f} ms and 200 took {large*1000:.0f} ms '
            f'({large/max(small,1e-9):.1f}x for 4x the fleet) — the whole metrics '
            f'store is being read per device again')

    def test_a_mid_size_fleet_is_not_seconds(self):
        took = _run(300)
        self.assertLess(took, 3.0,
                        f'300 devices took {took:.1f} s with the roll-up lock '
                        f'held; it was 21.9 s at 500 before the hoist')


class TestTheSamplerAcceptsAPreloadedStore(unittest.TestCase):

    def test_the_hoisted_store_is_actually_passed(self):
        sys.path.insert(0, str(pathlib.Path(__file__).parent))
        import srcpin
        body = srcpin.py_function(
            (_CGI / 'rollup_handlers.py').read_text(), 'run_metric_rollup_if_due')
        code = '\n'.join(l for l in body.splitlines()
                         if not l.lstrip().startswith('#'))
        self.assertIn('_store=', code,
                      'the per-device call is back to loading the whole store')

    def test_the_db_backends_still_answer_per_device(self):
        """The pre-loaded store must be ignored where a real per-row read
        exists, or a DB install would start reading a JSON blob."""
        sys.path.insert(0, str(pathlib.Path(__file__).parent))
        import srcpin
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  '_raw_metric_samples')
        self.assertLess(body.index('metric_range'), body.index('_store if'),
                        'the DB path must come first')


if __name__ == '__main__':
    unittest.main()
