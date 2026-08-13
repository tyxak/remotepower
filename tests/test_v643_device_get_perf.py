#!/usr/bin/env python3
"""device_get() copied the whole fleet to return one device.

Its docstring promises "READ ONE device by id without loading the whole devices
store … under SQLite/Postgres this is a single-row SELECT". Both of its paths
did the opposite:

  * JSON backend (the default on a small install): `load(DEVICES_FILE)`, which
    deep-copies the ENTIRE store on every read, warm or cold — a full-fleet copy
    to perform a dict lookup.
  * DB backends with a warm request cache: `_peek_load_cache(DEVICES_FILE)`,
    which deep-copied the entire cached document and then discarded all but one
    device. That path is taken whenever anything has already read devices in the
    same request, which is most of them, and it was measured at 332x SLOWER than
    the single-row read it exists to avoid.

Measured here on 400 devices: 38.3 ms per call before, 0.074 ms after — and
there are 42 call sites, several inside loops, so the cost was N x that.

The reason it survived is worth keeping: the deep copy is not gratuitous. It is
what stops a caller mutating the shared cache, and load() is deep by design for
exactly that reason. The fix is not to remove the copy but to copy the SELECTED
device instead of the fleet, which is why every test below checks a correctness
property rather than only the timing.

The timing assertion is deliberately loose (a ratio, on a fixture sized to make
the difference structural) because a wall-clock threshold on a shared CI box is
a flake generator. What it actually pins is that the cost does not scale with
FLEET SIZE — which is the defect.
"""
import copy
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-dgperf-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


def _fleet(n):
    return {f'dev{i}': {
        'name': f'host{i}.lab', 'tenant': 'default',
        'sysinfo': {'cpu': [0.1] * 64,
                    'mounts': [{'m': f'/m{j}', 'pct': j} for j in range(30)],
                    'ports': [{'p': 1000 + j} for j in range(60)],
                    'proc_names': [f'p{j}' for j in range(120)]}} for i in range(n)}


class _Base(unittest.TestCase):
    N = 400

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-dg-'))
        self._df = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / 'devices.json'
        api.save(api.DEVICES_FILE, _fleet(self.N))
        # Warm the request cache the way a list handler would, which is the
        # state in which the defect appeared.
        self.store = api.load(api.DEVICES_FILE)
        self.assertEqual(len(self.store), self.N)

    def tearDown(self):
        api.DEVICES_FILE = self._df


class TestCorrectnessIsUnchanged(_Base):
    """These matter more than the timing: the deep copy exists to stop a caller
    corrupting the shared cache, and the fix narrows it rather than removing it."""

    def test_returns_the_right_device(self):
        self.assertEqual(api.device_get('dev200')['name'], 'host200.lab')

    def test_a_mutating_caller_cannot_corrupt_the_cache(self):
        got = api.device_get('dev200')
        got['name'] = 'MUTATED'
        self.assertEqual(api.device_get('dev200')['name'], 'host200.lab')

    def test_the_copy_is_deep_not_shallow(self):
        """A shallow copy would pass the test above and still let a caller
        mutate nested state — which is most of a device record."""
        got = api.device_get('dev200')
        got['sysinfo']['cpu'][0] = 999
        got['sysinfo']['mounts'].append({'m': '/injected'})
        again = api.device_get('dev200')
        self.assertEqual(again['sysinfo']['cpu'][0], 0.1)
        self.assertEqual(len(again['sysinfo']['mounts']), 30)

    def test_the_shared_store_itself_is_undamaged(self):
        got = api.device_get('dev200')
        got['sysinfo']['ports'].clear()
        self.assertEqual(len(api.load(api.DEVICES_FILE)['dev200']['sysinfo']['ports']), 60)

    def test_missing_id_returns_the_default(self):
        self.assertIsNone(api.device_get('nope'))
        sentinel = object()
        self.assertIs(api.device_get('nope', sentinel), sentinel)

    def test_a_cold_cache_still_works(self):
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(api.device_get('dev7')['name'], 'host7.lab')


class TestCostDoesNotScaleWithFleetSize(_Base):

    def test_one_read_is_far_cheaper_than_copying_the_fleet(self):
        n = 40
        t0 = time.perf_counter()
        for _ in range(n):
            api.device_get('dev200')
        per_call = (time.perf_counter() - t0) / n

        t0 = time.perf_counter()
        for _ in range(n):
            copy.deepcopy(self.store)
        per_fleet_copy = (time.perf_counter() - t0) / n

        # POSITIVE CONTROL: if copying 400 devices is not measurably expensive on
        # this box, the comparison below proves nothing, so say so rather than
        # passing.
        self.assertGreater(per_fleet_copy, 0.002,
                           'copying the fleet is too cheap here to measure '
                           'against — this assertion would be vacuous')
        self.assertLess(per_call, per_fleet_copy / 10,
                        f'device_get costs {per_call * 1000:.2f} ms against a '
                        f'{per_fleet_copy * 1000:.2f} ms fleet copy — it is '
                        'still paying for the whole store to read one device')


if __name__ == '__main__':
    unittest.main()
