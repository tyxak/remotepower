#!/usr/bin/env python3
"""`_load_ro()` must actually skip the deepcopy — including on a COLD cache.

CLAUDE.md documents _load_ro as THE read-path optimisation and describes its
no-mutation contract as load-bearing. It was saving 1%.

Its cold path called load(), which reads the store, caches the canonical
object, and THEN deepcopies it — so the first read of a store in a request
paid exactly the copy _load_ro exists to avoid. Every request starts cold, and
most handlers read a given store once, so the common case got nothing.
Measured at 400 devices before the fix: cold load() 34.9 ms, cold _load_ro()
34.6 ms. After: 9.0 ms.

This is a behavioural pin, not a timing assertion — a wall-clock threshold
would be flaky on a loaded CI box. Identity is the honest test: _load_ro must
hand back the SAME object the cache holds, and load() must hand back a
different one.
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-loadro-'))
_spec = importlib.util.spec_from_file_location('api_loadro', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class TestLoadRoSkipsTheCopy(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a', 'sysinfo': {'x': [1, 2, 3]}}})
        api._LOAD_CACHE.clear()

    def test_cold_load_ro_returns_the_canonical_object(self):
        """The regression: on a COLD cache this used to return a fresh copy,
        because it fell through to load()."""
        first = api._load_ro(api.DEVICES_FILE)
        cached = api._LOAD_CACHE.get(api.DEVICES_FILE)
        self.assertIsNotNone(cached, 'the cold read did not warm the cache')
        self.assertIs(first, cached[0], 'cold _load_ro handed back a COPY')

    def test_warm_load_ro_returns_the_same_object_again(self):
        a = api._load_ro(api.DEVICES_FILE)
        b = api._load_ro(api.DEVICES_FILE)
        self.assertIs(a, b)

    def test_load_still_isolates_the_caller_from_the_cache(self):
        """The whole reason load() copies. If this ever fails, a caller doing
        `d = load(p); d['x'] = v` silently corrupts every later read in the
        same request."""
        api._LOAD_CACHE.clear()
        mine = api.load(api.DEVICES_FILE)
        mine['d1']['name'] = 'MUTATED'
        mine['d1']['sysinfo']['x'].append(99)
        fresh = api._load_ro(api.DEVICES_FILE)
        self.assertEqual(fresh['d1']['name'], 'a')
        self.assertEqual(fresh['d1']['sysinfo']['x'], [1, 2, 3],
                         'a NESTED mutation leaked into the cache')

    def test_load_returns_a_distinct_object_each_call(self):
        api._LOAD_CACHE.clear()
        self.assertIsNot(api.load(api.DEVICES_FILE), api.load(api.DEVICES_FILE))

    def test_invalidation_still_forces_a_re_read(self):
        api._load_ro(api.DEVICES_FILE)
        api.save(api.DEVICES_FILE, {'d2': {'name': 'b'}})
        self.assertIn('d2', api._load_ro(api.DEVICES_FILE))

    def test_a_missing_store_is_still_an_empty_dict(self):
        missing = api.DATA_DIR / 'no-such-store.json'
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(missing), {})
        self.assertEqual(api._load_ro(missing), {})


if __name__ == '__main__':
    unittest.main()
