"""v5.6.0 — File Manager long-poll must see the agent's result across processes.

Bug: the File Manager (and any `_longpoll_wait` round-trip) always reported
"No response from the agent within timeout" even though the agent ran the op.
Cause: `load()` memoises per request; `_longpoll_wait` loops `load(LONGPOLL_FILE)`
for the whole timeout inside ONE request, so after the first read it kept
returning its own cached `ready:False` snapshot and never saw the `ready:True`
that the agent's follow-up heartbeat (a DIFFERENT process) wrote to disk. The fix
busts the cache each poll.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-lp-'))
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_lp', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_API_SRC = (_CGI / 'api.py').read_text()


class TestLongpollBustsCache(unittest.TestCase):
    def test_source_invalidates_cache_each_poll(self):
        seg = _API_SRC[_API_SRC.index('def _longpoll_wait'):
                       _API_SRC.index('def _longpoll_wait') + 1400]
        self.assertIn('_invalidate_load_cache(LONGPOLL_FILE)', seg,
                      'the poll loop must bust the per-request load cache')

    def test_waiter_sees_cross_process_ready(self):
        dev = 'dev-longpoll'
        slot = {'cmd': 'files:list:x', 'ready': False, 'output': None, 'ts': 0}
        api.save(api.LONGPOLL_FILE, {dev: slot})
        if not Path(api.LONGPOLL_FILE).exists():
            self.skipTest('flat-JSON-only: LONGPOLL_FILE is a DB row on this backend')
        # Prime THIS request's load cache with ready:False (what the waiter sees first).
        self.assertFalse(api.load(api.LONGPOLL_FILE)[dev]['ready'])
        # Another process (the agent's follow-up heartbeat) writes ready:True
        # straight to the store — it does NOT touch our in-process cache.
        done = {'cmd': 'files:list:x', 'ready': True,
                'output': {'cmd': 'files:list:x', 'rc': 0, 'output': '{"entries":[]}'}, 'ts': 0}
        with open(api.LONGPOLL_FILE, 'w') as fh:
            json.dump({dev: done}, fh)
        # sleep → no-op so the loop iterates immediately
        with mock.patch.object(api.time, 'sleep', lambda *_a, **_k: None):
            status, output = api._longpoll_wait(dev, 5)
        self.assertEqual(status, 'ok', 'waiter must see the cross-process ready:True')
        self.assertEqual((output or {}).get('rc'), 0)


if __name__ == '__main__':
    unittest.main()
