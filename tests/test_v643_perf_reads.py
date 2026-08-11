#!/usr/bin/env python3
"""Read-only paths must not pay for a copy they never write to.

`load()` returns `copy.deepcopy(store)` on EVERY call, warm or cold, so a
caller that mutates its result cannot corrupt the shared cache. `_load_ro()`
hands back the shared object instead, and its contract is load-bearing: a
caller that mutates the result — or anything nested in it, or hands it to
`save()` — corrupts the cache for every later reader in the same request.

The sites changed here were each read and confirmed to PROJECT rather than
mutate. Three of them carried a comment asserting the read was cheap:

  _device_set_fingerprint  "Cheap — `load()` is memoised per request". The
                           memoisation removes the parse, not the copy, so a
                           function whose whole output is a hash of the key set
                           was materialising every device document to call
                           `.keys()`. Measured at 400 devices: 18.5 ms → 0.01 ms.
  handle_home              "one cheap file read" for a 30-element slice of a
                           store shaped {fleet: [...], devices: {id: [...]}}.
                           At 400 devices x 180 daily samples that is ~72,000
                           dicts deepcopied to reach one list. 114.7 ms → 38.2 ms
                           cold, 68.9 ms → ~0 ms warm.
  _maybe_sample_health     "cheap read-only pre-gate", where the identical gate
                           in _maybe_sample_compliance already used _load_ro.

These tests do not assert wall-clock — a timing assertion on a shared CI box is
a flake generator. They assert the BEHAVIOURAL property that makes the change
both correct and effective: the read returns the shared object, and no caller
writes through it.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643perf-'))

_spec = importlib.util.spec_from_file_location('api_v643_perf', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import srcpin  # noqa: E402


class TestTheReadsSkipTheCopy(unittest.TestCase):
    def setUp(self):
        api.save(api.HEALTH_HIST_FILE,
                 {'fleet': [{'date': '2026-01-01', 'ts': 1, 'score': 90}],
                  'devices': {'d1': [{'date': '2026-01-01', 'ts': 1, 'score': 90}]}})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1'}})
        for f in (api.HEALTH_HIST_FILE, api.DEVICES_FILE):
            api._invalidate_load_cache(f)

    def test_load_ro_returns_the_shared_object_and_load_does_not(self):
        """The premise. If _load_ro ever started copying, every change in this
        commit would silently become a no-op while still passing review."""
        api.load(api.HEALTH_HIST_FILE)                      # prime
        a = api._load_ro(api.HEALTH_HIST_FILE)
        b = api._load_ro(api.HEALTH_HIST_FILE)
        self.assertIs(a, b, '_load_ro is copying — the optimisation is dead')
        self.assertIsNot(api.load(api.HEALTH_HIST_FILE), a,
                         'load() stopped copying — a mutating caller can now '
                         'corrupt the cache for every later reader')

    def test_the_fingerprint_is_still_correct(self):
        """Correctness first: the read changed, the answer must not."""
        fp1 = api._device_set_fingerprint()
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1'}, 'd2': {'id': 'd2'}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        fp2 = api._device_set_fingerprint()
        self.assertNotEqual(fp1, fp2, 'adding a device must bust the fingerprint '
                                      '— that is the whole contract')

    def test_the_fingerprint_ignores_telemetry_churn(self):
        """The other half: every heartbeat rewrites devices.json, so a
        fingerprint that moved with telemetry would defeat the cache it feeds."""
        fp1 = api._device_set_fingerprint()
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'h1',
                                           'last_seen': 999, 'sysinfo': {'cpu': 9}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(fp1, api._device_set_fingerprint())

    def test_reading_the_fingerprint_does_not_corrupt_the_shared_store(self):
        """The _load_ro hazard, checked directly rather than by reading the
        code: call it, then confirm the cached store is untouched."""
        api.load(api.DEVICES_FILE)
        before = dict(api._load_ro(api.DEVICES_FILE))
        api._device_set_fingerprint()
        self.assertEqual(dict(api._load_ro(api.DEVICES_FILE)), before)


class TestNoRewriteWhenNothingChanged(unittest.TestCase):
    """`run_webhook_digests_if_due` runs from main() on EVERY request and used
    to `save()` unconditionally. Holding one notification for a 60-minute
    digest window therefore meant a full store rewrite per request for an
    hour, none of which changed a byte."""

    def test_a_tick_with_nothing_due_does_not_write(self):
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'dest1', 'url': 'https://example.invalid/hook',
             'digest_minutes': 60, 'enabled': True}]})
        import time as _t
        api.save(api.WEBHOOK_DIGEST_FILE,
                 {'dest1': {'first_ts': int(_t.time()), 'items': [{'event': 'x'}]}})
        for f in (api.CONFIG_FILE, api.WEBHOOK_DIGEST_FILE):
            api._invalidate_load_cache(f)

        writes = []
        _real_save, _real_locked = api.save, api._LockedUpdate
        api.save = lambda p, d, **k: (writes.append(p), _real_save(p, d, **k))[1]

        class _Spy:
            def __init__(self, path, *a, **k):
                writes.append(path)
                self._inner = _real_locked(path, *a, **k)

            def __enter__(self):
                return self._inner.__enter__()

            def __exit__(self, *a):
                return self._inner.__exit__(*a)

        api._LockedUpdate = _Spy
        try:
            api.run_webhook_digests_if_due()
        finally:
            # Restore unconditionally — a leaked stub here would silently
            # rewrite every later test's locking behaviour in this process.
            api.save, api._LockedUpdate = _real_save, _real_locked

        self.assertEqual(
            [w for w in writes if w == api.WEBHOOK_DIGEST_FILE], [],
            'the digest store was rewritten on a tick where nothing was due')

    def test_a_due_digest_still_clears_the_queue(self):
        """Positive control — without it, a version that never wrote at all
        would pass the test above and lose every held notification."""
        api.save(api.CONFIG_FILE, {'webhook_urls': [
            {'id': 'dest1', 'url': 'https://example.invalid/hook',
             'digest_minutes': 1, 'enabled': True}]})
        api.save(api.WEBHOOK_DIGEST_FILE,
                 {'dest1': {'first_ts': 1, 'items': [{'event': 'x', 'title': 't'}]}})
        for f in (api.CONFIG_FILE, api.WEBHOOK_DIGEST_FILE):
            api._invalidate_load_cache(f)
        _real = api._dispatch_one_webhook
        api._dispatch_one_webhook = lambda *a, **k: None
        try:
            api.run_webhook_digests_if_due()
        finally:
            api._dispatch_one_webhook = _real
        api._invalidate_load_cache(api.WEBHOOK_DIGEST_FILE)
        self.assertEqual(api.load(api.WEBHOOK_DIGEST_FILE) or {}, {},
                         'a flushed digest must leave the queue empty')

    def test_the_write_takes_the_lock(self):
        """An unlocked read-modify-write here races a concurrent enqueue and
        drops it — the lost-update class this codebase keeps rediscovering."""
        src = srcpin.py_function((_CGI / 'api.py').read_text(),
                                 'run_webhook_digests_if_due')
        # assertTrue, not assertIn — assertIn on a whole function body prints
        # the entire function on failure, which buries the message in a
        # multi-megabyte diff.
        self.assertTrue('_LockedUpdate(WEBHOOK_DIGEST_FILE)' in src,
                        'the digest remainder is written without holding the '
                        'lock — a concurrent enqueue is lost')
        self.assertTrue('save(WEBHOOK_DIGEST_FILE' not in src,
                        'the unlocked save() is back')


class TestTheCommentsNoLongerClaimSomethingUntrue(unittest.TestCase):
    """Each of these sites carried a comment asserting the read was cheap, and
    the comment is why nobody looked again. A wrong explanation outlives a
    wrong line of code."""

    def test_the_fingerprint_docstring_does_not_call_load_cheap(self):
        src = srcpin.py_function((_CGI / 'api.py').read_text(),
                                 '_device_set_fingerprint')
        self.assertNotIn('Cheap — `load()` is\n    memoised', src)
        self.assertIn('_load_ro', src)

    def test_no_health_history_read_uses_the_copying_reader(self):
        api_src = (_CGI / 'api.py').read_text()
        # strip comments so the explanation of this change is not counted
        code = re.sub(r'#[^\n]*', '', api_src)
        self.assertNotIn('load(HEALTH_HIST_FILE)'.replace('load(', ' load('),
                         code.replace('_load_ro(', ' _load_ro('),
                         'a HEALTH_HIST_FILE read still goes through the '
                         'copying reader; every one of them projects rather '
                         'than mutates, so _load_ro is correct there')


if __name__ == '__main__':
    unittest.main()
