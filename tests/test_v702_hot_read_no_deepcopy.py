#!/usr/bin/env python3
"""The two continuously-polled endpoints must not deepcopy the fleet.

`load()` returns a deepcopy on every read, warm or cold, so a mutating caller
cannot corrupt the shared cache. `_load_ro()` hands back the shared object
instead. That is a real difference on a real fleet:

      100 devices     9.8 ms per read
      500 devices    35.9 ms
    2,000 devices   147   ms

Prometheus scrapes its endpoint every 15-30 seconds and the Home Assistant
bridge is polled continuously, so both paid that on every request for a value
they only read.

`_load_ro`'s contract is load-bearing rather than advisory: a caller that
mutates the result — or anything nested in it, or hands it to `save()` —
corrupts the cache for every later reader in the same request. So this file
pins the reason each of these two is safe, not merely that they use it. The
Prometheus read is taken as a KEY SET; the bridge read is counted over and never
written. If either grows a write, the assertions below are the place that
notices.
"""
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_HOT = ('handle_prometheus_metrics', 'handle_ha_bridge')


def _body(name):
    return srcpin.py_function(_API.read_text(), name)


def _code(name):
    return '\n'.join(l for l in _body(name).splitlines()
                     if not l.lstrip().startswith('#'))


class TestTheyReadWithoutCopying(unittest.TestCase):

    def test_both_handlers_still_exist(self):
        """Positive control: a rename would make every assertion below vacuous
        by raising instead of failing, which is not the same thing."""
        for name in _HOT:
            self.assertGreater(len(_body(name)), 400, name)

    def test_neither_deepcopies_the_device_store(self):
        for name in _HOT:
            code = _code(name)
            self.assertNotIn('load(DEVICES_FILE)', code.replace('_load_ro(DEVICES_FILE)', ''),
                             f'{name} is back to a full copy of the fleet per request')

    def test_both_use_the_read_only_read(self):
        for name in _HOT:
            self.assertIn('_load_ro(DEVICES_FILE)', _code(name), name)


class TestTheyAreStillSafeToShare(unittest.TestCase):
    """The half that matters. Using _load_ro is only correct while the handler
    does not write through what it got back."""

    _WRITES = (r'\.pop\(', r'\.setdefault\(', r'\.update\(', r'\bdel\s',
               r'save\(DEVICES_FILE')

    def test_neither_writes_through_the_shared_object(self):
        for name in _HOT:
            code = _code(name)
            bad = [p for p in self._WRITES if re.search(p, code)]
            self.assertEqual(bad, [], f'{name} mutates something — check whether '
                                      f'it is the shared device store before '
                                      f'leaving _load_ro in place: {bad}')

    def test_prometheus_only_takes_a_key_set(self):
        code = _code('handle_prometheus_metrics')
        # There are two assignments — a `None` default and the real read. Pin
        # the one that touches the store; matching the first was this test's
        # own bug.
        reads = [l.split('=', 1)[1].strip() for l in code.splitlines()
                 if '_metrics_visible' in l and '=' in l
                 and 'DEVICES_FILE' in l]
        self.assertEqual(len(reads), 1, f'expected one store read, got {reads}')
        self.assertTrue(reads[0].startswith('set('),
                        'it is no longer taken as a key set, so the '
                        f'_load_ro reasoning no longer holds: {reads[0]}')

    def test_the_bridge_only_counts(self):
        code = _code('handle_ha_bridge')
        self.assertIn('for dev in devices.values():', code)
        # every use of the loop variable is a read
        for line in code.splitlines():
            if re.search(r'\bdev\b', line) and '=' in line and 'for dev' not in line:
                self.assertNotRegex(line.strip(), r'^\s*dev\[', line.strip())


if __name__ == '__main__':
    unittest.main()
