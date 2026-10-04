"""A monitor sweep takes about as long as its slowest probe, not the sum of all of them.

`_execute_monitor_checks` ran every probe one after another, and a probe is a ping, a socket or one
HTTP request that spends nearly all its time waiting. `GET /api/monitor` (the Monitor page's "run them
now") therefore answered after the SUM of the timeouts: twelve seeded monitors that cannot be reached
took 5.96 seconds for one page load, and the background sweep blocked for as long. The probes now run
together (up to eight at once) and the results come back in the order the monitors were configured.

This drives the real runner with stand-in probes that wait, so it measures the thing that changed:
elapsed time, result order, and that a worker thread never reads the config store itself (a worker has a
cold per-request cache and would open a storage connection of its own to fetch one boolean).
"""
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util   # noqa: E402
import sys               # noqa: E402

_CGI_BIN = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
_spec = importlib.util.spec_from_file_location("api_v710_probes", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_DELAY = 0.3


def _monitors(n, kind='ping'):
    return [{'type': kind, 'label': 'm%d' % i, 'target': '127.0.0.%d' % (i + 2)} for i in range(n)]


class TestMonitorProbesRunTogether(unittest.TestCase):

    def setUp(self):
        self._orig = api._run_one_monitor_check
        self.threads = set()

        def slow_probe(mtype, target, label, m):
            self.threads.add(threading.current_thread().name)
            time.sleep(_DELAY)
            return {'label': label, 'type': mtype, 'target': target, 'ok': True, 'detail': 'up',
                    'checked': 1, 'allow_internal': api._allow_internal_monitors()}

        api._run_one_monitor_check = slow_probe

    def tearDown(self):
        api._run_one_monitor_check = self._orig

    def test_six_probes_finish_in_about_one_delay_not_six(self):
        t0 = time.monotonic()
        res = api._execute_monitor_checks(_monitors(6))
        elapsed = time.monotonic() - t0
        self.assertEqual(6, len(res))
        self.assertLess(elapsed, _DELAY * 6 / 2, 'six waits of %.1fs took %.2fs: they ran one after another' % (_DELAY, elapsed))
        self.assertGreaterEqual(elapsed, _DELAY, 'finished faster than one probe can: the stand-in did not wait')
        self.assertGreater(len(self.threads), 1, self.threads)

    def test_results_come_back_in_configured_order_around_finished_entries(self):
        monitors = [
            {'type': 'ping', 'label': 'first', 'target': '127.0.0.2'},
            {'type': 'ping', 'label': 'paused', 'target': '127.0.0.3', 'paused': True},
            {'type': 'tcp', 'label': 'bad', 'target': '127.0.0.1:22'},      # loopback: refused before any probe
            {'type': 'ping', 'label': 'sat', 'target': '127.0.0.4', 'via_satellite': 'x'},
            {'type': 'tcp', 'label': 'last', 'target': '127.0.0.5:22'},
        ]
        res = api._execute_monitor_checks(monitors)
        self.assertEqual(['first', 'bad', 'last'], [r['label'] for r in res])
        self.assertEqual('blocked: invalid target', res[1]['detail'])

    def test_a_single_probe_does_not_start_a_pool(self):
        api._execute_monitor_checks(_monitors(1))
        self.assertEqual({threading.current_thread().name}, self.threads)

    def test_every_probe_sees_the_config_flag_the_caller_read(self):
        res = api._execute_monitor_checks(_monitors(4))
        self.assertEqual({False}, {r['allow_internal'] for r in res})
        self.assertGreater(len(self.threads), 1, 'the probes did not run on worker threads, so this proved nothing')


class TestWorkersNeverReadTheConfigStore(unittest.TestCase):
    """The real tcp probe reads allow_internal_monitors; with the value carried in, no worker does."""

    def test_every_config_read_happens_on_the_calling_thread(self):
        callers = []
        orig_cfg = api._config_ro
        orig_conn = api.socket.create_connection

        def spy():
            callers.append(threading.current_thread().name)
            return orig_cfg()

        def refuse(*a, **k):
            raise OSError('refused')

        api._config_ro = spy
        api.socket.create_connection = refuse
        try:
            res = api._execute_monitor_checks(
                [{'type': 'tcp', 'label': 't%d' % i, 'target': '192.0.2.%d:22' % (i + 1)} for i in range(4)])
        finally:
            api._config_ro = orig_cfg
            api.socket.create_connection = orig_conn
        self.assertEqual(['closed'] * 4, [r['detail'] for r in res])
        self.assertTrue(callers, 'the runner never read the config: the spy saw nothing')
        self.assertEqual({threading.current_thread().name}, set(callers), callers)


if __name__ == '__main__':
    unittest.main()
