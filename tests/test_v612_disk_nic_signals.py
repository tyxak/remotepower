"""Guardrails for two 'collected but could never alert' signals (v6.1.2 sweep).

Both were reported by the agent, stored by the server, rendered as text somewhere —
and excluded from every verdict, so nothing could ever page on them:

1. **NVMe spare reserve.** The agent sends `spare_pct` AND the drive's own
   `spare_threshold_pct`, and neither fed `_smart_disk_failed` or the disk-health
   risk score. The NVMe spec defines `available_spare < available_spare_threshold`
   as a critical warning — the remap reserve is gone and the drive is about to go
   read-only. A drive actively saying that still scored `risk=low` and raised
   nothing. Same for an explicitly FAILED self-test.

2. **NIC errors/drops.** `rx_err/tx_err/rx_drop/tx_drop` were drawer-only — no
   check, no event — so a failing cable / dirty SFP / dying switch port was
   invisible to every fleet-wide view. The counters are cumulative-since-boot, so
   the check reasons about the per-heartbeat DELTA (computed at ingest), not the
   absolute total: a box up for a year has collected a few errors and that is not
   news.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")

_spec = importlib.util.spec_from_file_location("api_v612_dn", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestNvmeSpareReserve(unittest.TestCase):

    def test_spare_at_or_below_threshold_is_a_failure(self):
        # The drive's own threshold — this is its self-assessment, not our heuristic.
        self.assertTrue(api._smart_disk_failed(
            {'health': 'PASSED', 'spare_pct': 5, 'spare_threshold_pct': 10}))
        self.assertTrue(api._smart_disk_failed(
            {'health': 'PASSED', 'spare_pct': 10, 'spare_threshold_pct': 10}))

    def test_healthy_spare_is_not_a_failure(self):
        self.assertFalse(api._smart_disk_failed(
            {'health': 'PASSED', 'spare_pct': 80, 'spare_threshold_pct': 10}))

    def test_no_threshold_reported_is_never_a_failure(self):
        """A drive that reports no threshold gives us nothing to compare against.
        spare_pct=0 alone is NOT evidence — plenty of devices report 0/absent."""
        self.assertFalse(api._smart_disk_failed({'health': 'PASSED', 'spare_pct': 0}))
        self.assertFalse(api._smart_disk_failed(
            {'health': 'PASSED', 'spare_pct': 0, 'spare_threshold_pct': 0}))
        self.assertFalse(api._smart_disk_failed(
            {'health': 'PASSED', 'spare_pct': 'n/a', 'spare_threshold_pct': 10}))


class TestSelfTestVerdict(unittest.TestCase):

    def test_explicit_failure_counts(self):
        for res in ('Completed: read failure', 'Completed: electrical failure'):
            with self.subTest(res=res):
                self.assertTrue(api._smart_disk_failed(
                    {'health': 'PASSED', 'selftest_result': res}))

    def test_never_run_or_aborted_is_NOT_a_failure(self):
        """The difference between a signal people act on and one they mute. A test
        that was never run, aborted by the host, or interrupted says nothing about
        the drive."""
        for res in ('never run', 'Completed without error', 'Aborted by host',
                    'Interrupted (host reset)', ''):
            with self.subTest(res=res):
                self.assertFalse(api._smart_disk_failed(
                    {'health': 'PASSED', 'selftest_result': res}))


class TestNicErrorCheck(unittest.TestCase):

    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        api.DEVICES_FILE = tmp / 'devices.json'

    def _rows(self, network_io):
        dev = {'id': 'd1', 'name': 'web01', 'last_seen': int(time.time()),
               'monitored': True, 'sysinfo': {'network_io': network_io}}
        api.save(api.DEVICES_FILE, {'d1': dev})
        return api._host_checks('d1', dev)

    def test_growing_errors_raise_a_warning_check(self):
        rows = self._rows([{'iface': 'eth0', 'rx_err': 40, 'err_delta': 7}])
        nic = [r for r in rows if r.get('key') == 'nic_errors']
        self.assertTrue(nic, 'no nic_errors check row — a dying NIC stays invisible')
        self.assertEqual(nic[0]['status'], 'warning')
        self.assertIn('eth0', nic[0]['output'])
        self.assertIn('+7', nic[0]['output'])

    def test_a_large_but_STATIC_counter_does_not_warn(self):
        """The whole point of the delta: a host up for a year has accumulated some
        errors. If the count isn't MOVING, there is nothing wrong right now."""
        rows = self._rows([{'iface': 'eth0', 'rx_err': 9000, 'err_delta': 0}])
        self.assertEqual([r for r in rows if r.get('key') == 'nic_errors'], [])

    def test_clean_nic_produces_no_row(self):
        rows = self._rows([{'iface': 'eth0', 'rx_err': 0, 'err_delta': 0}])
        self.assertEqual([r for r in rows if r.get('key') == 'nic_errors'], [])


class TestNicErrorDeltaIngest(unittest.TestCase):
    """The delta is computed at ingest against the PREVIOUS heartbeat, and a counter
    going backwards (a reboot / driver reload) must re-baseline, not go negative.

    The sanitizer is inline in handle_heartbeat, so this drives the REAL heartbeat
    and reads back what actually landed in the device store. (Deliberately no
    `except Exception: pass` fallback — a test that swallows the failure it exists to
    catch is worse than no test.)
    """

    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        api.DEVICES_FILE = tmp / 'devices.json'
        api.CONFIG_FILE = tmp / 'config.json'
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01',
                                           'token': 'tok', 'monitored': True}})
        self._real_respond = api.respond
        api.respond = lambda status, body: (_ for _ in ()).throw(SystemExit(0))

    def tearDown(self):
        api.respond = self._real_respond

    def _beat(self, network_io):
        api.get_json_body = lambda: {
            'device_id': 'd1', 'token': 'tok',
            'sysinfo': {'network_io': network_io},
        }
        api.method = lambda: 'POST'
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        stored = api.load(api.DEVICES_FILE)['d1']
        return (stored.get('sysinfo') or {}).get('network_io') or []

    def _delta_after(self, prev, cur):
        if prev is not None:
            self._beat([dict(iface='eth0', **prev)])
        rows = self._beat([dict(iface='eth0', **cur)])
        self.assertTrue(rows, 'network_io did not survive the heartbeat sanitizer')
        return rows[0].get('err_delta')

    def test_increase_produces_a_positive_delta(self):
        self.assertEqual(self._delta_after({'rx_err': 10}, {'rx_err': 17}), 7)

    def test_counter_reset_rebaselines_instead_of_going_negative(self):
        self.assertEqual(self._delta_after({'rx_err': 900}, {'rx_err': 3}), 0)

    def test_first_ever_heartbeat_has_no_previous_to_diff(self):
        # No prior sysinfo: the whole current count would otherwise read as a spike.
        self.assertEqual(self._delta_after(None, {'rx_err': 0}), 0)

    def test_delta_sums_every_error_and_drop_counter(self):
        self.assertEqual(
            self._delta_after({'rx_err': 1, 'tx_err': 1, 'rx_drop': 1, 'tx_drop': 1},
                              {'rx_err': 2, 'tx_err': 3, 'rx_drop': 4, 'tx_drop': 5}),
            (2 + 3 + 4 + 5) - (1 + 1 + 1 + 1))


if __name__ == '__main__':
    unittest.main()
