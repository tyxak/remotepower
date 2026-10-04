"""The SNMP sweep asks every device at once, then applies the answers one device at a time.

`run_snmp_polls_if_due` called `_do_snmp_poll` for each SNMP device in turn, and a device that does not
answer costs 4 s (two attempts of 2 s), so the pass took the sum of the waits: 446 unreachable devices took
about half an hour. The scheduler runs its sweeps one after another, so offline detection and every alert
behind the SNMP sweep waited for it too. The network half is now `_snmp_collect`, run for all devices on worker
threads, and `_do_snmp_poll` applies each device's answer (store write, thresholds, metric history, alerts) in
the calling thread, exactly as before.

The apply half also took the devices lock for every device on every pass, to refresh the OS column from
the SNMP description, and that lock re-reads and rewrites the whole fleet store. It now takes it only for a
device whose label actually differs from the record.

This drives the real sweep with stand-in SNMP requests that wait, so what is measured is elapsed time, what is
stored per device, which alerts fire, how often the devices lock is taken, and that a worker never reads the
storage backend itself.
"""
import importlib.util
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

_DELAY = 0.3


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-snmp-')
    spec = importlib.util.spec_from_file_location('api_v710_snmp', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        import snmp
        self.snmp = snmp
        self.api = _fresh_api()
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.threads = set()
        self.down = set()
        self.events = []

        def poll_system(host, community, port=161, timeout=2.0):
            self.threads.add(threading.current_thread().name)
            time.sleep(_DELAY)
            if host in self.down:
                raise TimeoutError('no response')
            return {'sysDescr': 'switch %s' % host, 'sysObjectID': '1.3.6.1.4.1.9', 'sysUpTime': 1000,
                    'sysContact': '', 'sysName': 'sw-%s' % host, 'sysLocation': 'rack 1', '_oids': {}}

        for name, value in (('poll_system', poll_system), ('poll_processors', lambda *a, **k: []),
                            ('poll_hr_storage', lambda *a, **k: []), ('poll_mikrotik', lambda *a, **k: {}),
                            ('poll_ucd_snmp', lambda *a, **k: {}), ('poll_synology', lambda *a, **k: {})):
            p = patch.object(snmp, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name, value in (('process_snmp_metric_thresholds', lambda *a, **k: None),
                            ('_record_snmp_metrics', lambda *a, **k: None),
                            ('fire_webhook', lambda event, payload=None, **k: self.events.append((event, (payload or {}).get('device_id'))))):
            p = patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def seed(self, n):
        self.api.save(self.api.DEVICES_FILE, {
            'sw%02d' % i: {'name': 'switch-%02d' % i, 'ip': '192.0.2.%d' % (i + 1), 'agentless': True, 'monitored': True,
                           'snmp': {'enabled': True, 'community': 'public', 'port': 161}} for i in range(n)})
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        cfg = self.api.load(self.api.CONFIG_FILE) or {}
        cfg['last_snmp_poll'] = 0
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.api.run_snmp_polls_if_due()
        return self.api.load(self.api.SNMP_DATA_FILE) or {}


class TestDevicesAreAskedTogether(_Base):

    def test_twelve_devices_take_about_one_wait_not_twelve(self):
        self.seed(12)
        t0 = time.monotonic()
        store = self.sweep()
        elapsed = time.monotonic() - t0
        self.assertEqual(12, len(store))
        self.assertTrue(all(e['last_ok'] and not e['last_error'] for e in store.values()))
        self.assertLess(elapsed, _DELAY * 12 / 3, 'twelve waits of %.1fs took %.2fs: they ran one after another' % (_DELAY, elapsed))
        self.assertGreaterEqual(elapsed, _DELAY, 'finished faster than one request can: the stand-in did not wait')
        self.assertGreater(len(self.threads), 1, self.threads)

    def test_each_device_stores_its_own_answer(self):
        self.seed(5)
        store = self.sweep()
        for i in range(5):
            self.assertEqual('sw-192.0.2.%d' % (i + 1), store['sw%02d' % i]['sysName'])
            self.assertEqual('192.0.2.%d' % (i + 1), store['sw%02d' % i]['host'])


class TestFailuresAndAlertsAreUnchanged(_Base):

    def test_an_unreachable_device_records_the_error_and_counts_the_failure(self):
        self.seed(6)
        self.down = {'192.0.2.2', '192.0.2.5'}
        store = self.sweep()
        for dev in ('sw01', 'sw04'):
            self.assertEqual('TimeoutError: no response', store[dev]['last_error'])
            self.assertEqual(1, store[dev]['consecutive_fails'])
        for dev in ('sw00', 'sw02', 'sw03', 'sw05'):
            self.assertFalse(store[dev]['last_error'], dev)
            self.assertEqual(0, store[dev]['consecutive_fails'])

    def test_unreachable_fires_once_on_the_second_failure_and_recover_once_after(self):
        self.seed(4)
        self.down = {'192.0.2.2'}
        self.sweep()
        self.assertEqual([], self.events, 'one failed poll must not alert (single-packet loss)')
        self.sweep()
        self.assertEqual([('snmp_unreachable', 'sw01')], self.events)
        self.sweep()
        self.assertEqual([('snmp_unreachable', 'sw01')], self.events, 'a third failure must not alert again')
        self.down = set()
        self.sweep()
        self.assertEqual([('snmp_unreachable', 'sw01'), ('snmp_recover', 'sw01')], self.events)

    def test_the_deep_poll_without_collected_data_still_makes_its_own_requests(self):
        """snmp_device_handlers calls _do_snmp_poll(dev_id, dev) directly."""
        self.seed(1)
        dev = self.api.load(self.api.DEVICES_FILE)['sw00']
        entry = self.api._do_snmp_poll('sw00', dev)
        self.assertEqual('sw-192.0.2.1', entry['sysName'])
        self.assertEqual('sw-192.0.2.1', self.api.load(self.api.SNMP_DATA_FILE)['sw00']['sysName'])


class TestWorkersNeverTouchTheStorageBackend(_Base):

    def test_every_store_read_happens_on_the_calling_thread(self):
        self.seed(8)
        api = self.api
        callers = []
        real_load, real_cfg = api.load, api._config_ro

        def load_spy(*a, **k):
            callers.append(threading.current_thread().name)
            return real_load(*a, **k)

        def cfg_spy():
            callers.append(threading.current_thread().name)
            return real_cfg()

        api.load, api._config_ro = load_spy, cfg_spy
        try:
            self.sweep()
        finally:
            api.load, api._config_ro = real_load, real_cfg
        self.assertTrue(callers, 'the sweep read no stores at all: the spy saw nothing')
        self.assertGreater(len(self.threads), 1, 'the requests did not run on worker threads, so this proved nothing')
        self.assertEqual({threading.current_thread().name}, set(callers), sorted(set(callers)))


class TestTheOsColumnIsWrittenOnlyWhenItChanges(_Base):

    def devices_lock_entries(self):
        api = self.api
        entered = []
        real = api._LockedUpdate

        def spy(path, non_blocking=False):
            if path == api.DEVICES_FILE:
                entered.append(path)
            return real(path, non_blocking)

        api._LockedUpdate = spy
        try:
            self.sweep()
        finally:
            api._LockedUpdate = real
        return len(entered)

    def test_the_first_pass_fills_the_column_and_the_second_takes_no_lock(self):
        self.seed(6)
        self.assertEqual(6, self.devices_lock_entries(), 'control: each device needs its OS column filled once')
        devs = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual({'switch 192.0.2.%d' % (i + 1) for i in range(6)}, {d['os'] for d in devs.values()})
        self.assertEqual(0, self.devices_lock_entries(), 'the labels already match: the fleet store must not be rewritten')

    def test_a_label_that_changed_is_written_again(self):
        self.seed(3)
        self.devices_lock_entries()
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['sw01']['os'] = 'something else'
        self.api.save(self.api.DEVICES_FILE, devs)
        self.assertEqual(1, self.devices_lock_entries())
        self.assertEqual('switch 192.0.2.2', self.api.load(self.api.DEVICES_FILE)['sw01']['os'])

    def test_an_operator_set_os_on_a_device_with_an_agent_is_never_overwritten(self):
        self.seed(2)
        devs = self.api.load(self.api.DEVICES_FILE)
        devs['sw00']['agentless'] = False
        devs['sw00']['os'] = 'Operator OS'
        self.api.save(self.api.DEVICES_FILE, devs)
        self.devices_lock_entries()
        after = self.api.load(self.api.DEVICES_FILE)
        self.assertEqual('Operator OS', after['sw00']['os'])
        self.assertEqual('switch 192.0.2.2', after['sw01']['os'])


if __name__ == '__main__':
    unittest.main()
