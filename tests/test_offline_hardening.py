"""Offline-detection hardening (anti-flap) tests.

Covers the three guards added after a real false-offline incident where a
device's stored last_seen was rolled back by a non-atomic devices.json writer
(the documented v2.1.2 lost-update race, reintroduced through the ~two dozen
plain save(DEVICES_FILE, ...) callers), and the offline sweep fired on the
stale value even though the device was heartbeating:

  1. Monotonic last_seen guard in save() — a stale writer can't roll a
     device's last_seen backward; the prevented regression is traced.
  2. ICMP fallback — before firing device_offline, a reachable host suppresses
     the false alert.
  3. _fresh_last_seen / _icmp_reachable helpers (input validation, cache bypass).
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='rp_offh_')
        os.environ['RP_DATA_DIR'] = cls.tmp
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        if 'api' in sys.modules:
            del sys.modules['api']
        import api
        cls.api = api

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)

    def setUp(self):
        self.api.save(self.api.DEVICES_FILE, {})
        self.api.save(self.api.CONFIG_FILE, {})

    def _device(self, last_seen, **over):
        d = {'name': 'host1', 'token': 't', 'ip': '10.0.0.99',
             'last_seen': last_seen, 'poll_interval': 60, 'monitored': True}
        d.update(over)
        return {'d1': d}


class TestMonotonicGuard(_Base):
    def test_stale_writer_cannot_roll_last_seen_back(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now))
        # A non-atomic writer holding an older snapshot writes last_seen back.
        self.api.save(self.api.DEVICES_FILE, self._device(now - 500))
        on_disk = self.api.load(self.api.DEVICES_FILE)['d1']['last_seen']
        self.assertEqual(on_disk, now)   # guard kept the newer value

    def test_forward_progress_still_allowed(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now - 500))
        self.api.save(self.api.DEVICES_FILE, self._device(now))   # newer
        self.assertEqual(self.api.load(self.api.DEVICES_FILE)['d1']['last_seen'], now)

    def test_new_device_and_delete_unaffected(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now))
        # Add a second device (must persist) and the guard must not resurrect d1
        # if a writer legitimately removes it.
        self.api.save(self.api.DEVICES_FILE, {'d2': {'name': 'h2', 'token': 'x',
                                                     'last_seen': now}})
        disk = self.api.load(self.api.DEVICES_FILE)
        self.assertIn('d2', disk)
        self.assertNotIn('d1', disk)


class TestHelpers(_Base):
    def test_icmp_reachable_rejects_bad_input(self):
        self.assertFalse(self.api._icmp_reachable(''))
        self.assertFalse(self.api._icmp_reachable(None))
        self.assertFalse(self.api._icmp_reachable('1.2.3.4; rm -rf /'))
        self.assertFalse(self.api._icmp_reachable('$(whoami)'))
        self.assertFalse(self.api._icmp_reachable('-oProxyCommand=evil'))

    def test_fresh_last_seen_reads_disk(self):
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now))
        self.assertEqual(self.api._fresh_last_seen('d1'), now)
        self.assertEqual(self.api._fresh_last_seen('missing'), 0)


class TestOfflineSuppression(_Base):
    def _arm_and_sweep(self, icmp_result):
        """Seed a very-stale, debounce-armed device and run one sweep with a
        forced ICMP result. Returns (fired_events, config_after)."""
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now - 100000))
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['offline_pending'] = {'d1': now - 100000}   # debounce already met
        cfg['offline_notified'] = {}
        self.api.save(self.api.CONFIG_FILE, cfg)

        fired = []
        orig_fw = self.api.fire_webhook
        orig_icmp = self.api._icmp_reachable
        self.api.fire_webhook = lambda ev, payload=None, **k: fired.append(ev)
        self.api._icmp_reachable = lambda *a, **k: icmp_result
        try:
            self.api.check_offline_webhooks(skip_dev_id=None)
        finally:
            self.api.fire_webhook = orig_fw
            self.api._icmp_reachable = orig_icmp
        return fired, self.api.load(self.api.CONFIG_FILE)

    def test_unreachable_device_fires_offline(self):
        fired, cfg = self._arm_and_sweep(icmp_result=False)
        self.assertTrue(cfg.get('offline_notified', {}).get('d1'))
        self.assertIn('device_offline', fired)

    def test_reachable_device_suppresses_offline(self):
        fired, cfg = self._arm_and_sweep(icmp_result=True)
        # notified flag reset, no webhook — the ping proved it's actually up.
        self.assertFalse(cfg.get('offline_notified', {}).get('d1'))
        self.assertNotIn('device_offline', fired)

    def test_fresh_snapshot_suppresses_before_icmp(self):
        # If the disk shows the device is actually fresh (a clobbered/stale
        # in-request snapshot), it's suppressed without even needing ICMP.
        now = int(time.time())
        self.api.save(self.api.DEVICES_FILE, self._device(now - 100000))
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['offline_pending'] = {'d1': now - 100000}
        cfg['offline_notified'] = {}
        self.api.save(self.api.CONFIG_FILE, cfg)

        fired = []
        orig_fw = self.api.fire_webhook
        orig_fresh = self.api._fresh_last_seen
        self.api.fire_webhook = lambda ev, payload=None, **k: fired.append(ev)
        self.api._fresh_last_seen = lambda dev_id: now   # disk says it's fresh
        try:
            self.api.check_offline_webhooks(skip_dev_id=None)
        finally:
            self.api.fire_webhook = orig_fw
            self.api._fresh_last_seen = orig_fresh
        self.assertNotIn('device_offline', fired)
        self.assertFalse(self.api.load(self.api.CONFIG_FILE)
                         .get('offline_notified', {}).get('d1'))


if __name__ == '__main__':
    unittest.main()
