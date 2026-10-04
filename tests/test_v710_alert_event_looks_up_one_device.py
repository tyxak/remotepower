"""An alert event looks up the one device it is about, not the whole fleet.

Two steps on the path of every event loaded the full device store with load() to read a single record:
`in_maintenance` (the group of the device, to decide whether a window covers it) and `_run_automation_rules`
(the group, tags and tenant of the device, to decide whether a rule matches). load() deep-copies the store, so
each event cost two fleet copies: 29 `device_offline` events on a 2,000-device fleet spent 32 s of profiled
time in load(), and a sweep that found 446 devices offline at once spent 83 s of CPU on it. Both now read the
one device with device_get().

This runs the real functions and counts load() calls on the device store, and checks the answers that the
lookup feeds (which devices a window suppresses, which a rule fires for), because the point of the lookup is
that answer.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-evt-')
    spec = importlib.util.spec_from_file_location('api_v710_evt', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.fired = []
        real = api._run_automation_action
        api._run_automation_action = lambda action, event, payload, dev_id, cfg, rule: self.fired.append((rule.get('id'), dev_id))
        self.addCleanup(lambda: setattr(api, '_run_automation_action', real))

    def seed(self, n):
        self.api.save(self.api.DEVICES_FILE, {
            'd%03d' % i: {'name': 'host-%03d' % i, 'group': 'prod' if i % 2 == 0 else 'db', 'tags': ['edge'] if i % 3 == 0 else [],
                          'tenant': 'tenantA' if i % 2 == 0 else 'tenantB', 'token': 't'} for i in range(n)})
        self.api._LOAD_CACHE.clear()

    def window(self, **kw):
        now = int(time.time())
        w = {'id': 'w1', 'scope': 'group', 'target': 'prod', 'start': now - 3600, 'end': now + 3600, 'reason': 'patching'}
        w.update(kw)
        self.api.save(self.api.MAINT_FILE, {'windows': [w]})
        self.api._LOAD_CACHE.clear()

    def rule(self, **kw):
        r = {'id': 'r1', 'enabled': True, 'cooldown_seconds': 0, 'actions': [{'type': 'notify'}],
             'match': {'events': ['device_offline'], 'device_match': {'group': 'prod'}}}
        r.update(kw)
        self.api.save(self.api.RULES_FILE, {'rules': [r]})
        self.api._LOAD_CACHE.clear()

    def devices_loads(self, fn):
        """How many times fn() loads the device store."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = [0]
        real = api.load

        def counting(path, *a, **k):
            if Path(str(path)).name == 'devices.json':
                calls[0] += 1
            return real(path, *a, **k)

        api.load = counting
        try:
            fn()
        finally:
            api.load = real
        return calls[0]


class TestMaintenanceCheck(_Base):

    def events(self, n_events):
        def run():
            for i in range(n_events):
                self.api._LOAD_CACHE.clear()
                self.api.in_maintenance('device_offline', {'device_id': 'd%03d' % i})
        return run

    def test_the_fleet_is_not_copied_per_event(self):
        self.window()
        self.seed(30)
        small = self.devices_loads(self.events(10))
        self.seed(300)
        big = self.devices_loads(self.events(10))
        self.assertEqual(0, big, 'the device store was loaded %d times for 10 events' % big)
        self.assertEqual(small, big)

    def test_a_group_window_covers_its_group_only(self):
        self.window()
        self.seed(6)
        covered = {i for i in range(6) if self.api.in_maintenance('device_offline', {'device_id': 'd%03d' % i})}
        self.assertEqual({0, 2, 4}, covered)
        info = self.api.in_maintenance('device_offline', {'device_id': 'd000'})
        self.assertEqual(('w1', 'group', 'prod'), (info['window_id'], info['scope'], info['target']))

    def test_an_expired_window_covers_nothing(self):
        now = int(time.time())
        self.window(start=now - 7200, end=now - 3600)
        self.seed(4)
        self.assertIsNone(self.api.in_maintenance('device_offline', {'device_id': 'd000'}))

    def test_a_global_window_covers_a_device_that_is_not_in_the_store(self):
        self.window(scope='global', target='')
        self.seed(2)
        self.assertIsNotNone(self.api.in_maintenance('device_offline', {'device_id': 'no-such-device'}))

    def test_a_group_window_does_not_cover_an_unknown_device(self):
        self.window()
        self.seed(2)
        self.assertIsNone(self.api.in_maintenance('device_offline', {'device_id': 'no-such-device'}))

    def test_an_event_that_is_not_suppressible_is_never_covered(self):
        self.window(scope='global', target='')
        self.seed(2)
        self.assertIsNone(self.api.in_maintenance('cve_scan_note_not_suppressible', {'device_id': 'd000'}))


class TestAutomationRules(_Base):

    def events(self, n_events):
        def run():
            for i in range(n_events):
                self.api._LOAD_CACHE.clear()
                self.api._run_automation_rules('device_offline', {'device_id': 'd%03d' % i}, {})
        return run

    def test_the_fleet_is_not_copied_per_event(self):
        self.rule()
        self.seed(30)
        small = self.devices_loads(self.events(10))
        self.seed(300)
        big = self.devices_loads(self.events(10))
        self.assertTrue(self.fired, 'control: the rule never fired, so the lookup was not exercised')
        self.assertEqual(0, big, 'the device store was loaded %d times for 10 events' % big)
        self.assertEqual(small, big)

    def test_a_group_rule_fires_for_its_group_only(self):
        self.rule()
        self.seed(6)
        self.events(6)()
        self.assertEqual(['d000', 'd002', 'd004'], sorted(d for _r, d in self.fired))

    def test_a_tag_rule_fires_for_devices_with_every_tag(self):
        self.rule(match={'events': ['device_offline'], 'device_match': {'tags': ['edge']}})
        self.seed(7)
        self.events(7)()
        self.assertEqual(['d000', 'd003', 'd006'], sorted(d for _r, d in self.fired))

    def test_a_tenant_stamped_rule_fires_for_that_tenants_devices_only(self):
        self.rule(match={'events': ['device_offline']}, tenant_gate='tenantA')
        self.seed(6)
        self.events(6)()
        self.assertEqual(['d000', 'd002', 'd004'], sorted(d for _r, d in self.fired))

    def test_an_event_with_no_device_never_matches_a_group_rule(self):
        self.rule()
        self.seed(4)
        self.api._run_automation_rules('device_offline', {}, {})
        self.assertEqual([], self.fired)

    def test_an_event_for_a_device_that_is_gone_matches_nothing(self):
        self.rule()
        self.seed(4)
        self.api._run_automation_rules('device_offline', {'device_id': 'no-such-device'}, {})
        self.assertEqual([], self.fired)


if __name__ == '__main__':
    unittest.main()
