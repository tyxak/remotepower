"""v6.3.0 — failed_unit_cleared auto-resolve.

failed_unit alerts were fire-and-forget: no recover event existed, so an alert
sat open forever after the operator fixed (or reset-failed) the units. The
heartbeat already diffs the previous failed_units set against the new one to
edge-trigger failed_unit; this feature fires failed_unit_cleared on units
LEAVING the set, carrying still_failed (the host's current failed set) so a
BATCH alert ("dmesg.service (+3 more)") resolves only when ALL of its units
have cleared.

Alerts are built via the REAL fire_webhook/_record_alert path (a hand-built
{'payload': {...}} dict bypasses the whitelist and gives false-green — the
v4.9.0 lesson), and the heartbeat leg drives the real handle_heartbeat.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v630_fuc', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestRegistryWiring(unittest.TestCase):
    def test_event_registered_and_derived(self):
        reg = api.EVENT_REGISTRY['failed_unit_cleared']
        self.assertEqual(reg.get('kind'), 'failed_units')
        self.assertEqual(reg.get('resolves'), ('failed_unit',))
        self.assertTrue(reg.get('label'))
        # Recover events create no inbox row of their own.
        self.assertNotIn('severity', reg)
        self.assertNotIn('failed_unit_cleared', api._ALERT_RULES)
        # Derived maps picked it up.
        self.assertEqual(api._ALERT_RECOVER.get('failed_unit_cleared'),
                         'failed_unit')
        self.assertIn('failed_unit_cleared', {e[0] for e in api.WEBHOOK_EVENTS})

    def test_units_batch_is_whitelisted_on_the_alert(self):
        # The all-units-cleared check reads the alert's stored 'units' list;
        # if the whitelist drops it, only the legacy single-unit fallback works.
        api.save(api.ALERTS_FILE, {'alerts': []})
        api._record_alert('failed_unit', {
            'device_id': 'd1', 'name': 'host1', 'unit': 'a.service',
            'units': ['a.service', 'b.service'], 'new_count': 2})
        alerts = (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['payload'].get('units'),
                         ['a.service', 'b.service'])

    def test_suppressible_alongside_firing_pair(self):
        self.assertIn('failed_unit_cleared', api.SUPPRESSIBLE_EVENTS)


class TestAutoResolveRealPath(unittest.TestCase):
    def setUp(self):
        api.save(api.ALERTS_FILE, {'alerts': []})

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
                if not a.get('resolved_at')]

    def _record_batch(self, dev='d1', units=('a.service', 'b.service')):
        api._record_alert('failed_unit', {
            'device_id': dev, 'name': 'host-' + dev, 'unit': units[0],
            'units': list(units), 'new_count': len(units)})

    def test_batch_alert_stays_open_while_any_unit_still_failed(self):
        self._record_batch()
        api._auto_resolve_alerts('failed_unit_cleared', {
            'device_id': 'd1', 'unit': 'a.service', 'units': ['a.service'],
            'cleared_count': 1, 'still_failed': ['b.service']})
        self.assertEqual(len(self._open()), 1,
                         'partial recovery must not close a batch alert')

    def test_batch_alert_resolves_when_all_units_cleared(self):
        self._record_batch()
        api._auto_resolve_alerts('failed_unit_cleared', {
            'device_id': 'd1', 'unit': 'b.service', 'units': ['b.service'],
            'cleared_count': 1, 'still_failed': []})
        opened = self._open()
        self.assertEqual(opened, [])
        resolved = (api.load(api.ALERTS_FILE) or {}).get('alerts', [])[0]
        self.assertEqual(resolved.get('resolved_by'), 'auto')

    def test_unrelated_still_failed_units_do_not_block(self):
        # c.service failing (never part of this alert) must not keep the
        # alert open once a+b cleared.
        self._record_batch()
        api._auto_resolve_alerts('failed_unit_cleared', {
            'device_id': 'd1', 'unit': 'a.service',
            'units': ['a.service', 'b.service'], 'cleared_count': 2,
            'still_failed': ['c.service']})
        self.assertEqual(self._open(), [])

    def test_legacy_single_unit_alert_resolves_via_fallback(self):
        # Pre-v6.3.0 alerts stored only 'unit' (no 'units' list).
        api._record_alert('failed_unit', {
            'device_id': 'd1', 'name': 'host1', 'unit': 'old.service',
            'new_count': 1})
        api._auto_resolve_alerts('failed_unit_cleared', {
            'device_id': 'd1', 'unit': 'old.service', 'units': ['old.service'],
            'cleared_count': 1, 'still_failed': []})
        self.assertEqual(self._open(), [])

    def test_other_device_alert_untouched(self):
        self._record_batch(dev='d1')
        self._record_batch(dev='d2')
        api._auto_resolve_alerts('failed_unit_cleared', {
            'device_id': 'd1', 'unit': 'a.service',
            'units': ['a.service', 'b.service'], 'cleared_count': 2,
            'still_failed': []})
        opened = self._open()
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0].get('device_id'), 'd2')

    def test_full_fire_webhook_path(self):
        # End-to-end through the single dispatch point (gates, whitelist,
        # auto-resolve) rather than the two internals in isolation.
        api.fire_webhook('failed_unit', {
            'device_id': 'd1', 'name': 'host1', 'unit': 'a.service',
            'units': ['a.service'], 'new_count': 1})
        self.assertEqual(len(self._open()), 1)
        api.fire_webhook('failed_unit_cleared', {
            'device_id': 'd1', 'name': 'host1', 'unit': 'a.service',
            'units': ['a.service'], 'cleared_count': 1, 'still_failed': []})
        self.assertEqual(self._open(), [])


class TestHeartbeatEdgeTrigger(unittest.TestCase):
    """The server must actually FIRE the recover event when a heartbeat's
    failed_units list shrinks (the 'feature that can never fire' class —
    a registry entry alone is dead code)."""

    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'host1', 'token': 'tok', 'poll_interval': 60,
            'sysinfo': {'failed_units': ['a.service', 'b.service']},
        }})
        api.save(api.CMDS_FILE, {})
        self._orig = (api.respond, api.method, api.get_json_body,
                      api.fire_webhook)
        self.fired = []

    def tearDown(self):
        (api.respond, api.method, api.get_json_body,
         api.fire_webhook) = self._orig

    def _beat(self, failed_units):
        def fake_respond(status, body_, **kw):
            raise SystemExit(0)
        api.respond = fake_respond
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {
            'device_id': 'd1', 'token': 'tok', 'version': '6.3.0',
            'sysinfo': {'failed_units': failed_units}}
        api.fire_webhook = lambda ev, pl: self.fired.append((ev, pl))
        try:
            api.handle_heartbeat()
        except (SystemExit, api.HTTPError):
            pass

    def test_cleared_units_fire_recover_event_with_still_failed(self):
        self._beat(['b.service'])
        cleared = [pl for ev, pl in self.fired if ev == 'failed_unit_cleared']
        self.assertEqual(len(cleared), 1, f'events fired: {self.fired}')
        self.assertEqual(cleared[0]['units'], ['a.service'])
        self.assertEqual(cleared[0]['still_failed'], ['b.service'])
        self.assertEqual(cleared[0]['cleared_count'], 1)
        self.assertEqual(cleared[0]['device_id'], 'd1')

    def test_no_recover_event_when_nothing_cleared(self):
        self._beat(['a.service', 'b.service'])
        self.assertEqual(
            [ev for ev, _ in self.fired if ev == 'failed_unit_cleared'], [])


class TestTimerFailedCleared(unittest.TestCase):
    """v6.3.0: timer_failed (scheduled-job failure) now auto-resolves via
    timer_failed_cleared — a per-unit recover event (one alert per timer, so a
    plain 'unit' sub_match, unlike failed_unit's batch)."""

    def setUp(self):
        api.save(api.ALERTS_FILE, {'alerts': []})

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
                if not a.get('resolved_at')]

    def test_registry_wired(self):
        reg = api.EVENT_REGISTRY['timer_failed_cleared']
        self.assertEqual(reg.get('resolves'), ('timer_failed',))
        self.assertEqual(reg.get('kind'), 'timer')
        self.assertNotIn('severity', reg)
        self.assertEqual(api._ALERT_RECOVER.get('timer_failed_cleared'),
                         'timer_failed')

    def test_recover_clears_only_the_recovered_timer(self):
        api._record_alert('timer_failed', {'device_id': 'd1', 'name': 'h',
                                           'unit': 'a.timer'})
        api._record_alert('timer_failed', {'device_id': 'd1', 'name': 'h',
                                           'unit': 'b.timer'})
        self.assertEqual(len(self._open()), 2)
        api._auto_resolve_alerts('timer_failed_cleared',
                                 {'device_id': 'd1', 'unit': 'a.timer',
                                  'still_failed': ['b.timer']})
        still = self._open()
        self.assertEqual(len(still), 1)
        self.assertEqual(still[0]['payload'].get('unit'), 'b.timer')


if __name__ == '__main__':
    unittest.main()
