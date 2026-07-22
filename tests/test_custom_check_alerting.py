"""A custom check that is failing from its FIRST observation must still alert.

_ingest_custom_check_results used to fire custom_check_failed only on an
ok -> failing EDGE, and seeded the first observation silently. A check that was
broken the moment it was applied therefore showed critical on the Checks page
and alerted nowhere, forever — you only got paged if it first went OK.

Now: the first observation still seeds silently (no storm when a batch of
baseline checks is applied), but a check STILL failing on the next report
alerts, and then stays quiet until it recovers.
"""
import os
import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

_ldr = importlib.machinery.SourceFileLoader(
    'api', str(Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DEV = 'dev-cc-1'
CHECK = {'id': 'ck_00001', 'name': 'AppArmor active', 'type': 'systemd_unit',
         'param': 'apparmor.service', 'target_kind': 'all', 'target': ''}


class TestFirstObservationAlerting(unittest.TestCase):
    def setUp(self):
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None: self.fired.append((ev, payload))
        api.save(api.CONFIG_FILE, {'custom_checks': [CHECK]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.DEVICES_FILE, {DEV: {'name': 'host1', 'sysinfo': {}}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        api.fire_webhook = self._fw

    def _report(self, status, output='x'):
        """Simulate the agent reporting this check's result, then ingest."""
        devs = api.load(api.DEVICES_FILE) or {}
        d = devs.get(DEV) or {}
        d.setdefault('sysinfo', {})['custom_check_results'] = {
            CHECK['id']: {'status': status, 'output': output}}
        devs[DEV] = d
        api.save(api.DEVICES_FILE, devs)
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.fired.clear()
        api._ingest_custom_check_results(DEV, 'host1')
        return [e for e, _ in self.fired]

    def _state(self):
        return ((api.load(api.DEVICES_FILE) or {}).get(DEV, {})
                .get('custom_check_state', {}).get(CHECK['id'], {}))

    def test_first_failing_observation_is_seeded_silently(self):
        self.assertEqual(self._report('critical'), [])          # no storm
        self.assertEqual(self._state().get('status'), 'critical')
        self.assertFalse(self._state().get('alerted'))

    def test_still_failing_on_the_next_report_alerts(self):
        """THE REGRESSION: this used to stay silent forever."""
        self._report('critical')
        self.assertEqual(self._report('critical'), ['custom_check_failed'])
        self.assertTrue(self._state().get('alerted'))

    def test_it_does_not_re_alert_every_beat(self):
        self._report('critical')
        self._report('critical')                                 # alerts
        self.assertEqual(self._report('critical'), [])           # then quiet
        self.assertEqual(self._report('critical'), [])

    def test_recovery_fires_only_after_an_alert(self):
        self._report('critical')
        self._report('critical')                                 # alerted
        self.assertEqual(self._report('ok'), ['custom_check_recovered'])
        self.assertFalse(self._state().get('alerted'))

    def test_recovery_is_silent_if_it_never_alerted(self):
        self._report('critical')                                 # seeded only
        self.assertEqual(self._report('ok'), [])                 # no stray recover

    def test_ok_then_failing_still_alerts_immediately(self):
        self._report('ok')
        self.assertEqual(self._report('critical'), ['custom_check_failed'])

    def test_warning_counts_as_failing(self):
        self._report('warning')
        self.assertEqual(self._report('warning'), ['custom_check_failed'])

    def test_unknown_carries_state_forward_without_alerting(self):
        self._report('critical')
        self._report('critical')                                 # alerted
        self.assertEqual(self._report('unknown'), [])
        self.assertEqual(self._state().get('status'), 'critical')  # not a recovery

    def test_pre_existing_failing_state_does_not_replay_on_upgrade(self):
        """State saved by the old code has no `alerted` key; a long-standing
        failure must not suddenly page everyone after an upgrade."""
        devs = api.load(api.DEVICES_FILE) or {}
        devs[DEV]['custom_check_state'] = {
            CHECK['id']: {'status': 'critical', 'output': 'old', 'changed_at': 1}}
        api.save(api.DEVICES_FILE, devs)
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(self._report('critical'), [])


if __name__ == '__main__':
    unittest.main()
