#!/usr/bin/env python3
"""Two hardware failure signals scored zero on the Reliability page.

`_device_reliability` is the fleet's failure-likelihood model — it scores SMART
failure, reallocated-sector growth, wear, ECC, reboot churn, overheating, OOM
and NIC errors. It read neither `platform_health` nor `battery`.

Under-voltage is the one condition the Checks engine itself rates **critical**;
its own comment calls it "the commonest cause of *randomly unstable*". So a host
browning out under a failing PSU showed critical on its Checks page and scored 0
on Reliability — and there is no event for it either, so it fired no webhook and
raised no needs-attention item. The only surface that told you was a per-host
tab. Battery wear fires `battery_health_low` and likewise counted for nothing.

Both signals were already whitelisted by safe_si; this needed no agent change.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-relhw-'))
_spec = importlib.util.spec_from_file_location('api_rel_hw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.w = api._reliability_weights()

    def score(self, si):
        dev = {'name': 'pi', 'os': 'Raspbian 12', 'last_seen': self.now,
               'sysinfo': si}
        r = api._device_reliability('d1', dev, {}, {}, [], {}, {}, {},
                                    self.now, None, self.w)
        return r.get('score') or 0


class TestTheWeightsExist(_Base):
    def test_both_factors_are_weighted(self):
        self.assertGreater(self.w.get('power_throttled', 0), 0)
        self.assertGreater(self.w.get('battery_worn', 0), 0)

    def test_under_voltage_outweighs_battery_wear(self):
        """A failing PSU is a failing machine; a worn laptop battery is a
        consumable. If the ordering ever inverts, say why."""
        self.assertGreater(self.w['power_throttled'], self.w['battery_worn'])

    def test_they_are_operator_tunable_like_every_other_factor(self):
        src = (_CGI / 'api.py').read_text()
        for k in ('power_throttled', 'battery_worn'):
            self.assertIn(f"'{k}'", src)
        # _reliability_weights derives its key set from _RELIABILITY_WEIGHTS, so
        # being in that dict IS being tunable — assert the derivation, not a
        # second hand-kept list.
        self.assertIn('power_throttled', api._RELIABILITY_WEIGHTS)
        self.assertIn('battery_worn', api._RELIABILITY_WEIGHTS)


class TestThrottling(_Base):
    def test_a_clean_host_scores_zero(self):
        """The control. Without it every assertion below could be satisfied by
        a model that scores everything."""
        self.assertEqual(0, self.score({}))

    def test_under_voltage_now_scores(self):
        s = self.score({'platform_health': {'throttle': {'undervolt_now': True}}})
        self.assertEqual(self.w['power_throttled'], s)

    def test_throttling_now_scores(self):
        s = self.score({'platform_health': {'throttle': {'throttled_now': True}}})
        self.assertEqual(self.w['power_throttled'], s)

    def test_since_boot_history_does_not_score(self):
        """The eight booleans split into live and since-boot. Scoring history
        as a current condition would keep a host penalised for a brownout it
        recovered from until the next reboot."""
        for k in ('undervolt_since_boot', 'freq_capped_since_boot',
                  'throttled_since_boot', 'soft_temp_since_boot'):
            with self.subTest(key=k):
                self.assertEqual(0, self.score(
                    {'platform_health': {'throttle': {k: True}}}))

    def test_it_counts_once_however_many_flags_are_live(self):
        s = self.score({'platform_health': {'throttle': {
            'undervolt_now': True, 'throttled_now': True,
            'freq_capped_now': True, 'soft_temp_now': True}}})
        self.assertEqual(self.w['power_throttled'], s)

    def test_a_malformed_shape_does_not_raise(self):
        for bad in ({'platform_health': 'nope'},
                    {'platform_health': {'throttle': 'nope'}},
                    {'platform_health': {}},
                    {'platform_health': None}):
            with self.subTest(shape=str(bad)[:40]):
                self.assertEqual(0, self.score(bad))


class TestBatteryWear(_Base):
    def test_a_worn_battery_scores(self):
        self.assertEqual(self.w['battery_worn'],
                         self.score({'battery': [{'health_pct': 41}]}))

    def test_a_healthy_battery_does_not(self):
        self.assertEqual(0, self.score({'battery': [{'health_pct': 92}]}))

    def test_the_worst_cell_decides(self):
        self.assertEqual(self.w['battery_worn'],
                         self.score({'battery': [{'health_pct': 95},
                                                 {'health_pct': 30}]}))

    def test_a_malformed_shape_does_not_raise(self):
        for bad in ({'battery': 'nope'}, {'battery': [None]},
                    {'battery': [{}]}, {'battery': []}):
            with self.subTest(shape=str(bad)[:40]):
                self.assertEqual(0, self.score(bad))


class TestTogether(_Base):
    def test_both_add(self):
        self.assertEqual(self.w['power_throttled'] + self.w['battery_worn'],
                         self.score({
                             'platform_health': {'throttle': {'undervolt_now': True}},
                             'battery': [{'health_pct': 41}]}))


if __name__ == '__main__':
    unittest.main()
