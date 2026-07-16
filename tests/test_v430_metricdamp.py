#!/usr/bin/env python3
"""v4.3.0: metric + SNMP flap dampening (the metrics/SNMP siblings of the
monitor failures_before_alert knob).

metric_failures_before_alert (default 1) holds a FIRST CPU/mem/disk/swap breach
(ok→warn/crit) until it has persisted N consecutive heartbeats. Escalation,
de-escalation and recovery are never held. SNMP's snmp_failures_before_alert
(default 2) makes the existing snmp_unreachable threshold configurable.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430md", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / 'server/html/index.html').read_text()
_APP_JS = (_ROOT / 'server/html/static/js/app.js').read_text()


class TestDampHoldHelper(unittest.TestCase):
    """Pure unit tests for the shared _metric_damp_hold predicate."""

    def test_need_one_never_holds(self):
        st = {}
        self.assertFalse(api._metric_damp_hold(st, 'k', 'ok', 'warning', 1))

    def test_first_breach_held_until_threshold(self):
        st = {}
        self.assertTrue(api._metric_damp_hold(st, 'k', 'ok', 'warning', 3))   # 1
        self.assertTrue(api._metric_damp_hold(st, 'k', 'ok', 'warning', 3))   # 2
        self.assertFalse(api._metric_damp_hold(st, 'k', 'ok', 'warning', 3))  # 3 → fire

    def test_escalation_never_held(self):
        st = {'k': 1}
        self.assertFalse(api._metric_damp_hold(st, 'k', 'warning', 'critical', 3))
        self.assertNotIn('k', st)   # streak cleared

    def test_recovery_never_held_and_clears(self):
        st = {'k': 2}
        self.assertFalse(api._metric_damp_hold(st, 'k', 'warning', 'ok', 3))
        self.assertNotIn('k', st)


class _MetricBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._cf = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / 'config.json'
        api._LOAD_CACHE.clear()
        self.fired = []
        self._orig_fire = api._fire_metric_webhook
        # capture (event, kind) without delivering
        api._fire_metric_webhook = lambda ev, dev_id, dev, kind, target, value, ref, extra=None: \
            self.fired.append((ev, kind))
        # neutralise maintenance-window / global-disable gates inside the engine
        self._orig_win = getattr(api, '_window_active', None)

    def tearDown(self):
        api._fire_metric_webhook = self._orig_fire
        api.CONFIG_FILE = self._cf
        api._LOAD_CACHE.clear()

    def _set_need(self, n):
        api.save(api.CONFIG_FILE, {'metric_failures_before_alert': n})
        api._LOAD_CACHE.clear()

    def _beat(self, dev, mem):
        api.process_metric_thresholds('d1', dev, {'mem_percent': mem})

    def _events(self):
        return [e for e, _ in self.fired]


class TestMetricDampening(_MetricBase):
    def test_default_fires_on_first_breach(self):
        self._set_need(1)
        dev = {'monitored': True}
        self._beat(dev, 88)            # well over the 85 warn default
        self.assertIn('metric_warning', self._events())

    def test_threshold_three_needs_three_breaches(self):
        self._set_need(3)
        dev = {'monitored': True}
        self._beat(dev, 88); self.assertEqual(self._events(), [])   # 1 held
        self._beat(dev, 88); self.assertEqual(self._events(), [])   # 2 held
        self._beat(dev, 88); self.assertEqual(self._events(), ['metric_warning'])  # 3

    def test_recovery_before_threshold_resets(self):
        self._set_need(3)
        dev = {'monitored': True}
        self._beat(dev, 88)            # streak 1
        self._beat(dev, 10)            # back to OK → streak cleared, no alert
        self.assertEqual(self._events(), [])
        self.assertNotIn('metric_breach_streak', {k: v for k, v in dev.items()
                                                  if dev.get('metric_breach_streak')})
        self._beat(dev, 88); self._beat(dev, 88)
        self.assertEqual(self._events(), [])          # only 2 in a row
        self._beat(dev, 88)
        self.assertEqual(self._events(), ['metric_warning'])

    def test_no_duplicate_after_firing(self):
        self._set_need(2)
        dev = {'monitored': True}
        self._beat(dev, 88); self._beat(dev, 88)      # fires once at 2
        self._beat(dev, 88); self._beat(dev, 88)      # still warning, no refire
        self.assertEqual(self._events(), ['metric_warning'])


class TestSnmpThresholdConfigurable(unittest.TestCase):
    def test_config_save_accepts_keys(self):
        import inspect
        src = inspect.getsource(api.handle_config_save)
        self.assertIn('snmp_failures_before_alert', src)
        self.assertIn('metric_failures_before_alert', src)

    def test_snmp_poll_uses_config(self):
        import inspect
        # the SNMP poll worker reads the configurable threshold
        src = inspect.getsource(api)
        self.assertIn("snmp_failures_before_alert", src)
        self.assertIn("_snmp_need", src)


class TestSettingsUI(unittest.TestCase):
    def test_controls_and_wiring(self):
        # v6.2.3: the dampening controls consolidated onto Settings → Alert
        # parameters (ap-metric-fails / ap-snmp-fails); the duplicate General-pane
        # rows (cfg-metric-fba / cfg-snmp-fba) that wrote the same keys were removed.
        self.assertIn('ap-metric-fails', _HTML)
        self.assertIn('ap-snmp-fails', _HTML)
        self.assertIn('metric_failures_before_alert', _APP_JS)
        self.assertIn('snmp_failures_before_alert', _APP_JS)


if __name__ == '__main__':
    unittest.main()
