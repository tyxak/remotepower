#!/usr/bin/env python3
"""v4.3.0: monitor flap dampening.

A monitor with failures_before_alert=N must only raise monitor_down after N
consecutive failed checks; a recovery before N resets the streak. Default
(field absent / 1) fires on the first failure exactly as before.
"""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430fd", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP_JS = (_ROOT / 'server/html/static/js/app.js').read_text()
_HTML = (_ROOT / 'server/html/index.html').read_text()


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        for name in ('CONFIG_FILE', 'MON_HIST_FILE'):
            setattr(self, '_' + name, getattr(api, name))
            setattr(api, name, self.d / Path(getattr(api, name)).name)
        self.fired = []
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))

    def tearDown(self):
        api.fire_webhook = self._orig_fire
        for name in ('CONFIG_FILE', 'MON_HIST_FILE'):
            setattr(api, name, getattr(self, '_' + name))

    def _cfg(self, fba=None):
        mon = {'label': 'site', 'type': 'http', 'target': 'https://x'}
        if fba is not None:
            mon['failures_before_alert'] = fba
        api.save(api.CONFIG_FILE, {'monitors': [mon]})

    def _fail(self):
        api._persist_monitor_results([{'label': 'site', 'type': 'http',
            'target': 'https://x', 'ok': False, 'detail': '500',
            'checked': int(time.time())}])

    def _ok(self):
        api._persist_monitor_results([{'label': 'site', 'type': 'http',
            'target': 'https://x', 'ok': True, 'detail': '200',
            'checked': int(time.time())}])

    def _events(self):
        return [e for e, _ in self.fired]


class TestFlapDampening(_Base):
    def test_default_fires_on_first_failure(self):
        self._cfg()                 # no failures_before_alert → default 1
        self._fail()
        self.assertEqual(self._events(), ['monitor_down'])

    def test_threshold_three_needs_three_failures(self):
        self._cfg(fba=3)
        self._fail();  self.assertEqual(self._events(), [])   # 1
        self._fail();  self.assertEqual(self._events(), [])   # 2
        self._fail();  self.assertEqual(self._events(), ['monitor_down'])  # 3 → fire

    def test_no_duplicate_after_alert(self):
        self._cfg(fba=2)
        self._fail(); self._fail()              # fires once at 2
        self._fail(); self._fail()              # still down — no second fire
        self.assertEqual(self._events(), ['monitor_down'])

    def test_recovery_before_threshold_resets_streak(self):
        self._cfg(fba=3)
        self._fail(); self._fail()              # streak 2, no alert
        self._ok()                              # recover → streak reset, no monitor_up
                                                # (was never "down" since we never alerted)
        self.assertEqual(self._events(), [])
        self._fail(); self._fail()              # streak 1,2 again — still no alert
        self.assertEqual(self._events(), [])
        self._fail()                            # streak 3 → fire
        self.assertEqual(self._events(), ['monitor_down'])

    def test_recovery_after_alert_fires_monitor_up(self):
        self._cfg(fba=2)
        self._fail(); self._fail()              # monitor_down
        self._ok()                              # monitor_up
        self.assertEqual(self._events(), ['monitor_down', 'monitor_up'])

    def test_streak_capped_in_config(self):
        # A long-down monitor must not grow the streak unbounded (it caps at the
        # threshold so config writes stop).
        self._cfg(fba=2)
        for _ in range(6):
            self._fail()
        streak = (api.load(api.CONFIG_FILE).get('monitor_fail_streak') or {}).get('site')
        self.assertEqual(streak, 2)             # capped at threshold


class TestConfigSaveValidation(unittest.TestCase):
    def test_save_validates_field(self):
        import inspect
        src = inspect.getsource(api.handle_config_save)
        self.assertIn('failures_before_alert', src)

    def test_ui_wired(self):
        self.assertIn('mon-failures-before-alert', _HTML)
        self.assertIn('failures_before_alert', _APP_JS)


if __name__ == '__main__':
    unittest.main()
