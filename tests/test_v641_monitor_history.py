"""v6.4.1: monitor check history is deeper, and operator-tunable.

The cap was 50 checks — under an hour at the default 60-second cadence. That is
the same window the Live Monitor sparkline, the latency percentiles and the SLO
availability figure are all computed over, so every one of them described a
period far shorter than the one an operator reasons about. Default is now 300
(~5h) and `monitor_history_max` tunes it.

The pattern's silent failure is the save whitelist: a key missing from
`handle_config_save`'s int loop persists nowhere, so the Settings input appears
to work and the value falls back to the default forever. These tests drive the
REAL save, then the REAL trim.
"""
import unittest

import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
# This module imports a sibling from tests/. `unittest discover -s tests`
# puts that directory on sys.path for free, so the omission is invisible
# there — but `python3 -m unittest tests.<this>` does not, and the module
# then fails to import at all. Make it runnable on its own.
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
from test_v622_alert_params import _SaveBase, api, _CGI

_API_SRC = (_CGI / 'api.py').read_text()


class TestTunablePlumbing(_SaveBase):
    def test_value_persists_through_the_real_save(self):
        cfg = self._save({'monitor_history_max': 1000})
        self.assertEqual(cfg.get('monitor_history_max'), 1000)

    def test_blank_clears_the_override(self):
        self._save({'monitor_history_max': 1000})
        cfg = self._save({'monitor_history_max': ''})
        self.assertNotIn('monitor_history_max', cfg)

    def test_out_of_range_rejected(self):
        self._save({'monitor_history_max': '99999'})
        self.assertEqual(self.cap.get('s'), 400)
        self._save({'monitor_history_max': '1'})
        self.assertEqual(self.cap.get('s'), 400)

    def test_model_accepts_it(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {'monitor_history_max': '500'})
        self.assertTrue(ok, err)

    def test_config_get_exposes_a_default(self):
        get_src = _API_SRC[_API_SRC.index('def handle_config_get'):
                           _API_SRC.index('def handle_config_save')]
        self.assertIn("setdefault('monitor_history_max'", get_src)

    def test_settings_input_and_field_row_exist(self):
        html = (_CGI.parent / 'html' / 'index.html').read_text()
        self.assertIn('id="ap-monitor-history-max"', html)
        import clientjs
        self.assertIn("'monitor_history_max'", clientjs.client_js())


class TestDefaultRaised(unittest.TestCase):
    def test_default_is_deeper_than_the_old_hour(self):
        self.assertGreaterEqual(api.MAX_MON_HISTORY, 300)

    def test_trim_reads_the_config_not_the_constant(self):
        src = _API_SRC[_API_SRC.index('def _persist_monitor_results'):]
        src = src[:src.index('\ndef ', 10)]
        self.assertIn("cfg.get('monitor_history_max')", src)
        self.assertIn('mh[key][-_hist_cap:]', src)
        # Hoisted: one read for the batch, not one per monitor result.
        self.assertLess(src.index('_hist_cap ='), src.index('for r in results:'))


class TestTrimHonoursTheSetting(_SaveBase):
    """Drive the real persist path — the cap has to actually change."""

    def _run(self, n):
        api.save(api.MON_HIST_FILE, {})
        api._invalidate_load_cache(api.MON_HIST_FILE)
        for i in range(n):
            api._persist_monitor_results(
                [{'label': 'probe', 'checked': 1000 + i, 'ok': True,
                  'detail': 'up', 'ms': 5}])
        api._invalidate_load_cache(api.MON_HIST_FILE)
        return len((api.load(api.MON_HIST_FILE) or {}).get('probe') or [])

    def test_custom_cap_is_applied(self):
        self._save({'monitor_history_max': 12})
        self.assertEqual(self._run(20), 12)

    def test_default_cap_keeps_far_more_than_fifty(self):
        self._save({'monitor_history_max': ''})
        self.assertEqual(self._run(60), 60)   # 60 > the old cap of 50

    def test_nonsense_config_falls_back_rather_than_crashing(self):
        # A hand-edited / GitOps config can carry anything; the trim must not
        # raise and must not drop history to zero.
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['monitor_history_max'] = 'lots'
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(self._run(20), 20)


if __name__ == '__main__':
    unittest.main()
