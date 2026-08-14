#!/usr/bin/env python3
"""The resource forecast now reaches an operator.

`forecast_resources` shipped in v6.4.2 — memory, swap and CPU-load
days-to-saturation, fitted from the same daily samples as the disk-fill ETA
that has raised `disk_predict_fail` since v4.6.0. It reached NOTHING. No alert,
no Needs-Attention item, no check row. A host projected to exhaust its memory
in three days was visible only to someone who opened that one device's drawer
and scrolled to the forecast card.

Computes the answer and throws it away — the dominant shape of the v6.4.2
backlog, and it survived a release because the feature LOOKS complete from
either end: the projection is correct, the card renders, and nobody asked who
was told.

Second half: `forecast_resources` has always accepted `ceilings=` / `floors=`,
documented as "optional {metric: percent} overrides so an operator can…", and
NO CALLER EVER PASSED THEM. A documented capability reachable from nowhere.
Both are now wired through the five-spot alert-parameter pattern.
"""
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643sat-'))

_spec = importlib.util.spec_from_file_location('api_v643_sat', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import forecast  # noqa: E402

DAY = 86400


def _climbing(metric_key, start, per_day, days=30):
    """Daily samples with a clean upward trend — the shape forecast.py fits.

    The key is `mem_percent`, NOT `memory_percent` — forecast._resource_value
    maps the metric NAME ('memory') to a different SAMPLE key. My first fixture
    used the metric name, forecast_resources returned [] for every host, and
    the sweep correctly fired nothing. Had the assertion been "no alert" rather
    than "an alert", it would have passed against a completely dead feature.
    That is why the failure message below prints what forecast_resources
    actually returned instead of just saying the alert was missing.
    """
    now = int(time.time())
    return [{'ts': now - (days - i) * DAY, metric_key: start + per_day * i}
            for i in range(days)]


class _Base(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.fired = []
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'monitored': True}})
        api.save(api.CONFIG_FILE, {})
        api.save(api.ALERTS_FILE, {'alerts': [], 'alert_seq': 0})
        state = api.DATA_DIR / 'resource_predict_state.json'
        api.save(state, {'alerted': []})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE, api.ALERTS_FILE,
                  api.METRICS_HIST_FILE, state):
            api._invalidate_load_cache(f)
        self._orig_fire = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, *a, **k: self.fired.append(
            (ev, payload or {}))

    def tearDown(self):
        api.fire_webhook = self._orig_fire

    def _hist(self, samples):
        api.save(api.METRICS_HIST_FILE, {'d1': {'samples': samples}})
        api._invalidate_load_cache(api.METRICS_HIST_FILE)

    def _run(self):
        api._invalidate_load_cache(api.DATA_DIR / 'resource_predict_state.json')
        api._check_resource_saturation(int(time.time()))
        return [e for e, _p in self.fired]


class TestItFiresAtAll(_Base):
    def test_a_host_climbing_towards_its_memory_ceiling_alerts(self):
        # 60% climbing 3%/day reaches the 90% default ceiling in ~10 days,
        # inside the 21-day warn window.
        self._hist(_climbing('mem_percent', 60.0, 1.0))
        events = self._run()
        if 'resource_saturation_predicted' not in events:
            # forecast.py's sample key may differ on this build; surface which
            # keys it accepts rather than passing vacuously on a wrong fixture.
            rows = forecast.forecast_resources(_climbing('mem_percent', 60.0, 1.0))
            self.fail('no alert fired; forecast_resources returned '
                      f'{rows!r} for this fixture — check the sample key')
        self.assertIn('resource_saturation_predicted', events)

    def test_a_flat_host_does_not_alert(self):
        """The positive control for the negative case. A sweep that fired
        unconditionally would satisfy the test above."""
        self._hist([{'ts': self.now - (30 - i) * DAY, 'mem_percent': 40.0}
                    for i in range(30)])
        self.assertNotIn('resource_saturation_predicted', self._run())

    def test_an_unmonitored_host_is_skipped(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'monitored': False}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self._hist(_climbing('mem_percent', 60.0, 1.0))
        self.assertNotIn('resource_saturation_predicted', self._run())


class TestItIsEdgeTriggered(_Base):
    def test_it_fires_once_not_every_sweep(self):
        self._hist(_climbing('mem_percent', 60.0, 1.0))
        for _ in range(4):
            self._run()
        n = [e for e, _p in self.fired].count('resource_saturation_predicted')
        self.assertLessEqual(n, 1, 'edge-triggered means once per transition — '
                                   'an alert re-firing every six hours is how '
                                   'operators learn to ignore a channel')

    def test_improving_clears_it(self):
        self._hist(_climbing('mem_percent', 60.0, 1.0))
        self._run()
        self._hist([{'ts': self.now - (30 - i) * DAY, 'mem_percent': 20.0}
                    for i in range(30)])
        self.assertIn('resource_saturation_cleared', self._run())


class TestPerMetricIdentity(unittest.TestCase):
    """One host can saturate memory AND swap independently. Without a
    per-metric discriminator the two coalesce into one alert row, and the
    recover event then clears both when only one improved — the still-saturating
    resource goes silent and never re-fires, because its edge state says it
    already alerted. Three layers, all required."""

    def test_metric_is_an_alert_identity_field(self):
        self.assertIn('metric', api._ALERT_IDENTITY_FIELDS,
                      'without this the two metrics coalesce into one row')

    def test_metric_is_in_the_record_alert_whitelist(self):
        import inspect
        src = inspect.getsource(api._record_alert)
        self.assertIn("'metric'", src,
                      'a match key that is not whitelisted is never STORED, so '
                      'the recover event can never find the row and the alert '
                      'stays open forever')

    def test_the_recover_event_has_a_sub_match_branch(self):
        import inspect
        src = inspect.getsource(api._auto_resolve_alerts)
        self.assertIn('resource_saturation_cleared', src)


class TestTheCeilingsAreActuallyReachable(unittest.TestCase):
    """They were parameters of forecast_resources that no caller passed."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_defaults_come_from_the_forecast_module(self):
        ceilings, floors = api._resource_forecast_bounds()
        self.assertEqual(ceilings, {}, 'no override configured → pass nothing '
                                       'and let forecast.py use its defaults')
        self.assertEqual(floors, {})

    def test_a_configured_ceiling_is_threaded_through(self):
        api.save(api.CONFIG_FILE, {'forecast_ceiling_memory': 75.5})
        api._invalidate_load_cache(api.CONFIG_FILE)
        ceilings, _floors = api._resource_forecast_bounds()
        self.assertEqual(ceilings.get('memory'), 75.5,
                         'a float must survive — the int loop would truncate '
                         '75.5 to 75, which is a different policy')

    def test_garbage_falls_back_rather_than_to_zero(self):
        """A ceiling of 0 would make every host instantly saturated."""
        api.save(api.CONFIG_FILE, {'forecast_ceiling_memory': 'soon'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        ceilings, _f = api._resource_forecast_bounds()
        self.assertNotIn('memory', ceilings)

    def test_every_metric_has_both_bounds_wired(self):
        api.save(api.CONFIG_FILE, {
            f'forecast_{k}_{m}': 42.0
            for m in forecast.RESOURCE_METRICS for k in ('ceiling', 'floor')})
        api._invalidate_load_cache(api.CONFIG_FILE)
        ceilings, floors = api._resource_forecast_bounds()
        for m in forecast.RESOURCE_METRICS:
            self.assertEqual(ceilings.get(m), 42.0, m)
            self.assertEqual(floors.get(m), 42.0, m)


class TestTheFiveWiringSpots(unittest.TestCase):
    """The alert-parameter pattern silently no-ops if any of the five is
    missed; the save whitelist is the one that fails without a sound."""

    def test_the_save_path_persists_every_key(self):
        from test_v622_alert_params import _SaveBase
        keys = {f'forecast_{k}_{m}': 42.5
                for m in forecast.RESOURCE_METRICS for k in ('ceiling', 'floor')}

        class _T(_SaveBase):
            def runTest(self):
                cfg = self._save(dict(keys))
                for k, v in keys.items():
                    assert cfg.get(k) == v, f'{k} did not persist: {cfg.get(k)}'
        t = _T()
        t.setUp()
        try:
            t.runTest()
        finally:
            t.tearDown()

    def test_config_get_defaults_every_key(self):
        import inspect
        src = inspect.getsource(api.handle_config_get)
        self.assertIn('forecast_ceiling_', src)
        self.assertIn('forecast_floor_', src)

    def test_the_ui_has_an_input_and_a_field_row_for_each(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        for m in forecast.RESOURCE_METRICS:
            for k in ('ceiling', 'floor'):
                self.assertIn(f'id="ap-forecast-{k}-{m}"', html)
                self.assertIn(f"'forecast_{k}_{m}'", js)

    def test_the_float_keys_set_includes_them(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        i = js.index('_ALERT_PARAM_FLOAT_KEYS')
        block = js[i:i + 1200]
        for m in forecast.RESOURCE_METRICS:
            self.assertIn(f"'forecast_ceiling_{m}'", block,
                          'not in the float set → parseInt truncates a '
                          'fractional ceiling on save')


if __name__ == '__main__':
    unittest.main()


class TestTheSweepIsActuallyReachable(unittest.TestCase):
    """The tests above call `_check_resource_saturation` DIRECTLY.

    That is not enough, and proving it is the point of this class: I removed
    the call site from `_maybe_check_disk_predictions` and all sixteen tests
    still passed. A feature can be perfectly implemented, perfectly tested, and
    reached by nothing — which is the exact bug this whole sweep exists to fix,
    reproduced inside its own test file.

    So: assert it is called from the cadence path, and that the cadence path is
    in BOTH registries — main()'s `_safe(...)` block and scheduler.py's CADENCE
    tuple, the second of which this project reliably forgets.
    """

    def test_the_cadence_sweep_calls_it(self):
        import inspect
        src = inspect.getsource(api._maybe_check_disk_predictions)
        self.assertIn('_check_resource_saturation(', src,
                      'the resource half is never invoked — the projection is '
                      'computed correctly and reaches nobody, which is the bug '
                      'this change was made to fix')

    def test_that_sweep_runs_from_main(self):
        import inspect
        self.assertIn('_maybe_check_disk_predictions',
                      inspect.getsource(api.main))

    def test_and_from_the_external_scheduler(self):
        """CADENCE in scheduler.py is a SECOND registry. A sweep added to
        main() and not to it silently stops running on any install with the
        out-of-band scheduler enabled — which is the enterprise default."""
        self.assertIn('_maybe_check_disk_predictions',
                      (_CGI / 'scheduler.py').read_text())

    def test_it_fires_through_the_real_cadence_path(self):
        """Behavioural, not a grep: drive _maybe_check_disk_predictions and
        watch the resource alert come out the far end."""
        fired = []
        orig_fire, orig_view = api.fire_webhook, api._disk_health_view
        api.fire_webhook = lambda ev, p=None, *a, **k: fired.append(ev)
        api._disk_health_view = lambda *a, **k: []
        try:
            api.save(api.DEVICES_FILE, {'d1': {'name': 'web01', 'monitored': True}})
            api.save(api.CONFIG_FILE, {'last_disk_predict_check': 0})
            api.save(api.METRICS_HIST_FILE,
                     {'d1': {'samples': _climbing('mem_percent', 60.0, 1.0)}})
            api.save(api.DATA_DIR / 'resource_predict_state.json', {'alerted': []})
            for f in (api.DEVICES_FILE, api.CONFIG_FILE, api.METRICS_HIST_FILE,
                      api.DATA_DIR / 'resource_predict_state.json'):
                api._invalidate_load_cache(f)
            api._maybe_check_disk_predictions()
        finally:
            api.fire_webhook, api._disk_health_view = orig_fire, orig_view
        self.assertIn('resource_saturation_predicted', fired,
                      'the alert does not survive the trip through the real '
                      'cadence entry point')
