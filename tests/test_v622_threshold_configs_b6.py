"""v6.2.2 batch 6 — FLOAT thresholds.

Six operator-configurable thresholds are FLOATS, so they can NOT ride the int
config-save loop (which int()s and would truncate 0.5 → 0). A SEPARATE float loop
in handle_config_save coerces with float() and bounds-checks; request_models
declares each as a loose str; handle_config_get setdefaults the float default; the
UI wires ap-* number inputs; and saveAlertParams parseFloats (not parseInts) these
six keys. Read-sites: forecast._MIN_R2 (via a param), the two reliability trend
constants (via _config_ro in _device_reliability), and cve_scanner's CVSS→severity
bands (via a module setter the api-side scan worker calls).

The cardinal invariant this guards: a fractional tuning survives the whole
save → load → UI round-trip WITHOUT being truncated to an int anywhere.
"""

import re
import unittest
from pathlib import Path

from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

_API_SRC = (_CGI / "api.py").read_text()

import cve_scanner  # noqa: E402  (sys.path set by test_v622_alert_params)
import forecast     # noqa: E402

# key -> (float value to persist, (lo, hi) bounds, ap-<slug> input id, code default)
_KEYS = {
    "forecast_min_r2":                    (0.7, (0.0, 1.0),    "ap-forecast-min-r2",     0.5),
    "reliability_realloc_growth_per_day": (0.7, (0.0, 1000.0), "ap-rel-realloc-growth",  0.05),
    "reliability_health_decline_per_day": (0.7, (0.0, 1000.0), "ap-rel-health-decline",  0.5),
    "cvss_band_critical":                 (0.7, (0.0, 10.0),   "ap-cvss-crit",           9.0),
    "cvss_band_high":                     (0.7, (0.0, 10.0),   "ap-cvss-high",           7.0),
    "cvss_band_medium":                   (0.7, (0.0, 10.0),   "ap-cvss-med",            4.0),
}


# ── save/load round-trip: a float persists and is NOT truncated ──
class TestFloatSavePersistsUntruncated(_SaveBase):
    def test_each_key_persists_as_float(self):
        cfg = self._save({k: v for k, (v, _b, _s, _d) in _KEYS.items()})
        for k, (v, _b, _s, _d) in _KEYS.items():
            got = cfg.get(k)
            self.assertEqual(got, v, f"{k} did not persist (save-whitelist gotcha)")
            # the whole point: 0.7 must NOT have been int()'d down to 0.
            self.assertIsInstance(got, float, f"{k} stored as {type(got)}, not float")
            self.assertNotEqual(got, 0, f"{k} truncated to 0")

    def test_blank_clears_override(self):
        self._save({k: v for k, (v, _b, _s, _d) in _KEYS.items()})
        cfg = self._save({"forecast_min_r2": ""})
        self.assertNotIn("forecast_min_r2", cfg)

    def test_out_of_range_rejected(self):
        self._save({"forecast_min_r2": "1.5"})        # > 1.0 max
        self.assertEqual(self.cap.get("s"), 400)
        self._save({"cvss_band_critical": "11"})       # > 10 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_number_rejected(self):
        self._save({"cvss_band_high": "high-ish"})
        self.assertEqual(self.cap.get("s"), 400)

    def test_zero_accepted(self):
        # 0.0 is a legal tuning for growth/decline/bands — must not be rejected.
        cfg = self._save({"reliability_realloc_growth_per_day": "0"})
        self.assertEqual(cfg.get("reliability_realloc_growth_per_day"), 0.0)

    def test_empty_body_accepted(self):
        self._save({})
        self.assertNotEqual(self.cap.get("s"), 400)


# ── request_models declares each key (loose str) ──
class TestModelAcceptsEveryKey(unittest.TestCase):
    def test_model_validates_each(self):
        import request_models as rm
        for k in _KEYS:
            ok, err = rm.validate(rm.ConfigSaveRequest, {k: "0.7"})
            self.assertTrue(ok, f"{k}: {err}")

    def test_model_accepts_empty_body(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {})
        self.assertTrue(ok, err)


# ── handle_config_get setdefaults the float default ──
class TestConfigGetDefaults(unittest.TestCase):
    def test_setdefault_present_in_source(self):
        get_src = _API_SRC[_API_SRC.index("def handle_config_get"):
                           _API_SRC.index("def handle_config_save")]
        for k in _KEYS:
            self.assertIn(f"setdefault('{k}'", get_src,
                          f"{k} missing from handle_config_get defaults")


# ── the float loop is SEPARATE from the int loop (no int() truncation) ──
class TestSeparateFloatLoopExists(unittest.TestCase):
    def test_float_loop_uses_float_not_int(self):
        save_src = _API_SRC[_API_SRC.index("def handle_config_save"):
                            _API_SRC.index("def handle_config_save") + 120000]
        # every float key is coerced in a loop that calls float(), not int().
        self.assertIn("FLOAT thresholds", save_src)
        m = re.search(r"for _tk, _lo, _hi in \((.*?)\):(.*?)cfg\[_tk\] = _fv",
                      save_src, re.S)
        self.assertIsNotNone(m, "float coercion loop not found")
        loop_head, loop_body = m.group(1), m.group(2)
        for k in _KEYS:
            self.assertIn(f"'{k}'", loop_head, f"{k} not in the float loop tuple")
        self.assertIn("float(_raw)", loop_body)
        self.assertNotIn("int(_raw)", loop_body)


# ── CVSS reclassification honours a changed band (real code path) ──
class TestCvssBandReclassification(unittest.TestCase):
    def tearDown(self):
        cve_scanner.set_cvss_bands()   # restore standard defaults

    def _sev(self, score):
        return cve_scanner._severity_from_vuln(
            {"severity": [{"score": str(score)}]})[0]

    def test_default_bands(self):
        cve_scanner.set_cvss_bands()
        self.assertEqual(self._sev(8.5), "high")     # 7.0 ≤ 8.5 < 9.0

    def test_lowered_critical_band_reclassifies(self):
        # move the critical cutoff to 8.0 → an 8.5 CVE is now CRITICAL.
        cve_scanner.set_cvss_bands(critical=8.0, high=7.0, medium=4.0)
        self.assertEqual(self._sev(8.5), "critical")
        # and the standard mapping is otherwise intact
        self.assertEqual(self._sev(7.5), "high")
        self.assertEqual(self._sev(5.0), "medium")

    def test_worker_pushes_config_bands(self):
        # the api-side scan worker must call set_cvss_bands from _config_ro.
        worker = _API_SRC[_API_SRC.index("def _cve_scan_worker"):]
        worker = worker[:worker.index("\ndef ", 10)]
        self.assertIn("cve_scanner.set_cvss_bands", worker)
        self.assertIn("cvss_band_critical", worker)
        self.assertIn("cvss_band_high", worker)
        self.assertIn("cvss_band_medium", worker)


# ── forecast read-site honours the config ──
class TestForecastReadSite(_SaveBase):
    def _bust(self):
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_forecast_min_r2_default_and_override(self):
        api.save(api.CONFIG_FILE, {})
        self._bust()
        self.assertEqual(api._forecast_min_r2(), float(forecast._MIN_R2))
        api.save(api.CONFIG_FILE, {"forecast_min_r2": 0.9})
        self._bust()
        self.assertEqual(api._forecast_min_r2(), 0.9)   # float, not truncated

    def test_forecast_mounts_receives_min_r2(self):
        # every forecast_mounts call in api.py passes min_r2 (config-threaded).
        for m in re.finditer(r"forecast\.forecast_mounts\(([^)]*)\)", _API_SRC):
            self.assertIn("min_r2", m.group(1),
                          f"forecast_mounts call without min_r2: {m.group(0)}")


# ── reliability read-site honours the config (drive the real scorer) ──
class TestReliabilityReadSite(_SaveBase):
    def _bust(self):
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _score(self, now):
        # a health series declining ~2 points/day (90→82 over 4 days).
        series = [{"ts": now - (4 - i) * 86400, "score": 90 - i * 2}
                  for i in range(5)]
        return api._device_reliability(
            "d1", {"sysinfo": {}}, {}, {}, series, {}, {}, {}, now)

    def test_health_decline_threshold_moves_the_verdict(self):
        now = 1_000_000
        api.save(api.CONFIG_FILE, {})
        self._bust()
        kinds = {f["kind"] for f in self._score(now)["factors"]}
        self.assertIn("health_declining", kinds,
                      "default 0.5/day decline should flag a -2/day trend")
        # raise the decline threshold above the observed slope → no longer flagged.
        api.save(api.CONFIG_FILE, {"reliability_health_decline_per_day": 5.0})
        self._bust()
        kinds2 = {f["kind"] for f in self._score(now)["factors"]}
        self.assertNotIn("health_declining", kinds2,
                         "a 5.0/day threshold must not flag a -2/day trend")

    def test_reliability_reads_both_float_keys(self):
        rel = _API_SRC[_API_SRC.index("def _device_reliability"):]
        rel = rel[:rel.index("\ndef ", 10)]
        self.assertIn("reliability_realloc_growth_per_day", rel)
        self.assertIn("reliability_health_decline_per_day", rel)
        self.assertIn("_rel_float", rel)


# ── frontend wiring: inputs, _ALERT_PARAM_FIELDS, and the parseFloat branch ──
class TestFrontendWiring(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "server/html/index.html").read_text()
        self.app = (ROOT / "server/html/static/js/app.js").read_text()
        m = re.search(r"_ALERT_PARAM_FIELDS\s*=\s*\[(.*?)\];", self.app, re.S)
        self.assertIsNotNone(m)
        self.fields_src = m.group(1)

    def test_each_input_present_once(self):
        for k, (_v, _b, slug, _d) in _KEYS.items():
            self.assertEqual(self.html.count(f'id="{slug}"'), 1,
                             f"{slug} ({k}) not present exactly once")

    def test_inputs_carry_a_fractional_step(self):
        # a float input needs step != 1 or the browser blocks 0.5.
        for k, (_v, _b, slug, _d) in _KEYS.items():
            m = re.search(rf'id="{slug}"[^>]*step="([^"]+)"', self.html)
            self.assertIsNotNone(m, f"{slug} missing a step attr")
            self.assertLess(float(m.group(1)), 1.0, f"{slug} step must be fractional")

    def test_each_key_in_alert_param_fields(self):
        for k, (_v, _b, slug, _d) in _KEYS.items():
            self.assertIn(f"'{k}'", self.fields_src, f"{k} missing from fields")
            self.assertIn(f"'{slug}'", self.fields_src, f"{slug} missing from fields")

    def test_save_uses_parsefloat_for_float_keys(self):
        # the round-trip MUST NOT parseInt these (0.5 → 0). A dedicated
        # float-key set + parseFloat branch in saveAlertParams guards it.
        m = re.search(r"_ALERT_PARAM_FLOAT_KEYS\s*=\s*new Set\(\[(.*?)\]\)",
                      self.app, re.S)
        self.assertIsNotNone(m, "_ALERT_PARAM_FLOAT_KEYS set not found")
        float_set = m.group(1)
        for k in _KEYS:
            self.assertIn(f"'{k}'", float_set, f"{k} not in _ALERT_PARAM_FLOAT_KEYS")
        save = self.app[self.app.index("async function saveAlertParams"):]
        save = save[:save.index("\n}\n")]
        self.assertIn("_ALERT_PARAM_FLOAT_KEYS.has(key)", save)
        self.assertIn("parseFloat", save)

    def test_new_section_has_save_button_and_i18n_title(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        self.assertIn("'Forecast & CVE tuning'", i18n,
                      "new section title missing from i18n DICT")
        # every settings-section in the pane carries its own Save button.
        i = self.html.index('id="settings-pane-alertparams"')
        j = self.html.index('id="settings-pane-ignored"', i)
        pane = self.html[i:j]
        self.assertEqual(pane.count('class="settings-section"'),
                         pane.count('data-action="saveAlertParams"'))


if __name__ == "__main__":
    unittest.main()
