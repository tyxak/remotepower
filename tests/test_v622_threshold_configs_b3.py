"""v6.2.2 batch 3 — make the hardware / thermal / SMART display+alert thresholds
operator-configurable on Settings → Thermal & GPU / Disk wear & SMART.

Eight new config keys, each wired through the FIVE layers or it silently no-ops:
(1) declared in the ``ConfigSaveRequest`` model, (2) written by a
``handle_config_save`` block (the save-whitelist gotcha), (3) defaulted in
``handle_config_get``, (4) an ``ap-<slug>`` input in index.html, (5) a row in
``_ALERT_PARAM_FIELDS`` in app.js. Plus the read-sites must actually HONOUR the
config, the fleet thermal/gpu/disk-health payloads must DELIVER ``hw_bands`` to
the client, and ``ecc_error_alert_min_delta`` default 0 must preserve today's
fire-on-any-positive-delta behaviour EXACTLY.
"""

import re
import unittest
from pathlib import Path

from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

# key -> (non-default value to persist, ap-<slug> input id)
_KEYS = {
    "thermal_hot_c":                (70,  "ap-thermal-hot-c"),
    "thermal_crit_c":               (90,  "ap-thermal-crit-c"),
    "gpu_hot_c":                    (80,  "ap-gpu-hot-c"),
    "smart_wear_warn_pct":          (75,  "ap-smart-wear-warn"),
    "smart_wear_high_pct":          (95,  "ap-smart-wear-high"),
    "smart_realloc_crit_sectors":   (200, "ap-smart-realloc-crit"),
    "disk_predict_medium_eta_days": (365, "ap-disk-eta-days"),
    "ecc_error_alert_min_delta":    (5,   "ap-ecc-min-delta"),
}


class TestSavePersistsEveryKey(_SaveBase):
    def test_each_key_persists(self):
        body = {k: v for k, (v, _slug) in _KEYS.items()}
        cfg = self._save(body)
        for k, (v, _slug) in _KEYS.items():
            self.assertEqual(cfg.get(k), v,
                             f"{k} did not persist (save-whitelist gotcha)")

    def test_blank_clears_override(self):
        self._save({k: v for k, (v, _s) in _KEYS.items()})
        cfg = self._save({"thermal_hot_c": ""})
        self.assertNotIn("thermal_hot_c", cfg)

    def test_out_of_range_rejected(self):
        self._save({"thermal_hot_c": "500"})  # > 200 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"smart_wear_warn_pct": "hot"})
        self.assertEqual(self.cap.get("s"), 400)

    def test_ecc_min_delta_accepts_zero(self):
        # ecc_error_alert_min_delta has a floor of 0 (0 = fire on any positive delta).
        cfg = self._save({"ecc_error_alert_min_delta": "0"})
        self.assertEqual(cfg.get("ecc_error_alert_min_delta"), 0)


class TestModelAcceptsEveryKey(unittest.TestCase):
    def test_model_validates(self):
        import request_models as rm
        for k in _KEYS:
            ok, err = rm.validate(rm.ConfigSaveRequest, {k: "5"})
            self.assertTrue(ok, f"{k}: {err}")

    def test_model_accepts_empty_body(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {})
        self.assertTrue(ok, err)


class TestConfigGetDefaults(unittest.TestCase):
    def test_setdefault_present_in_source(self):
        src = (_CGI / "api.py").read_text()
        get_src = src[src.index("def handle_config_get"):src.index("def handle_config_save")]
        for k in _KEYS:
            self.assertIn(f"setdefault('{k}'", get_src,
                          f"{k} missing from handle_config_get defaults")


class TestReadSitesHonourConfig(_SaveBase):
    """Drive the real fleet-thermal / fleet-gpu handlers and the ecc ingest and
    assert a changed config value actually moves the verdict."""

    def setUp(self):
        super().setUp()
        # extra stores the fleet handlers + ecc ingest read
        for attr in ("DEVICES_FILE", "HARDWARE_FILE", "THERMAL_HIST_FILE",
                     "GPU_HIST_FILE", "POSTURE_STATE_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self._orig["require_auth"] = api.require_auth
        self._orig["_caller_scope"] = api._caller_scope
        self._orig["_tenant_gate"] = api._tenant_gate
        api.require_auth = lambda require_admin=False: "jakob"
        api._caller_scope = lambda: None
        api._tenant_gate = lambda: None

    def _bust(self):
        api._invalidate_load_cache(api.CONFIG_FILE)

    def _call(self, fn):
        try:
            fn()
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def test_thermal_hot_flag_honours_config(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "web"}})
        api.save(api.HARDWARE_FILE,
                 {"d1": {"ts": 5, "temps": [{"label": "cpu", "current_c": 78}]}})
        # default hot cutoff 75 → 78 °C is hot
        self._bust()
        r = self._call(api.handle_fleet_thermal)
        self.assertEqual(r["hot"], 1)
        self.assertIn("hw_bands", r)
        self.assertEqual(r["hw_bands"]["thermal_hot"], 75)
        # raise the hot cutoff to 80 → 78 °C is no longer hot
        self._save({"thermal_hot_c": 80})
        self._bust()
        r = self._call(api.handle_fleet_thermal)
        self.assertEqual(r["hot"], 0)
        self.assertEqual(r["hw_bands"]["thermal_hot"], 80)

    def test_gpu_hot_count_honours_config(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "gpubox", "last_seen": 9e9}})
        api.save(api.HARDWARE_FILE,
                 {"d1": {"ts": 5, "gpus": [{"vendor": "nvidia", "name": "X",
                                            "temp_c": 82, "util_pct": 10}]}})
        # default gpu hot cutoff 85 → 82 °C is not hot
        self._bust()
        r = self._call(api.handle_fleet_gpus)
        self.assertEqual(r["summary"]["hot"], 0)
        self.assertIn("hw_bands", r)
        # lower the cutoff to 80 → 82 °C is now hot
        self._save({"gpu_hot_c": 80})
        self._bust()
        r = self._call(api.handle_fleet_gpus)
        self.assertEqual(r["summary"]["hot"], 1)
        self.assertEqual(r["hw_bands"]["gpu_hot"], 80)

    def test_disk_health_delivers_bands(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "web"}})
        api.save(api.HARDWARE_FILE, {"d1": {"ts": 5, "smart": []}})
        self._bust()
        r = self._call(api.handle_disk_health)
        self.assertIn("hw_bands", r)
        self.assertEqual(r["hw_bands"]["wear_warn"], 80)
        self.assertEqual(r["hw_bands"]["wear_high"], 90)

    def test_wear_and_realloc_and_eta_read_config(self):
        # These read-sites are exercised via the SMART trend engine, which needs
        # multi-day history; assert here that each read the config key (drive OR
        # grep per the batch-3 spec). Function-scoped grep so a stray hit elsewhere
        # can't mask a missing read.
        src = (_CGI / "api.py").read_text()
        dv = src[src.index("def _disk_health_view"):src.index("def _maybe_check_disk_predictions")]
        for k in ("smart_wear_warn_pct", "smart_wear_high_pct", "smart_realloc_crit_sectors"):
            self.assertIn(f"'{k}'", dv, f"{k} not read in _disk_health_view")
        mp = src[src.index("def _maybe_check_disk_predictions"):
                 src.index("def _ingest_custom_script_results")]
        self.assertIn("'disk_predict_medium_eta_days'", mp,
                      "disk_predict_medium_eta_days not read in _maybe_check_disk_predictions")

    # ── ecc_error_alert_min_delta: default 0 preserves fire-on-any-positive ──
    def _ecc_fires(self, prev_ce, cur_ce):
        """Drive the real _ingest_posture_v3110 ecc path; return True if
        ecc_errors fired for a (prev → cur) correctable-error transition."""
        dev_id = "eccdev"
        api._entity_write_one(api.POSTURE_STATE_FILE, dev_id,
                              {"ecc": {"ce": prev_ce, "ue": 0}})
        fired = []
        orig_fw = api.fire_webhook
        api.fire_webhook = lambda ev, payload: fired.append(ev)
        try:
            self._bust()
            api._ingest_posture_v3110(dev_id, "eccdev",
                                      {"ecc": {"ce": cur_ce, "ue": 0}})
        finally:
            api.fire_webhook = orig_fw
        return "ecc_errors" in fired

    def test_ecc_default_fires_on_any_positive_delta(self):
        # default ecc_error_alert_min_delta = 0 → a delta of 1 must fire (today's behaviour)
        self.assertTrue(self._ecc_fires(0, 1))
        self.assertFalse(self._ecc_fires(5, 5))   # no delta → no fire

    def test_ecc_min_delta_raises_the_floor(self):
        self._save({"ecc_error_alert_min_delta": 5})
        self.assertFalse(self._ecc_fires(0, 3))    # delta 3 <= floor 5 → no fire
        self.assertTrue(self._ecc_fires(0, 6))     # delta 6 > floor 5 → fire


class TestPayloadDeliversBands(unittest.TestCase):
    def test_handlers_deliver_hw_bands(self):
        src = (_CGI / "api.py").read_text()
        # thermal + gpu + disk-health each respond with hw_bands
        thermal = src[src.index("def handle_fleet_thermal"):src.index("def handle_fleet_gpus")]
        self.assertIn("'hw_bands'", thermal)
        gpus = src[src.index("def handle_fleet_gpus"):src.index("def handle_fleet_power")]
        self.assertIn("'hw_bands'", gpus)
        dh = src[src.index("def handle_disk_health"):src.index("def _maybe_check_disk_predictions")]
        self.assertIn("'hw_bands'", dh)


class TestFrontendWiring(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "server/html/index.html").read_text()
        self.app = (ROOT / "server/html/static/js/app.js").read_text()
        self.gpu = (ROOT / "server/html/static/js/app-gpu.js").read_text()
        m = re.search(r"_ALERT_PARAM_FIELDS\s*=\s*\[(.*?)\];", self.app, re.S)
        self.assertIsNotNone(m, "_ALERT_PARAM_FIELDS array not found")
        self.fields_src = m.group(1)

    def test_each_input_present_once(self):
        for k, (_v, slug) in _KEYS.items():
            self.assertEqual(self.html.count(f'id="{slug}"'), 1,
                             f"{slug} ({k}) not present exactly once in index.html")

    def test_each_key_in_alert_param_fields(self):
        for k, (_v, slug) in _KEYS.items():
            self.assertIn(f"'{k}'", self.fields_src,
                          f"{k} missing from _ALERT_PARAM_FIELDS")
            self.assertIn(f"'{slug}'", self.fields_src,
                          f"{slug} missing from _ALERT_PARAM_FIELDS")

    def test_hw_bands_helpers_present(self):
        for tok in ("_HW_BANDS", "_setHwBands"):
            self.assertIn(tok, self.app, f"{tok} missing from app.js")

    def test_wear_colour_driven_from_bands(self):
        # the SSD-wear cell colour must use the delivered bands, not a hardcoded 90/80
        self.assertIn("_HW_BANDS.wear_high", self.app)
        self.assertIn("_HW_BANDS.wear_warn", self.app)
        self.assertIn("_setHwBands(_diskHealthResp.hw_bands)", self.app)
        # the old hardcoded ladder is gone
        self.assertNotIn("_riskClass(t.wear_pct,90,80)", self.app)
        self.assertNotIn("_riskClass(r.wear_pct,90,80)", self.app)

    def test_gpu_colour_driven_from_bands(self):
        self.assertIn("_HW_BANDS.gpu_hot", self.gpu)
        self.assertIn("_HW_BANDS.thermal_hot", self.gpu)
        self.assertIn("_setHwBands(", self.gpu)
        self.assertNotIn("_riskClass(g.temp_c, 85, 75", self.gpu)


class TestSectionTitlesTranslated(unittest.TestCase):
    def test_new_section_titles_have_i18n(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for title in ("Thermal & GPU", "Disk wear & SMART"):
            self.assertIn(f"'{title}'", i18n, f"{title} missing from i18n DICT")


if __name__ == "__main__":
    unittest.main()
