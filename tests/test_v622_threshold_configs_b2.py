"""v6.2.2 batch 2 — make the risk-level and reliability-level score-bucket
cutoffs operator-configurable on Settings → Alert parameters.

Six new config keys, each wired through FIVE layers or it silently no-ops:
(1) declared in the ``ConfigSaveRequest`` model, (2) written by a
``handle_config_save`` block (the save-whitelist gotcha), (3) defaulted in
``handle_config_get``, (4) an ``ap-<slug>`` input in index.html, (5) a row in
``_ALERT_PARAM_FIELDS`` in app.js. Plus the read-sites (``_risk_level`` /
``_reliability_level``) must actually HONOUR the config, and the Risk Assessment
payload must DELIVER ``risk_levels`` to the client.
"""

import re
import unittest
from pathlib import Path

from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

# key -> (non-default value to persist, ap-<slug> input id)
_KEYS = {
    "risk_level_critical": (90, "ap-risk-crit"),
    "risk_level_high":     (55, "ap-risk-high"),
    "risk_level_medium":   (25, "ap-risk-medium"),
    "reliability_crit":    (80, "ap-rel-crit"),
    "reliability_high":    (50, "ap-rel-high"),
    "reliability_medium":  (25, "ap-rel-medium"),
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
        cfg = self._save({"risk_level_critical": ""})
        self.assertNotIn("risk_level_critical", cfg)

    def test_out_of_range_rejected(self):
        self._save({"risk_level_critical": "500"})  # > 100 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"reliability_crit": "high"})
        self.assertEqual(self.cap.get("s"), 400)


class TestReadSitesHonourConfig(_SaveBase):
    def _bust(self):
        api._invalidate_load_cache(api.CONFIG_FILE)

    def test_risk_level_honours_lowered_critical(self):
        # default critical cutoff is 80 → a score of 85 is 'critical'.
        self._bust()
        self.assertEqual(api._risk_level(85), "critical")
        # raise the critical cutoff to 90 → 85 is no longer critical.
        self._save({"risk_level_critical": 90, "risk_level_high": 50,
                    "risk_level_medium": 20})
        self._bust()
        self.assertNotEqual(api._risk_level(85), "critical")
        self.assertEqual(api._risk_level(85), "high")

    def test_risk_level_clamps_descending(self):
        # a fat-fingered config that inverts the ladder must not crash / invert.
        self._save({"risk_level_critical": 20, "risk_level_high": 90,
                    "risk_level_medium": 95})
        self._bust()
        crit, high, med = api._risk_level_cuts()
        self.assertGreaterEqual(crit, high)
        self.assertGreaterEqual(high, med)

    def test_reliability_level_honours_changed_crit(self):
        self._bust()
        self.assertEqual(api._reliability_level(72), "critical")   # default crit=70
        self._save({"reliability_crit": 80, "reliability_high": 45,
                    "reliability_medium": 20})
        self._bust()
        self.assertNotEqual(api._reliability_level(72), "critical")
        self.assertEqual(api._reliability_level(72), "high")

    def test_reliability_defaults_match_module_constant(self):
        # _RELIABILITY_LEVELS stays the source of the defaults.
        self._bust()
        dc = {name: t for t, name in api._RELIABILITY_LEVELS}
        crit, high, med = api._reliability_level_cuts()
        self.assertEqual((crit, high, med),
                         (dc["critical"], dc["high"], dc["medium"]))


class TestRiskOverviewDeliversLevels(_SaveBase):
    def test_payload_includes_risk_levels(self):
        cap = {}

        def _resp(s, b=None):
            cap["s"] = s
            cap["b"] = b
            raise api.HTTPError(s, b)

        orig = {n: getattr(api, n) for n in
                ("respond", "require_auth", "_fleet_risk_cached",
                 "_caller_scope", "_tenant_gate", "_respond_with_etag")}
        try:
            api.respond = _resp
            api.require_auth = lambda: None
            api._fleet_risk_cached = lambda *a, **k: []
            api._caller_scope = lambda: None
            api._tenant_gate = lambda: None
            # force the plain respond() path (skip the ETag branch)
            api._respond_with_etag = lambda *a, **k: None
            try:
                api.handle_risk_overview()
            except api.HTTPError:
                pass
        finally:
            for n, v in orig.items():
                setattr(api, n, v)
        self.assertEqual(cap.get("s"), 200)
        body = cap.get("b") or {}
        self.assertIn("risk_levels", body)
        self.assertEqual(set(body["risk_levels"]), {"critical", "high", "medium"})


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


class TestFrontendWiring(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "server/html/index.html").read_text()
        self.app = (ROOT / "server/html/static/js/app.js").read_text()
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

    def test_client_delivery_helpers_present(self):
        # _RISK_CUTS + _setRiskCuts + _riskLevel drive the badge from config.
        for tok in ("_RISK_CUTS", "_setRiskCuts", "_riskLevel", "_setRiskCuts(data.risk_levels)"):
            self.assertIn(tok, self.app, f"{tok} missing from app.js")


class TestSectionTitlesTranslated(unittest.TestCase):
    def test_new_section_titles_have_i18n(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for title in ("Risk levels", "Reliability levels"):
            self.assertIn(f"'{title}'", i18n, f"{title} missing from i18n DICT")


if __name__ == "__main__":
    unittest.main()
