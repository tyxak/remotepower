"""v6.2.2 batch 4 — Settings → per-factor SCORE WEIGHTS.

Prior batches made the grade/level CUTOFFS tunable; this batch makes the WEIGHTS
that PRODUCE the scores tunable, one config key per factor:

  * health_weight_<sev>       — _HEALTH_WEIGHTS deduction per NA item (_fleet_health)
  * risk_weight_<factor>      — _RISK_WEIGHTS  contribution (_device_risk)
  * reliability_weight_<factor> — _RELIABILITY_WEIGHTS contribution (_device_reliability)

Each is wired through the shipped 5-point template: config-get default, save-block
validation, ConfigSaveRequest model + coercer, index.html ap-* input, and the
_ALERT_PARAM_FIELDS loader/saver in app.js. The consumers call an ACCESSOR
(_health_weights / _risk_weights / _reliability_weights) that merges config
overrides over the constant defaults, hoisted once out of any per-device loop.

Guards the "toggle silently doesn't persist" gotcha end to end by driving the REAL
handle_config_save, and pins that every generated key is wired on both ends.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-b4-"))
_spec = importlib.util.spec_from_file_location("api_v622_b4", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# id-prefix per dict, mirroring the accessors + the frontend maps.
_IDPFX = {
    "health_weight_": "ap-hw-",
    "risk_weight_": "ap-rw-",
    "reliability_weight_": "ap-lw-",
}
_DICTS = (
    ("health_weight_", api._HEALTH_WEIGHTS),
    ("risk_weight_", api._RISK_WEIGHTS),
    ("reliability_weight_", api._RELIABILITY_WEIGHTS),
)


def _all_keys():
    """(config_key, factor, id, default) for every generated weight key."""
    for pfx, d in _DICTS:
        for factor, default in d.items():
            yield f"{pfx}{factor}", factor, f"{_IDPFX[pfx]}{factor}", default


# A representative sample across all three dicts (task requirement).
_SAMPLE = {
    "health_weight_critical": 50,
    "health_weight_warning": 3,
    "health_weight_info": 1,
    "risk_weight_offline": 40,
    "risk_weight_firewall_off": 20,
    "reliability_weight_smart_failing": 60,
    "reliability_weight_oom_recent": 4,
}


class _SaveBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("USERS_FILE", "CONFIG_FILE", "ROLES_FILE", "DEVICES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "verify_token", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"] = s
            self.cap["b"] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def _save(self, body):
        api.get_json_obj = lambda: body
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}


class TestWeightPersist(_SaveBase):
    def test_sample_keys_persist(self):
        cfg = self._save(dict(_SAMPLE))
        for k, v in _SAMPLE.items():
            self.assertEqual(cfg.get(k), v, f"{k} did not persist (save-whitelist gotcha)")

    def test_zero_is_legal_disables_factor(self):
        cfg = self._save({"risk_weight_offline": "0"})
        self.assertEqual(cfg.get("risk_weight_offline"), 0)

    def test_out_of_range_rejected(self):
        self._save({"risk_weight_offline": "5000"})   # > 1000 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"health_weight_critical": "abc"})
        self.assertEqual(self.cap.get("s"), 400)

    def test_blank_clears_override(self):
        self._save({"health_weight_critical": "50"})
        cfg = self._save({"health_weight_critical": ""})
        self.assertNotIn("health_weight_critical", cfg)


class TestAccessors(_SaveBase):
    def test_default_when_unconfigured(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api._health_weights(), dict(api._HEALTH_WEIGHTS))
        self.assertEqual(api._risk_weights(), dict(api._RISK_WEIGHTS))
        self.assertEqual(api._reliability_weights(), dict(api._RELIABILITY_WEIGHTS))

    def test_override_reflected(self):
        self._save({"health_weight_critical": "50",
                    "risk_weight_offline": "40",
                    "reliability_weight_smart_failing": "60"})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api._health_weights()["critical"], 50)
        self.assertEqual(api._risk_weights()["offline"], 40)
        self.assertEqual(api._reliability_weights()["smart_failing"], 60)
        # untouched factors keep their default
        self.assertEqual(api._health_weights()["warning"], api._HEALTH_WEIGHTS["warning"])

    def test_blank_reverts_accessor_to_default(self):
        self._save({"health_weight_critical": "50"})
        self._save({"health_weight_critical": ""})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api._health_weights()["critical"], api._HEALTH_WEIGHTS["critical"])

    def test_accessor_never_mutates_config(self):
        api.save(api.CONFIG_FILE, {"health_weight_critical": 50})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._health_weights()["critical"] = 999
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get("health_weight_critical"), 50)


class TestFleetHealthUsesWeight(_SaveBase):
    def _fleet_with_one_critical(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "d1", "monitored": True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        orig = api._attention_payload
        api._attention_payload = lambda *a, **k: {
            "items": [{"device_id": "d1", "severity": "critical"}], "counts": {}}
        try:
            return api._fleet_health(use_cache=False)
        finally:
            api._attention_payload = orig

    def test_default_deduction(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        h = self._fleet_with_one_critical()
        self.assertEqual(h["devices"][0]["score"], 100 - api._HEALTH_WEIGHTS["critical"])

    def test_heavier_weight_deducts_more(self):
        self._save({"health_weight_critical": "50"})
        api._invalidate_load_cache(api.CONFIG_FILE)
        h = self._fleet_with_one_critical()
        self.assertEqual(h["devices"][0]["score"], 50)  # 100 - 50 (> the default 25 hit)


class TestModelAcceptsWeights(unittest.TestCase):
    def test_validate_ok_for_a_weight_key(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {"health_weight_critical": "5"})
        self.assertTrue(ok, err)

    def test_validate_ok_for_all_generated_keys(self):
        import request_models as rm
        body = {k: "7" for k, _f, _i, _d in _all_keys()}
        ok, err = rm.validate(rm.ConfigSaveRequest, body)
        self.assertTrue(ok, err)


class TestFivePointWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api_src = (_CGI / "api.py").read_text()
        cls.html = (ROOT / "server/html/index.html").read_text()
        cls.app = (ROOT / "server/html/static/js/app.js").read_text()
        i = cls.app.index("const _SCORE_WEIGHT_DEFAULTS")
        cls.app_region = cls.app[i:cls.app.index("for (const [idPfx", i)]

    def test_every_key_has_a_config_get_default(self):
        get_src = self.api_src[self.api_src.index("def handle_config_get"):
                               self.api_src.index("def handle_config_save")]
        # defaults are generated from the dicts via the _SCORE_WEIGHT_PREFIXES loop
        self.assertIn("_SCORE_WEIGHT_PREFIXES", get_src)
        self.assertIn("safe.setdefault(f'{_wpfx}{_wk}'", get_src)

    def test_every_key_has_an_input_in_index_html(self):
        for cfg_key, _factor, _id, _default in _all_keys():
            self.assertEqual(self.html.count(f'id="{_id}"'), 1,
                             f'{cfg_key}: expected exactly one ap-* input id="{_id}"')

    def test_every_factor_wired_in_alert_param_fields(self):
        # _ALERT_PARAM_FIELDS is extended from _SCORE_WEIGHT_DEFAULTS at load time;
        # assert each id/key prefix and factor is in that generated map.
        self.assertIn("_ALERT_PARAM_FIELDS.push", self.app)
        for keypfx, idpfx in (("health_weight_", "ap-hw-"),
                              ("risk_weight_", "ap-rw-"),
                              ("reliability_weight_", "ap-lw-")):
            self.assertIn(f"'{keypfx}'", self.app_region)
            self.assertIn(f"'{idpfx}'", self.app_region)
        for _cfg_key, factor, _id, _default in _all_keys():
            self.assertIn(f"{factor}:", self.app_region,
                          f"factor {factor} missing from _SCORE_WEIGHT_DEFAULTS")

    def test_section_titles_translated(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for title in ("Health score weights", "Risk score weights",
                      "Reliability score weights"):
            self.assertIn(f"'{title}'", i18n, f"{title} missing from i18n DICT")
            self.assertIn(title, self.html)


if __name__ == "__main__":
    unittest.main()
