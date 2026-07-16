"""v6.2.2 batch 1 — make a batch of hardcoded alert-firing thresholds
operator-configurable on Settings → Alert parameters.

Each new config key must be wired through FIVE layers or it silently no-ops:
(1) declared in the ``ConfigSaveRequest`` model, (2) written by a
``handle_config_save`` block (the save-whitelist gotcha), (3) defaulted in
``handle_config_get``, (4) an ``ap-<slug>`` input in index.html, (5) a row in
``_ALERT_PARAM_FIELDS`` in app.js. This drives the REAL save/get handlers and
greps the two frontend surfaces so a missing layer fails here.
"""

import re
import unittest
from pathlib import Path

# Reuse the real save-handler harness (stubs require_admin_auth/get_json_obj/
# respond, points *_FILE at a tmp dir, drives handle_config_save for real).
from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

# key -> (non-default value to persist, ap-<slug> input id)
_KEYS = {
    "inode_warn_percent":             (70,  "ap-inode-warn"),
    "inode_crit_percent":             (88,  "ap-inode-crit"),
    "fd_warn_percent":                (60,  "ap-fd-warn"),
    "fd_crit_percent":                (90,  "ap-fd-crit"),
    "conntrack_warn_percent":         (65,  "ap-conntrack-warn"),
    "conntrack_crit_percent":         (92,  "ap-conntrack-crit"),
    "offline_missed_polls":           (8,   "ap-offline-polls"),
    "resolver_failures_before_alert": (4,   "ap-resolver-fails"),
    "ip_rep_confirm_scans":           (3,   "ap-iprep-scans"),
    "tls_warn_days":                  (30,  "ap-tls-warn-days"),
    "tls_crit_days":                  (5,   "ap-tls-crit-days"),
    "cert_file_expiring_days":        (45,  "ap-certfile-days"),
    "contract_warn_days":             (45,  "ap-contract-warn-days"),
    "contract_soon_days":             (120, "ap-contract-soon-days"),
    "os_eol_soon_days":               (120, "ap-os-eol-days"),
    "av_sig_stale_days":              (14,  "ap-av-stale-days"),
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
        cfg = self._save({"os_eol_soon_days": ""})
        self.assertNotIn("os_eol_soon_days", cfg)

    def test_out_of_range_rejected(self):
        self._save({"inode_warn_percent": "500"})  # > 100 max
        self.assertEqual(self.cap.get("s"), 400)

    def test_non_integer_rejected(self):
        self._save({"tls_warn_days": "soon"})
        self.assertEqual(self.cap.get("s"), 400)


class TestModelAcceptsEveryKey(unittest.TestCase):
    def test_model_validates(self):
        import request_models as rm
        for k in _KEYS:
            ok, err = rm.validate(rm.ConfigSaveRequest, {k: "5"})
            self.assertTrue(ok, f"{k}: {err}")

    def test_model_accepts_empty_body(self):
        # additive-superset: an empty {} body must still validate.
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


class TestSectionTitlesTranslated(unittest.TestCase):
    def test_new_section_titles_have_i18n(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for title in ("Capacity limits", "Reachability", "Certificates", "Lifecycle"):
            self.assertIn(f"'{title}'", i18n, f"{title} missing from i18n DICT")


if __name__ == "__main__":
    unittest.main()
