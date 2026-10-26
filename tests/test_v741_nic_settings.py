#!/usr/bin/env python3
"""v7.4.1, issue #37: the fleet-wide drop floor, on Settings -> Alert parameters.

`nic_drop_alert_min` is a new alert parameter, so it has to be wired through every
layer the earlier ones were or it silently does nothing: the save block, the GET
default, the request model, the input in index.html, the row in
_ALERT_PARAM_FIELDS, the shared kwargs the Checks engine reads, and the six
translations. The save and GET handlers are driven for real.

Blank means "judge drops with the errors", the way it worked before; 0 turns drop
alerts off.
"""
import re
import sys as _rp_sys
import pathlib as _rp_pl

_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import time  # noqa: E402
import unittest  # noqa: E402

from test_v622_alert_params import _SaveBase, ROOT, api  # noqa: E402

HTML = (ROOT / "server/html/index.html").read_text()
APP = (ROOT / "server/html/static/js/app.js").read_text()
I18N = (ROOT / "server/html/static/js/i18n.js").read_text()
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


class TestSave(_SaveBase):
    def test_a_value_persists(self):
        cfg = self._save({"nic_drop_alert_min": 500})
        self.assertEqual(cfg.get("nic_drop_alert_min"), 500)
        self.assertEqual(api._nic_fleet_floors(cfg), (api._NIC_ERR_ALERT_MIN, 500))

    def test_zero_is_kept_and_means_off(self):
        cfg = self._save({"nic_drop_alert_min": 0})
        self.assertIn("nic_drop_alert_min", cfg, "0 must be stored, not treated as blank")
        self.assertEqual(api._nic_fleet_floors(cfg)[1], 0)

    def test_blank_clears_it_and_drops_follow_the_errors_again(self):
        self._save({"nic_drop_alert_min": 500})
        cfg = self._save({"nic_drop_alert_min": ""})
        self.assertNotIn("nic_drop_alert_min", cfg)
        self.assertIsNone(api._nic_fleet_floors(cfg)[1])

    def test_out_of_range_and_junk_are_refused(self):
        for bad in (-1, 100001, "abc"):
            with self.subTest(bad=bad):
                self.cap.clear()
                self._save({"nic_drop_alert_min": bad})
                self.assertEqual(self.cap.get("s"), 400)

    def test_it_is_saved_alongside_the_errors_floor_without_disturbing_it(self):
        cfg = self._save({"nic_err_alert_min": 9, "nic_drop_alert_min": 300})
        self.assertEqual((cfg["nic_err_alert_min"], cfg["nic_drop_alert_min"]), (9, 300))

    def test_the_request_model_accepts_it(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {"nic_drop_alert_min": "500"})
        self.assertTrue(ok, err)
        ok, err = rm.validate(rm.ConfigSaveRequest, {"nic_drop_alert_min": 500})
        self.assertTrue(ok, err)


class TestFleetFloorsReader(unittest.TestCase):
    def test_junk_in_a_hand_edited_config_falls_back(self):
        d = api._NIC_ERR_ALERT_MIN
        for cfg, want in (({}, (d, None)),
                          ({"nic_drop_alert_min": ""}, (d, None)),
                          ({"nic_drop_alert_min": None}, (d, None)),
                          ({"nic_drop_alert_min": "x"}, (d, None)),
                          ({"nic_drop_alert_min": -3}, (d, None)),
                          ({"nic_drop_alert_min": 0.0}, (d, 0)),
                          ({"nic_drop_alert_min": "250"}, (d, 250)),
                          ({"nic_err_alert_min": 0}, (d, None)),
                          ({"nic_err_alert_min": "x"}, (d, None)),
                          ({"nic_err_alert_min": 12.0}, (12, None))):
            with self.subTest(cfg=cfg):
                self.assertEqual(api._nic_fleet_floors(cfg), want)


class TestGet(_SaveBase):
    def test_an_unconfigured_server_offers_a_blank_drop_floor(self):
        api.require_auth = lambda **k: "jakob"
        api.get_token_from_request = lambda: "tok"
        self._save({})
        try:
            api.handle_config_get()
        except api.HTTPError:
            pass
        body = self.cap.get("b") or {}
        self.assertEqual(body.get("nic_drop_alert_min"), "")
        self.assertEqual(body.get("nic_err_alert_min"), api._NIC_ERR_ALERT_MIN)


class TestPaneWiring(unittest.TestCase):
    def test_the_input_is_there_once_and_allows_zero(self):
        self.assertEqual(HTML.count('id="ap-nic-drop-min"'), 1)
        m = re.search(r'<input[^>]*id="ap-nic-drop-min"[^>]*>', HTML)
        self.assertIn('min="0"', m.group(0))

    def test_it_sits_in_the_network_and_time_section(self):
        i = HTML.index("Network &amp; time</div>")
        j = HTML.index('class="settings-section"', i)
        self.assertIn('id="ap-nic-drop-min"', HTML[i:j])

    def test_the_row_is_in_the_field_table_with_a_blank_default(self):
        self.assertRegex(APP, r"\['ap-nic-drop-min',\s+'nic_drop_alert_min',\s+''\]")

    def test_a_reset_button_on_a_blank_default_says_blank(self):
        self.assertIn("'Reset to default (blank)'", APP)

    def test_label_and_hint_are_translated_into_all_six_languages(self):
        hint = re.search(r'<p class="hint">(Errors and drops are added together[^<]*)</p>', HTML)
        self.assertTrue(hint, "the hint paragraph is missing")
        for key in ("NIC drop floor", hint.group(1)):
            with self.subTest(key=key[:30]):
                i = I18N.find('"%s"' % key)
                if i < 0:
                    i = I18N.find("'%s'" % key)
                self.assertGreater(i, 0, "no dictionary entry")
                entry = I18N[i:I18N.index("},", i)]
                for lang in LANGS:
                    self.assertRegex(entry, r"""["']?%s["']?\s*:""" % lang, "%s missing %s" % (key[:20], lang))

    def test_the_hint_does_not_claim_more_than_the_code_does(self):
        # "0 turns drop alerts off" and "a host can have its own floors" are both promises
        self.assertEqual(api._nic_fleet_floors({"nic_drop_alert_min": 0})[1], 0)
        self.assertEqual(
            api.checks_mod.nic_floors({"metric_thresholds": {"nic_drop_alert_min": 7}}, 5, None)[1], 7)


class TestThresholdPreviewModelsTheFloors(unittest.TestCase):
    """The preview re-runs the real Checks engine against the proposed value. Because the
    floors now ride the shared kwargs, setting a drop floor shows which hosts it would quiet."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("DEVICES_FILE", "CONFIG_FILE", "HARDWARE_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        now = int(time.time())
        nio = lambda e, d: [{"iface": "eth0", "errors_delta": e, "drops_delta": d, "err_delta": e + d}]  # noqa: E731
        api.save(api.DEVICES_FILE, {
            "media": {"name": "media01", "last_seen": now, "sysinfo": {"network_io": nio(0, 340)}},
            "cable": {"name": "cable01", "last_seen": now, "sysinfo": {"network_io": nio(9, 0)}},
            "quiet": {"name": "quiet01", "last_seen": now, "sysinfo": {"network_io": nio(0, 0)}},
        })
        api.save(api.CONFIG_FILE, {})
        for f in (api.DEVICES_FILE, api.CONFIG_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in ("respond", "method", "get_json_body", "require_admin_auth")}
        api.require_admin_auth = lambda: "jakob"
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def preview(self, body):
        api.get_json_body = lambda: body
        try:
            api.handle_threshold_preview()
        except api.HTTPError:
            pass
        return self.cap.get("b") or {}

    def test_a_drop_floor_would_quiet_the_media_server_and_leave_the_cable_alone(self):
        out = self.preview({"nic_drop_alert_min": 500})
        self.assertIn("nic_drop_alert_min", out.get("evaluated", []), out)
        self.assertNotIn("nic_drop_alert_min", out.get("not_evaluated", []))
        passing = {r["check"]: r for r in out.get("newly_passing", [])}
        self.assertIn("nic_errors", passing, out)
        self.assertEqual(passing["nic_errors"]["hosts"], 1)
        self.assertEqual(passing["nic_errors"]["examples"], ["media01"])
        self.assertEqual(out.get("newly_breaching"), [])

    def test_the_errors_floor_is_reported_as_not_assessed_not_as_safe(self):
        # The Checks row warns on any error; only the alert and the reliability score use this
        # floor, and the preview does not run those. It must say so rather than list it as
        # evaluated with no change.
        out = self.preview({"nic_err_alert_min": 50})
        self.assertIn("nic_err_alert_min", out.get("not_evaluated", []), out)
        self.assertNotIn("nic_err_alert_min", out.get("evaluated", []))


if __name__ == "__main__":
    unittest.main()
