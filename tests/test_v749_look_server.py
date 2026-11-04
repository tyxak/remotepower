#!/usr/bin/env python3
"""7.4.9: the interface look (Pilot or Classic) and its effects, as the server stores and hands them out.

A look is taste, not data. It lives in the account's `ui_prefs` (so a change on one browser reaches the others), with an optional
instance default and a lock under Branding for operators who want one look for everybody. The server holds three things:

* `_sanitise_ui_prefs` keeps `look` and `effects` only when they are one of the known words. The client posts the whole prefs
  document on every save, so anything else has to be dropped here, and it has to be dropped without costing the other prefs.
* `handle_config_save` / `handle_config_get` carry the default (`brand_look`) and the lock (`brand_look_locked`). Only an
  administrator can set them, an unknown look clears the default, and a lock without a look reads as unlocked.
* `handle_me` hands the default and the lock to the page, which applies them before anything is drawn.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v622_alert_params import ROOT, api  # noqa: E402

sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import request_models  # noqa: E402

# the real gates, taken before any test runs: other modules stub these on the shared module and some never put them back, and a
# test that "restores the original" from the module at setUp time restores their stub
REAL_REQUIRE_AUTH = api.require_auth
REAL_REQUIRE_ADMIN_AUTH = api.require_admin_auth

FILES = ("USERS_FILE", "CONFIG_FILE", "TENANTS_FILE", "AUDIT_LOG_FILE", "TOKENS_FILE")
STUBS = ("require_auth", "require_admin_auth", "verify_token", "get_token_from_request", "audit_log", "respond", "method",
         "get_json_body")

# what a client could send for a look or for effects, other than the words the product knows
BAD_WORDS = ["", " ", "PILOT", "Classic", " pilot", "pilot ", "pilot\n", "industrial", "new", "old", "none", "null", "0", "false",
             "x" * 5000]
BAD_KINDS = [None, True, False, 0, 1, 2.5, [], ["pilot"], {}, {"look": "pilot"}, ("pilot",)]
# the instance default is typed by an administrator and read without case or padding, like the default accent; these are
# the words that stay unknown after that
UNKNOWN_TO_CONFIG = ["", " ", "industrial", "new", "old", "none", "null", "0", "false", "x" * 5000]


class _Base(unittest.TestCase):
    """Drive the real handlers with stubbed auth and transport, on a throwaway store named after the key it replaces."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {n: getattr(api, n) for n in FILES}
        for n, old in self._files.items():
            setattr(api, n, self.d / Path(old).name)
        self._stubs = {n: getattr(api, n) for n in STUBS}
        self.cap = {}
        self.body = {}
        self.user, self.role = "jakob", "admin"
        api.require_auth = lambda require_admin=False: self.user
        api.require_admin_auth = lambda: self.user
        api.verify_token = lambda t: (self.user, self.role)
        api.get_token_from_request = lambda: "t"
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"
        api.get_json_body = lambda: self.body
        api._begin_request()

        def _resp(status, body=None):
            self.cap["s"], self.cap["b"] = status, body
            raise api.HTTPError(status, body)

        api.respond = _resp
        api.save(api.USERS_FILE, {"jakob": {"role": "admin", "created": 1}, "bob": {"role": "viewer", "created": 1}})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for n, v in self._stubs.items():
            setattr(api, n, v)
        for n, v in self._files.items():
            setattr(api, n, v)

    def call(self, fn, method="POST", body=None):
        self.cap = {}
        api.method = lambda: method
        self.body = {} if body is None else body
        try:
            fn()
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")

    def prefs(self):
        return (api.load(api.USERS_FILE) or {}).get("jakob", {}).get("ui_prefs", {})

    def cfg(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}


class TestUiPrefsKeepTheLook(_Base):

    def test_the_words_the_product_knows_are_kept(self):
        for look in api.UI_LOOKS:
            for effects in api.UI_EFFECTS:
                self.assertEqual(api._sanitise_ui_prefs({"look": look, "effects": effects}), {"look": look, "effects": effects})

    def test_the_two_lists_hold_what_the_ui_offers(self):
        self.assertEqual(api.UI_LOOKS, ("pilot", "classic"))
        self.assertEqual(api.UI_EFFECTS, ("full", "reduced"))

    def test_anything_else_is_dropped(self):
        for bad in BAD_WORDS + BAD_KINDS:
            with self.subTest(bad=repr(bad)[:40]):
                self.assertEqual(api._sanitise_ui_prefs({"look": bad, "effects": bad}), {})

    def test_a_bad_look_does_not_cost_the_other_prefs(self):
        clean = api._sanitise_ui_prefs({"look": "retro", "effects": "full", "temp_unit": "f", "team": "NOC"})
        self.assertEqual(clean, {"effects": "full", "temp_unit": "f", "team": "NOC"})

    def test_a_non_object_is_an_empty_document(self):
        for raw in (None, [], "pilot", 5, ["look"]):
            self.assertEqual(api._sanitise_ui_prefs(raw), {})

    def test_the_account_keeps_it_through_the_real_handler(self):
        status, body = self.call(api.handle_ui_prefs_set, body={"look": "classic", "effects": "reduced", "temp_unit": "c"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.prefs(), {"look": "classic", "effects": "reduced", "temp_unit": "c"})
        status, body = self.call(api.handle_ui_prefs_get, method="GET")
        self.assertEqual((status, body["look"], body["effects"]), (200, "classic", "reduced"))

    def test_a_save_without_the_look_removes_it(self):
        # whole-document replacement is the contract: the client always sends its copy, so a missing key means "unset"
        self.call(api.handle_ui_prefs_set, body={"look": "classic"})
        self.call(api.handle_ui_prefs_set, body={"temp_unit": "f"})
        self.assertEqual(self.prefs(), {"temp_unit": "f"})

    def test_each_account_has_its_own(self):
        self.call(api.handle_ui_prefs_set, body={"look": "classic"})
        self.user = "bob"
        self.call(api.handle_ui_prefs_set, body={"look": "pilot"})
        users = api.load(api.USERS_FILE)
        self.assertEqual(users["jakob"]["ui_prefs"]["look"], "classic")
        self.assertEqual(users["bob"]["ui_prefs"]["look"], "pilot")

    def test_a_viewer_can_set_their_own(self):
        self.user, self.role = "bob", "viewer"
        status, _body = self.call(api.handle_ui_prefs_set, body={"look": "classic"})
        self.assertEqual(status, 200)
        self.assertEqual(api.load(api.USERS_FILE)["bob"]["ui_prefs"]["look"], "classic")


class TestInstanceDefaultLook(_Base):

    def test_the_default_and_the_lock_are_kept(self):
        status, body = self.call(api.handle_config_save, body={"brand_look": "classic", "brand_look_locked": True})
        self.assertEqual(status, 200, body)
        cfg = self.cfg()
        self.assertEqual((cfg["brand_look"], cfg["brand_look_locked"]), ("classic", True))
        status, body = self.call(api.handle_config_get, method="GET")
        self.assertEqual((status, body["brand_look"], body["brand_look_locked"]), (200, "classic", True))

    def test_an_unknown_look_clears_the_default(self):
        self.call(api.handle_config_save, body={"brand_look": "classic"})
        for bad in UNKNOWN_TO_CONFIG + [None, 5, ["classic"], {"a": 1}]:
            with self.subTest(bad=repr(bad)[:40]):
                self.call(api.handle_config_save, body={"brand_look": "classic"})
                self.call(api.handle_config_save, body={"brand_look": bad})
                self.assertEqual(self.cfg().get("brand_look"), "")

    def test_the_word_is_read_without_case_or_padding(self):
        self.call(api.handle_config_save, body={"brand_look": "  PILOT "})
        self.assertEqual(self.cfg()["brand_look"], "pilot")

    def test_only_a_real_true_sets_the_lock(self):
        for value, locked in ((True, True), (False, False), ("true", False), ("yes", False), (1, False), ("", False), (None, False)):
            with self.subTest(value=repr(value)):
                self.call(api.handle_config_save, body={"brand_look": "pilot", "brand_look_locked": True})
                self.call(api.handle_config_save, body={"brand_look_locked": value})
                self.assertIs(self.cfg()["brand_look_locked"], locked)

    def test_a_save_that_does_not_name_them_leaves_them_alone(self):
        self.call(api.handle_config_save, body={"brand_look": "classic", "brand_look_locked": True})
        self.call(api.handle_config_save, body={"brand_name": "Acme"})
        cfg = self.cfg()
        self.assertEqual((cfg["brand_look"], cfg["brand_look_locked"], cfg["brand_name"]), ("classic", True, "Acme"))

    def test_a_lock_without_a_look_reads_as_unlocked(self):
        api.save(api.CONFIG_FILE, {"brand_look_locked": True})
        status, body = self.call(api.handle_config_get, method="GET")
        self.assertEqual((status, body["brand_look"], body["brand_look_locked"]), (200, "", False))
        status, me = self.call(api.handle_me, method="GET")
        self.assertEqual((me["brand"]["look"], me["brand"]["look_locked"]), ("", False))

    def test_a_hand_edited_config_cannot_hand_out_a_bad_look(self):
        for bad in ("retro", ["classic"], 5, {"x": 1}, None):
            with self.subTest(bad=repr(bad)):
                api.save(api.CONFIG_FILE, {"brand_look": bad, "brand_look_locked": True})
                _s, body = self.call(api.handle_config_get, method="GET")
                self.assertEqual((body["brand_look"], body["brand_look_locked"]), ("", False))
                _s, me = self.call(api.handle_me, method="GET")
                self.assertEqual((me["brand"]["look"], me["brand"]["look_locked"]), ("", False))

    def test_only_an_administrator_can_set_it(self):
        # the real gate, not a stub of it: only verify_token answers, and it says this caller is a viewer
        api.require_admin_auth = REAL_REQUIRE_ADMIN_AUTH
        api.require_auth = REAL_REQUIRE_AUTH
        self.user, self.role = "bob", "viewer"
        status, _body = self.call(api.handle_config_save, body={"brand_look": "classic", "brand_look_locked": True})
        self.assertEqual(status, 403)
        self.assertNotIn("brand_look", self.cfg())
        self.assertNotIn("brand_look_locked", self.cfg())


class TestMeCarriesTheDefault(_Base):

    def test_the_page_is_told_the_default_and_the_lock(self):
        api.save(api.CONFIG_FILE, {"brand_name": "Acme", "brand_accent": "violet", "brand_look": "classic", "brand_look_locked": True})
        status, me = self.call(api.handle_me, method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(me["brand"], {"name": "Acme", "accent": "violet", "look": "classic", "look_locked": True})

    def test_no_default_means_none(self):
        _s, me = self.call(api.handle_me, method="GET")
        self.assertEqual((me["brand"]["look"], me["brand"]["look_locked"]), ("", False))

    def test_a_tenant_brands_a_name_and_an_accent_not_a_layout(self):
        api.save(api.CONFIG_FILE, {"brand_look": "classic"})
        api.save(api.TENANTS_FILE, {"default": {"name": "d", "brand_name": "T", "brand_accent": "rose", "brand_look": "pilot"}})
        _s, me = self.call(api.handle_me, method="GET")
        self.assertEqual((me["brand"]["name"], me["brand"]["accent"], me["brand"]["look"]), ("T", "rose", "classic"))


class TestTheRequestModel(unittest.TestCase):

    def test_the_model_is_a_superset_pre_check(self):
        # the cardinal rule of request_models: it may reject a malformed body, never one the handler accepts
        for body in ({}, {"brand_look": "classic", "brand_look_locked": True}, {"brand_look": 5, "brand_look_locked": "yes"},
                     {"brand_look": None, "brand_look_locked": None}, {"brand_look": ["x"], "brand_look_locked": []}):
            with self.subTest(body=body):
                ok, err = request_models.validate(request_models.ConfigSaveRequest, body)
                self.assertTrue(ok, err)

    def test_the_fields_exist_and_are_covered_by_the_loose_coercers(self):
        fields = request_models.ConfigSaveRequest.model_fields
        self.assertIn("brand_look", fields)
        self.assertIn("brand_look_locked", fields)
        src = (ROOT / "server" / "cgi-bin" / "request_models.py").read_text()
        self.assertIn("'brand_look', 'brand_name'", src)
        self.assertIn("'brand_look_locked', 'brute_force_enabled'", src)


if __name__ == "__main__":
    unittest.main()
