#!/usr/bin/env python3
"""8.0.0: an administrator's default typeface, beside the default look, and both on the sign-in page.

The typeface was a per-account choice only (`ui_prefs.typeface`). The public demo wants B612 for everybody, including a visitor
who has not signed in yet, and an installation that wants one typeface should not have to set it account by account. So the
instance has a default (`brand_typeface`), kept like the default look (`brand_look`): one of the product's words or nothing,
read without case or padding, set by an administrator only, handed to the page by `/api/me` and, because the sign-in page has no
account, by the unauthenticated `/api/public-info`. A person's own choice still wins. There is no lock: a typeface is a reading
preference, and nobody should be made to read in one they cannot read.

The page's side (a first paint that matches, and the account beating the default) is in test_v800_brand_typeface_e2e.py.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v749_look_server import (  # noqa: E402
    REAL_REQUIRE_ADMIN_AUTH, REAL_REQUIRE_AUTH, ROOT, UNKNOWN_TO_CONFIG, _Base, api, request_models)


class TestInstanceDefaultTypeface(_Base):

    def test_the_default_is_kept_and_handed_back(self):
        status, body = self.call(api.handle_config_save, body={"brand_typeface": "b612"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.cfg()["brand_typeface"], "b612")
        status, body = self.call(api.handle_config_get, method="GET")
        self.assertEqual((status, body["brand_typeface"]), (200, "b612"))

    def test_the_system_font_can_be_the_default_too(self):
        self.call(api.handle_config_save, body={"brand_typeface": "system"})
        self.assertEqual(self.cfg()["brand_typeface"], "system")

    def test_an_unknown_typeface_clears_the_default(self):
        for bad in UNKNOWN_TO_CONFIG + ["comic sans", "b613", None, 5, ["b612"], {"a": 1}]:
            with self.subTest(bad=repr(bad)[:40]):
                self.call(api.handle_config_save, body={"brand_typeface": "b612"})
                self.call(api.handle_config_save, body={"brand_typeface": bad})
                self.assertEqual(self.cfg().get("brand_typeface"), "")

    def test_the_word_is_read_without_case_or_padding(self):
        self.call(api.handle_config_save, body={"brand_typeface": "  B612 "})
        self.assertEqual(self.cfg()["brand_typeface"], "b612")

    def test_a_save_that_does_not_name_it_leaves_it_alone(self):
        self.call(api.handle_config_save, body={"brand_typeface": "b612", "brand_look": "pilot"})
        self.call(api.handle_config_save, body={"brand_name": "Acme"})
        cfg = self.cfg()
        self.assertEqual((cfg["brand_typeface"], cfg["brand_look"], cfg["brand_name"]), ("b612", "pilot", "Acme"))

    def test_saving_the_look_does_not_touch_the_typeface(self):
        self.call(api.handle_config_save, body={"brand_typeface": "b612"})
        self.call(api.handle_config_save, body={"brand_look": "classic", "brand_look_locked": True})
        self.assertEqual(self.cfg()["brand_typeface"], "b612")

    def test_a_hand_edited_config_cannot_hand_out_a_bad_typeface(self):
        for bad in ("retro", ["b612"], 5, {"x": 1}, None, "B612"):
            with self.subTest(bad=repr(bad)):
                api.save(api.CONFIG_FILE, {"brand_typeface": bad})
                _s, body = self.call(api.handle_config_get, method="GET")
                self.assertEqual(body["brand_typeface"], "")
                _s, me = self.call(api.handle_me, method="GET")
                self.assertEqual(me["brand"]["typeface"], "")
                _s, info = self.call(api.handle_public_info, method="GET")
                self.assertEqual(info["typeface"], "")

    def test_only_an_administrator_can_set_it(self):
        api.require_admin_auth = REAL_REQUIRE_ADMIN_AUTH      # the real gate, not a stub of it
        api.require_auth = REAL_REQUIRE_AUTH
        self.user, self.role = "bob", "viewer"
        status, _body = self.call(api.handle_config_save, body={"brand_typeface": "b612"})
        self.assertEqual(status, 403)
        self.assertNotIn("brand_typeface", self.cfg())


class TestTheDefaultReachesThePage(_Base):

    def test_me_carries_it_beside_the_look(self):
        api.save(api.CONFIG_FILE, {"brand_name": "Acme", "brand_accent": "violet", "brand_look": "pilot", "brand_typeface": "b612"})
        status, me = self.call(api.handle_me, method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(me["brand"], {"name": "Acme", "accent": "violet", "look": "pilot", "look_locked": False, "typeface": "b612"})

    def test_no_default_means_none(self):
        _s, me = self.call(api.handle_me, method="GET")
        self.assertEqual(me["brand"]["typeface"], "")

    def test_a_tenant_does_not_brand_a_typeface(self):
        api.save(api.CONFIG_FILE, {"brand_typeface": "b612"})
        api.save(api.TENANTS_FILE, {"default": {"name": "d", "brand_name": "T", "brand_typeface": "system"}})
        _s, me = self.call(api.handle_me, method="GET")
        self.assertEqual(me["brand"]["typeface"], "b612", "like the look, the typeface is the instance's")

    def test_the_sign_in_page_is_told_before_anyone_has_signed_in(self):
        api.save(api.CONFIG_FILE, {"brand_look": "pilot", "brand_look_locked": True, "brand_typeface": "b612"})
        api.require_auth = lambda *a, **k: (_ for _ in ()).throw(AssertionError("public-info must not ask who is calling"))
        api.require_admin_auth = api.require_auth
        status, info = self.call(api.handle_public_info, method="GET")
        self.assertEqual(status, 200)
        self.assertEqual((info["look"], info["look_locked"], info["typeface"]), ("pilot", True, "b612"))

    def test_public_info_says_nothing_when_nothing_is_set(self):
        _s, info = self.call(api.handle_public_info, method="GET")
        self.assertEqual((info["look"], info["look_locked"], info["typeface"]), ("", False, ""))

    def test_a_lock_without_a_look_is_not_handed_out(self):
        api.save(api.CONFIG_FILE, {"brand_look_locked": True})
        _s, info = self.call(api.handle_public_info, method="GET")
        self.assertEqual((info["look"], info["look_locked"]), ("", False))

    def test_the_two_pages_hand_out_the_same_words_and_only_those(self):
        for look, face in (("pilot", "b612"), ("classic", "system"), ("", "")):
            api.save(api.CONFIG_FILE, {"brand_look": look, "brand_typeface": face})
            _s, me = self.call(api.handle_me, method="GET")
            _s, info = self.call(api.handle_public_info, method="GET")
            self.assertEqual((info["look"], info["typeface"]), (me["brand"]["look"], me["brand"]["typeface"]))
            self.assertLessEqual({info["look"], info["typeface"]}, {"", "pilot", "classic", "system", "b612"})

    def test_the_public_answer_still_holds_only_what_it_held_and_the_three_words(self):
        """The endpoint is open to the world. A new key is a decision, so the set of keys is pinned: the three taste fields are the
        whole difference from 7.5.0."""
        _s, info = self.call(api.handle_public_info, method="GET")
        self.assertEqual(sorted(info), sorted(["server_name", "server_version", "remember_me_default", "read_only", "oidc_enabled",
                                               "saml_enabled", "saml_unsolicited", "webauthn_enabled", "login_banner",
                                               "look", "look_locked", "typeface"]))


class TestTheRequestModel(unittest.TestCase):

    def test_the_field_exists_and_the_loose_coercer_covers_it(self):
        self.assertIn("brand_typeface", request_models.ConfigSaveRequest.model_fields)
        src = (ROOT / "server" / "cgi-bin" / "request_models.py").read_text()
        self.assertIn("'brand_name', 'brand_typeface'", src)

    def test_a_save_of_it_is_a_superset_pre_check(self):
        for body in ({"brand_typeface": "b612"}, {"brand_typeface": None}, {"brand_typeface": 5}, {"brand_typeface": ["x"]}, {}):
            ok, err = request_models.validate(request_models.ConfigSaveRequest, body)
            self.assertTrue(ok, (body, err))


if __name__ == "__main__":
    unittest.main()
