#!/usr/bin/env python3
"""7.4.9: the typeface (the system font or B612) as the server stores it.

A typeface is a reading preference, like the look: it lives in the account's `ui_prefs`, so a change on one browser reaches the
others. The server's part is small and has one job, the same as for the look: the client posts the whole prefs document on every
save, so `_sanitise_ui_prefs` keeps `typeface` only when it is one of the known words, and drops anything else without costing the
other prefs. It has no instance default and no lock: a font is not branding, and `/api/me` hands the page no typeface.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v749_look_server import BAD_KINDS, BAD_WORDS, _Base, api  # noqa: E402

# what a client could send for a typeface other than the words the product knows: the other vendored faces, the display names,
# a stack, and things that would be dangerous if they ever reached a style or a URL
TYPEFACE_BAD_WORDS = ["B612", "Inter", "inter", "jetbrains-mono", "JetBrains Mono", "b612 ", " b612", "b612\n", "b-612", "cockpit",
                      "SYSTEM", "System", "sans-serif", "monospace", "serif", "url(x)", "b612;color:red", "'><script>1</script>"]


class TestUiPrefsKeepTheTypeface(_Base):

    def test_the_words_the_product_knows_are_kept(self):
        for face in api.UI_TYPEFACES:
            self.assertEqual(api._sanitise_ui_prefs({"typeface": face}), {"typeface": face})

    def test_the_list_holds_what_the_ui_offers(self):
        # the system font first: it is the default, and B612 is an option
        self.assertEqual(api.UI_TYPEFACES, ("system", "b612"))

    def test_anything_else_is_dropped(self):
        for bad in BAD_WORDS + BAD_KINDS + TYPEFACE_BAD_WORDS:
            with self.subTest(bad=repr(bad)[:40]):
                self.assertEqual(api._sanitise_ui_prefs({"typeface": bad}), {})

    def test_a_bad_typeface_does_not_cost_the_other_prefs(self):
        clean = api._sanitise_ui_prefs({"typeface": "comic", "look": "pilot", "effects": "reduced", "temp_unit": "f", "team": "NOC"})
        self.assertEqual(clean, {"look": "pilot", "effects": "reduced", "temp_unit": "f", "team": "NOC"})

    def test_a_bad_look_does_not_cost_the_typeface(self):
        self.assertEqual(api._sanitise_ui_prefs({"typeface": "b612", "look": "retro", "effects": 3}), {"typeface": "b612"})

    def test_it_travels_with_the_look_and_the_effects(self):
        doc = {"look": "pilot", "effects": "reduced", "typeface": "b612"}
        self.assertEqual(api._sanitise_ui_prefs(doc), doc)

    def test_a_non_object_is_an_empty_document(self):
        for raw in (None, [], "b612", 5, ["typeface"]):
            self.assertEqual(api._sanitise_ui_prefs(raw), {})

    def test_the_account_keeps_it_through_the_real_handler(self):
        status, body = self.call(api.handle_ui_prefs_set, body={"typeface": "b612", "temp_unit": "c"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.prefs(), {"typeface": "b612", "temp_unit": "c"})
        status, body = self.call(api.handle_ui_prefs_get, method="GET")
        self.assertEqual((status, body["typeface"]), (200, "b612"))

    def test_a_bad_value_never_reaches_the_store(self):
        status, _body = self.call(api.handle_ui_prefs_set, body={"typeface": "b612;color:red", "temp_unit": "f"})
        self.assertEqual(status, 200)
        self.assertEqual(self.prefs(), {"temp_unit": "f"})

    def test_a_save_without_it_removes_it(self):
        # whole-document replacement is the contract: the client always sends its copy, so a missing key means "unset"
        self.call(api.handle_ui_prefs_set, body={"typeface": "b612"})
        self.call(api.handle_ui_prefs_set, body={"temp_unit": "f"})
        self.assertEqual(self.prefs(), {"temp_unit": "f"})

    def test_each_account_has_its_own(self):
        self.call(api.handle_ui_prefs_set, body={"typeface": "system"})
        self.user = "bob"
        self.call(api.handle_ui_prefs_set, body={"typeface": "b612"})
        users = api.load(api.USERS_FILE)
        self.assertEqual(users["jakob"]["ui_prefs"]["typeface"], "system")
        self.assertEqual(users["bob"]["ui_prefs"]["typeface"], "b612")

    def test_a_viewer_can_set_their_own(self):
        self.user, self.role = "bob", "viewer"
        status, _body = self.call(api.handle_ui_prefs_set, body={"typeface": "b612"})
        self.assertEqual(status, 200)
        self.assertEqual(api.load(api.USERS_FILE)["bob"]["ui_prefs"]["typeface"], "b612")


class TestTheTypefaceIsNotBranding(_Base):
    """A font is a reading preference: there is no instance default and no lock, so the page is told neither."""

    def test_me_carries_no_typeface(self):
        status, body = self.call(api.handle_me, method="GET")
        self.assertEqual(status, 200, body)
        self.assertEqual(sorted(body["brand"]), ["accent", "look", "look_locked", "name"])

    def test_a_config_save_does_not_keep_one(self):
        status, _body = self.call(api.handle_config_save, body={"brand_typeface": "b612", "brand_typeface_locked": True})
        self.assertEqual(status, 200)
        stored = self.cfg()
        self.assertNotIn("brand_typeface", stored)
        self.assertNotIn("brand_typeface_locked", stored)


class TestTheLookIsUnchanged(_Base):
    """The three words travel in one document; adding one must not have moved the other two."""

    def test_the_look_and_the_effects_still_have_their_words(self):
        self.assertEqual(api.UI_LOOKS, ("classic", "pilot"))
        self.assertEqual(api.UI_EFFECTS, ("full", "reduced"))

    def test_the_typeface_does_not_stand_in_for_them(self):
        for key in ("look", "effects"):
            for face in api.UI_TYPEFACES:
                self.assertNotIn(key, api._sanitise_ui_prefs({key: face}), (key, face))


if __name__ == "__main__":
    unittest.main()
