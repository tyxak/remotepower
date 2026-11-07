#!/usr/bin/env python3
"""8.0.0: which look and typeface the SIGN-IN page is drawn in, decided by the real functions of app.js run under node.

The instance's default look and typeface reach the sign-in page through /api/public-info, because nobody has signed in yet and
/api/me cannot be asked. The page already keeps a copy of the look and typeface it last drew, so that the first paint of the next
load matches. On a first visit that copy is not anybody's choice: the script wrote the fallback (Classic, the system font) when it
ran, a moment before the default arrived, and the copy then won the contest between the two. A browser test found it: the default
reached a signed-in page and never the sign-in page, which is the one a visitor of the demo sees first.

The order, in the two functions:

1. the administrator's lock beats everything (the look only: a typeface has no lock);
2. once the prefs have loaded, the account's choice decides, and then the default;
3. a page without a session is the sign-in page: the instance's default, if it has one, and not the browser's copy;
4. a page with a session, before its prefs are here: the browser's copy stands in, so the first paint matches. This is the line
   that has not moved since 7.4.9, and its tests (test_v749_look_client, test_v749_typeface_client) run with a session;
5. nothing known: the product's own default (Classic, the system font).

An instance with no default of its own is not affected by line 3: the sign-in page keeps using the browser's copy there, as before.
Every case below takes the functions from the source and runs them; a test that only read the text would pass over a reversed order.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v749_look_client import _APP, _JS, case, _run as run_look  # noqa: E402
from test_v749_typeface_client import _run as run_face  # noqa: E402
import srcpin  # noqa: E402

_NODE = shutil.which("node")
_CALENDAR = (_JS / "app-calendar.js").read_text()


def look(**kw):
    return run_look([case(**kw)])[0]["look"]


def face(**kw):
    return run_face([kw])[0]["face"]


@unittest.skipUnless(_NODE, "node not installed")
class TestTheSignInPageLook(unittest.TestCase):

    def test_a_first_visit_gets_the_default_not_the_fallback_the_script_wrote_a_moment_before(self):
        # the state a first visit is in when the answer arrives: the boot call has already stored Classic as "the last look drawn"
        self.assertEqual(look(signedout=True, brand="pilot", copy="classic"), "pilot")

    def test_with_no_copy_at_all_it_is_the_default_too(self):
        self.assertEqual(look(signedout=True, brand="pilot"), "pilot")
        self.assertEqual(look(signedout=True, brand="classic", copy="pilot"), "classic")

    def test_an_instance_without_a_default_keeps_using_the_browsers_copy_on_the_sign_in_page(self):
        self.assertEqual(look(signedout=True, copy="pilot"), "pilot")
        self.assertEqual(look(signedout=True, copy="classic"), "classic")
        self.assertEqual(look(signedout=True), "classic")

    def test_a_page_with_a_session_still_lets_the_copy_stand_in_until_its_prefs_are_here(self):
        # a person who chose Classic on an instance whose default is Pilot must not see Pilot flash on every reload
        self.assertEqual(look(brand="pilot", copy="classic"), "classic")
        self.assertEqual(look(brand="pilot", copy="pilot"), "pilot")

    def test_the_prefs_decide_once_they_have_loaded_whatever_the_session_says(self):
        for signedout in (False, True):
            with self.subTest(signedout=signedout):
                self.assertEqual(look(signedout=signedout, loaded=True, brand="pilot", prefs={"look": "classic"}), "classic")
                self.assertEqual(look(signedout=signedout, loaded=True, brand="pilot"), "pilot")
                self.assertEqual(look(signedout=signedout, loaded=True, brand="pilot", copy="classic"), "pilot")

    def test_a_lock_is_the_default_on_the_sign_in_page_too(self):
        self.assertEqual(look(signedout=True, brand="pilot", locked=True, copy="classic"), "pilot")

    def test_a_word_the_page_does_not_know_is_no_default(self):
        for bad in ("retro", "PILOT", None, 5, ["pilot"], {"a": 1}):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(look(signedout=True, brand=bad, copy="pilot"), "pilot")
                self.assertEqual(look(signedout=True, brand=bad), "classic")

    def test_the_palette_follows_the_look_it_is_given(self):
        r = run_look([case(signedout=True, brand="pilot", copy="classic")])[0]
        self.assertEqual((r["look"], r["dark"], r["light"]), ("pilot", "pilot", "pilot-paper"))


@unittest.skipUnless(_NODE, "node not installed")
class TestTheSignInPageTypeface(unittest.TestCase):

    def test_a_first_visit_gets_the_default_not_the_fallback_the_script_wrote_a_moment_before(self):
        self.assertEqual(face(signedout=True, brand="b612", copy="system"), "b612")
        self.assertEqual(face(signedout=True, brand="b612"), "b612")

    def test_an_instance_that_names_the_system_font_gets_it_over_a_stale_copy(self):
        self.assertEqual(face(signedout=True, brand="system", copy="b612"), "system")

    def test_an_instance_without_a_default_keeps_using_the_browsers_copy_on_the_sign_in_page(self):
        self.assertEqual(face(signedout=True, copy="b612"), "b612")
        self.assertEqual(face(signedout=True, copy="system"), "system")
        self.assertEqual(face(signedout=True), "system")

    def test_a_page_with_a_session_still_lets_the_copy_stand_in_until_its_prefs_are_here(self):
        self.assertEqual(face(brand="b612", copy="system"), "system")
        self.assertEqual(face(brand="system", copy="b612"), "b612")

    def test_once_the_prefs_have_loaded_the_account_then_the_default_decide(self):
        for signedout in (False, True):
            with self.subTest(signedout=signedout):
                self.assertEqual(face(signedout=signedout, loaded=True, brand="b612"), "b612")
                self.assertEqual(face(signedout=signedout, loaded=True, brand="b612", prefs={"typeface": "system"}), "system")
                self.assertEqual(face(signedout=signedout, loaded=True, brand="system", prefs={"typeface": "b612"}), "b612")
                self.assertEqual(face(signedout=signedout, loaded=True, brand="b612", copy="system"), "b612")

    def test_a_word_the_page_does_not_know_is_no_default(self):
        for bad in ("Inter", "B612", "system ", "", None, 5, ["b612"], {"a": 1}):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(face(signedout=True, brand=bad, copy="b612"), "b612")
                self.assertEqual(face(signedout=True, brand=bad), "system")

    def test_drawing_it_sets_the_attribute_and_keeps_a_copy(self):
        r = run_face([dict(signedout=True, brand="b612", copy="system", apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), ("b612", "b612"))
        r = run_face([dict(signedout=True, brand="system", copy="b612", apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), (None, "system"))


class TestTheSessionTest(unittest.TestCase):
    """What _hasSession reads, and that both choice functions use the one helper (a second copy of the rule is how the sixth site is
    missed)."""

    def test_it_asks_for_the_token_and_a_blocked_store_is_no_session(self):
        body = srcpin.js_function(_APP, "_hasSession")
        self.assertIn("getToken()", body)
        self.assertRegex(body, r"catch \(_\) \{ return false; \}")

    def test_both_choice_functions_use_it_after_the_prefs_branch_and_before_the_copy(self):
        for name, copy_key in (("_lookChoice", "rp_look"), ("_typefaceChoice", "rp_typeface")):
            body = srcpin.js_function(_APP, name)
            self.assertEqual(body.count("_hasSession()"), 1, name)
            self.assertLess(body.index("_uiPrefsLoaded"), body.index("_hasSession()"), name)
            self.assertLess(body.index("_hasSession()"), body.index(copy_key), name)

    def test_the_helper_and_the_token_reader_are_function_declarations(self):
        # the boot call at the bottom of app.js runs both choice functions as the script loads: a declaration is hoisted, so the
        # helper is there however far up or down it sits, and it reads nothing that a later `const` has yet to define
        self.assertIn("\nfunction getToken()", _APP)
        self.assertIn("\nfunction _hasSession()", _APP)
        self.assertNotRegex(srcpin.js_function(_APP, "getToken"), r"\b(?:const|let)\b")
        self.assertIn("\ntry { applyLook(); applyTheme(); } catch (_) {}\n", _APP)    # the boot call this protects


def _const(name):
    m = re.search(r"^const %s = (.+?);\s*$" % re.escape(name), _APP, re.M)
    assert m, name
    return m.group(0)


def _public_info_script(cases):
    """loadPublicInfo as it is in app-calendar.js, with the page's own choice functions, around a stub of the page and the network."""
    src = [_const("LOOKS"), _const("FX_LEVELS"), _const("LOOK_DEFAULT"), _const("TYPEFACES"), _const("TYPEFACE_DEFAULT")]
    src += [srcpin.js_function(_APP, f) for f in ("_hasSession", "_lookChoice", "_fxChoice", "applyLook", "_typefaceChoice", "applyTypeface")]
    src.append("async " + srcpin.js_function(_CALENDAR, "loadPublicInfo"))      # srcpin returns the text from `function`
    return (
        "const store = new Map();\n"
        "const localStorage = { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) };\n"
        "const revealed = [];\n"
        "const button = id => ({ classList: { remove: c => revealed.push(id) }, style: {} });\n"
        "const els = {};\n"
        "const document = { title: '', body: { dataset: {} }, querySelector: () => null, getElementById: id => els[id] || null };\n"
        "const window = {}; let session = true; let _uiPrefs = {}; let _uiPrefsLoaded = false; let _readOnlyMode = false;\n"
        "let moved = 0, themed = 0, themeThrows = false, info = {}, down = false, notOk = false;\n"
        "function getToken() { return session ? 'token' : ''; }\n"
        "function _lookChanged() { moved += 1; }\n"
        "function applyTheme() { themed += 1; if (themeThrows) throw new Error('boom'); }\n"
        "async function fetch() { if (down) throw new Error('down'); return { ok: !notOk, json: async () => info }; }\n"
        + "\n".join(src)
        + "\nconst cases = " + json.dumps(cases) + ";\n"
        "(async () => {\n"
        "  const out = [];\n"
        "  for (const c of cases) {\n"
        "    store.clear(); document.body.dataset = {}; revealed.length = 0; moved = 0; themed = 0;\n"
        "    for (const k of Object.keys(window)) delete window[k];\n"
        "    els['login-oidc-btn'] = button('oidc'); els['login-passkey-btn'] = button('passkey'); els['login-saml-btn'] = button('saml');\n"
        "    info = c.info || {}; session = !c.signedout; _uiPrefs = c.prefs || {}; _uiPrefsLoaded = !!c.loaded;\n"
        "    themeThrows = !!c.themeThrows; down = !!c.down; notOk = !!c.notOk;\n"
        "    if (c.copy !== undefined) store.set('rp_look', c.copy);\n"
        "    if (c.fcopy !== undefined) store.set('rp_typeface', c.fcopy);\n"
        "    if (c.booted) { applyLook(); applyTypeface(); }          // the calls the script makes as it loads, before the answer\n"
        "    await loadPublicInfo();\n"
        "    out.push({ look: document.body.dataset.look || null, face: document.body.dataset.typeface || null,\n"
        "               brandLook: window._brandLook, locked: window._brandLookLocked, brandFace: window._brandTypeface,\n"
        "               moved, themed, revealed: revealed.slice().sort(), copy: [store.get('rp_look') || null, store.get('rp_typeface') || null] });\n"
        "  }\n"
        "  console.log(JSON.stringify(out));\n"
        "})();\n"
    )


def _public_info(cases):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "public-info.js"
        path.write_text(_public_info_script(cases))
        proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


PILOT = {"look": "pilot", "look_locked": False, "typeface": "b612"}


@unittest.skipUnless(_NODE, "node not installed")
class TestWhatTheSignInPageDoesWithTheAnswer(unittest.TestCase):
    """loadPublicInfo itself, run with the choice functions it calls: what is on the page afterwards."""

    def one(self, **kw):
        return _public_info([kw])[0]

    def test_a_first_visit_is_drawn_in_the_default(self):
        r = self.one(info=PILOT, signedout=True, booted=True)
        self.assertEqual((r["look"], r["face"]), ("pilot", "b612"))
        self.assertEqual((r["brandLook"], r["locked"], r["brandFace"]), ("pilot", False, "b612"))
        self.assertEqual(r["copy"], ["pilot", "b612"], "the next visit starts from what this one drew")
        self.assertEqual((r["moved"], r["themed"]), (0, 1), "nobody is signed in: the palette follows, Home is not redrawn")

    def test_a_lock_is_taken_only_together_with_a_look(self):
        r = self.one(info={"look": "pilot", "look_locked": True, "typeface": ""}, signedout=True)
        self.assertEqual((r["brandLook"], r["locked"]), ("pilot", True))
        r = self.one(info={"look": "", "look_locked": True, "typeface": ""}, signedout=True)
        self.assertEqual((r["brandLook"], r["locked"]), ("", False))

    def test_a_word_the_page_does_not_know_is_not_taken(self):
        for bad in ("retro", "PILOT", None, 5, ["pilot"], {"a": 1}):
            with self.subTest(bad=repr(bad)):
                r = self.one(info={"look": bad, "look_locked": False, "typeface": bad}, signedout=True, booted=True)
                self.assertEqual((r["brandLook"], r["brandFace"], r["look"], r["face"]), ("", "", "classic", None))

    def test_an_answer_with_none_of_the_words_changes_nothing_from_before(self):
        r = self.one(info={"server_name": "RemotePower"}, signedout=True, booted=True, copy="pilot", fcopy="b612")
        self.assertEqual((r["look"], r["face"]), ("pilot", "b612"), "an older server: the browser's copy stands")

    def test_a_look_that_moves_while_signed_in_is_redrawn_the_way_the_brand_does_it(self):
        # the prefs have loaded (an account with no choice), /api/public-info answers last and moves the look: Home must be redrawn
        r = self.one(info=PILOT, loaded=True, booted=True)
        self.assertEqual((r["look"], r["moved"], r["themed"]), ("pilot", 1, 0))
        # the look did not move: only the palette is looked at again
        r = self.one(info=PILOT, loaded=True, booted=True, prefs={"look": "pilot"})
        self.assertEqual((r["moved"], r["themed"]), (0, 1))

    def test_the_account_still_beats_the_default_once_its_prefs_are_here(self):
        r = self.one(info=PILOT, loaded=True, prefs={"look": "classic", "typeface": "system"}, booted=True)
        self.assertEqual((r["look"], r["face"]), ("classic", None))

    def test_a_signed_in_reload_keeps_the_copy_until_the_prefs_are_here(self):
        r = self.one(info=PILOT, copy="classic", fcopy="system", booted=True)
        self.assertEqual((r["look"], r["face"]), ("classic", None))

    def test_the_sign_in_buttons_are_shown_whatever_the_look_code_does(self):
        everything = {"look": "pilot", "look_locked": False, "typeface": "b612", "oidc_enabled": True, "saml_enabled": True,
                      "webauthn_enabled": True}
        r = self.one(info=everything, signedout=True, themeThrows=True)
        self.assertEqual(r["revealed"], ["oidc", "passkey", "saml"], "a failing palette took the sign-in buttons with it")
        self.assertEqual(self.one(info=everything, signedout=True)["revealed"], ["oidc", "passkey", "saml"])

    def test_an_endpoint_that_cannot_be_reached_leaves_the_page_as_it_was(self):
        for kw in ({"down": True}, {"notOk": True}):
            with self.subTest(kw=kw):
                r = self.one(info=PILOT, signedout=True, booted=True, **kw)
                # the globals were never set: JSON leaves an undefined value out, so they are read with .get
                self.assertEqual((r["look"], r["face"], r.get("brandLook"), r.get("brandFace")), ("classic", None, None, None))


if __name__ == "__main__":
    unittest.main()
