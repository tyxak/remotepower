#!/usr/bin/env python3
"""7.4.9: which look the page draws, decided by the real functions of app.js run under node.

The look (Pilot or Classic) is a per-account preference that an administrator can default and lock. Four places hold a value for it
and they must agree on an order, because getting the order wrong shows one person another person's look or shows the wrong look for
the length of a request:

1. the administrator's lock beats everything (a lock without a default is nothing);
2. once the prefs have loaded, the account's choice decides, and the browser's copy is ignored: the copy may belong to the person
   who used this browser before;
3. before the prefs have loaded, the browser's copy stands in, so the first paint matches;
4. with no choice at all, the administrator's default, and without one Classic: Pilot is an option, never the default.

Anything that is not one of the known words is ignored at every step. The palette a browser uses when it has chosen none follows the
look (Pilot has its own pair, Classic keeps Midnight and Daylight).

The functions are taken from the source and run; a test that only read the text would pass over a reversed order.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which("node")
_APP = (_JS / "app.js").read_text()
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()
_I18N = (_JS / "i18n.js").read_text()

FUNCS = ("_lookChoice", "_fxChoice", "applyLook", "_defaultTheme")


def _const(name):
    m = re.search(r"^const %s = (.+?);\s*$" % re.escape(name), _APP, re.M)
    assert m, name
    return m.group(0)


def _script(cases):
    src = [_const("LOOKS"), _const("FX_LEVELS"), _const("LOOK_DEFAULT")]
    src += [srcpin.js_function(_APP, f) for f in FUNCS]
    return (
        "const store = new Map();\n"
        "const localStorage = { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) };\n"
        "const document = { body: { dataset: {} } };\n"
        "const window = {};\n"
        "let _uiPrefs = {}; let _uiPrefsLoaded = false;\n"
        + "\n".join(src)
        + "\nconst cases = " + json.dumps(cases) + ";\n"
        "const out = cases.map(c => {\n"
        "  store.clear(); document.body.dataset = {};\n"
        "  window._brandLook = c.brand; window._brandLookLocked = !!c.locked;\n"
        "  _uiPrefs = c.prefs || {}; _uiPrefsLoaded = !!c.loaded;\n"
        "  if (c.copy !== undefined) store.set('rp_look', c.copy);\n"
        "  if (c.fxcopy !== undefined) store.set('rp_fx', c.fxcopy);\n"
        "  const r = { look: _lookChoice(), fx: _fxChoice(), dark: _defaultTheme(false), light: _defaultTheme(true) };\n"
        "  if (c.apply) { r.changed = applyLook(); r.attr = document.body.dataset.look; r.fxattr = document.body.dataset.fx || null;\n"
        "                 r.copy = store.get('rp_look'); r.fxcopy = store.get('rp_fx'); r.again = applyLook();\n"
        "                 if (c.then) { _uiPrefs = c.then; r.changed2 = applyLook(); r.attr2 = document.body.dataset.look;\n"
        "                               r.fxattr2 = document.body.dataset.fx || null; } }\n"
        "  return r;\n"
        "});\n"
        "console.log(JSON.stringify(out));\n"
    )


def _run(cases):
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "look.js"
        path.write_text(_script(cases))
        proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def case(**kw):
    kw.setdefault("brand", "")
    return kw


@unittest.skipUnless(_NODE, "node not installed")
class TestWhichLookIsDrawn(unittest.TestCase):

    def look(self, **kw):
        return _run([case(**kw)])[0]["look"]

    def test_the_default_is_classic_and_pilot_is_an_option(self):
        self.assertEqual(self.look(), "classic")
        self.assertEqual(self.look(loaded=True), "classic")
        self.assertEqual(self.look(loaded=True, prefs={}), "classic")

    def test_before_the_prefs_load_the_browsers_copy_stands_in(self):
        self.assertEqual(self.look(copy="pilot"), "pilot")
        self.assertEqual(self.look(copy="classic"), "classic")

    def test_after_the_prefs_load_the_copy_is_ignored(self):
        # the copy may be the last person's, and the account has not chosen
        self.assertEqual(self.look(loaded=True, copy="pilot"), "classic")
        self.assertEqual(self.look(loaded=True, copy="classic", prefs={"look": "pilot"}), "pilot")

    def test_the_accounts_choice_decides(self):
        self.assertEqual(self.look(loaded=True, prefs={"look": "pilot"}), "pilot")
        self.assertEqual(self.look(loaded=True, prefs={"look": "classic"}, brand="pilot"), "classic")

    def test_the_administrators_default_applies_until_a_choice_is_made(self):
        self.assertEqual(self.look(loaded=True, brand="pilot"), "pilot")
        self.assertEqual(self.look(brand="pilot"), "pilot")
        self.assertEqual(self.look(brand="pilot", copy="classic"), "classic")

    def test_a_lock_beats_everything(self):
        for kw in ({}, {"prefs": {"look": "classic"}}, {"copy": "classic"}):
            with self.subTest(kw=kw):
                self.assertEqual(self.look(loaded=True, brand="pilot", locked=True, **kw), "pilot")
                self.assertEqual(self.look(loaded=False, brand="pilot", locked=True, **kw), "pilot")

    def test_a_lock_without_a_default_is_nothing(self):
        self.assertEqual(self.look(loaded=True, locked=True, prefs={"look": "pilot"}), "pilot")

    def test_an_unknown_word_is_ignored_at_every_step(self):
        for bad in ("retro", "", "PILOT", None, 5, ["pilot"], {"a": 1}):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(self.look(loaded=True, prefs={"look": bad}), "classic")
                self.assertEqual(self.look(loaded=False, copy=bad), "classic")
                self.assertEqual(self.look(loaded=True, brand=bad), "classic")
                self.assertEqual(self.look(loaded=True, brand=bad, locked=True, prefs={"look": "pilot"}), "pilot")


@unittest.skipUnless(_NODE, "node not installed")
class TestEffects(unittest.TestCase):

    def test_the_same_order_as_the_look_without_a_lock(self):
        r = _run([case(loaded=True, prefs={"effects": "reduced"}, fxcopy="full"),
                  case(loaded=True, fxcopy="reduced"),
                  case(loaded=False, fxcopy="reduced"),
                  case(loaded=False),
                  case(loaded=True, prefs={"effects": "loud"})])
        self.assertEqual([x["fx"] for x in r], ["reduced", "full", "reduced", "full", "full"])

    def test_a_lock_does_not_touch_the_effects(self):
        r = _run([case(loaded=True, brand="classic", locked=True, prefs={"effects": "reduced"})])[0]
        self.assertEqual((r["look"], r["fx"]), ("classic", "reduced"))


@unittest.skipUnless(_NODE, "node not installed")
class TestApplyLook(unittest.TestCase):

    def test_it_sets_the_attributes_and_the_copy_and_says_whether_the_look_changed(self):
        r = _run([case(loaded=True, prefs={"look": "pilot", "effects": "reduced"}, apply=True)])[0]
        self.assertEqual((r["attr"], r["fxattr"], r["copy"], r["fxcopy"]), ("pilot", "reduced", "pilot", "reduced"))
        self.assertIs(r["changed"], True)
        self.assertIs(r["again"], False)       # the same look again is not a change: nothing needs redrawing

    def test_full_effects_remove_the_attribute(self):
        r = _run([case(loaded=True, prefs={"look": "pilot"}, apply=True)])[0]
        self.assertEqual((r["attr"], r["fxattr"], r["fxcopy"]), ("pilot", None, "full"))
        r = _run([case(loaded=True, apply=True)])[0]
        self.assertEqual((r["attr"], r["fxattr"], r["fxcopy"]), ("classic", None, "full"))

    def test_going_back_to_full_effects_removes_the_attribute_it_set(self):
        # the page is not reloaded between the two: a stale attribute would keep the glow off after the person turned it back on
        r = _run([case(loaded=True, prefs={"look": "pilot", "effects": "reduced"}, apply=True, then={"look": "classic"})])[0]
        self.assertEqual((r["attr"], r["fxattr"]), ("pilot", "reduced"))
        self.assertEqual((r["changed2"], r["attr2"], r["fxattr2"]), (True, "classic", None))

    def test_the_copy_follows_what_was_drawn_not_what_was_asked(self):
        # an account without a choice, on a browser whose copy says pilot: the page draws classic and the copy is corrected
        r = _run([case(loaded=True, copy="pilot", apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), ("classic", "classic"))


@unittest.skipUnless(_NODE, "node not installed")
class TestThePaletteFollowsTheLook(unittest.TestCase):

    def test_each_look_has_its_own_pair(self):
        r = _run([case(copy="pilot"), case(copy="classic"), case(), case(loaded=True, prefs={"look": "pilot"}),
                  case(loaded=True, prefs={"look": "classic"})])
        self.assertEqual([(x["dark"], x["light"]) for x in r],
                         [("pilot", "pilot-paper"), ("dark", "light"), ("dark", "light"), ("pilot", "pilot-paper"), ("dark", "light")])

    def test_both_pairs_are_themes_the_page_knows(self):
        ids = set(re.findall(r"\{ id:'([a-z-]+)',\s+name:", _APP))
        for theme in ("pilot", "pilot-paper", "dark", "light"):
            self.assertIn(theme, ids)
        css = (_ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()
        for theme in ("pilot", "pilot-paper"):
            self.assertIn('body[data-theme="%s"]' % theme, css)


class TestTheTwoSidesAgree(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        from test_v622_alert_params import api  # noqa: E402
        cls.api = api

    @staticmethod
    def words_of(name):
        m = re.search(r"^const %s = \[([^\]]*)\];" % name, _APP, re.M)
        return tuple(w.strip().strip("'\"") for w in m.group(1).split(","))

    def words(self, name):
        return self.words_of(name)

    def test_the_words_match_the_server(self):
        self.assertEqual(self.words("LOOKS"), self.api.UI_LOOKS)
        self.assertEqual(self.words("FX_LEVELS"), self.api.UI_EFFECTS)

    def test_every_card_is_a_look_and_every_look_has_a_card(self):
        cards = re.findall(r"\{ id: '([a-z]+)',\s+name: '([A-Za-z]+)'", _APP)
        ids = [c[0] for c in cards if c[0] in self.words("LOOKS")]
        self.assertEqual(sorted(ids), sorted(self.words("LOOKS")))


class TestTheWiring(unittest.TestCase):

    def test_classic_is_the_default_and_comes_first(self):
        words = TestTheTwoSidesAgree.words_of("LOOKS")
        self.assertEqual(words[0], "classic")
        self.assertEqual(re.search(r"^const LOOK_DEFAULT = '(\w+)';", _APP, re.M).group(1), "classic")
        cards = re.findall(r"\{ id: '([a-z]+)',\s+name: '[A-Za-z]+',\s+desc:", _APP)
        self.assertEqual(cards, ["classic", "pilot"])
        # the administrator's blank option names the default, and it is the one that is true
        self.assertIn('<option value="">No default (Classic)</option>', _HTML)

    def test_the_effects_are_offered_only_under_pilot(self):
        self.assertRegex(_HTML, r'<div id="acct-fx-wrap">\s*<div class="form-label mb-6 mt-8">Effects</div>\s*<select id="acct-fx"')
        self.assertIn("fxWrap.classList.toggle('d-none', cur !== 'pilot')", srcpin.js_function(_APP, "_buildLookPicker"))

    def test_the_account_page_has_the_picker_and_the_effects_select(self):
        self.assertIn('id="acct-look"', _HTML)
        self.assertRegex(_HTML, r'<select id="acct-fx"[^>]*data-change="setFxUI"')
        self.assertIn('id="acct-look-locked"', _HTML)

    def test_the_branding_form_has_the_default_and_the_lock(self):
        self.assertIn('id="cfg-brand-look"', _HTML)
        self.assertIn('id="cfg-brand-look-locked"', _HTML)
        save = srcpin.js_function(_APP, "saveBranding")
        self.assertIn("brand_look: document.getElementById('cfg-brand-look').value", save)
        self.assertIn("brand_look_locked: document.getElementById('cfg-brand-look-locked').checked", save)

    def test_the_setters_exist_and_are_registered(self):
        for fn in ("setLookUI", "setFxUI", "_buildLookPicker", "_lookChanged"):
            srcpin.js_function(_APP, fn)
        self.assertIn("window.setLookUI = setLookUI;", _APP)
        self.assertIn("window.setFxUI = setFxUI;", _APP)

    def test_a_locked_look_cannot_be_set_from_the_picker(self):
        self.assertIn("window._brandLookLocked", srcpin.js_function(_APP, "setLookUI"))
        self.assertIn("b.disabled = locked", srcpin.js_function(_APP, "_buildLookPicker"))

    def test_the_prefs_arriving_and_the_brand_arriving_both_re_apply_the_look(self):
        load = srcpin.js_function(_APP, "loadUiPrefs")
        self.assertRegex(load, r"_uiPrefsLoaded = true;\s*try \{ applyLook\(\); applyTheme\(\); \}")
        me = srcpin.js_function(_APP, "loadMe")
        self.assertIn("window._brandLook =", me)
        self.assertIn("window._brandLookLocked =", me)
        self.assertIn("if (applyLook()) _lookChanged();", me)

    def test_the_look_is_painted_when_the_script_runs(self):
        # showApp shows the shell before it asks for the prefs: without this the shell is drawn in the default colours
        # a top-level statement (the one in loadUiPrefs is indented), so it runs while the script loads, before showApp
        self.assertIn("\ntry { applyLook(); applyTheme(); } catch (_) {}\n", _APP)

    def test_changing_the_look_forgets_the_last_home_render(self):
        # Home skips a redraw when the data is the same; the hero depends on the look, not on the data
        body = srcpin.js_function(_APP, "_lookChanged")
        self.assertIn("window._homeLastRender = null", body)
        self.assertLess(body.index("window._homeLastRender = null"), body.index("loadHome()"))

    def test_the_effects_options_do_not_borrow_a_word_the_dictionary_already_owns(self):
        # "Full" is the disk fullness column and translates as such; a select that said Full would read "Füllgrad" in German
        opts = re.search(r'<select id="acct-fx".*?</select>', _HTML, re.S).group(0)
        texts = re.findall(r">([^<]+)</option>", opts)
        self.assertEqual(texts, ["Full effects", "Reduced effects"])


class TestTheTranslations(unittest.TestCase):
    """Every string the look switch adds, in all six languages. The dictionary gates hold the categories; this holds the list."""

    KEYS = ["Look", "Pilot", "Classic", "Calm panels, status shown as lights, dot readouts.", "The familiar layout, unchanged.",
            "Saved to your account, so it follows you to other browsers. Palette, accent and background are set per browser.",
            "Your administrator has set the look for everyone.", "Effects", "Full effects", "Reduced effects",
            "Reduced effects turn off the glow and the dot texture. No colour changes.", "Default look", "No default (Classic)",
            "Everyone uses this look (hides the choice in My Account)",
            "People get the default look until they choose their own in My Account. With the box ticked they cannot."]

    def test_every_key_has_all_six_languages(self):
        for key in self.KEYS:
            m = re.search(r'^\s+"%s": \{ (.+?) \},$' % re.escape(key), _I18N, re.M)
            self.assertIsNotNone(m, key)
            langs = re.findall(r'"(zh|hi|es|ar|de|fr)": "[^"]+"', m.group(1))
            self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"], key)

    def test_every_string_the_page_shows_is_in_the_list(self):
        shown = ["Look", "Effects", "Full effects", "Reduced effects", "Default look", "No default (Classic)", "Pilot", "Classic",
                 "Your administrator has set the look for everyone."]
        shown += re.findall(r"desc: '([^']+)'", _APP)
        for text in shown:
            self.assertIn(text, self.KEYS, text)

    def test_the_hints_in_the_page_are_the_listed_ones(self):
        for hint in ("Saved to your account, so it follows you to other browsers. Palette, accent and background are set per browser.",
                     "Reduced effects turn off the glow and the dot texture. No colour changes.",
                     "People get the default look until they choose their own in My Account. With the box ticked they cannot."):
            self.assertIn(hint, _HTML)
            self.assertIn(hint, self.KEYS)


if __name__ == "__main__":
    unittest.main()
