#!/usr/bin/env python3
"""7.4.9: which typeface the page draws, decided by the real functions of app.js run under node.

The typeface (the system font or B612) is a per-account reading preference. It has no administrator default or lock, so the order is
shorter than the look's, but it has the same trap: two places hold a value, and getting the order wrong shows one person another
person's font, or the wrong font for the length of a request.

1. once the prefs have loaded, the account's choice decides, and the browser's copy is ignored: the copy may belong to the person who
   used this browser before;
2. before the prefs have loaded, the browser's copy stands in, so the first paint matches;
3. with no choice at all, the system font: B612 is an option, never the default.

Anything that is not one of the two known words is ignored at every step. The system font is the page with no `data-typeface`
attribute at all, so the default is exactly what it was before the option existed.

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
_CSS = (_ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()

FUNCS = ("_hasSession", "_typefaceChoice", "applyTypeface", "setTypefaceUI", "_buildTypefacePicker")


def _const(name):
    m = re.search(r"^const %s = (.+?);\s*$" % re.escape(name), _APP, re.M)
    assert m, name
    return m.group(0)


def _script(cases):
    src = [_const("TYPEFACES"), _const("TYPEFACE_DEFAULT")]
    src += [srcpin.js_function(_APP, f) for f in FUNCS]
    return (
        "const store = new Map();\n"
        "const localStorage = { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) };\n"
        "const select = { value: '' };\n"
        "const document = { body: { dataset: {} }, getElementById: id => (id === 'acct-typeface' ? select : null) };\n"
        "const window = {}; let session = true;\n"
        "function getToken() { return session ? 'token' : ''; }\n"
        "let _uiPrefs = {}; let _uiPrefsLoaded = false; let flushes = 0;\n"
        "function _scheduleFlushUiPrefs() { flushes += 1; }\n"
        + "\n".join(src)
        + "\nconst cases = " + json.dumps(cases) + ";\n"
        "const attr = () => (('typeface' in document.body.dataset) ? document.body.dataset.typeface : null);\n"
        "const out = cases.map(c => {\n"
        "  store.clear(); document.body.dataset = {}; flushes = 0; select.value = '';\n"
        "  _uiPrefs = c.prefs || {}; _uiPrefsLoaded = !!c.loaded;\n"
        "  window._brandTypeface = c.brand; session = !c.signedout;   // a page with an account unless a case says it is the sign-in page\n"
        "  if (c.copy !== undefined) store.set('rp_typeface', c.copy);\n"
        "  if (c.attr !== undefined) document.body.dataset.typeface = c.attr;\n"
        "  if (c.look !== undefined) document.body.dataset.look = c.look;\n"
        "  const r = { face: _typefaceChoice() };\n"
        "  if (c.apply) { applyTypeface(); r.attr = attr(); r.copy = store.has('rp_typeface') ? store.get('rp_typeface') : null;\n"
        "                 r.look = document.body.dataset.look === undefined ? null : document.body.dataset.look; }\n"
        "  if (c.set !== undefined) { select.value = c.set; setTypefaceUI(); r.prefs = _uiPrefs; r.flushes = flushes; r.attr2 = attr();\n"
        "                             r.copy2 = store.has('rp_typeface') ? store.get('rp_typeface') : null; }\n"
        "  if (c.picker) { select.value = 'unset'; _buildTypefacePicker(); r.picked = select.value; }\n"
        "  return r;\n"
        "});\n"
        "console.log(JSON.stringify(out));\n"
    )


def _run(cases):
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "typeface.js"
        path.write_text(_script(cases))
        proc = subprocess.run([_NODE, str(path)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@unittest.skipUnless(_NODE, "node not installed")
class TestWhichTypefaceIsDrawn(unittest.TestCase):

    def face(self, **kw):
        return _run([kw])[0]["face"]

    def test_the_default_is_the_system_font(self):
        self.assertEqual(self.face(), "system")
        self.assertEqual(self.face(loaded=True), "system")

    def test_before_the_prefs_load_the_browsers_copy_stands_in(self):
        self.assertEqual(self.face(copy="b612"), "b612")
        self.assertEqual(self.face(copy="system"), "system")
        self.assertEqual(self.face(copy="b612", prefs={"typeface": "system"}), "b612")   # the prefs are not here yet

    def test_after_the_prefs_load_the_copy_is_ignored(self):
        # the previous person at this browser chose B612; this account never did
        self.assertEqual(self.face(copy="b612", loaded=True), "system")
        self.assertEqual(self.face(copy="b612", loaded=True, prefs={"look": "pilot"}), "system")

    def test_the_accounts_choice_decides(self):
        self.assertEqual(self.face(loaded=True, prefs={"typeface": "b612"}), "b612")
        self.assertEqual(self.face(loaded=True, prefs={"typeface": "b612"}, copy="system"), "b612")
        self.assertEqual(self.face(loaded=True, prefs={"typeface": "system"}, copy="b612"), "system")

    def test_an_unknown_word_is_ignored_at_every_step(self):
        for bad in ["Inter", "B612", "system ", "", "null", None, 5, True, [], ["b612"], {}, {"typeface": "b612"}]:
            with self.subTest(bad=repr(bad)):
                self.assertEqual(self.face(copy=bad, loaded=False), "system")
                self.assertEqual(self.face(prefs={"typeface": bad}, loaded=True), "system")

    def test_one_case_does_not_leak_into_the_next(self):
        out = _run([dict(copy="b612"), dict(), dict(loaded=True, prefs={"typeface": "b612"}), dict(loaded=True)])
        self.assertEqual([r["face"] for r in out], ["b612", "system", "b612", "system"])


@unittest.skipUnless(_NODE, "node not installed")
class TestApplyTypeface(unittest.TestCase):

    def test_b612_sets_the_attribute_and_the_copy(self):
        r = _run([dict(copy="b612", apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), ("b612", "b612"))

    def test_the_system_font_is_no_attribute_at_all(self):
        r = _run([dict(apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), (None, "system"))

    def test_going_back_to_the_system_font_removes_the_attribute_it_set(self):
        # state carried in from an earlier draw: a version that only ever set the attribute would pass the two cases above
        r = _run([dict(attr="b612", loaded=True, prefs={"typeface": "system"}, apply=True)])[0]
        self.assertIsNone(r["attr"])
        self.assertEqual(r["copy"], "system")

    def test_the_copy_follows_what_was_drawn_not_what_was_asked(self):
        # a stale copy of b612 with an account that chose nothing: the page draws the system font, and the copy says so
        r = _run([dict(copy="b612", loaded=True, apply=True)])[0]
        self.assertEqual((r["attr"], r["copy"]), (None, "system"))

    def test_it_does_not_touch_the_look(self):
        r = _run([dict(look="pilot", copy="b612", apply=True)])[0]
        self.assertEqual((r["attr"], r["look"]), ("b612", "pilot"))


@unittest.skipUnless(_NODE, "node not installed")
class TestChoosingFromTheAccountPage(unittest.TestCase):

    def test_a_choice_is_saved_to_the_account_drawn_and_copied(self):
        r = _run([dict(loaded=True, set="b612")])[0]
        self.assertEqual(r["prefs"], {"typeface": "b612"})
        self.assertEqual(r["flushes"], 1)
        self.assertEqual((r["attr2"], r["copy2"]), ("b612", "b612"))

    def test_choosing_the_system_font_again_removes_the_attribute(self):
        r = _run([dict(loaded=True, prefs={"typeface": "b612"}, attr="b612", set="system")])[0]
        self.assertEqual(r["prefs"], {"typeface": "system"})
        self.assertEqual((r["attr2"], r["copy2"]), (None, "system"))

    def test_it_keeps_the_other_prefs(self):
        r = _run([dict(loaded=True, prefs={"look": "pilot", "temp_unit": "f"}, set="b612")])[0]
        self.assertEqual(r["prefs"], {"look": "pilot", "temp_unit": "f", "typeface": "b612"})

    def test_a_word_the_page_does_not_know_changes_nothing(self):
        r = _run([dict(loaded=True, prefs={"typeface": "b612"}, attr="b612", set="Inter")])[0]
        self.assertEqual(r["prefs"], {"typeface": "b612"})
        self.assertEqual(r["flushes"], 0)
        self.assertEqual(r["attr2"], "b612")

    def test_the_select_shows_the_choice_in_force(self):
        self.assertEqual(_run([dict(loaded=True, prefs={"typeface": "b612"}, picker=True)])[0]["picked"], "b612")
        self.assertEqual(_run([dict(loaded=True, picker=True)])[0]["picked"], "system")
        self.assertEqual(_run([dict(copy="b612", loaded=True, picker=True)])[0]["picked"], "system")


class TestTheTwoSidesAgree(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        from test_v622_alert_params import api  # noqa: E402
        cls.api = api

    @staticmethod
    def words():
        m = re.search(r"^const TYPEFACES = \[([^\]]*)\];", _APP, re.M)
        return tuple(w.strip().strip("'\"") for w in m.group(1).split(","))

    def test_the_words_match_the_server(self):
        self.assertEqual(self.words(), self.api.UI_TYPEFACES)

    def test_the_system_font_is_first_and_the_default(self):
        self.assertEqual(self.words()[0], "system")
        self.assertEqual(re.search(r"^const TYPEFACE_DEFAULT = '(\w+)';", _APP, re.M).group(1), "system")

    def test_the_select_offers_the_words_in_order(self):
        sel = re.search(r'<select id="acct-typeface".*?</select>', _HTML, re.S).group(0)
        self.assertEqual(tuple(re.findall(r'<option value="([a-z0-9]+)">', sel)), self.words())

    def test_every_word_but_the_default_has_its_rule_in_the_stylesheet(self):
        for word in self.words():
            if word != "system":
                self.assertIn('body[data-typeface="%s"]' % word, _CSS, word)

    def test_the_default_has_no_rule(self):
        # the system font is the page with nothing set, so there is nothing to select it by
        self.assertNotIn('body[data-typeface="system"]', _CSS)


class TestTheWiring(unittest.TestCase):

    def test_the_account_page_has_the_select(self):
        self.assertRegex(_HTML, r'<select id="acct-typeface"[^>]*data-change="setTypefaceUI"[^>]*aria-label="Typeface"')

    def test_it_sits_in_the_appearance_section_after_the_look_and_before_the_palette(self):
        i_fx, i_tf, i_theme = (_HTML.index(s) for s in ('id="acct-fx"', 'id="acct-typeface"', 'id="acct-theme-grid"'))
        self.assertLess(i_fx, i_tf)
        self.assertLess(i_tf, i_theme)

    def test_the_new_markup_has_no_inline_style(self):
        row = _HTML[_HTML.index("<!-- 7.4.9: the typeface."):_HTML.index('<p class="hint">Pick a theme for this browser.')]
        self.assertNotIn("style=", row)
        self.assertNotRegex(row, r"\son[a-z]+=")

    def test_the_setters_exist_and_are_registered(self):
        for fn in ("setTypefaceUI", "_buildTypefacePicker", "applyTypeface", "_typefaceChoice"):
            srcpin.js_function(_APP, fn)
        self.assertIn("window.setTypefaceUI = setTypefaceUI;", _APP)

    def test_a_choice_is_saved_to_the_account(self):
        body = srcpin.js_function(_APP, "setTypefaceUI")
        self.assertIn("_uiPrefs.typeface = v;", body)
        self.assertIn("_scheduleFlushUiPrefs();", body)
        self.assertIn("applyTypeface();", body)

    def test_the_default_is_no_attribute(self):
        body = srcpin.js_function(_APP, "applyTypeface")
        self.assertIn("delete document.body.dataset.typeface", body)
        self.assertIn("document.body.dataset.typeface = face", body)

    def test_the_picker_is_built_with_the_rest_of_the_appearance_section(self):
        self.assertIn("_buildTypefacePicker();", srcpin.js_function(_APP, "_buildAppearancePicker"))
        self.assertIn("el.value = _typefaceChoice()", srcpin.js_function(_APP, "_buildTypefacePicker"))

    def test_the_prefs_arriving_re_apply_the_typeface_and_fill_the_select(self):
        # the select is right as soon as the prefs are here; waiting for the account page to build it left "System font" showing
        # for the moment after the page opened, for a person who had chosen B612
        load = srcpin.js_function(_APP, "loadUiPrefs")
        self.assertRegex(load, r"(?s)_uiPrefsLoaded = true;.*try \{ applyTypeface\(\); _buildTypefacePicker\(\); \} catch \(_\) \{\}")

    def test_the_typeface_is_painted_when_the_script_runs(self):
        # showApp shows the shell before it asks for the prefs; a top-level statement (the one in loadUiPrefs is indented)
        self.assertIn("\ntry { applyTypeface(); } catch (_) {}", _APP)

    def test_the_typeface_has_an_instance_default_and_no_lock(self):
        # 8.0.0 gave it a default (test_v800_brand_typeface*); it still has no lock, because nobody should be made to read in a face they cannot read
        for text in (_APP, _HTML):
            self.assertNotIn("brand_typeface_locked", text)
            self.assertNotIn("_brandTypefaceLocked", text)
        self.assertIn("cfg-brand-typeface", _HTML)

    def test_the_look_code_is_untouched(self):
        # the existing look contract is held by test_v749_look_client; these call sites keep their exact form
        load = srcpin.js_function(_APP, "loadUiPrefs")
        self.assertRegex(load, r"_uiPrefsLoaded = true;\s*try \{ applyLook\(\); applyTheme\(\); \}")
        self.assertIn("\ntry { applyLook(); applyTheme(); } catch (_) {}\n", _APP)


class TestTheTranslations(unittest.TestCase):
    """Every string the typeface row adds, in all six languages. The dictionary gates hold the categories; this holds the list."""

    HINT = ("B612 was drawn for aircraft cockpit screens, with letters that are easy to tell apart. It loads only when it is in use, "
            "and it covers Latin letters; other scripts use your system font. Saved to your account, so it follows you to other "
            "browsers.")
    KEYS = ["Typeface", "System font", "B612", HINT]

    def entry(self, key):
        return re.search(r'^\s+"%s": \{ (.+?) \},$' % re.escape(key), _I18N, re.M)

    def test_every_key_has_all_six_languages(self):
        for key in self.KEYS:
            m = self.entry(key)
            self.assertIsNotNone(m, key)
            langs = re.findall(r'"(zh|hi|es|ar|de|fr)": "[^"]+"', m.group(1))
            self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"], key)

    def test_every_string_the_row_shows_is_in_the_list(self):
        # the row ends where the next one starts: the Text size row (8.0.0) sits between this one and the theme hint
        row = _HTML[_HTML.index("<!-- 7.4.9: the typeface."):_HTML.index("<!-- Text size. The page is zoomed")]
        shown = re.findall(r'class="form-label mb-6">([^<]+)<', row)
        shown += re.findall(r"<option[^>]*>([^<]+)</option>", row)
        shown += re.findall(r'<p class="hint">([^<]+)</p>', row)
        self.assertEqual(shown, ["Typeface", "System font", "B612", self.HINT])
        for text in shown:
            self.assertIn(text, self.KEYS, text)

    def test_the_options_do_not_borrow_a_word_the_dictionary_already_owns(self):
        # "System" is the sidebar group and translates as such; a select that said System would read as a page name
        sel = re.search(r'<select id="acct-typeface".*?</select>', _HTML, re.S).group(0)
        self.assertEqual(re.findall(r">([^<]+)</option>", sel), ["System font", "B612"])

    def test_the_font_name_is_the_same_in_every_language(self):
        body = self.entry("B612").group(1)
        self.assertEqual(set(re.findall(r'"(?:zh|hi|es|ar|de|fr)": "([^"]+)"', body)), {"B612"})


if __name__ == "__main__":
    unittest.main()
