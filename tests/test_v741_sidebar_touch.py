#!/usr/bin/env python3
"""v7.4.1, issue #35: the source half of the touch-screen sidebar fix.

The rendered half, which taps a real touch-emulating browser, is
tests/test_v741_sidebar_touch_e2e.py. This one is cheap and runs in the fast
gate: it pins the rule that makes the e2e hold, and it counts a population.

THE RULE. The rail's hover reveal needs a pointer that can hover. Every
`.sidebar:hover` selector in the stylesheet therefore carries
`body.pointer-hover`, and app.js is the only thing that sets that class, from
`(hover: hover) and (pointer: fine)`. One `.sidebar:hover` left without it is a
rail that opens under a fingertip again.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from srcpin import js_function  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_CSS = (_ROOT / "server/html/static/css/styles.css").read_text()
_JS = (_ROOT / "server/html/static/js/app.js").read_text()
_HTML = (_ROOT / "server/html/index.html").read_text()
_I18N = (_ROOT / "server/html/static/js/i18n.js").read_text()

GATE = "body.sidebar-collapsed.pointer-hover .sidebar:hover"


def _code(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


class TestEveryHoverRevealNeedsAPointerThatCanHover(unittest.TestCase):

    def test_the_population_is_not_empty(self):
        self.assertGreaterEqual(_code(_CSS).count(".sidebar:hover"), 12)

    def test_no_sidebar_hover_selector_is_left_ungated(self):
        css = _code(_CSS)
        total = css.count(".sidebar:hover")
        gated = css.count(GATE)
        self.assertEqual(
            gated, total,
            f"{total - gated} of {total} `.sidebar:hover` selectors lack "
            f"`body.pointer-hover`: a rail that opens under a fingertip again")

    def test_no_other_selector_hovers_the_rail_open(self):
        """The rule is about `.sidebar:hover`. A rule that expands the rail from
        another hover (the brand, a nav button) would reopen the same hole."""
        css = _code(_CSS)
        for m in re.finditer(r"body\.sidebar-collapsed[^{,]*:hover[^{,]*", css):
            sel = m.group(0)
            if ".sidebar:hover" in sel:
                continue
            self.assertNotRegex(sel, r"width|\.sidebar\b", sel)


class TestOnlyAppJsDecidesTheTwoClasses(unittest.TestCase):

    def test_the_media_query_is_the_one_the_stylesheet_means(self):
        body = js_function(_JS, "_canHover")
        self.assertIn("_HOVER_MQ", body)
        self.assertIn("(hover: hover) and (pointer: fine)", _JS)

    def test_pointer_hover_is_set_at_load_and_when_the_pointer_changes(self):
        sets = [ln for ln in _JS.splitlines()
                if "'pointer-hover'" in ln and "classList" in ln]
        self.assertEqual(len(sets), 2, sets)

    def test_autohide_is_applied_in_one_place_and_needs_a_hovering_pointer(self):
        writers = [ln for ln in _JS.splitlines()
                   if "classList.toggle('autohide-sidebar'" in ln
                   or "classList.add('autohide-sidebar'" in ln]
        self.assertEqual(len(writers), 1, writers)
        self.assertIn("_autohidePref() && _canHover()", js_function(_JS, "_applyAutohide"))

    def test_the_stored_choice_still_defaults_to_on(self):
        """Where a pointer can hover nothing changed: auto-hide is on until the
        operator turns it off."""
        body = js_function(_JS, "_autohidePref")
        self.assertIn("rp_autohide_sidebar", body)
        self.assertIn("|| '1'", body)


class TestTheSwitchSaysWhyItIsOff(unittest.TestCase):

    def test_the_hint_is_in_the_page_and_starts_hidden(self):
        m = re.search(r'<p class="hint" id="acct-autohide-touch-hint" hidden>([^<]+)</p>', _HTML)
        self.assertTrue(m, "the touch-screen hint is missing from My Account")
        self.assertIn("hover", m.group(1))

    def test_the_hint_is_translated_into_all_six_languages(self):
        key = re.search(r'id="acct-autohide-touch-hint" hidden>([^<]+)<', _HTML).group(1)
        line = next((ln for ln in _I18N.splitlines() if f'"{key}"' in ln), "")
        self.assertTrue(line, "no DICT entry for the hint")
        for lang in ("fr", "de", "zh", "hi", "es", "ar"):
            self.assertRegex(line, rf'"{lang}":\s*"', f"{lang} missing")

    def test_both_switches_follow_the_pointer(self):
        sync = js_function(_JS, "_syncAutohideControls")
        self.assertEqual(sync.count(".disabled = !hover"), 2)
        self.assertIn("acct-autohide-touch-hint", sync)


if __name__ == "__main__":
    unittest.main()
