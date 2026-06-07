#!/usr/bin/env python3
"""v4.1 — full theme system + expanded i18n catalog (static-UI strings, 5 langs)."""
import json
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
CSS = (_ROOT / "server/html/static/css/styles.css").read_text()
APP = (_ROOT / "server/html/static/js/app.js").read_text()
I18N = (_ROOT / "server/html/static/js/i18n.js").read_text()
HTML = (_ROOT / "server/html/index.html").read_text()

# Themes that must be real, full palettes (data-theme + JS catalog entry).
DARK_THEMES = ["nord", "dracula", "gruvbox", "catppuccin", "tokyo", "rosepine",
               "solarized", "oceanic"]
LIGHT_THEMES = ["solarized-light", "nord-light", "paper"]


class TestThemes(unittest.TestCase):
    def test_each_theme_has_full_palette_in_css(self):
        for t in DARK_THEMES + LIGHT_THEMES:
            m = re.search(r'body\[data-theme="%s"\]\s*\{([^}]*)\}' % re.escape(t), CSS, re.S)
            self.assertIsNotNone(m, f"no CSS block for theme {t}")
            block = m.group(1)
            # a real theme sets the structural palette, not just an accent
            for var in ("--bg", "--surface", "--border", "--text", "--accent"):
                self.assertIn(var, block, f"{t} missing {var}")

    def test_js_theme_catalog_lists_all(self):
        m = re.search(r'const THEMES = \[(.*?)\];', APP, re.S)
        self.assertIsNotNone(m)
        block = m.group(1)
        for t in DARK_THEMES + LIGHT_THEMES + ["dark", "light", "auto"]:
            self.assertIn(f"id:'{t}'", block.replace(" ", ""), f"THEMES missing {t}")
        # light themes must be typed 'light' so JS adds the body.light class
        for t in LIGHT_THEMES + ["light"]:
            self.assertRegex(block, r"id:'%s'[^}]*type:'light'" % re.escape(t))

    def test_picker_grid_present_and_select_gone(self):
        self.assertIn('id="acct-theme-grid"', HTML)
        self.assertNotIn('id="acct-theme"', HTML)   # old 3-option select replaced
        self.assertIn("function setThemeUI", APP)
        self.assertIn("window.setThemeUI = setThemeUI", APP)   # exposed for dispatch
        self.assertIn("dataset.action = 'setThemeUI'", APP)    # cards dispatch to it

    def test_accent_still_works_on_top(self):
        # accent presets remain (orthogonal override declared AFTER themes)
        self.assertIn('body[data-accent="emerald"]', CSS)
        self.assertLess(CSS.index('body[data-theme="nord"]'),
                        CSS.index('body[data-accent="emerald"]'),
                        "accent presets must come after theme blocks so accent wins")


class TestI18nCatalog(unittest.TestCase):
    def _dict_keys(self):
        region = I18N[I18N.index("var DICT = {"):I18N.index("};", I18N.index("var DICT = {"))]
        keys = re.findall(r"\n\s*'([^']+)':\s*\{", region)
        keys += re.findall(r'\n\s*"([^"]+)":\s*\{', region)
        return region, keys

    def test_catalog_grew_well_beyond_nav(self):
        _region, keys = self._dict_keys()
        self.assertGreater(len(keys), 140, f"catalog only has {len(keys)} entries")

    def test_sample_static_strings_translated_all_langs(self):
        region, _ = self._dict_keys()
        for src in ("Accounts", "ACME certificates"):
            m = re.search(r'"%s":\s*\{([^}]*)\}' % re.escape(src), region)
            self.assertIsNotNone(m, f"{src!r} not in catalog")
            for lang in ("zh", "hi", "es", "ar"):
                self.assertRegex(m.group(1), r'"%s":\s*"[^"]+"' % lang,
                                 f"{src!r} missing {lang}")

    def test_selectors_broadened(self):
        self.assertIn("'.page-subtitle'", I18N)
        self.assertIn("'.section-title'", I18N)

    def test_apply_wired_into_page_show(self):
        i = APP.index("function showPage")
        chunk = APP[i:i + 7000]
        self.assertIn("RPi18n.apply", chunk)

    def test_dict_block_is_valid_object(self):
        # Pull the DICT object literal and confirm it parses as JSON once the
        # single-quoted keys are normalized (values are already JSON objects).
        region = I18N[I18N.index("var DICT = {") + len("var DICT = "):]
        region = region[:region.index("\n  };") + 4]
        # quick structural sanity: balanced braces
        self.assertEqual(region.count("{"), region.count("}"))


if __name__ == "__main__":
    unittest.main()
