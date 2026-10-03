"""A translated text node must not print a space before closing punctuation.

A paragraph that contains inline markup is several text nodes, and DICT is keyed per
node. The engine used to put each node's ORIGINAL edge whitespace back around its
translation, so a node whose German, Chinese or Spanish text starts with "," or ")"
printed " ," after the preceding <code> element. 39 audited nodes were affected, from
single pieces like "page." -> "." to whole clauses.

`translateTextNode` now drops that space where the translation starts with closing
punctuation (or ends on an opening bracket), keeps it for French, which spaces before
: ; ! ? on purpose, and puts the original whitespace back when the page returns to
English.

This loads the real engine into a blank page and checks the text it produces. The probe
strings are DERIVED from the dictionary (entries whose translation starts with closing
punctuation), so the test cannot rot into checking nothing.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required   # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except Exception:       # pragma: no cover
    _HAVE_PLAYWRIGHT = False

_GATE = _HAVE_PLAYWRIGHT or browser_required.required()

_ROOT = Path(__file__).resolve().parent.parent
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
_CLOSING = ')]}.,;:!?，。；：！？、）،؛'
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')


def _probes():
    """{lang: [(english key, translation)]} for entries whose translation starts with closing punctuation.

    Only the machine-written, double-quoted block is read; that is plenty and keeps the regex honest.
    """
    src = _I18N.read_text(encoding='utf-8')
    out = {lang: [] for lang in _LANGS}
    for m in re.finditer(r'^    "((?:[^"\\]|\\.)+)": \{ (.*) \},?$', src, re.M):
        key = m.group(1)
        if '\\' in key or '<' in key or len(key) > 120:
            continue
        for lang in _LANGS:
            v = re.search(r'"%s": "((?:[^"\\]|\\.)*)"' % lang, m.group(2))
            if v and v.group(1) and v.group(1)[0] in _CLOSING and '\\' not in v.group(1):
                out[lang].append((key, v.group(1)))
    return out


@unittest.skipUnless(_GATE, 'playwright is not installed')
class TestNoSpaceBeforeClosingPunctuation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail('playwright is not installed')
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:                    # pragma: no cover
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        cls.probes = _probes()

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def _page(self, key):
        page = self._browser.new_page()
        page.set_content('<body><p id="t"><code>x</code> %s</p></body>' % key.replace('&', '&amp;').replace('<', '&lt;'))
        page.add_script_tag(path=str(_I18N))
        return page

    def test_the_probe_population_is_not_empty(self):
        """Control: with no probe the loop below would pass without checking anything."""
        for lang in ('de', 'es', 'zh', 'ar'):
            self.assertGreaterEqual(len(self.probes[lang]), 3, f'{lang}: {len(self.probes[lang])} probes')

    def test_closing_punctuation_loses_the_leading_space(self):
        checked = 0
        for lang in ('de', 'es', 'zh', 'ar', 'hi'):
            for key, value in self.probes[lang][:4]:
                page = self._page(key)
                try:
                    page.evaluate('l => RPi18n.setLang(l, false)', lang)
                    text = page.evaluate("() => document.getElementById('t').textContent")
                finally:
                    page.close()
                self.assertEqual(text, 'x' + value, f'{lang}: "{key}" printed {text!r}')
                checked += 1
        self.assertGreaterEqual(checked, 12)

    def test_french_keeps_the_space_before_a_colon(self):
        """French spaces before : ; ! ? by convention, so the engine must leave that one alone."""
        colon = [(k, v) for k, v in self.probes['fr'] if v[0] in ':;!?']
        self.assertTrue(colon, 'no French entry starts with : ; ! or ? - the control has nothing to check')
        key, value = colon[0]
        page = self._page(key)
        try:
            page.evaluate('l => RPi18n.setLang(l, false)', 'fr')
            text = page.evaluate("() => document.getElementById('t').textContent")
        finally:
            page.close()
        self.assertEqual(text, 'x ' + value)

    def test_going_back_to_english_restores_the_original_space(self):
        key, _value = self.probes['zh'][0]
        page = self._page(key)
        try:
            page.evaluate('l => RPi18n.setLang(l, false)', 'zh')
            page.evaluate('l => RPi18n.setLang(l, false)', 'en')
            text = page.evaluate("() => document.getElementById('t').textContent")
        finally:
            page.close()
        self.assertEqual(text, 'x ' + key)


if __name__ == '__main__':
    unittest.main()
