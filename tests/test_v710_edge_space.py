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
_CLOSING = ')]}.,;:!?，。；：！？、）،؛।'
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

    @staticmethod
    def _with_entries(lines):
        """i18n.js with extra DICT entries injected, so a test does not depend on which real entries exist."""
        src = _I18N.read_text(encoding='utf-8')
        marker = 'var DICT = {\n'
        assert src.count(marker) == 1, 'the DICT opening line changed; update this test with it'
        patched = src.replace(marker, marker + lines)
        assert lines in patched
        return patched

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

    def test_a_one_character_translation_can_be_switched_back_to_english(self):
        """The engine used to judge a node by its CURRENT text, so a node translated to a single character
        ("。" in Chinese, "।" in Hindi) was shorter than the two-character minimum and stayed translated
        after the page went back to English. A sentinel entry is injected so the test does not depend on
        which real entries happen to be one character long."""
        patched = self._with_entries('    "Sentinel one-char": { "zh": "。", "hi": "।", "es": ".", "ar": ".", "de": ".", "fr": "." },\n')
        page = self._browser.new_page()
        try:
            page.set_content('<body><p id="t"><code>x</code> Sentinel one-char</p></body>')
            page.add_script_tag(content=patched)
            page.evaluate('l => RPi18n.setLang(l, false)', 'zh')
            self.assertEqual(page.evaluate("() => document.getElementById('t').textContent"), 'x。')
            page.evaluate('l => RPi18n.setLang(l, false)', 'en')
            self.assertEqual(page.evaluate("() => document.getElementById('t').textContent"), 'x Sentinel one-char')
        finally:
            page.close()

    def test_french_sets_a_space_before_a_semicolon_that_follows_markup_directly(self):
        """"</strong>; off means" has no space in English, but French sets one before ; : ! ? whatever precedes
        them, so the engine supplies a non-breaking space when the node itself had none. German must not get
        one, and a literal marker such as "!HSTS" is not punctuation and must stay glued."""
        patched = self._with_entries(
            '    "; Sentinel glued semicolon": { "fr": "; arrêt", "de": "; Halt", "es": "; parada", "zh": "；停止", "hi": "; रुकें", "ar": "؛ توقف" },\n'
            '    "!Sentinel marker": { "fr": "!Marqueur", "de": "!Marker", "es": "!Marcador", "zh": "!标记", "hi": "!चिह्न", "ar": "!علامة" },\n')
        page = self._browser.new_page()
        try:
            page.set_content('<body><p id="t"><strong>x</strong>; Sentinel glued semicolon</p>'
                             '<p id="m"><strong>x</strong>!Sentinel marker</p></body>')
            page.add_script_tag(content=patched)
            text = "() => [document.getElementById('t').textContent, document.getElementById('m').textContent]"
            page.evaluate('l => RPi18n.setLang(l, false)', 'fr')
            self.assertEqual(page.evaluate(text), ['x\u00a0; arrêt', 'x!Marqueur'])
            page.evaluate('l => RPi18n.setLang(l, false)', 'de')
            self.assertEqual(page.evaluate(text), ['x; Halt', 'x!Marker'])
            page.evaluate('l => RPi18n.setLang(l, false)', 'en')
            self.assertEqual(page.evaluate(text), ['x; Sentinel glued semicolon', 'x!Sentinel marker'])
        finally:
            page.close()

    def test_going_back_to_english_restores_the_original_space(self):
        key, _value = next((k, v) for k, v in self.probes['zh'] if len(v) > 1)
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
