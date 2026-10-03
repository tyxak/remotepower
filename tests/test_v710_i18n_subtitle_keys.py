"""A page subtitle is translated only if its markup matches a dictionary key AS THE BROWSER SERIALISES IT.

The engine looks a `.page-subtitle` up by `_normWS(el.innerHTML)`. innerHTML is what the
browser WRITES, not what the source says: a valueless attribute comes back as `name=""`,
quotes are normalised, and the dynamic widgets the page appends are still in there. The
existing gate in test_v430_i18n_gate mirrors the key from the SOURCE text, so a subtitle
whose source and serialisation differ passes the gate and renders in English.

Found by the rendered audit at 7.1.0: two subtitles carried `data-prevent-default` with no
value (the browser writes `data-prevent-default=""`), so their entries could never match,
and a third carried an empty `<span id="image-updates-meta">` that the app fills in before
the first language switch. All three showed English in every language while the gate was
green. The fix is the markup (an explicit attribute value) and `data-i18n-park`, which tells
the engine to lift a dynamic widget out before it computes the key, as it does for the
Related-pages chips.

This test loads index.html into a real browser and reads innerHTML the way the engine does,
including the parking step, so source/serialisation drift of any kind is caught.
"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required   # noqa: E402
from test_v710_i18n_glue import dict_rows   # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except Exception:       # pragma: no cover
    _HAVE_PLAYWRIGHT = False

_GATE = _HAVE_PLAYWRIGHT or browser_required.required()

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / 'server' / 'html' / 'index.html'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'

# What the engine does before it reads a subtitle: lift the widgets other code appends, then
# collapse whitespace. Keep this in step with translateSubtitles() in i18n.js.
_READ = """() => [...document.querySelectorAll('.page-subtitle')].map(el => {
  const c = el.cloneNode(true);
  c.querySelectorAll('.rel-pages, [data-i18n-park]').forEach(n => n.remove());
  return c.innerHTML.replace(/\\s+/g, ' ').replace(/^\\s+|\\s+$/g, '');
})"""


def htmldict_keys():
    src = _I18N.read_text(encoding='utf-8')
    m = re.search(r'var HTMLDICT = \{(.*?)\n  \};', src, re.S)
    assert m, 'HTMLDICT block not found in i18n.js'
    keys = set()
    for em in re.finditer(r'^\s{4}"((?:[^"\\]|\\.)*)":\s*\{', m.group(1), re.M):
        keys.add(json.loads('"' + em.group(1) + '"'))
    return keys


@unittest.skipUnless(_GATE, 'playwright is not installed')
class TestSubtitleKeysMatchTheRenderedMarkup(unittest.TestCase):

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
        page = cls._browser.new_page()
        try:
            page.set_content(_HTML.read_text(encoding='utf-8'))
            cls.subtitles = [s for s in page.evaluate(_READ) if s]
        finally:
            page.close()
        cls.keys = htmldict_keys() | set(dict_rows())

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def test_the_page_has_subtitles_and_the_dictionary_has_keys(self):
        """Control: with nothing read, the check below would pass without inspecting anything."""
        self.assertGreaterEqual(len(self.subtitles), 90, 'only %d subtitles read from index.html' % len(self.subtitles))
        self.assertGreaterEqual(len(htmldict_keys()), 150, 'HTMLDICT parsed to %d keys' % len(htmldict_keys()))

    def test_every_static_subtitle_is_a_key_as_the_browser_writes_it(self):
        missing = [s for s in self.subtitles if s not in self.keys]
        self.assertEqual([], [s[:160] for s in missing],
                         '%d subtitles read back from the browser have no HTMLDICT/DICT key. If the source has a '
                         'valueless attribute, give it a value; if the app appends a widget, mark it data-i18n-park.'
                         % len(missing))

    def test_a_valueless_attribute_is_what_the_check_catches(self):
        """The checker on its own: a subtitle serialised with name="" does not match a key written without it."""
        page = self._browser.new_page()
        try:
            page.set_content('<div class="page-subtitle">Go <a href="#" data-prevent-default class="c">there</a></div>')
            got = page.evaluate(_READ)[0]
        finally:
            page.close()
        self.assertIn('data-prevent-default=""', got)
        self.assertNotIn('data-prevent-default class', got)


if __name__ == '__main__':
    unittest.main()
