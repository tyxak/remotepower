#!/usr/bin/env python3
"""Every "did you know" tip has a translation in all six languages.

`_DYK_TIPS` in app.js is an array of prose strings. No markup extraction sees an
array element, so the i18n gate that scans `index.html` and `app*.js` for text
in tags never counted them: at v7.3.0, 169 of 172 tips were English in every
language and the gate was fully green. This is the same shape as the
server-provided labels (`test_v702_server_labels_i18n`): text that reaches the
page as a text node without ever being markup.

The tip is rendered with `textContent`, so the engine's text-node lookup applies
and the fix is a DICT entry keyed by the exact tip text. The round trip below
asks the real engine rather than checking that a key exists.

Adding a tip means adding six translations, and a tip that names a page or a
label should use the wording of that page or label in each language.
"""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_APP = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
_NODE = shutil.which('node')
_LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')


def _tips():
    """The array, evaluated rather than scraped: some tips carry \\u escapes
    and quotes, and the DICT key is the evaluated string."""
    src = _APP.read_text(encoding='utf-8')
    start = src.index('const _DYK_TIPS = [')
    end = src.index('\n];', start) + 3
    arr = src[start + len('const _DYK_TIPS = '):end].rstrip(';')
    r = subprocess.run([_NODE, '-e', 'process.stdout.write(JSON.stringify('
                        + arr + '))'], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    return json.loads(r.stdout)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTipsRoundTripThroughTheRealEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tips = _tips()
        work = pathlib.Path(tempfile.mkdtemp(prefix='rp-tips-i18n-'))
        (work / 'run.js').write_text('''
const store = {};
global.localStorage = { getItem: k => (k in store ? store[k] : null),
                        setItem: (k, v) => { store[k] = String(v); } };
const stub = () => ({
  setAttribute(){}, getAttribute(){ return null; }, hasAttribute(){ return false; },
  querySelectorAll(){ return []; }, addEventListener(){}, appendChild(){},
  dataset: {}, classList: { contains(){ return false; } }, value: '', style: {},
});
global.document = { readyState: 'complete', documentElement: stub(), body: null,
                    createElement: stub, createTreeWalker: null,
                    getElementById(){ return null; }, querySelectorAll(){ return []; },
                    addEventListener(){} };
global.window = global;
global.fetch = () => ({ catch(){} });
require(process.argv[2]);
const strings = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const lang of window.RPi18n.langs) {
  if (lang === 'en') continue;
  window.RPi18n.setLang(lang, false);
  out[lang] = strings.filter(s => window.RPi18n.t(s) === s);
}
console.log(JSON.stringify(out));
''', encoding='utf-8')
        r = subprocess.run([_NODE, str(work / 'run.js'), str(_I18N)],
                           input=json.dumps(cls.tips),
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise AssertionError('node could not load i18n.js: ' + r.stderr[-800:])
        cls.untranslated = json.loads(r.stdout)

    def test_the_population_was_found(self):
        """Control: an empty array would satisfy the assertion below."""
        self.assertGreater(len(self.tips), 100, 'tip population collapsed')
        self.assertEqual(len(set(self.tips)), len(self.tips), 'duplicate tip')

    def test_the_engine_reported_the_six_languages(self):
        self.assertEqual(sorted(self.untranslated), sorted(_LANGS))

    def test_every_tip_is_translated_in_every_language(self):
        gaps = {lang: v for lang, v in self.untranslated.items() if v}
        self.assertEqual(
            gaps, {},
            'the real engine returns these tips unchanged (a DICT entry keyed by '
            'the exact tip text, with all six languages, is the whole fix): '
            + json.dumps({k: v[:5] for k, v in gaps.items()},
                         indent=2, ensure_ascii=False))

    def test_a_tip_with_no_entry_is_reported(self):
        """Control on the harness: it must be able to say no."""
        r = subprocess.run([_NODE, '-e', '''
global.localStorage={getItem:()=>null,setItem:()=>{}};
const stub=()=>({setAttribute(){},getAttribute(){return null},hasAttribute(){return false},
querySelectorAll(){return[]},addEventListener(){},appendChild(){},dataset:{},
classList:{contains(){return false}},value:'',style:{}});
global.document={readyState:'complete',documentElement:stub(),body:null,createElement:stub,
createTreeWalker:null,getElementById(){return null},querySelectorAll(){return[]},addEventListener(){}};
global.window=global;global.fetch=()=>({catch(){}});
require(process.argv[1]);
window.RPi18n.setLang('fr', false);
console.log(window.RPi18n.t('A tip that no dictionary will ever carry'));
''', str(_I18N)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertEqual(r.stdout.strip(), 'A tip that no dictionary will ever carry')


if __name__ == '__main__':
    unittest.main()
