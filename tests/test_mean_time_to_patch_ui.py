#!/usr/bin/env python3
"""The mean time to patch card of the Patches header: the strings it shows and the function that draws it.

The card is drawn from `mttp` of `GET /api/patch-report` by `_renderPatchMttp` (app.js). Two things are held here without a browser:

  * every word the card and its window select show is a key of the dictionary with all six languages (the page is translated one text node at a time, so a
    sentence with a number in it would be untranslatable: each word is an element of its own and each number is a text node of its own);
  * the real function, extracted from app.js and run under node over a small stand-in for the document, draws what it should in each state: figures, below the
    minimum, nothing recorded, the 90-day window, three days and more shown as days, a class with no completed patch left out, and hostile input written as text.

The layout, the right-to-left languages and the focus ring are measured in a browser: tests/test_mean_time_to_patch_e2e.py.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_NODE = shutil.which('node')

# every English text the card and the window select can show; a word the dictionary already had is listed too, since the card depends on it
STRINGS = [
    'Mean time to patch', 'Median', '90th percentile', 'Samples (n)', 'Security updates', 'Not enough data', 'Minimum',
    'No completed patches recorded yet', 'Last 30 days', 'Last 90 days', 'hours', 'days',
    'Mean time to patch window',
    'The time from the hourly check that first saw an update waiting on a host to the check that saw none waiting. Only completed patches count, '
    'so a host that never reaches zero pending updates adds nothing.',
]


class TestTheWordsAreTranslated(unittest.TestCase):

    def test_every_string_has_all_six_languages(self):
        rows = dict_rows()
        self.assertGreater(len(rows), 1000, 'control: the dictionary was read')
        missing = {s: sorted(set(LANGS) - rows.get(s, set())) for s in STRINGS if set(LANGS) - rows.get(s, set())}
        self.assertEqual(missing, {}, 'strings of the mean time to patch card that are not in the dictionary in every language')

    def test_the_markup_uses_exactly_these_words(self):
        for s in ('Mean time to patch window', 'Last 30 days', 'Last 90 days'):
            self.assertIn(s, _HTML, s)
        self.assertIn('id="patch-mttp-card"', _HTML)
        self.assertIn(STRINGS[-1], _HTML, 'the tooltip of the card is the translated sentence')
        js = (_JS / 'app.js').read_text(encoding='utf-8')
        body = srcpin.js_function(js, '_renderPatchMttp')
        for s in ('Median', '90th percentile', 'Samples (n)', 'Security updates', 'Not enough data', 'Minimum', 'No completed patches recorded yet',
                  'Last 30 days', 'Last 90 days'):
            self.assertIn("'" + s + "'", body, s)

    def test_a_number_is_never_part_of_a_sentence(self):
        body = srcpin.js_function((_JS / 'app.js').read_text(encoding='utf-8'), '_renderPatchMttp')
        self.assertNotIn('innerHTML', body, 'the card is built from text nodes: nothing the server sends is parsed as markup')
        self.assertNotIn('${', body, 'no template string: a sentence with a number in it cannot be translated')

    def test_the_card_sits_in_the_header_row_and_the_select_in_the_toolbar(self):
        i_row = _HTML.index('id="patch-summary"')
        i_card = _HTML.index('id="patch-mttp-card"')
        i_next = _HTML.index('class="table-card"', i_row)
        self.assertTrue(i_row < i_card < i_next, 'the card is inside the stat row above the table')
        self.assertIn('id="patch-mttp-days"', _HTML)
        self.assertIn('data-change="loadPatchReport"', _HTML[_HTML.index('id="patch-mttp-days"') - 80:_HTML.index('id="patch-mttp-days"') + 200])


_STUB = r'''
class El {
  constructor(tag) { this.tag = tag; this.kids = []; this.className = ''; this._t = ''; }
  set textContent(v) { this._t = String(v); this.kids = []; }
  get textContent() { return this._t + this.kids.map(k => k.textContent).join(''); }
  set innerHTML(v) { throw new Error('innerHTML was assigned: ' + v); }
  appendChild(c) { this.kids.push(c); return c; }
  replaceChildren(...cs) { this.kids = cs; this._t = ''; }
}
const els = {};
for (const id of ['patch-mttp-num', 'patch-mttp-unit', 'patch-mttp-detail']) els[id] = new El('span');
let windowValue = null;
const document = {
  createElement: t => new El(t),
  createTextNode: t => ({ textContent: String(t) }),
  getElementById: id => id === 'patch-mttp-days' ? (windowValue === null ? null : { value: windowValue }) : (els[id] || null),
};
'''


def _run(cases):
    """Each case: {'m': <the mttp object or null>, 'drop': [ids to remove], 'window': value of the select or null}. Returns what the card holds after each."""
    js = (_JS / 'app.js').read_text(encoding='utf-8')
    body = '\n'.join(srcpin.js_function(js, n) for n in ('_patchMttpQuery', '_mttpAmount', '_renderPatchMttp'))
    script = (_STUB + body + '\n'
              'const cases = ' + json.dumps(cases) + ';\n'
              'const out = [];\n'
              'for (const c of cases) {\n'
              '  for (const id of Object.keys(els)) { els[id] = new El("span"); els[id].textContent = id === "patch-mttp-num" ? "—" : ""; }\n'
              '  for (const id of (c.drop || [])) delete els[id];\n'
              '  windowValue = c.window === undefined ? null : c.window;\n'
              '  let err = null;\n'
              '  try { _renderPatchMttp(c.m); } catch (e) { err = e.message; }\n'
              '  const d = els["patch-mttp-detail"];\n'
              '  out.push({err, query: _patchMttpQuery(), num: els["patch-mttp-num"] && els["patch-mttp-num"].textContent, unit: els["patch-mttp-unit"] && els["patch-mttp-unit"].textContent,\n'
              '            lines: d ? d.kids.map(l => l.kids.map(k => k.textContent).join("")) : null});\n'
              '}\n'
              'console.log(JSON.stringify(out));\n')
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-mttp-ui-'))
    try:
        f = d / 'card.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def stat(n, mean=None, median=None, p90=None, hidden=None):
    hidden = (n < 5) if hidden is None else hidden
    return {'n': n, 'hidden': hidden, 'mean_h': mean, 'median_h': median, 'p90_h': p90, 'hosts': 1}


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheCardIsDrawnFromTheFigures(unittest.TestCase):

    def one(self, m, **extra):
        return _run([dict({'m': m}, **extra)])[0]

    def test_the_figures_of_the_fleet(self):
        got = self.one({'window_days': 30, 'min_n': 5, 'fleet': {'all': stat(12, 41.52, 30, 60.2), 'sec': stat(6, 12.04, 10, 20)}})
        self.assertIsNone(got['err'])
        self.assertEqual((got['num'], got['unit']), ('41.5', 'hours'))
        self.assertEqual(got['lines'], ['Last 30 days',
                                        'Median 30 hours · 90th percentile 60.2 hours · Samples (n) 12',
                                        'Security updates 12 hours Samples (n) 6'])

    def test_three_days_and_more_read_as_days(self):
        got = self.one({'window_days': 30, 'fleet': {'all': stat(5, 100, 72, 240), 'sec': stat(0)}})
        self.assertEqual((got['num'], got['unit']), ('4.2', 'days'))
        self.assertEqual(got['lines'][1], 'Median 3 days · 90th percentile 10 days · Samples (n) 5')
        got = self.one({'window_days': 30, 'fleet': {'all': stat(5, 71.9, 71.9, 71.9), 'sec': stat(0)}})
        self.assertEqual((got['num'], got['unit']), ('71.9', 'hours'), 'just under three days stays in hours')

    def test_below_the_minimum_the_number_is_not_shown_and_n_is(self):
        got = self.one({'window_days': 30, 'min_n': 5, 'fleet': {'all': stat(3), 'sec': stat(0)}})
        self.assertEqual((got['num'], got['unit']), ('—', ''))
        self.assertEqual(got['lines'], ['Last 30 days', 'Not enough data Samples (n) 3 Minimum 5'])

    def test_nothing_recorded_is_said_and_is_not_zero(self):
        for m in ({'window_days': 30, 'fleet': {'all': stat(0), 'sec': stat(0)}}, {'window_days': 30, 'fleet': {}}, {'fleet': {'all': None, 'sec': None}}, None, {}):
            got = self.one(m)
            self.assertEqual((got['num'], got['unit']), ('—', ''), m)
            self.assertEqual(got['lines'][-1], 'No completed patches recorded yet', m)
            self.assertNotIn('0', got['num'])

    def test_the_security_class_is_left_out_when_it_has_no_completed_patch_and_says_so_when_it_has_too_few(self):
        got = self.one({'window_days': 30, 'fleet': {'all': stat(8, 20, 18, 40), 'sec': stat(0)}})
        self.assertEqual(len(got['lines']), 2)
        got = self.one({'window_days': 30, 'fleet': {'all': stat(8, 20, 18, 40), 'sec': stat(2)}})
        self.assertEqual(got['lines'][2], 'Security updates Not enough data Samples (n) 2')

    def test_the_window_is_named(self):
        got = self.one({'window_days': 90, 'fleet': {'all': stat(0), 'sec': stat(0)}})
        self.assertEqual(got['lines'][0], 'Last 90 days')
        for w in (30, 7, None, 'x'):
            self.assertEqual(self.one({'window_days': w, 'fleet': {}})['lines'][0], 'Last 30 days', w)

    def test_a_figure_that_is_not_a_number_is_not_drawn_as_one(self):
        for bad in ('x', None, True, [], {'a': 1}):
            got = self.one({'window_days': 30, 'fleet': {'all': {'n': 9, 'hidden': False, 'mean_h': bad, 'median_h': 1, 'p90_h': 2}}})
            self.assertEqual(got['num'], '—', repr(bad))
        got = self.one({'window_days': 30, 'fleet': {'all': {'n': 9, 'hidden': True, 'mean_h': 5, 'median_h': 1, 'p90_h': 2}}})
        self.assertEqual(got['num'], '—', 'a figure the server withheld is not drawn even if one is there')

    def test_what_the_server_sends_is_text_and_never_markup(self):
        evil = '<img src=x onerror=alert(1)>'
        got = self.one({'window_days': 30, 'fleet': {'all': {'n': evil, 'hidden': True, 'mean_h': None, 'median_h': None, 'p90_h': None},
                                                      'sec': {'n': evil, 'hidden': True}}, 'min_n': evil})
        self.assertIsNone(got['err'], 'assigning innerHTML would have thrown in the stand-in document')
        self.assertIn(evil, ' '.join(got['lines']))

    def test_a_page_without_the_card_is_left_alone(self):
        for ids in (['patch-mttp-num'], ['patch-mttp-unit'], ['patch-mttp-detail']):
            got = self.one({'window_days': 30, 'fleet': {'all': stat(8, 20, 18, 40)}}, drop=ids)
            self.assertIsNone(got['err'], ids)

    def test_the_request_asks_for_ninety_days_only_when_the_select_says_so(self):
        got = _run([{'m': None, 'window': w} for w in ('90', '30', '', '1e9', None, '7')])
        self.assertEqual([g['query'] for g in got], ['?mttp_days=90', '', '', '', '', ''])


if __name__ == '__main__':
    unittest.main()
