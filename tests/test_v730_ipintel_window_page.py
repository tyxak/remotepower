"""The Threat intel tables draw a window of their rows, and say how many there are (v7.3.0).

1,000 attacker rows were 36k DOM nodes and about 0.3 s a render, repeated on every
keystroke in the filter. The page draws the first 200 now and offers more. What
matters is that a cut is never silent, that the window never grows past what the page
drew before, that a filter starts it over, and that "Load all" asks the server for
what it keeps and no more.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-windowpage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_PY = (_ROOT / 'server' / 'cgi-bin' / 'ip_intel_handlers.py').read_text()
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
HAVE_NODE = bool(shutil.which('node'))


def _const(name):
    m = re.search(r'^const %s = \{.*?^\};' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    return m.group(0)


def _line(name):
    m = re.search(r'^(?:const|let) %s = .*;.*$' % re.escape(name), _JS, re.M)
    assert m, name
    return m.group(0)


def _py_const(name):
    return int(re.search(r'^%s = (\d+)' % name, _PY, re.M).group(1))


def node(script, timeout=30):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
    parts = [
        esc, esca, _const('_IPI_MORE_WORD'), _const('_IPI_CLEAR_WORD'), _const('_IPI_CLEAR_DIALOG'),
        _line('_IPI_ROW_STEP'), _line('_IPI_ROW_MAX'), _line('_IPI_LOAD_ALL'), _line('_ipiRowLimit'),
        _line('_ipiRowsAsked'),
        'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: "", hidden: false,'
        ' addEventListener(t, f) { (this._h = this._h || {})[t] = f; }});',
        'const document = {getElementById: mk};',
        'let _ipiData = null, _ipiAdmin = false, _ipiWired = false; const _ipiOpen = new Set(); const sent = [];',
        'let reply = {ok: true};',
        'async function api(m, p, body) { sent.push({m, p, body}); return reply; }',
        'const tableCtl = {wireSortOnly() {}, sortRows(name, rows, fn) { return rows; }};',
        # the row-level renderers are not what is under test: a row is one <tr>
        'function _ipiStatus() { return ""; } function _ipiStatusHtml() { return ""; }'
        ' function _ipiEvidenceHtml() { return ""; } function _ipiEvidenceText() { return ""; }'
        ' function _ipiEvidenceWeight() { return 0; } function _ipiDetailHtml() { return ""; }'
        ' function _ipiScoreClass() { return ""; } function timeAgo() { return ""; } function timeAgoHtml() { return ""; }'
        ' function _fmtDuration() { return ""; } function _ipiFillSettings() {}'
        ' function _ipiRenderSources() {} function _ipiRenderEdge() {} function _ipiRenderEdgeList() {}',
        srcpin.js_function(_JS, '_ipiPhrase'),
        srcpin.js_function(_JS, '_ipiWindow'),
        srcpin.js_function(_JS, '_ipiRenderMore'),
        srcpin.js_function(_JS, '_ipiRerender'),
        srcpin.js_function(_JS, 'showMoreIpIntel'),
        srcpin.js_function(_JS, 'showAllIpIntel'),
        'async ' + srcpin.js_function(_JS, 'loadAllIpIntel'),
        srcpin.js_function(_JS, '_ipiRenderAttackerNote'),
        srcpin.js_function(_JS, '_ipiRenderAttackers'),
        srcpin.js_function(_JS, '_ipiRenderBlocks'),
        srcpin.js_function(_JS, '_ipiWire'),
        'async ' + srcpin.js_function(_JS, 'loadIpIntel'),
    ]
    # through stdin: a few thousand rows of JSON are past the limit of one argument
    out = subprocess.run(['node'], input='\n'.join(parts) + '\n(async () => {' + script + '})()',
                         capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def attackers(n):
    return [{'ip': '198.51.%d.%d' % (i // 250, i % 250 + 1), 'last_seen': 1_790_000_000 - i, 'devices': [],
             'reported': {}, 'errors': {}} for i in range(n)]


def blocks(n):
    return [{'ip': '198.51.%d.%d' % (i // 250, i % 250 + 1), 'device_id': 'd1', 'name': 'web01', 'at': 1, 'until': 2}
            for i in range(n)]


def setup(n_att=0, n_blk=0, total=None):
    d = {'attackers': attackers(n_att), 'attackers_total': n_att if total is None else total,
         'blocks': blocks(n_blk)}
    return '_ipiData = %s; _ipiWire();' % json.dumps(d)


def tr_count(html):
    return len(re.findall(r'<tr>', html))


SNAP = ('const att = mk("ipintel-att-tbody").innerHTML, blk = mk("ipintel-blk-tbody").innerHTML;'
        'const am = mk("ipintel-att-more"), bm = mk("ipintel-blk-more");'
        'return {att, blk, am: {hidden: am.hidden, html: am.innerHTML}, bm: {hidden: bm.hidden, html: bm.innerHTML}};')


def snap(script):
    out = node('const snap = () => { %s };' % SNAP + script + 'console.log(JSON.stringify(snap()));')
    out['att_rows'] = tr_count(out['att'])
    out['blk_rows'] = tr_count(out['blk'])
    return out


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheAttackersWindow(unittest.TestCase):
    def test_a_long_list_draws_a_window_and_says_how_many_there_are(self):
        out = snap(setup(1000) + '_ipiRenderAttackers();')
        self.assertEqual(out['att_rows'], 200)
        self.assertFalse(out['am']['hidden'])
        self.assertIn('<span>Shown</span>: 200 · <span>In all</span>: 1000', out['am']['html'])
        self.assertIn('data-action="showMoreIpIntel" data-arg="attackers"', out['am']['html'])
        self.assertIn('data-action="showAllIpIntel" data-arg="attackers"', out['am']['html'])

    def test_a_short_list_draws_all_of_it_and_says_nothing(self):
        out = snap(setup(150) + '_ipiRenderAttackers();')
        self.assertEqual(out['att_rows'], 150)
        self.assertTrue(out['am']['hidden'])
        self.assertEqual(out['am']['html'], '')

    def test_show_more_adds_a_step_and_show_all_goes_to_the_most_the_page_drew_before(self):
        out = snap(setup(1000) + '_ipiRenderAttackers(); showMoreIpIntel("attackers");')
        self.assertEqual(out['att_rows'], 400)
        out = snap(setup(4000) + '_ipiRenderAttackers(); showAllIpIntel("attackers");')
        self.assertEqual(out['att_rows'], 1000, 'never more than the page drew before')
        self.assertIn('<span>In all</span>: 4000', out['am']['html'])
        self.assertIn('Filter the list to see the rest.', out['am']['html'])
        self.assertNotIn('data-action', out['am']['html'], 'no button that would do nothing')

    def test_the_window_stops_at_the_maximum_however_often_it_is_asked(self):
        out = snap(setup(4000) + '_ipiRenderAttackers(); for (let i = 0; i < 20; i++) showMoreIpIntel("attackers");')
        self.assertEqual(out['att_rows'], 1000)

    def test_a_filter_starts_the_window_over_and_counts_what_matches(self):
        out = snap(setup(1000) + '_ipiRenderAttackers(); showMoreIpIntel("attackers"); showMoreIpIntel("attackers");'
                   'mk("ipintel-filter").value = "198.51"; mk("ipintel-filter")._h.input();')
        self.assertEqual(out['att_rows'], 200, 'back to the first window')
        self.assertIn('<span>Matching</span>: 1000', out['am']['html'])
        self.assertNotIn('<span>In all</span>', out['am']['html'])

    def test_no_match_hides_the_count(self):
        out = snap(setup(1000) + 'mk("ipintel-filter").value = "no-such-address"; _ipiRenderAttackers();')
        self.assertTrue(out['am']['hidden'])

    def test_an_empty_table_leaves_no_stale_footer(self):
        out = snap(setup(1000) + '_ipiRenderAttackers(); _ipiData.attackers = []; _ipiData.attackers_total = 0;'
                   '_ipiRenderAttackers();')
        self.assertTrue(out['am']['hidden'])
        self.assertEqual(out['am']['html'], '')

    def test_an_unknown_table_name_is_ignored(self):
        out = node(setup(1000) + '_ipiRenderAttackers();'
                   'for (const w of ["settings", "__proto__", "constructor", "toString", "", null, 7]) {'
                   ' showMoreIpIntel(w); showAllIpIntel(w); }'
                   'console.log(JSON.stringify(_ipiRowLimit));')
        self.assertEqual(out, {'attackers': 200, 'blocks': 200})


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheBlocksWindow(unittest.TestCase):
    def test_a_long_blocks_table_is_a_window_too(self):
        out = snap(setup(0, 1012) + '_ipiRenderBlocks();')
        self.assertEqual(out['blk_rows'], 200)
        self.assertFalse(out['bm']['hidden'])
        self.assertIn('<span>In all</span>: 1012', out['bm']['html'])
        self.assertIn('data-arg="blocks"', out['bm']['html'])

    def test_show_more_and_show_all_act_on_the_blocks_only(self):
        out = snap(setup(1000, 1012) + '_ipiRenderAttackers(); _ipiRenderBlocks(); showMoreIpIntel("blocks");')
        self.assertEqual((out['att_rows'], out['blk_rows']), (200, 400))
        out = snap(setup(1000, 1012) + '_ipiRenderAttackers(); _ipiRenderBlocks(); showAllIpIntel("blocks");')
        self.assertEqual((out['att_rows'], out['blk_rows']), (200, 1000))

    def test_a_short_blocks_table_says_nothing(self):
        out = snap(setup(0, 12) + '_ipiRenderBlocks();')
        self.assertEqual(out['blk_rows'], 12)
        self.assertTrue(out['bm']['hidden'])

    def test_no_blocks_is_the_empty_row_and_no_footer(self):
        out = snap(setup(0, 0) + '_ipiRenderBlocks();')
        self.assertIn('No active blocks.', out['blk'])
        self.assertTrue(out['bm']['hidden'])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestLoadAll(unittest.TestCase):
    def run_load(self, script):
        return node('reply = {is_admin: true, attackers: [], blocks: [], sensors: [], settings: {}};' + script)

    def test_the_first_load_asks_for_the_default(self):
        out = self.run_load('await loadIpIntel(); console.log(JSON.stringify(sent));')
        self.assertEqual(out, [{'m': 'GET', 'p': '/ip-intel'}])

    def test_load_all_asks_for_everything_the_server_keeps_and_a_refresh_keeps_asking(self):
        out = self.run_load('await loadAllIpIntel(); await loadIpIntel(); console.log(JSON.stringify(sent));')
        self.assertEqual([r['p'] for r in out], ['/ip-intel?limit=5000', '/ip-intel?limit=5000'])

    def test_the_note_offers_load_all_only_while_the_list_is_cut(self):
        out = node('_ipiData = {attackers: [{}], attackers_total: 4812}; _ipiRenderAttackerNote();'
                   'const n = mk("ipintel-att-note"); console.log(JSON.stringify({h: n.hidden, html: n.innerHTML}));')
        self.assertFalse(out['h'])
        self.assertIn('data-action="loadAllIpIntel"', out['html'])
        self.assertIn('<span>Load all</span>', out['html'])
        out = node('_ipiData = {attackers: [{}, {}], attackers_total: 2}; _ipiRenderAttackerNote();'
                   'const n = mk("ipintel-att-note"); console.log(JSON.stringify({h: n.hidden, html: n.innerHTML}));')
        self.assertTrue(out['h'])
        self.assertEqual(out['html'], '')

    def test_the_numbers_the_page_uses_are_the_servers(self):
        self.assertEqual(node('console.log(_IPI_LOAD_ALL)'), _py_const('ATTACKER_CAP'),
                         'Load all must ask for what the server keeps')
        self.assertEqual(node('console.log(_IPI_ROW_MAX)'), _py_const('PAGE_ROWS'),
                         'the window may grow to what the server sends by default, no further')
        self.assertLess(node('console.log(_IPI_ROW_STEP)'), node('console.log(_IPI_ROW_MAX)'))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWordsAndTheMarkup(unittest.TestCase):
    def test_every_phrase_is_translated(self):
        rows = dict_rows()
        phrases = set(json.loads(subprocess.run(
            ['node', '-e', _const('_IPI_MORE_WORD') + '\nconsole.log(JSON.stringify(Object.values(_IPI_MORE_WORD)));'],
            capture_output=True, text=True, check=True).stdout)) | {'Load all'}
        self.assertEqual(len(phrases), 7)
        for key in sorted(phrases):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_every_word_is_used_and_every_use_is_in_the_table(self):
        words = set(json.loads(subprocess.run(
            ['node', '-e', _const('_IPI_MORE_WORD') + '\nconsole.log(JSON.stringify(Object.keys(_IPI_MORE_WORD)));'],
            capture_output=True, text=True, check=True).stdout))
        src = srcpin.js_function(_JS, '_ipiRenderMore') + srcpin.js_function(_JS, '_ipiRenderAttackers') + \
            srcpin.js_function(_JS, '_ipiRenderBlocks')
        used = set(re.findall(r'_IPI_MORE_WORD\.([a-z_]+)', src)) | set(re.findall(r'\bM\.([a-z_]+)', src))
        self.assertEqual(used - words, set())
        self.assertEqual(words - used, set(), 'a word nobody prints')

    def test_the_footers_are_in_the_page_and_start_hidden(self):
        for ident in ('ipintel-att-more', 'ipintel-blk-more'):
            tag = re.search(r'<p[^>]*id="%s"[^>]*>' % ident, _HTML)
            self.assertTrue(tag, ident)
            self.assertRegex(tag.group(0), r'\shidden[\s>]')
            self.assertIn('class="hint', tag.group(0))

    def test_the_footer_sits_under_its_own_table(self):
        att = _HTML[_HTML.index('id="ipintel-att-tbody"'):]
        self.assertLess(att.index('id="ipintel-att-more"'), att.index('<div class="section-title">Active blocks'))
        blk = _HTML[_HTML.index('id="ipintel-blk-tbody"'):]
        self.assertLess(blk.index('id="ipintel-blk-more"'), blk.index('<div class="section-title">Log sources'))

    def test_the_actions_are_functions_the_dispatcher_can_call(self):
        for fn in ('showMoreIpIntel', 'showAllIpIntel', 'async function loadAllIpIntel'):
            self.assertIn(fn if fn.startswith('async') else 'function ' + fn + '(', _JS)


if __name__ == '__main__':
    unittest.main()
