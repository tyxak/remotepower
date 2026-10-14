"""The Threat intel page's Clear button and the count under the table (v7.3.0).

The same questions as the page's other halves. Does the button exist, for an
administrator only, and ask before it does anything; does it send exactly what the
endpoint reads and print what comes back escaped; does the page say so when the
list it received is not the whole list; and has every phrase six languages.
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-clearpage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
HAVE_NODE = bool(shutil.which('node'))


def _const(name):
    m = re.search(r'^const %s = \{.*?^\};' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    return m.group(0)


def node(script, real_load=False, timeout=30):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
    parts = [
        esc, esca, _const('_IPI_CLEAR_WORD'), _const('_IPI_CLEAR_DIALOG'),
        'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: "", hidden: false});',
        'const document = {getElementById: mk};',
        'let _ipiData = null, _ipiAdmin = false, _ipiWired = false, _ipiRowsAsked = 0; const sent = [], asked = [];',
        'let answer = true, reply = {ok: true}, loads = 0;',
        'async function api(m, p, body) { sent.push({m, p, body}); return reply; }',
        'async function uiConfirm(o) { asked.push(o); return answer; }',
        'const tableCtl = {wireSortOnly() {}};',
        'function _ipiWire() {} function _ipiFillSettings() {} function _ipiRenderAttackers() {}'
        ' function _ipiRenderBlocks() {} function _ipiRenderSources() {} function _ipiRenderEdge() {}'
        ' function _ipiRenderEdgeList() {}',
        srcpin.js_function(_JS, '_ipiPhrase'),
        srcpin.js_function(_JS, '_ipiRenderAttackerNote'),
        srcpin.js_function(_JS, '_ipiClearResultHtml'),
        'async ' + srcpin.js_function(_JS, 'clearIpIntel'),
    ]
    parts.append('async ' + srcpin.js_function(_JS, 'loadIpIntel') if real_load
                 else 'async function loadIpIntel() { loads++; }')
    out = subprocess.run(['node', '-e', '\n'.join(parts) + '\n(async () => {' + script + '})()'],
                         capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def table(name):
    return json.loads(subprocess.run(
        ['node', '-e', _const(name) + '\nconsole.log(JSON.stringify(%s));' % name],
        capture_output=True, text=True, timeout=30, check=True).stdout)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWords(unittest.TestCase):
    def test_every_word_is_used_and_every_use_is_in_the_table(self):
        words = set(table('_IPI_CLEAR_WORD'))
        src = ''.join(srcpin.js_function(_JS, f) for f in
                      ('_ipiRenderAttackerNote', '_ipiClearResultHtml', 'clearIpIntel'))
        used = set(re.findall(r'\bCW\.([a-z_]+)', src)) | set(re.findall(r'_IPI_CLEAR_WORD\.([a-z_]+)', src))
        self.assertEqual(used - words, set(), 'a word the page prints that is not in the table')
        self.assertEqual(words - used, set(), 'a word nobody prints')

    def test_every_phrase_is_translated(self):
        rows = dict_rows()
        phrases = set(table('_IPI_CLEAR_WORD').values()) | {'Clear'}
        for d in table('_IPI_CLEAR_DIALOG').values():
            phrases |= set(d.values())
        self.assertGreaterEqual(len(phrases), 9, len(phrases))
        for key in sorted(phrases):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)


class TestTheButton(unittest.TestCase):
    def card(self):
        i = _HTML.index('<div class="section-title">Attackers</div>')
        return _HTML[i:_HTML.index('<div class="section-title">Active blocks</div>')]

    def test_it_sits_in_the_attackers_toolbar_with_an_icon_and_a_label(self):
        card = self.card()
        m = re.search(r'<button[^>]*id="ipintel-clear-btn"[^>]*>(.*?)</button>', card, re.S)
        self.assertTrue(m, 'no Clear button in the Attackers card')
        tag = m.group(0)
        self.assertIn('data-action="clearIpIntel"', tag)
        self.assertRegex(tag, r'<svg aria-hidden="true"[^>]*><use href="#ic-a93e5032"/></svg>')
        self.assertTrue(m.group(1).rstrip().endswith('Clear'), 'a visible label, not an icon alone')
        self.assertNotIn('onclick', tag)
        self.assertNotIn('style=', tag)

    def test_it_starts_hidden_so_a_non_administrator_never_sees_it(self):
        tag = re.search(r'<button[^>]*id="ipintel-clear-btn"[^>]*>', self.card()).group(0)
        self.assertRegex(tag, r'\shidden[\s>]')

    def test_the_answer_is_announced(self):
        tag = re.search(r'<div[^>]*id="ipintel-clear-result"[^>]*>', self.card()).group(0)
        self.assertIn('role="status"', tag)
        self.assertIn('aria-live="polite"', tag)

    def test_the_action_is_a_function_the_dispatcher_can_call(self):
        self.assertIn('async function clearIpIntel()', _JS)

    def test_the_page_sends_nothing_the_endpoint_does_not_read(self):
        from request_models import IpIntelClearRequest
        self.assertEqual(set(IpIntelClearRequest.model_fields), set())
        self.assertIn("api('POST', '/ip-intel/clear', {})", srcpin.js_function(_JS, 'clearIpIntel'))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatTheButtonDoes(unittest.TestCase):
    def test_it_asks_first_and_a_refusal_changes_nothing(self):
        out = node('answer = false; await clearIpIntel();'
                   'console.log(JSON.stringify({sent, asked, loads, result: mk("ipintel-clear-result").innerHTML}));')
        self.assertEqual((out['sent'], out['loads'], out['result']), ([], 0, ''))
        self.assertEqual(len(out['asked']), 1)
        ask = out['asked'][0]
        self.assertTrue(ask['danger'])
        self.assertEqual(ask['confirmText'], 'Clear')
        for fixed in ('Blocks and bans stay', 'edge blocklist', 'reported twice'):
            self.assertIn(fixed, ask['message'], 'the dialog must say what it leaves')

    def test_a_yes_clears_says_what_went_and_reloads(self):
        out = node('reply = {ok: true, cleared: 812, queue: 37, kept_listed: 14, remembered: 5};'
                   'await clearIpIntel();'
                   'console.log(JSON.stringify({sent, loads, result: mk("ipintel-clear-result").innerHTML}));')
        self.assertEqual(out['sent'], [{'m': 'POST', 'p': '/ip-intel/clear', 'body': {}}])
        self.assertEqual(out['loads'], 1)
        html = out['result']
        self.assertIn('<span>Addresses cleared</span>: 812', html)
        self.assertIn('<span>Waiting to be looked up, cleared</span>: 37', html)
        self.assertIn('<span>Kept because the edge blocklist uses them</span>: 14', html)
        self.assertIn('<span>Remembered for a day so they are not reported twice</span>: 5', html)

    def test_a_line_for_something_that_did_not_happen_is_not_printed(self):
        out = node('reply = {ok: true, cleared: 3, queue: 0, kept_listed: 0, remembered: 0};'
                   'await clearIpIntel(); console.log(JSON.stringify({html: mk("ipintel-clear-result").innerHTML}));')
        self.assertIn('Addresses cleared', out['html'])
        for absent in ('Waiting to be looked up', 'Kept because', 'Remembered for a day'):
            self.assertNotIn(absent, out['html'])

    def test_a_refusal_is_shown_and_nothing_reloads(self):
        out = node("reply = {error: 'Admins only'}; await clearIpIntel();"
                   "console.log(JSON.stringify({loads, text: mk('ipintel-clear-result').textContent}));")
        self.assertEqual((out['loads'], out['text']), (0, 'Admins only'))
        out = node("reply = null; await clearIpIntel();"
                   "console.log(JSON.stringify({loads, text: mk('ipintel-clear-result').textContent}));")
        self.assertEqual((out['loads'], out['text']), (0, 'Could not clear'))

    def test_what_comes_back_is_a_number_and_is_escaped(self):
        out = node("reply = {ok: true, cleared: '<img src=x onerror=alert(1)>', queue: '<b>9</b>'};"
                   "await clearIpIntel(); console.log(JSON.stringify({html: mk('ipintel-clear-result').innerHTML}));")
        self.assertNotIn('<img', out['html'])
        self.assertNotIn('<b>', out['html'])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestOnlyAnAdministratorSeesIt(unittest.TestCase):
    def shown(self, is_admin):
        out = node('mk("ipintel-clear-btn").hidden = true;'
                   'reply = {is_admin: %s, attackers: [], blocks: [], sensors: [], settings: {}};'
                   'await loadIpIntel();'
                   'console.log(JSON.stringify({hidden: mk("ipintel-clear-btn").hidden}));'
                   % ('true' if is_admin else 'false'), real_load=True)
        return not out['hidden']

    def test_an_administrator_sees_it(self):
        self.assertTrue(self.shown(True))

    def test_anyone_else_does_not(self):
        self.assertFalse(self.shown(False))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheCountUnderTheTable(unittest.TestCase):
    def note(self, data):
        return node('_ipiData = %s; _ipiRenderAttackerNote();'
                    'const n = mk("ipintel-att-note");'
                    'console.log(JSON.stringify({hidden: n.hidden, html: n.innerHTML}));' % json.dumps(data))

    def test_a_cut_list_says_how_many_there_are(self):
        out = self.note({'attackers': [{}] * 1000, 'attackers_total': 4812})
        self.assertFalse(out['hidden'])
        self.assertTrue(out['html'].startswith(
            '<span>Most recent shown</span>: 1000 · <span>Recorded in all</span>: 4812 '), out['html'])
        self.assertIn('data-action="loadAllIpIntel"', out['html'])

    def test_a_whole_list_says_nothing(self):
        for data in ({'attackers': [{}] * 7, 'attackers_total': 7}, {'attackers': [], 'attackers_total': 0},
                     {'attackers': [{}] * 3}):
            out = self.note(data)
            self.assertTrue(out['hidden'], data)
            self.assertEqual(out['html'], '')

    def test_the_note_is_written_on_every_render(self):
        src = srcpin.js_function(_JS, '_ipiRenderAttackers')
        self.assertIn('_ipiRenderAttackerNote();', src)
        self.assertLess(src.index('_ipiRenderAttackerNote();'), src.index('if (!rows.length)'),
                        'before the empty-list return, or a filter that matches nothing hides the count')

    def test_the_note_element_is_in_the_page_and_starts_hidden(self):
        tag = re.search(r'<p[^>]*id="ipintel-att-note"[^>]*>', _HTML).group(0)
        self.assertRegex(tag, r'\shidden[\s>]')
        self.assertIn('class="hint', tag)


if __name__ == '__main__':
    unittest.main()
