"""The page half of the ignore list (v7.3.0): the two settings, the Ignore button on a
row, and what a row says about an address that is on the list.

Same questions as the page's other halves. Is every phrase in six languages, does
the button appear only where it can do something, does it ask first and send exactly
what the endpoint reads, and does the page offer exactly the kinds of attack the
server knows (a class the page offered and the server refused would be a save that
silently fails).
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

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-ignorepage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
import threat_evidence  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_CSS = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
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


def node(script, timeout=30):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
    parts = [
        esc, esca, _const('_IPI_CLASS'), _const('_IPI_IGNORE_WORD'), _const('_IPI_IGNORE_DIALOG'),
        _const('_IPI_MORE_WORD'), _line('_IPI_ROW_STEP'), _line('_IPI_ROW_MAX'), _line('_ipiRowLimit'),
        'const els = {}; const mk = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: "", hidden: false,'
        ' checked: false, addEventListener(t, f) { (this._h = this._h || {})[t] = f; }});',
        'const document = {getElementById: mk};',
        'let _ipiData = {attackers: [], blocks: [], can_ignore: true}, _ipiWired = false; const _ipiOpen = new Set();'
        ' const sent = [], asked = [], toasts = []; let answer = true, reply = {ok: true}, loads = 0;',
        'async function api(m, p, body) { sent.push({m, p, body}); return reply; }',
        'async function uiConfirm(o) { asked.push(o); return answer; }',
        'function toast(t, k) { toasts.push([t, k]); } function loadIpIntel() { loads++; }',
        'const tableCtl = {wireSortOnly() {}, sortRows(n, rows) { return rows; }};',
        'function _ipiEvidenceHtml() { return ""; } function _ipiEvidenceText() { return ""; }'
        ' function _ipiEvidenceWeight() { return 0; } function _ipiDetailHtml() { return ""; }'
        ' function _ipiScoreClass() { return ""; } function timeAgo() { return ""; } function timeAgoHtml() { return ""; }'
        ' function _ipiRenderAttackerNote() {} function openIpIntelBan() {} function unbanIpIntel() {}'
        ' function blockIpIntel() {}',
        'const _IPI_BAN_WORD = {in_list: "in the edge blocklist", edge_ban: "banned at the edge", edge_wait: "w"};',
        srcpin.js_function(_JS, '_ipiPhrase'),
        srcpin.js_function(_JS, '_ipiWindow'),
        srcpin.js_function(_JS, '_ipiRenderMore'),
        srcpin.js_function(_JS, '_ipiNotBlockedReason'),
        srcpin.js_function(_JS, '_ipiEdgeState'),
        srcpin.js_function(_JS, '_ipiReason'),
        srcpin.js_function(_JS, '_ipiStatus'),
        srcpin.js_function(_JS, '_ipiStatusHtml'),
        srcpin.js_function(_JS, '_ipiClassName'),
        srcpin.js_function(_JS, '_ipiRenderIgnoreClasses'),
        srcpin.js_function(_JS, '_ipiIgnoredClasses'),
        srcpin.js_function(_JS, '_ipiRenderAttackers'),
        srcpin.js_function(_JS, '_ipiWire'),
        'async ' + srcpin.js_function(_JS, 'ignoreIpIntel'),
    ]
    out = subprocess.run(['node'], input='\n'.join(parts) + '\n(async () => {' + script + '})()',
                         capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def row(ip='203.0.113.9', **kw):
    return dict({'ip': ip, 'reported': {}, 'errors': {}, 'devices': [], 'score': 40}, **kw)


def actions(attackers, can_ignore=True):
    d = {'attackers': attackers, 'blocks': [], 'can_ignore': can_ignore, 'attackers_total': len(attackers)}
    out = node('_ipiData = %s; _ipiRenderAttackers(); console.log(JSON.stringify(mk("ipintel-att-tbody").innerHTML));'
               % json.dumps(d))
    return out


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWords(unittest.TestCase):
    def test_every_word_is_used_and_every_use_is_in_the_table(self):
        words = set(node('console.log(JSON.stringify(Object.keys(_IPI_IGNORE_WORD)));'))
        src = srcpin.js_function(_JS, 'ignoreIpIntel')
        used = set(re.findall(r'_IPI_IGNORE_WORD\.([a-z_]+)', src))
        self.assertEqual(used - words, set(), 'a word the page prints that is not in the table')
        self.assertEqual(words - used, set(), 'a word nobody prints')

    def test_every_phrase_is_translated(self):
        rows = dict_rows()
        phrases = set(node('console.log(JSON.stringify(Object.values(_IPI_IGNORE_WORD)));'))
        for d in node('console.log(JSON.stringify(_IPI_IGNORE_DIALOG));').values():
            phrases |= set(d.values())
        # the two reasons the server sends, one of them also printed by the status builders
        phrases |= {'only attacks you ignore', 'on the ignore list'}
        for key in sorted(phrases):
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_the_static_labels_and_hints_are_translated(self):
        rows = dict_rows()
        card = _HTML[_HTML.index('id="ipintel-ignore"') - 300:_HTML.index('id="ipintel-ignore-classes"') + 700]
        texts = []
        texts += re.findall(r'<label[^>]*for="ipintel-ignore"[^>]*>(.*?)</label>', card, re.S)
        texts += re.findall(r'<div class="form-label">(.*?)</div>', card, re.S)
        texts += re.findall(r'<p class="hint">(.*?)</p>', card, re.S)
        texts = [re.sub(r'\s+', ' ', t).strip() for t in texts]
        for key in ('Never report these addresses (one address or network per line)',
                    'Never report an address when all it did was'):
            self.assertIn(key, texts)
        self.assertGreaterEqual(len(texts), 4, texts)
        for key in texts:
            self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_the_status_builders_print_the_servers_phrase_word_for_word(self):
        server = (_ROOT / 'server' / 'cgi-bin' / 'ip_intel.py').read_text()
        self.assertIn("return 'on the ignore list'", server)
        for fn in ('_ipiStatus', '_ipiStatusHtml'):
            body = srcpin.js_function(_JS, fn)
            self.assertIn("'on the ignore list'", body, fn)
            self.assertIn("'not reported: on the ignore list'", body, fn)

    def test_both_server_reasons_come_from_one_function_the_status_test_reads(self):
        """tests/test_v710_ipintel_status derives the reasons from named functions;
        ignore_reason must be one of them or a new reason ships untranslated."""
        src = (_ROOT / 'tests' / 'test_v710_ipintel_status.py').read_text()
        self.assertIn("'ignore_reason'", src)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheKindsOffered(unittest.TestCase):
    def test_the_page_offers_exactly_the_kinds_the_server_knows(self):
        offered = set(node('console.log(JSON.stringify(Object.keys(_IPI_CLASS)));'))
        self.assertEqual(offered, set(threat_evidence.CLASSES))

    def test_the_boxes_are_made_from_that_table_and_the_saved_ones_are_ticked(self):
        out = node('_ipiRenderIgnoreClasses(["bad_bot", "probe"]);'
                   'console.log(JSON.stringify(mk("ipintel-ignore-classes").innerHTML));')
        ids = re.findall(r'data-ipi-class="([a-z_]+)"', out)
        self.assertEqual(set(ids), set(threat_evidence.CLASSES))
        ticked = re.findall(r'data-ipi-class="([a-z_]+)" checked', out)
        self.assertEqual(set(ticked), {'bad_bot', 'probe'})
        self.assertIn('<span>unwanted web crawling</span>', out, 'a phrase of its own, so the engine can translate it')

    def test_what_is_ticked_is_what_is_sent(self):
        out = node('_ipiRenderIgnoreClasses(["bad_bot", "xss"]);'
                   'const box = mk("ipintel-ignore-classes");'
                   'box.querySelectorAll = () => [...box.innerHTML.matchAll(/data-ipi-class="([a-z_]+)"( checked)?/g)]'
                   '.map(m => ({dataset: {ipiClass: m[1]}, checked: !!m[2]}));'
                   'console.log(JSON.stringify(_ipiIgnoredClasses()));')
        self.assertEqual(sorted(out), ['bad_bot', 'xss'])

    def test_a_missing_container_is_not_a_crash(self):
        out = node('delete els["ipintel-ignore-classes"]; const real = document.getElementById;'
                   'document.getElementById = id => id === "ipintel-ignore-classes" ? null : real(id);'
                   '_ipiRenderIgnoreClasses([]); console.log(JSON.stringify(_ipiIgnoredClasses()));')
        self.assertEqual(out, [])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheRowButton(unittest.TestCase):
    def test_it_is_on_a_row_the_list_does_not_cover(self):
        html = actions([row(ignored=False)])
        self.assertIn('data-ipi-ignore="203.0.113.9"', html)
        self.assertRegex(html, r'data-ipi-ignore="203\.0\.113\.9" aria-label="Ignore"><svg aria-hidden="true"')

    def test_not_on_a_row_the_list_already_covers(self):
        self.assertNotIn('data-ipi-ignore', actions([row(ignored=True)]))

    def test_not_for_someone_who_may_not_change_the_list(self):
        self.assertNotIn('data-ipi-ignore', actions([row(ignored=False)], can_ignore=False))

    def test_the_address_is_escaped_in_the_attribute(self):
        html = actions([row(ip='"><img src=x onerror=alert(1)>', ignored=False)])
        self.assertNotIn('<img', html)

    def test_a_click_asks_about_the_address_on_the_row(self):
        out = node('_ipiData = %s; _ipiWire();'
                   'const tb = mk("ipintel-att-tbody");'
                   'tb._h.click({target: {closest: s => s === "button[data-ipi-ignore]" ? {dataset: {ipiIgnore: "198.51.100.4"}} : null}});'
                   'await new Promise(r => setTimeout(r, 20));'
                   'console.log(JSON.stringify({sent, asked: asked.length}));'
                   % json.dumps({'attackers': [], 'blocks': [], 'can_ignore': True}))
        self.assertEqual(out['asked'], 1)
        self.assertEqual(out['sent'], [{'m': 'POST', 'p': '/ip-intel/ignore', 'body': {'ip': '198.51.100.4'}}])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatTheButtonDoes(unittest.TestCase):
    def test_it_asks_first_and_a_refusal_changes_nothing(self):
        out = node('answer = false; await ignoreIpIntel("203.0.113.9");'
                   'console.log(JSON.stringify({sent, asked, loads, toasts}));')
        self.assertEqual((out['sent'], out['loads'], out['toasts']), ([], 0, []))
        ask = out['asked'][0]
        self.assertEqual(ask['confirmText'], 'Ignore')
        self.assertIn('not report', ask['message'])
        self.assertIn('never-block list', ask['message'], 'it must say what it does not do')

    def test_a_yes_sends_the_address_and_reloads(self):
        out = node('await ignoreIpIntel("203.0.113.9");'
                   'console.log(JSON.stringify({sent, loads, toasts}));')
        self.assertEqual(out['sent'], [{'m': 'POST', 'p': '/ip-intel/ignore', 'body': {'ip': '203.0.113.9'}}])
        self.assertEqual((out['loads'], out['toasts']), (1, [['Ignored', 'success']]))

    def test_a_refusal_is_shown_and_nothing_reloads(self):
        out = node('reply = {error: "The ignore list is managed by the platform operator."};'
                   'await ignoreIpIntel("203.0.113.9"); console.log(JSON.stringify({loads, toasts}));')
        self.assertEqual(out['loads'], 0)
        self.assertEqual(out['toasts'], [['The ignore list is managed by the platform operator.', 'error']])
        out = node('reply = null; await ignoreIpIntel("203.0.113.9"); console.log(JSON.stringify({loads, toasts}));')
        self.assertEqual(out['toasts'], [['Could not ignore this address', 'error']])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatTheRowSays(unittest.TestCase):
    def status(self, a):
        return node('_ipiData = %s; console.log(JSON.stringify({html: _ipiStatusHtml(%s), text: _ipiStatus(%s)}));'
                    % (json.dumps({'blocks': []}), json.dumps(a), json.dumps(a)))

    def test_an_ignored_row_says_so_once_as_a_phrase_of_its_own(self):
        a = row(ignored=True, errors={'abuseipdb': 'not reported: on the ignore list',
                                      'sniffcat': 'not reported: on the ignore list'})
        out = self.status(a)
        self.assertEqual(out['html'].count('on the ignore list'), 1)
        self.assertIn('<span>on the ignore list</span>', out['html'])
        self.assertEqual(out['text'].count('on the ignore list'), 1)

    def test_a_different_refusal_is_still_shown_next_to_it(self):
        a = row(ignored=True, errors={'abuseipdb': 'HTTP 429'})
        out = self.status(a)
        self.assertIn('<span>on the ignore list</span>', out['html'])
        self.assertIn('abuseipdb: ', out['html'])

    def test_the_kind_reason_is_a_phrase_after_not_reported(self):
        a = row(errors={'abuseipdb': 'not reported: only attacks you ignore'})
        out = self.status(a)
        self.assertIn('<span>not reported:</span> <span>only attacks you ignore</span>', out['html'])

    def test_a_row_that_is_not_ignored_says_nothing_of_it(self):
        self.assertNotIn('ignore', self.status(row(ignored=False))['html'])


class TestTheMarkupAndTheRequest(unittest.TestCase):
    def test_the_two_settings_are_in_the_providers_limits_card_and_the_grid_is_capped(self):
        card = _HTML[_HTML.index('id="ipintel-never"'):]
        card = card[:card.index('id="ipintel-budget"')]
        self.assertIn('id="ipintel-ignore"', card)
        self.assertIn('id="ipintel-ignore-classes"', card)
        tag = re.search(r'<div[^>]*id="ipintel-ignore-classes"[^>]*>', card).group(0)
        self.assertIn('scroll-cap', tag, 'a variable-height box is capped (CLAUDE.md box rule)')
        self.assertNotRegex(card, r'\son[a-z]+\s*=')
        self.assertNotRegex(card, r'\sstyle\s*=')

    def test_the_checkbox_row_has_styles_and_stays_on_the_type_scale(self):
        self.assertIn('.ipi-ignore-classes {', _CSS)
        rule = re.search(r'\.ipi-ignore-class \{[^}]*\}', _CSS).group(0)
        self.assertIn('font-size: 13px', rule)

    def test_save_sends_both_lists_and_the_server_reads_both(self):
        from request_models import IpIntelSettingsRequest
        save = srcpin.js_function(_JS, 'saveIpIntelSettings')
        self.assertIn("ignore_addresses: v('ipintel-ignore').value", save)
        self.assertIn('ignore_classes: _ipiIgnoredClasses()', save)
        self.assertTrue({'ignore_addresses', 'ignore_classes'} <= set(IpIntelSettingsRequest.model_fields))

    def test_the_ignore_request_has_the_one_field_the_page_sends(self):
        from request_models import IpIntelIgnoreRequest
        self.assertEqual(set(IpIntelIgnoreRequest.model_fields), {'ip'})
        self.assertIn("api('POST', '/ip-intel/ignore', {ip})", srcpin.js_function(_JS, 'ignoreIpIntel'))

    def test_the_settings_load_fills_both(self):
        fill = srcpin.js_function(_JS, '_ipiFillSettings')
        self.assertIn("set('ipintel-ignore', (s.ignore_addresses || []).join('\\n'))", fill)
        self.assertIn('_ipiRenderIgnoreClasses(s.ignore_classes || [])', fill)


if __name__ == '__main__':
    unittest.main()
