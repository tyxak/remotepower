"""The Threat intel page's Edge blocklist card (v7.3.0).

Four questions, the same as the other halves of this page:

  - do the words the page has match what the server sends (derived from the
    server's source, so a new state or reason on either side cannot reach the
    screen as a raw id or an untranslated sentence);
  - has every phrase six languages;
  - is everything the page prints from the server escaped, because a provider's or
    Cloudflare's error sentence and a list name are free text;
  - do the buttons do what they say: Preview writes nothing, Sync now asks before
    it takes over a list RemotePower did not create, and Sync anyway asks.
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-listpage-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import edge_blocklist as eb  # noqa: E402
import ip_intel  # noqa: E402
import srcpin  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-ipintel.js').read_text()
_APP = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_HANDLERS_PATH = _ROOT / 'server' / 'cgi-bin' / 'edge_blocklist_handlers.py'
_HANDLERS = _HANDLERS_PATH.read_text()
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')
HAVE_NODE = bool(shutil.which('node'))


def _const(name):
    m = re.search(r'^const %s = [\[{].*?^[\]}];' % re.escape(name), _JS, re.S | re.M)
    assert m, name
    return m.group(0)


def node(script, timeout=30):
    esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
    prelude = '\n'.join([
        esc,
        _const('_IPI_LIST_STATE'), _const('_IPI_LIST_STATE_CLASS'), _const('_IPI_LIST_SRC'),
        _const('_IPI_LIST_WORD'), _const('_IPI_LIST_DIALOG'), _const('_IPI_LIST_WHY'), _const('_IPI_EDGE_DIALOG'),
        'const els = {}; const el = id => (els[id] = els[id] || {innerHTML: "", textContent: "", value: "", checked: false, hidden: false});',
        'const document = {getElementById: el};',
        'function timeAgo(t) { return t ? "5m ago" : "never"; }',
        'function timeAgoHtml(t) { return t ? "5m ago" : "never"; }',
        'let _ipiData = null; const sent = []; const asked = []; let answer = true; let reply = {ok: true, result: {state: "ok"}}; let replies = null;',
        'async function api(m, p, body) { sent.push({m, p, body}); return replies ? replies.shift() : reply; }',
        'async function uiConfirm(o) { asked.push(o); return answer; }',
        'function toast() {} function loadIpIntel() {}',
        srcpin.js_function(_JS, '_ipiPhrase'),
        srcpin.js_function(_JS, '_ipiListCurrent'), srcpin.js_function(_JS, '_ipiListNeedsAdopt'),
        srcpin.js_function(_JS, '_ipiListSrc'), srcpin.js_function(_JS, '_ipiListWhy'),
        srcpin.js_function(_JS, '_ipiRenderEdgeList'),
        'async ' + srcpin.js_function(_JS, 'previewIpIntelList'),
        'async ' + srcpin.js_function(_JS, '_ipiSyncList'), 'async ' + srcpin.js_function(_JS, '_ipiConfirmAdopt'),
        'async ' + srcpin.js_function(_JS, 'syncIpIntelList'),
        'async ' + srcpin.js_function(_JS, 'syncIpIntelListForce'),
        'async ' + srcpin.js_function(_JS, 'clearIpIntelListToken'),
        'async ' + srcpin.js_function(_JS, 'clearIpIntelEdgeToken')])
    out = subprocess.run(['node', '-e', prelude + '\n(async () => {' + script + '})()'],
                         capture_output=True, text=True, timeout=timeout)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def table(name):
    return node(f'console.log(JSON.stringify({name}));')


def _server_sentences():
    """Every sentence the server can put in a result's `why`: the string constants of
    the handler module and of hold_reason() that end in a full stop and have at least
    three words, leaving out docstrings and anything handed to respond() or
    audit_log(), which are not reasons."""
    out = set()

    def walk(node, skip=False):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ('respond', 'audit_log'):
            return
        # what the ban endpoint says when the edge cannot take a ban is an error text
        # shown by the dialog, not one of the card's reasons
        if isinstance(node, ast.FunctionDef) and node.name == '_edge_not_ready':
            return
        if isinstance(node, (ast.FunctionDef, ast.Module)) and node.body and isinstance(node.body[0], ast.Expr) \
                and isinstance(getattr(node.body[0], 'value', None), ast.Constant):
            body = node.body[1:]
        else:
            body = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value
            if v.endswith('.') and len(v.split()) >= 3 and v[:1].isupper():
                out.add(v)
        for child in (body if body is not None else ast.iter_child_nodes(node)):
            walk(child)

    walk(ast.parse(_HANDLERS))
    src = Path(eb.__file__).read_text()
    for fn in ast.parse(src).body:
        if isinstance(fn, ast.FunctionDef) and fn.name == 'hold_reason':
            for ret in ast.walk(fn):
                if isinstance(ret, ast.Return) and isinstance(ret.value, ast.Constant) \
                        and isinstance(ret.value.value, str) and ret.value.value.endswith('.'):
                    out.add(ret.value.value)
    return out


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheWordsMatchTheServer(unittest.TestCase):
    def test_every_state_the_server_writes_has_words(self):
        written = set(re.findall(r"state='([a-z_]+)'", _HANDLERS)) | set(re.findall(r"'state': '([a-z_]+)'", _HANDLERS))
        self.assertGreaterEqual(len(written), 6, written)
        shown = set(table('_IPI_LIST_STATE'))
        self.assertEqual(written - shown, set(), 'a state the page cannot say')
        self.assertEqual(shown - written, {'waiting'}, 'what the page adds for itself')
        self.assertEqual(set(table('_IPI_LIST_STATE_CLASS')), shown)

    def test_every_source_the_server_builds_from_has_a_name(self):
        self.assertEqual(set(table('_IPI_LIST_SRC')), set(eb.SOURCES))

    def test_every_sentence_the_server_gives_as_a_reason_has_a_translation_slot(self):
        sentences = _server_sentences()
        # the control: the instrument sees the sentences it exists to see
        for must in ('Nothing would be left in the list.', 'The list would shrink by more than half.',
                     'A source did not answer and has no recent copy.', 'Cloudflare did not answer.'):
            self.assertIn(must, sentences)
        self.assertGreaterEqual(len(sentences), 12, sentences)
        self.assertEqual(set(table('_IPI_LIST_WHY')), sentences)

    def test_every_word_in_the_table_is_used_and_every_use_is_in_the_table(self):
        words = set(table('_IPI_LIST_WORD'))
        used = set(re.findall(r'\b(?:W|_IPI_LIST_WORD)\.([a-z_]+)', _JS))
        self.assertEqual(used - words, set(), 'a word the page prints that is not in the table')
        self.assertEqual(words - used, set(), 'a word nobody prints')

    def test_the_panel_claims_in_the_dialogs_are_the_ones_the_server_enforces(self):
        """The dialog for Sync anyway names two reasons a sync is held; hold_reason()
        and the failed-source check are the two."""
        msg = table('_IPI_LIST_DIALOG')['force']['message']
        self.assertIn('empty or halve', msg)
        self.assertIn('did not answer', msg)
        self.assertEqual(eb.SHRINK_FLOOR, 0.5)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestEveryPhraseIsTranslated(unittest.TestCase):
    STATIC_HTML = (
        'Edge blocklist', 'Keep a Cloudflare IP list up to date', 'Cloudflare API token (can edit lists)',
        'List name', 'Addresses RemotePower found', "AbuseIPDB's blacklist", "SniffCat's blacklist",
        'Found addresses: score of at least', 'Found addresses: seen within (days)',
        'AbuseIPDB: confidence of at least', 'AbuseIPDB: most addresses',
        'SniffCat: confidence of at least', 'SniffCat: most addresses',
        'Update every (hours)', 'Most entries in the list',
        'Always include (one address or network per line)', 'Preview', 'Sync now', 'Remove token',
    )
    HINTS = (
        'RemotePower can keep one Cloudflare IP list up to date from the sources you pick, so a rule that '
        'uses the list keeps blocking what they report. It writes the list and nothing else; the rules that '
        'use it stay yours. It needs its own token, one that can edit lists, and it is off until you turn it on.',
        'The account id is the one under Edge sources. The list is created if it does not exist. A list that '
        'RemotePower did not create is left alone until you tell it to take the list over.',
        'Public addresses and networks only, and nothing wider than /16 for IPv4 or /32 for IPv6. Your own '
        "hosts, your never-block list and Cloudflare's addresses are always left out, whatever a source says.",
        'Save first: Preview and Sync now use what is saved. Preview shows what a sync would change and '
        'writes nothing.',
    )

    def _has_six(self, rows, key):
        self.assertTrue(rows.get(key) and all(rows[key].get(l) for l in _LANGS), 'no six languages: ' + key)

    def test_the_static_labels_and_hints_are_in_the_page_and_translated(self):
        rows = dict_rows()
        for key in self.STATIC_HTML + self.HINTS:
            self.assertIn(key, _HTML, key)
            self._has_six(rows, key)

    def test_every_phrase_the_script_prints_is_translated(self):
        rows = dict_rows()
        phrases = set(table('_IPI_LIST_WHY'))
        phrases |= {v for k, v in table('_IPI_LIST_STATE').items()}
        phrases |= {v for k, v in table('_IPI_LIST_SRC').items() if k in ('always', 'own')}
        phrases |= set(table('_IPI_LIST_WORD').values())
        for d in list(table('_IPI_LIST_DIALOG').values()) + list(table('_IPI_EDGE_DIALOG').values()):
            phrases |= set(d.values())
        phrases |= {'Saved', 'Could not save'}
        # the control: the population is the one this test exists to cover
        self.assertGreaterEqual(len(phrases), 45, len(phrases))
        for must in ('Sync anyway', 'Take over this list', 'In the list now', 'saved copy'):
            self.assertIn(must, phrases)
        for key in sorted(phrases):
            self._has_six(rows, key)

    def test_a_translation_is_not_the_english_with_a_language_label(self):
        """A copy of the English in a language slot is a missing translation that
        looks present. Brand names and numbers aside, no phrase may be identical to
        its English in every language."""
        rows = dict_rows()
        for key in ('Edge blocklist', 'Take over this list', 'In the list now', 'Held'):
            same = [l for l in _LANGS if rows[key][l] == key]
            self.assertEqual(same, [], key)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestWhatIsPrinted(unittest.TestCase):
    LAST = {
        'mode': 'apply', 'at': 100, 'state': 'ok', 'changed': True, 'created': False,
        'list': {'name': 'tyxak_cf_waf', 'id': 'a' * 32, 'exists': True, 'items': 9079, 'managed': True},
        'capacity': 10000, 'current': 9079, 'size': 9500, 'added': 421, 'removed': 0, 'trimmed': 12,
        'dropped': {'protected': 3},
        'kept': {'always': 2, 'own': 30, 'abuseipdb': 7000, 'sniffcat': 2468},
        'sources': {'abuseipdb': {'from': 'download', 'at': 90, 'n': 7000, 'error': ''},
                    'sniffcat': {'from': 'copy', 'at': 40, 'n': 2500, 'error': 'SniffCat answered HTTP 500'}},
        'failed': {}, 'added_sample': ['1.2.3.4', '5.6.7.0/24'], 'removed_sample': [],
    }

    def render(self, el):
        return node('''_ipiData = {edge_list: %s};
          _ipiRenderEdgeList();
          console.log(JSON.stringify(els["ipintel-edgelist-status"].innerHTML));''' % json.dumps(el))

    def test_a_finished_sync(self):
        h = self.render({'enabled': True, 'last': self.LAST, 'preview': {}})
        self.assertIn('<span class="c-green"><span>Up to date</span></span> · 5m ago', h)
        self.assertIn('<span>In the list now</span> 9079', h)
        self.assertIn('<span>Should hold</span> 9500', h)
        self.assertIn('<span>Added</span> 421', h)
        self.assertIn('<span>Room in the account</span> 10000', h)
        self.assertIn('<span>Left out for lack of room</span> 12', h)
        self.assertIn('<span>Left out as protected</span> 3', h)
        self.assertIn('<span>Managed by RemotePower</span>', h)
        self.assertIn('AbuseIPDB: 7000 <span>addresses</span> · 5m ago · <span>downloaded</span>', h)
        self.assertIn('SniffCat: 2500 <span>addresses</span> · 5m ago · <span>saved copy</span> · SniffCat answered HTTP 500', h)
        self.assertIn('+ 1.2.3.4<br>+ 5.6.7.0/24', h)
        self.assertNotIn('data-action', h, 'nothing to override when nothing was held')

    def test_a_held_sync_offers_the_override_and_says_why(self):
        held = dict(self.LAST, state='held', changed=None, can_force=True,
                    why='The list would shrink by more than half.')
        h = self.render({'enabled': True, 'last': held, 'preview': {}})
        self.assertIn('<span class="c-amber"><span>Held</span></span>', h)
        self.assertIn('<span>The list would shrink by more than half.</span>', h)
        self.assertEqual(h.count('data-action="syncIpIntelListForce"'), 1)
        self.assertIn('<span>Sync anyway</span>', h)

    def test_a_failure_with_no_override_has_no_button(self):
        err = dict(self.LAST, state='error', why='Cloudflare could not apply the change.', can_force=False)
        h = self.render({'enabled': True, 'last': err, 'preview': {}})
        self.assertNotIn('data-action', h)
        held = dict(self.LAST, state='held', can_force=False, why='x')
        self.assertNotIn('data-action', self.render({'enabled': True, 'last': held, 'preview': {}}))

    def test_a_list_that_is_not_ours_is_said_so(self):
        foreign = {'mode': 'apply', 'at': 100, 'state': 'needs_adopt',
                   'why': 'A list with this name exists and RemotePower did not create it.',
                   'list': {'name': 'tyxak_cf_waf', 'exists': True, 'managed': False, 'items': 9079}}
        h = self.render({'enabled': True, 'last': foreign, 'preview': {}})
        self.assertIn('<span>Needs to be taken over</span>', h)
        self.assertIn('<span>Not created by RemotePower</span>', h)
        self.assertEqual(h.count('A list with this name exists and RemotePower did not create it.'), 1)

    def test_a_list_that_is_not_ours_says_how_many_entries_it_holds(self):
        foreign = {'mode': 'apply', 'at': 100, 'state': 'needs_adopt',
                   'why': 'A list with this name exists and RemotePower did not create it.',
                   'list': {'name': 'tyxak_cf_waf', 'exists': True, 'managed': False, 'items': 9079}}
        h = self.render({'enabled': True, 'last': foreign, 'preview': {}})
        self.assertIn('<code>tyxak_cf_waf</code> · <span>Not created by RemotePower</span> · 9079 <span>entries</span>', h)
        missing = dict(foreign, list={'name': 'new_list', 'exists': False, 'managed': False, 'items': 0})
        h = self.render({'enabled': True, 'last': missing, 'preview': {}})
        self.assertIn('<span>Does not exist yet</span>', h)
        self.assertNotIn('<span>entries</span>', h, 'a list that is not there has no size to give')

    def test_the_newer_of_preview_and_sync_is_shown(self):
        pre = dict(self.LAST, mode='preview', at=200, state='preview', needs_adopt=True)
        h = self.render({'enabled': True, 'last': self.LAST, 'preview': pre})
        self.assertIn('<span>Preview</span>', h)
        self.assertIn('<span>A list with this name exists and RemotePower did not create it.</span>', h)
        old = dict(pre, at=50)
        h = self.render({'enabled': True, 'last': self.LAST, 'preview': old})
        self.assertIn('<span>Up to date</span>', h)
        self.assertNotIn('<span>Preview</span>', h)

    def test_nothing_yet_and_off(self):
        self.assertIn('<span>Waiting for the first sync</span>', self.render({'enabled': True, 'last': {}, 'preview': {}}))
        self.assertIn('<span>Off</span>', self.render({'enabled': False, 'last': {}, 'preview': {}}))

    def test_cloudflares_sentence_after_the_fixed_words_is_not_lost_or_trusted(self):
        err = {'at': 1, 'state': 'error', 'why': 'The token cannot edit lists: Authentication error'}
        h = self.render({'enabled': True, 'last': err, 'preview': {}})
        self.assertIn('<span>The token cannot edit lists:</span> Authentication error', h)
        err['why'] = 'The token cannot edit lists: <b>x</b>'
        h = self.render({'enabled': True, 'last': err, 'preview': {}})
        self.assertNotIn('<b>', h)
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', h)

    def test_everything_free_text_is_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        last = dict(self.LAST, why=evil, list=dict(self.LAST['list'], name=evil),
                    sources={'abuseipdb': {'from': 'copy', 'at': 1, 'n': 1, 'error': evil}},
                    failed={'sniffcat': evil}, added_sample=[evil], removed_sample=[evil], state='held',
                    can_force=True)
        h = self.render({'enabled': True, 'last': last, 'preview': {}})
        self.assertNotIn('<img', h)
        self.assertGreaterEqual(h.count('&lt;img'), 6, 'every place the text appears is escaped')
        self.assertEqual(h.count('data-action'), 1, 'and none of it became a control')


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheButtons(unittest.TestCase):
    def run_js(self, setup, call):
        return node('''_ipiData = {edge_list: %s};
          %s
          await %s;
          console.log(JSON.stringify({sent, asked, list: _ipiData.edge_list,
                                      box: els["ipintel-edgelist-status"]}));''' % (json.dumps(setup[0]), setup[1], call))

    FOREIGN = {'enabled': True, 'last': {'at': 1, 'state': 'needs_adopt'}, 'preview': {}}
    MANAGED = {'enabled': True, 'last': {'at': 1, 'state': 'ok'}, 'preview': {}}

    def test_preview_posts_to_the_preview_route_and_keeps_the_answer_apart(self):
        got = self.run_js((self.MANAGED, 'reply = {ok: true, result: {state: "preview", at: 9, added: 1}};'),
                          'previewIpIntelList()')
        self.assertEqual([(s['m'], s['p']) for s in got['sent']], [('POST', '/ip-intel/edge-list/preview')])
        self.assertEqual(got['asked'], [], 'a preview asks nothing')
        self.assertEqual(got['list']['preview']['added'], 1)
        self.assertEqual(got['list']['last']['state'], 'ok', 'the last real result is not replaced')

    def test_sync_now_on_our_own_list_just_syncs(self):
        got = self.run_js((self.MANAGED, 'reply = {ok: true, result: {state: "ok", at: 9}};'), 'syncIpIntelList()')
        self.assertEqual([(s['p'], s['body']) for s in got['sent']], [('/ip-intel/edge-list/sync', {})])
        self.assertEqual(got['asked'], [])
        self.assertEqual(got['list']['last']['at'], 9)

    def test_sync_now_on_a_list_that_is_not_ours_asks_first_and_says_what_it_will_do(self):
        got = self.run_js((self.FOREIGN, ''), 'syncIpIntelList()')
        self.assertEqual(len(got['asked']), 1)
        ask = got['asked'][0]
        self.assertTrue(ask['danger'])
        self.assertIn('replaces everything in it', ask['message'])
        self.assertIn('Stop any other tool', ask['message'])
        self.assertEqual([s['body'] for s in got['sent']], [{'adopt': True}])

    def test_the_first_press_asks_when_the_server_says_the_list_is_not_ours(self):
        """With nothing on the page yet the button cannot know. The server leaves the
        list alone and says so; the page then asks at once, and one press is enough."""
        got = self.run_js(({'enabled': True, 'last': {}, 'preview': {}}, '''
            replies = [{ok: true, result: {state: "needs_adopt", at: 5}},
                       {ok: true, result: {state: "ok", at: 6, changed: true}}];'''),
                          'syncIpIntelList()')
        self.assertEqual([s['body'] for s in got['sent']], [{}, {'adopt': True}])
        self.assertEqual(len(got['asked']), 1)
        self.assertTrue(got['asked'][0]['danger'])
        self.assertIn('replaces everything in it', got['asked'][0]['message'])
        self.assertEqual(got['list']['last']['state'], 'ok')

    def test_declining_at_that_point_leaves_the_list_alone(self):
        got = self.run_js(({'enabled': True, 'last': {}, 'preview': {}}, '''
            replies = [{ok: true, result: {state: "needs_adopt", at: 5}}]; answer = false;'''),
                          'syncIpIntelList()')
        self.assertEqual([s['body'] for s in got['sent']], [{}], 'nothing was sent after the refusal')
        self.assertEqual(len(got['asked']), 1)
        self.assertEqual(got['list']['last']['state'], 'needs_adopt')

    def test_sync_anyway_keeps_its_force_flag_through_the_question(self):
        got = self.run_js(({'enabled': True, 'last': {}, 'preview': {}}, '''
            replies = [{ok: true, result: {state: "needs_adopt", at: 5}},
                       {ok: true, result: {state: "ok", at: 6}}];'''),
                          'syncIpIntelListForce()')
        self.assertEqual([s['body'] for s in got['sent']],
                         [{'force': True, 'adopt': False}, {'force': True, 'adopt': True}])
        self.assertEqual(len(got['asked']), 2, 'the override, then the take-over')

    def test_it_never_asks_twice_for_the_same_press(self):
        """An adopt request cannot come back needs_adopt; if a server ever said so the
        page must not loop."""
        got = self.run_js(({'enabled': True, 'last': {}, 'preview': {}}, '''
            replies = [{ok: true, result: {state: "needs_adopt", at: 5}},
                       {ok: true, result: {state: "needs_adopt", at: 6}}];'''),
                          'syncIpIntelList()')
        self.assertEqual(len(got['sent']), 2)
        self.assertEqual(len(got['asked']), 1)

    def test_declining_the_question_sends_nothing(self):
        got = self.run_js((self.FOREIGN, 'answer = false;'), 'syncIpIntelList()')
        self.assertEqual(len(got['asked']), 1)
        self.assertEqual(got['sent'], [])
        got = self.run_js((self.MANAGED, 'answer = false;'), 'syncIpIntelListForce()')
        self.assertEqual(got['sent'], [])

    def test_sync_anyway_asks_and_sends_force(self):
        got = self.run_js((self.MANAGED, ''), 'syncIpIntelListForce()')
        self.assertEqual(len(got['asked']), 1)
        self.assertTrue(got['asked'][0]['danger'])
        self.assertEqual([s['body'] for s in got['sent']], [{'force': True, 'adopt': False}])
        got = self.run_js((self.FOREIGN, ''), 'syncIpIntelListForce()')
        self.assertEqual([s['body'] for s in got['sent']], [{'force': True, 'adopt': True}])

    def test_an_error_answer_is_shown_and_not_thrown(self):
        got = self.run_js((self.MANAGED, 'reply = {error: "Cloudflare is still applying the last change. Try again in a minute."};'),
                          'syncIpIntelList()')
        self.assertIn('Try again in a minute', got['box']['textContent'])
        got = self.run_js((self.MANAGED, 'reply = null;'), 'previewIpIntelList()')
        self.assertEqual(got['box']['textContent'], 'Preview failed')

    def test_removing_the_read_token_asks_and_sends_its_own_flag(self):
        got = self.run_js((self.MANAGED, ''), 'clearIpIntelEdgeToken()')
        self.assertEqual(len(got['asked']), 1)
        self.assertTrue(got['asked'][0]['danger'])
        self.assertEqual([(s['p'], s['body']) for s in got['sent']],
                         [('/ip-intel/settings', {'clear_edge_token': True})])
        got = self.run_js((self.MANAGED, 'answer = false;'), 'clearIpIntelEdgeToken()')
        self.assertEqual(got['sent'], [])

    def test_removing_the_token_asks_and_sends_only_the_clear_flag(self):
        got = self.run_js((self.MANAGED, ''), 'clearIpIntelListToken()')
        self.assertEqual(len(got['asked']), 1)
        self.assertEqual([(s['p'], s['body']) for s in got['sent']],
                         [('/ip-intel/settings', {'clear_edge_list_token': True})])
        got = self.run_js((self.MANAGED, 'answer = false;'), 'clearIpIntelListToken()')
        self.assertEqual(got['sent'], [])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheSettingsRoundTrip(unittest.TestCase):
    FIELDS = {   # input id -> setting key
        'ipintel-edgelist-name': 'edgelist_name', 'ipintel-edgelist-own-score': 'edgelist_own_score',
        'ipintel-edgelist-own-days': 'edgelist_own_days',
        'ipintel-edgelist-abuseipdb-conf': 'edgelist_abuseipdb_conf',
        'ipintel-edgelist-abuseipdb-limit': 'edgelist_abuseipdb_limit',
        'ipintel-edgelist-sniffcat-conf': 'edgelist_sniffcat_conf',
        'ipintel-edgelist-sniffcat-limit': 'edgelist_sniffcat_limit',
        'ipintel-edgelist-hours': 'edgelist_hours', 'ipintel-edgelist-max': 'edgelist_max',
        'ipintel-edgelist-always': 'edgelist_always',
    }
    CHECKS = {'ipintel-edgelist': 'edgelist_enabled', 'ipintel-edgelist-own': 'edgelist_own',
              'ipintel-edgelist-abuseipdb': 'edgelist_abuseipdb', 'ipintel-edgelist-sniffcat': 'edgelist_sniffcat'}

    def run_js(self, script):
        fill = srcpin.js_function(_JS, '_ipiFillSettings')
        save = 'async ' + srcpin.js_function(_JS, 'saveIpIntelSettings')
        prelude = '''
const els = {};
const el = id => (els[id] = els[id] || {value: '', checked: false, placeholder: '', textContent: '', hidden: false, innerHTML: '', querySelectorAll: () => []});
const document = {getElementById: el};
let sent = null; let _ipiData = {settings: {}};
async function api(m, p, body) { sent = {m, p, body}; return {ok: true}; }
function toast() {} function loadIpIntel() {} async function uiConfirm() { return true; }
'''
        helpers = '\n'.join([
            re.search(r'^const _IPI_CLASS = \{.*?^\};', _JS, re.S | re.M).group(0),
            'function escAttr(s) { return String(s); } function escHtml(s) { return String(s); }',
            srcpin.js_function(_JS, '_ipiPhrase'), srcpin.js_function(_JS, '_ipiRenderIgnoreClasses'),
            srcpin.js_function(_JS, '_ipiIgnoredClasses')])
        out = subprocess.run(['node', '-e', prelude + helpers + '\n' + fill + '\n' + save + '\n(async () => {' + script + '})()'],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_every_input_is_in_the_markup_and_every_key_is_one_the_server_keeps(self):
        from request_models import IpIntelSettingsRequest
        for i in list(self.FIELDS) + list(self.CHECKS) + ['ipintel-edgelist-token', 'ipintel-edgelist-clear']:
            self.assertRegex(_HTML, r'id="%s"' % re.escape(i))
        known = set(ip_intel.DEFAULTS)
        fields = set(IpIntelSettingsRequest.model_fields)
        for key in list(self.FIELDS.values()) + list(self.CHECKS.values()):
            self.assertIn(key, known, key)
            self.assertIn(key, fields, key)
        self.assertIn('edge_list_token', fields)
        self.assertIn('clear_edge_list_token', fields)

    def test_fill_shows_what_is_stored(self):
        got = self.run_js('''
          _ipiFillSettings({edgelist_enabled: true, edgelist_name: 'tyxak_cf_waf', edgelist_own: true,
            edgelist_abuseipdb: false, edgelist_sniffcat: true, edgelist_own_score: 60, edgelist_own_days: 7,
            edgelist_abuseipdb_conf: 90, edgelist_abuseipdb_limit: 5000, edgelist_sniffcat_conf: 85,
            edgelist_sniffcat_limit: 1500, edgelist_hours: 12, edgelist_max: 9000,
            edgelist_always: ['1.2.3.4', '5.6.7.0/24'], edge_list_token_set: true}, {});
          const ids = %s;
          console.log(JSON.stringify({v: Object.fromEntries(ids.map(i => [i, els[i].value])),
            c: Object.fromEntries(%s.map(i => [i, els[i].checked])),
            ph: els['ipintel-edgelist-token'].placeholder, clearHidden: els['ipintel-edgelist-clear'].hidden}));
        ''' % (json.dumps(list(self.FIELDS)), json.dumps(list(self.CHECKS))))
        self.assertEqual(got['v']['ipintel-edgelist-name'], 'tyxak_cf_waf')
        self.assertEqual(got['v']['ipintel-edgelist-max'], 9000)
        self.assertEqual(got['v']['ipintel-edgelist-always'], '1.2.3.4\n5.6.7.0/24')
        self.assertEqual(got['c'], {'ipintel-edgelist': True, 'ipintel-edgelist-own': True,
                                    'ipintel-edgelist-abuseipdb': False, 'ipintel-edgelist-sniffcat': True})
        self.assertIn('saved', got['ph'])
        self.assertFalse(got['clearHidden'])

    def test_the_remove_buttons_are_there_only_when_there_is_a_token(self):
        got = self.run_js('''
          _ipiFillSettings({edge_list_token_set: false, edge_token_set: false}, {});
          const off = {list: els['ipintel-edgelist-clear'].hidden, read: els['ipintel-edge-clear'].hidden,
                       ph: els['ipintel-edgelist-token'].placeholder};
          _ipiFillSettings({edge_list_token_set: false, edge_token_set: true}, {});
          const read = {list: els['ipintel-edgelist-clear'].hidden, read: els['ipintel-edge-clear'].hidden};
          console.log(JSON.stringify({off, read}));''')
        self.assertEqual(got['off'], {'list': True, 'read': True, 'ph': ''})
        self.assertEqual(got['read'], {'list': True, 'read': False}, 'each button follows its own token')

    def test_save_sends_what_was_typed_and_the_token_only_when_typed(self):
        script = '''
          for (const [i, v] of Object.entries(%s)) el(i).value = v;
          for (const i of %s) el(i).checked = true;
          await saveIpIntelSettings();
          console.log(JSON.stringify(sent));''' % (
            json.dumps({i: ('x_list' if i.endswith('name') else '1.2.3.4' if i.endswith('always') else '70')
                        for i in self.FIELDS}), json.dumps(list(self.CHECKS)))
        got = self.run_js(script)
        self.assertEqual(('POST', '/ip-intel/settings'), (got['m'], got['p']))
        b = got['body']
        self.assertEqual(b['edgelist_name'], 'x_list')
        self.assertEqual(b['edgelist_always'], '1.2.3.4')
        self.assertEqual(b['edgelist_hours'], '70')
        self.assertTrue(all(b[k] is True for k in self.CHECKS.values()))
        self.assertNotIn('edge_list_token', b, 'an untouched token box keeps the stored token')
        got = self.run_js(script.replace('await saveIpIntelSettings();',
                                         "el('ipintel-edgelist-token').value = ' NEWtoken_" + 'x' * 30 + " '; await saveIpIntelSettings();"))
        self.assertEqual(got['body']['edge_list_token'], 'NEWtoken_' + 'x' * 30)


class TestTheCard(unittest.TestCase):
    def card(self):
        start = _HTML.index('id="ipintel-edgelist-card"')
        start = _HTML.rindex('<div', 0, start)
        end = _HTML.index('id="ipintel-limits-card"')
        return _HTML[start:_HTML.rindex('<div', 0, end)]

    def test_it_is_for_the_operator_only(self):
        self.assertRegex(_HTML, r'id="ipintel-edgelist-card" hidden')
        self.assertIn("document.getElementById('ipintel-edgelist-card').hidden = !(_ipiAdmin && _ipiData.edge_list)", _JS)

    def test_the_card_follows_the_house_rules(self):
        card = self.card()
        self.assertTrue(card.lstrip().startswith('<div class="dash-card'))
        first = re.search(r'<div class="section-title">Edge blocklist</div>', card)
        self.assertTrue(first, 'the header is the first child, as a .section-title')
        self.assertNotRegex(card, r'\sstyle="', 'no inline style under the CSP')
        self.assertNotRegex(card, r'\son[a-z]+="', 'no inline handler under the CSP')
        self.assertNotIn('<table', card, 'a table would need its sort wired')
        self.assertIn('id="ipintel-edgelist-status" class="mt-8 scroll-cap"', card, 'the status is capped and scrolls')
        icons = re.findall(r'<button class="btn-icon"[^>]*>(.*?)</button>', card, re.S)
        self.assertGreaterEqual(len(icons), 3, 'the control: the three icon buttons are found')
        for ic in icons:
            self.assertIn('<svg', ic, 'an icon button carries an inline svg, never an emoji')

    def test_every_button_runs_a_function_that_exists(self):
        for name in re.findall(r'data-action="([A-Za-z]+)"', self.card()) + ['syncIpIntelListForce']:
            self.assertRegex(_JS, r'(?:async )?function %s\(' % name, name)


if __name__ == '__main__':
    unittest.main()
