#!/usr/bin/env python3
"""8.0.2: the security news watch -- every place it has to be named, read from the sources.

A feature that is named in one registry and not in the next fails quietly: the tab that never loads its file, the event that never shows in the feed, the sentence the server sends a
code for and the page has no text for, the route the API reference does not list. Each has its check here, and each population is read from the code (the server's own list of
reason and outcome codes, the ids the script reaches for, the actions the markup names), not kept by hand. The behaviour behind them is in test_v802_news_watch_rules.py (the rules)
and test_v802_news_watch_sweep.py (the sweep, the routes and the fetch).
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-newswatch-wiring-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import news_watch as N  # noqa: E402
import srcpin  # noqa: E402
from i18n_engine import dict_rows  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402

ROOT = _TESTS.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js'
APP = (JS / 'app.js').read_text()
NW = (JS / 'app-newswatch.js').read_text()
HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()
I18N = (JS / 'i18n.js').read_text()
NODE = shutil.which('node')
LANGS = ('zh', 'hi', 'es', 'ar', 'de', 'fr')
EVENT = 'security_news_critical'


def _card():
    """The markup of the news card, from its id to the end of the CVE page."""
    start = HTML.index('id="news-watch-wrap"')
    return HTML[start:HTML.index('<!-- ── v4.2.0 (B5): Security Scans page', start)]


def _js_map(name):
    m = re.search(r'const ' + name + r' = \{(.*?)\n\};', NW, re.S)
    assert m, name
    return dict(re.findall(r"(\w+):\s*'([^']*)'", m.group(1)))


class TestTheServerNamesIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def test_the_four_routes_resolve_to_the_four_handlers(self):
        defs = {(path, tuple(methods or ()), handler) for _kind, methods, path, _suffix, handler, _cond in self.api._PATTERN_ROUTE_DEFS}
        for path, method, handler in (('/api/news-watch', 'GET', 'handle_news_watch_get'), ('/api/news-watch/config', 'POST', 'handle_news_watch_config_set'),
                                      ('/api/news-watch/clear', 'POST', 'handle_news_watch_clear'), ('/api/news-watch/run', 'POST', 'handle_news_watch_run')):
            self.assertIn((path, (method,), handler), defs)
            fn = getattr(self.api, handler)
            self.assertTrue(callable(fn))
            self.assertEqual(fn.__module__, 'news_watch_handlers', 'the handler lives in its bound module and not in api.py')

    def test_the_sweep_is_in_both_cadence_registries(self):
        main = srcpin.py_function((ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(), 'main')
        self.assertIn("_safe(run_news_watch_if_due, 'run_news_watch_if_due')", main)
        import scheduler
        self.assertIn('run_news_watch_if_due', scheduler.CADENCE)
        self.assertEqual(self.api.run_news_watch_if_due.__module__, 'news_watch_handlers')

    def test_the_event_the_channel_kind_and_the_message_are_named(self):
        reg = self.api.EVENT_REGISTRY[EVENT]
        self.assertIn(reg['kind'], {k for k, _label, _group in self.api.CHANNEL_KIND_DEFS})
        import notify
        self.assertIn(EVENT, notify._EVENT_COLORS)
        self.assertIn('Security news', {label for _k, label, _g in self.api.CHANNEL_KIND_DEFS})

    def test_the_store_and_the_setting_are_in_the_shape_registry(self):
        import store_shapes
        self.assertIn('news_watch.json', store_shapes.SHAPES)
        self.assertIn('news_watch', store_shapes._config_fields())
        self.assertEqual(self.api.NEWS_WATCH_FILE.name, 'news_watch.json')

    def test_the_request_model_is_an_additive_check(self):
        model = self.api.request_models.NewsWatchConfigRequest
        model()                                                   # an empty body validates
        model(**{'enabled': 'true', 'feeds': 'a\nb', 'scope': 1, 'action': None, 'unknown': {'x': 1}})
        self.assertEqual(self.api.request_models.validate(model, {}), (True, None))
        clear = self.api.request_models.NewsWatchClearRequest
        clear()                                                   # an empty body validates: the handler is what says "name something"
        clear(**{'ids': 'x', 'all': 'yes', 'unknown': [1]})
        self.assertEqual(self.api.request_models.validate(clear, {'ids': {'a': 1}, 'all': 7}), (True, None))

    def test_the_module_is_in_the_lint_and_type_baselines(self):
        make = (ROOT / 'Makefile').read_text()
        self.assertEqual(len(re.findall(r'server/cgi-bin/news_watch\.py', make)), 2, 'LINT_SRC and TYPECHECK_SRC')

    def test_the_sidebar_poll_carries_the_figure_for_the_operator_only_and_its_cache_follows_the_store(self):
        src = srcpin.py_function((ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(), 'handle_nav_counts')
        self.assertRegex(src, r'if _nc_admin and _tenant_gate\(\) is None:\s+_nw_n, _nw_at = news_watch_handlers_mod\.attention\(now\)')
        self.assertRegex(src, r'CONFIRMATIONS_FILE, TICKETS_FILE, NEWS_WATCH_FILE\)', 'a change of the store busts the 15 second cache')
        self.assertTrue(callable(self.api.news_watch_handlers_mod.attention))

    def test_the_codes_the_server_sends_are_the_codes_the_page_holds_a_sentence_for(self):
        reasons, outcomes = _js_map('_NW_REASON'), _js_map('_NW_OUTCOME')
        self.assertEqual(set(N.REASONS), set(reasons), 'every reason code has a sentence, and no sentence is for a code nothing sends')
        self.assertEqual(set(N.OUTCOMES), set(outcomes))
        handlers = (ROOT / 'server' / 'cgi-bin' / 'news_watch_handlers.py').read_text()
        sent = set()
        for line in handlers.splitlines():
            if 'outcome"]' in line and '=' in line:
                sent |= set(re.findall(r'"(\w+)"', line.split('=', 1)[1]))
        self.assertEqual(sent, set(N.OUTCOMES), 'the outcomes the sweep sets are the outcomes the module lists, and the page has a sentence for each')
        given = set(re.findall(r"reasons\.append\(['\"](\w+)['\"]\)", (ROOT / 'server' / 'cgi-bin' / 'news_watch.py').read_text()))
        self.assertEqual(given, set(N.REASONS), 'the reasons classify gives are the reasons the module lists')


class TestTheClientNamesIt(unittest.TestCase):

    def test_the_tab_is_wired_without_a_module_and_its_file_is_fetched_when_it_shows(self):
        self.assertIn("['cve', 'news', null, 'app-newswatch.js', 'newsWatchEnter']", APP)
        lazy = re.search(r"const _LAZY_NON_PAGE_MODULES = \[([^\]]*)\]", APP).group(1)
        self.assertIn("'app-newswatch.js'", lazy)
        self.assertNotRegex(HTML, r'<script[^>]+app-newswatch\.js', 'a script tag would load it with the first page of every visit')
        self.assertRegex(HTML, r'<button class="pg-tab" data-pg-tab-btn="news" data-action="pgTab" data-arg="cve:news">Security news<span class="news-mark d-none" aria-hidden="true"></span></button>')
        self.assertNotIn('data-module', re.search(r'<button[^>]*data-pg-tab-btn="news"[^>]*>', HTML).group(0), 'every installation has the tab')
        self.assertIn('function newsWatchEnter(', NW)

    def test_the_hook_loads_the_file_for_a_tab_with_no_module_and_still_waits_for_a_module_that_is_off(self):
        body = srcpin.js_function(APP, '_pgTabEnter')
        self.assertIn('(mod && !(window._modules && window._modules[mod]))', body)

    def test_every_id_the_script_reaches_for_is_in_the_markup(self):
        ids = set(re.findall(r"getElementById\('([\w-]+)'\)", NW)) | set(re.findall(r"\bset\('([\w-]+)'", NW))
        self.assertGreaterEqual(len(ids), 8, 'control: the scan found the ids')
        missing = sorted(i for i in ids if f'id="{i}"' not in HTML)
        self.assertEqual(missing, [], 'the script reads or writes an element that is not on the page')

    def test_every_action_the_card_names_is_a_function_of_the_script(self):
        actions = set(re.findall(r'data-action="(\w+)"', _card()))
        self.assertEqual(actions, {'newsWatchRun', 'newsWatchLoad', 'newsWatchSave'})
        for name in actions:
            self.assertRegex(NW, r'(?:async )?function ' + name + r'\(', name)

    def test_the_card_carries_its_tab_and_every_role_has_something_in_it(self):
        self.assertIn('<div data-pg-tab="news" class="dash-card mt-16" id="news-watch-wrap">', HTML)
        self.assertIn('id="news-watch-note"', _card())
        self.assertIn("'The platform operator manages the security news watch.'", NW, 'a role that reads nothing is told why, so its tab is not empty')

    def test_the_card_has_no_inline_handler_and_no_inline_style(self):
        card = _card()
        self.assertNotRegex(card, r'\son[a-z]+=')
        self.assertNotRegex(card, r'\sstyle=')
        self.assertNotRegex(NW, r'\son[a-z]+=')
        self.assertNotRegex(NW, r'style="')

    def test_the_mark_is_on_the_sidebar_entry_and_on_the_tab_and_is_painted_from_the_poll(self):
        self.assertEqual(len(re.findall(r'class="[^"]*\bnews-mark\b[^"]*"', HTML)), 2, 'the CVEs entry of the sidebar and the Security news tab')
        nav = re.search(r'<button class="nav-btn" data-page="cve".*?</button>', HTML, re.S).group(0)
        span = re.search(r'<span class="nav-badge nav-badge-alert news-mark d-none"([^>]*)></span>', nav)
        self.assertTrue(span, 'the mark sits in the sidebar entry, hidden until the poll says so, and holds no text until then')
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', span.group(1)))
        self.assertEqual((attrs['role'], attrs['aria-label'], attrs['aria-hidden']), ('img', attrs['title'], 'true'), 'a "!" alone says nothing to a screen reader, and nothing while it is not there')
        self.assertTrue(set(LANGS) <= dict_rows(I18N).get(attrs['aria-label'], set()), 'and its words are translated')
        tab = re.search(r'<button class="pg-tab" data-pg-tab-btn="news".*?</button>', HTML, re.S).group(0)
        self.assertIn('<span class="news-mark d-none" aria-hidden="true"></span>', tab)
        refresh = srcpin.js_function(APP, 'refreshNavCounts')
        self.assertIn("window._newsRunningAt = typeof c.news_running_at === 'number' ? c.news_running_at : null", refresh)
        self.assertIn('_paintNewsMark();', refresh)
        self.assertIn('_paintNewsMark', srcpin.js_function(APP, '_renderFavorites'), 'a pinned favourite is a clone of the entry and is painted too')
        self.assertIn("'rp_news_seen'", srcpin.js_function(APP, '_paintNewsMark'))
        self.assertIn("'rp_news_seen'", NW, 'the tab writes the key the sidebar reads')
        css = (JS.parent / 'css' / 'styles.css').read_text()
        self.assertRegex(css, r'\.pg-tab \.news-mark\s*\{')
        self.assertRegex(css, r'\.nav-badge\.news-mark\s*\{')
        self.assertRegex(css, r'\.nav-badge\.d-none\s*\{\s*display:\s*none\s*!important;\s*\}', 'the rules that open the collapsed sidebar draw every span of a nav button again, and must not draw a hidden badge')

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_mark_shows_only_for_an_item_newer_than_the_newest_this_browser_has_shown(self):
        body = srcpin.js_function(APP, '_paintNewsMark')
        script = ('const make = withRole => { const attrs = withRole ? {role: "img", "aria-hidden": "true"} : {"aria-hidden": "true"};\n'
                  '  return {textContent: "", classList: {hidden: null, toggle(c, hide) { if (c === "d-none") this.hidden = hide; }},\n'
                  '    hasAttribute: n => n in attrs, removeAttribute: n => { delete attrs[n]; }, setAttribute: (n, v) => { attrs[n] = v; }, aria: () => attrs["aria-hidden"] || null}; };\n'
                  'const els = [make(true), make(false)];\n'
                  'const document = {querySelectorAll: sel => (sel === ".news-mark" ? els : [])};\n'
                  'let store = {}, broken = false;\n'
                  'const localStorage = {getItem: k => { if (broken) throw new Error("no storage"); return k in store ? store[k] : null; }};\n'
                  'const window = {};\n' + body + '\n'
                  'const out = [], text = [], aria = [];\n'
                  'for (const [at, seen] of [[100, null], [100, "50"], [100, "100"], [100, "150"], [null, null], [null, "5"], ["x", null], [undefined, null], [100, "junk"], [100, ""]]) {\n'
                  '  window._newsRunningAt = at; store = seen === null ? {} : {rp_news_seen: seen}; _paintNewsMark(); out.push(els.map(e => e.classList.hidden));\n'
                  '  text.push(els.map(e => e.textContent)); aria.push(els.map(e => e.aria()));\n'
                  '}\n'
                  'broken = true; window._newsRunningAt = 100; _paintNewsMark(); out.push(els.map(e => e.classList.hidden));\n'
                  'console.log(JSON.stringify({out, text, aria}));\n')
        got = self._node(script)
        out = got['out']
        shown, hidden = [False, False], [True, True]
        self.assertEqual(out, [shown, shown, hidden, hidden, hidden, hidden, hidden, hidden, shown, shown, shown],
                         'shown for 100 with nothing seen or an older item seen or a damaged value; hidden for the same or a newer one seen, and for no item at all; both copies together')
        on = [i for i, o in enumerate(out[:-1]) if o == shown]
        for i in range(len(got['text'])):
            want = ['!', '!'] if i in on else ['', '']
            self.assertEqual(got['text'][i], want, 'the "!" is in the mark only while it shows: the collapsed sidebar draws a span again when the rail opens, and a hidden one must have nothing to draw')
            self.assertEqual(got['aria'][i], [None, 'true'] if i in on else ['true', 'true'], 'the one with a role is announced only while it shows, the one without never is')

    @unittest.skipUnless(NODE, 'node not installed')
    def test_the_tab_remembers_the_newest_item_it_showed_and_never_an_older_one(self):
        script = ('let store = {}, painted = 0, broken = false;\n'
                  'const localStorage = {getItem: k => { if (broken) throw new Error("no"); return k in store ? store[k] : null; },\n'
                  '                      setItem: (k, v) => { if (broken) throw new Error("no"); store[k] = String(v); }};\n'
                  'function _paintNewsMark() { painted++; }\n' + NW + '\n'
                  'const out = [];\n'
                  'for (const at of [100, 50, 150, null, "x", undefined, 150]) { _nwSeen(at); out.push([store.rp_news_seen || null, painted]); }\n'
                  'broken = true; _nwSeen(500);\n'
                  'console.log(JSON.stringify(out.concat([[store.rp_news_seen, painted]])));\n')
        out = self._node(script)
        self.assertEqual([o[0] for o in out], ['100', '100', '150', '150', '150', '150', '150', '150'], 'the newest, and nothing older replaces it')
        self.assertEqual([o[1] for o in out], [1, 2, 3, 3, 3, 3, 4, 5], 'painted after each number, and not for a value that is no number; a browser with no storage still paints')

    def test_the_tab_records_what_it_has_shown_every_time_it_draws_and_the_form_sends_the_names(self):
        paint = srcpin.js_function(NW, '_nwPaint')
        self.assertIn('_nwSeen(d.attention_at);', paint, 'without this call the mark never goes')
        self.assertNotIn('_nwSeen', srcpin.js_function(NW, '_nwPaint').split('if (!d.editable)')[1].split('return;')[0], 'a role that is shown nothing records nothing')
        self.assertIn("words: document.getElementById('nw-words').value", srcpin.js_function(NW, 'newsWatchSave'))
        self.assertIn("set('nw-words'", srcpin.js_function(NW, '_nwFillForm'))
        self.assertIn("critical_words: document.getElementById('nw-critical-words').value", srcpin.js_function(NW, 'newsWatchSave'))
        self.assertIn("set('nw-critical-words'", srcpin.js_function(NW, '_nwFillForm'))

    def test_the_field_for_the_words_is_in_the_form_with_a_label_a_hint_and_room_for_fifty_words(self):
        html = HTML
        field = re.search(r'<label class="form-label" for="nw-critical-words">([^<]+)</label><textarea id="nw-critical-words"([^>]*)></textarea><div class="hint mt-6">([^<]+)</div>', html)
        self.assertTrue(field, 'the label, the textarea and the hint are one group of the form')
        self.assertEqual(field.group(1), 'Words that make an item critical, one on each line')
        room = int(re.search(r'maxlength="(\d+)"', field.group(2)).group(1))
        self.assertGreaterEqual(room, N.MAX_CRITICAL_WORDS * (40 + 1) , 'fifty words of forty characters and the line ends between them fit')
        self.assertIn('It applies to items found after you save.', field.group(3), 'the hint says what the words do not do')
        self.assertLess(html.index('id="nw-words"'), html.index('id="nw-critical-words"'), 'it follows the names of software')
        self.assertLess(html.index('id="nw-critical-words"'), html.index('data-action="newsWatchSave"'), 'and comes before the button that saves')
        self.assertEqual(N.REASONS[-1], 'word')
        self.assertIn("word: 'Matches a word you added'", NW)

    def _node(self, script):
        d = Path(tempfile.mkdtemp(prefix='rp-newsnode-'))
        try:
            (d / 't.js').write_text(script)
            r = subprocess.run([NODE, str(d / 't.js')], capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        return json.loads(r.stdout)

    def test_the_choices_of_what_counts_and_what_happens_are_the_ones_the_server_knows_in_the_same_order(self):
        rows = dict_rows(I18N)
        for sel_id, known in (('nw-scope', N.SCOPES), ('nw-action', N.ACTIONS)):
            sel = re.search(r'<select id="%s"[^>]*>(.*?)</select>' % sel_id, HTML, re.S).group(1)
            self.assertEqual(tuple(re.findall(r'<option value="(\w+)"', sel)), known, sel_id)
            for text in re.findall(r'<option value="\w+">([^<]+)</option>', sel):
                self.assertTrue(set(LANGS) <= rows.get(text, set()), text)
        self.assertEqual(N.settings(None)['scope'], 'relevant', 'the default is the middle choice')

    def test_the_feed_and_the_inbox_know_the_event(self):
        self.assertRegex(APP, r"'security_news_critical': 'warn'")
        feed = APP[APP.index('function _renderHomeActivity'):]
        self.assertIn("'security_news_critical',", feed[:feed.index('const _seenActivity')], 'the allow list of the activity feed (test_v223 holds that it equals the server set)')
        self.assertIn("e.event === 'security_news_critical' ? p.title", feed, 'two headlines are two rows')
        self.assertIn("case 'security_news_critical':", feed)

    @unittest.skipUnless(NODE, 'node not installed')
    def test_a_headline_in_the_feed_opens_the_tab_and_no_other_event_does(self):
        body = srcpin.js_function(APP, '_homeActivityAttrs')
        script = ('function escAttr(s){return String(s);}\n' + body + '\n'
                  'const out = {};\n'
                  'for (const ev of ["security_news_critical", "detection_found", "cve_found", "tls_expiry", "ct_new_certificate"]) out[ev] = _homeActivityAttrs(ev, {});\n'
                  'console.log(JSON.stringify(out));\n')
        d = Path(tempfile.mkdtemp(prefix='rp-newsroute-'))
        try:
            (d / 'route.js').write_text(script)
            r = subprocess.run([NODE, str(d / 'route.js')], capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        out = json.loads(r.stdout)
        self.assertIn('data-home-act="cve-news"', out[EVENT])
        for other in ('detection_found', 'cve_found', 'tls_expiry', 'ct_new_certificate'):
            self.assertNotIn('data-home-act="cve-news"', out[other], 'a case group lost its return to the new one: %s' % other)

    def test_the_nav_action_the_feed_names_goes_to_the_tab_of_the_page(self):
        body = srcpin.js_function(APP, '_homeNavAction')
        case = re.search(r"case 'cve-news':(.*?)break;", body, re.S)
        self.assertTrue(case, 'the feed names an act the click handler does not know')
        self.assertIn("showPage('cve'", case.group(1))
        self.assertIn("pgTab('cve:news')", case.group(1))


class TestTheSentencesAreTranslated(unittest.TestCase):

    def test_every_sentence_the_script_shows_has_all_six_languages(self):
        rows = dict_rows(I18N)
        sentences = set(_js_map('_NW_REASON').values()) | set(_js_map('_NW_OUTCOME').values())
        sentences |= set(re.findall(r"_nwNote\('([^']+)'\)", NW))
        sentences |= set(re.findall(r'<span class="hint">([^<$]+)</span>', NW))
        sentences |= set(re.findall(r"<div class=\"c-muted\">([^<]+)</div>", NW))
        sentences |= set(re.findall(r'data-action="newsWatchClear"[^>]*>([^<]+)</button>', NW))      # the labels of the buttons that clear a !
        sentences |= set(re.findall(r'data-action="newsWatchRestore"[^>]*>([^<]+)</button>', NW))    # and of the ones that bring it back
        sentences |= {'Called critical', 'Failed:', 'reachable from the Internet', 'Running on your hosts:', 'Items about software running on your hosts:'}
        sentences.add('A red ! marks an item that names software running on one of your hosts. An item that names software that is only installed has no !.')
        sentences |= {'Only items that name software running on my hosts', 'Other software to count, one name on each line',
                      'Names of software that is installed on your hosts and is not on the built-in list. A package whose name starts with one of them counts when a headline names it.',
                      'A security news item names software that runs on your hosts', 'Clear !', 'Clear all !', '! cleared', 'Say which items to clear',
                      'Bring back !', 'Bring back all !', 'Say which items to bring back', 'Words that make an item critical, one on each line',
                      'A headline or summary that holds one of them as a word or phrase counts as critical, whatever else it says: the nickname of a flaw, or the name of a product you do not want to miss. It applies to items found after you save.'}
        self.assertGreaterEqual(len(sentences), 20, 'control: the scan found the sentences')
        missing = {s: sorted(set(LANGS) - rows.get(s, set())) for s in sorted(sentences) if not set(LANGS) <= rows.get(s, set())}
        self.assertEqual(missing, {}, 'sentences the Security news tab shows with no translation')


@unittest.skipUnless(NODE, 'node not installed')
class TestThePageIsSafe(unittest.TestCase):
    """The rows are built from a feed. The server cuts and cleans what it stores, and the page escapes again: this runs the real rendering code with the app's own escaping."""

    HOSTILE_ITEM = {
        'id': 'x', 'feed': '"><script>alert(1)</script>', 'title': '<img src=x onerror=alert(1)>', 'link': 'javascript:alert(1)', 'published': 1_800_000_000, 'seen_at': 1_800_000_100,
        'reasons': ['critical', '<script>', '__proto__', 'constructor'], 'cves': ['<i>CVE</i>'], 'cvss': None, 'software': ['<b>php</b>'], 'outcome': '__proto__',
    }
    RUNNING = [{'name': 'nginx', 'hosts': 3, 'world': True}, {'name': 'php', 'hosts': 1, 'world': False}]
    HOSTILE_RUNNING = [{'name': '<img src=x onerror=alert(1)>', 'hosts': '<b>3</b>', 'world': True}, 'junk', None, {'name': 7}, {'hosts': 2}]
    HOSTILE_FEED = {'url': 'https://x.example/"onmouseover="alert(1)', 'title': '<svg onload=alert(1)>', 'last_ok': 1_800_000_000, 'last_error': '<script>x</script>', 'fail_streak': 3,
                    'last_new': 2, 'last_critical': 1}

    def _render(self):
        # by pattern and not by srcpin: the scanner of srcpin reads the quotes inside the regular expressions of escHtml as the start of a string
        parts = [re.search(r'^function escHtml\(s\) \{.*\}$', APP, re.M).group(0), re.search(r'^function escAttr\(s\) \{.*\}$', APP, re.M).group(0),
                 re.search(r'^function _safeHttpHref\(u\) \{.*?\n\}', APP, re.M | re.S).group(0)]
        self.assertTrue(all(parts) and len(parts[2]) < 400, 'control: the three helpers were cut out whole, not a page of app.js')
        harness = ('const window = {location: {origin: "https://rp.example"}};\n'
                   'const document = {getElementById: () => null};\n'
                   'function timeAgoHtml(ts) { return "<time>" + Number(ts) + "</time>"; }\n'
                   + '\n'.join(parts) + '\n' + NW + '\n'
                   'const good = {id: "g", feed: "Example News", title: "PHP fixes 7 critical flaws", link: "https://news.example.net/php", published: 1800000000, seen_at: 1800000100,\n'
                   '  reasons: ["critical", "unauth_exec"], cves: ["CVE-2026-1"], cvss: null, software: ["php"], outcome: "scanned"};\n'
                   'console.log(JSON.stringify({hostile: _nwItemHtml(' + json.dumps(self.HOSTILE_ITEM) + '), feed: _nwFeedHtml(' + json.dumps(self.HOSTILE_FEED) + '), good: _nwItemHtml(good),\n'
                   '  running: _nwItemHtml(Object.assign({}, good, {running: ' + json.dumps(self.RUNNING) + '})),\n'
                   '  hostile_running: _nwItemHtml(Object.assign({}, good, {running: ' + json.dumps(self.HOSTILE_RUNNING) + '})),\n'
                   '  not_a_list: _nwItemHtml(Object.assign({}, good, {running: "nginx"}))}));\n')
        d = Path(tempfile.mkdtemp(prefix='rp-newsrender-'))
        try:
            (d / 'render.js').write_text(harness)
            r = subprocess.run([NODE, str(d / 'render.js')], capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        return json.loads(r.stdout)

    def test_hostile_text_never_becomes_markup(self):
        out = self._render()
        for key in ('hostile', 'feed'):
            html = out[key]
            for raw in ('<img', '<script', '<svg', '<b>', '<i>', '"onmouseover', '" onmouseover', 'javascript:'):
                self.assertNotIn(raw, html, (key, raw))
        self.assertNotIn('<a ', out['hostile'], 'a link that is not http or https is not a link')

    def test_a_code_that_is_not_one_of_ours_shows_no_sentence(self):
        out = self._render()['hostile']
        self.assertEqual(out.count('status-pill'), 1, 'only "critical" of the four reason codes has a sentence, and the outcome __proto__ has none')

    def test_the_red_mark_is_for_software_that_runs_and_for_nothing_else(self):
        out = self._render()
        bang = '<span class="c-red fw-600" aria-hidden="true">!</span>'
        self.assertNotIn(bang, out['good'], 'installed software is named under the headline and has no mark')
        self.assertIn('Names software on your hosts:', out['good'])
        self.assertIn(bang + ' <a href="https://news.example.net/php"', out['running'], 'the mark stands before the headline')
        self.assertIn('Running on your hosts:', out['running'])
        self.assertRegex(out['running'], r'nginx</span> <span class="hint">Hosts</span> <span class="fw-500">3</span> <span class="status-pill critical">reachable from the Internet</span>')
        self.assertRegex(out['running'], r'php</span> <span class="hint">Hosts</span> <span class="fw-500">1</span>(?! <span class="status-pill critical")')
        self.assertEqual(out['running'].count('reachable from the Internet'), 1, 'only the program with a socket open to the Internet says so')
        self.assertNotIn(bang, out['not_a_list'], 'a running that is not a list is nothing')
        self.assertNotIn(bang, out['hostile'], 'the hostile item names nothing that runs')

    def test_hostile_names_and_counts_of_what_runs_stay_inert(self):
        html = self._render()['hostile_running']
        for raw in ('<img', '<b>', 'onerror=alert(1)>'):
            self.assertNotIn(raw, html, raw)
        self.assertIn('&lt;img', html, 'shown as the text it is')
        self.assertRegex(html, r'<span class="hint">Hosts</span> <span class="fw-500">0</span>', 'a count that is not a number is a zero')
        self.assertEqual(html.count('<span class="c-red fw-600" aria-hidden="true">!</span>'), 1, 'one mark for one item, whatever the number of entries')
        self.assertEqual(html.count('Hosts</span>'), 1, 'the entries that are not maps, or have no name, are left out')

    def _node(self, script):
        d = Path(tempfile.mkdtemp(prefix='rp-newsclear-'))
        try:
            (d / 't.js').write_text(script)
            r = subprocess.run([NODE, str(d / 't.js')], capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        return json.loads(r.stdout)

    def _helpers(self):
        parts = [re.search(r'^function escHtml\(s\) \{.*\}$', APP, re.M).group(0), re.search(r'^function escAttr\(s\) \{.*\}$', APP, re.M).group(0),
                 re.search(r'^function _safeHttpHref\(u\) \{.*?\n\}', APP, re.M | re.S).group(0)]
        return ('const window = {location: {origin: "https://rp.example"}};\n'
                'function timeAgoHtml(ts) { return "<time>" + Number(ts) + "</time>"; }\n' + '\n'.join(parts) + '\n')

    def test_a_bang_has_a_button_to_clear_it_and_a_cleared_item_says_so_and_has_neither(self):
        run = [{'name': 'nginx', 'hosts': 3, 'world': False}]
        base = {'id': '1234567890123456', 'feed': 'F', 'title': 'Critical nginx flaw', 'link': 'https://n.example/x', 'published': 1, 'seen_at': 2, 'reasons': ['critical'], 'cves': [], 'cvss': None,
                'software': [], 'outcome': 'scanned', 'running': run, 'cleared_at': None}
        cases = {'flagged': base, 'cleared': dict(base, cleared_at=1800000500), 'installed_only': dict(base, running=[]), 'junk_stamp': dict(base, cleared_at='x'),
                 'hostile_id': dict(base, id='"><img src=x onerror=alert(1)>'), 'hostile_id_cleared': dict(base, id='"><img src=x onerror=alert(1)>', cleared_at=5),
                 'cleared_and_not_running': dict(base, running=[], cleared_at=1800000500)}
        out = self._node(self._helpers() + 'const document = {getElementById: () => null};\n' + NW + '\nconst cases = ' + json.dumps(cases)
                         + ';\nconst out = {}; for (const k in cases) out[k] = _nwItemHtml(cases[k]); console.log(JSON.stringify(out));')
        bang = '<span class="c-red fw-600" aria-hidden="true">!</span>'
        button = 'data-action="newsWatchClear" data-arg="nw-1234567890123456">Clear !</button>'
        self.assertIn(bang, out['flagged'])
        self.assertIn(button, out['flagged'], 'an item with a ! has its own button')
        self.assertNotIn('! cleared', out['flagged'])
        for key in ('cleared', 'installed_only'):
            self.assertNotIn(bang, out[key], key)
            self.assertNotIn('newsWatchClear', out[key], key + ': nothing to clear')
        self.assertIn('<span class="hint">! cleared</span> <time>1800000500</time>', out['cleared'], 'it says it was cleared, and when')
        self.assertIn('Running on your hosts:', out['cleared'], 'what runs is still shown')
        self.assertNotIn('! cleared', out['installed_only'])
        self.assertIn(bang, out['junk_stamp'], 'a stamp that is not a number is no clear')
        self.assertNotIn('<img', out['hostile_id'])
        self.assertIn('&lt;img', out['hostile_id'], 'the id is escaped in the attribute')
        # a clear can be undone, on the item that shows it: a cleared item that runs has the button, with the same prefixed id, and no other item has it
        back = 'data-action="newsWatchRestore" data-arg="nw-1234567890123456">Bring back !</button>'
        self.assertIn(back, out['cleared'], 'a cleared item has a button to bring the ! back')
        for key in ('flagged', 'installed_only', 'junk_stamp', 'cleared_and_not_running'):
            self.assertNotIn('newsWatchRestore', out[key], key + ': nothing to bring back')
        self.assertNotIn('<img', out['hostile_id_cleared'])
        self.assertIn('&lt;img', out['hostile_id_cleared'], 'the id is escaped in the attribute of the button that brings it back too')
        self.assertEqual(re.findall(r'data-arg="([^"]*)"', out['cleared']), ['nw-1234567890123456'])
        # the dispatcher turns an argument that looks like a number into one (app.js: coerce), and sixteen hex digits can look like one: the prefix is what keeps the id a string
        coerce = 'const coerce = v => (v !== undefined && v !== "" && !isNaN(v)) ? Number(v) : v;'
        args = re.findall(r'data-arg="([^"]*)"', out['flagged'])
        self.assertEqual(args, ['nw-1234567890123456'])
        self.assertIn(coerce.replace('"', "'"), APP.replace('"', "'"), 'control: the dispatcher still coerces this way, so the prefix is still needed')
        got = self._node('const base = "1234567890123456", prefixed = "nw-1234567890123456";\n' + coerce
                         + '\nconsole.log(JSON.stringify({bare: typeof coerce(base), prefixed: typeof coerce(prefixed), exp: String(coerce("1e5000000000"))}));')
        self.assertEqual((got['bare'], got['prefixed'], got['exp']), ('number', 'string', 'Infinity'), 'a bare id would have arrived as a number, a prefixed one stays text')

    def test_the_line_above_the_list_counts_the_items_that_show_a_bang_and_offers_to_clear_them_all(self):
        item = {'id': 'aaaaaaaaaaaaaaaa', 'feed': 'F', 'title': 'T', 'link': '', 'published': 1, 'seen_at': 2, 'reasons': [], 'cves': [], 'cvss': None, 'software': [], 'outcome': 'listed',
                'running': [{'name': 'nginx', 'hosts': 1, 'world': False}], 'cleared_at': None}
        page = {'editable': True, 'enabled': True, 'feeds': ['https://x.example/f'], 'last_run': 1, 'scope': 'relevant', 'action': 'scan', 'words': [], 'status': []}
        cases = {'two_of_three': [item, dict(item, id='bbbbbbbbbbbbbbbb'), dict(item, id='cccccccccccccccc', cleared_at=5), dict(item, id='dddddddddddddddd', running=[])],
                 'all_cleared': [dict(item, cleared_at=5), dict(item, id='bbbbbbbbbbbbbbbb', cleared_at=6)], 'none_run': [dict(item, running=[])], 'no_items': [],
                 'cleared_and_nothing_runs': [dict(item, cleared_at=5, running=[])]}
        script = (self._helpers() + 'const els = {};\nconst document = {getElementById: id => (els[id] = els[id] || {hidden: false, innerHTML: "", textContent: "", value: ""})};\n' + NW
                  + '\nconst page = ' + json.dumps(page) + ', cases = ' + json.dumps(cases) + ';\nconst out = {};\n'
                  'for (const k in cases) { _nwPaint(Object.assign({}, page, {items: cases[k]}), true); out[k] = {hidden: els["news-watch-running"].hidden, html: els["news-watch-running"].innerHTML}; }\n'
                  'console.log(JSON.stringify(out));')
        out = self._node(script)
        two = out['two_of_three']
        self.assertFalse(two['hidden'])
        self.assertIn('<strong>2</strong>', two['html'], 'two items show a !: the cleared one and the one that runs nothing do not count')
        self.assertIn('data-action="newsWatchClear" data-arg="all">Clear all !</button>', two['html'])
        # the cleared one that runs is counted on its own and can be brought back, after the part that clears
        self.assertIn('<span class="hint">! cleared</span> <strong>1</strong> <button type="button" class="btn-icon" data-action="newsWatchRestore" data-arg="all">Bring back all !</button>', two['html'])
        self.assertLess(two['html'].index('Clear all !'), two['html'].index('Bring back all !'))
        self.assertIn(' · ', two['html'], 'the two parts are told apart')
        cleared = out['all_cleared']
        self.assertFalse(cleared['hidden'], 'when every item is cleared the line stays, to offer them back')
        self.assertIn('<strong>2</strong>', cleared['html'])
        self.assertIn('data-action="newsWatchRestore" data-arg="all">Bring back all !</button>', cleared['html'])
        self.assertNotIn('newsWatchClear', cleared['html'], 'nothing is left to clear')
        self.assertNotIn(' · ', cleared['html'], 'one part, no separator')
        for key in ('none_run', 'no_items', 'cleared_and_nothing_runs'):
            self.assertEqual((out[key]['hidden'], out[key]['html']), (True, ''), key + ': no ! shown and nothing cleared that runs, so no line and no button')

    def test_the_clear_sends_one_id_or_all_and_nothing_else(self):
        script = (self._helpers() + 'const document = {getElementById: () => null};\n'
                  'let calls = [], painted = [], toasts = [], navs = 0, answer = {ok: true, editable: true, items: []}, navBroken = false;\n'
                  'async function api(m, p, b) { calls.push([m, p, JSON.stringify(b)]); return answer; }\n'
                  'function failToast(r) { toasts.push(r); }\n'
                  'function refreshNavCounts() { navs++; if (navBroken) throw new Error("no"); }\n' + NW + '\n'
                  '_nwPaint = function (d, force) { painted.push([d === answer, force]); };\n'
                  '(async () => {\n'
                  '  const out = {};\n'
                  '  for (const a of ["all", "nw-0123456789abcdef", "nw-demonews00000001"]) await newsWatchClear(a);\n'
                  '  out.sent = calls.slice(); out.painted = painted.slice(); out.navs = navs;\n'
                  '  calls = [];\n'
                  '  for (const a of [5, 0, "nw-", "nw-../x", "nw-a b", "nw-" + "a".repeat(33), "nw-\\"><img src=x onerror=alert(1)>", "x", "", "ALL", undefined, null, {}, ["all"], true]) await newsWatchClear(a);\n'
                  '  out.refused_sent = calls.length;\n'
                  '  answer = {error: "nope"}; painted = []; navs = 0; await newsWatchClear("all");\n'
                  '  out.failed = [toasts.length, painted.length, navs];\n'
                  '  answer = {ok: true, editable: true, items: []}; navBroken = true; painted = []; await newsWatchClear("all");\n'
                  '  out.broken_poll = painted.length;\n'
                  '  console.log(JSON.stringify(out));\n'
                  '})();\n')
        out = self._node(script)
        self.assertEqual(out['sent'], [['POST', '/news-watch/clear', '{"all":true}'], ['POST', '/news-watch/clear', '{"ids":["0123456789abcdef"]}'],
                                       ['POST', '/news-watch/clear', '{"ids":["demonews00000001"]}']], 'the ids the watch makes (hex) and the ids the demo seed holds (letters and digits) are both sent')
        self.assertEqual(out['painted'], [[True, False]] * 3, 'the answer is the page, drawn without refilling the form the operator may be typing in')
        self.assertEqual(out['navs'], 3, 'the sidebar is asked again so its mark agrees at once')
        self.assertEqual(out['refused_sent'], 0, 'an argument that is not "all" or a prefixed id is not sent')
        self.assertEqual(out['failed'], [1, 0, 0], 'a refusal is said, the page is left as it is and the sidebar is not asked')
        self.assertEqual(out['broken_poll'], 1, 'a sidebar poll that fails does not undo the redraw')

    def test_bringing_it_back_sends_one_id_or_all_with_undo_and_nothing_else(self):
        script = (self._helpers() + 'const document = {getElementById: () => null};\n'
                  'let calls = [], painted = [], toasts = [], navs = 0, answer = {ok: true, editable: true, items: []};\n'
                  'async function api(m, p, b) { calls.push([m, p, JSON.stringify(b)]); return answer; }\n'
                  'function failToast(r) { toasts.push(r); }\n'
                  'function refreshNavCounts() { navs++; }\n' + NW + '\n'
                  '_nwPaint = function (d, force) { painted.push([d === answer, force]); };\n'
                  '(async () => {\n'
                  '  const out = {};\n'
                  '  for (const a of ["all", "nw-0123456789abcdef", "nw-demonews00000001"]) await newsWatchRestore(a);\n'
                  '  out.sent = calls.slice(); out.painted = painted.slice(); out.navs = navs;\n'
                  '  calls = [];\n'
                  '  for (const a of [5, 0, "nw-", "nw-../x", "nw-a b", "nw-" + "a".repeat(33), "nw-\\"><img src=x onerror=alert(1)>", "x", "", "ALL", undefined, null, {}, ["all"], true]) await newsWatchRestore(a);\n'
                  '  out.refused_sent = calls.length;\n'
                  '  answer = {error: "nope"}; painted = []; navs = 0; await newsWatchRestore("all");\n'
                  '  out.failed = [toasts.length, painted.length, navs];\n'
                  '  console.log(JSON.stringify(out));\n'
                  '})();\n')
        out = self._node(script)
        self.assertEqual(out['sent'], [['POST', '/news-watch/clear', '{"all":true,"undo":true}'], ['POST', '/news-watch/clear', '{"ids":["0123456789abcdef"],"undo":true}'],
                                       ['POST', '/news-watch/clear', '{"ids":["demonews00000001"],"undo":true}']], 'the same route as the clear, with undo, and the same ids')
        self.assertEqual(out['painted'], [[True, False]] * 3, 'the answer is the page, drawn without refilling the form')
        self.assertEqual(out['navs'], 3, 'the sidebar is asked again so its mark agrees at once')
        self.assertEqual(out['refused_sent'], 0, 'an argument that is not "all" or a prefixed id is not sent')
        self.assertEqual(out['failed'], [1, 0, 0], 'a refusal is said, the page is left as it is and the sidebar is not asked')

    def test_every_action_the_script_puts_in_markup_is_a_function_of_the_script(self):
        actions = set(re.findall(r'data-action="(\w+)"', NW))
        functions = set(re.findall(r'^(?:async )?function (\w+)\(', NW, re.M))
        self.assertTrue({'newsWatchClear', 'newsWatchRestore'} <= actions, 'control: the scan found the buttons of the clear and of the undo')
        self.assertEqual(actions - functions, set(), 'a button whose function is not in the file does nothing, and says nothing')

    def test_control_a_good_item_is_a_link_with_its_reasons_and_what_was_done(self):
        good = self._render()['good']
        self.assertIn('<a href="https://news.example.net/php" target="_blank" rel="noopener noreferrer"', good)
        self.assertIn('Called critical', good)
        self.assertIn('Code execution without signing in', good)
        self.assertIn('Alert raised and a scan of all hosts started', good)
        self.assertIn('php', good)


class TestTheSeedAndTheDocs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('seed_newswatch', ROOT / 'packaging' / 'seed-demo-data.py')
        cls.seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.seed)

    def test_the_demo_holds_a_watch_that_is_off_and_reads_no_real_feed(self):
        import urllib.parse
        text = (ROOT / 'packaging' / 'seed-demo-data.py').read_text()
        self.assertIn("'news_watch.json':             build_news_watch,", text)
        self.assertEqual(urllib.parse.urlsplit(self.seed._DEMO_NEWS_FEED).hostname, 'news.example.net', 'example.net is reserved, so the demo cannot reach a real feed')
        self.assertEqual(N.valid_feed_url(self.seed._DEMO_NEWS_FEED), (self.seed._DEMO_NEWS_FEED, None))

    def test_the_demo_state_is_what_the_watch_would_store(self):
        import store_shapes
        data = self.seed.build_news_watch()
        self.assertEqual(repr(store_shapes.normalize('news_watch.json', json.loads(json.dumps(data)))), repr(json.loads(json.dumps(data))), 'no repair')
        items = data['items']
        self.assertGreaterEqual(len(items), 5)
        self.assertEqual([i['seen_at'] for i in items], sorted((i['seen_at'] for i in items), reverse=True), 'newest first, as the watch keeps them')
        self.assertTrue({r for i in items for r in i['reasons']} <= set(N.REASONS))
        self.assertTrue({i['outcome'] for i in items} <= set(N.OUTCOMES))
        self.assertEqual({i['outcome'] for i in items} & {'scanned', 'scan_waiting', 'listed', 'baseline'}, {'scanned', 'scan_waiting', 'listed', 'baseline'}, 'the card shows each outcome a visitor meets first')
        self.assertEqual(len({i['id'] for i in items}), len(items))
        self.assertEqual(set(data['feeds'][self.seed._DEMO_NEWS_FEED]['seen']), {i['id'] for i in items})

    def test_the_demo_setting_is_off_and_valid(self):
        import ast
        text = (ROOT / 'packaging' / 'seed-demo-data.py').read_text()
        m = re.search(r"'news_watch': (\{[^}]*\})", text)
        self.assertTrue(m)
        setting = ast.literal_eval(m.group(1).replace('_DEMO_NEWS_FEED', repr(self.seed._DEMO_NEWS_FEED)))
        self.assertEqual(setting['enabled'], False)
        self.assertEqual(N.settings(setting), setting, 'the settings read back unchanged')

    def test_the_docs_describe_it_and_the_feature_table_holds_one_row(self):
        cve = (ROOT / 'docs' / 'cve.md').read_text()
        self.assertIn('## Security news watch', cve)
        for text in ('Only items that name software on my hosts', 'Raise an alert and scan all hosts', 'security_news_critical', 'at most one scan in six', 'Clear !', 'Clear all !'):
            self.assertIn(text, cve)
        for word in ('genuine', 'genuinely', 'verbatim', 'deliberate', 'deliberately'):
            self.assertNotRegex(cve[cve.index('## Security news watch'):cve.index('## Permissions')], r'\b' + word + r'\b')
        features = (ROOT / 'docs' / 'features.md').read_text()
        self.assertEqual(len(re.findall(r'^\| Security news watch \|', features, re.M)), 1)
        self.assertIn('security_news_critical', (ROOT / 'CHANGELOG.md').read_text())


if __name__ == '__main__':
    unittest.main()
