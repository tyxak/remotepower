#!/usr/bin/env python3
"""8.0.0: a tab that belongs to an optional module is wired the same way everywhere, and the Traffic view sits on the Threat Intel page.

`_PG_TAB_HOOKS` in app.js lists the tabs whose cards a lazy file fills: [page, tab, module, file, function]. For each entry the page needs a tab button of that name, hidden until
the module gate shows it (`data-module`, class `d-none`), with a `data-arg` that names the same page and tab, and cards carrying that tab name; the file has to exist and define
the function. A hook that still names the page a tab moved away from fails every one of those, so the move of Traffic from Network to Threat Intel cannot leave the old line behind
(the browser would show an empty tab with no error). The other direction is checked too: a tab hidden by a module that has no hook shows nothing when it opens.

The checker is a function, so the controls at the end can hand it planted sources and see it fail.
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / 'server' / 'html' / 'index.html'
JS = ROOT / 'server' / 'html' / 'static' / 'js'


class _Scan(HTMLParser):
    """The tab strips, their buttons and the cards that name a tab, each with the page it sits in."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.page = None
        self.nav = None
        self.buttons = []       # dicts: page, strip, tab, module, arg, classes
        self.cards = []         # (page, [tab names])
        self.ids = {}           # id -> [page, ...]

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        classes = (a.get('class') or '').split()
        if (a.get('id') or '').startswith('page-') and 'page' in classes:
            self.page = a['id'][5:]
        if tag == 'nav' and 'pg-tabs' in classes:
            self.nav = a.get('data-pg')
        if tag == 'button' and 'data-pg-tab-btn' in a and self.nav:
            self.buttons.append({'page': self.page, 'strip': self.nav, 'tab': a['data-pg-tab-btn'], 'module': a.get('data-module'), 'arg': a.get('data-arg'), 'classes': classes})
        if 'data-pg-tab' in a:
            self.cards.append((self.page, a['data-pg-tab'].split()))
        if a.get('id'):
            self.ids.setdefault(a['id'], []).append(self.page)

    def handle_endtag(self, tag):
        if tag == 'nav':
            self.nav = None


def scan(html):
    s = _Scan()
    s.feed(html)
    s.close()
    return s


def hooks_of(app_js):
    """The entries of _PG_TAB_HOOKS as 5-tuples, read from the source of app.js."""
    m = re.search(r'const _PG_TAB_HOOKS = \[(.*?)\];', app_js, re.S)
    assert m, '_PG_TAB_HOOKS was not found in app.js'
    entry = r"\[\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\]"
    return re.findall(entry, m.group(1))


def module_pages_of(app_js):
    m = re.search(r'const MODULE_PAGES = \{(.*?)\n\};', app_js, re.S)
    assert m, 'MODULE_PAGES was not found in app.js'
    return set(re.findall(r'^\s*([a-z_]+):', m.group(1), re.M))


def problems(hooks, sc, modules, files):
    """What is wrong with the wiring of the module tabs: a list of sentences, empty when it is sound. `files` maps a file name to its source."""
    out = []
    for page, tab, module, file, fn in hooks:
        btn = [b for b in sc.buttons if b['strip'] == page and b['tab'] == tab]
        if not btn:
            out.append(f'hook {page}:{tab}: the {page} page has no tab button named {tab}')
            continue
        b = btn[0]
        if b['module'] != module:
            out.append(f'hook {page}:{tab}: the button carries data-module={b["module"]!r}, the hook names module {module!r}')
        if b['arg'] != f'{page}:{tab}':
            out.append(f'hook {page}:{tab}: the button opens {b["arg"]!r}')
        if 'd-none' not in b['classes']:
            out.append(f'hook {page}:{tab}: the button is not hidden until the module gate shows it (class d-none), so a switched-off module shows an empty tab')
        if not any(p == page and tab in names for p, names in sc.cards):
            out.append(f'hook {page}:{tab}: no card on the {page} page carries data-pg-tab={tab}')
        if module not in modules:
            out.append(f'hook {page}:{tab}: {module!r} is not a key of MODULE_PAGES')
        src = files.get(file)
        if src is None:
            out.append(f'hook {page}:{tab}: {file} does not exist')
        elif not re.search(r'function\s+' + re.escape(fn) + r'\s*\(', src):
            out.append(f'hook {page}:{tab}: {file} does not define {fn}()')
    hooked = {(p, t) for p, t, *_ in hooks}
    for b in sc.buttons:
        if b['module'] and (b['strip'], b['tab']) not in hooked:
            out.append(f'tab {b["strip"]}:{b["tab"]} is hidden by module {b["module"]!r} but has no entry in _PG_TAB_HOOKS, so nothing fills it')
    return out


def _files():
    return {p.name: p.read_text(encoding='utf-8') for p in JS.glob('app*.js')}


class TestTheWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = (JS / 'app.js').read_text(encoding='utf-8')
        cls.sc = scan(HTML.read_text(encoding='utf-8'))
        cls.hooks = hooks_of(cls.app)
        cls.modules = module_pages_of(cls.app)
        cls.files = _files()

    def test_the_population_is_what_was_counted(self):
        gated = [b for b in self.sc.buttons if b['module']]
        self.assertGreaterEqual(len(self.hooks), 1, 'hooks')
        self.assertGreaterEqual(len(gated), 1, 'tab buttons hidden by a module')
        # counted on 2026-11-09: 55 buttons in 17 strips, 120 elements that name a tab (grep over the markup gives the same 17, 55 and 120)
        self.assertGreaterEqual(len(self.sc.buttons), 50, 'tab buttons in all (the scan went blind if this drops)')
        self.assertGreaterEqual(len({b['strip'] for b in self.sc.buttons}), 16, 'tab strips')
        self.assertGreaterEqual(len(self.sc.cards), 110, 'elements that name a tab')

    def test_every_hook_matches_the_markup_and_every_gated_tab_has_a_hook(self):
        gated = [b for b in self.sc.buttons if b['module']]
        found = problems(self.hooks, self.sc, self.modules, self.files)
        self.assertEqual(found, [], f'{len(self.hooks)} hooks, {len(gated)} gated tabs:\n' + '\n'.join(found))

    def test_the_traffic_view_is_on_the_threat_intel_page_and_not_on_the_network_page(self):
        self.assertEqual(self.sc.ids.get('traffic-wrap'), ['ipintel'], 'the cards of the Traffic view are on the Threat Intel page, once')
        mine = [b for b in self.sc.buttons if b['tab'] == 'traffic' and b['module'] == 'traffic']
        self.assertEqual([(b['strip'], b['arg']) for b in mine], [('ipintel', 'ipintel:traffic')])
        self.assertEqual([t for t in self.hooks if t[2] == 'traffic'], [('ipintel', 'traffic', 'traffic', 'app-traffic.js', 'trafficEnter')])
        network = [b['tab'] for b in self.sc.buttons if b['strip'] == 'netmap']
        self.assertEqual(network, ['map', 'dependencies', 'discovery', 'watches'], 'the Network page keeps its four tabs')
        ipintel = [b['tab'] for b in self.sc.buttons if b['strip'] == 'ipintel']
        self.assertEqual(ipintel, ['attackers', 'blocks', 'sources', 'traffic', 'settings'], 'Traffic sits before Settings')


class TestTheCheckerCanFail(unittest.TestCase):
    """Planted sources: each wrong wiring is named, and the right one is not."""

    HOOK = [('ipintel', 'traffic', 'traffic', 'app-traffic.js', 'trafficEnter')]
    FILES = {'app-traffic.js': 'function trafficEnter() {}'}
    MODULES = {'traffic', 'alerts'}
    PAGE = ('<div id="page-ipintel" class="page"><nav class="pg-tabs" data-pg="ipintel">'
            '<button class="pg-tab d-none" data-pg-tab-btn="traffic" data-module="traffic" data-action="pgTab" data-arg="ipintel:traffic">Traffic</button></nav>'
            '<div id="traffic-wrap" data-pg-tab="traffic"></div></div>')

    def check(self, html=None, hooks=None, files=None, modules=None):
        return problems(self.HOOK if hooks is None else hooks, scan(self.PAGE if html is None else html), self.MODULES if modules is None else modules, self.FILES if files is None else files)

    def test_the_planted_sound_wiring_is_clean(self):
        self.assertEqual(self.check(), [])

    def test_a_hook_that_names_the_page_a_tab_moved_away_from(self):
        out = self.check(hooks=[('netmap', 'traffic', 'traffic', 'app-traffic.js', 'trafficEnter')])
        self.assertTrue(any('the netmap page has no tab button named traffic' in p for p in out), out)
        self.assertTrue(any('hidden by module' in p and 'no entry' in p for p in out), 'and the tab that is left has no hook: ' + str(out))

    def test_a_button_of_another_module(self):
        out = self.check(html=self.PAGE.replace('data-module="traffic"', 'data-module="alerts"'))
        self.assertTrue(any("data-module='alerts'" in p for p in out), out)

    def test_a_button_that_is_not_hidden_until_the_gate_shows_it(self):
        out = self.check(html=self.PAGE.replace('pg-tab d-none', 'pg-tab'))
        self.assertTrue(any('not hidden until the module gate' in p for p in out), out)

    def test_a_button_that_opens_another_page(self):
        out = self.check(html=self.PAGE.replace('data-arg="ipintel:traffic"', 'data-arg="netmap:traffic"'))
        self.assertTrue(any("opens 'netmap:traffic'" in p for p in out), out)

    def test_cards_that_name_no_such_tab(self):
        out = self.check(html=self.PAGE.replace('data-pg-tab="traffic"', 'data-pg-tab="other"'))
        self.assertTrue(any('no card on the ipintel page carries data-pg-tab=traffic' in p for p in out), out)

    def test_a_file_that_is_missing_or_lacks_the_function(self):
        self.assertTrue(any('does not exist' in p for p in self.check(files={})))
        self.assertTrue(any('does not define trafficEnter()' in p for p in self.check(files={'app-traffic.js': 'function other() {}'})))

    def test_a_module_that_is_not_registered(self):
        self.assertTrue(any('not a key of MODULE_PAGES' in p for p in self.check(modules={'alerts'})))

    def test_a_gated_tab_without_a_hook(self):
        out = self.check(hooks=[])
        self.assertTrue(any('has no entry in _PG_TAB_HOOKS' in p for p in out), out)

    def test_the_parsers_read_the_real_source_shape(self):
        self.assertEqual(hooks_of("const _PG_TAB_HOOKS = [['a', 'b', 'c', 'd.js', 'fn'], ['e','f','g','h.js','fn2']];"), [('a', 'b', 'c', 'd.js', 'fn'), ('e', 'f', 'g', 'h.js', 'fn2')])
        self.assertEqual(module_pages_of("const MODULE_PAGES = {\n  alerts:     'alerts',\n  mcp:        null,   // note\n  traffic:    null,\n};"), {'alerts', 'mcp', 'traffic'})


if __name__ == '__main__':
    unittest.main()
