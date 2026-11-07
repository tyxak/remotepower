#!/usr/bin/env python3
"""Every sidebar page, rendered on the seeded stack, read for the classes of defect a source scan cannot see.

A source scan reads the markup and the string literals. It cannot read a word that is built at run time from a stored
token, a column that is too narrow for its own placeholder, or a row of buttons that wraps onto a second line: the
markup is correct and the page is not. These are measured here, on the demo seeder's data (an empty install renders
every table's empty state, which is the blind spot that made the a11y walk useless until 6.4.3), one login, one walk
over every sidebar page at 1440 x 900 with the sidebar open, and each question asked of what the walk saw.

The walk runs once (`setUpClass`); each test is one question about it. Every question names its population and has a
control that fails when the walk measured nothing.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only (layout is not a
property of the store).
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
# (tests/test_ci_green_parity.py holds the shape).
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

# RP_SWEEP_PAGES=timeline,drift walks only those pages. It exists to take one page's fix out and watch this file fail in about a
# minute instead of three (tools/mutation-harness.py); the population controls below are skipped for it, and a run that uses it
# proves nothing about the other pages.
_SUBSET = [p for p in os.environ.get('RP_SWEEP_PAGES', '').split(',') if p]

# Every text a person can read on the page, with its element's tag and whether it is code: visible text nodes, the
# options of a visible select, and the title / aria-label / placeholder of a visible element.
_MEASURE = r"""(name) => {
  const root = document.getElementById('page-' + name);
  if (!root) return {missing: true};
  const vis = (el) => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const out = {texts: []};
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const p = n.parentElement;
    if (!p || p.closest('script, style, option')) continue;
    if (!vis(p)) continue;
    const t = n.nodeValue.replace(/\s+/g, ' ').trim();
    if (t) out.texts.push({t: t, code: !!p.closest('code, pre, kbd, samp')});
  }
  for (const sel of root.querySelectorAll('select')) {
    if (!vis(sel)) continue;
    for (const o of sel.options) { const t = o.textContent.replace(/\s+/g, ' ').trim(); if (t) out.texts.push({t: t, code: false, option: true}); }
  }
  for (const el of root.querySelectorAll('[title], [aria-label], [placeholder]')) {
    if (!vis(el)) continue;
    for (const a of ['title', 'aria-label', 'placeholder']) {
      const t = (el.getAttribute(a) || '').replace(/\s+/g, ' ').trim();
      if (t) out.texts.push({t: t, code: false, attr: a});
    }
  }
  // a placeholder wider than its own box: measured with the input's font against its inner width
  const cv = document.createElement('canvas').getContext('2d');
  out.placeholders = [];
  for (const i of root.querySelectorAll('input[placeholder]')) {
    if (!vis(i) || i.value || !['text', 'search', 'email', 'url', ''].includes(i.type)) continue;
    const cs = getComputedStyle(i);
    cv.font = cs.fontStyle + ' ' + cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily;
    const need = cv.measureText(i.placeholder).width;
    const have = i.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    out.placeholders.push({id: i.id || '', ph: i.placeholder.slice(0, 60), need: Math.round(need), have: Math.round(have)});
  }
  // the last cell of a body row that holds 2+ buttons: are they on one line?
  out.actionCells = [];
  for (const tr of root.querySelectorAll('tbody tr')) {
    if (!vis(tr)) continue;
    const td = tr.lastElementChild; if (!td) continue;
    const btns = [...td.querySelectorAll('button, a.btn-icon')].filter(vis);
    if (btns.length < 2) continue;
    // a new line starts where a button begins below the bottom of the line before it: small and large buttons on one baseline
    // have different tops and are still one line
    const rs = btns.map(b => b.getBoundingClientRect()).sort((a, b) => a.top - b.top);
    let lines = 1, lineBottom = rs[0].bottom;
    for (let k = 1; k < rs.length; k++) {
      if (rs[k].top >= lineBottom - 1) { lines++; lineBottom = rs[k].bottom; } else lineBottom = Math.max(lineBottom, rs[k].bottom);
    }
    out.actionCells.push({table: (tr.closest('table') || {}).id || '', buttons: btns.length, lines: lines});
  }
  // a search box that reserves room for a magnifier and has none
  out.searchBoxes = [...root.querySelectorAll('input.input-search')].filter(vis).map(i => ({
    id: i.id || i.placeholder, icon: !!(i.parentElement && i.parentElement.querySelector(':scope > svg.icon-search-abs, :scope > svg.icon-search-abs-sm'))}));
  // the Links grid: how tall may it grow (the cap) against the window
  const lg = root.querySelector('#links-grid');
  out.linksGridMax = lg ? parseFloat(getComputedStyle(lg).maxHeight) || 0 : null;
  out.innerHeight = window.innerHeight;
  // page sections: how many titled cards the page has and how tall it is with every card showing (this walk runs with One long
  // page chosen), and whether it has a tab strip. The strip is hidden in this mode, not absent.
  out.sections = {titled: [...root.querySelectorAll('.section-title')].filter(vis).length,
                  height: Math.round(root.getBoundingClientRect().height), strip: !!root.querySelector('nav.pg-tabs[data-pg]')};
  // a control smaller than 24 x 24 px (WCAG 2.2, 2.5.8). SVG parts are not controls of the page's own.
  out.targets = {measured: 0, small: []};
  for (const e of root.querySelectorAll('button, input:not([type=hidden]):not([type=checkbox]):not([type=radio]), select, [role=button], summary')) {
    if (e instanceof SVGElement || getComputedStyle(e).pointerEvents === 'none') continue;   // a native select kept for a combo box is not pressed
    const r = e.getBoundingClientRect(); if (!r.width || !r.height) continue;
    out.targets.measured++;
    if (r.width < 24 || r.height < 24) out.targets.small.push((e.tagName.toLowerCase() + '.' + String(e.className || '').split(' ').slice(0, 2).join('.')) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
  }
  const heads = [...root.querySelectorAll('.page-title, .section-title')].filter(vis);
  out.headings = {pageTitles: heads.filter(h => h.classList.contains('page-title')).length,
                  pageTitlesMarked: heads.filter(h => h.classList.contains('page-title') && h.getAttribute('role') === 'heading' && h.getAttribute('aria-level') === '1').length,
                  cardTitles: heads.filter(h => h.classList.contains('section-title')).length,
                  cardTitlesMarked: heads.filter(h => h.classList.contains('section-title') && h.getAttribute('role') === 'heading').length,
                  levelOnes: [...root.querySelectorAll('[role=heading][aria-level="1"], h1')].filter(vis).length};
  out.netmapNodes = [...root.querySelectorAll('.netmap-node')].map(g => { const t = g.querySelector(':scope > title'); return {name: (g.querySelector('text:nth-of-type(2)') || {}).textContent || '', title: t ? t.textContent : ''}; });
  // a card title that sits flush against the card's own edge (a .table-card has no padding unless it is .card-padded)
  out.flushTitles = [...root.querySelectorAll('.table-card > .section-title')].filter(vis)
    .filter(t => t.getBoundingClientRect().left - t.parentElement.getBoundingClientRect().left < 8).map(t => t.textContent.trim().slice(0, 40));
  return out;
}"""

# Where the word device is the right word. Each entry says why, because an undeclared exemption is indistinguishable
# from a page nobody has looked at (tests/host_terms.py PROTECT is the same list for the source scan).
DEVICE_ALLOWED = [
    (None, re.compile(r'USB devices?', re.I), 'a USB device is a device: the one right use of the word on a page about hosts'),
    ('vpn', re.compile(r'per-device client configs'),
     'WG Access issues a config for each phone or laptop a person connects with: their own device, not one of the hosts'),
    ('self', re.compile(r'\.json'), 'a data file name'),
    ('audit', re.compile(r'\bdevice='),
     'the audit trail shows each record as logged: its detail is key=value text that SIEM forwarding and the CSV carry unchanged, '
     'and a program that reads device= must keep reading it'),
]
_DEVICE = re.compile(r'\bdevices?\b', re.I)

# Page sections. A page with this many titled cards, or this tall with every card showing, has the tab strip (pgTab in app.js), so it
# does not stack five cards or more on one scroll. Measured on the demo seed at 1440 x 900: the median page has 2 titled cards and is
# 938 px tall, 41 of 85 have one or none. The rule is not "every page": a strip with one tab is noise.
SECTIONS_MAX_CARDS = 5
SECTIONS_MAX_PX = 1800
# Pages that meet the rule and have no strip, each with the reason. A listed page that gets tabs or shrinks fails the walk until it
# is taken off the list, so the list only gets shorter.
SECTIONS_EXEMPT = {
    'home': 'a dashboard the user arranges from 71 widgets: several named dashboards would be the answer there, not tabs over a fixed set',
    'docs': 'reference text: 89 cards, each folded, with a search over them; it needs an outline, not tabs',
    'advisory': 'one list of findings, each folded to a line: 27 titles in 865 px',
    'settings': 'has its own left navigation and shows one pane at a time',
}


def device_words(page_name, texts):
    """The texts of a page that say device and are not an allowed use. Code is not read: a file name, a command, a path."""
    bad = []
    for t in texts:
        if t.get('code') or not _DEVICE.search(t['t']):
            continue
        if any((p is None or page_name == p) and rx.search(t['t']) for p, rx, _why in DEVICE_ALLOWED):
            continue
        bad.append(t['t'][:100])
    return bad


# Where a placeholder may be wider than its box, with the reason.
PLACEHOLDER_ALLOWED = {}

# Where a table's action cell may put its buttons on more than one line. Each needs a reason.
ACTION_WRAP_ALLOWED = {
    'ipintel': 'Ban and Ignore are a vertical stack of labelled buttons in a narrow column, by design',
}


def clipped_placeholders(page_name, items):
    return [i for i in items if i['need'] > i['have'] + 1 and (page_name, i['id']) not in PLACEHOLDER_ALLOWED]


def wrapped_action_cells(page_name, cells):
    return [c for c in cells if c['lines'] > 1 and page_name not in ACTION_WRAP_ALLOWED]


# Controls under 24 x 24 px on the demo's pages (see test_controls_are_at_least_24_pixels_across): none.
SMALL_TARGET_CEILING = 0


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestEverySidebarPageRendered(unittest.TestCase):
    rendered = {}

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once, under the default backend')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        data_dir = tempfile.mkdtemp(prefix='rp-pages-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.launch()
        except Exception as exc:
            pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
            return
        try:
            base, shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            browser.close()
            pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        try:
            cls._walk(browser, base)
        finally:
            try:
                browser.close()
                pw.stop()
            finally:
                shutdown()

    @classmethod
    def _walk(cls, browser, base):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        pages, seen = [], set()
        for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                pages.append(m.group(1))
        if _SUBSET:
            pages = [p for p in pages if p in _SUBSET]
        ctx = browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")  # one long page: every card is in this walk
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        page = ctx.new_page()
        try:
            page.goto(base + '/index.html')
            page.fill('#login-user', 'alice')          # the seeder builds its own operator accounts: there is no 'admin'
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(1500)
                cls.rendered[name] = page.evaluate(_MEASURE, name)
                cls.rendered[name]['docTitle'] = page.title()
        finally:
            page.close()
            ctx.close()

    def test_the_walk_saw_every_page_and_read_text_on_it(self):
        if _SUBSET:
            self.skipTest('RP_SWEEP_PAGES: a subset walk')
        self.assertGreaterEqual(len(self.rendered), 80, 'the page enumeration lost pages')
        empty = [n for n, r in self.rendered.items() if r.get('missing') or len(r.get('texts', [])) < 3]
        self.assertEqual(empty, [], 'a page rendered with no readable text: the walk measured nothing there')

    def test_no_page_says_device_for_a_host(self):
        found = {n: device_words(n, r.get('texts', [])) for n, r in self.rendered.items()}
        found = {n: w for n, w in found.items() if w}
        self.assertEqual(found, {}, 'a stored token worded for a person (device_offline, devices, scope device) puts the word back: '
                                    'word it with hostWord() / kindWords() in app.js')

    def test_the_scan_sees_the_word_and_spares_the_allowed_uses(self):
        self.assertEqual(device_words('timeline', [{'t': 'Device Offline', 'code': False}]), ['Device Offline'])
        self.assertEqual(device_words('timeline', [{'t': 'device.json', 'code': True}]), [])
        self.assertEqual(device_words('vpn', [{'t': 'issue per-device client configs so people', 'code': False}]), [])
        self.assertEqual(device_words('hosts', [{'t': 'issue per-device client configs so people', 'code': False}]),
                         ['issue per-device client configs so people'])
        self.assertEqual(device_words('kb', [{'t': 'A USB device was connected to a host', 'code': False}]), [])
        self.assertEqual(device_words('audit', [{'t': 'device=pmx01 doc=d1c', 'code': False}]), [])
        self.assertEqual(device_words('hosts', [{'t': 'device=pmx01', 'code': False}]), ['device=pmx01'])
        # control on the walk itself: the pages known to have shown the word before the fix were read
        for name in ('home', 'timeline', 'history', 'drift', 'dataexplorer', 'maintenance'):
            if name in self.rendered:
                self.assertGreater(len(self.rendered[name]['texts']), 5, name)


    def test_no_placeholder_is_cut_off_by_its_own_box(self):
        seen = sum(len(r.get('placeholders', [])) for r in self.rendered.values())
        if not _SUBSET:
            self.assertGreater(seen, 60, 'control: the walk measured few placeholders, so an empty result below means nothing')
        found = {n: clipped_placeholders(n, r.get('placeholders', [])) for n, r in self.rendered.items()}
        found = {n: [(i['id'] or i['ph'], i['need'], i['have']) for i in v] for n, v in found.items() if v}
        self.assertEqual(found, {}, 'a filter that reads "Search" for "Search hosts..." tells nobody what it searches: give the box '
                                    'room (.input-filter) or let its row wrap')

    def test_no_table_row_puts_its_action_buttons_on_two_lines(self):
        cells = sum(len(r.get('actionCells', [])) for r in self.rendered.values())
        if not _SUBSET:
            self.assertGreater(cells, 100, 'control: the walk measured few action cells, so an empty result below means nothing')
        found = {n: wrapped_action_cells(n, r.get('actionCells', [])) for n, r in self.rendered.items()}
        found = {n: (len(v), v[0]) for n, v in found.items() if v}
        self.assertEqual(found, {}, 'action cells stay on one row at every width (td.row-6, td.exposure-actions, td .btn-icon in '
                                    'styles.css); a row that wraps doubles its height for every host')

    def test_a_search_box_that_leaves_room_for_a_magnifier_draws_it(self):
        boxes = [(n, b) for n, r in self.rendered.items() for b in r.get('searchBoxes', [])]
        if not _SUBSET:
            self.assertGreaterEqual(len(boxes), 3, 'control: the walk found few input-search boxes (hosts, patches, tickets, contacts)')
        self.assertEqual([(n, b['id']) for n, b in boxes if not b['icon']], [],
                         '.input-search reserves 34px on the left for an icon: wrap the input with .search-box and the icon')

    def test_no_card_title_sits_against_the_edge_of_its_card(self):
        found = {n: r['flushTitles'] for n, r in self.rendered.items() if r.get('flushTitles')}
        self.assertEqual(found, {}, 'a .section-title directly inside a .table-card needs .card-padded, or it sits on the card border')

    def test_every_network_map_node_has_its_words_on_hover(self):
        nodes = self.rendered['netmap']['netmapNodes'] if 'netmap' in self.rendered else []
        if not _SUBSET:
            self.assertGreaterEqual(len(nodes), 10, 'control: the seeded map has nodes')
        self.assertEqual([n['name'] for n in nodes if not n['title'] or ' — ' not in n['title']], [])

    def test_the_tab_names_the_page(self):
        titles = {n: r.get('docTitle', '') for n, r in self.rendered.items()}
        if not _SUBSET:
            self.assertGreaterEqual(len(set(titles.values())), 80, 'control: the walk read the tab title of every page')
        # every page has a title of its own, and it is not the bare site title every page used to have
        bare = [n for n, t in titles.items() if ' — ' not in t]
        self.assertEqual(bare, [], 'the tab title does not name the page')
        seen = {}
        for n, t in titles.items():
            seen.setdefault(t, []).append(n)
        self.assertEqual({t: ns for t, ns in seen.items() if len(ns) > 1}, {}, 'two pages share a tab title')

    def test_every_page_has_one_level_one_heading_and_its_card_titles_are_headings(self):
        if not _SUBSET:
            self.assertGreater(sum(r['headings']['cardTitles'] for r in self.rendered.values()), 100, 'control: the walk saw the card titles')
        no_title = {n: r['headings'] for n, r in self.rendered.items() if r['headings']['pageTitlesMarked'] < 1 or r['headings']['levelOnes'] != 1}
        self.assertEqual(no_title, {}, 'a page needs exactly one visible level-1 heading (.page-title marked by _markHeadings)')
        unmarked = {n: (r['headings']['cardTitles'], r['headings']['cardTitlesMarked']) for n, r in self.rendered.items()
                    if r['headings']['cardTitlesMarked'] != r['headings']['cardTitles']}
        self.assertEqual(unmarked, {}, 'a card title that is not a heading is invisible to a screen reader\'s heading list')

    def test_a_page_with_many_cards_or_a_long_scroll_has_tabs(self):
        if _SUBSET:
            self.skipTest('RP_SWEEP_PAGES: a subset walk')
        long_page = lambda r: r['sections']['titled'] >= SECTIONS_MAX_CARDS or r['sections']['height'] > SECTIONS_MAX_PX   # noqa: E731
        needs = {n: r['sections'] for n, r in self.rendered.items() if long_page(r) and not r['sections']['strip']}
        unexplained = {n: s for n, s in needs.items() if n not in SECTIONS_EXEMPT}
        self.assertEqual(unexplained, {}, f'a page with {SECTIONS_MAX_CARDS}+ titled cards or taller than {SECTIONS_MAX_PX} px (every card '
                                          'showing) needs tabs: tag its cards with data-pg-tab and add a .pg-tabs strip, or list it in '
                                          'SECTIONS_EXEMPT with the reason')
        # control: the walk measured the pages, and found the ones that have the strip (3 of the old four are sidebar pages, and 11 gained it)
        self.assertGreaterEqual(sum(1 for r in self.rendered.values() if r['sections']['strip']), 14)
        self.assertGreater(sum(r['sections']['titled'] for r in self.rendered.values()), 150, 'control: the walk counted the card titles')
        # an exemption has an expiry date: a listed page that grew tabs or got short comes off the list
        for name, why in SECTIONS_EXEMPT.items():
            self.assertGreater(len(why), 25, name)
            self.assertIn(name, needs, f'{name} no longer needs its exemption: remove it from SECTIONS_EXEMPT')

    def test_the_tabs_rule_sees_a_long_page_and_a_short_one(self):
        long_page = lambda s: s['titled'] >= SECTIONS_MAX_CARDS or s['height'] > SECTIONS_MAX_PX   # noqa: E731
        self.assertTrue(long_page({'titled': 5, 'height': 900}))
        self.assertTrue(long_page({'titled': 1, 'height': 1801}))
        self.assertFalse(long_page({'titled': 4, 'height': 1800}))

    def test_controls_are_at_least_24_pixels_across(self):
        measured = sum(r['targets']['measured'] for r in self.rendered.values())
        small = {n: r['targets']['small'] for n, r in self.rendered.items() if r['targets']['small']}
        if not _SUBSET:
            self.assertGreater(measured, 3500, 'control: the walk measured the controls of the pages')
        # 1,742 of 4,284 were under it when this was written, and none are now. A control that sets
        # its own size under 24 px is the way back: give it the box (negative margin returns the room) rather than a number here.
        self.assertLessEqual(sum(len(v) for v in small.values()), SMALL_TARGET_CEILING, small)

    def test_the_links_grid_may_use_most_of_the_window(self):
        if _SUBSET and 'links' not in self.rendered:
            self.skipTest('RP_SWEEP_PAGES: no links page')
        r = self.rendered['links']
        # a 340px cap left a 900px window half empty under the cards; scroll-cap-lg is 62vh
        self.assertGreaterEqual(r['linksGridMax'], 0.55 * r['innerHeight'])

    def test_the_scans_see_the_defect_and_spare_what_fits(self):
        self.assertEqual(len(clipped_placeholders('x', [{'id': 'a', 'ph': 'Search hosts', 'need': 89, 'have': 74}])), 1)
        self.assertEqual(clipped_placeholders('x', [{'id': 'a', 'ph': 'Search', 'need': 40, 'have': 74}]), [])
        self.assertEqual(len(wrapped_action_cells('monitor', [{'table': '', 'buttons': 5, 'lines': 2}])), 1)
        self.assertEqual(wrapped_action_cells('ipintel', [{'table': '', 'buttons': 2, 'lines': 2}]), [])
        self.assertEqual(wrapped_action_cells('monitor', [{'table': '', 'buttons': 5, 'lines': 1}]), [])


if __name__ == '__main__':
    unittest.main()
