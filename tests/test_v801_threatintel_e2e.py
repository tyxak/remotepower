#!/usr/bin/env python3
"""8.0.1 on the Threat Intel page, in a browser on the demo seed: the Request log, the limits of each service and the setting that lets a ban engine's decision block.

One page, not the gate. The Request log must be where the tabs put it, show what the seeder wrote and keep its box (no sideways scroll at a desktop or a phone width),
every word of it must be translated, the checkbox must go to the server through the real endpoint and come back, the blocks table must say who decided, and the
six limits of the Limits card (lookups, reports and blacklist downloads for each service) must save through the real endpoint, come back, be cleared by a blank box,
keep the card's box at a phone width and be translated.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402

_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the page is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-v801-ti-')
    proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        shutil.rmtree(data_dir, ignore_errors=True)
        browser_required.skip_or_fail('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
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
        shutil.rmtree(data_dir, ignore_errors=True)
        browser_required.skip_or_fail(f'app stack not available: {exc}')
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()
        shutil.rmtree(_STATE.get('data_dir', ''), ignore_errors=True)       # tmpfs: the seeded data dir goes with the module


def _until(fn, seconds=20, step=0.25):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(step)
    return last


CARD_WORDS = ('Request log', 'Time', 'Service or host', 'Request', 'Address', 'Answer', 'Took', 'Note', 'Lookup', 'Report',
              'Blacklist download', 'Sensor report', 'OK', 'Already reported', 'Rate limited', 'Server error', 'No answer')
LIMIT_WORDS = ('Lookups per day', 'Reports per day', 'Blacklist downloads per day',
               'Each service can have limits of its own, for example when your plan allows more than the numbers above. Leave a box blank to use the number above; blacklist downloads then use 4 a day.')

# the six limits as the server holds them, null where none is set; `save` presses the page's own Save first
READ_LIMITS = """async (save) => {
    if (save) await saveIpIntelSettings();
    const s = (await api('GET', '/ip-intel')).settings, out = {};
    for (const p of ['abuseipdb', 'sniffcat']) for (const k of ['lookups', 'reports', 'downloads']) out[p + '_' + k] = s['limit_' + p + '_' + k] ?? null;
    return out;
}"""
NO_LIMITS = {p + '_' + k: None for p in ('abuseipdb', 'sniffcat') for k in ('lookups', 'reports', 'downloads')}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = _STATE['browser'].new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on('pageerror', lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE['base'] + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(4000)
        cls.page.evaluate("() => showPage('ipintel')")
        cls.page.wait_for_selector('#page-ipintel.active', timeout=20000)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def tab(self, name):
        self.page.click('#page-ipintel [data-pg-tab-btn="%s"]' % name)
        self.page.wait_for_timeout(300)

    def test_the_card_is_in_the_log_sources_tab_and_shows_what_the_seeder_wrote(self):
        self.tab('sources')
        self.page.wait_for_selector('#ipintel-requests-card:not([hidden])', timeout=15000)
        self.assertTrue(self.page.is_visible('#ipintel-requests-card'))
        rows = self.page.evaluate("() => document.querySelectorAll('#ipintel-req-tbody tr').length")
        self.assertEqual(rows, 19, 'the demo seeds fourteen requests and five passes of the hosts')
        text = self.page.inner_text('#ipintel-requests-card')
        for words in ('Request log', 'SniffCat', 'AbuseIPDB', 'Server error', 'No answer', 'Already reported', 'Rate limited',
                      'Blacklist download', 'Sensor report', 'held back by the hour', 'Internal server error. Please report this to: support@sniffcat.com', 'unreachable: TimeoutError'):
            self.assertIn(words, text)
        self.assertEqual(self.page.evaluate("() => document.querySelectorAll('#ipintel-req-tbody .c-red').length > 0"), True)
        self.tab('attackers')
        self.assertFalse(self.page.is_visible('#ipintel-requests-card'), 'a card in another tab stays out of this one')

    def test_it_keeps_its_box_and_the_page_does_not_scroll_sideways(self):
        self.tab('sources')
        self.page.wait_for_selector('#ipintel-requests-card:not([hidden])', timeout=15000)
        for width, height in ((1440, 900), (390, 844)):
            self.page.set_viewport_size({'width': width, 'height': height})
            self.page.wait_for_timeout(400)
            got = self.page.evaluate("""() => {
                const card = document.getElementById('ipintel-requests-card');
                const wrap = card.querySelector('.scrollable-table-wrap');
                const r = card.getBoundingClientRect();
                return {page: document.documentElement.scrollWidth - window.innerWidth, right: Math.round(r.right), width: window.innerWidth,
                        wrapHeight: Math.round(wrap.getBoundingClientRect().height), scrolls: wrap.scrollHeight >= wrap.clientHeight};
            }""")
            self.assertLessEqual(got['page'], 1, '%dpx wide: the page scrolls sideways by %d' % (width, got['page']))
            self.assertLessEqual(got['right'], got['width'] + 1, '%dpx wide: the card runs off the right edge' % width)
            self.assertLessEqual(got['wrapHeight'], 400, '%dpx wide: the table box is uncapped (%d px)' % (width, got['wrapHeight']))
        self.page.set_viewport_size({'width': 1440, 'height': 900})

    def _every_word_has_a_translation(self, tab, card, words):
        page = self.page
        self.tab(tab)
        page.wait_for_selector('#%s:not([hidden])' % card, timeout=15000)
        assert page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'
        rows = dict_rows()
        try:
            for lang in page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')"):
                page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for key in words:
                    # what the engine returns is what the dictionary holds (a word can be the English one: German "OK", French "Service")
                    self.assertEqual(page.evaluate("(k) => RPi18n.t(k)", key), rows[key][lang], '%s: %r' % (lang, key))
                last = []

                def probe():
                    nonlocal last
                    last = page.evaluate("""(id) => {
                        const out = [], w = document.createTreeWalker(document.getElementById(id), NodeFilter.SHOW_TEXT);
                        for (let n = w.nextNode(); n; n = w.nextNode()) {
                            const t = n.nodeValue.trim();
                            if (t && n.parentElement.offsetParent !== null && RPi18n.t(t) !== t) out.push(t);
                        }
                        return out; }""", card)
                    return not last
                _until(probe, seconds=4, step=0.2)
                self.assertEqual(last, [], '%s: text on the card that the dictionary would have translated' % lang)
        finally:
            page.evaluate("() => RPi18n.setLang('en', false)")

    def test_every_word_of_the_card_has_a_translation(self):
        self._every_word_has_a_translation('sources', 'ipintel-requests-card', CARD_WORDS)

    def test_every_word_of_the_limits_card_has_a_translation(self):
        self._every_word_has_a_translation('settings', 'ipintel-limits-card', LIMIT_WORDS)

    def test_the_limits_card_saves_a_limit_for_one_service_and_a_blank_clears_it(self):
        page = self.page
        self.tab('settings')
        page.wait_for_selector('#ipintel-lim-sniffcat-reports', state='visible', timeout=15000)
        general = page.evaluate("async () => { const s = (await api('GET', '/ip-intel')).settings; return [s.daily_lookup_budget ?? 900, s.daily_report_budget ?? 900]; }")
        self.assertEqual(page.evaluate(READ_LIMITS, False), NO_LIMITS, 'none set on the demo instance')
        for prov in ('abuseipdb', 'sniffcat'):
            for kind in ('lookups', 'reports', 'downloads'):
                self.assertEqual(page.input_value('#ipintel-lim-%s-%s' % (prov, kind)), '', 'blank until one is filled in')
        self.assertEqual(page.get_attribute('#ipintel-lim-sniffcat-lookups', 'placeholder'), str(general[0]), 'the placeholder is the number a blank box uses')
        self.assertEqual(page.get_attribute('#ipintel-lim-sniffcat-reports', 'placeholder'), str(general[1]))
        self.assertEqual(page.get_attribute('#ipintel-lim-sniffcat-downloads', 'placeholder'), '4')
        try:
            page.fill('#ipintel-lim-sniffcat-reports', '8800')
            page.fill('#ipintel-lim-sniffcat-downloads', '16')
            self.assertEqual(page.evaluate(READ_LIMITS, True), dict(NO_LIMITS, sniffcat_reports=8800, sniffcat_downloads=16),
                             'one service has its own limits; the other still uses the general ones')
            page.fill('#ipintel-lim-sniffcat-reports', '')          # empty the boxes first, so that only the server can put the numbers back
            page.fill('#ipintel-lim-sniffcat-downloads', '')
            page.evaluate("async () => { await loadIpIntel(); }")
            page.wait_for_timeout(500)
            self.assertEqual(page.input_value('#ipintel-lim-sniffcat-reports'), '8800', 'the page did not show what the server holds')
            self.assertEqual(page.input_value('#ipintel-lim-sniffcat-downloads'), '16', 'the page did not show what the server holds')
            usage = page.inner_text('#ipintel-budget')
            self.assertEqual(usage.count('/ 8800'), 1, usage)
            self.assertIn('AbuseIPDB', usage.split('Reports today:')[1].split('SniffCat')[0])
            self.assertTrue(usage.split('Reports today:')[1].split('SniffCat')[0].rstrip(', ').endswith('/ %s' % general[1]), usage)
        finally:
            page.fill('#ipintel-lim-sniffcat-reports', '')
            page.fill('#ipintel-lim-sniffcat-downloads', '')
            self.assertEqual(page.evaluate(READ_LIMITS, True), NO_LIMITS, 'a blank box clears the limit of that service')

    def test_the_limits_card_keeps_its_box_at_a_desktop_and_a_phone_width(self):
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        try:
            for width, height in ((1440, 900), (390, 844)):
                self.page.set_viewport_size({'width': width, 'height': height})
                self.page.wait_for_timeout(400)
                got = self.page.evaluate("""() => {
                    const card = document.getElementById('ipintel-limits-card'), r = card.getBoundingClientRect();
                    const boxes = [...card.querySelectorAll('input[id^="ipintel-lim-"]')].map(e => e.getBoundingClientRect());
                    return {page: document.documentElement.scrollWidth - window.innerWidth, right: Math.round(r.right), width: window.innerWidth, inputs: boxes.length,
                            clipped: boxes.filter(b => b.right > window.innerWidth + 1 || b.left < -1 || b.width < 30).length};
                }""")
                self.assertEqual(got['inputs'], 6)
                self.assertLessEqual(got['page'], 1, '%dpx wide: the page scrolls sideways by %d' % (width, got['page']))
                self.assertLessEqual(got['right'], got['width'] + 1, '%dpx wide: the card runs off the right edge' % width)
                self.assertEqual(got['clipped'], 0, '%dpx wide: %d of the six limit boxes run off the screen or are squeezed under 30 px' % (width, got['clipped']))
        finally:
            self.page.set_viewport_size({'width': 1440, 'height': 900})

    def test_the_checkbox_goes_to_the_server_and_comes_back(self):
        page = self.page
        self.tab('settings')
        page.wait_for_selector('#ipintel-block-confirmed', state='visible', timeout=15000)
        self.assertFalse(page.is_checked('#ipintel-block-confirmed'), 'off by default')
        label = page.inner_text('#ipintel-settings-card')
        self.assertIn('Also block addresses that fail2ban, CrowdSec or a honeypot has already banned, whatever their score', label)
        self.assertIn('It needs automatic blocking on.', label)
        try:
            page.check('#ipintel-block-confirmed')
            saved = page.evaluate("""async () => { await saveIpIntelSettings(); return (await api('GET', '/ip-intel')).settings.block_confirmed; }""")
            self.assertIs(saved, True)
            page.uncheck('#ipintel-block-confirmed')               # clear it on the page first, so that only the server can tick it again
            page.evaluate("async () => { await loadIpIntel(); }")
            page.wait_for_timeout(500)
            self.assertTrue(page.is_checked('#ipintel-block-confirmed'), 'the page did not show what the server holds')
        finally:
            page.uncheck('#ipintel-block-confirmed')
            self.assertIs(page.evaluate("""async () => { await saveIpIntelSettings(); return (await api('GET', '/ip-intel')).settings.block_confirmed; }"""), False)

    def test_the_blocks_table_says_who_decided(self):
        page = self.page

        def rewrite(route):
            resp = route.fetch()
            body = resp.json()
            blocks = body.get('blocks') or []
            if blocks:
                blocks[0] = dict(blocks[0], by='auto', why='fail2ban')
            route.fulfill(response=resp, json=body)
        page.route('**/api/ip-intel*', rewrite)
        try:
            page.evaluate("async () => { await loadIpIntel(); }")
            self.tab('blocks')
            page.wait_for_selector('#ipintel-blk-tbody tr', timeout=10000)
            text = page.inner_text('#ipintel-blk-tbody')
            self.assertIn('automatic · fail2ban', text.replace('\n', ' '))
        finally:
            page.unroute('**/api/ip-intel*')
            page.evaluate("async () => { await loadIpIntel(); }")

    def test_the_limits_boxes_stand_in_columns_at_every_width(self):
        """The Lookups boxes of the general row and of each service stand one under the other, the Reports boxes in the next column, every box has the
        column's width (a box that wraps does not stretch) and no two boxes on a line overlap. The first version gave each service's name a cell of
        its own, which put its three boxes one column to the right of the general row's; the overflow test above could not see that."""
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        rows = (('ipintel-lookup-budget', 'ipintel-report-budget', 'ipintel-cache-hours'),
                ('ipintel-lim-abuseipdb-lookups', 'ipintel-lim-abuseipdb-reports', 'ipintel-lim-abuseipdb-downloads'),
                ('ipintel-lim-sniffcat-lookups', 'ipintel-lim-sniffcat-reports', 'ipintel-lim-sniffcat-downloads'))
        try:
            for width, height in ((1440, 900), (1000, 800), (800, 800), (390, 844)):
                self.page.set_viewport_size({'width': width, 'height': height})
                self.page.wait_for_timeout(400)
                got = self.page.evaluate("""(rows) => rows.map(r => r.map(id => {
                    const b = document.getElementById(id).getBoundingClientRect();
                    return {x: Math.round(b.left), w: Math.round(b.width), y: Math.round(b.top)}; }))""", rows)
                where = '%dpx wide: %r' % (width, got)
                for col in range(3):
                    xs = [r[col]['x'] for r in got]
                    self.assertLessEqual(max(xs) - min(xs), 1, 'column %d does not line up. %s' % (col + 1, where))
                widths = [b['w'] for r in got for b in r]
                self.assertLessEqual(max(widths) - min(widths), 1, 'the boxes differ in width. %s' % where)
                self.assertGreaterEqual(min(widths), 140, 'a box is squeezed. %s' % where)
                for r in got:
                    if abs(r[0]['x'] - r[1]['x']) > 1:
                        self.assertLessEqual(abs(r[0]['y'] - r[1]['y']), 1, 'side by side, the first two boxes of a row are not level. %s' % where)
                    for i, a in enumerate(r):
                        for b in r[i + 1:]:
                            if abs(a['y'] - b['y']) <= 1:
                                self.assertLessEqual(a['x'] + a['w'], b['x'] + 1, 'two boxes on a line overlap. %s' % where)
        finally:
            self.page.set_viewport_size({'width': 1440, 'height': 900})

    # The list of kinds that are never reported, as a ruler sees it: the grid's own tracks and, for every kind, where its box starts (from the
    # side reading starts on), how far the middle of the box is from the middle of the first line of its words, how many lines the words take,
    # which grid row it is in (labels whose heights overlap are one row, whatever each label's own top is: a label that is centred or pushed to
    # the bottom of its row has another top than the tallest one) and what makes a general kind a heading. `narrow` names kinds that are squeezed
    # first, so the list holds names that wrap whatever the font and the language. The squeeze is put back whatever happens.
    KINDS = """(narrow) => {
        const box = document.getElementById('ipintel-ignore-classes'), cs = getComputedStyle(box), rtl = cs.direction === 'rtl';
        const squeezed = narrow.map(id => box.querySelector('input[data-ipi-class="' + id + '"]').parentElement);
        for (const l of squeezed) l.style.maxWidth = '150px';
        try {
            const b = box.getBoundingClientRect(), edge = rtl ? b.left + box.clientLeft + box.clientWidth : b.left + box.clientLeft;
            const from = (r) => Math.round((rtl ? edge - r.right : r.left - edge) * 10) / 10;
            const kinds = [...box.querySelectorAll('label')].map(l => {
                const i = l.querySelector('input'), ir = i.getBoundingClientRect(), lr = l.getBoundingClientRect(), ls = getComputedStyle(l);
                const range = document.createRange();
                range.selectNodeContents(l.querySelector('span'));
                const runs = [...range.getClientRects()].filter(r => r.width > 0).sort((a, c) => a.top - c.top);
                const first = runs.filter(r => r.top - runs[0].top < 8), last = runs[runs.length - 1];
                const mid = (Math.min(...first.map(r => r.top)) + Math.max(...first.map(r => r.bottom))) / 2;
                return {id: i.dataset.ipiClass, general: l.classList.contains('ipi-ignore-general'),
                        box: from(ir), boxW: Math.round(ir.width * 100) / 100, boxH: Math.round(ir.height * 100) / 100, words: Math.min(...runs.map(from)),
                        top: Math.round(lr.top * 10) / 10, bottom: lr.bottom, boxTop: Math.round(ir.top * 10) / 10,
                        offLine: Math.round((ir.top + ir.height / 2 - mid) * 10) / 10,
                        lines: 1 + Math.round((last.top - runs[0].top) / (parseFloat(ls.lineHeight) || 1)),
                        width: Math.round(lr.width), end: Math.round((from(lr) + lr.width) * 10) / 10,
                        weight: parseInt(ls.fontWeight, 10), rule: parseFloat(ls.borderTopWidth), ruleStyle: ls.borderTopStyle,
                        ruleColour: ls.borderTopColor, lead: parseFloat(ls.marginTop) + parseFloat(ls.paddingTop), row: -1};
            });
            let row = -1, reach = -Infinity;
            for (const k of [...kinds].sort((p, q) => p.top - q.top || p.box - q.box)) {
                if (k.top >= reach - 0.5) { row++; reach = k.bottom; } else reach = Math.max(reach, k.bottom);
                k.row = row;
            }
            return {tracks: cs.gridTemplateColumns.split(' ').map(parseFloat), gap: parseFloat(cs.columnGap), wide: box.clientWidth,
                    sideways: box.scrollWidth - box.clientWidth, rtl, table: Object.keys(_IPI_CLASS).length, kinds,
                    cap: parseFloat(cs.maxHeight), window: window.innerHeight, clientH: box.clientHeight, scrollH: box.scrollHeight,
                    ref: Math.round(document.getElementById('ipintel-report-samples').getBoundingClientRect().width * 100) / 100,
                    coarse: matchMedia('(pointer: coarse)').matches};
        } finally {
            for (const l of squeezed) l.style.maxWidth = '';
        }
    }"""

    # Where the ring of the focused box is drawn, against the edges of the list that clips it (negative: cut). The ring's outer edge is
    # the border box grown by the outline's offset and width.
    RING = """() => {
        const a = document.activeElement, box = document.getElementById('ipintel-ignore-classes');
        const cs = getComputedStyle(a), r = a.getBoundingClientRect(), b = box.getBoundingClientRect();
        const grow = (cs.outlineStyle === 'none' ? 0 : parseFloat(cs.outlineWidth)) + (parseFloat(cs.outlineOffset) || 0);
        const L = b.left + box.clientLeft, T = b.top + box.clientTop, R = L + box.clientWidth, B = T + box.clientHeight;
        return {id: a.dataset && a.dataset.ipiClass, style: cs.outlineStyle, visible: a.matches(':focus-visible'),
                left: r.left - grow - L, top: r.top - grow - T, right: R - (r.right + grow), bottom: B - (r.bottom + grow)};
    }"""

    # The focused element is a box of the list. Firefox puts a list that overflows (so it can be scrolled from the keyboard) in the tab order before
    # its boxes, so a walk through the boxes starts at the first Tab that lands on one.
    IS_BOX = "() => !!document.activeElement && document.activeElement.matches('#ipintel-ignore-classes input')"

    def _the_list_stands_on_its_lines(self, where, got, box):
        """What one measurement of the list has to show. `box` is the size of a checkbox on this screen."""
        kinds, tracks = got['kinds'], got['tracks']
        self.assertEqual(len(kinds), got['table'], '%s: one box for each kind of the page\'s table' % where)
        self.assertGreater(len(kinds), 25, 'the control: the list is there')
        self.assertLessEqual(got['sideways'], 1, '%s: the list scrolls sideways by %s' % (where, got['sideways']))
        wrapped = sorted(k['id'] for k in kinds if k['lines'] > 1)
        self.assertTrue({'waf', 'config_probe'} <= set(wrapped), 'the control: the two squeezed names wrap. %s: %r' % (where, wrapped))
        self.assertAlmostEqual(got['ref'], box, delta=0.5, msg='%s: the page\'s own checkbox is %spx, the control for the size of ours' % (where, got['ref']))
        for k in kinds:
            self.assertAlmostEqual(k['boxW'], got['ref'], delta=0.5, msg='%s: the box of %s is %spx wide, the page\'s checkboxes are %spx'
                                   % (where, k['id'], k['boxW'], got['ref']))
            self.assertAlmostEqual(k['boxH'], got['ref'], delta=0.5, msg='%s: the box of %s is %spx high, the page\'s checkboxes are %spx (the page keeps a '
                                   'narrower box 16px wide, so a box that is too small shows in its height)' % (where, k['id'], k['boxH'], got['ref']))
            self.assertLessEqual(abs(k['offLine']), 1.25, '%s: the box of %s is %spx from the middle of its first line (its words take %d lines)'
                                 % (where, k['id'], k['offLine'], k['lines']))
            self.assertLessEqual(k['end'], got['wide'] + 1, '%s: %s runs out of the list' % (where, k['id']))
            self.assertAlmostEqual(k['words'] - k['box'], k['boxW'] + 8, delta=1, msg='%s: the words of %s start %spx after its box, which is %spx wide plus 8px'
                                   % (where, k['id'], k['words'] - k['box'], k['boxW']))
        # a general kind reads as a heading: a rule above it with room around it, heavier than the kinds, and a row of its own
        general = [k for k in kinds if k['general']]
        self.assertEqual(sorted(k['id'] for k in general), ['probe', 'service_brute'], where)
        for k in general:
            self.assertGreaterEqual(k['weight'], 600, '%s: %s is not heavier than its kinds (%s)' % (where, k['id'], k['weight']))
            self.assertEqual((k['rule'], k['ruleStyle']), (1, 'solid'), '%s: %s has no rule above it' % (where, k['id']))
            self.assertNotIn(k['ruleColour'], ('rgba(0, 0, 0, 0)', 'transparent'), '%s: the rule above %s cannot be seen' % (where, k['id']))
            self.assertGreaterEqual(k['lead'], 12, '%s: the rule above %s has no room (%spx)' % (where, k['id'], k['lead']))
            self.assertGreaterEqual(k['width'], got['wide'] - 1, '%s: the general kind %s has the row to itself' % (where, k['id']))
        for k in kinds:
            if not k['general']:
                self.assertLessEqual(k['weight'], 500, '%s: %s is as heavy as a heading (%s)' % (where, k['id'], k['weight']))
                self.assertEqual(k['rule'], 0, '%s: %s has a rule above it' % (where, k['id']))
        # the column lines: the grid's own tracks, and in one column the edge
        columns = len(tracks)
        if columns > 1:
            step = tracks[0] + got['gap']
            lines = [round(i * step, 1) for i in range(columns)]
            for k in kinds:
                self.assertLessEqual(min(abs(k['box'] - x) for x in lines), 1,
                                     '%s: the box of %s starts %spx in, on none of the column lines %r' % (where, k['id'], k['box'], lines))
            self.assertEqual(len({round(k['box'] / step) for k in kinds}), columns, 'the control: every column holds a box. %s' % where)
        else:
            for k in kinds:
                self.assertLessEqual(abs(k['box']), 1, '%s: in one column the box of %s starts %spx in, not at the edge' % (where, k['id'], k['box']))
        # a row is level: the labels of a row, and so the boxes in them, start at the same height whatever the names take (a label
        # that is centred or pushed down has another top than the tallest one beside it)
        rows = {}
        for k in kinds:
            rows.setdefault(k['row'], []).append(k)
        if columns > 1:
            self.assertTrue(any(len({k['lines'] for k in r}) > 1 for r in rows.values()),
                            'the control: some row holds a name that wraps beside one that does not. %s' % where)
        for n, r in rows.items():
            for field in ('top', 'boxTop'):
                values = [k[field] for k in r]
                self.assertLessEqual(max(values) - min(values), 1, '%s: the %ss of the row %d are not level: %r' % (where, field, n, [(k['id'], k[field]) for k in r]))
        # the cap: 62% of the window (scroll-cap-lg), and where the list is wide enough to need no scrolling it needs none; the 340px cap
        # cut the list inside its first general kind in German at two columns and in English too
        self.assertAlmostEqual(got['cap'], 0.62 * got['window'], delta=1, msg='%s: the list is capped at %spx, which is not 62%% of the window (%spx)'
                               % (where, got['cap'], got['window']))
        if columns > 1:
            self.assertLessEqual(got['scrollH'] - got['clientH'], 1, '%s: the list scrolls inside itself (%s of %s px)' % (where, got['clientH'], got['scrollH']))
        else:
            self.assertGreater(got['scrollH'], got['clientH'] + 50, 'the control: in one column the list is longer than its cap and scrolls inside. %s' % where)

    def test_the_kinds_that_are_never_reported_stand_on_the_column_lines(self):
        """Every box of the list starts on one of the grid's column lines and sits on the first line of its words, in several columns and in
        one, in English, German and Arabic. The first version indented the finer kinds in every column, so the lower half of the list stood 22px
        to the side of the upper half, and it centred a box on words that wrap, so the box of a two-line name sat between its lines."""
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        self.page.wait_for_function("() => document.querySelectorAll('#ipintel-ignore-classes label').length > 20", timeout=15000)
        assert self.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'
        columns = set()
        try:
            for lang in ('en', 'de', 'ar'):
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for width, height in ((1440, 900), (1150, 900), (1024, 900), (390, 844), (280, 700)):
                    self.page.set_viewport_size({'width': width, 'height': height})
                    self.page.wait_for_timeout(500)
                    got = self.page.evaluate(self.KINDS, ['waf', 'config_probe'])
                    self.assertEqual(got['rtl'], lang == 'ar', '%s, %dpx wide' % (lang, width))
                    self.assertFalse(got['coarse'], 'the control: this context has a mouse')
                    self._the_list_stands_on_its_lines('%s, %dpx wide' % (lang, width), got, 16)
                    columns.add(len(got['tracks']))
            self.assertIn(1, columns, 'the control: the list was measured as one column')
            self.assertGreaterEqual(max(columns), 3, 'the control: and as several, %r' % sorted(columns))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})

    def test_a_larger_line_moves_the_box_with_it(self):
        """The box sits on the first line of its words because its place is worked out from the label's own line, not from a number: a larger
        font in the label (a browser's minimum font size and a text size both make one) moves it with the words. With the line height written
        as 19.5px the box of every name stood 5px above its first line at a 20px font."""
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        self.page.wait_for_function("() => document.querySelectorAll('#ipintel-ignore-classes label').length > 20", timeout=15000)
        tag = self.page.add_style_tag(content='.ipi-ignore-class { font-size: 20px; }')
        try:
            self.page.wait_for_timeout(300)
            got = self.page.evaluate(self.KINDS, ['waf', 'config_probe'])
            self.assertEqual(got['kinds'][0]['lines'], 1, 'the control: a short name takes one line')
            self.assertGreater(max(k['lines'] for k in got['kinds']), 2, 'the control: the font is larger, the squeezed names take more lines')
            for k in got['kinds']:
                self.assertLessEqual(abs(k['offLine']), 1.25, 'at a 20px font the box of %s is %spx from the middle of its first line' % (k['id'], k['offLine']))
        finally:
            self.page.evaluate("(t) => t.remove()", tag)

    def test_a_keyboard_focus_ring_is_not_cut_by_the_list(self):
        """The list scrolls, so it clips: a ring drawn outside a box in the first column or the first row is cut by the list's own edge.
        Moving the list from scroll-cap to scroll-cap-lg took it out of the rule that draws the ring inside (outline-offset: -2px) and
        cut the ring of every box in the first column by 3px; nothing in the suite looked at a ring."""
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        self.page.wait_for_function("() => document.querySelectorAll('#ipintel-ignore-classes label').length > 20", timeout=15000)
        ids = self.page.evaluate("() => [...document.querySelectorAll('#ipintel-ignore-classes input')].map(i => i.dataset.ipiClass)")
        self.assertGreater(len(ids), 25, 'the control: the list is there')
        try:
            for width, height in ((1440, 900), (390, 844)):
                self.page.set_viewport_size({'width': width, 'height': height})
                self.page.wait_for_timeout(400)
                self.page.focus('#ipintel-ignore')
                for _ in range(4):
                    self.page.keyboard.press('Tab')
                    if self.page.evaluate(self.IS_BOX):
                        break
                else:
                    self.fail('%dpx wide: four Tabs from the box before the list did not reach a box of it' % width)
                for n, want in enumerate(ids):
                    if n:
                        self.page.keyboard.press('Tab')
                    ring = self.page.evaluate(self.RING)
                    where = '%dpx wide, %s: %r' % (width, want, ring)
                    self.assertEqual(ring['id'], want, 'Tab did not go to the next box. ' + where)
                    self.assertTrue(ring['visible'] and ring['style'] != 'none', 'the focused box shows no ring. ' + where)
                    # the sides of the list do not scroll, so there the ring is cut or it is not; a list scrolls to a whole pixel, so a box can
                    # stand up to a pixel past the edge it was scrolled to at the top or the bottom (the old ring was cut by 1.25px and 3px)
                    for side, room in (('left', 0.5), ('right', 0.5), ('top', 1.0), ('bottom', 1.0)):
                        self.assertGreaterEqual(ring[side], -room, 'the ring is cut at the %s edge of the list. %s' % (side, where))
        finally:
            self.page.set_viewport_size({'width': 1440, 'height': 900})

    def test_on_a_touch_screen_the_boxes_are_the_pages_size_and_on_their_first_line(self):
        """A phone draws a checkbox at 20px and shows the list in one column. The list takes its box size from the same screen the rest of
        the page does, and the box still sits on the first line of its words."""
        ctx = _STATE['browser'].new_context(viewport={'width': 390, 'height': 844}, has_touch=True, is_mobile=True, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        try:
            page = ctx.new_page()
            page.goto(_STATE['base'] + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(4000)
            page.evaluate("() => showPage('ipintel')")
            page.wait_for_selector('#page-ipintel.active', timeout=20000)
            page.click('#page-ipintel [data-pg-tab-btn="settings"]')
            page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
            page.wait_for_function("() => document.querySelectorAll('#ipintel-ignore-classes label').length > 20", timeout=15000)
            page.wait_for_timeout(500)
            got = page.evaluate(self.KINDS, ['waf', 'config_probe'])
            self.assertTrue(got['coarse'], 'the control: this context is a touch screen')
            self.assertEqual(len(got['tracks']), 1, 'the control: a phone shows the list in one column')
            self._the_list_stands_on_its_lines('touch, 390px wide', got, 20)
        finally:
            ctx.close()

    def test_the_page_threw_nothing(self):
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
