#!/usr/bin/env python3
"""8.0.1 on the Threat Intel page, in a browser on the demo seed: the Request log, the limits of each service and the setting that lets a ban engine's decision block.

One page, not the gate. The Request log must be where the tabs put it, show what the seeder wrote and keep its box (no sideways scroll at a desktop or a phone width),
every word of it must be translated, the checkbox must go to the server through the real endpoint and come back, the blocks table must say who decided, and the
six limits of the Limits card (lookups, reports and blacklist downloads for each service) must save through the real endpoint, come back, be cleared by a blank box,
keep the card's box at a phone width and be translated.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
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
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()
        import shutil
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
    # side reading starts on), how far the middle of the box is from the middle of the first line of its words, and how many lines the words take.
    # `narrow` names kinds that are squeezed first, so the list holds names that wrap whatever the font and the language.
    KINDS = """(narrow) => {
        const box = document.getElementById('ipintel-ignore-classes'), cs = getComputedStyle(box), rtl = cs.direction === 'rtl';
        for (const id of narrow) box.querySelector('input[data-ipi-class="' + id + '"]').parentElement.style.maxWidth = '150px';
        const b = box.getBoundingClientRect(), edge = rtl ? b.left + box.clientLeft + box.clientWidth : b.left + box.clientLeft;
        const from = (r) => Math.round((rtl ? edge - r.right : r.left - edge) * 10) / 10;
        const kinds = [...box.querySelectorAll('label')].map(l => {
            const i = l.querySelector('input'), ir = i.getBoundingClientRect(), lr = l.getBoundingClientRect();
            const range = document.createRange();
            range.selectNodeContents(l.querySelector('span'));
            const runs = [...range.getClientRects()].filter(r => r.width > 0).sort((a, c) => a.top - c.top);
            const first = runs.filter(r => r.top - runs[0].top < 8), last = runs[runs.length - 1];
            const mid = (Math.min(...first.map(r => r.top)) + Math.max(...first.map(r => r.bottom))) / 2;
            return {id: i.dataset.ipiClass, general: l.classList.contains('ipi-ignore-general'), kind: l.classList.contains('ipi-ignore-kind'),
                    box: from(ir), words: Math.min(...runs.map(from)), top: Math.round(lr.top), boxTop: Math.round(ir.top * 10) / 10,
                    offLine: Math.round((ir.top + ir.height / 2 - mid) * 10) / 10, lines: 1 + Math.round((last.top - runs[0].top) / parseFloat(getComputedStyle(l).fontSize) / 1.2),
                    width: Math.round(lr.width), end: Math.round((from(lr) + lr.width) * 10) / 10};
        });
        for (const id of narrow) box.querySelector('input[data-ipi-class="' + id + '"]').parentElement.style.maxWidth = '';
        return {tracks: cs.gridTemplateColumns.split(' ').map(parseFloat), gap: parseFloat(cs.columnGap), wide: box.clientWidth,
                sideways: box.scrollWidth - box.clientWidth, rtl, table: Object.keys(_IPI_CLASS).length, kinds};
    }"""

    def test_the_kinds_that_are_never_reported_stand_on_the_column_lines(self):
        """Every box of the list starts on one of the grid's column lines and sits on the first line of its words, in several columns and in
        one, in English and in Arabic. The first version indented the finer kinds in every column, so the lower half of the list stood 22px
        to the side of the upper half, and it centred a box on words that wrap, so the box of a two-line name sat between its lines."""
        self.tab('settings')
        self.page.wait_for_selector('#ipintel-limits-card:not([hidden])', timeout=15000)
        self.page.wait_for_function("() => document.querySelectorAll('#ipintel-ignore-classes label').length > 20", timeout=15000)
        assert self.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'
        columns = set()
        try:
            for lang in ('en', 'ar'):
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for width, height in ((1440, 900), (1150, 900), (1024, 900), (390, 844)):
                    self.page.set_viewport_size({'width': width, 'height': height})
                    self.page.wait_for_timeout(500)
                    got = self.page.evaluate(self.KINDS, ['waf', 'config_probe'])
                    where, kinds, tracks = '%s, %dpx wide' % (lang, width), got['kinds'], got['tracks']
                    self.assertEqual(got['rtl'], lang == 'ar', where)
                    self.assertEqual(len(kinds), got['table'], '%s: one box for each kind of the page\'s table' % where)
                    self.assertGreater(len(kinds), 25, 'the control: the list is there')
                    self.assertLessEqual(got['sideways'], 1, '%s: the list scrolls sideways by %s' % (where, got['sideways']))
                    wrapped = sorted(k['id'] for k in kinds if k['lines'] > 1)
                    self.assertTrue({'waf', 'config_probe'} <= set(wrapped), 'the control: the two squeezed names wrap. %s: %r' % (where, wrapped))
                    for k in kinds:
                        self.assertLessEqual(abs(k['offLine']), 2.5, '%s: the box of %s is %spx from the middle of its first line (its words take %d lines)'
                                             % (where, k['id'], k['offLine'], k['lines']))
                        self.assertLessEqual(k['end'], got['wide'] + 1, '%s: %s runs out of the list' % (where, k['id']))
                        if k['general']:
                            self.assertGreaterEqual(k['width'], got['wide'] - 1, '%s: the general kind %s has the row to itself' % (where, k['id']))
                    columns.add(len(tracks))
                    if len(tracks) > 1:
                        step = tracks[0] + got['gap']
                        lines = [round(i * step, 1) for i in range(len(tracks))]
                        for k in kinds:
                            self.assertLessEqual(min(abs(k['box'] - x) for x in lines), 1,
                                                 '%s: the box of %s starts %spx in, on none of the column lines %r' % (where, k['id'], k['box'], lines))
                        self.assertEqual(len({round(k['box'] / step) for k in kinds}), len(tracks), 'the control: every column holds a box. %s' % where)
                    else:
                        under = {k['words'] for k in kinds if k['general']}
                        self.assertEqual(len(under), 1, '%s: the words of the general kinds start at one place: %r' % (where, under))
                        for k in kinds:
                            want = under.copy().pop() if k['kind'] else 0
                            self.assertLessEqual(abs(k['box'] - want), 1, '%s: in one column the box of %s starts %spx in; %s'
                                                 % (where, k['id'], k['box'], 'a finer kind stands under the words of its general kind' if k['kind'] else 'it stands at the edge'))
                    rows = {}
                    for k in kinds:
                        rows.setdefault(k['top'], []).append(k['boxTop'])
                    for top, tops in rows.items():
                        self.assertLessEqual(max(tops) - min(tops), 1, '%s: the boxes of the row at %d are not level: %r' % (where, top, tops))
            self.assertIn(1, columns, 'the control: the list was measured as one column')
            self.assertGreaterEqual(max(columns), 3, 'the control: and as several, %r' % sorted(columns))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})

    def test_the_page_threw_nothing(self):
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
