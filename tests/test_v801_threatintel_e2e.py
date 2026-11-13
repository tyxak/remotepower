#!/usr/bin/env python3
"""8.0.1 on the Threat Intel page, in a browser on the demo seed: the card of provider requests and the setting that lets a ban engine's decision block.

One page, not the gate. The card must be where the tabs put it, show what the seeder wrote and keep its box (no sideways scroll at a desktop or a phone width),
every word of it must be translated, the checkbox must go to the server through the real endpoint and come back, and the blocks table must say who decided.

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


CARD_WORDS = ('Provider requests', 'Time', 'Service', 'Request', 'Address', 'Answer', 'Took', 'Note', 'Lookup', 'Report',
              'Blacklist download', 'OK', 'Already reported', 'Rate limited', 'Server error', 'No answer')


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
        self.assertEqual(rows, 14, 'the demo seeds fourteen lines')
        text = self.page.inner_text('#ipintel-requests-card')
        for words in ('Provider requests', 'SniffCat', 'AbuseIPDB', 'Server error', 'No answer', 'Already reported', 'Rate limited',
                      'Blacklist download', 'Internal server error. Please report this to: support@sniffcat.com', 'unreachable: TimeoutError'):
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

    def test_every_word_of_the_card_has_a_translation(self):
        page = self.page
        self.tab('sources')
        page.wait_for_selector('#ipintel-requests-card:not([hidden])', timeout=15000)
        assert page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'
        rows = dict_rows()
        try:
            for lang in page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')"):
                page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for key in CARD_WORDS:
                    # what the engine returns is what the dictionary holds (a word can be the English one: German "OK", French "Service")
                    self.assertEqual(page.evaluate("(k) => RPi18n.t(k)", key), rows[key][lang], '%s: %r' % (lang, key))
                last = []

                def probe():
                    nonlocal last
                    last = page.evaluate("""() => {
                        const out = [], w = document.createTreeWalker(document.getElementById('ipintel-requests-card'), NodeFilter.SHOW_TEXT);
                        for (let n = w.nextNode(); n; n = w.nextNode()) {
                            const t = n.nodeValue.trim();
                            if (t && n.parentElement.offsetParent !== null && RPi18n.t(t) !== t) out.push(t);
                        }
                        return out; }""")
                    return not last
                _until(probe, seconds=4, step=0.2)
                self.assertEqual(last, [], '%s: text on the card that the dictionary would have translated' % lang)
        finally:
            page.evaluate("() => RPi18n.setLang('en', false)")

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

    def test_the_page_threw_nothing(self):
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
