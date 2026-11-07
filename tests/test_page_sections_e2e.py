#!/usr/bin/env python3
"""Page sections: the pages with many cards show one group at a time under tabs (the shared `pgTab` strip).

Threat Intel, My Account, Sites and Reports had the strip since 7.4.0. Server Status, Compliance, Live Monitor, Patches, Tuning,
Network, Pentest, SSH Gateway, Autonomy, KMIP and Tickets stacked 5 to 17 titled cards on one scroll (measured on the demo seed:
1,662 to 4,737 px), so they have it now. The population is read from index.html, so a page that gains or loses its strip changes
what is asserted, and NEW_PAGES below says which pages must have it (a page that lost its strip fails, it does not just drop out).

What is held, for every page with a strip:
* one group of cards is displayed and a click swaps it; a card two tabs share shows on both and on no other;
* every tab shows something (a tab whose cards are all hidden is an empty tab);
* with My Account > Appearance > Page sections set to one long page, every card shows and the strip is hidden, and the switch
  writes its choice to this browser and redoes the page that is open;
* a tile or a link goes to the group when everything is showing.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
import re
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

# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
# (tests/test_ci_green_parity.py holds the shape).
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')

# Every page with a strip, from the markup (lazy pages are templates in index.html, so they count too).
PAGES = sorted(set(re.findall(r'<nav class="pg-tabs"[^>]*\bdata-pg="([a-z0-9-]+)"', _HTML)))
OLD_PAGES = ('account', 'ipintel', 'reports', 'sites')                 # tabs since 7.4.0
# The pages this change added. Each must still have its strip: the list is the control that the population cannot shrink quietly.
NEW_PAGES = ('kmip', 'autonomy', 'sshgw', 'tuning', 'tickets', 'scans', 'patches', 'monitor', 'netmap', 'compliance', 'self', 'cve', 'containers')


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestPageSections(unittest.TestCase):
    page = None

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once, under the default backend')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        data_dir = tempfile.mkdtemp(prefix='rp-sections-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
            return
        try:
            cls._base, cls._shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls._browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls._ctx = cls._browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        cls._ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        cls.page = cls._ctx.new_page()
        cls.errors = []
        cls.page.on('pageerror', lambda e: cls.errors.append(str(e)))
        cls.page.goto(cls._base + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(5000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._ctx.close()
            cls._browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        # one test must not leave the other's preference behind
        self.page.evaluate("() => { localStorage.removeItem('rp_pagetabs'); }")
        self._errors_before = len(self.errors)
        self.addCleanup(lambda: self.assertEqual(self.errors[self._errors_before:], [], 'a page error came up in this test'))

    # ── helpers ──────────────────────────────────────────────────────────────
    def _open(self, name, stacked=False):
        self.page.evaluate("""([n, stacked]) => {
            if (stacked) localStorage.setItem('rp_pagetabs', 'stacked'); else localStorage.removeItem('rp_pagetabs');
            localStorage.removeItem('pgtab.' + n);
            showPage(n); }""", [name, stacked])
        self.page.wait_for_selector(f'#page-{name}.active', timeout=20000)
        self.page.wait_for_timeout(900)
        # a page whose cards a script builds (Server Status) is asked again until every tab of its strip has a card to show
        deadline = time.time() + 25
        while time.time() < deadline:
            drawn = self.page.evaluate("""(n) => { const root = document.getElementById('page-' + n);
                const names = [...root.querySelectorAll('[data-pg-tab-btn]')].map(b => b.dataset.pgTabBtn);
                const have = new Set();
                root.querySelectorAll('[data-pg-tab]').forEach(c => c.dataset.pgTab.split(/\\s+/).forEach(t => have.add(t)));
                return names.every(t => have.has(t)); }""", name)
            if drawn:
                break
            self.page.wait_for_timeout(300)

    def _cards(self, name):
        """One entry per tagged element the page has not hidden itself: its tabs and whether it is displayed."""
        return self.page.evaluate("""(name) => {
            const out = [];
            document.querySelectorAll('#page-' + name + ' [data-pg-tab]').forEach(c => {
              // a card the page hides for its own reasons (the hidden attribute, or the .hidden / .d-none class its scripts toggle)
              if (c.hidden || c.classList.contains('hidden') || c.classList.contains('d-none')) return;
              const r = c.getBoundingClientRect();
              out.push({tabs: c.dataset.pgTab.split(/\\s+/), shown: getComputedStyle(c).display !== 'none', h: r.height});
            });
            return out; }""", name)

    def _tabs(self, name):
        return self.page.eval_on_selector_all(f'#page-{name} [data-pg-tab-btn]', 'els => els.map(e => e.dataset.pgTabBtn)')

    # ── the population ───────────────────────────────────────────────────────
    def test_the_pages_with_a_strip_are_the_old_four_and_the_new_ones(self):
        self.assertEqual(set(PAGES), set(OLD_PAGES) | set(NEW_PAGES))
        self.assertTrue(set(NEW_PAGES) <= set(PAGES), 'a page lost its strip')

    # ── tabs ─────────────────────────────────────────────────────────────────
    def test_one_group_shows_and_a_click_swaps_it(self):
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name)
                tabs = self._tabs(name)
                self.assertGreaterEqual(len(tabs), 2, name)
                for tab in tabs:
                    self.page.click(f'#page-{name} [data-pg-tab-btn="{tab}"]')
                    cards = self._cards(name)
                    self.assertTrue(cards, f'{name}: no tagged cards')
                    for c in cards:
                        self.assertEqual(c['shown'], tab in c['tabs'], f'{name}/{tab}: a card of {c["tabs"]} is {"shown" if c["shown"] else "off"}')
                    self.assertEqual(self.page.get_attribute(f'#page-{name} [data-pg-tab-btn="{tab}"]', 'aria-current'), 'true')

    def test_a_page_opens_on_one_group_before_anything_is_clicked(self):
        # a script-built page (Server Status) draws its cards after showPage has applied the tab: it must apply it again
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name)
                current = self.page.evaluate(f"document.querySelector('#page-{name} [data-pg-tab-btn].active').dataset.pgTabBtn")
                cards = self._cards(name)
                self.assertTrue(cards, name)
                for c in cards:
                    self.assertEqual(c['shown'], current in c['tabs'], f'{name}: opened on {current}, and a card of {c["tabs"]} is '
                                                                      f'{"shown" if c["shown"] else "off"}')

    # A card with no tab shows on every tab, and the tests above never see it (they look at the tagged cards). So the population here is
    # every card-like box of the page, read from the DOM, and the rule is that each is on a tab. A box that answers the toolbar above
    # the strip (a result that appears after a button press) is listed with its reason.
    ALWAYS_SHOWN = {
        '#self-test-result': 'the answer to the Run diagnostics button in the toolbar above the strip, whichever tab is open',
    }

    def test_no_card_is_left_without_a_tab(self):
        seen = 0
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name)
                found = self.page.evaluate("""([n, allowed]) => {
                    const root = document.getElementById('page-' + n);
                    const sel = '.dash-card, .table-card, .doc-card, .card-padded, .settings-section';
                    const all = [...root.querySelectorAll(sel)];
                    const left = all.filter(c => !c.closest('[data-pg-tab]') && !(c.parentElement && c.parentElement.closest(sel))
                                                 && !allowed.some(a => c.closest(a)))
                      .map(c => (c.id ? '#' + c.id : '') + '.' + String(c.className).split(' ').filter(Boolean).slice(0, 3).join('.'));
                    return {total: all.length, left: left}; }""", [name, list(self.ALWAYS_SHOWN)])
                seen += found['total']
                self.assertEqual(found['left'], [], f'{name}: a card with no tab shows on every tab')
        self.assertGreater(seen, 80, 'control: the population of cards was read')

    def test_every_tab_shows_something(self):
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name)
                for tab in self._tabs(name):
                    self.page.click(f'#page-{name} [data-pg-tab-btn="{tab}"]')
                    boxes = [c for c in self._cards(name) if c['shown'] and tab in c['tabs'] and c['h'] > 20]
                    self.assertTrue(boxes, f'{name}/{tab} shows nothing')

    def test_a_card_two_tabs_share_shows_on_both_and_on_no_other(self):
        # Pentest: the New scan card holds the host, tool and profile that the scans and the schedules both use
        self._open('scans')
        seen = {}
        for tab in self._tabs('scans'):
            self.page.click(f'#page-scans [data-pg-tab-btn="{tab}"]')
            seen[tab] = self.page.evaluate("""() => { const c = document.querySelector('#page-scans [data-pg-tab="scans schedules"]');
                return c ? getComputedStyle(c).display !== 'none' : null; }""")
        self.assertEqual(seen, {'scans': True, 'targets': False, 'schedules': True})

    def test_a_link_to_one_monitoring_panel_opens_the_tab_that_holds_it(self):
        # the Scripts page links to the Monitoring page's custom scripts panel with showMonitorSection
        for section, panel, tab in (('section-scripts', 'mon-panel-scripts', 'setup'), ('section-ports', 'mon-panel-ports', 'hosts'),
                                    ('section-slo', 'mon-panel-slo', 'checks')):
            with self.subTest(section=section):
                self._open('monitor')
                self.page.evaluate("s => showMonitorSection(s)", section)
                self.page.wait_for_timeout(300)
                shown = self.page.evaluate("p => getComputedStyle(document.getElementById(p)).display", panel)
                self.assertNotEqual(shown, 'none', f'{panel} is not showing')
                self.assertEqual(self.page.get_attribute(f'#page-monitor [data-pg-tab-btn="{tab}"]', 'aria-current'), 'true')
        self._open('monitor')       # leave the panel filter the way a normal visit does

    def test_the_network_map_is_drawn_when_the_page_opens_on_another_tab(self):
        # the map reads its container's width while it lays out; with its tab hidden that width is 0, and it must still come out whole
        self.page.evaluate("() => { localStorage.setItem('pgtab.netmap', 'watches'); showPage('netmap'); }")
        self.page.wait_for_selector('#page-netmap.active')
        self.page.wait_for_timeout(2500)
        self.page.click('#page-netmap [data-pg-tab-btn="map"]')
        got = self.page.evaluate("""() => { const svg = document.getElementById('netmap-svg');
            return {nodes: svg.querySelectorAll('.netmap-node').length, nan: svg.outerHTML.includes('NaN'), width: svg.getBoundingClientRect().width}; }""")
        self.assertGreater(got['nodes'], 0, got)
        self.assertFalse(got['nan'], got)
        self.assertGreater(got['width'], 300, got)

    def test_a_printed_page_shows_every_group_and_not_the_strip(self):
        # a printed page shows everything the screen could show (test_v740_print_e2e): the tabs are for the screen
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name)
                self.page.emulate_media(media='print')
                try:
                    cards = self._cards(name)
                    self.assertTrue(cards, name)
                    for c in cards:
                        self.assertTrue(c['shown'], f'{name}: a card of {c["tabs"]} is left out of the print')
                    strip = self.page.evaluate(f"getComputedStyle(document.querySelector('#page-{name} .pg-tabs')).display")
                    self.assertEqual(strip, 'none', f'{name}: the strip would print')
                finally:
                    self.page.emulate_media(media='screen')

    # ── links into a card that sits on another tab ────────────────────────────
    # Code that scrolls to a card or focuses a box does nothing when the card is on a tab that is not showing. Found by listing the
    # ids that sit on a tab that is not their page's default and reading every script line that scrolls to or focuses one.
    def test_the_silenced_list_takes_you_to_the_container_exclude_list_on_its_own_tab(self):
        self._open('tuning')
        self.page.click('#page-tuning [data-pg-tab-btn="silenced"]')
        self.page.evaluate("() => gotoSuppression('tuning', 'container-excludes')")
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.get_attribute('#page-tuning [data-pg-tab-btn="containers"]', 'aria-current'), 'true')
        self.assertTrue(self.page.evaluate("document.getElementById('container-excludes').offsetParent !== null"))

    def test_an_unverified_scan_target_opens_the_targets_tab(self):
        self._open('scans')
        self.page.evaluate("""async () => {
            _scanSelectedDevice = {id: 'x', name: 'x'}; _scanVerifiedVhosts = ['verified.example'];
            document.getElementById('scan-vhost').value = 'unverified.example';
            await queueScan(); }""")
        self.page.wait_for_timeout(300)
        try:
            self.assertEqual(self.page.get_attribute('#page-scans [data-pg-tab-btn="targets"]', 'aria-current'), 'true')
            self.assertTrue(self.page.evaluate("document.getElementById('scan-targets-list').offsetParent !== null"))
        finally:
            self.page.evaluate("() => { _scanSelectedDevice = null; document.getElementById('scan-vhost').value = ''; }")

    def test_the_password_nudge_opens_the_security_tab(self):
        self.page.evaluate("() => { localStorage.setItem('pgtab.account', 'profile'); gotoPasswordChange(); }")
        self.page.wait_for_selector('#page-account.active')
        self.page.wait_for_timeout(700)
        try:
            self.assertEqual(self.page.get_attribute('#page-account [data-pg-tab-btn="security"]', 'aria-current'), 'true')
            self.assertTrue(self.page.evaluate("document.getElementById('account-password-section').offsetParent !== null"))
        finally:
            self.page.keyboard.press('Escape')        # the nudge opens the change-password dialog
            self.page.evaluate("() => localStorage.removeItem('pgtab.account')")

    # ── one long page ────────────────────────────────────────────────────────
    def test_one_long_page_shows_every_card_and_hides_the_strip(self):
        for name in PAGES:
            with self.subTest(page=name):
                self._open(name, stacked=True)
                for c in self._cards(name):
                    self.assertTrue(c['shown'], f'{name}: a card of {c["tabs"]} is off with one long page chosen')
                strip = self.page.evaluate(f"getComputedStyle(document.querySelector('#page-{name} .pg-tabs')).display")
                self.assertEqual(strip, 'none', name)

    def test_tabs_come_back_when_the_choice_is_undone(self):
        name = 'kmip'
        self._open(name, stacked=True)
        self.page.evaluate("() => { localStorage.removeItem('rp_pagetabs'); }")
        self.page.evaluate("n => showPage(n)", 'sites')
        self.page.wait_for_selector('#page-sites.active')
        self.page.evaluate("n => showPage(n)", name)
        self.page.wait_for_selector(f'#page-{name}.active')
        self.page.wait_for_timeout(400)
        self.assertNotEqual(self.page.evaluate(f"getComputedStyle(document.querySelector('#page-{name} .pg-tabs')).display"), 'none')
        self.assertTrue(any(not c['shown'] for c in self._cards(name)), 'every card still shows with tabs chosen')

    def test_the_appearance_switch_writes_the_choice_and_redoes_the_open_page(self):
        self.page.evaluate("() => { localStorage.removeItem('pgtab.account'); showPage('account'); }")
        self.page.wait_for_selector('#page-account.active')
        self.page.wait_for_selector('#acct-page-sections', state='attached')
        self.page.wait_for_timeout(600)
        sel = self.page.locator('#acct-page-sections')
        self.assertEqual(sel.input_value(), 'tabs')
        self.assertTrue(any(not c['shown'] for c in self._cards('account')), 'tabs are on but every account card shows')
        sel.select_option('stacked')
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.evaluate("localStorage.getItem('rp_pagetabs')"), 'stacked')
        self.assertTrue(all(c['shown'] for c in self._cards('account')), 'the open page was not redone')
        # the select shows the stored value the next time the page is built
        self.page.evaluate("() => { showPage('sites'); showPage('account'); }")
        self.page.wait_for_timeout(600)
        self.assertEqual(self.page.locator('#acct-page-sections').input_value(), 'stacked')
        self.page.locator('#acct-page-sections').select_option('tabs')
        self.page.wait_for_timeout(300)
        self.assertIsNone(self.page.evaluate("localStorage.getItem('rp_pagetabs')"))
        self.assertTrue(any(not c['shown'] for c in self._cards('account')))

    def test_a_tile_goes_to_its_group_when_everything_is_showing(self):
        name = 'kmip'
        self._open(name, stacked=True)
        got = self.page.evaluate("""() => {
            const seen = [];
            const orig = Element.prototype.scrollIntoView;
            Element.prototype.scrollIntoView = function () { seen.push(this.dataset.pgTab || ''); };
            try { pgTab('kmip:activity'); } finally { Element.prototype.scrollIntoView = orig; }
            return seen; }""")
        self.assertEqual(got, ['activity'])
        # with tabs it swaps the group in and does not scroll
        self._open(name)
        got = self.page.evaluate("""() => {
            const seen = [];
            const orig = Element.prototype.scrollIntoView;
            Element.prototype.scrollIntoView = function () { seen.push(this.dataset.pgTab || ''); };
            try { pgTab('kmip:activity'); } finally { Element.prototype.scrollIntoView = orig; }
            return seen; }""")
        self.assertEqual(got, [])


if __name__ == '__main__':
    unittest.main()
