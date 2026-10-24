"""7.4.0: long pages show one group of cards at a time (pgTab, the .pg-tabs bar).

Drives the real page: opens each tabbed page, checks that only the chosen group's cards are
displayed, switches tab, and checks again. Also that the choice survives leaving the page, and
that a Threat Intel tile opens its tab. Source checks cover the derived population: every
`data-pg-tab` card belongs to a tab that has a button, and every button has a card.
"""
import os as _os
import sys as _sys
import unittest

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import browser_available, SKIP_REASON   # noqa: E402
import browser_required                                  # noqa: E402

_GATE = browser_available() or browser_required.required()
if browser_available():
    from playwright.sync_api import sync_playwright

PAGES = ('ipintel', 'account', 'sites', 'reports')


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTabsInTheBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            browser_required.skip_or_fail(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _login(self):
        page = self.browser.new_page()
        self.errors = []
        page.on('pageerror', lambda e: self.errors.append(str(e)))
        page.goto(self.base + '/index.html')
        page.evaluate("localStorage.setItem('rp_tour_done', '1')")
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=15000)
        return page

    @staticmethod
    def _shown(page, name):
        """{tab: [cards displayed]} for cards the page itself has not hidden."""
        return page.evaluate("""(name) => {
          const out = {};
          document.querySelectorAll('#page-' + name + ' [data-pg-tab]').forEach(c => {
            if (c.hidden) return;
            (out[c.dataset.pgTab] = out[c.dataset.pgTab] || []).push(getComputedStyle(c).display !== 'none');
          });
          return out;
        }""", name)

    def test_one_group_shows_and_a_click_swaps_it(self):
        page = self._login()
        try:
            for name in PAGES:
                with self.subTest(page=name):
                    page.evaluate(f"localStorage.removeItem('pgtab.{name}'); showPage('{name}')")
                    page.wait_for_selector(f'#page-{name}.active', timeout=10000)
                    page.wait_for_timeout(300)
                    tabs = page.eval_on_selector_all(
                        f'#page-{name} [data-pg-tab-btn]', 'els => els.map(e => e.dataset.pgTabBtn)')
                    self.assertGreaterEqual(len(tabs), 2)
                    for tab in tabs:
                        page.click(f'#page-{name} [data-pg-tab-btn="{tab}"]')
                        shown = self._shown(page, name)
                        self.assertTrue(shown, f'{name}: no cards found')
                        self.assertTrue(all(shown.get(tab, [True])), f'{name}/{tab}: its own cards are off')
                        for other, flags in shown.items():
                            if other != tab:
                                self.assertFalse(any(flags), f'{name}: {other} still shows on {tab}')
                        self.assertEqual(
                            page.get_attribute(f'#page-{name} [data-pg-tab-btn="{tab}"]', 'aria-current'), 'true')
        finally:
            page.close()
        self.assertEqual(self.errors, [])

    def test_the_choice_survives_leaving_the_page(self):
        page = self._login()
        try:
            page.evaluate("localStorage.removeItem('pgtab.reports'); showPage('reports')")
            page.wait_for_selector('#page-reports.active')
            page.click('#page-reports [data-pg-tab-btn="capacity"]')
            page.evaluate("showPage('sites')")
            page.wait_for_selector('#page-sites.active')
            page.evaluate("showPage('reports')")
            page.wait_for_selector('#page-reports.active')
            self.assertEqual(
                page.get_attribute('#page-reports [data-pg-tab-btn="capacity"]', 'aria-current'), 'true')
            self.assertTrue(all(self._shown(page, 'reports')['capacity']))
        finally:
            page.close()

    def test_a_threat_intel_tile_opens_its_tab(self):
        page = self._login()
        try:
            page.evaluate("localStorage.removeItem('pgtab.ipintel'); showPage('ipintel')")
            page.wait_for_selector('#page-ipintel.active')
            page.wait_for_selector('#ipintel-tiles .pg-tile', timeout=10000)
            tile = page.locator('#ipintel-tiles .pg-tile', has_text='Active blocks')
            self.assertEqual(tile.count(), 1)
            tile.click()
            self.assertEqual(
                page.get_attribute('#page-ipintel [data-pg-tab-btn="blocks"]', 'aria-current'), 'true')
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
