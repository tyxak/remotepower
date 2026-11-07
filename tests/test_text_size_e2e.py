#!/usr/bin/env python3
"""Text size, measured in a browser: the user menu, a dialog at 150 percent, a tooltip, a narrow window.

The source pins are in test_text_size.py. What they cannot see is geometry:

* at 150 percent the Enrol dialog was taller than the window and its top was cut off, because zoom
  scaled the `90vh` cap along with everything else;
* a popup placed from a measured rect landed `zoom` times too far from the control it belongs to.

Self-skips without playwright / Chromium / gunicorn, like the other browser suites.
"""
import os as _os
import sys as _sys
import unittest

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import browser_available, SKIP_REASON   # noqa: E402
import browser_required                                  # noqa: E402

# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure; it has to be part of the CLASS condition.
_GATE = browser_available() or browser_required.required()

if browser_available():                                  # noqa: E402
    from playwright.sync_api import sync_playwright

_INIT = ("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); %s } catch (e) {}")


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTextSizeRendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('text size is backend-agnostic: run once under the default backend')
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

    def _open(self, width=1440, height=900, stored=None):
        ctx = self.browser.new_context(viewport={'width': width, 'height': height}, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")  # one long page: every card is in this walk
        self.addCleanup(ctx.close)
        stored_js = f"localStorage.setItem('rp_uiscale', '{stored}');" if stored is not None else ''
        ctx.add_init_script(_INIT % stored_js)
        page = ctx.new_page()
        self.errors = []
        page.on('pageerror', lambda e: self.errors.append(str(e)))
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=30000)
        page.wait_for_timeout(800)
        return page

    def _zoom(self, page):
        return page.evaluate("() => ({ variable: document.documentElement.style.getPropertyValue('--rp-zoom'), "
                             "computed: getComputedStyle(document.documentElement).zoom, stored: localStorage.getItem('rp_uiscale'), "
                             "shown: document.getElementById('acct-textsize-val').textContent })")

    def test_the_user_menu_steps_the_size_and_it_survives_a_reload(self):
        page = self._open()
        self.assertEqual(self._zoom(page)['shown'], '100%')
        page.click('.acct-btn')
        page.click('#acct-textsize-up')
        page.click('#acct-textsize-up')
        z = self._zoom(page)
        self.assertEqual((z['variable'], z['computed'], z['stored'], z['shown']), ('1.25', '1.25', '125', '125%'))
        self.assertFalse(page.evaluate("document.getElementById('acct-dropdown').classList.contains('hidden')"),
                         'the menu closed on the first press: a second press would need it opened again')
        page.reload()
        page.wait_for_selector('#app', state='visible', timeout=30000)
        page.wait_for_timeout(800)
        self.assertEqual(self._zoom(page)['computed'], '1.25', 'the size is kept in this browser')
        page.click('.acct-btn')
        page.click('#acct-textsize-down')
        page.click('#acct-textsize-down')
        z = self._zoom(page)
        self.assertEqual((z['variable'], z['computed'], z['shown']), ('', '1', '100%'))
        self.assertEqual(self.errors, [])

    def test_my_account_marks_the_step_in_use(self):
        page = self._open(stored=150)
        page.evaluate("showPage('account')")
        page.wait_for_selector('#cfg-ui-scale button')
        marked = page.evaluate("() => [...document.querySelectorAll('#cfg-ui-scale button')].map(b => [b.textContent, b.getAttribute('aria-pressed'), b.disabled])")
        self.assertEqual([m[0] for m in marked], ['80%', '90%', '100%', '110%', '125%', '150%', '175%', '200%', '250%', '300%'])
        self.assertEqual([m[0] for m in marked if m[1] == 'true'], ['150%'])
        self.assertEqual([m[0] for m in marked if m[2]], ['250%', '300%'])   # 1440 wide keeps 720 page pixels at 200
        page.click('#cfg-ui-scale button[data-arg="110"]')
        self.assertEqual(self._zoom(page)['computed'], '1.1')

    def test_a_dialog_fits_the_window_at_150_percent(self):
        for stored in (100, 150):
            with self.subTest(size=stored):
                page = self._open(stored=stored)
                page.evaluate("openEnrollModal()")
                page.wait_for_selector('#enroll-modal .modal', state='visible')
                page.wait_for_timeout(300)
                r = page.evaluate("() => { const r = document.querySelector('#enroll-modal .modal').getBoundingClientRect(); return {top: r.top, bottom: r.bottom, h: innerHeight}; }")
                self.assertGreaterEqual(r['top'], 0, 'the top of the dialog is above the window')
                self.assertLessEqual(r['bottom'], r['h'] + 1, 'the bottom of the dialog is below the window')

    def test_a_tooltip_stays_beside_its_control_when_the_page_is_zoomed(self):
        for stored in (100, 150):
            with self.subTest(size=stored):
                page = self._open(stored=stored)
                nav = page.query_selector('.nav-btn[data-page="alerts"]')
                nav.hover()
                page.wait_for_selector('#rp-tooltip:not([hidden])', timeout=5000)
                page.wait_for_timeout(200)
                gap = page.evaluate("() => document.getElementById('rp-tooltip').getBoundingClientRect().left - document.querySelector('.nav-btn[data-page=alerts]').getBoundingClientRect().right")
                # 8 page pixels between the control and the tip, which is 8 * zoom screen pixels
                self.assertAlmostEqual(gap, 8 * stored / 100, delta=2.5)

    def test_the_top_bar_keeps_the_page_name_at_the_largest_step(self):
        # at 200% on a 1440 window the bar is 467 page pixels wide; the crumb was squeezed to 6 px by the refresh label and the buttons
        page = self._open(stored=200)
        for name, text in (('home', 'Dashboard'), ('checks', 'Checks')):
            page.evaluate("n => showPage(n)", name)
            page.wait_for_timeout(700)
            m = page.evaluate("() => { const c = document.getElementById('topbar-crumb'); return {text: c.textContent, w: c.getBoundingClientRect().width, clipped: c.scrollWidth > c.clientWidth + 1}; }")
            self.assertIn(text, m['text'])
            self.assertFalse(m['clipped'], m)
            self.assertGreater(m['w'], 100, m)      # page pixels * 2 at this size: Dashboard is 63 at 100%

    def test_a_narrow_window_is_held_to_the_sizes_that_fit(self):
        for width, want in ((390, '110%'), (1000, '125%'), (1440, '200%')):
            with self.subTest(width=width):
                page = self._open(width=width, height=800, stored=300)
                self.assertEqual(self._zoom(page)['shown'], want)
        page = self._open(width=1440, height=800, stored=300)
        page.set_viewport_size({'width': 1000, 'height': 800})
        page.wait_for_function("document.getElementById('acct-textsize-val').textContent === '125%'", timeout=5000)


if __name__ == '__main__':
    unittest.main()
