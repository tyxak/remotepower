#!/usr/bin/env python3
"""7.4.0: the Back button follows the pages — in a real browser.

test_v740_back_button.py runs the history rules in V8 against a fake stack. This
drives Chromium's own history: nav clicks, history.back() and history.forward(),
and reads what is on screen and what the URL says after each.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os as _os
import sys as _sys
import unittest

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
import browser_required  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright

# Pages every install has on an empty data directory (alerts is a module that
# defaults on).
WALK = ('devices', 'alerts', 'monitor')


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestBackFollowsThePages(unittest.TestCase):
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

    def open_app(self):
        page = self.browser.new_page()
        self.addCleanup(page.close)
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=15000)
        page.evaluate("document.getElementById('tour-backdrop')?.remove();"
                      "document.getElementById('tour-pop')?.remove();")
        self.on(page, 'home')
        return page

    def on(self, page, name, timeout=8000):
        page.wait_for_function(
            "(n) => (document.querySelector('.page.active') || {}).id === 'page-' + n",
            arg=name, timeout=timeout)

    def go(self, page, name):
        page.evaluate("(p) => document.querySelector(`.nav-btn[data-page='${p}']`).click()", name)
        self.on(page, name)

    def back(self, page, name):
        page.evaluate('history.back()')
        self.on(page, name)

    def hash(self, page):
        return page.evaluate('location.hash')

    def test_back_and_forward_walk_the_pages(self):
        page = self.open_app()
        for name in WALK:
            self.go(page, name)
            self.assertEqual(self.hash(page), '#' + name)
        # Back retraces the pages in reverse, one entry each
        for name in ('alerts', 'devices'):
            self.back(page, name)
            self.assertEqual(self.hash(page), '#' + name)
        self.back(page, 'home')
        self.assertIn(self.hash(page), ('', '#home'), 'the page the app was opened on')
        # and Forward replays them
        page.evaluate('history.forward()')
        self.on(page, 'devices')
        self.assertEqual(self.hash(page), '#devices')
        page.evaluate('history.forward()')
        self.on(page, 'alerts')

    def test_the_history_holds_one_entry_per_page_and_no_more(self):
        page = self.open_app()
        start = page.evaluate('history.length')
        for name in WALK:
            self.go(page, name)
        self.go(page, 'devices')            # a page already visited is a new entry
        self.assertEqual(page.evaluate('history.length') - start, len(WALK) + 1)
        before = page.evaluate('history.length')
        page.evaluate("document.querySelector(`.nav-btn[data-page='devices']`).click()")
        page.wait_for_timeout(300)
        self.assertEqual(page.evaluate('history.length'), before, 'the page you are on added an entry')

    def test_settings_tabs_do_not_pile_onto_history(self):
        page = self.open_app()
        start = page.evaluate('history.length')
        self.go(page, 'settings')
        tabs = page.evaluate("[...document.querySelectorAll('[data-action=\"switchSettingsTab\"]')]"
                             ".map(b => b.dataset.arg).filter(Boolean).slice(0, 4)")
        self.assertGreaterEqual(len(tabs), 3, 'control: the settings tabs were found')
        for t in tabs:
            page.evaluate("(t) => switchSettingsTab(t)", t)
            page.wait_for_function("(t) => location.hash === '#settings/' + t", arg=t, timeout=4000)
        self.assertEqual(page.evaluate('history.length') - start, 1, 'a tab flip added an entry')
        self.back(page, 'home')

    def test_calling_off_a_back_with_unsaved_settings_keeps_the_url_in_step(self):
        page = self.open_app()
        self.go(page, 'settings')
        page.evaluate('window._settingsDirty = true')
        page.evaluate('history.back()')
        page.wait_for_selector('#ui-prompt-modal.active', timeout=6000)
        page.click('#ui-prompt-modal [data-action="_uiPromptCancel"]')
        page.wait_for_selector('#ui-prompt-modal.active', state='detached', timeout=6000)
        self.on(page, 'settings')
        self.assertTrue(self.hash(page).startswith('#settings'),
                        'the URL says %r while Settings is on screen' % self.hash(page))
        page.evaluate('window._settingsDirty = false')


if __name__ == '__main__':
    unittest.main()
