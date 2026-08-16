#!/usr/bin/env python3
"""v7.0.0: the rendered half of the sidebar auto-hide fix.

The source pins in `test_v700_sidebar_autohide.py` say which class drives the
reveal. This one measures what the browser actually lays out, because the bug
was only visible as geometry: with an alert open, a collapsed sidebar rendered
at 248px while `.app-content` kept its 56px rail margin, so the sidebar sat on
top of the content — "it just moves the other div".

Four states, one page load:
  alerts + auto-hide                      → pinned open (248px)
  alerts + auto-hide + keep-hiding opt-in → stays a rail (56px)   [the new option]
  alerts + manual collapse (auto-hide off)→ stays a rail (56px)   [the bug]
  no alerts + auto-hide                   → stays a rail (56px)

Self-skips without playwright/Chromium/gunicorn, like the other browser suites.
"""
import unittest

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import browser_available, SKIP_REASON   # noqa: E402

if browser_available():                                  # noqa: E402
    from playwright.sync_api import sync_playwright

RAIL = 56
OPEN = 248


@unittest.skipUnless(browser_available(), SKIP_REASON)
class TestSidebarAutohideRendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest(
                'sidebar layout is backend-agnostic — run once under the default backend')
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        self.page = self.browser.new_page(viewport={'width': 1280, 'height': 800})
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.goto(self.base + '/index.html')
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        # The pointer starts at (0,0) — inside the sidebar — and :hover expands
        # it exactly like the alert pin does. Park it over the content or every
        # measurement below reads 248px for the wrong reason.
        self.page.mouse.move(1000, 600)

    def tearDown(self):
        self.page.close()

    def _widths(self):
        """(sidebar width, .app-content left margin), in px."""
        return tuple(self.page.evaluate(
            "() => [document.querySelector('.sidebar'),"
            "       document.querySelector('.app-content')]"
            "      .map((el, i) => parseFloat(getComputedStyle(el)"
            "           [i ? 'marginLeft' : 'width']))"))

    def _set(self, autohide, alerts, keep_hiding=False):
        self.page.evaluate(
            "([ah, n, keep]) => {"
            "  toggleAutohideThroughAlerts(keep);"
            "  toggleAutohideSidebar(ah);"
            "  if (!ah) document.body.classList.add('sidebar-collapsed');"
            "  _paintAlertsBadge(n);"
            "}", [autohide, alerts, keep_hiding])
        # The rail animates its width over 0.16s.
        self.page.wait_for_timeout(400)

    def test_control_the_pin_still_reveals_the_rail(self):
        """Known-good case first: without it, every 56px below proves nothing."""
        self._set(autohide=True, alerts=3)
        width, margin = self._widths()
        self.assertAlmostEqual(width, OPEN, delta=1,
                               msg='auto-hide + open alerts must reveal the sidebar')
        # It reveals as an overlay — the content must NOT be pushed across.
        self.assertAlmostEqual(margin, RAIL, delta=1)

    def test_open_alerts_do_not_block_a_manual_collapse(self):
        """The reported bug. Auto-hide off + Collapse + an open alert."""
        self._set(autohide=False, alerts=3)
        width, margin = self._widths()
        self.assertAlmostEqual(
            width, RAIL, delta=1,
            msg='a manually collapsed sidebar was forced back open by an alert, '
                'while the content kept the 56px rail margin — they overlapped')
        self.assertAlmostEqual(margin, RAIL, delta=1)

    def test_keep_hiding_opt_in_hides_the_rail_through_alerts(self):
        self._set(autohide=True, alerts=3, keep_hiding=True)
        width, _ = self._widths()
        self.assertAlmostEqual(width, RAIL, delta=1,
                               msg='the keep-hiding option did not survive open alerts')

    def test_collapse_works_at_every_width_that_offers_it(self):
        """The Collapse button must do something wherever it is visible.

        v2.2.7 moved the mobile-drawer breakpoint 768→720 but left the desktop
        collapse rules at min-width:769px, so between 721 and 768 the button
        rendered and was inert — no rail, no content margin. 760 and 730 are
        inside that band; 780 and 1280 are the widths that always worked.
        """
        for width in (730, 760, 780, 1280):
            with self.subTest(width=width):
                self.page.set_viewport_size({'width': width, 'height': 800})
                self.page.wait_for_timeout(150)
                # Auto-hide OFF first: the Collapse button is hidden in
                # auto-hide mode (it is redundant there), so checking its
                # visibility before this reads false at every width.
                self._set(autohide=False, alerts=0)
                self.assertTrue(
                    self.page.is_visible('.sidebar-collapse-btn'),
                    f'the Collapse button is hidden at {width}px — if that '
                    'is intended, this width does not belong in the list')
                width_px, margin = self._widths()
                self.assertAlmostEqual(
                    width_px, RAIL, delta=1,
                    msg=f'at {width}px the sidebar offers Collapse but ignores it')
                self.assertAlmostEqual(
                    margin, RAIL, delta=1,
                    msg=f'at {width}px the content keeps the full-width margin '
                        'beside a collapsed sidebar')

    def test_clearing_the_alerts_releases_the_pin(self):
        self._set(autohide=True, alerts=3)
        self.page.evaluate("_paintAlertsBadge(0)")
        self.page.wait_for_timeout(400)
        width, _ = self._widths()
        self.assertAlmostEqual(width, RAIL, delta=1)
        self.assertEqual(self.errors, [], f'uncaught JS errors: {self.errors}')


if __name__ == "__main__":
    unittest.main()
