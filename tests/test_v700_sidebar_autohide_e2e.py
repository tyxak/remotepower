#!/usr/bin/env python3
"""v7.0.0: the rendered half of the sidebar auto-hide fix.

The source pins in `test_v700_sidebar_autohide.py` say which class drives the
reveal. This one measures what the browser actually lays out, because the bug
was only visible as geometry: with an alert open, a collapsed sidebar rendered
at 248px while `.app-content` kept its 56px rail margin, so the sidebar sat on
top of the content — "it just moves the other div".

Four states, one page load:
  alerts + auto-hide                      → pinned open (248px), the content makes room (v7.4.7)
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
import browser_required                                  # noqa: E402

# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a
# failure. It has to be folded into the CLASS condition: a class-level
# skipUnless never reaches setUpClass, so skip_or_fail alone could not see
# a missing browser at all.
_GATE = browser_available() or browser_required.required()

if browser_available():                                  # noqa: E402
    from playwright.sync_api import sync_playwright

RAIL = 56
OPEN = 248


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestSidebarAutohideRendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest(
                'sidebar layout is backend-agnostic — run once under the default backend')
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
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

    def setUp(self):
        self.page = self.browser.new_page(viewport={'width': 1280, 'height': 800})
        self.page.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")  # one long page: every card is in this test
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
        # v7.4.7: the pin holds the rail open for as long as alerts are open, so the content makes room for it. Until
        # then it kept the margin of the closed rail and the left 192px of every page sat under the pinned rail.
        self.assertAlmostEqual(margin, OPEN, delta=1)

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

    def _edges(self):
        """Where the pinned rail ends and where the page begins, in px from the left edge: the rail's right edge, the
        page title's left edge and the top bar's left margin."""
        return tuple(self.page.evaluate(
            "() => { const r = document.querySelector('.sidebar').getBoundingClientRect();"
            "  const t = document.querySelector('.page.active .page-title').getBoundingClientRect();"
            "  return [r.right, t.left, parseFloat(getComputedStyle(document.querySelector('header')).marginLeft)]; }"))

    def test_the_pinned_rail_does_not_cover_the_page(self):
        """What the user saw: with alerts open the page title, the first filter and the first columns were under the
        rail. Measured on the page title and on the top bar, with the rail pinned open."""
        self._set(autohide=True, alerts=3)
        rail_right, title_left, header_margin = self._edges()
        self.assertGreaterEqual(title_left, rail_right - 1,
                                msg='the page starts under the pinned rail')
        self.assertAlmostEqual(header_margin, OPEN, delta=1,
                               msg='the top bar starts under the pinned rail')

    def test_the_hover_reveal_stays_an_overlay(self):
        """The room is made for the pin only: a hover lasts as long as the pointer is on the rail, and moving the page
        over and back for every pass of the mouse would be worse than the overlap it cures."""
        self._set(autohide=True, alerts=0)
        self.page.mouse.move(20, 300)
        self.page.wait_for_timeout(400)
        width, margin = self._widths()
        self.assertAlmostEqual(width, OPEN, delta=1, msg='hovering the rail did not open it')
        self.assertAlmostEqual(margin, RAIL, delta=1, msg='a hover pushed the page across')

    def test_the_page_follows_the_rail_in_and_out(self):
        self._set(autohide=True, alerts=3)
        self.assertAlmostEqual(self._widths()[1], OPEN, delta=1)
        self.page.evaluate("_paintAlertsBadge(0)")
        self.page.wait_for_timeout(400)
        self.assertAlmostEqual(self._widths()[1], RAIL, delta=1,
                               msg='the page kept the pinned rail margin after the alerts were gone')

    def test_the_opt_out_and_a_manual_collapse_keep_the_rail_margin(self):
        for kwargs in ({'autohide': True, 'alerts': 3, 'keep_hiding': True}, {'autohide': False, 'alerts': 3}):
            with self.subTest(**kwargs):
                self._set(**kwargs)
                self.assertAlmostEqual(self._widths()[1], RAIL, delta=1)

    def test_right_to_left_makes_room_on_the_right(self):
        self.page.evaluate("document.documentElement.setAttribute('dir', 'rtl')")
        self._set(autohide=True, alerts=3)
        margins = self.page.evaluate(
            "() => { const c = getComputedStyle(document.querySelector('.app-content'));"
            "  const h = getComputedStyle(document.querySelector('header'));"
            "  return [parseFloat(c.marginLeft), parseFloat(c.marginRight), parseFloat(h.marginLeft), parseFloat(h.marginRight)]; }")
        self.assertEqual(margins[0], 0, msg='the page kept a left margin in Arabic')
        self.assertAlmostEqual(margins[1], OPEN, delta=1)
        self.assertEqual(margins[2], 0)
        self.assertAlmostEqual(margins[3], OPEN, delta=1)

    def test_the_phone_layout_is_untouched(self):
        """Below 721px the rail is a drawer and the page takes the full width, pinned or not."""
        self.page.set_viewport_size({'width': 700, 'height': 800})
        self.page.wait_for_timeout(150)
        self._set(autohide=True, alerts=3)
        self.assertEqual(self._widths()[1], 0, msg='the pin pushed the phone layout across')
        header = self.page.evaluate("() => parseFloat(getComputedStyle(document.querySelector('header')).marginLeft)")
        self.assertEqual(header, 0)

    def test_clearing_the_alerts_releases_the_pin(self):
        self._set(autohide=True, alerts=3)
        self.page.evaluate("_paintAlertsBadge(0)")
        self.page.wait_for_timeout(400)
        width, _ = self._widths()
        self.assertAlmostEqual(width, RAIL, delta=1)
        self.assertEqual(self.errors, [], f'uncaught JS errors: {self.errors}')


if __name__ == "__main__":
    unittest.main()
