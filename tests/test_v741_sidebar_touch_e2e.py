#!/usr/bin/env python3
"""v7.4.1, issue #35: auto-hide is unusable on a touch screen.

The rail expanded on :hover and on nothing else. On an iPad a tap counts as a
hover and the browser keeps it until the next tap somewhere else, so the
sidebar opened over the page on any tap near it. Auto-hide was on by default,
and in that mode the Collapse button is hidden, so nothing on the page would
undo it. Open alerts also pin the rail open on every alert poll, which read as
"it reopened by itself after about 30 seconds".

Measured with a touch-emulating browser context (the iPad's primary pointer
cannot hover) and, as the control, a desktop context where it can:

  touch    default            -> no auto-hide, sidebar open, Collapse visible
  touch    Collapse, then tap the rail -> stays a rail (the sticky hover)
  touch    Collapse, then open alerts  -> stays a rail (the 30 s reopen)
  touch    auto-hide stored ON -> still not applied; the switch says why
  desktop  default            -> auto-hide on, rail, expands under the mouse

Self-skips without playwright/Chromium, like the other browser suites.
"""
import os as _os
import sys as _sys
import unittest

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import browser_available, SKIP_REASON   # noqa: E402
import browser_required                                  # noqa: E402

_GATE = browser_available() or browser_required.required()

if browser_available():                                  # noqa: E402
    from playwright.sync_api import sync_playwright

RAIL = 56
OPEN = 248

# An iPad in portrait: 810 CSS px is above the 720 px phone breakpoint, so the
# desktop rail rules apply, which is exactly where the report came from.
IPAD = dict(viewport={'width': 810, 'height': 1080}, has_touch=True, is_mobile=True,
            device_scale_factor=2,
            user_agent='Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 '
                       '(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1')
DESKTOP = dict(viewport={'width': 1280, 'height': 800})


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestSidebarOnATouchScreen(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if _os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest(
                'sidebar layout is backend-agnostic: run once under the default backend')
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

    def open(self, device, storage=None):
        """A logged-in page in a fresh context. `storage` is localStorage set
        before the app's own script runs, i.e. what an earlier visit left."""
        ctx = self.browser.new_context(**device)
        self.addCleanup(ctx.close)
        if storage:
            ctx.add_init_script(
                "(() => { try { %s } catch (e) {} })();" %
                ' '.join(f"localStorage.setItem('{k}','{v}');" for k, v in storage.items()))
        page = ctx.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=15000)
        page.wait_for_timeout(500)
        self.errors = errors
        return page

    @staticmethod
    def widths(page):
        """(sidebar width, .app-content left margin), in px."""
        return tuple(page.evaluate(
            "() => [document.querySelector('.sidebar'),"
            "       document.querySelector('.app-content')]"
            "      .map((el, i) => parseFloat(getComputedStyle(el)"
            "           [i ? 'marginLeft' : 'width']))"))

    @staticmethod
    def can_hover(page):
        return page.evaluate("() => matchMedia('(hover: hover) and (pointer: fine)').matches")

    def classes(self, page):
        return set(page.evaluate("() => [...document.body.classList]"))

    # ── the controls that make the measurements below mean something ──

    def test_control_the_emulation_really_cannot_hover(self):
        """If Chromium's touch emulation reported a hovering pointer, every touch
        test below would pass on the old code for the wrong reason."""
        page = self.open(IPAD)
        self.assertFalse(self.can_hover(page), 'the iPad context can hover')
        self.assertTrue(page.evaluate("() => matchMedia('(pointer: coarse)').matches"))

    def test_control_a_desktop_pointer_can_hover(self):
        page = self.open(DESKTOP)
        self.assertTrue(self.can_hover(page))

    # ── touch ──

    def test_touch_default_is_an_open_sidebar_with_a_collapse_button(self):
        page = self.open(IPAD)
        cls = self.classes(page)
        self.assertNotIn('autohide-sidebar', cls, 'auto-hide was applied on a touch screen')
        self.assertNotIn('sidebar-collapsed', cls)
        width, margin = self.widths(page)
        self.assertAlmostEqual(width, OPEN, delta=1)
        self.assertAlmostEqual(margin, OPEN, delta=1)
        btn = page.locator('.sidebar-collapse-btn')
        self.assertTrue(btn.is_visible(), 'the Collapse button is hidden on touch')

    def test_touch_tapping_a_collapsed_rail_does_not_open_it(self):
        """The reported sequence: collapse, tap near the sidebar, stay on the page."""
        page = self.open(IPAD)
        page.tap('.sidebar-collapse-btn')
        page.wait_for_timeout(500)
        self.assertAlmostEqual(self.widths(page)[0], RAIL, delta=1, msg='Collapse did nothing')
        # Tap an empty part of the rail, then the page: a tap sets :hover, and
        # the browser keeps it until the next tap somewhere else.
        page.touchscreen.tap(28, 1000)
        page.wait_for_timeout(500)
        self.assertAlmostEqual(
            self.widths(page)[0], RAIL, delta=1,
            msg='a tap on the rail opened it over the page (sticky :hover)')
        page.touchscreen.tap(500, 600)
        page.wait_for_timeout(1500)
        self.assertAlmostEqual(self.widths(page)[0], RAIL, delta=1,
                               msg='the rail reopened by itself')

    def test_touch_open_alerts_do_not_reopen_a_collapsed_rail(self):
        """The "about 30 seconds": every alert poll re-applied the pin."""
        page = self.open(IPAD)
        page.tap('.sidebar-collapse-btn')
        page.wait_for_timeout(400)
        page.evaluate("() => { _paintAlertsBadge(3); _paintAlertsBadge(3); }")
        page.wait_for_timeout(500)
        self.assertNotIn('sidebar-alert-pinned', self.classes(page))
        self.assertAlmostEqual(self.widths(page)[0], RAIL, delta=1)

    def test_touch_a_stored_autohide_choice_is_not_applied(self):
        page = self.open(IPAD, storage={'rp_autohide_sidebar': '1'})
        self.assertNotIn('autohide-sidebar', self.classes(page))
        self.assertAlmostEqual(self.widths(page)[0], OPEN, delta=1)
        # and asking for it from the page does not collapse the sidebar either
        page.evaluate("() => toggleAutohideSidebar(true)")
        page.wait_for_timeout(400)
        self.assertNotIn('autohide-sidebar', self.classes(page))
        self.assertAlmostEqual(self.widths(page)[0], OPEN, delta=1)

    def test_touch_the_switch_is_off_and_says_why(self):
        page = self.open(IPAD)
        box = page.locator('#acct-autohide-sidebar')
        self.assertFalse(box.is_checked())
        self.assertTrue(box.is_disabled(), 'the switch can be turned on, to no effect')
        hint = page.locator('#acct-autohide-touch-hint')
        self.assertFalse(page.evaluate(
            "() => document.getElementById('acct-autohide-touch-hint').hidden"),
            'the reason is not shown')
        self.assertIn('hover', hint.inner_text().lower())

    # ── desktop control: the feature is still there for a pointer ──

    def test_desktop_default_still_hides_and_expands_under_the_mouse(self):
        page = self.open(DESKTOP)
        page.mouse.move(1000, 600)
        page.wait_for_timeout(500)
        cls = self.classes(page)
        self.assertIn('autohide-sidebar', cls)
        self.assertAlmostEqual(self.widths(page)[0], RAIL, delta=1)
        page.mouse.move(20, 400)
        page.wait_for_timeout(500)
        self.assertAlmostEqual(self.widths(page)[0], OPEN, delta=1,
                               msg='hovering the rail no longer expands it on a desktop')
        page.mouse.move(1000, 600)
        page.wait_for_timeout(500)
        self.assertAlmostEqual(self.widths(page)[0], RAIL, delta=1)

    def test_desktop_switch_is_enabled_and_hint_hidden(self):
        page = self.open(DESKTOP)
        self.assertTrue(page.locator('#acct-autohide-sidebar').is_enabled())
        self.assertTrue(page.evaluate(
            "() => document.getElementById('acct-autohide-touch-hint').hidden"))


if __name__ == '__main__':
    unittest.main()
