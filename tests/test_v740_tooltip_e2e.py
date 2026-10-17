#!/usr/bin/env python3
"""7.4.0: the tooltip, in a real browser.

test_v740_tooltip.py runs the placement in V8. This drives Chromium: a mouse
rests on an element, the keyboard moves focus to one, a finger holds one. After
each it reads what is on screen and what the element looks like to the page and
to assistive technology: the title is off while the tooltip is up and back after,
the name is never lost, a handler that reads the title still finds it.

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

# Probe controls placed on the page: an icon-only button (named by its title), a
# button with text (described by it), a cell, one that opts out, and one at the
# bottom-right corner to see the tooltip stay on screen.
PROBES = """
(() => {
  const host = document.createElement('div');
  host.id = 'tp-host';
  host.style.cssText = 'position:fixed;left:200px;top:120px;z-index:5000;display:flex;gap:40px;'
    + 'background:var(--surface);padding:12px';
  const svg = '<svg width="16" height="16" viewBox="0 0 24 24"><path d="M3 3h18v18H3z"/></svg>';
  host.innerHTML = '<button id="tp-icon" title="Refresh the list">' + svg + '</button>'
    + '<button id="tp-text" title="Opens the settings">Settings</button>'
    + '<span id="tp-cell" title="Line one\\nLine two">cell</span>'
    + '<button id="tp-off" title="Native only" data-no-tip>Off</button>'
    + '<input id="tp-input" title="A field hint" aria-label="field">';
  document.body.appendChild(host);
  const corner = document.createElement('button');
  corner.id = 'tp-corner';
  corner.title = 'A tooltip near the corner of the window that must not leave it';
  corner.textContent = 'corner';
  corner.style.cssText = 'position:fixed;right:2px;bottom:2px;z-index:5000';
  document.body.appendChild(corner);
  window.__clicks = [];
  for (const id of ['tp-icon', 'tp-text']) {
    document.getElementById(id).addEventListener('click', (e) => {
      window.__clicks.push([id, e.currentTarget.getAttribute('title')]);
    });
  }
})();
"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheTooltip(unittest.TestCase):
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

    def open_app(self, touch=False):
        ctx = self.browser.new_context(has_touch=touch, viewport={'width': 1200, 'height': 800})
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        page.goto(self.base + '/index.html')
        page.fill('#login-user', 'admin')
        page.fill('#login-pass', 'remotepower')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=15000)
        page.evaluate("document.getElementById('tour-backdrop')?.remove();"
                      "document.getElementById('tour-pop')?.remove();")
        page.evaluate(PROBES)
        page.wait_for_function('window.RPTooltip !== undefined', timeout=4000)
        return page

    def up(self, page, text=None, timeout=3000):
        page.wait_for_function(
            "(want) => { const t = document.getElementById('rp-tooltip');"
            " return !!t && !t.hidden && (want === null || t.textContent === want); }",
            arg=text, timeout=timeout)

    def down(self, page, timeout=3000):
        page.wait_for_function(
            "() => { const t = document.getElementById('rp-tooltip'); return !t || t.hidden; }",
            timeout=timeout)

    def attr(self, page, sel, name):
        return page.evaluate("([s, n]) => document.querySelector(s).getAttribute(n)", [sel, name])

    def test_resting_the_pointer_shows_it_and_leaving_gives_the_title_back(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page, 'Opens the settings')
        self.assertIsNone(self.attr(page, '#tp-text', 'title'), 'the browser would show its own as well')
        self.assertEqual(self.attr(page, '#tp-text', 'aria-describedby'), 'rp-tooltip')
        page.mouse.move(5, 5)
        self.down(page)
        self.assertEqual(self.attr(page, '#tp-text', 'title'), 'Opens the settings')
        self.assertIsNone(self.attr(page, '#tp-text', 'aria-describedby'), 'it left a description behind')

    def test_an_icon_only_control_never_loses_its_name(self):
        """Named by its title, so while the title is off the same words are its label."""
        page = self.open_app()
        name = "() => document.getElementById('tp-icon').getAttribute('aria-label')"
        self.assertIsNone(page.evaluate(name))
        page.hover('#tp-icon')
        self.up(page, 'Refresh the list')
        self.assertEqual(page.evaluate(name), 'Refresh the list')
        page.mouse.move(5, 5)
        self.down(page)
        self.assertIsNone(page.evaluate(name), 'the label outlived the title and would go stale')
        self.assertEqual(self.attr(page, '#tp-icon', 'title'), 'Refresh the list')

    def test_the_words_are_text_and_keep_their_line_breaks(self):
        page = self.open_app()
        page.hover('#tp-cell')
        self.up(page, 'Line one\nLine two')
        self.assertEqual(page.evaluate("getComputedStyle(document.getElementById('rp-tooltip')).whiteSpace"),
                         'pre-line')

    def test_a_click_finds_the_title_where_it_was(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page)
        page.click('#tp-text')
        self.assertEqual(page.evaluate('window.__clicks'), [['tp-text', 'Opens the settings']])

    def test_keyboard_focus_shows_it_and_escape_dismisses_it(self):
        page = self.open_app()
        page.keyboard.press('Tab')                    # the page is now in keyboard modality
        page.evaluate("document.getElementById('tp-icon').focus()")
        self.up(page, 'Refresh the list')
        page.keyboard.press('Escape')
        self.down(page)
        self.assertEqual(self.attr(page, '#tp-icon', 'title'), 'Refresh the list')

    def test_pressing_enter_on_a_focused_control_gives_the_title_back_first(self):
        page = self.open_app()
        page.keyboard.press('Tab')
        page.evaluate("document.getElementById('tp-text').focus()")
        self.up(page)
        page.keyboard.press('Enter')
        page.wait_for_function('window.__clicks.length === 1', timeout=3000)
        self.assertEqual(page.evaluate('window.__clicks'), [['tp-text', 'Opens the settings']])

    def test_a_title_the_app_changed_while_it_was_held_is_kept(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page)
        page.evaluate("document.getElementById('tp-text').setAttribute('title', 'Opens the new settings')")
        page.mouse.move(5, 5)
        self.down(page)
        self.assertEqual(self.attr(page, '#tp-text', 'title'), 'Opens the new settings')

    def test_form_fields_and_opted_out_elements_keep_the_browsers_tooltip(self):
        page = self.open_app()
        for sel in ('#tp-input', '#tp-off'):
            page.hover(sel)
            page.wait_for_timeout(700)
            self.down(page, timeout=500)
            self.assertIsNotNone(self.attr(page, sel, 'title'), sel)
            page.mouse.move(5, 5)

    def test_it_stays_open_while_the_pointer_is_on_it(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page)
        box = page.evaluate("(() => { const r = document.getElementById('rp-tooltip').getBoundingClientRect();"
                            " return [r.left + r.width / 2, r.top + r.height / 2]; })()")
        page.mouse.move(box[0], box[1], steps=6)
        page.wait_for_timeout(600)
        self.up(page, 'Opens the settings', timeout=500)
        page.mouse.move(5, 5)
        self.down(page)

    def test_it_stays_inside_the_window(self):
        page = self.open_app()
        page.hover('#tp-corner')
        self.up(page)
        inside = page.evaluate("""(() => {
          const r = document.getElementById('rp-tooltip').getBoundingClientRect();
          return r.left >= 0 && r.top >= 0 && r.right <= innerWidth && r.bottom <= innerHeight;
        })()""")
        self.assertTrue(inside)

    def test_an_element_replaced_under_a_still_pointer_takes_it_with_it(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page)
        page.evaluate("document.getElementById('tp-text').remove()")
        self.down(page, timeout=2500)

    def test_moving_along_a_toolbar_does_not_wait_again(self):
        page = self.open_app()
        page.hover('#tp-icon')
        self.up(page, 'Refresh the list')
        page.hover('#tp-text')
        self.up(page, 'Opens the settings', timeout=250)      # well under the 350 ms wait

    def test_scrolling_dismisses_it(self):
        page = self.open_app()
        page.hover('#tp-text')
        self.up(page)
        page.evaluate("window.dispatchEvent(new Event('scroll'))")
        self.down(page, timeout=500)

    def test_a_held_finger_shows_it_and_the_hold_is_not_a_tap(self):
        page = self.open_app(touch=True)
        page.evaluate("window.__taps = 0; document.getElementById('tp-text')"
                      ".addEventListener('click', () => { window.__taps++; });")
        page.dispatch_event('#tp-text', 'touchstart')
        page.wait_for_timeout(250)
        self.down(page, timeout=300)                     # not yet: it is a hold, not a touch
        self.up(page, 'Opens the settings', timeout=1500)
        page.dispatch_event('#tp-text', 'touchend')
        page.dispatch_event('#tp-text', 'click')          # what the browser sends when the finger lifts
        self.assertEqual(page.evaluate('window.__taps'), 0, 'the long press also pressed the button')
        self.down(page, timeout=4000)                    # it goes by itself
        self.assertEqual(self.attr(page, '#tp-text', 'title'), 'Opens the settings')
        page.wait_for_timeout(1300)
        page.dispatch_event('#tp-text', 'click')
        self.assertEqual(page.evaluate('window.__taps'), 1, 'a later tap must still work')

    def test_a_tap_that_is_not_a_hold_shows_nothing(self):
        page = self.open_app(touch=True)
        page.dispatch_event('#tp-text', 'touchstart')
        page.wait_for_timeout(150)
        page.dispatch_event('#tp-text', 'touchend')
        page.wait_for_timeout(700)
        self.down(page, timeout=300)


if __name__ == '__main__':
    unittest.main()
