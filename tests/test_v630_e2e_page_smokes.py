#!/usr/bin/env python3
"""v6.3.0: per-page E2E smoke sweep — every sidebar page opens clean.

test_v430_e2e walks the core path (login → dashboard → devices → settings);
everything else only ever met source-level pins. Runtime-only regressions on
the other ~60 pages (a loader that throws, broken event wiring, a renderer
dying on empty data) shipped repeatedly — the wave-11 "devices table replays
its entrance animation" class would have been caught here.

One stack boot, one login, then every `data-page` in the sidebar: navigate,
wait for the page div to activate, fail on any uncaught JS error attributed
to the page that was open when it fired.

Self-skips without playwright/chromium/gunicorn, like its sibling.
"""
import re
import unittest
from pathlib import Path

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from e2e_harness import browser_available, SKIP_REASON   # noqa: E402

if browser_available():                                  # noqa: E402
    from playwright.sync_api import sync_playwright

_ROOT = Path(__file__).resolve().parent.parent


# Pages whose module ships OFF, so their nav button is hidden on the empty
# install this sweep runs against. Named rather than silent — the assertion in
# the walk fails if anything ELSE becomes unreachable, which is the whole point
# of listing them.
MODULE_GATED_OFF_ON_EMPTY_INSTALL = {'billing', 'kb', 'autonomy'}


def _sidebar_pages():
    """Every sidebar page, using the TOLERANT attribute order.

    The strict form — `class="nav-btn…" data-page=…` with nothing between —
    silently missed six buttons that carry an `id` first, among them `billing`
    and `kb`. They were not being smoke-tested at all, and the omission looked
    like a pass. The same strictness bug was already fixed in the other page
    sweeps; this one still had it.
    """
    html = (_ROOT / 'server/html/index.html').read_text()
    pages = []
    for m in re.finditer(r'class="nav-btn[^"]*"[^>]*?\sdata-page="([a-z-]+)"', html):
        if m.group(1) not in pages:
            pages.append(m.group(1))
    return pages


@unittest.skipUnless(browser_available(), SKIP_REASON)
class TestEveryPageOpensClean(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os as _os
        import sys as _sys
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

    def test_every_sidebar_page_activates_without_js_errors(self):
        pages = _sidebar_pages()
        # 78, not 50. A floor far below the true count only catches TOTAL
        # collapse: this sweep sat at 75 of 81 for releases — six buttons
        # carry an id before data-page and were never enumerated — and the
        # old `> 50` passed the whole time. A threshold has to be near the
        # real number to catch shrinkage.
        self.assertGreater(len(pages), 78, 'sidebar page enumeration broke')
        page = self.browser.new_page()
        errors = []   # (current_page, error)
        current = ['login']
        page.on('pageerror', lambda e: errors.append((current[0], str(e))))
        try:
            page.goto(self.base + '/index.html')
            # Fresh data dir → first login auto-starts the onboarding tour,
            # whose #tour-backdrop intercepts every nav click (65/67 pages
            # "failed" on the first run of this sweep). Pre-mark it done the
            # way a returning user's browser would.
            page.evaluate("localStorage.setItem('rp_tour_done', '1')")
            page.fill('#login-user', 'admin')
            page.fill('#login-pass', 'remotepower')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=15000)
            failed_nav = []
            for p in pages:
                if p in MODULE_GATED_OFF_ON_EMPTY_INSTALL:
                    continue          # nav hidden by design; audited seeded
                current[0] = p
                with self.subTest(page=p):
                    try:
                        # The sidebar is an ACCORDION — navigating re-collapses
                        # the other groups, so re-expand before EVERY click
                        # (same as test_v430_e2e._nav; doing it once after
                        # login left every later group's button hidden).
                        page.evaluate(
                            "document.body.classList.remove('autohide-sidebar', 'sidebar-collapsed');"
                            "document.querySelectorAll('.sidebar-group.collapsed')"
                            ".forEach(g => g.classList.remove('collapsed'))")
                        page.click(f'.nav-btn[data-page="{p}"]', timeout=5000)
                        page.wait_for_selector(f'#page-{p}.active', timeout=10000)
                        # let the page's async loader run (and possibly throw)
                        page.wait_for_timeout(250)
                    except Exception as exc:
                        failed_nav.append(f'{p}: {exc}')
                        self.fail(f'page {p!r} did not activate: {exc}')
            page_errors = [f'[{pg}] {err}' for pg, err in errors]
            self.assertEqual(page_errors, [],
                             'uncaught JS errors while walking the pages:\n'
                             + '\n'.join(page_errors))
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
