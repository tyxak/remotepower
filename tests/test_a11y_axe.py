#!/usr/bin/env python3
"""docs/master-improvement-scoping-internal.md #63 — automated accessibility
regression checks (axe-core), added to the local test gate the same way the
browser smoke suite (test_v430_e2e.py) was: reuses the shared e2e_harness
(real gunicorn+wsgi.py stack, real Chromium), self-skips when the optional
deps aren't installed.

Bar: zero axe 'critical'/'serious' violations on the login page and the
post-login dashboard, with EVERY rule enforced — no disabled rules.

color-contrast is FULLY ENFORCED (#62's contrast fix landed in the same
session that added this gate): every theme's --accent got a computed
--accent-contrast (black text clears 4.5:1 against every current accent
except the `paper` theme, which keeps white), --muted was retuned per-theme
where it fell short against --surface, and two remaining hardcoded-color
outliers (.sev-pill.sev-low, .isl-751) got dedicated colors sized for their
actual composited background. See CHANGELOG / the #62 tracker row for the
full per-theme numbers.

nested-interactive is ALSO fully enforced as of v6.1.1 (#62's other half):
the sidebar favorite-star toggle (.nav-star, role="button" tabindex="0")
used to be injected as a DESCENDANT of the <button class="nav-btn">, which
is invalid (two independently-focusable/activatable controls, nested).
Fixed by restructuring the star out to a SIBLING of .nav-btn — both wrapped
in a new `.nav-item` flex row (app.js's `_initFavorites`/`_renderFavorites`,
CSS in styles.css near `.nav-item`). Verified with a real Playwright pass:
star click still pins/unpins, the pinned clone under "Main" keeps its own
un-pin star, keyboard Enter still activates it, regular nav-btn clicks are
unaffected, the collapsed-sidebar state still hides the star, and the
sidebar search index doesn't double-count a pinned clone. Two click-delegate
handlers in app.js used `star.closest('.nav-btn')` (an ANCESTOR search) to
find the button from a star click — that broke once the star became a
SIBLING instead of a descendant (`closest()` can't walk sideways) and had
to be changed to a same-parent lookup; a `:not(.nav-fav-clone)` selector in
`_buildSidebarIdx` had the same class-moved-to-the-wrapper issue.

Install to run:
    pip install playwright gunicorn axe-core-python
    python -m playwright install chromium
Run directly via `make e2e` (bundled with the rest of the browser suite) or
`python3 -m pytest tests/test_a11y_axe.py`.
"""
import json
import unittest

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

try:
    from axe_core_python.sync_playwright import Axe
    _HAVE_AXE = True
except ImportError:
    _HAVE_AXE = False

_SERIOUS_IMPACTS = ('critical', 'serious')

# v6.1.1: no rules disabled -- nested-interactive's fix (see module
# docstring) closed the last named exemption. Pass {} (every default rule
# enforced) rather than deleting this constant, so a future exemption has an
# obvious place to land with the same "named reason, not a blanket ignore"
# discipline.
_AXE_OPTIONS = {}


def _run_axe(page, axe, options=None):
    """axe_core_python 0.1.0's Axe.run() str()-formats the options dict for
    the injected JS call, which emits Python's `False`/`True`/`None` instead
    of JS `false`/`true`/`null` -- a ReferenceError for any options dict with
    a boolean (i.e. every realistic one, including ours). Reuses the
    package's vendored axe.min.js (no need to vendor our own copy) but does
    the injection + evaluate ourselves with json.dumps, which IS valid JS."""
    page.evaluate(axe.axe_script)
    return page.evaluate(
        "axe.run(%s).then(r => r)" % json.dumps(options or {}))


@unittest.skipUnless(_HAVE_PLAYWRIGHT and _HAVE_AXE,
                     'playwright + axe-core-python not installed (pip install '
                     'playwright gunicorn axe-core-python && '
                     'python -m playwright install chromium)')
class TestAccessibilityAxe(unittest.TestCase):
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
        cls.axe = Axe()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        self.page = self.browser.new_page()

    def tearDown(self):
        self.page.close()

    def _login(self):
        self.page.goto(self.base + '/index.html')
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        self.page.wait_for_selector('#page-home.active', timeout=15000)

    def _assert_no_serious_violations(self, results, page_label):
        violations = results.get('violations') or []
        serious = [v for v in violations if v.get('impact') in _SERIOUS_IMPACTS]
        if serious:
            detail = json.dumps(
                [{'id': v['id'], 'impact': v['impact'], 'help': v['help'],
                  'nodes': len(v.get('nodes') or [])} for v in serious],
                indent=2)
            self.fail(f'{page_label}: {len(serious)} critical/serious a11y '
                     f'violation(s):\n{detail}')

    def test_login_page(self):
        self.page.goto(self.base + '/index.html')
        self.page.wait_for_selector('#login-user', state='visible', timeout=15000)
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'login page')

    def test_dashboard_after_login(self):
        self._login()
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'dashboard')

    def test_devices_page(self):
        self._login()
        self.page.evaluate(
            "document.body.classList.remove('autohide-sidebar', 'sidebar-collapsed');"
            "document.querySelectorAll('.sidebar-group.collapsed')"
            ".forEach(g => g.classList.remove('collapsed'))")
        self.page.click('.nav-btn[data-page="devices"]')
        self.page.wait_for_selector('#page-devices.active', timeout=15000)
        self.page.wait_for_timeout(500)
        results = _run_axe(self.page, self.axe, _AXE_OPTIONS)
        self._assert_no_serious_violations(results, 'devices page')


if __name__ == '__main__':
    unittest.main()
