#!/usr/bin/env python3
"""docs/master-improvement-scoping-internal.md #63 — automated accessibility
regression checks (axe-core), added to the local test gate the same way the
browser smoke suite (test_v430_e2e.py) was: reuses the shared e2e_harness
(real gunicorn+wsgi.py stack, real Chromium), self-skips when the optional
deps aren't installed.

Bar: zero axe 'critical'/'serious' violations on the login page and the
post-login dashboard, EXCEPT two rules disabled below with a named reason —
this app hasn't had a full WCAG audit pass yet (see master-improvement-
scoping #62), and gating on every finding today would either fail on a
backlog unrelated to whatever change triggered the run, or need everything
triaged/allowlisted up front. What's disabled is diagnosed, not guessed:

  - color-contrast: two confirmed, SHARED-variable patterns, each far too
    wide-blast-radius to safely fix as a side-effect of adding this test —
    white text on --accent (.btn-primary/.enroll-btn/#topbar-avatar; the
    default #3b7eff only reaches 3.74:1, and every user-selectable accent
    color, e.g. amber #f59e0b, would need its own contrast-safe text-color
    decision), and var(--muted) at 4.22:1 vs the 4.5:1 floor (309 use sites
    across the whole app). Both belong to #62's dedicated contrast audit.
  - nested-interactive: EVERY sidebar nav button fails this — the
    favorite-star toggle (.nav-star, role="button" tabindex="0") is
    injected as a DESCENDANT of the <button class="nav-btn">, which is
    invalid (two independently-focusable/activatable controls, nested).
    Root-caused, not guessed — see the sidebar favorites-star injection
    (app.js, `data-fav` sources). The real fix restructures the star out
    to a sibling of nav-btn (a wrapper element + CSS), which needs its own
    visual-regression pass across every sidebar state (collapsed/expanded/
    active/badge overlap) — out of scope for this test's addition.

Every OTHER axe rule stays enforced, so this gate still catches a genuinely
new structural issue (a missing aria-label's role, a broken focus trap, a
button with no accessible name) — it just doesn't (yet) claim to cover
color contrast or the pre-existing nav-star nesting.

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

# Disabled with a named, diagnosed reason -- see the module docstring. NOT a
# blanket "ignore everything" allowlist; every other rule stays enforced.
_AXE_OPTIONS = {'rules': {
    'color-contrast':     {'enabled': False},   # #62's dedicated contrast audit
    'nested-interactive': {'enabled': False},   # .nav-star inside .nav-btn, root-caused above
}}


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
