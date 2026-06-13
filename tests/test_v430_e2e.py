#!/usr/bin/env python3
"""v4.3.0: browser smoke suite — the first tests that actually RUN the UI.

Everything else in the suite checks the JS at the source level (V8 parse +
regex pins); regressions that only exist at runtime (broken event wiring,
a render that throws, CSS that hides the app) shipped repeatedly because
nothing clicked through the app. This suite boots the real stack (static
files + the SCGI worker) in a real Chromium and walks the core path:
login → dashboard → devices → settings, failing on any page error.

Self-skips when playwright (or its Chromium) is not installed:
    pip install playwright && python -m playwright install chromium
Run directly via `make e2e`.
"""
import unittest

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False


@unittest.skipUnless(_HAVE_PLAYWRIGHT, 'playwright not installed (pip install '
                     'playwright && python -m playwright install chromium)')
class TestSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # `make e2e` runs from tests/, but `unittest discover` from the repo
        # root (the `make check` gate) leaves this dir off sys.path — make the
        # sibling-harness import work regardless of cwd.
        import os as _os
        import sys as _sys
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        from e2e_harness import start_stack  # local import: harness needs no deps
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:               # browser binary missing
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        cls.base, cls._shutdown = start_stack()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        self.page = self.browser.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))

    def tearDown(self):
        self.page.close()

    def _login(self):
        self.page.goto(self.base + '/index.html')
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        # showApp() reveals #app via inline style.display (the d-none CLASS
        # stays on the element) — wait for visibility, not for the class.
        self.page.wait_for_selector('#app', state='visible', timeout=15000)

    def _assert_no_page_errors(self):
        self.assertEqual(self.errors, [],
                         f'uncaught JS errors during the flow: {self.errors}')

    def _nav(self, page_name):
        # Buried nav entries live in collapsible sidebar groups — expand them
        # all first (same as a user opening the group) so the click lands.
        self.page.evaluate(
            "document.querySelectorAll('.sidebar-group.collapsed')"
            ".forEach(g => g.classList.remove('collapsed'))")
        self.page.click(f'.nav-btn[data-page="{page_name}"]')
        self.page.wait_for_selector(f'#page-{page_name}.active', timeout=15000)

    def test_login_page_renders(self):
        self.page.goto(self.base + '/index.html')
        self.page.wait_for_selector('#login-user', state='visible', timeout=15000)
        self._assert_no_page_errors()

    def test_login_reaches_dashboard(self):
        self._login()
        # Home page is the post-login landing; its fleet tiles must render.
        self.page.wait_for_selector('#page-home.active', timeout=15000)
        self._assert_no_page_errors()

    def test_devices_page_and_drawer_deep_link(self):
        self._login()
        self._nav('devices')
        # Empty fleet → the enroll empty-state (not a crash, not skeletons stuck)
        self.page.wait_for_timeout(800)
        self._assert_no_page_errors()
        # v4.3.0 deep link: #device/<id> must open the drawer even for an
        # unknown id (drawer opens, name falls back to the id — no JS error).
        self.page.evaluate("location.hash = '#device/no-such-id'")
        self.page.wait_for_selector('#device-drawer.open', timeout=10000)
        self._assert_no_page_errors()

    def test_settings_page_loads_config(self):
        self._login()
        self._nav('settings')
        self.page.wait_for_timeout(1200)   # config fetch + form fill
        self._assert_no_page_errors()

    def test_table_sort_click_is_wired(self):
        self._login()
        self._nav('alerts')
        ths = self.page.query_selector_all('#page-alerts th[data-col]')
        if ths:
            ths[0].click()
        self.page.wait_for_timeout(400)
        self._assert_no_page_errors()


if __name__ == '__main__':
    unittest.main()
