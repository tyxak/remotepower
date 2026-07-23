"""v6.4.0 FUNCTIONAL browser test — the living stat-tile UI actually renders.

Boots the real gunicorn+wsgi stack in real Chromium and confirms the Category-B
summary restructures (Alerts + Checks) render as .stat-card living tiles (which
the shared statTiles machinery then enhances), and that the OLD bespoke pill
markup (.alerts-summary-pill / .chk-pill) is gone. Complements the source-pin
guards in test_v410 — this proves the DOM actually builds, not just that the
strings are present.

Self-skips when playwright / gunicorn are unavailable (as the other e2e suites
do), so it's a no-op in the dep-limited CI runner and a real check locally:
    pip install playwright gunicorn && python -m playwright install chromium
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from playwright.sync_api import sync_playwright
    import gunicorn  # noqa: F401
    _HAVE = True
except Exception:
    _HAVE = False


@unittest.skipUnless(_HAVE, 'playwright + gunicorn required (see module docstring)')
class TestLivingTilesRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from e2e_harness import start_stack
        cls.base, cls._shutdown = start_stack()
        cls._pw = sync_playwright().start()
        cls.browser = cls._pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _login_page(self):
        pg = self.browser.new_page()
        pg.goto(self.base + '/index.html')
        pg.fill('#login-user', 'admin')
        pg.fill('#login-pass', 'remotepower')
        pg.click('#login-form button[type="submit"]')
        pg.wait_for_timeout(1500)
        return pg

    def _show(self, pg, page_id):
        pg.evaluate("(p) => { try { showPage(p); } catch (e) {} }", page_id)
        pg.wait_for_timeout(1500)

    def test_alerts_and_checks_render_living_tiles(self):
        pg = self._login_page()
        try:
            self._show(pg, 'alerts')
            self.assertGreaterEqual(
                pg.eval_on_selector_all('#alerts-summary .stat-card', 'e => e.length'), 3)
            self.assertEqual(
                pg.eval_on_selector_all('#alerts-summary .alerts-summary-pill', 'e => e.length'), 0)

            self._show(pg, 'checks')
            self.assertEqual(
                pg.eval_on_selector_all('#checks-summary .stat-card', 'e => e.length'), 4)
            labels = set(pg.eval_on_selector_all(
                '#checks-summary .stat-label', 'e => e.map(x => x.textContent)'))
            self.assertTrue({'Critical', 'Warning', 'Unknown', 'OK'}.issubset(labels))
            self.assertEqual(
                pg.eval_on_selector_all('#checks-summary .chk-pill', 'e => e.length'), 0)

            self.assertTrue(pg.evaluate(
                "() => typeof statTiles !== 'undefined' && typeof statTiles.enhanceAll === 'function'"))
        finally:
            pg.close()


if __name__ == '__main__':
    unittest.main()
