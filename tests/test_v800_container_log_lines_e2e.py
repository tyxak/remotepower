#!/usr/bin/env python3
"""8.0.0: the Tuning card for log lines in an unhealthy container's alert, in a browser on the demo seed.

The setting is off until an administrator turns it on, and the page must not be able to turn it on by accident or to send a number it never saw.
Held here: the box starts at the stored value (0), a whole number from 0 to 10 is saved and read back from the server, a value that is not one is
refused in the page with no request made, a viewer sees the number and cannot change it, and the page threw nothing.

The filename carries 'e2e', so make test-fast skips it. Self-skips without playwright / Chromium / gunicorn, and runs under the default storage
backend only.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

_ROOT = Path(__file__).resolve().parent.parent
# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
# (tests/test_ci_green_parity.py holds the shape).
_GATE = browser_available() or browser_required.required()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheLogLinesCard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("the setting is backend-agnostic: measured once, under the default backend")
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail("playwright is not installed")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        data_dir = tempfile.mkdtemp(prefix="rp-loglines-e2e-")
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail("chromium not available: %s" % exc)
        try:
            cls.base, shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest("app stack not available: %s" % exc)
        cls._stop = [shutdown]

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._stop[0]()

    def visit(self, user):
        ctx = self.browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        # one long page: every card of Tuning shows, whichever tab it belongs to
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        self.addCleanup(ctx.close)
        page = ctx.new_page()
        self.errors = []
        self.posts = []
        page.on("pageerror", lambda e: self.errors.append(str(e)))
        page.on("request", lambda r: self.posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/config") else None)
        page.goto(self.base + "/index.html")
        page.wait_for_selector("#login-form")
        page.fill("#login-user", user)
        page.fill("#login-pass", "demo")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3500)
        page.evaluate("showPage('tuning')")
        page.wait_for_selector("#container-log-lines:not([disabled])", state="attached", timeout=30000)
        return page

    def stored(self, page):
        # a key that was never saved is not in the configuration: that is off, the same as a stored 0
        return page.evaluate("async () => (await api('GET', '/config')).container_alert_log_lines ?? 0")

    def reset(self, page):
        page.evaluate("async () => { await api('POST', '/config', {container_alert_log_lines: 0}); }")

    def test_it_starts_at_the_stored_value_and_a_saved_number_is_kept(self):
        page = self.visit("alice")
        self.addCleanup(lambda: self.reset(page))
        self.assertEqual(page.eval_on_selector("#container-log-lines", "e => e.value"), "0", "off until an administrator turns it on")
        self.assertEqual(page.eval_on_selector("#container-log-lines", "e => [e.min, e.max, e.step]"), ["0", "10", "1"])
        page.fill("#container-log-lines", "5")
        page.click("#container-log-lines-save")
        page.wait_for_function("() => document.querySelector('#container-log-lines-save') && !document.querySelector('#container-log-lines-save').disabled", timeout=15000)
        self.assertEqual(self.stored(page), 5)
        self.assertEqual(page.eval_on_selector("#container-log-lines", "e => e.value"), "5", "the box shows what the server kept")
        page.reload()
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(3000)
        page.evaluate("showPage('tuning')")
        page.wait_for_function("() => { const e = document.getElementById('container-log-lines'); return e && !e.disabled && e.value === '5'; }", timeout=30000)
        self.assertEqual(self.errors, [])

    def test_a_value_that_is_not_a_whole_number_from_0_to_10_is_refused_before_any_request(self):
        page = self.visit("alice")
        self.addCleanup(lambda: self.reset(page))
        for bad in ("11", "-1", "2.5", "", "1e1", "99"):
            with self.subTest(bad=bad):
                before = len(self.posts)
                page.fill("#container-log-lines", bad)
                page.click("#container-log-lines-save")
                page.wait_for_selector("text=Enter a whole number from 0 to 10.", timeout=10000)
                self.assertEqual(len(self.posts), before, "a refused value must not reach the server")
                self.assertEqual(self.stored(page), 0)
        self.assertEqual(self.errors, [])

    def test_a_viewer_sees_the_number_and_cannot_change_it(self):
        page = self.visit("demo")
        self.assertTrue(page.eval_on_selector("#container-log-lines", "e => e.readOnly"))
        self.assertFalse(page.is_visible("#container-log-lines-save"), "a viewer is not offered the button")
        self.assertIn("Only an administrator can change this.", page.inner_text("#container-log-lines-status"))
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
