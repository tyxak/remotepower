#!/usr/bin/env python3
"""7.4.2: the host drawer gives focus back to what opened it, however it was opened.

openDeviceDrawer remembers document.activeElement as the place to return to. It does that on every
call, and a call can come while the drawer is already open: the first open has by then moved focus
INTO the drawer, so the second call remembers a button inside the drawer, and closing tries to
focus it after the drawer is hidden. Nothing takes focus, and it falls to <body>. The keyboard
test (test_v740_keyboard_e2e) met exactly that state, "opener still in the page, focus on BODY",
once in three runs under load and in three gates of 7.4.1; this reproduces the cause without load.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-drawerfocus-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f"app stack not available: {exc}")
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    page.evaluate("n => showPage(n)", "devices")
    page.wait_for_timeout(2500)
    # Hold the auto-refresh still: a redraw would replace the opener, which is another test's subject.
    page.evaluate("() => { window._refreshShouldPause = () => true; }")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()
        _STACK.clear()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestFocusReturn(unittest.TestCase):

    def setUp(self):
        self.page = _STACK["page"]
        self.page.evaluate("() => { if (_drawerDeviceId) closeDeviceDrawer(); }")

    def tearDown(self):
        self.page.evaluate("() => { if (_drawerDeviceId) closeDeviceDrawer(); }")

    def opener(self):
        """The first host's open-drawer button, focused the way a keyboard user leaves it."""
        return self.page.evaluate("""() => {
            const b = document.querySelector("#page-devices button[data-action='openDeviceDrawer']");
            b.focus();
            window.__opener = b;
            window.__host = [b.getAttribute('data-arg'), b.getAttribute('data-name') || ''];
            return !!b && document.activeElement === b;
        }""")

    def wait_focus_inside(self):
        self.page.wait_for_function(
            "() => document.getElementById('device-drawer').contains(document.activeElement)", timeout=10000)

    def state(self):
        return self.page.evaluate("""() => ({
            onOpener: document.activeElement === window.__opener,
            active: document.activeElement ? document.activeElement.tagName + '#' + document.activeElement.id : null,
            drawerOpen: document.getElementById('device-drawer').classList.contains('open')})""")

    def test_a_single_open_and_close_returns_to_the_opener(self):
        """The control: the case that has always worked."""
        self.assertTrue(self.opener())
        self.page.evaluate("() => { const [id, n] = window.__host; openDeviceDrawer(id, n); }")
        self.wait_focus_inside()
        self.page.evaluate("() => closeDeviceDrawer()")
        s = self.state()
        self.assertTrue(s["onOpener"], s)

    def test_a_second_open_while_it_is_open_does_not_change_where_focus_returns(self):
        self.assertTrue(self.opener())
        self.page.evaluate("() => { const [id, n] = window.__host; openDeviceDrawer(id, n); }")
        self.wait_focus_inside()
        # A second trigger (a keydown handler and the click it synthesises, the command palette, a
        # deep link) calls it again with focus already inside the drawer.
        self.page.evaluate("() => { const [id, n] = window.__host; openDeviceDrawer(id, n); }")
        self.wait_focus_inside()
        self.page.evaluate("() => closeDeviceDrawer()")
        s = self.state()
        self.assertFalse(s["drawerOpen"])
        self.assertTrue(s["onOpener"], f"focus did not go back to what opened the drawer: {s}")

    def test_opening_another_host_while_it_is_open_still_returns_to_the_first_opener(self):
        self.assertTrue(self.opener())
        ids = self.page.evaluate("async () => (await api('GET', '/devices')).slice(0, 2).map(d => [d.id, d.name])")
        if len(ids) < 2:
            self.skipTest("the seeded fleet has one host")
        self.page.evaluate("([id, n]) => openDeviceDrawer(id, n)", ids[0])
        self.wait_focus_inside()
        self.page.evaluate("([id, n]) => openDeviceDrawer(id, n)", ids[1])
        self.wait_focus_inside()
        self.page.evaluate("() => closeDeviceDrawer()")
        s = self.state()
        self.assertTrue(s["onOpener"], f"focus did not go back to what opened the drawer: {s}")

    def test_closing_before_the_deferred_focus_runs_leaves_focus_on_the_opener(self):
        """open() queues a timeout that moves focus into the drawer. A close in the same task
        runs first; the timeout must not then act on a drawer that is no longer open."""
        self.assertTrue(self.opener())
        self.page.evaluate("() => { const [id, n] = window.__host; openDeviceDrawer(id, n); closeDeviceDrawer(); }")
        self.page.wait_for_timeout(300)
        s = self.state()
        self.assertFalse(s["drawerOpen"])
        self.assertTrue(s["onOpener"], s)


if __name__ == "__main__":
    unittest.main()
