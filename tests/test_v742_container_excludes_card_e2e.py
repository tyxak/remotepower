#!/usr/bin/env python3
"""7.4.2, issue #43: the container exclude list has a box on Monitoring -> Tuning.

`container_alert_excludes` could only be set through the API. The server side (the matcher, the
config save, the rollup row) is in test_v742_container_excludes. What that cannot show is the box:
that it is filled from the saved list, that Save stores what the reader sees and nothing else,
that a box which never got the list cannot be saved empty over it, that a refused save keeps what
was typed, that a reload does not eat text being typed, and that a reader who cannot change the
list sees it read-only. The page is real (a seeded instance, a signed-in browser, the real
buttons); only the answers that stand in for a failure are canned.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import json
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

IMG = "image:ghcr.io/getarcaneapp/tools"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-ctrexcl-")
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
    # Service workers answer the page's requests before Playwright can see them.
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors)


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
class TestTheBox(unittest.TestCase):

    def setUp(self):
        _STACK["errors"].clear()
        self.page = _STACK["page"]
        self.set_list([])
        self.open_page()

    def tearDown(self):
        self.page.unroute("**/api/config")
        self.page.evaluate("() => { document.querySelectorAll('#toast-container .toast').forEach(t => t.remove()); }")

    # ---- helpers -------------------------------------------------------------------------------

    def set_list(self, entries):
        """Store the list the way an API client does, before the page is looked at."""
        r = self.page.evaluate("async (e) => await api('POST', '/config', {container_alert_excludes: e})", entries)
        self.assertTrue(r and r.get("ok"), r)

    def stored(self):
        return self.page.evaluate("async () => (await api('GET', '/config')).container_alert_excludes || []")

    def mark_unread(self):
        """The loader enables the box last, once the list has been read, so a disabled box is the
        marker that waits for THIS load. Without it wait_ready() returns at once on a box an
        earlier load enabled, and the test races the request."""
        self.page.evaluate("() => { document.getElementById('container-excludes').disabled = true; }")

    def open_page(self):
        # The loader remembers what the box was last filled with; a fresh page view starts clean.
        self.page.evaluate("() => { _ceLoaded = null; document.getElementById('container-excludes').value = ''; }")
        self.mark_unread()
        self.page.evaluate("() => showPage('tuning')")
        self.wait_ready()

    def wait_ready(self):
        self.page.wait_for_function(
            "() => { const t = document.getElementById('container-excludes'); return t && !t.disabled; }",
            timeout=20000)

    def box(self):
        return self.page.evaluate("() => document.getElementById('container-excludes').value")

    def fill(self, text):
        self.page.fill("#container-excludes", text)

    def toast_text(self, kind):
        self.page.wait_for_selector(f"#toast-container .toast.{kind}", timeout=10000)
        return self.page.evaluate(
            f"() => [...document.querySelectorAll('#toast-container .toast.{kind}')].map(t => t.textContent).join('|')")

    # ---- the tests -----------------------------------------------------------------------------

    def test_the_box_is_filled_from_the_saved_list_one_entry_per_line(self):
        self.set_list(["pause", IMG, "k8s_POD"])
        self.open_page()
        self.assertEqual(self.box(), f"pause\n{IMG}\nk8s_POD")

    def test_the_box_and_the_button_start_disabled_in_a_fresh_page(self):
        """Nothing may be saved before the list has been read: a box that never got the list would
        replace it with nothing. A second page shows the markup as it is served."""
        fresh = self.page.context.new_page()
        try:
            fresh.goto(_STACK["base"] + "/index.html")
            state = fresh.evaluate("""() => ({
                box: document.getElementById('container-excludes').disabled,
                save: document.getElementById('container-excludes-save').disabled})""")
        finally:
            fresh.close()
        self.assertEqual(state, {"box": True, "save": True})

    def test_an_empty_list_gives_an_empty_enabled_box(self):
        self.assertEqual(self.box(), "")
        self.assertTrue(self.page.evaluate("() => !document.getElementById('container-excludes-save').disabled"))

    def test_save_stores_what_the_reader_sees_and_changes_nothing_else(self):
        before = self.page.evaluate("async () => await api('GET', '/config')")
        self.fill("  pause  \n\n" + IMG + "\n   \nephemeral-\n")
        self.page.click("#container-excludes-save")
        self.toast_text("success")
        self.assertEqual(self.stored(), ["pause", IMG, "ephemeral-"])
        after = self.page.evaluate("async () => await api('GET', '/config')")
        changed = sorted(k for k in set(before) | set(after)
                         if before.get(k) != after.get(k) and k != "container_alert_excludes")
        self.assertEqual(changed, [], "saving the list must not touch another setting")
        # The box is refilled from what the server kept: no blank lines, no padding.
        self.assertEqual(self.box(), f"pause\n{IMG}\nephemeral-")

    def test_blank_lines_do_not_use_up_the_entries_the_server_keeps(self):
        """The server keeps the first 200 items it is sent and drops the blank ones after that count,
        so a list typed with a blank line between its entries would lose its tail if the blank lines
        were sent along."""
        lines = []
        for i in range(120):
            lines += [f"entry-{i:03d}", ""]
        self.fill("\n".join(lines))
        self.page.click("#container-excludes-save")
        self.toast_text("success")
        stored = self.stored()
        self.assertEqual(len(stored), 120)
        self.assertEqual(stored[-1], "entry-119")

    def test_clearing_the_box_clears_the_list(self):
        self.set_list(["pause"])
        self.open_page()
        self.fill("")
        self.page.click("#container-excludes-save")
        self.toast_text("success")
        self.assertEqual(self.stored(), [])

    def test_what_was_saved_is_listed_below_and_open_goes_to_the_box(self):
        self.fill("pause\n" + IMG)
        self.page.click("#container-excludes-save")
        self.toast_text("success")
        self.page.wait_for_function(
            "() => document.querySelectorAll('#suppressions-tbody tr').length >= 2 "
            "&& document.getElementById('suppressions-tbody').textContent.includes('image:ghcr.io')",
            timeout=15000)
        rows = self.page.evaluate("""() => [...document.querySelectorAll('#suppressions-tbody tr')]
            .filter(r => r.textContent.includes('Container exclusion'))
            .map(r => r.children[2].textContent.trim()).sort()""")
        self.assertEqual(rows, sorted(["pause", IMG]))
        # "Open" on one of them takes the reader to the box instead of reloading the page.
        self.page.evaluate("() => { document.getElementById('container-excludes').blur(); }")
        self.page.click("#suppressions-tbody tr:has-text('Container exclusion') button[data-action='gotoSuppression']")
        self.assertEqual(self.page.evaluate("() => document.activeElement && document.activeElement.id"),
                         "container-excludes")

    def test_a_list_that_could_not_be_read_cannot_be_saved_over_the_real_one(self):
        self.set_list(["keep-me"])
        self.page.route("**/api/config", lambda route: route.fulfill(
            status=500, content_type="application/json", body=json.dumps({"error": "boom"}))
            if route.request.method == "GET" else route.continue_())
        self.page.evaluate("() => { _ceLoaded = null; loadContainerExcludes(); }")
        self.page.wait_for_selector("#container-excludes-status .error-state", timeout=10000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('container-excludes').disabled"))
        self.assertTrue(self.page.evaluate("() => document.getElementById('container-excludes-save').disabled"))
        # The save handler refuses too, in case a click gets through some other way.
        self.page.evaluate("() => saveContainerExcludes()")
        self.page.wait_for_timeout(300)
        self.page.unroute("**/api/config")
        self.assertEqual(self.stored(), ["keep-me"])
        # Retry reads it and opens the box.
        self.page.click("#container-excludes-status button[data-action='uiRetry']")
        self.wait_ready()
        self.assertEqual(self.box(), "keep-me")
        self.assertEqual(self.page.evaluate("() => document.getElementById('container-excludes-status').textContent.trim()"), "")

    def test_a_dropped_connection_is_the_same_failure(self):
        self.set_list(["keep-me"])
        self.page.route("**/api/config", lambda route: route.abort()
                        if route.request.method == "GET" else route.continue_())
        self.page.evaluate("() => { _ceLoaded = null; loadContainerExcludes(); }")
        self.page.wait_for_selector("#container-excludes-status .error-state", timeout=10000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('container-excludes').disabled"))
        self.assertTrue(self.page.evaluate("() => document.getElementById('container-excludes-save').disabled"))
        self.page.unroute("**/api/config")
        self.assertEqual(self.stored(), ["keep-me"])

    def test_a_refused_save_keeps_what_was_typed_and_says_why(self):
        self.set_list(["old"])
        self.open_page()
        self.page.route("**/api/config", lambda route: route.fulfill(
            status=400, content_type="application/json",
            body=json.dumps({"error": "container_alert_excludes must be a list"}))
            if route.request.method == "POST" else route.continue_())
        self.fill("old\nnew")
        self.page.click("#container-excludes-save")
        self.assertIn("must be a list", self.toast_text("error"))
        self.assertEqual(self.box(), "old\nnew", "a refused save must not reload over the text")
        self.assertTrue(self.page.evaluate("() => !document.getElementById('container-excludes-save').disabled"),
                        "the button stays usable for another try")
        self.page.unroute("**/api/config")
        self.assertEqual(self.stored(), ["old"])

    def test_a_reload_does_not_eat_text_being_typed(self):
        self.set_list(["saved"])
        self.open_page()
        self.fill("saved\nhalf-typed")
        # Refresh, a mute action and the undo closures all end in loadTuning().
        self.mark_unread()
        self.page.click("#page-tuning button[data-action='loadTuning']")
        self.wait_ready()                      # the reload has read the list and finished
        self.assertEqual(self.box(), "saved\nhalf-typed")
        self.assertEqual(self.stored(), ["saved"])

    def test_a_reload_picks_up_a_change_made_elsewhere_when_nothing_was_typed(self):
        self.set_list(["one"])
        self.open_page()
        self.set_list(["one", "two"])
        self.page.click("#page-tuning button[data-action='loadTuning']")
        self.page.wait_for_function(
            "() => document.getElementById('container-excludes').value === 'one\\ntwo'", timeout=15000)

    def test_a_reader_who_cannot_change_it_sees_the_list_read_only(self):
        self.set_list(["pause"])
        self.open_page()
        self.mark_unread()
        self.page.evaluate("() => { window.__me = _meCache; _meCache = Object.assign({}, _meCache, {admin: false}); loadContainerExcludes(true); }")
        self.wait_ready()
        try:
            self.page.wait_for_function(
                "() => document.getElementById('container-excludes').readOnly", timeout=10000)
            self.assertEqual(self.box(), "pause")
            self.assertTrue(self.page.evaluate(
                "() => document.getElementById('container-excludes-save').classList.contains('hidden')"))
            self.assertIn("administrator", self.page.evaluate(
                "() => document.getElementById('container-excludes-status').textContent"))
            # Typing does nothing and a stray call to the saver sends nothing.
            self.page.evaluate("() => saveContainerExcludes()")
            self.page.wait_for_timeout(300)
            self.assertEqual(self.stored(), ["pause"])
        finally:
            self.mark_unread()
            self.page.evaluate("() => { _meCache = window.__me; loadContainerExcludes(true); }")
            self.wait_ready()
        self.assertFalse(self.page.evaluate("() => document.getElementById('container-excludes').readOnly"))
        self.assertFalse(self.page.evaluate(
            "() => document.getElementById('container-excludes-save').classList.contains('hidden')"))

    def test_the_page_logged_no_script_error(self):
        self.open_page()
        self.fill("pause")
        self.page.click("#container-excludes-save")
        self.toast_text("success")
        self.assertEqual(_STACK["errors"], [])


if __name__ == "__main__":
    unittest.main()
