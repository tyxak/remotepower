#!/usr/bin/env python3
"""7.4.3, issue #52: the monitor form carries the Method and the Verify TLS switch both ways.

The server side (the probe, the save, the export and the import) is in test_v743_monitors. What that
cannot show is the form: that the two controls appear for an HTTP monitor and for nothing else, that
Add sends them, that Edit and Clone read them back, and that leaving them at their defaults sends
nothing, so a monitor that never used them stays as it was. A form that drops a field reads as a
feature that works until the next edit quietly resets it.

The page is real (a seeded instance, a signed-in browser, the modal opened the way a person opens
it). Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
LABEL = "e2e home assistant"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-monform-")
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


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheMonitorForm(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.page.evaluate("showPage('monitor')")
        self.page.wait_for_timeout(500)

    def tearDown(self):
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.page.evaluate("""async (label) => {
            const cfg = await api('GET', '/config');
            await api('POST', '/config', {monitors: (cfg.monitors || []).filter(m => !String(m.label).startsWith(label))});
        }""", LABEL)

    def monitors(self):
        return self.page.evaluate("api('GET', '/config').then(c => c.monitors || [])")

    def mine(self):
        return [m for m in self.monitors() if m["label"] == LABEL]

    def open_add(self, mtype):
        self.page.evaluate("openMonitorAdd()")
        self.page.select_option("#mon-type", mtype)

    def visible(self, selector):
        return self.page.is_visible(selector)

    def test_the_two_controls_belong_to_an_http_monitor_only(self):
        self.open_add("http")
        self.assertTrue(self.visible("#mon-method"))
        self.assertTrue(self.visible("#mon-verify-tls"))
        for other in ("tcp", "ping", "dns", "db", "icmp", "http_flow"):
            with self.subTest(type=other):
                self.page.select_option("#mon-type", other)
                self.assertFalse(self.visible("#mon-method"), other)
                self.assertFalse(self.visible("#mon-verify-tls"), other)

    def test_a_new_monitor_starts_with_the_defaults(self):
        self.open_add("http")
        self.assertEqual(self.page.input_value("#mon-method"), "")
        self.assertTrue(self.page.is_checked("#mon-verify-tls"))
        self.assertEqual([o.strip() for o in self.page.eval_on_selector_all(
            "#mon-method option", "els => els.map(e => e.textContent)")], ["Auto", "HEAD", "GET"])

    def wait_closed(self):
        self.page.wait_for_function("() => !document.getElementById('monitor-add-modal').classList.contains('active')",
                                    timeout=15000)

    def fill_and_add(self, method="", verify=True, status=""):
        self.page.fill("#mon-label", LABEL)
        self.page.fill("#mon-target", "https://ha.example:8123/")
        self.page.select_option("#mon-method", method)
        self.page.set_checked("#mon-verify-tls", verify)
        self.page.fill("#mon-status", str(status))
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.wait_closed()

    def test_add_sends_what_was_chosen(self):
        self.open_add("http")
        self.fill_and_add(method="get", verify=False, status="401")
        m = self.mine()
        self.assertEqual(len(m), 1, m)
        self.assertEqual(m[0]["method"], "get")
        self.assertIs(m[0]["verify_tls"], False)
        self.assertEqual(m[0]["expect_status"], 401)

    def test_the_defaults_send_nothing(self):
        self.open_add("http")
        self.fill_and_add()
        m = self.mine()
        self.assertEqual(len(m), 1, m)
        self.assertNotIn("method", m[0])
        self.assertNotIn("verify_tls", m[0])

    def row_index(self):
        self.page.wait_for_function("(l) => (window.monitorTargets || []).some(r => r.label === l)", arg=LABEL,
                                    timeout=15000)
        return self.page.evaluate("(l) => window.monitorTargets.findIndex(r => r.label === l)", LABEL)

    def test_a_second_add_does_not_inherit_the_first(self):
        self.open_add("http")
        self.page.select_option("#mon-method", "get")
        self.page.set_checked("#mon-verify-tls", False)
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.open_add("http")
        self.assertEqual(self.page.input_value("#mon-method"), "")
        self.assertTrue(self.page.is_checked("#mon-verify-tls"))

    def test_edit_and_clone_read_the_choices_back(self):
        self.open_add("http")
        self.fill_and_add(method="head", verify=False)
        idx = self.row_index()
        self.page.evaluate("(i) => editMonitor(i)", idx)
        self.page.wait_for_selector("#mon-method", state="visible", timeout=15000)
        self.assertEqual(self.page.input_value("#mon-method"), "head")
        self.assertFalse(self.page.is_checked("#mon-verify-tls"))
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.page.evaluate("(i) => cloneMonitor(i)", idx)
        self.page.wait_for_selector("#mon-method", state="visible", timeout=15000)
        self.assertEqual(self.page.input_value("#mon-method"), "head")
        self.assertFalse(self.page.is_checked("#mon-verify-tls"))
        self.assertIn("(copy)", self.page.input_value("#mon-label"))

    def test_saving_an_edit_back_to_the_defaults_removes_the_keys(self):
        self.open_add("http")
        self.fill_and_add(method="get", verify=False)
        idx = self.row_index()
        self.page.evaluate("(i) => editMonitor(i)", idx)
        self.page.wait_for_selector("#mon-method", state="visible", timeout=15000)
        self.page.select_option("#mon-method", "")
        self.page.set_checked("#mon-verify-tls", True)
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.wait_closed()
        m = self.mine()
        self.assertEqual(len(m), 1, m)
        self.assertNotIn("method", m[0])
        self.assertNotIn("verify_tls", m[0])

    def test_head_with_a_body_check_is_refused_and_says_why(self):
        self.open_add("http")
        self.page.fill("#mon-label", LABEL)
        self.page.fill("#mon-target", "https://ha.example:8123/")
        self.page.select_option("#mon-method", "head")
        self.page.select_option("#mon-body-mode", "contains")
        self.page.fill("#mon-body-value", "Welcome")
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.page.wait_for_selector(".toast.error", timeout=15000)
        self.assertEqual(self.mine(), [])
        self.assertIn("HEAD", self.page.inner_text(".toast.error"))


if __name__ == "__main__":
    unittest.main()
