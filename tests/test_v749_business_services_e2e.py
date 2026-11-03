#!/usr/bin/env python3
"""7.4.9: the Business services page, in a real browser on the seeded demo.

The server side (the states of each kind of part, the rules, the sweep, the alerts) is in test_v749_business_services. What that
cannot show is the page: that the five demo services list with the state the rest of the demo gives them (Public website down,
Media and Nextcloud up, Smart home and the service that holds them degraded), that a click opens the parts with their reasons, and that a person can
create a service from the editor (pick a rule, add a host and a unit), see it, change it and delete it. Self-skips without
playwright/chromium/gunicorn, like its siblings.
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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-bs-")
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
class TestTheBusinessServicesPage(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def open_page(self):
        self.page.evaluate("() => showPage('business-services', document.querySelector('.nav-btn[data-page=\"business-services\"]'))")
        self.page.wait_for_selector("#bs-tbody tr td a[data-action='openBusinessServiceDetail']", timeout=30000)

    def rows(self):
        return self.page.eval_on_selector_all(
            "#bs-tbody tr", "rs => rs.map(r => [...r.querySelectorAll('td')].map(td => td.innerText.trim().replace(/\\s+/g, ' ')))")

    def setUp(self):
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        for m in ("bs-modal", "bs-detail-modal"):
            try:
                self.page.evaluate("(m) => closeModal(m)", m)
            except Exception:
                pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def test_the_demo_services_have_the_states_the_demo_gives_them(self):
        self.open_page()
        state = dict(self.page.eval_on_selector_all(
            "#bs-tbody tr", "rs => rs.map(r => [r.querySelector('a').innerText.trim(), r.children[1].innerText.trim()])"))
        joined = " | ".join(f"{k}={v}" for k, v in state.items())
        self.assertIn("Down", state["Public website"], joined)
        self.assertIn("Up", state["Media"], joined)
        self.assertIn("Degraded", state["Smart home"], joined)
        self.assertIn("Up", state["Nextcloud"], joined)
        self.assertIn("Degraded", state["Home services"], joined)
        # the stat numbers count up from zero; read them once they have arrived
        try:
            self.page.wait_for_function(
                "() => ['critical','warning','ok'].map(k => document.getElementById('bs-n-' + k).innerText.trim()).join(',') === '1,2,2'",
                timeout=8000)
        except Exception:
            pass
        counts = [self.page.inner_text(f"#bs-n-{k}") for k in ("critical", "warning", "ok")]
        self.assertEqual(counts, ["1", "2", "2"], joined)

    def test_the_detail_lists_the_parts_with_the_reason(self):
        self.open_page()
        self.page.click("#bs-tbody a:has-text('Public website')")
        self.page.wait_for_selector("#bs-detail-modal.active, #bs-detail-modal[style*='flex']", timeout=15000)
        text = self.page.inner_text("#bs-detail-members")
        self.assertIn("nginx.service on nginx.lab", text)
        self.assertIn("Public site", text)
        self.assertRegex(text, r"Down\s+down")      # the monitor's state and its reason
        self.assertIn("Up", text)
        self.assertIn("Recent changes", self.page.inner_text("#bs-detail-modal"))

    def test_a_person_can_create_change_and_delete_a_service(self):
        self.open_page()
        self.page.click("#bs-new-btn")
        self.page.wait_for_selector("#bs-modal-name", state="visible", timeout=15000)
        self.page.fill("#bs-modal-name", "Browser made")
        self.page.select_option("#bs-modal-rule", "min")
        self.assertTrue(self.page.is_visible("#bs-modal-min"))
        self.page.fill("#bs-modal-min", "1")
        # a host, then a unit on the same host
        self.page.select_option("#bs-add-kind", "host")
        self.page.select_option("#bs-add-host", label="nginx.lab")
        self.page.click("[data-action='bsAddPart']")
        self.page.select_option("#bs-add-kind", "unit")
        self.page.select_option("#bs-add-host", label="nginx.lab")
        self.page.fill("#bs-add-text", "nginx.service")
        self.page.click("[data-action='bsAddPart']")
        parts = self.page.inner_text("#bs-members")
        self.assertIn("nginx.lab", parts)
        self.assertIn("nginx.service on nginx.lab", parts)
        self.page.click("[data-action='saveBusinessService']")
        self.page.wait_for_selector("#bs-tbody a:has-text('Browser made')", timeout=30000)
        row = [r for r in self.rows() if r[0].startswith("Browser made")][0]
        self.assertIn("Up", row[1])
        self.assertIn("At least 1 parts", row[2])
        self.assertTrue(row[3].startswith("2 of 2"), row)

        # change it: take the unit out, make the rule 'all'
        self.page.click("#bs-tbody tr:has-text('Browser made') button:has-text('Edit')")
        self.page.wait_for_selector("#bs-modal-name", state="visible", timeout=15000)
        self.assertEqual(self.page.input_value("#bs-modal-name"), "Browser made")
        self.assertEqual(self.page.input_value("#bs-modal-rule"), "min")
        self.page.click("#bs-members [data-action='bsRemovePart'][data-arg='1']")
        self.page.select_option("#bs-modal-rule", "all")
        self.page.click("[data-action='saveBusinessService']")
        self.page.wait_for_function(
            "() => [...document.querySelectorAll('#bs-tbody tr')].some(r => r.innerText.includes('Browser made') && r.innerText.includes('1 of 1'))",
            timeout=30000)

        # delete it
        self.page.click("#bs-tbody tr:has-text('Browser made') button:has-text('Edit')")
        self.page.wait_for_selector("#bs-modal-delete-btn", state="visible", timeout=15000)
        self.page.click("#bs-modal-delete-btn")
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function(
            "() => ![...document.querySelectorAll('#bs-tbody tr')].some(r => r.innerText.includes('Browser made'))", timeout=30000)

    def test_the_editor_refuses_a_service_with_no_parts(self):
        self.open_page()
        self.page.click("#bs-new-btn")
        self.page.wait_for_selector("#bs-modal-name", state="visible", timeout=15000)
        self.page.fill("#bs-modal-name", "Nothing in it")
        self.page.click("[data-action='saveBusinessService']")
        self.page.wait_for_selector(".toast", timeout=10000)
        self.assertIn("Add at least one part", self.page.inner_text(".toast"))
        self.assertFalse(any(r[0].startswith("Nothing in it") for r in self.rows()))

    def test_the_page_fits_a_phone(self):
        self.open_page()
        self.page.set_viewport_size({"width": 390, "height": 800})
        try:
            self.page.wait_for_timeout(300)
            wide = self.page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth + 2")
            self.assertFalse(wide, "the page scrolls sideways at 390 px")
        finally:
            self.page.set_viewport_size({"width": 1440, "height": 900})


if __name__ == "__main__":
    unittest.main()
