#!/usr/bin/env python3
"""7.4.3, issue #48: the maintenance window form carries "While the window is active" both ways.

The server side (what a window holds back, in the inbox, in Needs attention and on the dashboard) is
in test_v743_maintenance_alerts. What that cannot show is the form: that the setting appears with the
right default, that Create sends it, that Edit reads it back and can switch it off again, and that the
list says which windows raise no alerts. The form is also the only way most people make a window, so
this makes one for each kind of target the server accepts, because a form that reads the target for
some of them and not for the others fails with a message about a missing target.

The page is real (a seeded instance, a signed-in browser). Self-skips without playwright/chromium/
gunicorn, like its siblings.
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
REASON = "e2e nightly backup"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-maintform-")
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
class TestTheMaintenanceForm(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("closeModal('new-maint-modal')")
        self.page.evaluate("showPage('maintenance')")
        self.page.wait_for_timeout(500)

    def tearDown(self):
        self.page.evaluate("closeModal('new-maint-modal')")
        self.page.evaluate("""async (reason) => {
            const r = await api('GET', '/maintenance');
            for (const w of (r.windows || [])) if (w.reason === reason) await api('DELETE', '/maintenance/' + w.id);
        }""", REASON)

    def windows(self):
        return [w for w in self.page.evaluate("api('GET', '/maintenance').then(r => r.windows || [])")
                if w["reason"] == REASON]

    def wait_closed(self):
        self.page.wait_for_function("() => !document.getElementById('new-maint-modal').classList.contains('active')",
                                    timeout=15000)

    def open_new(self):
        self.page.evaluate("openNewMaintModal()")
        self.page.wait_for_selector("#maint-suppress", state="visible", timeout=15000)

    def create(self, scope="global", target="", suppress=None):
        self.open_new()
        self.page.fill("#maint-reason", REASON)
        self.page.select_option("#maint-scope", scope)
        if target:
            self.page.fill("#maint-target-group", target)
        if suppress:
            self.page.select_option("#maint-suppress", suppress)
        self.page.click('#new-maint-modal [data-action="saveMaintenance"]')
        self.wait_closed()

    def test_a_new_window_starts_with_notifications_only(self):
        self.open_new()
        self.assertEqual(self.page.input_value("#maint-suppress"), "notifications")
        self.assertEqual(self.page.eval_on_selector_all(
            "#maint-suppress option", "els => els.map(e => [e.value, e.textContent.trim()])"),
            [["notifications", "Hold notifications only"], ["alerts", "Raise no alerts at all"]])

    def test_create_sends_the_choice_and_the_list_says_so(self):
        self.create(suppress="alerts")
        w = self.windows()
        self.assertEqual(len(w), 1, w)
        self.assertEqual(w[0]["suppress"], "alerts")
        self.page.evaluate("loadMaintenance()")
        self.page.wait_for_selector("#maint-tbody .chk-pill", timeout=15000)
        self.assertIn("no alerts", self.page.inner_text("#maint-tbody").lower())   # the pill is set in capitals

    def test_the_default_leaves_no_badge(self):
        self.create()
        self.assertEqual(self.windows()[0]["suppress"], "notifications")
        self.page.evaluate("loadMaintenance()")
        self.page.wait_for_selector("#maint-tbody tr", timeout=15000)
        self.assertNotIn("no alerts", self.page.inner_text("#maint-tbody").lower())

    def test_edit_reads_it_back_and_can_switch_it_off(self):
        self.create(suppress="alerts")
        self.open_new()                                  # leaves the select at its default
        self.page.evaluate("closeModal('new-maint-modal')")
        self.page.evaluate("loadMaintenance()")
        self.page.wait_for_selector("#maint-tbody button[data-action-btn='_editMaintenanceBtn']", timeout=15000)
        self.page.click("#maint-tbody tr:has-text('%s') button[data-action-btn='_editMaintenanceBtn']" % REASON)
        self.page.wait_for_selector("#maint-suppress", state="visible", timeout=15000)
        self.assertEqual(self.page.input_value("#maint-suppress"), "alerts")
        self.page.select_option("#maint-suppress", "notifications")
        self.page.click('#new-maint-modal [data-action="saveMaintenance"]')
        self.wait_closed()
        self.assertEqual(self.windows()[0]["suppress"], "notifications")

    def test_a_second_new_window_does_not_inherit_the_first(self):
        self.open_new()
        self.page.select_option("#maint-suppress", "alerts")
        self.page.select_option("#maint-scope", "tag")
        self.page.fill("#maint-target-group", "left-over")
        self.page.evaluate("closeModal('new-maint-modal')")
        self.open_new()
        self.assertEqual(self.page.input_value("#maint-suppress"), "notifications")
        self.assertEqual(self.page.input_value("#maint-target-group"), "", "a tag typed into the last form")

    def test_every_kind_of_target_can_be_saved_from_the_form(self):
        """The server takes a group, a site, a tag or a smart group by name; the form has one text box for all."""
        for scope, target in (("group", "prod"), ("site", "berlin"), ("tag", "backup"), ("smart", "sg-abc123")):
            with self.subTest(scope=scope):
                self.create(scope=scope, target=target)
                w = self.windows()
                self.assertEqual([(x["scope"], x["target"]) for x in w], [(scope, target)], w)
                self.page.evaluate("""async (reason) => {
                    const r = await api('GET', '/maintenance');
                    for (const w of (r.windows || [])) if (w.reason === reason) await api('DELETE', '/maintenance/' + w.id);
                }""", REASON)

    def test_editing_a_tag_window_shows_its_target(self):
        self.create(scope="tag", target="backup")
        self.page.evaluate("loadMaintenance()")
        self.page.wait_for_selector("#maint-tbody button[data-action-btn='_editMaintenanceBtn']", timeout=15000)
        self.page.click("#maint-tbody tr:has-text('%s') button[data-action-btn='_editMaintenanceBtn']" % REASON)
        self.page.wait_for_selector("#maint-target-group", state="visible", timeout=15000)
        self.assertEqual(self.page.input_value("#maint-target-group"), "backup")


if __name__ == "__main__":
    unittest.main()
