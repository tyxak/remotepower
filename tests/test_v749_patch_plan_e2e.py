#!/usr/bin/env python3
"""7.4.9: the patch preview dialog, in a real browser on the seeded demo.

test_v749_patch_plan covers the reader, the script and the handlers. What it cannot show is the dialog: that the Patch Report
offers the button for a Linux host and not for a Windows one, that the plan the demo holds for gitea.lab is laid out with its
versions, security marks, kernel flag and held package, that a parked upgrade on the Approvals page carries a Preview button, that
asking a host with no plan puts up the waiting state and then shows the answer when it arrives, and that what a host sends is shown
as text and never as markup. Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
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
        raise unittest.SkipTest("what is measured is the dialog, not the backend (the test edits the JSON store)")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-pp-")
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
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, data=Path(data_dir))


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestThePatchPreviewDialog(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    @property
    def store(self):
        return _STACK["data"] / "patch_previews.json"

    def read_store(self):
        return json.loads(self.store.read_text()) if self.store.exists() else {}

    def write_plan(self, dev, plan_patch=None, pending=None, fresh=True):
        """Put a plan (the demo's, with changes) on a host the way the server stores it."""
        store = self.read_store()
        base = json.loads(json.dumps(self.default_plan))      # always the demo's own plan, not what an earlier test left
        base.update(plan_patch or {})
        if fresh:
            base["at"] = int(time.time())
        store[dev] = {"pending": pending, "plan": base}
        self.store.write_text(json.dumps(store))

    @classmethod
    def setUpClass(cls):
        cls.default_plan = json.loads((_STACK["data"] / "patch_previews.json").read_text())["gt01"]["plan"]

    def setUp(self):
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        for m in ("patch-plan-modal", "device-patch-modal"):
            try:
                self.page.evaluate("(m) => closeModal(m)", m)
            except Exception:
                pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def open_dialog(self, dev, name):
        """What a click on a Preview button ends in. The module is lazy, so it is loaded first, as the dispatcher does."""
        self.page.evaluate("async ([d, n]) => { await _loadJsModule('app-patchplan.js'); return patchPlanOpen('host:' + d, n); }", [dev, name])

    def dialog_text(self):
        return self.page.inner_text("#patch-plan-modal")

    def open_from_patch_report(self, dev, name):
        self.page.evaluate("([d, n]) => openDevicePatchReport(d, n)", [dev, name])
        self.page.wait_for_selector("#device-patch-body [data-action-btn='_patchPlanBtn']", timeout=30000)
        self.page.click("#device-patch-body [data-action-btn='_patchPlanBtn']")

    # ── the plan ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_demo_plan_is_laid_out_with_versions_marks_and_flags(self):
        self.write_plan("gt01")
        self.open_from_patch_report("gt01", "gitea.lab")
        self.page.wait_for_selector("#patch-plan-body table", timeout=30000)
        text = self.dialog_text()
        for want in ("gitea.lab", "openssl", "3.0.15-1~deb12u1", "3.0.16-1~deb12u1", "linux-image-6.1.0-29-amd64", "docker-ce",
                     "linux-image-6.1.0-25-amd64"):
            self.assertIn(want, text)
        rows = self.page.eval_on_selector_all(
            "#patch-plan-body table:first-of-type tbody tr",
            "rs => rs.map(r => [...r.children].map(c => c.innerText.trim().replace(/\\s+/g, ' ')))")
        by = {r[0]: r for r in rows}
        self.assertEqual(by["openssl"][1:3], ["3.0.15-1~deb12u1", "3.0.16-1~deb12u1"])
        self.assertIn("security", by["openssl"][3])
        self.assertNotIn("security", by["curl"][3])
        chips = self.page.eval_on_selector_all("#patch-plan-body .sysinfo-pill",
                                               "ps => ps.map(p => p.innerText.trim().replace(/\\s+/g, ' ').toLowerCase())")
        joined = " | ".join(chips)
        self.assertIn("to upgrade 5", joined)
        self.assertIn("new packages 1", joined)
        self.assertIn("security updates 4", joined)
        self.assertIn("kernel update", text.lower())
        self.assertIn("on hold", text.lower())
        self.assertIn("Nothing was changed on the host", text)

    def test_the_hosts_own_output_is_there_when_asked_for(self):
        self.write_plan("gt01", {"raw": "The following packages will be upgraded:\n  openssl\n1 upgraded, 0 newly installed"})
        self.open_from_patch_report("gt01", "gitea.lab")
        self.page.wait_for_selector("#patch-plan-body table", timeout=30000)
        self.assertEqual(self.page.eval_on_selector("#patch-plan-raw", "e => getComputedStyle(e).display"), "none")
        self.page.click("[data-action='patchPlanRaw']")
        self.page.wait_for_function("() => getComputedStyle(document.getElementById('patch-plan-raw')).display !== 'none'", timeout=10000)
        self.assertIn("1 upgraded, 0 newly installed", self.page.inner_text("#patch-plan-raw"))

    def test_nothing_to_upgrade_says_so(self):
        self.write_plan("gt01", {"upgrades": [], "installs": [], "removals": [], "kept_back": [], "autoremove": [], "kernel": False,
                                 "reboot_likely": False, "reboot_reasons": [], "counts": {"upgrade": 0, "install": 0, "remove": 0,
                                                                                         "kept_back": 0, "security": 0}})
        self.open_from_patch_report("gt01", "gitea.lab")
        self.page.wait_for_selector("#patch-plan-body .empty-state", timeout=30000)
        self.assertIn("Nothing to upgrade.", self.dialog_text())

    # ── who gets the button ─────────────────────────────────────────────────────────────────────────────────────────
    def test_a_windows_host_is_not_offered_the_preview(self):
        self.page.evaluate("() => openDevicePatchReport('wks01', 'design-win11')")
        self.page.wait_for_selector("#device-patch-body .sysinfo-row", timeout=30000)
        self.assertEqual(self.page.locator("#device-patch-body [data-action-btn='_patchPlanBtn']").count(), 0)

    def test_the_approvals_page_offers_it_for_a_parked_upgrade_and_not_for_the_others(self):
        self.write_plan("gt01")
        self.page.evaluate("() => showPage('confirmations', document.querySelector('.nav-btn[data-page=\"confirmations\"]'))")
        self.page.wait_for_function("() => { const t = document.getElementById('confirmations-tbody'); return t && t.children.length && !t.innerText.includes('Loading'); }", timeout=30000)
        rows = self.page.eval_on_selector_all(
            "#confirmations-tbody tr",
            "rs => rs.map(r => [r.innerText.replace(/\\s+/g, ' '), r.querySelectorAll(\"[data-action-btn='_patchPlanBtn']\").length])")
        with_btn = [t for t, n in rows if n]
        self.assertEqual(len(with_btn), 1, rows)
        self.assertIn("queue_command", with_btn[0])
        self.assertIn("gitea.lab", with_btn[0])
        self.page.click("#confirmations-tbody [data-action-btn='_patchPlanBtn']")
        self.page.wait_for_selector("#patch-plan-body table", timeout=30000)
        self.assertIn("openssl", self.dialog_text())

    # ── asking ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_host_with_no_plan_is_asked_and_the_answer_shows_up_by_itself(self):
        before = self.read_store().get("ng01")
        self.assertIsNone(before)
        self.open_dialog("ng01", "nginx.lab")
        self.page.wait_for_function("() => document.getElementById('patch-plan-body').innerText.includes('Waiting for the host')", timeout=30000)
        self.assertEqual(self.page.eval_on_selector("#patch-plan-actions", "e => getComputedStyle(e).display"), "none")
        pend = self.read_store()["ng01"]["pending"]
        self.assertTrue(pend["id"].startswith("pp-"))
        self.assertEqual(pend["by"], "alice")
        # the host's agent would answer on its next report; write what the server would store
        plan = dict(self.default_plan, id=pend["id"], at=int(time.time()), by="alice")
        plan["upgrades"] = [{"name": "nginx", "from": "1.24.0-2ubuntu7", "to": "1.24.0-2ubuntu7.1", "security": True, "source": "Ubuntu:24.04/noble-security"}]
        plan["installs"] = []
        plan["counts"] = {"upgrade": 1, "install": 0, "remove": 0, "kept_back": 0, "security": 1}
        store = self.read_store()
        store["ng01"] = {"pending": None, "plan": plan}
        self.store.write_text(json.dumps(store))
        self.page.wait_for_selector("#patch-plan-body table", timeout=20000)
        self.assertIn("nginx", self.dialog_text())
        self.assertNotIn("Waiting for the host", self.dialog_text())
        self.assertNotEqual(self.page.eval_on_selector("#patch-plan-actions", "e => getComputedStyle(e).display"), "none")

    def test_a_plan_that_is_young_enough_is_shown_without_asking_again(self):
        self.write_plan("jf01")
        before = self.read_store()["jf01"]
        self.open_dialog("jf01", "jellyfin.lab")
        self.page.wait_for_selector("#patch-plan-body table", timeout=30000)
        self.assertEqual(self.read_store()["jf01"]["pending"], before["pending"])

    # ── what a host sends is text ───────────────────────────────────────────────────────────────────────────────────
    def test_names_and_versions_from_a_host_are_never_markup(self):
        evil = "<img src=x onerror=\"window.__pwn=1\">"
        self.write_plan("pmx01", {"upgrades": [{"name": evil, "from": evil, "to": evil, "security": True, "source": evil}],
                                  "installs": [{"name": evil, "to": evil, "security": False, "source": evil}],
                                  "removals": [{"name": evil, "from": evil}], "kept_back": [{"name": evil, "held": True}],
                                  "deferred": [evil], "autoremove": [evil], "reboot_reasons": [evil], "error": evil, "by": evil})
        self.open_dialog("pmx01", "<b>x</b>")
        self.page.wait_for_selector("#patch-plan-body table", timeout=30000)
        self.page.wait_for_timeout(500)
        self.assertEqual(self.page.locator("#patch-plan-modal img").count(), 0)
        self.assertEqual(self.page.locator("#patch-plan-modal b").count() - self.page.locator("#patch-plan-modal b:not(:has(*))").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__pwn"))
        self.assertIn("<img src=x", self.dialog_text(), "shown as text")
        self.assertEqual(self.page.locator("#patch-plan-host b").count(), 0, "the host name is text too")


if __name__ == "__main__":
    unittest.main()
