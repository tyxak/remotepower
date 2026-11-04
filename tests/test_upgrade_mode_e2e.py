"""Discussion #30, the upgrade mode in a browser, over the seeded demo.

The server side is held by test_upgrade_mode and the page functions run under node in test_upgrade_mode_pages. What
neither shows is the real thing: that the Patch Report dialog of an apt host draws the select, that choosing Extended
reaches the server and changes the dialog and the table, that a Windows host gets no select, and that the bulk action
sets the mode on the apt hosts and counts the others as skipped. 7.4.9 added the checkbox under Host settings in the host's own drawer,
beside the Upgrade packages button: it is drawn from the real roster, a tick reaches the server and the Patch Report shows the same mode,
a refused save puts the box back, and a Windows host has none. Self-skips without playwright/chromium/gunicorn.
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

KEPT = ["linux-image-amd64", "linux-firmware"]


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors


def _shape_the_fleet(data_dir):
    """Give one Debian or Ubuntu host the package data of an apt host that has packages kept back, and pick a Windows host.
    The demo hosts carry no package manager at all, so this is what an agent that has reported would have stored. Returns
    ((apt id, name), (windows id, name)), or None when the demo has no such hosts."""
    path = Path(data_dir) / "devices.json"
    devs = json.loads(path.read_text())
    apt = next((k for k, v in devs.items() if str(v.get("os", "")).startswith(("Debian", "Ubuntu"))), None)
    win = next((k for k, v in devs.items() if "windows" in str(v.get("os", "")).lower()), None)
    if apt is None or win is None:
        return None
    devs[apt].setdefault("sysinfo", {})["packages"] = {"manager": "apt", "upgradable": 3, "kept_back": list(KEPT)}
    devs[apt].pop("upgrade_mode", None)
    path.write_text(json.dumps(devs))
    return (apt, devs[apt].get("name", apt)), (win, devs[win].get("name", win))


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-upgrade-mode-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    hosts = _shape_the_fleet(data_dir)
    if hosts is None:
        raise unittest.SkipTest("the demo has no apt host and Windows host to test with")
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
    context, page, errors = _sign_in(browser, base, "alice", "demo")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, apt=hosts[0], win=hosts[1])


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheUpgradeModeInTheBrowser(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def api(self, method, path, body=None):
        return self.page.evaluate("async ([m, p, b]) => (b === null ? await api(m, p) : await api(m, p, b))", [method, path, body])

    def setUp(self):
        self.apt_id, self.apt_name = _STACK["apt"]
        self.win_id, self.win_name = _STACK["win"]
        self.reset()
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        try:
            self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.open, .modal-overlay.active').forEach(m => m.classList.remove('open', 'active')); }")
        except Exception:
            pass
        self.reset()
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def reset(self):
        """Every host back to Standard, whatever a test left."""
        rows = self.api("GET", "/patch-report")["devices"]
        for r in rows:
            if r.get("upgrade_mode") == "extended":
                self.api("PUT", f"/devices/{r['device_id']}/upgrade-mode", {"mode": "standard"})

    def open_dialog(self, dev_id, name):
        self.page.evaluate("([id, n]) => openDevicePatchReport(id, n)", [dev_id, name])
        self.page.wait_for_selector("#device-patch-body .sysinfo-pill", timeout=30000)

    def toast_has(self, text):
        self.page.wait_for_function("(t) => [...document.querySelectorAll('.toast')].some(x => x.textContent.includes(t))", arg=text, timeout=30000)

    def test_the_dialog_of_an_apt_host_has_the_select_and_names_what_is_kept_back(self):
        self.open_dialog(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#upgrade-mode-block #device-patch-mode", timeout=15000)
        self.assertEqual(self.page.input_value("#device-patch-mode"), "standard")
        text = self.page.inner_text("#upgrade-mode-block")
        for name in KEPT:
            self.assertIn(name, text)
        self.assertIn("The standard upgrade leaves them. Switch to Extended to install them.", text)

    def test_choosing_extended_reaches_the_server_and_changes_the_dialog_and_the_table(self):
        self.open_dialog(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#device-patch-mode", timeout=15000)
        self.page.select_option("#device-patch-mode", "extended")
        self.toast_has("Upgrade mode saved")
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "extended")
        self.page.wait_for_function("() => document.getElementById('upgrade-mode-block').innerText.includes('The next upgrade installs them.')", timeout=15000)
        self.assertEqual(self.page.input_value("#device-patch-mode"), "extended")
        # the Patches page marks the host
        self.page.evaluate("showPage('patches')")
        self.page.wait_for_function("typeof loadPatchReport === 'function'", timeout=60000)
        self.page.evaluate("() => loadPatchReport()")
        self.page.wait_for_function("(n) => [...document.querySelectorAll('#patch-tbody tr')].some(r => r.innerText.includes(n))", arg=self.apt_name, timeout=60000)
        row = self.page.evaluate("(n) => [...document.querySelectorAll('#patch-tbody tr')].find(r => r.innerText.includes(n)).querySelector('td').innerText", self.apt_name)
        self.assertIn("Extended", row)

    def test_choosing_standard_again_removes_the_mark(self):
        self.api("PUT", f"/devices/{self.apt_id}/upgrade-mode", {"mode": "extended"})
        self.open_dialog(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#device-patch-mode", timeout=15000)
        self.assertEqual(self.page.input_value("#device-patch-mode"), "extended")
        self.page.select_option("#device-patch-mode", "standard")
        self.toast_has("Upgrade mode saved")
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "standard")

    def test_a_windows_host_has_no_select_and_the_server_refuses_to_set_one(self):
        self.open_dialog(self.win_id, self.win_name)
        self.assertEqual(self.page.locator("#upgrade-mode-block").count(), 0)
        r = self.api("PUT", f"/devices/{self.win_id}/upgrade-mode", {"mode": "extended"})
        self.assertEqual(r.get("reason"), "not_linux", r)
        self.assertEqual(self.api("GET", f"/devices/{self.win_id}/upgrade-mode")["mode"], "standard")

    def test_the_bulk_action_sets_the_apt_hosts_and_skips_the_others(self):
        self.page.evaluate("showPage('devices')")
        self.page.wait_for_function("() => (window._devicesCache || []).length > 0", timeout=60000)
        self.page.evaluate("() => openBulkActions()")
        self.page.wait_for_selector("#bulk-action", timeout=15000)
        self.page.select_option("#bulk-action", "upgrade_mode_extended")
        self.page.click('[data-action="runBulkAction"]')
        self.page.wait_for_selector("#ui-prompt-confirm", state="visible", timeout=15000)
        self.page.click("#ui-prompt-confirm")
        self.toast_has("Upgrade mode extended set on")
        text = self.page.evaluate("() => [...document.querySelectorAll('.toast')].map(t => t.textContent).join(' | ')")
        self.assertIn("skipped (not apt)", text)
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "extended")
        self.assertEqual(self.api("GET", f"/devices/{self.win_id}/upgrade-mode")["mode"], "standard")

    # ── 7.4.9: the checkbox in the host's own drawer ─────────────────────────────────────────────────────────────────────────
    def open_drawer(self, dev_id, name):
        self.addCleanup(lambda: self.page.evaluate("() => { try { closeDeviceDrawer(); } catch (e) {} }"))
        self.page.evaluate("([id, n]) => openDeviceDrawer(id, n)", [dev_id, name])
        self.page.wait_for_selector("#drawer-settings-form #ds-name", timeout=30000)

    def test_the_drawer_of_an_apt_host_has_the_checkbox_with_the_hosts_other_checks(self):
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#ds-upgrade-extended", timeout=15000)
        self.assertFalse(self.page.is_checked("#ds-upgrade-extended"))
        text = self.page.inner_text("#ds-upgrade-row")
        self.assertIn("Upgrade mode", text)
        self.assertIn("Extended", text)
        for name in KEPT:
            self.assertIn(name, text)
        self.assertIn("The standard upgrade leaves them. Switch to Extended to install them.", text)
        # it sits with the other checks of the host: after Quarantine, before the poll interval
        order = self.page.evaluate("""() => { const q = id => document.getElementById(id), after = (a, b) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
            return [after(q('ds-quarantine'), q('ds-upgrade-extended')), after(q('ds-upgrade-extended'), q('ds-poll')), !!q('ds-upgrade-extended').closest('#drawer-settings-form')]; }""")
        self.assertEqual(order, [True, True, True])
        # the box has a name for a screen reader: its own visible label
        self.assertIn("Extended", self.page.evaluate("() => document.getElementById('ds-upgrade-extended').labels[0].textContent"))

    def test_ticking_it_saves_and_the_patch_report_shows_the_same_mode(self):
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.check("#ds-upgrade-extended")
        self.toast_has("Upgrade mode saved")
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "extended")
        self.page.wait_for_function("() => document.getElementById('ds-upgrade-row').innerText.includes('The next upgrade installs them.')", timeout=15000)
        self.assertTrue(self.page.is_checked("#ds-upgrade-extended"))
        self.assertEqual(self.page.evaluate("() => document.activeElement && document.activeElement.id"), "ds-upgrade-extended",
                         "the row is drawn again after a save, and the keyboard stays on the box")
        # the same setting, seen from the Patch Report
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_dialog(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#device-patch-mode", timeout=15000)
        self.assertEqual(self.page.input_value("#device-patch-mode"), "extended")
        # and the drawer opened again says so too
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.open, .modal-overlay.active').forEach(m => m.classList.remove('open', 'active')); }")
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#ds-upgrade-extended", timeout=15000)
        self.assertTrue(self.page.is_checked("#ds-upgrade-extended"))

    def test_the_patch_report_changes_what_the_drawer_shows(self):
        self.api("PUT", f"/devices/{self.apt_id}/upgrade-mode", {"mode": "extended"})
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#ds-upgrade-extended", timeout=15000)
        self.assertTrue(self.page.is_checked("#ds-upgrade-extended"))
        self.assertIn("The next upgrade installs them.", self.page.inner_text("#ds-upgrade-row"))

    def test_unticking_it_goes_back_to_standard(self):
        self.api("PUT", f"/devices/{self.apt_id}/upgrade-mode", {"mode": "extended"})
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#ds-upgrade-extended", timeout=15000)
        self.page.uncheck("#ds-upgrade-extended")
        self.toast_has("Upgrade mode saved")
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "standard")
        self.page.wait_for_function("() => document.getElementById('ds-upgrade-row').innerText.includes('Switch to Extended')", timeout=15000)

    def test_a_refused_save_puts_the_box_back(self):
        self.open_drawer(self.apt_id, self.apt_name)
        self.page.wait_for_selector("#ds-upgrade-extended", timeout=15000)
        self.page.route("**/upgrade-mode", lambda r: r.fulfill(status=403, content_type="application/json", body='{"error": "Admin access required"}')
                        if r.request.method == "PUT" else r.continue_())
        self.addCleanup(lambda: self.page.unroute("**/upgrade-mode"))
        self.page.check("#ds-upgrade-extended", force=True)
        self.toast_has("Admin access required")
        self.page.wait_for_function("() => !document.getElementById('ds-upgrade-extended').checked", timeout=15000)
        self.page.unroute("**/upgrade-mode")
        self.assertEqual(self.api("GET", f"/devices/{self.apt_id}/upgrade-mode")["mode"], "standard", "nothing reached the host record")

    def test_a_windows_host_has_no_checkbox_in_its_drawer(self):
        self.open_drawer(self.win_id, self.win_name)
        self.assertEqual(self.page.locator("#ds-upgrade-row").count(), 0)
        self.assertEqual(self.page.locator("#ds-upgrade-extended").count(), 0)
        self.assertGreater(self.page.locator("#drawer-settings-form .drawer-setting-row").count(), 5, "the rest of the form is there")

    def test_the_host_list_the_drawer_reads_carries_the_mode(self):
        rows = {r["id"]: r for r in self.api("GET", "/devices")}
        self.assertEqual((rows[self.apt_id]["upgrade_mode"], rows[self.apt_id]["upgrade_mode_applies"]), ("standard", True))
        self.assertIs(rows[self.win_id]["upgrade_mode_applies"], False)


if __name__ == "__main__":
    unittest.main()
