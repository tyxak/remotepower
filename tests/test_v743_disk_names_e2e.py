#!/usr/bin/env python3
"""7.4.3, issue #47: naming a drive from the Hardware tab, and finding the name again where the disk shows.

The server side (the table, the key, the words of an alert) is in test_v743_disk_names. What that cannot
show is the page: that the box under the SMART table lists the drives that have a serial number, that
Save sends what was typed, that the name then appears where the letter was, on the Hardware tab and on
the fleet disk-health page, that clearing a box clears the name, and that a reader who cannot change
things sees the names but not the boxes.

The page is real (a seeded instance, a signed-in browser, the drawer opened the way a person opens it).
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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-diskname-")
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
    context, page, errors = _sign_in(browser, base, "alice", "demo")
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
class TestNamingFromTheHardwareTab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        page = _STACK["page"]
        found = page.evaluate("""async () => {
            const devs = await api('GET', '/devices');
            for (const d of (devs.devices || devs)) {
                const hw = await api('GET', `/devices/${d.id}/hardware`);
                const disks = ((hw && hw.smart) || []).filter(x => x.serial);
                if (disks.length >= 2) return {id: d.id, name: d.name, disks: disks.map(x => ({device: x.device, serial: x.serial}))};
            }
            return null;
        }""")
        if not found:
            raise unittest.SkipTest("the seeded fleet has no host with two disks that report a serial number")
        cls.host = found

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.clear()

    def clear(self):
        self.page.evaluate("""async ([id, serials]) => {
            const names = {};
            for (const s of serials) names[s] = '';
            await api('PUT', `/devices/${id}/disk-names`, {names});
        }""", [self.host["id"], [d["serial"] for d in self.host["disks"]]])

    def open_hardware(self, page=None):
        page = page or self.page
        page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [self.host["id"], self.host["name"]])
        page.wait_for_selector("#audit-sec-hardware", state="attached", timeout=30000)
        if not page.eval_on_selector("#audit-sec-hardware", "d => d.open"):
            page.click("#audit-sec-hardware > summary")       # open the section the way a person does
        page.wait_for_selector("#hw-smart-thead", state="visible", timeout=30000)

    def smart_cells(self, page=None):
        page = page or self.page
        return page.evaluate("""() => Array.from(document.querySelectorAll('#hw-smart-thead')[0]
            .closest('table').querySelectorAll('tbody tr')).map(tr => tr.cells[0].innerText)""")

    def test_the_box_lists_a_row_for_every_drive_with_a_serial(self):
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        got = self.page.eval_on_selector_all("#hw-diskname-form input[data-serial]",
                                             "els => els.map(e => e.dataset.serial)")
        self.assertEqual(sorted(got), sorted(d["serial"] for d in self.host["disks"]))
        head = self.page.text_content("#hw-smart-thead th[data-col='device']").strip()
        self.assertTrue(head.startswith("Disk"), head)

    def test_a_saved_name_shows_where_the_letter_was(self):
        first = self.host["disks"][0]
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        self.page.fill(f"#hw-diskname-form input[data-serial='{first['serial']}']", "Pool disk 2")
        self.page.click('#hw-diskname-form [data-action="saveDiskNames"]')
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.page.wait_for_function(
            "() => { const t = document.getElementById('hw-smart-thead'); "
            "return !!t && t.closest('table').innerText.includes('Pool disk 2'); }", timeout=15000)
        cells = self.smart_cells()
        named = [c for c in cells if "Pool disk 2" in c]
        self.assertEqual(len(named), 1, cells)
        self.assertIn(first["device"], named[0], "the letter stays next to the name")
        self.assertIn(first["serial"], named[0], "and so does the serial")
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def test_the_fleet_disk_health_page_shows_it_too(self):
        first = self.host["disks"][0]
        self.page.evaluate("""async ([id, serial]) => { await api('PUT', `/devices/${id}/disk-names`, {names: {[serial]: 'Pool disk 2'}}); }""",
                           [self.host["id"], first["serial"]])
        self.page.evaluate("showPage('disk-health')")
        self.page.wait_for_function(
            "() => document.getElementById('disk-health-tbody') && document.getElementById('disk-health-tbody').innerText.includes('Pool disk 2')",
            timeout=30000)
        row = self.page.evaluate("""() => Array.from(document.querySelectorAll('#disk-health-tbody tr'))
            .map(tr => tr.innerText).find(t => t.includes('Pool disk 2'))""")
        self.assertIn(first["device"], row)
        self.assertIn(first["serial"], row)

    def test_clearing_the_box_clears_the_name(self):
        first = self.host["disks"][0]
        self.page.evaluate("""async ([id, serial]) => { await api('PUT', `/devices/${id}/disk-names`, {names: {[serial]: 'Pool disk 2'}}); }""",
                           [self.host["id"], first["serial"]])
        self.open_hardware()
        self.page.wait_for_selector("#hw-diskname-form", timeout=15000)
        box = f"#hw-diskname-form input[data-serial='{first['serial']}']"
        self.assertEqual(self.page.input_value(box), "Pool disk 2")
        self.page.fill(box, "")
        self.page.click('#hw-diskname-form [data-action="saveDiskNames"]')
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.page.wait_for_function(
            "() => { const t = document.getElementById('hw-smart-thead'); "
            "return !!t && !t.closest('table').innerText.includes('Pool disk 2'); }", timeout=15000)
        self.assertEqual([c for c in self.smart_cells() if "Pool disk 2" in c], [])

    def test_a_reader_who_cannot_change_things_sees_the_name_and_no_boxes(self):
        first = self.host["disks"][0]
        self.page.evaluate("""async ([id, serial]) => { await api('PUT', `/devices/${id}/disk-names`, {names: {[serial]: 'Pool disk 2'}}); }""",
                           [self.host["id"], first["serial"]])
        context, viewer, errors = _sign_in(_STACK["browser"], _STACK["base"], "demo", "demo")
        try:
            self.open_hardware(viewer)
            viewer.wait_for_function(
                "() => document.getElementById('hw-smart-thead').closest('table').innerText.includes('Pool disk 2')",
                timeout=30000)
            self.assertEqual(viewer.query_selector("#hw-diskname-form"), None, "a reader gets no boxes")
            self.assertEqual(errors, [])
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
