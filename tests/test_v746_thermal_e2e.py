"""7.4.6, issue #54 (follow-up): the Thermal page, in a browser, over the seeded demo.

The server side is held by test_v746_drive_lines_thermal. What it cannot show is that the sensor table of an
expanded host paints a drive by the state the server gives it, with lines the operator set through the API.
Self-skips without playwright/chromium/gunicorn.
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
    data_dir = tempfile.mkdtemp(prefix="rp-thermal-")
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
class TestTheSensorTableFollowsTheDriveLines(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def host_with_a_drive(self):
        return self.page.evaluate("""async () => {
            const r = await api('GET', '/fleet/thermal');
            const h = (r.hosts || []).find(h => (h.detail || []).some(s => s.type === 'disk'));
            return h ? {id: h.device_id, name: h.device} : null;
        }""")

    def open_detail(self, host):
        self.page.evaluate("showPage('thermal')")
        self.page.wait_for_function("(id) => document.querySelector(`[data-action=\"toggleThermalDetail\"][data-arg=\"${id}\"]`)",
                                    arg=host["id"], timeout=60000)
        self.page.evaluate("(id) => { if (!_thermalExpanded.has(id)) toggleThermalDetail(id); }", host["id"])
        self.page.wait_for_selector(".thermal-sensor-table tbody tr", timeout=30000)

    def disk_cells(self):
        return self.page.evaluate("""() => [...document.querySelectorAll('.thermal-sensor-table tbody tr')].map(tr => {
            const t = tr.querySelectorAll('td');
            return {type: t[2].textContent.trim(), cls: t[1].className, crit: t[3].textContent.trim()};
        }).filter(c => c.type === 'disk')""")

    def lines(self, host, warn, crit):
        return self.page.evaluate(
            "async ([id, w, c]) => await api('PATCH', `/devices/${id}/metric-thresholds`, {drivetemp_warn_c: w, drivetemp_crit_c: c})",
            [host["id"], warn, crit])

    def test_a_drive_over_its_lines_is_painted_and_shows_its_critical_line(self):
        host = self.host_with_a_drive()
        self.assertIsNotNone(host, "the demo has a host with a drive that reports a temperature")
        try:
            self.assertTrue(self.lines(host, 10, 15)["ok"])
            self.open_detail(host)
            cells = self.disk_cells()
            self.assertTrue(cells)
            self.assertTrue(all("c-red" in c["cls"] for c in cells), cells)
            self.assertTrue(all(c["crit"].startswith("15") for c in cells), cells)
        finally:
            self.page.evaluate("async (id) => await api('DELETE', `/devices/${id}/metric-thresholds`)", host["id"])

    def test_a_drive_between_its_warning_and_its_critical_line_is_amber(self):
        """The case the older colouring could not tell: far under the critical line, so only the state the
        server gives the drive can make the cell amber."""
        host = self.host_with_a_drive()
        try:
            self.assertTrue(self.lines(host, 10, 80)["ok"])
            self.open_detail(host)
            cells = self.disk_cells()
            self.assertTrue(cells)
            self.assertTrue(all("c-amber" in c["cls"] and "c-red" not in c["cls"] for c in cells), cells)
            self.assertTrue(all(c["crit"].startswith("80") for c in cells), cells)
        finally:
            self.page.evaluate("async (id) => await api('DELETE', `/devices/${id}/metric-thresholds`)", host["id"])

    def test_without_the_hosts_lines_the_same_drives_are_not_painted(self):
        host = self.host_with_a_drive()
        self.page.evaluate("async (id) => await api('DELETE', `/devices/${id}/metric-thresholds`)", host["id"])
        self.page.evaluate("showPage('thermal')")
        self.open_detail(host)
        self.page.evaluate("() => { _thermalResp = null; loadThermal(); }")
        self.page.wait_for_function("() => document.querySelectorAll('.thermal-sensor-table tbody tr').length > 0", timeout=30000)
        cells = self.disk_cells()
        self.assertTrue(cells)
        # The demo sets drive lines for the whole fleet, so a drive without lines of its host's still shows the
        # fleet's critical line, and its temperature is under it.
        self.assertFalse(any("c-red" in c["cls"] for c in cells), cells)
        self.assertFalse(any(c["crit"].startswith("15") for c in cells), "the host's lines are gone: " + str(cells))


if __name__ == "__main__":
    unittest.main()
