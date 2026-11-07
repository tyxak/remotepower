"""Issue #54, a drivetemp sensor held to the lines of the disk it reads: the pages, in a browser, over the seeded demo.

The server side is held by test_drivetemp_disk_lines, and the two page functions are run under node there. What neither
shows is that the Thermal page and the host drawer call them: that the table names the disk next to the sensor, paints
each sensor by its own disk's pair, and that the drawer's temperature list agrees with the page.

One seeded host gets the shape of the report: a hard disk (sda) and a SATA SSD (sdb) behind drivetemp sensors on the
same controllers, and a third drivetemp sensor the agent could not name a disk for. Self-skips without
playwright/chromium/gunicorn, like the other browser tests.
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

HDD = "drivetemp-scsi-0-0/temp1"
SSD = "drivetemp-scsi-1-0/temp1"
LOST = "drivetemp-scsi-9-0/temp1"
LINES = {"drivetemp_hdd_warn_c": 45, "drivetemp_hdd_crit_c": 50,
         "drivetemp_ssd_warn_c": 65, "drivetemp_ssd_crit_c": 70,
         "drivetemp_warn_c": 55, "drivetemp_crit_c": 60}


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors


def _shape_the_report(data_dir):
    """Give one seeded host the report of the issue and return its id and name."""
    path = Path(data_dir) / "hardware.json"
    hw = json.loads(path.read_text())
    dev_id = next(k for k, v in hw.items() if isinstance(v, dict) and v.get("smart"))
    rec = hw[dev_id]
    rec["smart"] = [
        {"device": "/dev/sda", "health": "PASSED", "model": "E2E HDD", "serial": "E2E-HDD", "media": "hdd", "temperature_c": 40},
        {"device": "/dev/sdb", "health": "PASSED", "model": "E2E SSD", "serial": "E2E-SSD", "media": "ssd", "temperature_c": 40},
    ]
    rec.setdefault("hardware", {})["temps"] = [
        {"label": HDD, "current_c": 51.0, "drive": "sda"},
        {"label": SSD, "current_c": 66.0, "drive": "sdb"},
        {"label": LOST, "current_c": 50.0},
    ]
    path.write_text(json.dumps(hw))
    name = json.loads((Path(data_dir) / "devices.json").read_text())[dev_id].get("name", dev_id)
    return dev_id, name


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-drivetemp-disk-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    host, name = _shape_the_report(data_dir)
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
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, host=host, name=name)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheSensorsOfAMixedHost(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        r = self.page.evaluate("async ([id, lines]) => await api('PATCH', `/devices/${id}/metric-thresholds`, lines)",
                               [_STACK["host"], LINES])
        self.assertTrue(r and r.get("ok"), r)

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.page.evaluate("async (id) => await api('DELETE', `/devices/${id}/metric-thresholds`)", _STACK["host"])
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def sensor_rows(self):
        host = _STACK["host"]
        self.page.evaluate("showPage('thermal')")
        # the page's script is loaded when the page is first opened; reload the answer so this test reads its own lines
        self.page.wait_for_function("typeof loadThermal === 'function'", timeout=60000)
        self.page.evaluate("() => { _thermalResp = null; loadThermal(); }")
        self.page.wait_for_function("(id) => document.querySelector(`[data-action=\"toggleThermalDetail\"][data-arg=\"${id}\"]`)",
                                    arg=host, timeout=60000)
        self.page.evaluate("(id) => { if (!_thermalExpanded.has(id)) toggleThermalDetail(id); }", host)
        self.page.wait_for_selector(".thermal-sensor-table tbody tr", timeout=30000)
        rows = self.page.evaluate("""() => [...document.querySelectorAll('.thermal-sensor-table tbody tr')].map(tr => {
            const t = tr.querySelectorAll('td');
            return {label: t[0].textContent.trim(), cls: t[1].className, type: t[2].textContent.trim(), crit: t[3].textContent.trim()};
        })""")
        return {r["label"].split(" ")[0]: r for r in rows if r["type"] == "sensor"}

    def test_the_thermal_page_names_each_sensors_disk_and_paints_it_by_its_disks_pair(self):
        rows = self.sensor_rows()
        self.assertEqual(sorted(rows), sorted([HDD, SSD, LOST]), rows)
        hdd, ssd, lost = rows[HDD], rows[SSD], rows[LOST]
        # the hard disk at 51 is over its 50, though 51 is under the 60 that "any other drive" would hold it to
        self.assertIn("sda · HDD", hdd["label"])
        self.assertIn("c-red", hdd["cls"])
        self.assertTrue(hdd["crit"].startswith("50"), hdd)
        # the SSD at 66 is between its 65 and its 70, and over the 60 that "any other drive" would call critical
        self.assertIn("sdb · SSD", ssd["label"])
        self.assertIn("c-amber", ssd["cls"])
        self.assertNotIn("c-red", ssd["cls"])
        self.assertTrue(ssd["crit"].startswith("70"), ssd)
        # the sensor with no disk keeps the lines for any other drive, and says why
        self.assertIn("disk not identified", lost["label"])
        self.assertNotIn("c-red", lost["cls"])
        self.assertNotIn("c-amber", lost["cls"])
        self.assertTrue(lost["crit"].startswith("60"), lost)

    def test_the_drawers_temperature_list_agrees_with_the_page(self):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [_STACK["host"], _STACK["name"]])
        self.page.wait_for_selector("#audit-sec-hardware", state="attached", timeout=30000)
        if not self.page.eval_on_selector("#audit-sec-hardware", "d => d.open"):
            self.page.click("#audit-sec-hardware > summary")
        self.page.wait_for_function(
            "(label) => [...document.querySelectorAll('#audit-sec-hardware .cmd-badge')].some(b => b.textContent.includes(label))",
            arg=HDD, timeout=30000)
        badges = self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#audit-sec-hardware .cmd-badge')]
            .filter(b => b.textContent.includes('drivetemp-scsi')).map(b => [b.textContent.split(':')[0].trim(), b.className]))""")
        self.assertIn("c-red", badges[HDD], badges)     # critical
        self.assertIn("c-red", badges[SSD], badges)     # hot: the drawer marks anything over a line
        self.assertNotIn("c-red", badges[LOST], badges)  # 50 is under the 55 of the lines for any other drive
        head = self.page.evaluate("() => document.querySelector('#audit-sec-hardware').innerText")
        self.assertIn("2 hot", head)


if __name__ == "__main__":
    unittest.main()
