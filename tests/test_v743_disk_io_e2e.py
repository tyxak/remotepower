#!/usr/bin/env python3
"""7.4.3, issue #49: per-disk I/O on the pages.

The server side (the ingest, the metric engine, the alert words, the Hardware answer) is in
test_v743_disk_io. What that cannot show is the page: that the Hardware tab lists a Disk I/O table
with the busy share, the rates, the wait and a trend for every disk the host reports, colours a disk
by the lines it is held to, sorts, and shows the name an operator gave the drive; that a host's own
lines can be set and cleared from the Metric thresholds box and fall back to the fleet's, shown in
grey; and that Settings -> Alert parameters has the three fleet values and saves them.

The page is real (a seeded instance, a signed-in browser, the drawer and the dialogs opened the way a
person opens them). Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import os
import re
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
HOST = "tnas"


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
    data_dir = tempfile.mkdtemp(prefix="rp-diskio-")
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


class _Page(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        # a toast from the test before would satisfy this test's wait for its own
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.assertEqual(_STACK["errors"], [], "the page threw")


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheHardwareTab(_Page):

    @classmethod
    def setUpClass(cls):
        hw = _STACK["page"].evaluate(f"async () => await api('GET', '/devices/{HOST}/hardware')")
        cls.rows = (hw or {}).get("diskio") or []
        if len(cls.rows) < 2:
            raise unittest.SkipTest("the seeded fleet has no host reporting disk I/O")
        cls.smart = {d["device"]: d for d in (hw.get("smart") or [])}

    def tearDown(self):
        super().tearDown()
        self.page.evaluate("""async (serials) => {
            const names = {};
            for (const s of serials) names[s] = '';
            await api('PUT', `/devices/%s/disk-names`, {names});
        }""" % HOST, [d["serial"] for d in self.smart.values() if d.get("serial")])

    def open_hardware(self):
        self.page.evaluate("([id]) => openDeviceDrawer(id, 'truenas.lab', 'audit')", [HOST])
        self.page.wait_for_selector("#audit-sec-hardware", state="attached", timeout=30000)
        if not self.page.eval_on_selector("#audit-sec-hardware", "d => d.open"):
            self.page.click("#audit-sec-hardware > summary")      # open the section the way a person does
        self.page.wait_for_selector("#hw-diskio-thead", state="visible", timeout=30000)

    def table(self):
        return self.page.evaluate("""() => {
            const t = document.getElementById('hw-diskio-thead');
            if (!t) return null;
            return Array.from(t.closest('table').querySelectorAll('tbody tr')).map(tr => ({
                cells: Array.from(tr.cells).map(c => c.innerText.trim()),
                busyClass: tr.cells[1].className,
                sparks: tr.querySelectorAll('svg.sparkline').length,
            }));
        }""")

    def test_every_disk_the_host_reports_has_a_row_with_figures_and_a_trend(self):
        self.open_hardware()
        rows = self.table()
        self.assertEqual(len(rows), len(self.rows))
        self.assertEqual(sorted(r["cells"][0].split("\n")[-1] for r in rows), sorted(r["dev"] for r in self.rows))
        for r in rows:
            self.assertTrue(r["cells"][1].endswith("%"), r["cells"])
            self.assertIn("MB/s", r["cells"][2])
            self.assertIn("MB/s", r["cells"][3])
            self.assertEqual(r["sparks"], 1, "one trend per disk")
        heads = self.page.eval_on_selector_all("#hw-diskio-thead th", "els => els.map(e => e.innerText.trim())")
        # the heads are drawn in capitals with a sort arrow after the word
        heads = [re.sub(r"[\s\u2195\u25b2\u25bc]+$", "", h).lower() for h in heads]
        self.assertEqual(heads, ["disk", "busy", "read", "write", "iops", "wait", "trend"])

    def test_a_disk_over_its_line_is_coloured_and_a_quiet_one_is_not(self):
        self.open_hardware()
        rows = {r["cells"][0].split("\n")[-1]: r for r in self.table()}
        busy = max(self.rows, key=lambda r: r["busy_pct"])
        quiet = min(self.rows, key=lambda r: r["busy_pct"])
        self.assertIsNotNone(busy["warn"], "the seeded config holds a busy line")
        self.assertGreaterEqual(busy["busy_pct"], busy["warn"])
        self.assertRegex(rows[busy["dev"]]["busyClass"], r"c-(amber|red)")
        self.assertNotRegex(rows[quiet["dev"]]["busyClass"], r"c-(amber|red)")

    def test_busy_sorts_both_ways(self):
        self.open_hardware()
        before = [r["cells"][0] for r in self.table()]
        self.page.click("#hw-diskio-thead th[data-col='busy']")
        self.page.wait_for_function(
            "(first) => { const t = document.getElementById('hw-diskio-thead'); "
            "return !!t && t.closest('table').querySelector('tbody tr').cells[0].innerText.trim() !== first; }",
            arg=before[0], timeout=15000)
        once = [r["cells"][0] for r in self.table()]
        self.page.click("#hw-diskio-thead th[data-col='busy']")
        self.page.wait_for_function(
            "(first) => { const t = document.getElementById('hw-diskio-thead'); "
            "return !!t && t.closest('table').querySelector('tbody tr').cells[0].innerText.trim() !== first; }",
            arg=once[0], timeout=15000)
        twice = [r["cells"][0] for r in self.table()]
        self.assertEqual(once, list(reversed(twice)))
        busiest = max(self.rows, key=lambda r: r["busy_pct"])["dev"]
        self.assertIn(busiest, (once[0].split("\n")[-1], once[-1].split("\n")[-1]))

    def test_a_named_drive_shows_its_name_in_the_table(self):
        dev = max(self.rows, key=lambda r: r["busy_pct"])["dev"]
        smart = self.smart.get("/dev/" + dev)
        if not smart or not smart.get("serial"):
            self.skipTest("the busiest disk reports no serial number")
        self.page.evaluate("""async ([id, serial]) => { await api('PUT', `/devices/${id}/disk-names`, {names: {[serial]: 'Pool disk 3'}}); }""",
                           [HOST, smart["serial"]])
        self.open_hardware()
        # the drawer keeps what it loaded for this host, so read the section again
        self.page.evaluate("_loadAuditSectionForce('hardware')")
        self.page.wait_for_function(
            "() => { const t = document.getElementById('hw-diskio-thead'); "
            "return !!t && t.closest('table').innerText.includes('Pool disk 3'); }", timeout=15000)
        rows = {r["cells"][0].split("\n")[-1]: r for r in self.table()}
        self.assertIn("Pool disk 3", rows[dev]["cells"][0])
        self.assertIn(dev, rows[dev]["cells"][0], "the letter stays next to the name")


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheHostsOwnLines(_Page):

    def tearDown(self):
        try:
            self.page.evaluate("closeModal('metric-thresholds-modal')")
        except Exception:
            pass
        self.page.evaluate(f"async () => {{ await api('DELETE', '/devices/{HOST}/metric-thresholds'); }}")
        super().tearDown()

    def open_box(self):
        self.page.evaluate(f"openMetricThresholds('{HOST}', 'truenas.lab')")
        self.page.wait_for_function(
            "() => document.getElementById('thr-diskio-warn') && document.getElementById('thr-diskio-warn').placeholder !== ''",
            timeout=15000)

    def overrides(self):
        return self.page.evaluate(f"async () => (await api('GET', '/devices/{HOST}/metric-thresholds')).overrides")

    def test_the_fleets_lines_are_shown_in_grey_and_the_boxes_start_empty(self):
        self.open_box()
        self.assertEqual(self.page.get_attribute("#thr-diskio-warn", "placeholder"), "85")
        self.assertEqual(self.page.get_attribute("#thr-diskio-crit", "placeholder"), "98")
        self.assertEqual(self.page.input_value("#thr-diskio-warn"), "")
        self.assertEqual(self.page.input_value("#thr-diskio-crit"), "")

    def test_a_value_is_saved_and_emptying_the_box_removes_it(self):
        self.open_box()
        self.page.fill("#thr-diskio-warn", "60")
        self.page.fill("#thr-diskio-crit", "80")
        self.page.click('#metric-thresholds-modal [data-action="saveMetricThresholds"]')
        self.page.wait_for_selector(".toast.success", timeout=15000)
        o = self.overrides()
        self.assertEqual((o.get("diskio_warn_percent"), o.get("diskio_crit_percent")), (60, 80))
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.open_box()
        self.assertEqual(self.page.input_value("#thr-diskio-warn"), "60")
        self.page.fill("#thr-diskio-warn", "")
        self.page.click('#metric-thresholds-modal [data-action="saveMetricThresholds"]')
        self.page.wait_for_selector(".toast.success", timeout=15000)
        o = self.overrides()
        self.assertNotIn("diskio_warn_percent", o, "an emptied box removes the host's line")
        self.assertEqual(o.get("diskio_crit_percent"), 80, "and leaves the other one alone")

    def test_a_number_outside_one_to_ninety_nine_is_refused_and_nothing_is_kept(self):
        self.open_box()
        self.page.fill("#thr-diskio-warn", "150")
        self.page.click('#metric-thresholds-modal [data-action="saveMetricThresholds"]')
        self.page.wait_for_function(
            "() => { const e = document.getElementById('metric-thresholds-error'); return !!e && e.style.display !== 'none' && e.textContent.trim() !== ''; }",
            timeout=15000)
        self.assertEqual(self.overrides().get("diskio_warn_percent"), None)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheFleetLines(_Page):

    def tearDown(self):
        self.page.evaluate("""async () => { await api('POST', '/config',
            {diskio_warn_percent: 85, diskio_crit_percent: 98, diskio_sustain: 5}); }""")
        super().tearDown()

    def open_pane(self):
        self.page.evaluate("showPage('settings')")
        self.page.wait_for_selector("#settings-tab-btn-alertparams", state="visible", timeout=30000)
        # the pane keeps what the last test typed; empty it so the wait below is for the values the
        # tab button loads, not for the old ones
        self.page.evaluate("() => ['warn', 'crit', 'sustain'].forEach(k => "
                           "{ const e = document.getElementById('ap-diskio-' + k); if (e) e.value = ''; })")
        self.page.click("#settings-tab-btn-alertparams")      # the tab button also loads the values
        self.page.wait_for_function(
            "() => { const e = document.getElementById('ap-diskio-warn'); return !!e && e.value !== ''; }", timeout=30000)

    def config(self):
        return self.page.evaluate("async () => { const c = await api('GET', '/config'); "
                                  "return [c.diskio_warn_percent, c.diskio_crit_percent, c.diskio_sustain]; }")

    def test_the_pane_shows_the_three_values(self):
        self.open_pane()
        got = [self.page.input_value(f"#ap-diskio-{k}") for k in ("warn", "crit", "sustain")]
        self.assertEqual(got, ["85", "98", "5"])
        title = self.page.evaluate("() => document.getElementById('ap-diskio-warn').closest('.settings-section')"
                                   ".querySelector('.section-title').innerText.trim()")
        self.assertEqual(title, "Disk activity")

    def test_a_changed_value_is_saved(self):
        self.open_pane()
        self.page.fill("#ap-diskio-warn", "90")
        self.page.fill("#ap-diskio-sustain", "3")
        self.page.click("#ap-diskio-warn >> xpath=ancestor::div[contains(@class,'settings-section')]"
                        "//button[@data-action='saveAlertParams']")
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.config(), [90, 98, 3])

    def test_a_value_out_of_range_is_refused(self):
        self.open_pane()
        self.page.fill("#ap-diskio-sustain", "0")
        self.page.click("#ap-diskio-warn >> xpath=ancestor::div[contains(@class,'settings-section')]"
                        "//button[@data-action='saveAlertParams']")
        self.page.wait_for_selector(".toast.error", timeout=15000)
        self.assertEqual(self.config(), [85, 98, 5], "nothing was kept")


if __name__ == "__main__":
    unittest.main()
