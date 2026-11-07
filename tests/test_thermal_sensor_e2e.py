"""The Thermal page charts any sensor of a host, in a browser, over the seeded demo.

The server and the page's functions are held by test_thermal_sensor_history and test_thermal_sensor_page. What
they cannot show is the whole path: the button on a row of the sensor table, the request it sends, the series
the server answers with from the seeded history, and what the chart draws. The Disk chart of the Metrics
window is looked at in the same run, because its axis is fitted to the values and the others are not.
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
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    errors, requests = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("request", lambda r: requests.append(r.url))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors, requests


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-sensorgraph-")
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
    context, page, errors, requests = _sign_in(browser, base, "alice", "demo")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, requests=requests)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestChartingASensor(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        _STACK["requests"].clear()

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def host(self):
        found = self.page.evaluate("""async () => {
            const r = await api('GET', '/fleet/thermal');
            const h = (r.hosts || []).find(h => ['sensor', 'disk', 'gpu'].every(t => (h.detail || []).some(s => s.type === t)));
            return h ? {id: h.device_id, name: h.device, detail: h.detail.map(s => ({type: s.type, label: s.label}))} : null;
        }""")
        self.assertIsNotNone(found, "the demo has a host with a board sensor, a drive and a GPU")
        return found

    def open(self, host):
        self.page.evaluate("showPage('thermal')")
        self.page.wait_for_function("(id) => document.querySelector(`[data-action=\"toggleThermalDetail\"][data-arg=\"${id}\"]`)",
                                    arg=host["id"], timeout=60000)
        # The page module is loaded now. Start each test from the hottest reading, with the host closed.
        self.page.evaluate("(id) => { _thermalSensor.delete(id); _thermalRange.delete(id); _thermalExpanded.delete(id); }", host["id"])
        self.page.evaluate("(id) => { if (!_thermalExpanded.has(id)) toggleThermalDetail(id); }", host["id"])
        self.page.wait_for_selector(".thermal-sensor-table tbody tr", timeout=30000)
        self.chart_ready(host)

    def chart_ready(self, host):
        self.page.wait_for_function("(id) => document.querySelector(`#thermal-ts-${CSS.escape(id)} svg.ts-chart`)", arg=host["id"], timeout=30000)

    def chart(self, host):
        return self.page.evaluate("""(id) => {
            const box = document.getElementById('thermal-ts-' + id);
            const svg = box.querySelector('svg.ts-chart');
            return {aria: svg.getAttribute('aria-label'), paths: svg.querySelectorAll('path').length,
                    legend: [...box.querySelectorAll('.ts-leg')].map(e => e.textContent.trim()),
                    head: document.getElementById('thermal-tl-' + id).firstElementChild.textContent.replace(/\\s+/g, ' ').trim(),
                    ranges: [...document.querySelectorAll('#thermal-tl-' + id + ' .metric-range-btn')].map(b => b.textContent.trim()),
                    note: document.getElementById('thermal-tsnote-' + id).textContent.trim()};
        }""", host["id"])

    def chart_button(self, host, kind, label=None):
        rows = self.page.evaluate("""() => [...document.querySelectorAll('.thermal-sensor-table tbody tr')].map(tr => {
            const b = tr.querySelector('button[data-action="thermalPickSensor"]');
            return b ? {arg2: b.getAttribute('data-arg2'), pressed: b.getAttribute('aria-pressed'), on: tr.classList.contains('thermal-sensor-on'),
                        cell: tr.querySelector('td').textContent.trim()} : null;
        }).filter(Boolean)""")
        for row in rows:
            if row["arg2"].startswith(kind + "|") and (label is None or row["arg2"] == f"{kind}|{label}"):
                return row
        self.fail(f"no Chart button for {kind} in {rows}")

    def click_chart(self, host, key):
        self.page.click(f'.thermal-sensor-table button[data-action="thermalPickSensor"][data-arg2="{key}"]')
        self.page.wait_for_function("([id, key]) => { const h = document.getElementById('thermal-tl-' + id); return h && h.textContent.includes(key.split('|').slice(1).join('|')); }",
                                    arg=[host["id"], key], timeout=30000)
        self.chart_ready(host)
        self.page.wait_for_timeout(300)

    def test_every_row_has_a_chart_button_and_the_chart_starts_on_the_hottest_reading(self):
        host = self.host()
        self.open(host)
        listed = {(s["type"], s["label"]) for s in host["detail"]}
        buttons = self.page.evaluate("""() => [...document.querySelectorAll('.thermal-sensor-table button[data-action="thermalPickSensor"]')]
            .map(b => b.getAttribute('data-arg2'))""")
        self.assertEqual({tuple(b.split("|", 1)) for b in buttons}, listed)
        chart = self.chart(host)
        self.assertIn("Charting the hottest reading", chart["head"])
        self.assertEqual(chart["ranges"], ["24 hours", "8 days", "30 days", "2 years"])
        self.assertEqual(chart["legend"], ["Min", "Avg", "Max"])
        self.assertFalse([u for u in _STACK["requests"] if "sensor=" in u])

    def test_a_board_sensor_is_charted_from_its_own_series(self):
        host = self.host()
        self.open(host)
        label = next(s["label"] for s in host["detail"] if s["type"] == "sensor")
        self.click_chart(host, f"sensor|{label}")
        chart = self.chart(host)
        self.assertEqual(chart["head"], f"Charting {label} Hottest reading")
        self.assertIn(label, chart["aria"])
        self.assertEqual(chart["ranges"], ["24 hours", "8 days", "30 days"])
        self.assertEqual(chart["legend"], [], "one reading a point: one line, no legend")
        self.assertEqual(chart["paths"], 1)
        self.assertTrue([u for u in _STACK["requests"] if "tier=raw" in u and "sensor=sensor%7C" in u], _STACK["requests"][-6:])
        row = self.chart_button(host, "sensor", label)
        self.assertEqual((row["pressed"], row["on"]), ("true", True))

    def test_a_drive_and_a_gpu_are_charted_too(self):
        host = self.host()
        self.open(host)
        for kind in ("disk", "gpu"):
            with self.subTest(kind=kind):
                label = next(s["label"] for s in host["detail"] if s["type"] == kind)
                self.click_chart(host, f"{kind}|{label}")
                chart = self.chart(host)
                self.assertIn(label, chart["aria"])
                self.assertEqual(chart["paths"], 1)
                self.assertNotIn("No history for this sensor yet", chart["note"])

    def test_the_longer_ranges_come_from_the_hourly_series_with_the_band(self):
        host = self.host()
        self.open(host)
        label = next(s["label"] for s in host["detail"] if s["type"] == "sensor")
        self.click_chart(host, f"sensor|{label}")
        _STACK["requests"].clear()
        self.page.click('#thermal-tl-%s .metric-range-btn[data-arg2="30d"]' % host["id"])
        self.page.wait_for_function("(id) => document.querySelector(`#thermal-ts-${CSS.escape(id)} .ts-leg`)", arg=host["id"], timeout=30000)
        chart = self.chart(host)
        self.assertEqual(chart["legend"], ["Min", "Avg", "Max"])
        self.assertTrue([u for u in _STACK["requests"] if "tier=hourly" in u and "sensor=" in u])
        self.assertIn("30 days", chart["aria"])
        self.page.click('#thermal-tl-%s .metric-range-btn[data-arg2="8d"]' % host["id"])
        self.page.wait_for_timeout(600)
        self.assertIn("8 days", self.chart(host)["aria"])

    def test_the_way_back_to_the_hottest_reading(self):
        host = self.host()
        self.open(host)
        label = next(s["label"] for s in host["detail"] if s["type"] == "sensor")
        self.click_chart(host, f"sensor|{label}")
        self.page.click("#thermal-tl-%s button[data-action='thermalPickSensor']" % host["id"])
        self.page.wait_for_function("(id) => document.getElementById('thermal-tl-' + id).textContent.includes('Charting the hottest reading')", arg=host["id"], timeout=30000)
        chart = self.chart(host)
        self.assertEqual(chart["ranges"], ["24 hours", "8 days", "30 days", "2 years"])
        self.assertEqual(chart["legend"], ["Min", "Avg", "Max"])
        self.assertEqual(self.chart_button(host, "sensor", label)["pressed"], "false")

    def test_choosing_the_charted_sensor_again_goes_back_too(self):
        host = self.host()
        self.open(host)
        label = next(s["label"] for s in host["detail"] if s["type"] == "sensor")
        self.click_chart(host, f"sensor|{label}")
        self.page.click(f'.thermal-sensor-table button[data-action="thermalPickSensor"][data-arg2="sensor|{label}"]')
        self.page.wait_for_function("(id) => document.getElementById('thermal-tl-' + id).textContent.includes('Charting the hottest reading')", arg=host["id"], timeout=30000)

    def test_a_sensor_stays_charted_when_the_table_is_refreshed(self):
        host = self.host()
        self.open(host)
        label = next(s["label"] for s in host["detail"] if s["type"] == "disk")
        self.click_chart(host, f"disk|{label}")
        self.page.evaluate("loadThermal()")
        self.page.wait_for_function("(id) => document.getElementById('thermal-tl-' + id) && document.getElementById('thermal-tl-' + id).textContent.includes('Charting')",
                                    arg=host["id"], timeout=30000)
        self.chart_ready(host)
        self.assertIn(label, self.chart(host)["aria"])

    def test_a_sensor_with_no_history_says_so(self):
        host = self.host()
        self.open(host)
        self.page.evaluate("(id) => { thermalPickSensor('th-' + id, 'sensor|a sensor the host never reported'); }", host["id"])
        self.page.wait_for_function("(id) => document.querySelector(`#thermal-ts-${CSS.escape(id)} .empty-state`)", arg=host["id"], timeout=30000)
        text = self.page.evaluate("(id) => document.querySelector(`#thermal-ts-${CSS.escape(id)} .empty-state`).textContent", host["id"])
        self.assertIn("No history for this sensor yet", text)
        self.page.evaluate("(id) => thermalPickSensor('th-' + id, '')", host["id"])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheDiskChartFitsItsAxis(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def labels(self, chart_id):
        return self.page.evaluate("""(id) => [...document.querySelectorAll('#' + id + ' svg text')].map(t => t.textContent)
                                       .filter(t => /^[0-9]+%$/.test(t))""", chart_id)

    def test_cpu_keeps_its_zero_to_a_hundred_axis_and_disk_is_fitted(self):
        host = self.page.evaluate("""async () => { const r = await api('GET', '/fleet/thermal'); const h = r.hosts[0]; return {id: h.device_id, name: h.device}; }""")
        self.page.evaluate("(a) => openMetrics(a[0], a[1])", [host["id"], host["name"]])
        self.page.wait_for_selector("#mc-disk svg", timeout=30000)
        self.page.wait_for_timeout(500)
        cpu, disk = self.labels("mc-cpu"), self.labels("mc-disk")
        self.assertEqual(cpu, ["0%", "25%", "50%", "75%", "100%"])
        self.assertEqual(len(disk), 5)
        values = [int(v[:-1]) for v in disk]
        self.assertEqual(values, sorted(values))
        self.assertNotEqual(values[:1] + values[-1:], [0, 100], "the Disk axis is not fitted to the data")
        self.assertLessEqual(values[-1] - values[0], 20)
        note = self.page.evaluate("() => document.getElementById('mc-disk').closest('.isl-355').textContent")
        self.assertIn("root filesystem", note)
        self.page.evaluate("closeModal('metrics-modal')")


if __name__ == "__main__":
    unittest.main()
