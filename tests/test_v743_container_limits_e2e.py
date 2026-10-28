#!/usr/bin/env python3
"""7.4.3, issue #50: the container CPU and memory lines, from the two places a person sets them.

The server side (what counts as over a line, when an alert opens and closes, what is kept) is in
test_v743_container_thresholds. What that cannot show is the pages: the Monitoring -> Tuning card that
holds the fleet's lines and overrides, each host's own form under its containers table, the numbers
coloured when they are over a line, and the two trend lines beside them.

The page is real (a seeded instance, a signed-in browser). Only one answer is canned, the host's
containers with their readings, because a seeded fleet has no container over a line. Self-skips without
playwright/chromium/gunicorn, like its siblings.
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
    data_dir = tempfile.mkdtemp(prefix="rp-ctrlimits-")
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
class TestTheContainerLines(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        page = _STACK["page"]
        found = page.evaluate("""async () => {
            const devs = await api('GET', '/devices');
            for (const d of (devs.devices || devs)) {
                const c = await api('GET', `/devices/${d.id}/containers`).catch(() => null);
                if (c && (c.items || []).length) return {id: d.id, name: d.name};
            }
            return null;
        }""")
        if not found:
            raise unittest.SkipTest("the seeded fleet has no host that reports containers")
        cls.host = found

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        # A toast from the last test would satisfy a wait for this one's and let it read too early.
        self.page.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.page.unroute("**/api/devices/*/containers")
        self.page.evaluate("""async (id) => {
            await api('POST', '/config', {container_thresholds: {}});
            await api('PUT', `/devices/${id}/container-thresholds`, {thresholds: {}});
        }""", self.host["id"])

    def open_tuning(self):
        self.page.evaluate("showPage('tuning')")
        self.page.wait_for_function("() => !document.getElementById('ctl-cpu').disabled", timeout=30000)
        self.page.evaluate("async () => { await loadContainerLimits(true); }")     # the boxes as the server has them

    def test_the_card_saves_the_lines_and_the_overrides_and_shows_them_again(self):
        self.open_tuning()
        self.page.fill("#ctl-cpu", "150")
        self.page.fill("#ctl-memp", "90")
        self.page.fill("#ctl-memmb", "2048")
        self.page.fill("#ctl-sustain", "4")
        self.page.fill("#ctl-overrides", "jellyfin cpu=400 mb=4096\nimage:ghcr.io/acme/job cpu=0 mb=0\n# a comment\n")
        self.page.click("#ctl-save")
        self.page.wait_for_selector(".toast.success", timeout=15000)
        kept = self.page.evaluate("api('GET', '/config').then(c => c.container_thresholds)")
        self.assertEqual(kept, {"cpu_pct": 150, "mem_pct": 90, "mem_mb": 2048, "sustain": 4,
                                "overrides": [{"match": "jellyfin", "cpu_pct": 400, "mem_mb": 4096},
                                              {"match": "image:ghcr.io/acme/job", "cpu_pct": 0, "mem_mb": 0}]})
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(3000)
        self.open_tuning()
        self.assertEqual(self.page.input_value("#ctl-cpu"), "150")
        self.assertEqual(self.page.input_value("#ctl-sustain"), "4")
        self.assertEqual(self.page.input_value("#ctl-overrides"),
                         "jellyfin cpu=400 mb=4096\nimage:ghcr.io/acme/job cpu=0 mb=0")

    def test_a_line_that_is_not_one_is_refused_before_anything_is_sent(self):
        self.open_tuning()
        self.page.fill("#ctl-cpu", "150")
        for bad, why in (("jellyfin cpu=lots", "cpu=lots"), ("jellyfin", "sets nothing"), ("jellyfin gpu=3", "gpu=3")):
            with self.subTest(line=bad):
                self.page.fill("#ctl-overrides", bad)
                self.page.click("#ctl-save")
                self.page.wait_for_selector(".toast.error", timeout=15000)
                self.assertIn(why, self.page.inner_text(".toast.error"))
                self.page.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.assertEqual(self.page.evaluate("api('GET', '/config').then(c => c.container_thresholds || null)"), None)

    def test_an_empty_box_is_not_a_zero(self):
        self.open_tuning()
        self.page.fill("#ctl-cpu", "150")
        self.page.click("#ctl-save")
        self.page.wait_for_selector(".toast.success", timeout=15000)
        self.assertEqual(self.page.evaluate("api('GET', '/config').then(c => c.container_thresholds)"), {"cpu_pct": 150})

    def containers_answer(self, items):
        body = {"device_id": self.host["id"], "name": self.host["name"], "reported_at": 1, "is_stale": False,
                "stale_ttl": 900, "items": items, "summary": {}, "df": None}
        self.page.route("**/api/devices/*/containers", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(body)))

    def open_containers(self):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [self.host["id"], self.host["name"]])
        self.page.wait_for_selector("#audit-sec-containers", state="attached", timeout=30000)
        if not self.page.eval_on_selector("#audit-sec-containers", "d => d.open"):
            self.page.click("#audit-sec-containers > summary")
        self.page.wait_for_selector("#audit-body-containers table", state="visible", timeout=30000)

    def test_what_is_over_its_line_is_red_and_the_trend_is_drawn(self):
        hist = [[1000 + 60 * i, 20.0 + 10 * i, 30.0 + i, 300.0 + i] for i in range(8)]
        base = {"image": "nginx", "tag": "1", "status": "Up 2 hours", "health": "", "ports": [], "runtime": "docker",
                "restart_count": 0, "uptime_seconds": 7200, "mem_usage": "512MiB", "limits": {}, "res_alerting": []}
        self.containers_answer([
            dict(base, name="hot", cpu_percent=412.5, mem_percent=31.0, res_alerting=["cpu"], hist=hist),
            dict(base, name="calm", cpu_percent=3.0, mem_percent=10.0, hist=[]),
        ])
        self.open_containers()
        rows = self.page.evaluate("""() => Array.from(document.querySelectorAll('#audit-body-containers tbody tr')).map(tr => ({
            name: tr.cells[0].innerText.trim(),
            red: Array.from(tr.cells[4].querySelectorAll('.c-red')).map(e => e.textContent.trim()),
            spark: tr.cells[4].querySelectorAll('svg.sparkline').length,
            text: tr.cells[4].innerText}))""")
        hot = next(r for r in rows if r["name"].startswith("hot"))
        calm = next(r for r in rows if r["name"].startswith("calm"))
        self.assertEqual(hot["red"], ["412.5% cpu"], "only the resource that is over its line is red")
        self.assertEqual(hot["spark"], 2, "a trend for the CPU and one for the memory")
        self.assertEqual(calm["red"], [])
        self.assertEqual(calm["spark"], 0, "no samples, no drawing")
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def test_each_host_has_its_own_form_with_the_fleets_lines_as_the_hint(self):
        self.page.evaluate("api('POST', '/config', {container_thresholds: {cpu_pct: 150, sustain: 4}})")
        self.open_containers()
        self.page.click("#audit-body-containers details > summary")
        self.page.wait_for_selector("#hctl-form", state="visible", timeout=15000)
        self.assertEqual(self.page.get_attribute("#hctl-form [data-ctl='cpu']", "placeholder"), "150")
        self.assertEqual(self.page.get_attribute("#hctl-form [data-ctl='memp']", "placeholder"), "off")
        self.page.fill("#hctl-form [data-ctl='cpu']", "75")
        self.page.fill("#hctl-form [data-ctl='overrides']", "db mb=8192")
        self.page.click('#hctl-form [data-action="saveHostContainerLimits"]')
        self.page.wait_for_selector(".toast.success", timeout=15000)
        mine = self.page.evaluate("([id]) => api('GET', `/devices/${id}/container-thresholds`)", [self.host["id"]])
        self.assertEqual(mine["thresholds"], {"cpu_pct": 75, "overrides": [{"match": "db", "mem_mb": 8192}]})
        self.assertEqual(mine["fleet"], {"cpu_pct": 150, "sustain": 4})

    def test_a_reader_gets_neither_the_form_nor_a_save_button(self):
        self.page.evaluate("api('POST', '/config', {container_thresholds: {cpu_pct: 150}})")
        context, viewer, errors = _sign_in(_STACK["browser"], _STACK["base"], "demo", "demo")
        try:
            viewer.evaluate("showPage('tuning')")
            viewer.wait_for_function("() => !document.getElementById('ctl-cpu').disabled", timeout=30000)
            self.assertEqual(viewer.input_value("#ctl-cpu"), "150", "a reader sees the lines")
            self.assertTrue(viewer.eval_on_selector("#ctl-cpu", "e => e.readOnly"))
            self.assertFalse(viewer.is_visible("#ctl-save"))
            viewer.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [self.host["id"], self.host["name"]])
            viewer.wait_for_selector("#audit-sec-containers", state="attached", timeout=30000)
            if not viewer.eval_on_selector("#audit-sec-containers", "d => d.open"):
                viewer.click("#audit-sec-containers > summary")
            viewer.wait_for_selector("#audit-body-containers table", state="visible", timeout=30000)
            self.assertEqual(viewer.query_selector("#hctl-form"), None)
            self.assertEqual(errors, [])
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
