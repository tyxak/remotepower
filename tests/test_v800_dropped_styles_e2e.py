#!/usr/bin/env python3
"""8.0.0: four places that had a colour or a dimming before the CSP change have it again, measured in a browser.

When the inline styles were removed (42dca579) a style that carried a value became a placeholder class, `.isl-N { /* dynamic colour, applied via data-color attribute */ }`, and the
element was meant to carry a `data-color` attribute that a small hook turns into the colour. Four sites did not get the attribute, and the reviewed list in tests/test_css_class_parity.py
(`LEGACY_UNSTYLED`) recorded the classes as "the colour arrives from the attribute" without anyone looking at the elements:

* the Patch Report dialog's Status (green, amber, grey) and Online (green, red) lines were plain text; the colour was computed into a variable and never used;
* the host audit's Metrics tiles never showed the state of their threshold (red for critical, amber for a warning), though the page reads that state;
* a row of the drift table lost its separator line, and a file the operator marked as ignored was no longer dimmed.

What the page puts on screen is measured here: the computed colour of each element against the colour a probe element with the same utility class gets (so the theme is not hard-coded), and the computed
opacity and border of the drift rows. The server's answers are fixtures put in front of the real page code; tests/test_v800_dynamic_colour_carrier.py holds the rule over every render site.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

_STATE = {}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what the page draws does not depend on the storage backend: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-dropped-styles-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack

    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


def _login(browser):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    page.set_default_timeout(20000)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3000)
    return ctx, page, errors


_PROBES = """() => {
  const out = {};
  for (const cls of ['c-green', 'c-amber', 'c-red', 'c-muted']) {
    const el = document.createElement('span');
    el.className = cls; el.textContent = 'x';
    document.body.appendChild(el);
    out[cls] = getComputedStyle(el).color;
    el.remove();
  }
  return out;
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestWhatThePageDraws(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"])
        cls.probe = cls.page.evaluate(_PROBES)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def answer(self, pattern, body, status=200):
        self.page.route(pattern, lambda route: route.fulfill(status=status, content_type="application/json", body=json.dumps(body)))

    def clear_routes(self):
        self.page.unroute_all()

    def tearDown(self):
        self.clear_routes()

    def test_the_probes_are_four_different_colours(self):
        """The expected colours below are read from probes, so the probes have to differ or every comparison would pass."""
        self.assertEqual(len(set(self.probe.values())), 4, self.probe)

    # ── the Patch Report dialog ───────────────────────────────────────────────────

    def patch_report(self, **fields):
        data = {"patch_status": "fully_patched", "upgradable": 0, "online": True, "os": "Debian 12", "pkg_manager": "apt", "version": "7.5.0"}
        data.update(fields)
        self.answer("**/api/patch-report/device/*", data)
        self.page.evaluate("() => openDevicePatchReport('d-probe', 'probe-host')")
        self.page.wait_for_selector("#device-patch-body .sysinfo-pill .value", timeout=15000)
        return self.page.evaluate("""() => {
          const out = {};
          document.querySelectorAll('#device-patch-body .sysinfo-pill').forEach(p => {
            const label = p.querySelector('.label').textContent.trim();
            out[label] = getComputedStyle(p.querySelector('.value')).color;
          });
          return out;
        }""")

    def test_a_patched_online_host_reads_green_on_both_lines(self):
        got = self.patch_report(patch_status="fully_patched", online=True)
        self.assertEqual((got["Status"], got["Online"]), (self.probe["c-green"], self.probe["c-green"]), got)

    def test_pending_patches_read_amber_and_an_offline_host_red(self):
        got = self.patch_report(patch_status="patches_available", upgradable=4, online=False)
        self.assertEqual((got["Status"], got["Online"]), (self.probe["c-amber"], self.probe["c-red"]), got)

    def test_a_host_with_no_patch_data_reads_grey(self):
        got = self.patch_report(patch_status="unknown", online=True)
        self.assertEqual(got["Status"], self.probe["c-muted"], got)

    # ── the host audit's Metrics tiles ────────────────────────────────────────────

    def metric_tiles(self, state):
        host = {"id": "d-probe", "name": "probe-host",
                "sysinfo": {"cpu_percent": 93.0, "mem_percent": 82.0, "swap_percent": 3.0, "loadavg_1m": 0.4, "mounts": [{"path": "/", "percent": 41.0}]},
                "metric_state": state}
        self.answer("**/api/devices", [host])
        self.page.evaluate("""() => {
          document.getElementById('audit-body-metrics')?.remove();
          document.getElementById('audit-badge-metrics')?.remove();
          const body = document.createElement('div'); body.id = 'audit-body-metrics';
          const badge = document.createElement('span'); badge.id = 'audit-badge-metrics';
          document.body.append(body, badge);
          _drawerDeviceId = 'd-probe';
        }""")
        self.page.evaluate("() => _loadAuditSection('metrics')")
        self.page.wait_for_selector("#audit-body-metrics .sysinfo-pill .value", timeout=15000)
        return self.page.evaluate("""() => {
          const out = {};
          document.querySelectorAll('#audit-body-metrics .sysinfo-pill').forEach(p => {
            out[p.querySelector('.label').textContent.trim()] = getComputedStyle(p.querySelector('.value')).color;
          });
          return out;
        }""")

    def test_a_critical_metric_is_red_a_warning_amber_and_an_ok_one_neither(self):
        got = self.metric_tiles({"cpu:": "critical", "memory:": "warning"})
        self.assertEqual(got["CPU"], self.probe["c-red"], got)
        self.assertEqual(got["Memory"], self.probe["c-amber"], got)
        # Load is judged by the CPU state key ('cpu:'), so it follows the CPU tile; Swap and the root disk have states of their own, and both are ok here
        self.assertEqual(got["Load"], got["CPU"], got)
        for ok_tile in ("Swap", "Disk /"):
            self.assertNotIn(got[ok_tile], (self.probe["c-red"], self.probe["c-amber"]), got)
        self.assertEqual(got["Swap"], got["Disk /"], "two ok tiles read the same")

    # ── the drift table ───────────────────────────────────────────────────────────

    def drift_rows(self):
        files = {
            "/etc/hosts": {"current_hash": "a", "baseline_hash": "a", "exists": True, "ignored": False, "last_check": 1700000000, "drift_count": 0},
            "/etc/motd": {"current_hash": "b", "baseline_hash": "a", "exists": True, "ignored": True, "last_check": 1700000000, "drift_count": 2},
        }
        self.answer("**/api/devices/*/drift", {"files": files, "watched_files": list(files), "source": "default"})
        self.page.evaluate("() => openDriftDetail('d-probe', 'probe-host')")
        self.page.wait_for_selector("#drift-detail-body tbody tr", timeout=15000)
        return self.page.evaluate("""() => {
          const out = {};
          document.querySelectorAll('#drift-detail-body tbody tr').forEach(tr => {
            const path = tr.querySelector('td')?.textContent.trim();
            if (!path || !path.startsWith('/')) return;
            const cs = getComputedStyle(tr);
            out[path] = {opacity: cs.opacity, borderStyle: cs.borderBottomStyle, borderWidth: cs.borderBottomWidth};
          });
          return out;
        }""")

    def test_every_row_has_its_separator_and_only_an_ignored_file_is_dimmed(self):
        rows = self.drift_rows()
        self.assertEqual(sorted(rows), ["/etc/hosts", "/etc/motd"], rows)
        for path, r in rows.items():
            self.assertEqual((r["borderStyle"], r["borderWidth"]), ("solid", "1px"), f"{path}: no separator line: {r}")
        self.assertEqual(rows["/etc/hosts"]["opacity"], "1", rows)
        self.assertAlmostEqual(float(rows["/etc/motd"]["opacity"]), 0.55, places=2, msg=rows)

    def test_the_page_raised_no_script_error(self):
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
