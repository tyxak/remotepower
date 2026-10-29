#!/usr/bin/env python3
"""7.4.4 security review: markup in the strings a host reports about its drives stays text on the pages.

A host chooses the device name, the serial number and the model of every drive it reports, and an
administrator chooses the name a drive is shown under. The temperature lines print those strings on the
Hardware tab (two boxes for each drive, with the serial in an attribute and the device in a label), and
the alert they raise prints them on Needs attention, in the inbox and on the predictive health page.

This plants an element that would run into each of those strings, on a seeded instance, signs in and opens
each page. Two controls keep a green result honest: the planted text must be on the page (as text, so
"nothing ran" cannot mean "nothing was shown"), and the detector must fire for an element that really is
injected. test_v744_security.py holds the server side of the same review.

Self-skips without playwright/chromium/gunicorn, like its siblings.
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
HOST = "tnas"
HOST_NAME = "truenas.lab"

# Each closes the quote or the tag it lands in, then adds an element that counts itself when it runs.
IMG = '"><img src=x onerror="window.__pwned=(window.__pwned||0)+1">'
SVG = '"><svg/onload=window.__pwned=(window.__pwned||0)+1>'

# What the page reports about the planted text and about what ran: how many elements the payloads made, how many
# times a handler ran, and how often the payload's own text is on the page (in text, a title or an aria-label).
_REPORT_JS = """() => {
  const attrs = Array.from(document.querySelectorAll('[title],[aria-label],[data-line-serial]'))
      .map(e => ['title', 'aria-label', 'data-line-serial'].map(a => e.getAttribute(a) || '').join(' ')).join(' ');
  const text = document.body.innerText + ' ' + attrs;
  return {
    ran: window.__pwned || 0,
    injected: document.querySelectorAll('img[src="x"], svg[onload], [onerror]').length,
    shown: (text.match(/onerror=/g) || []).length + (text.match(/onload=/g) || []).length,
  };
}"""


def _plant(data_dir):
    """Hostile device, serial, model and name for the hot drive of the seeded NAS, and the state and alert that go with it."""
    d = Path(data_dir)
    hw = json.loads((d / "hardware.json").read_text())
    hot = next(x for x in hw[HOST]["smart"] if x["device"] == "/dev/sdb")
    hot.update(serial="SN" + IMG, device="/dev/sdb" + SVG, model="Model" + IMG, temperature_c=52)
    hw[HOST]["_drive_temp"] = {hot["serial"]: {"l": "critical", "m": 0}}
    (d / "hardware.json").write_text(json.dumps(hw))
    (d / "disk_names.json").write_text(json.dumps({HOST: {hot["serial"]: "Pool" + IMG}}))
    alerts = json.loads((d / "alerts.json").read_text())
    planted = 0
    for a in alerts["alerts"]:
        payload = a.get("payload") or {}
        if payload.get("metric") == "drivetemp":
            payload.update(target=hot["serial"], serial=hot["serial"], disk=hot["device"], disk_name="Pool" + IMG)
            a["title"] = "Drive Pool" + IMG + " CRITICAL on " + HOST_NAME + ": 52°C"
            planted += 1
    assert planted, "the seeder no longer raises a drive temperature alert; the plant has nothing to change"
    (d / "alerts.json").write_text(json.dumps(alerts))


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
        return
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-drivetemp-sec-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    _plant(data_dir)
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f"app stack not available: {exc}")
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors, dialogs = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def on_dialog(dlg):
        dialogs.append(dlg.message)
        dlg.dismiss()
    page.on("dialog", on_dialog)
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, errors=errors, dialogs=dialogs)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestMarkupInADrivesStringsIsText(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("() => { window.__pwned = 0; }")

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass

    def report(self):
        self.page.wait_for_timeout(2500)                # a handler of an injected element runs after the markup is in
        return self.page.evaluate(_REPORT_JS)

    def assert_text_only(self, where, need_shown=True):
        got = self.report()
        self.assertEqual(got["ran"], 0, f"{where}: planted markup ran: {got}")
        self.assertEqual(got["injected"], 0, f"{where}: planted markup became elements: {got}")
        if need_shown:
            self.assertGreater(got["shown"], 0, f"{where}: the planted text is not on the page, so nothing was measured: {got}")
        self.assertEqual(_STACK["dialogs"], [], where)
        self.assertEqual(_STACK["errors"], [], where)

    def test_the_detector_fires_for_an_element_that_is_really_injected(self):
        self.page.evaluate("""() => {
            const c = document.createElement('div'); c.id = '__control'; document.body.appendChild(c);
            c.innerHTML = '<img src=x onerror="window.__pwned=(window.__pwned||0)+1">';
        }""")
        try:
            got = self.report()
        finally:
            self.page.evaluate("() => { const c = document.getElementById('__control'); if (c) c.remove(); window.__pwned = 0; }")
        self.assertTrue(got["injected"] > 0, got)       # a content-security policy may stop the handler, never the element

    def test_needs_attention_the_inbox_and_the_predictive_health_page_show_it_as_text(self):
        for name in ("home", "alerts", "disk-health"):
            with self.subTest(page=name):
                self.page.evaluate(f"showPage('{name}')")
                self.assert_text_only(name)

    def test_the_hardware_tab_shows_it_as_text_in_the_rows_the_boxes_and_their_labels(self):
        self.page.evaluate(f"openDeviceDrawer('{HOST}', '{HOST_NAME}', 'audit')")
        self.page.wait_for_selector("#audit-sec-hardware", state="attached", timeout=30000)
        if not self.page.eval_on_selector("#audit-sec-hardware", "d => d.open"):
            self.page.click("#audit-sec-hardware > summary")
        self.page.wait_for_selector("#hw-diskname-form", timeout=30000)
        boxes = self.page.evaluate("""() => Array.from(document.querySelectorAll('#hw-diskname-form input[data-line]'))
            .map(e => [e.dataset.lineSerial, e.getAttribute('aria-label')])""")
        self.assertTrue(any("<img" in (b[0] or "") for b in boxes), f"the planted drive has no line boxes: {boxes[:2]}")
        self.assertTrue(any("<svg" in (b[1] or "") for b in boxes), boxes[:2])
        self.assert_text_only("hardware tab")


if __name__ == "__main__":
    unittest.main()
