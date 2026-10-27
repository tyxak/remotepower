#!/usr/bin/env python3
"""7.4.2, issue #42: the SNMP card, drawn by the real page from the answer the server gives.

The server's side of this (the sum, the list cell, the alert) is in test_v742_snmp_memory. What
that cannot show is the card: whether the Memory block appears, says the right thing and is the
right colour, and whether the device's own "Real memory" line stops shouting red once it is known
to include the cache. So the page is real (a seeded instance, a signed-in browser, the drawer
opened the way a person opens it) and only the one answer is canned: the deep SNMP read, which
would otherwise need a firewall on the network.

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
import snmp as snmp_mod  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
MB = 1024 * 1024


def row(index, descr, size_mb, used_mb):
    size, used = size_mb * MB, used_mb * MB
    return {"index": index, "descr": descr, "size_bytes": size, "used_bytes": used,
            "used_pct": round(used * 100.0 / size, 1)}


def deep_answer(storage, ucd_total_mb=7918, ucd_free_mb=464):
    """What /api/devices/<id>/snmp/deep returns, with the memory block built by the server's own sum."""
    out = {"host": "10.0.0.1", "port": 161, "errors": {}, "system": {"sysName": "opnsense"},
           "storage": storage,
           "ucd_snmp": {"laLoad_1m": 0.2, "laLoad_5m": 0.1, "laLoad_15m": 0.1,
                        "memTotalReal": ucd_total_mb * 1024, "memAvailReal": ucd_free_mb * 1024},
           "polled_at": 1}
    mem = snmp_mod.memory_in_use(storage)
    if mem:
        out["memory"] = mem
    return out


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-snmpcard-")
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
    # A service worker answers the page's requests before Playwright can see them, and a route
    # that never fires reads as "the card is broken". Blocked, the canned answer is the answer.
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()
        _STACK.clear()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheCard(unittest.TestCase):

    def card(self, answer):
        """Open a host's drawer, answer the deep read with `answer`, and return the SNMP section's DOM."""
        page = _STACK["page"]
        page.route("**/api/devices/*/snmp/deep", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(answer)))
        try:
            dev = page.evaluate("async () => { const d = await api('GET', '/devices'); return d[0]; }")
            page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [dev["id"], dev["name"]])
            page.wait_for_selector("#audit-sec-snmp", state="attached", timeout=30000)
            page.evaluate("() => { _drawerAuditLoaded.snmp = true; _loadAuditSection('snmp'); }")
            # The OID browser's preset list also says "Storage", so wait for the HEADING.
            page.wait_for_function(
                "() => Array.from(document.querySelectorAll('#audit-body-snmp h4'))"
                ".some(h => h.textContent.trim() === 'Storage')", timeout=30000)
            return page.evaluate("""() => {
                const body = document.getElementById('audit-body-snmp');
                const heads = Array.from(body.querySelectorAll('h4')).map(h => h.textContent.trim());
                const pills = Array.from(body.querySelectorAll('.sysinfo-pill')).map(p => ({
                    label: (p.querySelector('.label') || {}).textContent,
                    value: (p.querySelector('.value') || {}).textContent,
                    color: (p.querySelector('.value') || {}).getAttribute ? p.querySelector('.value').getAttribute('data-color') : null}));
                const real = Array.from(body.querySelectorAll('div.fs-13')).find(d => /Real memory/.test(d.textContent));
                return {heads, pills, text: body.textContent,
                        real: real ? {text: real.textContent, color: (real.querySelector('span[data-color]') || {getAttribute: () => null}).getAttribute('data-color')} : null};
            }""")
        finally:
            page.evaluate("() => closeDeviceDrawer()")
            page.unroute("**/api/devices/*/snmp/deep")

    def test_the_reporters_firewall(self):
        card = self.card(deep_answer([
            row(1, "Physical memory", 7918, 7454), row(2, "Cached memory", 3919, 3919),
            row(3, "Memory buffers", 802, 502), row(4, "Swap space", 8192, 0), row(5, "/", 220000, 41000)]))
        self.assertIn("Memory", card["heads"])
        pills = {p["label"]: p for p in card["pills"] if p["label"] in ("In use", "Cache and buffers", "Total")}
        self.assertEqual(pills["In use"]["value"], "38.3%")
        self.assertEqual(pills["Cache and buffers"]["value"], "4,421 MB")
        self.assertEqual(pills["Total"]["value"], "7,918 MB")
        self.assertEqual(pills["In use"]["color"], "inherit", "38% is not a warning colour")
        self.assertIn("reports 94.1%", card["text"])
        self.assertIn("alerts on the share without them", card["text"])
        self.assertTrue(card["real"], "the device's own UCD line should still be there")
        self.assertIn("94.1%", card["real"]["text"])
        self.assertIn("includes cache and buffers", card["real"]["text"])
        self.assertEqual(card["real"]["color"], "inherit", "the line that includes the cache must not be red")
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def test_a_host_short_of_memory_is_coloured_for_it(self):
        card = self.card(deep_answer([
            row(1, "Physical memory", 8000, 7900), row(2, "Cached memory", 400, 400),
            row(3, "Memory buffers", 100, 50)], ucd_total_mb=8000, ucd_free_mb=100))
        pills = {p["label"]: p for p in card["pills"]}
        self.assertEqual(pills["In use"]["value"], "93.1%")   # (7,900 - 400 - 50) of 8,000
        self.assertEqual(pills["In use"]["color"], "var(--red)")

    def test_a_host_with_no_cache_rows_is_drawn_as_it_was(self):
        card = self.card(deep_answer([row(1, "Physical memory", 7918, 7454), row(5, "/", 220000, 41000)]))
        self.assertNotIn("Memory", card["heads"])
        self.assertNotIn("includes cache and buffers", card["text"])
        self.assertTrue(card["real"])
        self.assertEqual(card["real"]["color"], "var(--red)", "no cache to take off: the old colouring stands")


if __name__ == "__main__":
    unittest.main()
