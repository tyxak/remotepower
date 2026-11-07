#!/usr/bin/env python3
"""v7.5.0 (UI census, findings N1, N2 and G1): three things the interface got wrong that only a browser can see.

* **N1** At phone width the CMDB asset dialog's tab strip did not wrap, so three of its six tabs (Hardware, Contracts & contacts, SNMP)
  sat past the edge of the screen.
* **N2** At phone width the Monitor page's header buttons (Mail round-trip, Add target) ended 27 and 150 px past the edge: the 7.4.9
  rule that keeps the Hosts buttons on one line gave the row `flex: 0 0 auto`, so it could not shrink below its one-line width.
* **G1** The keyboard-focus ring used the accent itself, which in the four light themes was 1.9 to 2.1 times as light as the surface it
  sat on (WCAG 1.4.11 asks 3:1 for the outline of a control). It uses the ink variant of the accent, which every theme keeps at AA.

Measured on the seeded demo, in a real browser. Each has a control that fails when the walk measures nothing: the number of tabs and of
buttons found, and the number of themes visited with the light ones among them.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tests"))
import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except Exception:                                               # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
THEMES = re.findall(r"\{ id:'([a-z-]+)',\s+name:'[^']+',\s+type:'(dark|light)'", APP)

_RING = """() => {
  const el = document.querySelector('.btn-primary, .btn-secondary, .nav-btn') || document.body;
  el.focus({focusVisible: true});
  const cs = getComputedStyle(el);
  const rgb = c => (c.match(/[\\d.]+/g) || []).map(Number);
  let bg = [255, 255, 255];
  for (let n = el; n; n = n.parentElement) {
    const c = rgb(getComputedStyle(n).backgroundColor);
    if (c.length >= 3 && (c.length < 4 || c[3] > 0.5)) { bg = c.slice(0, 3); break; }
  }
  return {outline: rgb(cs.outlineColor).slice(0, 3), bg, style: cs.outlineStyle, width: cs.outlineWidth, theme: document.body.dataset.theme || (document.body.classList.contains('light') ? 'light' : 'dark')};
}"""


def _lum(rgb):
    def f(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2])


def _contrast(a, b):
    hi, lo = max(_lum(a), _lum(b)), min(_lum(a), _lum(b))
    return (hi + 0.05) / (lo + 0.05)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestThreeMediums(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail("playwright not installed")
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("layout is backend-agnostic: measured once")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.is_file():
            raise unittest.SkipTest("demo seeder not in this tree")
        cls.data_dir = tempfile.mkdtemp(prefix="rp-v750-ui-")
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", cls.data_dir, "--apply"],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f"chromium not available: {exc}")
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f"app stack not available: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def signed_in(self, width, height, theme="dark"):
        ctx = self.browser.new_context(viewport={"width": width, "height": height})
        ctx.add_init_script("try { localStorage.setItem('rp_theme', %r); localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}" % theme)
        page = ctx.new_page()
        page.goto(self.base + "/index.html")
        page.fill("#login-user", "alice")
        page.fill("#login-pass", "demo")
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector("#app", state="visible", timeout=90000)
        page.wait_for_timeout(6000)
        return ctx, page

    def test_n1_the_cmdb_asset_tabs_all_fit_at_phone_width(self):
        ctx, page = self.signed_in(390, 844)
        try:
            page.evaluate("() => openModal('cmdb-asset-modal')")
            page.wait_for_timeout(800)
            got = page.evaluate("""() => {
              const tl = document.querySelector('#cmdb-asset-modal [role=tablist]');
              const vw = innerWidth;
              const tabs = [...tl.children].map(b => { const r = b.getBoundingClientRect(); return {t: b.textContent.trim(), l: r.left, r: r.right, top: Math.round(r.top)}; });
              return {vw, tabs, wrap: getComputedStyle(tl).flexWrap};
            }""")
        finally:
            page.close()
            ctx.close()
        self.assertEqual(got["vw"], 390)
        self.assertGreaterEqual(len(got["tabs"]), 5, "control: the dialog's tab strip was found and has its tabs")
        out = [t["t"] for t in got["tabs"] if t["r"] > got["vw"] + 1 or t["l"] < -1]
        self.assertEqual(out, [], "tabs past the edge of the screen")
        self.assertEqual(got["wrap"], "wrap")
        self.assertGreater(len({t["top"] for t in got["tabs"]}), 1, "at 390 px the six tabs take more than one row")

    def test_n2_the_monitor_header_buttons_stay_on_screen_at_phone_width(self):
        ctx, page = self.signed_in(390, 844)
        try:
            page.evaluate("() => { try { showPage('monitor') } catch (e) {} }")
            page.wait_for_timeout(2500)
            got = page.evaluate("""() => {
              const vw = innerWidth;
              const sh = document.querySelector('#section-targets');
              const btns = [...sh.querySelectorAll('button')].map(b => ({t: b.textContent.trim().slice(0, 20), r: b.getBoundingClientRect().right}));
              return {vw, btns};
            }""")
        finally:
            page.close()
            ctx.close()
        names = [b["t"] for b in got["btns"]]
        self.assertTrue({"Add target", "Check now"} <= set(names), f"control: the header's buttons were found ({names})")
        self.assertEqual([b["t"] for b in got["btns"] if b["r"] > got["vw"] + 1], [], "buttons past the edge of the screen")

    def test_g1_the_focus_ring_has_3_to_1_contrast_in_every_theme(self):
        concrete = [(i, t) for i, t in THEMES]
        self.assertGreaterEqual(len(concrete), 15, "the theme list was not read")
        self.assertEqual(sum(1 for _, t in concrete if t == "light"), 5, "control: five light themes, the ones that failed")
        ctx, page = self.signed_in(1280, 800)
        weak = {}
        try:
            for theme_id, _ in concrete:
                page.evaluate("t => { localStorage.setItem('rp_theme', t); applyTheme(); }", theme_id)
                page.wait_for_timeout(150)
                r = page.evaluate(_RING)
                self.assertEqual((r["style"], r["width"]), ("solid", "2px"), (theme_id, r))
                ratio = _contrast(r["outline"], r["bg"])
                if ratio < 3.0:
                    weak[theme_id] = round(ratio, 2)
        finally:
            page.close()
            ctx.close()
        self.assertEqual(weak, {}, "themes whose focus ring is below 3:1 against its surface")


if __name__ == "__main__":
    unittest.main()
