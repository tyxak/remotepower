#!/usr/bin/env python3
"""One icon-to-label gap, measured in the browser, not asserted in CSS.

The product's icon+label spacing is 5px. It was 5px on 289 buttons and
something else on 24 of them, and no CSS reading finds that — because the CSS
is correct in every one of those rules. The deviations came from three places
that only exist once the page is laid out:

  * `.icon-btn`, a class set on the <svg> itself, still carried
    `margin-right: 4px` from before flex `gap` existed. Inside a button that
    now supplies its own gap the margin STACKS: measured 9px. A sibling cleanup
    had already removed `.btn-primary svg { margin-right: 5px }` for exactly
    this reason and missed this one.
  * two classes declared 6px where the rest of the product uses 5px.
  * `.alerts-group-toggle` was neither flex nor gapped, so its chevron sat at
    whatever the markup whitespace collapsed to (3.6px).
  * two buttons put the label on its own SOURCE LINE, so the collapsed
    indentation rendered on top of the gap (7.4 and 7.9px). Wrapping the label
    in a <span> makes it a real flex item, which is what the other 313 do.

A pixel is not worth a test on its own. Twenty-four buttons disagreeing with
the other 289, in a UI where controls sit side by side, is — that is the
difference you cannot name but can see.
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
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

STANDARD_GAP = 5.0
# Rendered gaps that are legitimately not the button standard.
EXEMPT_CLASSES = {
    'patch-badge': 'an inline count badge, not an icon+label control — its svg '
                   'is decorative and sits flush by design',
}

_MEASURE = """() => {
  const out = [];
  document.querySelectorAll('#app .page.active button').forEach(b => {
    const st = getComputedStyle(b);
    if (st.display === 'none' || b.offsetParent === null) return;
    const svg = b.querySelector(':scope > svg');
    if (!svg) return;
    const sr = svg.getBoundingClientRect();
    let gap = null;
    for (const n of b.childNodes) {
      if (n === svg) continue;
      let tr = null;
      if (n.nodeType === 3 && n.textContent.trim()) {
        const rg = document.createRange(); rg.selectNodeContents(n);
        tr = rg.getBoundingClientRect();
      } else if (n.nodeType === 1 && n.textContent.trim()) {
        tr = n.getBoundingClientRect();
      }
      if (tr && tr.width > 0) { gap = Math.round((tr.left - sr.right) * 10) / 10; break; }
    }
    if (gap === null) return;
    out.push({cls: b.className, gap, t: (b.textContent || '').trim().slice(0, 30)});
  });
  return out;
}"""


class TestOneIconLabelGap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            raise unittest.SkipTest('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic — measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.dir = tempfile.mkdtemp(prefix='rp-gap-')
        p = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.dir,
                            '--apply'], capture_output=True, cwd=str(_ROOT),
                           timeout=900)
        if p.returncode != 0:
            raise unittest.SkipTest('seeder failed')
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop(); raise unittest.SkipTest(f'chromium: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.dir)
        except Exception as exc:
            cls.browser.close(); cls._pw.stop()
            raise unittest.SkipTest(f'stack: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def test_every_icon_button_uses_the_standard_gap(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        pages, seen = [], set()
        for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1)); pages.append(m.group(1))
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        measured, bad = 0, {}
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(900)
                for it in page.evaluate(_MEASURE):
                    measured += 1
                    if any(c in it['cls'].split() for c in EXEMPT_CLASSES):
                        continue
                    if abs(it['gap'] - STANDARD_GAP) > 0.6:
                        bad.setdefault(f"{it['gap']}px", []).append(
                            f"{name} .{it['cls'][:36]} :: {it['t']}")
        finally:
            page.close(); ctx.close()

        self.assertGreater(measured, 200,
                           'measured almost no icon buttons — did the walk run?')
        self.assertEqual(bad, {}, 'icon-to-label gaps that are not 5px:\n' +
                         '\n'.join(f'  {g}: {v[:4]}' for g, v in bad.items()))

    def test_the_exemptions_state_a_reason(self):
        for cls, why in EXEMPT_CLASSES.items():
            with self.subTest(cls=cls):
                self.assertGreater(len(why), 25)


class TestTheMarginIsNotReintroduced(unittest.TestCase):
    """Cheap source-level companion — the browser walk is slow, and this is the
    specific regression that produced the 9px class."""

    def test_icon_btn_margin_is_nulled_inside_flex_buttons(self):
        css = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        self.assertRegex(
            css, r':is\([^)]*\.btn-primary[^)]*\)\s*>\s*\.icon-btn\s*\{[^}]*margin-right:\s*0',
            'the .icon-btn margin reset is gone — it stacks on the flex gap')


if __name__ == '__main__':
    unittest.main()
