#!/usr/bin/env python3
"""One toolbar row, one control height — measured in the browser.

styles.css normalises every control in a toolbar/inline row to 34px, and it
does it with a DIRECT-CHILD selector. `app.js`'s `_wrapSelects()` then inserts
a `<span class="rp-ddwrap">` between every `<select>` and its parent at
runtime, so the select becomes a GRANDCHILD and the `>` stops matching it. On
the seeded instance 102 of 110 visible selects are wrapped, which meant the
`select.form-input` and `select.select-sm` clauses in that allowlist could
never fire — the select fell back to `.input-auto` / `.select-sm` and rendered
35-36px (and 31px under `.isl-16`) beside buttons and inputs pinned at 34px.
25 rows across 20 pages, each one visibly out of line.

Reading the CSS finds none of this: every rule involved is correct, and the
element the rule targets is not where the source says it is. Only the rendered
DOM knows what `_wrapSelects` did to the tree.

Cost: the walk is derived from the markup — only pages whose `#page-<name>`
block contains a `<select>` — so it visits ~half the app rather than all 81
pages. The derivation is asserted non-empty below, because a broken
derivation would make this pass while measuring nothing.
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

import browser_required

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

# The row containers styles.css pins to a single control height. Kept in step
# with the `:is(...)` list in the control-height rule; the source check below
# fails if that list loses the wrapper-piercing arm.
_ROW_CONTAINERS = [
    'toolbar', 'toolbar-mb24', 'isl-173', 'isl-186', 'isl-178', 'row-8-center',
    'row-6-center', 'row-8', 'batch-bar', 'home-ai-ask', 'sb-controls',
    'section-header', 'form-row-wrap', 'settings-row', 'modal-actions',
]

# A control may sit 1px off its neighbour through border rounding; 2px is the
# step the wrapped-select bug produced and is what a reader sees.
_TOLERANCE_PX = 1.5

_MEASURE = """(containers) => {
  const out = [];
  const page = document.querySelector('#app .page.active');
  if (!page) return out;
  page.querySelectorAll('*').forEach(par => {
    const cls = (par.className || '').toString().split(/\\s+/);
    if (!cls.some(c => containers.includes(c))) return;
    // A select is one level deeper than its markup says: _wrapSelects() puts
    // an .rp-ddwrap span around it. Reach through the wrapper, or every
    // wrapped select is invisible to this measurement.
    const items = [];
    [...par.children].forEach(k => {
      if (k.classList && k.classList.contains('rp-ddwrap')) {
        const s = k.querySelector(':scope > select');
        if (s) items.push(s);
        return;
      }
      if (['BUTTON', 'INPUT', 'SELECT'].includes(k.tagName)) items.push(k);
    });
    const vis = items.filter(e => {
      const r = e.getBoundingClientRect();
      return r.height > 3 && r.width > 3;
    });
    if (vis.length < 2) return;
    // Group by top edge: a row that WRAPPED is a second row, not a mismatch.
    const byRow = new Map();
    vis.forEach(e => {
      const r = e.getBoundingClientRect();
      const key = Math.round(r.top / 4);
      if (!byRow.has(key)) byRow.set(key, []);
      byRow.get(key).push({
        h: Math.round(r.height * 10) / 10,
        what: (e.id || e.tagName.toLowerCase() + '.' +
               (e.className || '').toString().split(/\\s+/)[0]),
      });
    });
    byRow.forEach(row => {
      if (row.length < 2) return;
      const hs = row.map(x => x.h);
      out.push({
        par: (par.className || par.tagName).toString().slice(0, 30),
        spread: Math.round((Math.max(...hs) - Math.min(...hs)) * 10) / 10,
        row: row.map(x => `${x.what}=${x.h}px`),
      });
    });
  });
  return out;
}"""

_WRAP_RATIO = """() => {
  const sels = [...document.querySelectorAll('select')]
    .filter(s => s.getBoundingClientRect().height > 3);
  return {
    visible: sels.length,
    wrapped: sels.filter(s => s.parentElement &&
                              s.parentElement.classList.contains('rp-ddwrap')).length,
  };
}"""


def _pages_with_a_select():
    """Pages whose markup actually holds a <select> — derived, not listed.

    A hand-kept page list goes stale silently; this cannot. It is asserted
    non-empty by the caller, because an empty walk would report success.
    """
    html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
    order = []
    for m in re.finditer(r'class="nav-btn[^"]*"[^>]*?\sdata-page="([a-z-]+)"', html):
        if m.group(1) not in order:
            order.append(m.group(1))
    blocks = {}
    for m in re.finditer(r'<div id="page-([a-z-]+)"', html):
        start = m.end()
        nxt = html.find('<div id="page-', start)
        blocks[m.group(1)] = html[start:nxt if nxt > 0 else len(html)]
    return [p for p in order if '<select' in blocks.get(p, '')]


class TestOneControlHeightPerRow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic — measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.dir = tempfile.mkdtemp(prefix='rp-ctlh-')
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
            cls._pw.stop(); browser_required.skip_or_fail(f'chromium: {exc}')
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

    def test_controls_in_one_row_render_at_one_height(self):
        pages = _pages_with_a_select()
        self.assertGreater(
            len(pages), 15,
            f'derived only {len(pages)} pages with a <select> — the derivation '
            f'broke, so an empty finding list proves nothing')

        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        rows_seen, bad, ratio = 0, [], None
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            # The seeded SPA needs a long first paint, then a settle: several
            # renderers finish after #app becomes visible.
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(600)
                for r in page.evaluate(_MEASURE, _ROW_CONTAINERS):
                    rows_seen += 1
                    if r['spread'] > _TOLERANCE_PX:
                        bad.append(f"{name} .{r['par']}: " + '  '.join(r['row']))
                if ratio is None:
                    ratio = page.evaluate(_WRAP_RATIO)
        finally:
            page.close(); ctx.close()

        # Positive control: the bug only exists because selects ARE wrapped. If
        # nothing is wrapped here, this measurement is not testing what it says.
        self.assertIsNotNone(ratio)
        self.assertGreater(ratio['wrapped'], 0,
                           'no <select> is inside an .rp-ddwrap — either '
                           '_wrapSelects stopped running or the walk never '
                           'reached a page with a select')
        self.assertGreater(
            rows_seen, 40,
            f'only {rows_seen} multi-control rows measured — the walk did not '
            f'run, so an empty finding list means nothing')
        self.assertEqual(
            sorted(set(bad)), [],
            'controls sitting side by side in one row render at different '
            'heights:\n' + '\n'.join('  ' + b for b in sorted(set(bad))[:14]))


if __name__ == '__main__':
    unittest.main()
