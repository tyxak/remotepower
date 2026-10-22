#!/usr/bin/env python3
"""7.4.0: a printed page shows everything the screen shows, and nothing runs off the sheet.

The screen caps every variable-row panel at about 15 lines and scrolls it. On paper that cap
is a loss: rows past it are simply not printed. The print stylesheet lifts the caps, and this
measures that it did, on the SEEDED instance (an empty install renders every table's empty
state, which hides the whole class).

For each sidebar page the test switches to print media, then looks for two things:

  * a box that still clips its content (scrollHeight past clientHeight with overflow hidden,
    auto or scroll), which is a row that would not be printed;
  * a box that reaches past the right edge of the sheet, which is a column that would not be
    printed.

The control: the same walk in SCREEN media must find clipped boxes, or the measurement is
looking at nothing.
"""
import json
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

# A4 at 96 dpi, less the default margins.
_SHEET_W = 718

# Boxes that clip on purpose, in print as on screen. Each needs a reason.
EXEMPT = {
    'ellipsis': 'a single-line label cut with text-overflow: ellipsis keeps its full text in the title',
}

_MEASURE = """(sheet) => {
  const out = [], seen = new Set();
  const root = document.querySelector('#app .page.active');
  if (!root) return [{kind: 'no-page'}];
  root.querySelectorAll('*').forEach(el => {
    const st = getComputedStyle(el);
    if (st.display === 'none' || st.visibility === 'hidden') return;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return;
    let kind = '';
    const clips = ['hidden', 'auto', 'scroll'].includes(st.overflowY);
    if (clips && el.scrollHeight > el.clientHeight + 4 && el.clientHeight > 0
        && st.textOverflow !== 'ellipsis' && el.children.length >= 3) kind = 'clipped';
    else if (r.right > sheet + 4 && el.tagName !== 'HTML') kind = 'off-sheet';
    if (!kind) return;
    const key = kind + '|' + (el.id || '') + '|' + el.className;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({kind, id: el.id || '', cls: String(el.className).slice(0, 60), tag: el.tagName,
              h: el.scrollHeight, ch: el.clientHeight, right: Math.round(r.right)});
  });
  return out;
}"""


class TestPrintShowsEverything(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic, measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-print-')
        proc = subprocess.run(
            [sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
            capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close(); cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def _pages(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        seen, out = set(), []
        for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1)); out.append(m.group(1))
        return out

    def _walk(self, media):
        ctx = self.browser.new_context(viewport={'width': _SHEET_W if media == 'print' else 1440, 'height': 900})
        page = ctx.new_page()
        found, measured = {}, 0
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in self._pages():
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(1200)
                page.emulate_media(media=media)
                measured += 1
                bad = [b for b in page.evaluate(_MEASURE, _SHEET_W if media == 'print' else 10 ** 6)
                       if b.get('kind') != 'no-page' and b.get('id') not in EXEMPT]
                page.emulate_media(media='screen')
                if bad:
                    found[name] = bad
        finally:
            page.close(); ctx.close()
        return measured, found

    def test_print_clips_nothing_and_fits_the_sheet(self):
        measured, found = self._walk('print')
        self.assertGreaterEqual(measured, 80, 'the walk visited fewer pages than exist')
        self.assertEqual(found, {}, 'These boxes still clip or run off the sheet in print media:\n'
                         + json.dumps(found, indent=2))

    def test_the_measurement_sees_the_screen_caps(self):
        """Control: with screen media the same measurement must find clipped panels."""
        measured, found = self._walk('screen')
        clipped = sum(1 for v in found.values() for b in v if b['kind'] == 'clipped')
        self.assertGreater(clipped, 0, 'the screen walk found no clipped panel on %d pages: the print '
                           'measurement is looking at nothing' % measured)


if __name__ == '__main__':
    unittest.main()
