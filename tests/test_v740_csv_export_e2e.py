#!/usr/bin/env python3
"""7.4.0: a sortable table with rows offers a CSV export, whatever its size and however it is drawn.

The export button lived in the pager, which a table gets past 15 rows, and only for tables drawn by
tableCtl.render. On the seeded instance 13 of 78 sortable tables with rows had no way to export (the
custom-rendered ones, and every table of 15 rows or fewer on a page that drew its own rows). They get a
bar of their own now.

Walks every sidebar page of the seeded instance, finds each visible table whose header has sortable
columns and at least one real row, and checks that a CSV export button follows it. Three tables are
listed in MISSING with the reason; a listed table that starts to pass fails the test, so the list only
shrinks. One export is clicked and the downloaded file read, so a button that does nothing is caught.
"""
import csv
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

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

# thead id -> why it has no export. The table is built after the sort call, so the call finds no header.
MISSING = {
    'alerts-thead': 'the grouped view sorts nothing through tableCtl; only the flat view does',
    'discovery-thead': 'the table is drawn after wireSortOnly/sortRows ran, so there was no header to find it by',
    'cs-results-thead': 'same: the table is drawn after the sort call',
}

_TABLES = """() => {
  const out = [];
  document.querySelectorAll('#app .page.active table').forEach(t => {
    const th = t.querySelector('thead');
    if (!th || !th.querySelector('th[data-col]') || t.offsetParent === null) return;
    const rows = [...t.tBodies].flatMap(b => [...b.rows]).filter(
      r => !r.querySelector('.empty-state, .empty-state-sm, .error-state, .skeleton') && r.cells.length > 1);
    const card = t.closest('.table-card') || t;
    const nxt = card.nextElementSibling;
    out.push({thead: th.id, rows: rows.length,
              has: !!(nxt && nxt.querySelector && nxt.querySelector('[data-action="tblExportCsv"]'))});
  });
  return out;
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestEverySortableTableExports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic, measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-csv-')
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

    def test_every_sortable_table_with_rows_has_an_export_and_one_works(self):
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block',
                                       accept_downloads=True)
        page = ctx.new_page()
        seen = withrows = 0
        missing = {}
        downloaded = None
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in self._pages():
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(2200)
                for t in page.evaluate(_TABLES):
                    seen += 1
                    if not t['rows']:
                        continue
                    withrows += 1
                    if not t['has']:
                        missing[t['thead']] = name
                if downloaded is None and name == 'catalog':
                    btn = page.query_selector('#app .page.active [data-action="tblExportCsv"]')
                    if btn:
                        with page.expect_download(timeout=15000) as dl:
                            btn.evaluate('b => b.click()')   # the first-run tour covers the page
                        path = dl.value.path()
                        downloaded = list(csv.reader(open(path, newline='')))
        finally:
            page.close(); ctx.close()
        self.assertGreater(withrows, 60, 'the walk found only %d sortable tables with rows (%d seen)' % (withrows, seen))
        unlisted = sorted(set(missing) - set(MISSING))
        self.assertEqual(unlisted, [], 'sortable tables with rows and no CSV export: %s'
                         % {k: missing[k] for k in unlisted})
        fixed = sorted(set(MISSING) - set(missing))
        self.assertEqual(fixed, [], 'these tables export now, delete them from MISSING: %s' % fixed)
        self.assertIsNotNone(downloaded, 'the Catalog page offered no export to click')
        self.assertGreater(len(downloaded), 1, 'the exported file holds no rows')
        self.assertGreater(len(downloaded[0]), 1, 'the exported file has no header row')


if __name__ == '__main__':
    unittest.main()
