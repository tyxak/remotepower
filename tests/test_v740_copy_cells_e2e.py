#!/usr/bin/env python3
"""7.4.0: an address or an id in a table cell copies on click.

Renderers write their own rows, so a copy affordance added one by one is missing wherever nobody
added it: on the seeded instance 214 address cells and 18 id cells on 11 pages had none. A watcher
now marks a cell whose whole text is an IP address, a CIDR, a MAC address, a UUID, a long hex id or a
CVE id. Walks every page and checks that no such cell is left unmarked, that plenty were marked
(the control: a walk that finds nothing proves nothing), and that a click puts the text on the
clipboard.
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

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

# Cells the watcher leaves alone on purpose: wildcard and loopback addresses nobody copies.
_NEVER = ('0.0.0.0', '::', '127.0.0.1', '::1')

_SCAN = r"""(never) => {
  const IP = /^(?:\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/\d{1,3})?)$/i;
  const ID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,64}|CVE-\d{4}-\d{4,7}|[0-9a-f]{2}(?::[0-9a-f]{2}){5,31})$/i;
  const out = {missing: [], marked: 0};
  document.querySelectorAll('#app .page.active td').forEach(td => {
    if (td.offsetParent === null) return;
    const t = (td.textContent || '').trim();
    if (!t || t.length > 80 || never.includes(t) || !(IP.test(t) || ID.test(t))) return;
    if (td.hasAttribute('data-copy')) { out.marked++; return; }
    if (td.closest('[data-copy], [data-action], tr[tabindex]') ||
        td.querySelector('a, button, input, select, textarea, [data-action], [data-copy]')) return;
    out.missing.push(t);
  });
  return out;
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAddressCellsCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic, measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-copy-')
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

    def test_every_address_and_id_cell_copies_and_a_click_copies_it(self):
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        page = ctx.new_page()
        marked, missing, copied = 0, {}, None
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            page.evaluate("() => { window.__copied = null; Object.defineProperty(navigator, 'clipboard', "
                          "{value: {writeText: t => { window.__copied = t; return Promise.resolve(); }}, "
                          "configurable: true}); }")
            for name in self._pages():
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(2000)
                r = page.evaluate(_SCAN, list(_NEVER))
                marked += r['marked']
                if r['missing']:
                    missing[name] = r['missing'][:3]
                if copied is None and name == 'devices':
                    cell = page.query_selector('#app .page.active td[data-copy]')
                    if cell:
                        want = cell.inner_text().strip()
                        cell.evaluate('c => c.click()')
                        page.wait_for_timeout(200)
                        copied = (want, page.evaluate('() => window.__copied'))
        finally:
            page.close(); ctx.close()
        self.assertGreater(marked, 60, 'the walk marked only %d cells: the scan may be looking at nothing' % marked)
        self.assertEqual(missing, {}, 'address or id cells with no click-to-copy: %s' % missing)
        self.assertIsNotNone(copied, 'the Hosts page had no marked cell to click')
        self.assertEqual(copied[0], copied[1], 'a click did not put the cell text on the clipboard')


if __name__ == '__main__':
    unittest.main()
