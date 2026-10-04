"""A hidden sidebar entry leaves no empty row.

Every nav button is wrapped in a `.nav-item` that also holds the favorites star.
`_applyModuleNavGates` hides the button with `d-none`, and the wrapper stayed
behind at 22px, so a module that is switched off (SSH gateway, billing, KB) left
a blank row in its group. Measured on the seeded stack with the real gate.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tests'))
from e2e_harness import browser_available, SKIP_REASON  # noqa: E402
import browser_required  # noqa: E402

# RP_BROWSER_REQUIRE has to be folded into the CLASS condition: a class-level
# skipUnless never reaches setUpClass, so skip_or_fail alone cannot see a
# missing browser.
_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestHiddenNavEntryLeavesNoRow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-navgap-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed')
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def test_switching_modules_off_removes_their_rows(self):
        page = self.browser.new_page(viewport={'width': 1440, 'height': 900})
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice'); page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            page.click('.sidebar-group[data-group="access"] .sidebar-group-toggle')
            page.wait_for_timeout(600)
            before = page.evaluate("""() => [...document.querySelectorAll('.nav-item')]
              .filter(w => w.querySelector('.nav-btn[data-page="sshgw"]'))
              .map(w => Math.round(w.getBoundingClientRect().height))""")
            self.assertTrue(before and before[0] > 0, 'control: the SSH gateway row is visible while its module is on: %r' % before)
            page.evaluate("() => _applyModuleNavGates({sshgw: false, billing: false, kb: false})")
            gaps = page.evaluate("""() => [...document.querySelectorAll('.nav-item')]
              .filter(w => w.querySelector('.nav-btn.d-none'))
              .map(w => [w.querySelector('.nav-btn').dataset.page, Math.round(w.getBoundingClientRect().height)])
              .filter(x => x[1] > 0)""")
            hidden = page.evaluate("() => document.querySelectorAll('.nav-item .nav-btn.d-none').length")
            self.assertGreater(hidden, 0, 'nothing was hidden, so this measured nothing')
            self.assertEqual([], gaps, 'hidden entries still take up a row (page, px): %r' % gaps)
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
