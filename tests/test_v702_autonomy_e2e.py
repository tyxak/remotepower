#!/usr/bin/env python3
"""The Autonomy page, measured in a browser against a SEEDED instance.

The gates that already exist stop one step short of this one. The page-smoke
sweep clicks every nav button and asserts the page activates without a JS error;
the click sweep derives its targets from the ~70 `data-action` names whose
handler calls `openModal()`, and neither of the controls added in v7.0.2 does.
So the page rendered, nothing threw, and nothing had looked at the receipts
table, the new column, the toolbar or the delete path.

That gap is the shape CLAUDE.md keeps recording: a source reading answers a
different question than a rendered one. A `<td>` count that disagrees with its
`<th>` count is invisible in the source of two files edited minutes apart, and
obvious the moment a row is laid out.

Named `*e2e*` on purpose: `make test-fast` skips those, so an eight-minute
browser boot is not added to every gate run by everyone forever.
"""
import os
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
from e2e_harness import browser_available, SKIP_REASON
try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

# What the seeder's default tenant allows, and the four classes that keep the
# backup precondition. Derived from the source at test time rather than listed,
# so the assertion cannot drift away from the catalog.
_AUTONOMY = _ROOT / 'server' / 'cgi-bin' / 'autonomy.py'


def _needs_backup():
    import importlib.util
    spec = importlib.util.spec_from_file_location('autonomy_e2e', _AUTONOMY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {k for k, v in mod.ACTION_CLASSES.items()
            if v.get('requires_backup', v['destructive'])}


_READ_TABLE = """() => {
  const head = document.querySelectorAll('#autonomy-receipts-head th').length;
  const rows = [...document.querySelectorAll('#autonomy-receipts-body tr')];
  return {
    head,
    rows: rows.length,
    cells: [...new Set(rows.map(r => r.children.length))],
    deletes: document.querySelectorAll(
      '#autonomy-receipts-body [data-action="deleteAutonomyReceipt"]').length,
    firstId: (document.querySelector(
      '#autonomy-receipts-body [data-action="deleteAutonomyReceipt"]') || {}).dataset
      ? document.querySelector(
          '#autonomy-receipts-body [data-action="deleteAutonomyReceipt"]').dataset.arg
      : null,
  };
}"""

_READ_ENVELOPE = """() => {
  const btn = sel => {
    const b = document.querySelector(sel);
    if (!b) return null;
    const r = b.getBoundingClientRect();
    return {text: b.textContent.trim(), w: r.width, h: r.height,
            svg: !!b.querySelector('svg')};
  };
  const acts = [...document.querySelectorAll('#autonomy-actions .autonomy-act-row')]
    .map(r => ({
      name: (r.querySelector('code') || {}).textContent || '',
      pills: [...r.querySelectorAll('.chk-pill')].map(p => p.textContent.trim()),
    }));
  const cb = document.getElementById('autonomy-require-precedent');
  const groups = [...document.querySelectorAll('#autonomy-actions .autonomy-act-group')]
    .map(g => (g.textContent || '').trim());
  return {
    groups,
    clear: btn('[data-action="clearAutonomyReceipts"]'),
    refresh: btn('#page-autonomy [data-action="loadAutonomy"]'),
    precedent: cb ? {present: true, checked: cb.checked} : {present: false},
    actions: acts,
  };
}"""


@unittest.skipUnless(browser_available(), SKIP_REASON)
class TestTheAutonomyPageRenders(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.dir = tempfile.mkdtemp(prefix='rp-autoe2e-')
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

    def setUp(self):
        self.ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        self.page = self.ctx.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.goto(self.base + '/index.html')
        # alice is the seeder's admin. The receipts DELETE is admin-only, so a
        # viewer would 403 and every assertion below would be measuring the
        # refusal rather than the feature.
        self.page.fill('#login-user', 'alice')
        self.page.fill('#login-pass', 'demo')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=90000)
        self.page.wait_for_timeout(6000)
        self.page.evaluate("() => { try { showPage('autonomy') } catch (e) {} }")
        self._settle()

    def _settle(self):
        """Wait for the page's own content, not for a clock.

        `loadAutonomy` awaits two fetches and paints between them, so a fixed
        sleep is a race against whatever else is contending for the box — this
        file first failed only when run alongside two other browser suites, with
        an empty allow-list, which reads as a rendering bug rather than a slow
        one. Waiting on the last thing painted removes the class rather than
        widening the sleep.
        """
        self.page.wait_for_selector('#autonomy-actions .autonomy-act-row',
                                    timeout=30000)
        self.page.wait_for_selector('#autonomy-receipts-body tr', timeout=30000)

    def tearDown(self):
        self.page.close(); self.ctx.close()

    def test_the_seeded_receipts_actually_render(self):
        """Control for everything below: an empty table would satisfy a column
        check and a pill check while measuring nothing."""
        t = self.page.evaluate(_READ_TABLE)
        self.assertGreaterEqual(t['rows'], 5, t)
        self.assertEqual(self.errors, [], 'uncaught JS errors on the page')

    def test_every_row_has_as_many_cells_as_the_header_has_columns(self):
        """The column was added to the header in index.html and to the rows in
        app-autonomy.js — two files, one edit each, and a mismatch renders as a
        table that quietly shears."""
        t = self.page.evaluate(_READ_TABLE)
        self.assertEqual(t['cells'], [t['head']],
                         f"header has {t['head']} columns, rows have {t['cells']}")

    def test_every_seeded_receipt_offers_a_delete(self):
        """Rows written before receipts carried ids get no button rather than a
        broken one — so the seeder giving every row an id is what makes this
        assertion meaningful rather than vacuous."""
        t = self.page.evaluate(_READ_TABLE)
        self.assertEqual(t['deletes'], t['rows'], t)

    def test_the_toolbar_buttons_render_with_their_icons(self):
        e = self.page.evaluate(_READ_ENVELOPE)
        for name in ('clear', 'refresh'):
            b = e[name]
            self.assertIsNotNone(b, f'{name} button is not in the DOM')
            self.assertGreater(b['w'], 40, f'{name}: {b}')
            self.assertGreater(b['h'], 16, f'{name}: {b}')
            self.assertTrue(b['svg'], f'{name} has no icon')
        self.assertIn('Clear', e['clear']['text'])

    def test_the_precedent_checkbox_reflects_the_stored_policy(self):
        """The seeder stores require_precedent: True. A checkbox that renders
        unchecked would be the save-whitelist class one layer up — the UI and
        the store disagreeing about a safety setting."""
        e = self.page.evaluate(_READ_ENVELOPE)
        self.assertTrue(e['precedent']['present'], 'the checkbox is not rendered')
        self.assertTrue(e['precedent']['checked'],
                        'the seeded policy requires precedent; the page says it does not')

    def test_the_allow_list_is_grouped(self):
        """Twenty-six machine names in one flat column is a wall — the whole
        reason the list was regrouped. An empty heading list means the page
        fell back to rendering one."""
        e = self.page.evaluate(_READ_ENVELOPE)
        self.assertGreaterEqual(len(e['groups']), 4, e['groups'])
        self.assertTrue(any('Destructive' in g for g in e['groups']), e['groups'])

    def test_the_filter_narrows_the_list_and_folds_empty_groups(self):
        self.page.fill('#autonomy-act-filter', 'container')
        self.page.wait_for_timeout(400)
        vis = self.page.evaluate(
            "() => ({rows: [...document.querySelectorAll("
            "'#autonomy-actions .autonomy-act-row')].filter("
            "r => !r.classList.contains('row-hidden')).length,"
            " groups: [...document.querySelectorAll("
            "'#autonomy-actions .autonomy-act-group')].filter("
            "g => !g.classList.contains('row-hidden')).length})")
        self.assertGreater(vis['rows'], 0, 'the filter hid everything')
        self.assertLess(vis['rows'], 10, vis)
        self.assertLessEqual(vis['groups'], 3,
                             'a heading stayed behind labelling nothing')
        self.page.fill('#autonomy-act-filter', '')
        self.page.wait_for_timeout(400)
        after = self.page.evaluate(_READ_ENVELOPE)
        self.assertGreaterEqual(len(after['actions']), 25, 'clearing did not restore')

    def test_the_allow_list_marks_exactly_the_actions_that_need_a_backup(self):
        e = self.page.evaluate(_READ_ENVELOPE)
        self.assertGreaterEqual(len(e['actions']), 25, 'the allow-list did not render')
        shown = {a['name'] for a in e['actions']
                 if any('needs backup' in p for p in a['pills'])}
        self.assertEqual(shown, _needs_backup(),
                         'the page and the catalog disagree about which actions '
                         'a proven-recoverable backup applies to')

    def test_deleting_a_row_reaches_the_server(self):
        """The whole path: a click, the DELETE, the re-render — and then a
        reload, because a row vanishing from the DOM proves only that the
        renderer ran."""
        before = self.page.evaluate(_READ_TABLE)
        victim = before['firstId']
        self.assertTrue(victim, 'no receipt id to delete')
        self.page.click(f'[data-action="deleteAutonomyReceipt"][data-arg="{victim}"]')
        self.page.wait_for_timeout(2500)
        after = self.page.evaluate(_READ_TABLE)
        self.assertEqual(after['rows'], before['rows'] - 1, (before, after))
        self.page.reload()
        self.page.wait_for_selector('#app', state='visible', timeout=90000)
        self.page.evaluate("() => { try { showPage('autonomy') } catch (e) {} }")
        self._settle()
        reloaded = self.page.evaluate(_READ_TABLE)
        self.assertEqual(reloaded['rows'], before['rows'] - 1,
                         'the row came back on reload — the DELETE never landed')
        self.assertNotIn(victim, self.page.content())
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
