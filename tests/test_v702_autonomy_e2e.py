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

# Folded so RP_BROWSER_REQUIRE is reachable. Guarding the class on
# browser_available() alone removes it before setUpClass runs, so skip_or_fail
# never gets asked and the flag turns a missing browser into nothing at all.
_GATE = browser_available() or browser_required.required()

if browser_available():
    from playwright.sync_api import sync_playwright
else:
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


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheAutonomyPageRenders(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not browser_available():
            browser_required.skip_or_fail(SKIP_REASON)
        # v7.0.2: the same guard its sibling seeded-stack suites carry
        # (test_v643_box_overflow_rendered, test_v643_icon_label_gap), and this
        # file was written without it. The demo seeder writes JSON files; under
        # RP_STORAGE_BACKEND=sqlite the stack looks for a users table that was
        # never migrated, so alice/demo cannot log in and all thirteen tests
        # ERROR on a 90-second `#app` timeout. What they measure — the rendered
        # page — is the same whichever backend served it.
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest(
                'the rendered page is backend-agnostic — measured once under '
                'the default backend')
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
        # Auto-hide OFF for this file. It is a per-browser preference that
        # defaults ON, and it turns the sidebar into a 56px rail that expands to
        # 248px as an OVERLAY — which covers the first 248px of content,
        # including the envelope card's controls at x≈99. Playwright then
        # refuses to click them: the hit test lands on `<span>Confirmations</span>`
        # inside the nav.
        #
        # The reveal is a CSS `:hover` on the rail itself, so a real cursor
        # arriving at x≈154 does not trigger it — this is the automation's
        # pointer sequence, not something an operator hits. Auto-hide has its own
        # e2e file; here it is a variable this test is not about.
        self.ctx.add_init_script(
            "try { localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
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

    def test_the_allow_list_fills_the_card(self):
        """It rendered at 392px inside a 1096px row — about a third of the card.

        #autonomy-actions is a block container wrapped in a .settings-row, which
        is display:flex, so with no flex property it took the default `0 1 auto`
        and sized to its content. The row grid then had roughly 110px left for
        the description column, and every row wrapped into a paragraph: the list
        read as a wall of text with the names and the prose run together.

        Measured, because the markup and every CSS rule involved are individually
        correct — this is only visible once something lays it out.
        """
        m = self.page.evaluate("""() => {
          const list = document.getElementById('autonomy-actions');
          const row  = list.querySelector('.autonomy-act-row');
          return {list: list.getBoundingClientRect().width,
                  parent: list.parentElement.getBoundingClientRect().width,
                  row: row ? row.getBoundingClientRect().width : 0};
        }""")
        self.assertGreater(m['parent'], 400, 'the card itself did not lay out')
        self.assertGreaterEqual(
            m['list'], m['parent'] - 1,
            f"the list fills {m['list']:.0f} of {m['parent']:.0f}px "
            f"({m['list'] / m['parent']:.0%} of its row)")
        self.assertGreaterEqual(m['row'], m['parent'] - 1,
                                'the rows do not fill the list')

    def test_the_filter_responds_to_real_keystrokes(self):
        """The sibling test uses page.fill(), which sets .value and dispatches
        one input event. A person types, and the dispatch that carries this is
        `window[el.dataset.input]` — undefined resolves to a silent return, so
        "the filter does nothing" is what a missing or unloaded handler looks
        like. Type it properly, and check the count label the operator reads.
        """
        self.page.click('#autonomy-act-filter')
        self.page.type('#autonomy-act-filter', 'container', delay=30)
        self.page.wait_for_timeout(600)
        out = self.page.evaluate("""() => {
          const rows = [...document.querySelectorAll(
            '#autonomy-actions .autonomy-act-row')];
          return {total: rows.length,
                  visible: rows.filter(r => !r.classList.contains('row-hidden')).length,
                  label: (document.getElementById('autonomy-act-filter-count')
                          || {}).textContent || ''};
        }""")
        self.assertGreater(out['total'], 20, 'the list did not render')
        self.assertGreater(out['visible'], 0, 'the filter hid everything')
        self.assertLess(out['visible'], out['total'], 'the filter hid nothing')
        self.assertEqual(out['label'], f"{out['visible']} of {out['total']}",
                         'the count beside the box disagrees with the rows')
        self.assertEqual(self.errors, [], f'page errors: {self.errors}')

    def test_the_allow_list_marks_exactly_the_actions_that_need_a_backup(self):
        e = self.page.evaluate(_READ_ENVELOPE)
        self.assertGreaterEqual(len(e['actions']), 25, 'the allow-list did not render')
        shown = {a['name'] for a in e['actions']
                 if any('needs backup' in p for p in a['pills'])}
        self.assertEqual(shown, _needs_backup(),
                         'the page and the catalog disagree about which actions '
                         'a proven-recoverable backup applies to')

    def test_saving_the_envelope_reaches_the_server(self):
        """The button moved out of the Mode row — where it read as "save the
        mode" — to the foot of the card, below the last field it saves. Nothing
        had ever driven it, so a move that left it wired to nothing would have
        looked exactly like this test not existing.

        Toggled and toggled back, so the instance is left as it was found and
        both directions are measured.
        """
        sel = '#autonomy-actions input.autonomy-act[data-act="trim_filesystem"]'
        before = self.page.eval_on_selector(sel, 'el => el.checked')

        self._set_action(sel, not before)
        self._save_and_reload()
        self.assertEqual(self.page.eval_on_selector(sel, 'el => el.checked'),
                         not before,
                         'the allow-list change did not survive a reload — the '
                         'button saved nothing')

        self._set_action(sel, before)          # leave it as it was found
        self._save_and_reload()
        self.assertEqual(self.page.eval_on_selector(sel, 'el => el.checked'), before)
        self.assertEqual(self.errors, [])

    def _park_cursor(self):
        """Get the pointer away from the left edge before clicking anything.

        The seeded instance runs the sidebar in auto-hide, so it is a 56px rail
        that expands to 248px on hover. The envelope card's controls sit at
        x≈99 — 43px clear of the rail collapsed, well under it expanded — so a
        click left over from the previous action keeps the sidebar open and it
        swallows the next one. Measured, not guessed: the failure log named
        `<span>Confirmations</span> from <nav class="sidebar">` as the element
        that intercepted the click.
        """
        self.page.mouse.move(1200, 400)
        self.page.wait_for_timeout(350)     # longer than the reveal transition

    def _set_action(self, sel, want):
        """Tick or untick one allow-list row.

        Scrolled into view first, and only then handed to Playwright's
        actionability check. The card is at the FOOT of a long page now, inside
        a 340px scroll cap, so the row sits well over a thousand pixels below
        the fold.
        """
        self._park_cursor()
        self.page.eval_on_selector(sel, "el => el.scrollIntoView({block: 'center'})")
        self.page.wait_for_timeout(300)
        if want:
            self.page.check(sel, timeout=15000)
        else:
            self.page.uncheck(sel, timeout=15000)

    def _save_and_reload(self):
        """Save, then come back from a fresh load — a checkbox that stays ticked
        in the DOM proves only that the click landed."""
        self._park_cursor()
        self.page.eval_on_selector('[data-action="saveAutonomyPolicy"]',
                                   "el => el.scrollIntoView({block: 'center'})")
        self.page.click('[data-action="saveAutonomyPolicy"]', timeout=15000)
        self.page.wait_for_timeout(1500)
        self.page.reload()
        self.page.wait_for_selector('#app', state='visible', timeout=90000)
        self.page.evaluate("() => { try { showPage('autonomy') } catch (e) {} }")
        self._settle()

    def test_the_save_button_sits_below_the_fields_it_saves(self):
        """It was in the Mode row, above four thresholds, five checkboxes and a
        26-row allow-list that it also saves."""
        pos = self.page.evaluate(
            "() => {const b = document.querySelector("
            "'[data-action=\"saveAutonomyPolicy\"]');"
            " const a = document.getElementById('autonomy-actions');"
            " const m = document.getElementById('autonomy-mode');"
            " return {btn: b.getBoundingClientRect().top,"
            "         acts: a.getBoundingClientRect().top,"
            "         mode: m.getBoundingClientRect().top};}")
        self.assertGreater(pos['btn'], pos['acts'], pos)
        self.assertGreater(pos['btn'], pos['mode'], pos)

    def test_deleting_a_row_reaches_the_server(self):
        """The whole path: a click, the DELETE, the re-render — and then a
        reload, because a row vanishing from the DOM proves only that the
        renderer ran."""
        before = self.page.evaluate(_READ_TABLE)
        victim = before['firstId']
        self.assertTrue(victim, 'no receipt id to delete')
        self._park_cursor()
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
