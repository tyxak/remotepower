#!/usr/bin/env python3
"""Fixes to single sidebar pages that need a browser to prove: a layout measured, a message read, a card folded.

The class-wide questions (a word, a placeholder, a row of buttons) are in test_sidebar_pages_rendered_e2e.py. These are the
page-specific ones found by looking at every page of the seeded demo:

* Logs said "none match the current filter" with no filter set. The live tail asks for the last ten minutes, and the lines in the
  buffer were older, so it sent people to clear a filter that was not there.
* Documentation led with twelve paragraphs of release notes on every visit; it folds after the first visit to a version.
* Software Policy put each rule's remove button on a line under the rule (the class it used, `row-flex`, had no style).
* The Threat Intel attackers table gave the Evidence and Status columns about 100 px each, so a row ran to five lines.
* The Timesheet put an entry's Edit above its Delete.
* My Account reached from the user menu named itself "account" in the top bar.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
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

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None


class TestSidebarPageFixes(unittest.TestCase):
    page = None

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once, under the default backend')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        data_dir = tempfile.mkdtemp(prefix='rp-pagefix-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
            return
        try:
            cls._base, cls._shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls._browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls._ctx = cls._browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        cls._ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        cls.page = cls._ctx.new_page()
        cls.page.goto(cls._base + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(5000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._ctx.close()
            cls._browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _show(self, name, wait=1800):
        self.page.evaluate("n => showPage(n)", name)
        self.page.wait_for_timeout(wait)

    # ── Logs ────────────────────────────────────────────────────────────────
    def _logs_with_an_empty_tail(self, filtered):
        stats = {'total_lines': 24, 'devices_reporting': 4, 'alert_rules': 3}
        self.page.route('**/api/logs/tail*', lambda route: route.fulfill(
            status=200, content_type='application/json', body='{"lines": [], "newest_ts": 0, "stats": %s}' % __import__('json').dumps(stats)))
        try:
            self._show('logs', 1200)
            # the filters keep their value from one visit to the next: set them, whichever way the last test left them
            self.page.evaluate("""(filtered) => { const d = document.getElementById('logs-device-filter'), u = document.getElementById('logs-unit-filter');
                                          u.value = ''; d.value = filtered ? [...d.options].find(o => o.value).value : ''; startLogsTail(); }""", filtered)
            self.page.wait_for_timeout(800)
            return self.page.inner_text('#logs-viewer')
        finally:
            self.page.unroute('**/api/logs/tail*')

    def test_logs_with_no_filter_says_the_tail_shows_ten_minutes(self):
        text = self._logs_with_an_empty_tail(filtered=False)
        self.assertIn('24 lines in the buffer, but none from the last 10 minutes', text)
        self.assertNotIn('none match the current filter', text)

    def test_logs_with_a_filter_still_blames_the_filter(self):
        text = self._logs_with_an_empty_tail(filtered=True)
        self.assertIn('none match the current filter', text)

    # ── Documentation ───────────────────────────────────────────────────────
    def test_whats_new_opens_once_per_version_and_folds_after(self):
        def first_card_open():
            return self.page.evaluate("document.querySelector('#page-docs details.doc-card').open")
        self._show('docs', 400)      # the page is built on its first visit
        version = self.page.evaluate("(/\\bv\\d+\\.\\d+\\.\\d+/.exec(document.querySelector('#page-docs details.doc-card').dataset.keywords) || [''])[0]")
        self.assertRegex(version, r'^v\d+\.\d+\.\d+$')
        self.page.evaluate("localStorage.removeItem('rp_whatsnew_seen')")
        self._show('docs', 400)
        self.assertTrue(first_card_open(), 'the first visit shows the release notes')
        self.assertEqual(self.page.evaluate("localStorage.getItem('rp_whatsnew_seen')"), version)
        self._show('home', 300)
        self._show('docs', 400)
        self.assertFalse(first_card_open(), 'the second visit folds them, so the quick reference is on the screen')
        self.page.evaluate("localStorage.setItem('rp_whatsnew_seen', 'v0.0.1')")
        self._show('home', 300)
        self._show('docs', 400)
        self.assertTrue(first_card_open(), 'a new version opens it again')

    # ── Software Policy ─────────────────────────────────────────────────────
    def test_a_policy_rule_and_its_remove_button_share_a_line(self):
        self._show('software-policy')
        rows = self.page.evaluate("""() => [...document.querySelectorAll('#swpol-rules .swpol-rule')].map(r => {
            const t = r.firstElementChild.getBoundingClientRect(), b = r.querySelector('button').getBoundingClientRect();
            return {textMid: (t.top + t.bottom) / 2, btnMid: (b.top + b.bottom) / 2, h: r.getBoundingClientRect().height}; })""")
        self.assertGreaterEqual(len(rows), 3, 'control: the seeded policy has rules')
        for r in rows:
            self.assertLess(abs(r['textMid'] - r['btnMid']), 12, r)
            self.assertLess(r['h'], 60, r)

    # ── Threat Intel ────────────────────────────────────────────────────────
    def test_the_attackers_table_gives_evidence_and_status_room(self):
        self._show('ipintel', 2500)
        m = self.page.evaluate("""() => { const q = (s) => [...document.querySelectorAll(s)].map(e => e.getBoundingClientRect().width);
            const rows = [...document.querySelectorAll('#page-ipintel tbody tr')].filter(r => r.querySelector('.ipi-actions')).map(r => r.getBoundingClientRect().height);
            return {ev: q('.ipi-evidence-cell'), st: q('.ipi-status-cell'), rows}; }""")
        self.assertTrue(m['ev'] and m['st'] and m['rows'], 'control: the seeded attackers table has rows')
        self.assertGreaterEqual(min(m['ev']), 215)
        self.assertGreaterEqual(min(m['st']), 145)

    # ── Timesheet ───────────────────────────────────────────────────────────
    def test_an_entrys_edit_and_delete_sit_side_by_side(self):
        self._show('timesheet', 2200)
        pairs = self.page.evaluate("""() => [...document.querySelectorAll('.ts-entry')].map(e => [...e.querySelectorAll('.btn-icon')].map(b => b.getBoundingClientRect()))
                                              .filter(p => p.length === 2).map(p => [p[0].top, p[1].top, p[0].left, p[1].left])""")
        self.assertTrue(pairs, 'control: the seeded week has entries that can be edited')
        for top1, top2, left1, left2 in pairs:
            self.assertLess(abs(top1 - top2), 3, 'edit above delete')
            self.assertLess(left1, left2)

    # ── Forecast ────────────────────────────────────────────────────────────
    def test_the_word_projected_is_not_struck_through_by_the_projection(self):
        self._show('forecast', 2500)
        m = self.page.evaluate("""() => {
            const svg = [...document.querySelectorAll('#page-forecast svg')].find(s => [...s.querySelectorAll('text')].some(t => t.textContent === 'projected'));
            if (!svg) return null;
            const word = [...svg.querySelectorAll('text')].find(t => t.textContent === 'projected').getBoundingClientRect();
            const line = svg.querySelector('line[stroke-dasharray="6 5"]');
            if (!line) return {word: [word.left, word.top, word.bottom], line: null};
            const l = line.getBoundingClientRect();
            return {word: [word.left, word.top, word.bottom], line: [l.left, l.top, l.right, l.bottom], x1: +line.getAttribute('x1'), y1: +line.getAttribute('y1'),
                    x2: +line.getAttribute('x2'), y2: +line.getAttribute('y2')}; }""")
        self.assertIsNotNone(m, 'control: the seeded forecast draws a chart with a projected region')
        self.assertIsNotNone(m['line'], 'control: and a projection line')
        # the line's own y at the word's x, in screen coordinates (the box of a diagonal says nothing about where it passes)
        l_left, l_top, l_right, l_bottom = m['line']
        w_left, w_top, w_bottom = m['word']
        w_mid_x, w_mid_y = w_left + 20, (w_top + w_bottom) / 2
        if l_right > l_left:
            frac = min(1, max(0, (w_mid_x - l_left) / (l_right - l_left)))
            rising = m['y2'] < m['y1']
            y_at = (l_bottom - frac * (l_bottom - l_top)) if rising else (l_top + frac * (l_bottom - l_top))
            self.assertGreater(abs(w_mid_y - y_at), 10, 'the projection line passes through the word')

    # ── Advisory ────────────────────────────────────────────────────────────
    def test_the_advisory_builds_itself_the_first_time(self):
        self.page.evaluate("_advLast = null")
        self._show('advisory', 2500)
        findings = self.page.inner_text('#adv-findings')
        self.assertNotIn('Choose a scope and build', findings)
        self.assertGreater(len(self.page.query_selector_all('#adv-summary .adv-tile')), 2, 'the summary tiles are drawn')
        self.assertGreater(len(findings), 40, 'the findings are drawn')

    # ── My Account ──────────────────────────────────────────────────────────
    def test_my_account_names_itself_in_the_top_bar(self):
        self.page.evaluate("openAccount()")
        self.page.wait_for_timeout(600)
        crumb = self.page.inner_text('#topbar-crumb')
        self.assertNotEqual(crumb.strip().lower(), 'account', 'the raw page name')
        self.assertRegex(crumb, r'(?i)my account|account')
        self.assertNotRegex(crumb.strip(), r'^account$')


if __name__ == '__main__':
    unittest.main()
