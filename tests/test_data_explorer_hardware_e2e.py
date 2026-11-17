#!/usr/bin/env python3
"""The hardware entity in the Data Explorer page, measured in a real browser on the seeded demo instance.

The entity list and the field lists are built from `GET /api/query/fields`, so the entity and its fields reach the page by themselves. What a browser has to say:

  * `hardware` is in the entity select and its fields are in the sort select; choosing it shows the sentence that says what a row is;
  * a query over it returns rows of the seeded hosts with the maker, model and serial the demo seeded, and the table of 24 columns stays inside its own scroll box:
    no horizontal overflow of the page at 1440, 768 and 390 pixels, in English and in Arabic (right to left);
  * German and Arabic reach the sentence (it is the dictionary's text, not English left in place);
  * no console error, page error or failed request while the page loads, the entity changes and the query runs.

The page gains no control (the hint is text), so there is no new focus ring or icon-only button to check; the entity select was already reachable by keyboard.
Named *e2e* so it stays off `make test-fast`.
"""
import os
import shutil
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

VIEWPORTS = ((1440, 900), (768, 1024), (390, 844))
HINT_START = 'One row for each host'


class TestTheEntityInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-explorer-hw-e2e-')
        cls.addClassCleanup(shutil.rmtree, cls.data_dir, True)
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply', '--quiet'], capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        cls.addClassCleanup(cls._pw.stop)
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        cls.addClassCleanup(cls.browser.close)
        try:
            cls.base, shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls.addClassCleanup(shutdown)
        cls.ctx = cls.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        cls.addClassCleanup(cls.ctx.close)
        cls.ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")      # one long page: every card is in the walk
        cls.page = cls.ctx.new_page()
        cls.problems = []
        cls.page.on('console', lambda m: cls.problems.append(('console', m.text)) if m.type == 'error' else None)
        cls.page.on('pageerror', lambda e: cls.problems.append(('pageerror', str(e))))
        cls.page.on('requestfailed', lambda r: cls.problems.append(('requestfailed', r.url)))
        cls.page.on('response', lambda r: cls.problems.append(('http %d' % r.status, r.url)) if r.status >= 400 else None)
        cls.page.goto(cls.base + '/index.html')
        cls.page.fill('#login-user', 'alice')
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(6000)
        cls.page.evaluate("() => _ensureI18n()")                # i18n.js is loaded on demand: without it RPi18n is undefined
        cls.problems.clear()                                    # what the page does on its own at sign-in is not this page's
        cls.page.evaluate("() => { try { showPage('dataexplorer') } catch (e) {} }")
        cls.page.wait_for_selector('#qe-entity option[value="hardware"]', state='attached', timeout=60000)
        cls.page.select_option('#qe-entity', 'hardware')
        cls.page.wait_for_function("(s) => (document.getElementById('qe-entity-hint') || {}).textContent.startsWith(s)", arg=HINT_START, timeout=30000)

    def hint(self):
        return self.page.evaluate("() => document.getElementById('qe-entity-hint').textContent.trim()")

    def use_hardware(self):
        """The page forgets the choice of entity whenever it is shown again, so each test chooses it."""
        self.page.select_option('#qe-entity', 'hardware')
        self.page.wait_for_function("(s) => document.getElementById('qe-entity-hint').textContent.startsWith(s)", arg=HINT_START, timeout=10000)

    def run_query(self, field=None, op='eq', value=''):
        page = self.page
        self.use_hardware()                                     # which also gives a fresh condition row
        if field:
            page.select_option('.qe-cond-field', field)
            page.select_option('.qe-cond-op', op)
            page.fill('.qe-cond-value', value)
        page.click('button[data-action="qeRun"]')
        page.wait_for_function("() => document.querySelectorAll('#qe-results-tbody tr').length > 0 && !/Running/.test(document.getElementById('qe-status').textContent)", timeout=30000)
        page.wait_for_timeout(400)
        return page.evaluate("""() => ({cols: Array.from(document.querySelectorAll('#qe-results-thead th')).map(t => t.textContent.trim()),
                                       rows: Array.from(document.querySelectorAll('#qe-results-tbody tr')).map(tr => Array.from(tr.children).map(td => td.textContent.trim()))})""")

    def test_the_entity_is_listed_with_its_fields_and_says_what_a_row_is(self):
        self.use_hardware()
        opts = self.page.evaluate("() => Array.from(document.querySelectorAll('#qe-entity option')).map(o => o.value)")
        self.assertIn('hardware', opts)
        self.assertEqual(len(opts), len(set(opts)))
        fields = self.page.evaluate("() => Array.from(document.querySelectorAll('#qe-sort option')).map(o => o.value).filter(Boolean)")
        for f in ('vendor', 'model', 'serial', 'cpu_model', 'cpu_count', 'memory_modules', 'memory_type', 'disk_models', 'gpu_models', 'reported_at'):
            self.assertIn(f, fields)
        self.assertEqual(len(fields), 24, fields)
        self.assertTrue(self.hint().startswith(HINT_START))
        self.page.select_option('#qe-entity', 'devices')
        self.page.wait_for_function("() => document.getElementById('qe-entity-hint').textContent === ''", timeout=10000)
        self.page.select_option('#qe-entity', 'hardware')
        self.page.wait_for_function("(s) => document.getElementById('qe-entity-hint').textContent.startsWith(s)", arg=HINT_START, timeout=10000)

    def test_a_query_over_the_entity_returns_the_seeded_hosts_with_their_maker_model_and_serial(self):
        got = self.run_query()
        for c in ('vendor', 'model', 'serial', 'cpu_model', 'memory_modules'):
            self.assertIn(c, got['cols'])
        by_id = {r[got['cols'].index('device_id')]: r for r in got['rows']}
        self.assertGreaterEqual(len(by_id), 15, 'a row for each seeded host, with or without hardware data')
        pmx = by_id['pmx01']
        self.assertEqual((pmx[got['cols'].index('vendor')], pmx[got['cols'].index('model')], pmx[got['cols'].index('serial')]), ('Dell Inc.', 'PowerEdge R740', 'DEMO-R740-0001'))
        got = self.run_query('vendor', 'eq', 'Dell Inc.')
        ids = {r[got['cols'].index('device_id')] for r in got['rows']}
        self.assertIn('pmx01', ids)
        self.assertNotIn('tnas', ids, 'a Supermicro host is not a Dell host')
        self.assertTrue(all(r[got['cols'].index('vendor')] == 'Dell Inc.' for r in got['rows']))

    def test_nothing_overflows_at_three_widths_in_english_and_in_arabic(self):
        problems = {}
        self.run_query()
        try:
            for lang in ('en', 'ar'):
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(600)
                for w, h in VIEWPORTS:
                    self.page.set_viewport_size({'width': w, 'height': h})
                    self.page.wait_for_timeout(500)
                    o = self.page.evaluate("""() => { const d = document.documentElement, h = document.getElementById('qe-entity-hint'), r = h.getBoundingClientRect();
                      return {page: d.scrollWidth - d.clientWidth, hint: h.scrollWidth - h.clientWidth, left: Math.round(r.left), right: Math.round(r.right), width: window.innerWidth}; }""")
                    bad = {k: v for k, v in o.items() if k in ('page', 'hint') and v > 0}
                    if o['left'] < 0 or o['right'] > o['width']:
                        bad['outside the viewport'] = o
                    if bad:
                        problems['%s %dpx' % (lang, w)] = bad
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})
            self.page.wait_for_timeout(400)
        self.assertEqual(problems, {})

    def test_german_and_arabic_reach_the_sentence(self):
        self.use_hardware()
        english = self.hint()
        try:
            for lang, word in (('de', 'Eine Zeile pro Host'), ('ar', 'صف واحد لكل مضيف')):
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(600)
                got = self.hint()
                self.assertNotEqual(got, english, lang)
                self.assertTrue(got.startswith(word), (lang, got[:60]))
                self.assertEqual(self.page.evaluate("document.documentElement.dir"), 'rtl' if lang == 'ar' else 'ltr', lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.wait_for_timeout(400)
        self.assertEqual(self.hint(), english, 'and back to English')

    def test_loading_the_page_changing_the_entity_and_running_a_query_raised_no_error(self):
        self.page.evaluate("() => { try { showPage('dataexplorer') } catch (e) {} }")
        self.page.wait_for_timeout(1500)
        self.run_query('cpu_model', 'exists', '')
        self.assertEqual(self.problems, [], self.problems)


if __name__ == '__main__':
    unittest.main()
