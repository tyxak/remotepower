#!/usr/bin/env python3
"""Licence cost in software metering, measured in a real browser on the seeded demo instance.

Three rules are written into the seeded settings from what the seeded hosts have installed (counted here in Python the way the report counts: a package whose
name contains the rule's name): one short of licences with a cost, one with licences to spare and a cost, one with licences to spare and no cost. The billing
settings say EUR. The page is then held to:

  * the columns, the rows and the fleet total are the ones worked out from the data here, in euros, and a rule with no cost has no amount;
  * the CSV the page's own export button downloads has the same columns, in the order of the table, with the amounts as numbers;
  * the rule editor takes a cost ("name = limit @ cost"), saves it (the table and the stored setting follow, to two decimals), and refuses a cost that is not an
    amount without sending anything;
  * no horizontal overflow of the page at 1440, 768 and 390 pixels, in English and in Arabic (right to left);
  * German and Arabic reach the column labels, the total and the sentence over the editor;
  * a read-only user's page has no cost column, no amount and no currency, and the settings it reads carry no cost;
  * no console error, page error or failed request while the page loads and the rules are saved.

The new columns and the total are text, not controls; the editor, its Save button and the CSV button were already reachable by keyboard and have their focus rings.
Named *e2e* so it stays off `make test-fast`.
"""
import json
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
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
import browser_plant

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

VIEWPORTS = ((1440, 900), (768, 1024), (390, 844))
COST_COLUMNS = ['Unit cost', 'Cost to buy', 'Cost to reclaim']
ALL_COLUMNS = ['Software', 'Installed', 'Owned', 'Unit cost', 'Short by', 'Cost to buy', 'Spare', 'Cost to reclaim', 'Reclaim', 'Hosts']


def count(packages, needle):
    """How many hosts have a package whose name contains `needle`: the rule of the report."""
    return sum(1 for entry in packages.values() if any(needle in str(p.get('name') or '').lower() for p in (entry or {}).get('packages') or []))


def plant_rules(data_dir):
    """Three rules from the seeded inventory; returns the rules and what the report must say of them."""
    packages = browser_plant.load(data_dir, 'PACKAGES_FILE')
    names = sorted({str(p['name']).lower() for e in packages.values() for p in e.get('packages', []) if p.get('name')})
    scored = sorted(((count(packages, n), n) for n in names), key=lambda x: (-x[0], x[1]))
    c1, n1 = scored[0]
    mid = [x for x in scored if x[1] != n1 and 1 <= x[0] < c1]
    assert c1 >= 4 and len(mid) >= 2, scored[:6]
    (c2, n2), (c3, n3) = mid[0], mid[1]
    rules = [{'name': n1, 'limit': c1 - 2, 'unit_cost': '19.99'}, {'name': n2, 'limit': c2 + 3, 'unit_cost': '123.45'}, {'name': n3, 'limit': c3 + 1}]
    browser_plant.update(data_dir, 'CONFIG_FILE', {'software_meters': rules})
    browser_plant.save(data_dir, 'BILLING_FILE', {'currency': 'EUR'})
    expect = {
        n1: {'installed': c1, 'owned': c1 - 2, 'short': 2, 'short_cost': '39.98', 'spare': 0, 'spare_cost': '0.00', 'unit': '19.99'},        # 2 x 19.99
        n2: {'installed': c2, 'owned': c2 + 3, 'short': 0, 'short_cost': '0.00', 'spare': 3, 'spare_cost': '370.35', 'unit': '123.45'},      # 3 x 123.45
        n3: {'installed': c3, 'owned': c3 + 1, 'short': 0, 'short_cost': None, 'spare': 1, 'spare_cost': None, 'unit': None},               # no cost: no amount
    }
    return rules, expect, {'short': 2, 'spare': 4, 'short_cost': '39.98', 'spare_cost': '370.35', 'unpriced': 1}


def js_number(text):
    """What `String(Number(text))` is in the page: the amount as a number, with no trailing zeros, and nothing for no amount."""
    if text is None:
        return ''
    x = float(text)
    return str(int(x)) if x == int(x) else repr(x)


def euro(text):
    whole, cents = text.split('.')
    return 'EUR ' + '{:,}'.format(int(whole)) + '.' + cents


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheTableInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-metering-e2e-')
        cls.addClassCleanup(shutil.rmtree, cls.data_dir, True)
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply', '--quiet'], capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        cls.rules, cls.expect, cls.totals = plant_rules(cls.data_dir)
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
        cls.problems = []
        cls.page = cls.sign_in('alice', cls.problems)
        cls.open_metering(cls.page)

    @classmethod
    def sign_in(cls, user, problems):
        ctx = cls.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block', accept_downloads=True)
        cls.addClassCleanup(ctx.close)
        ctx.add_init_script("try { localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")        # one long page: every card is in the walk
        page = ctx.new_page()
        page.on('console', lambda m: problems.append(('console', m.text)) if m.type == 'error' else None)
        page.on('pageerror', lambda e: problems.append(('pageerror', str(e))))
        page.on('requestfailed', lambda r: problems.append(('requestfailed', r.url)))
        page.on('response', lambda r: problems.append(('http %d' % r.status, r.url)) if r.status >= 400 else None)
        page.goto(cls.base + '/index.html')
        page.fill('#login-user', user)
        page.fill('#login-pass', 'demo')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=90000)
        page.wait_for_timeout(6000)
        page.evaluate("() => _ensureI18n()")                    # i18n.js is loaded on demand: without it RPi18n is undefined
        problems.clear()                                        # what the page does on its own at sign-in is not this table's
        return page

    @classmethod
    def open_metering(cls, page):
        page.evaluate("() => { try { showPage('reports') } catch (e) {} }")
        page.wait_for_selector('#page-reports.active', timeout=30000)
        page.evaluate("() => loadReportsMetering()")
        page.wait_for_selector('#metering-results table', timeout=60000)
        page.wait_for_timeout(800)

    def table(self, page=None):
        page = page or self.page
        return page.evaluate("""() => {
          const rows = Array.from(document.querySelectorAll('#metering-results tbody tr')).map(tr => Array.from(tr.children).map(td => td.textContent.replace(/\\s+/g, ' ').trim()));
          const th = Array.from(document.querySelectorAll('#metering-thead th')).map(t => t.textContent.replace(/[\\u2195\\u25b2\\u25bc]/g, '').replace(/\\s+/g, ' ').trim());   // without the sort arrow
          const tot = document.querySelector('#metering-results .metering-totals');
          return {th, rows, total: tot ? tot.textContent.replace(/\\s+/g, ' ').trim() : null};
        }""")

    def by_rule(self, t):
        return {r[0].split(' +')[0].strip(): dict(zip(t['th'], r)) for r in t['rows']}

    def test_the_columns_rows_and_total_are_the_ones_worked_out_from_the_data(self):
        t = self.table()
        self.assertEqual(t['th'], ALL_COLUMNS)
        got = self.by_rule(t)
        self.assertEqual(sorted(got), sorted(self.expect))
        for name, want in self.expect.items():
            row = got[name]
            self.assertEqual(row['Installed'].split()[0], str(want['installed']), name)
            self.assertEqual(row['Owned'], str(want['owned']), name)
            self.assertEqual(row['Unit cost'], euro(want['unit']) if want['unit'] else '—', name)
            self.assertEqual(row['Short by'], str(want['short']), name)
            self.assertEqual(row['Cost to buy'], euro(want['short_cost']) if want['short_cost'] else '—', name)
            self.assertEqual(row['Spare'], str(want['spare']), name)
            self.assertEqual(row['Cost to reclaim'], euro(want['spare_cost']) if want['spare_cost'] else '—', name)
        want = self.totals
        self.assertEqual(t['total'], 'Fleet total Short by %d Cost to buy %s Spare %d Cost to reclaim %s Rules without a cost %d'
                         % (want['short'], euro(want['short_cost']), want['spare'], euro(want['spare_cost']), want['unpriced']))

    def test_the_csv_the_page_exports_has_the_same_columns_in_the_same_order(self):
        with self.page.expect_download(timeout=30000) as dl:
            self.page.click('#page-reports button[data-action="tblExportCsv"][data-arg="metering"]')
        text = Path(dl.value.path()).read_text()
        lines = text.strip().split('\n')
        self.assertEqual(lines[0], 'software,installed,owned,unit_cost,shortfall,shortfall_cost,surplus,surplus_cost,reclaim,currency')
        by = {l.split(',')[0]: l.split(',') for l in lines[1:]}
        self.assertEqual(sorted(by), sorted(self.expect))
        for name, want in self.expect.items():
            c = by[name]
            self.assertEqual((c[1], c[2], c[4], c[6], c[9]), (str(want['installed']), str(want['owned']), str(want['short']), str(want['spare']), 'EUR'), name)
            for i, key in ((3, 'unit'), (5, 'short_cost'), (7, 'spare_cost')):
                self.assertEqual(c[i], js_number(want[key]), (name, i))

    def test_the_editor_shows_the_cost_saves_it_and_the_table_follows(self):
        page = self.page
        n1, want = next(iter(self.expect.items()))
        lines = page.input_value('#metering-config').split('\n')
        self.assertIn('%s = %d @ 19.99' % (n1, want['owned']), lines)
        self.assertTrue(any(l.endswith('@ 123.45') for l in lines))
        self.assertTrue(any('@' not in l for l in lines), 'the rule with no cost has no @')
        new = page.input_value('#metering-config').replace('@ 19.99', '@ 20.5')
        page.fill('#metering-config', new)
        with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'POST', timeout=30000) as resp:
            page.click('#page-reports button[data-action="saveMetering"]')
        self.assertEqual(resp.value.status, 200)
        page.wait_for_function("(c) => document.querySelector('#metering-results tbody').textContent.includes(c)", arg=euro('41.00'), timeout=30000)   # 2 x 20.50
        self.assertEqual(self.by_rule(self.table())[n1]['Unit cost'], 'EUR 20.50', 'stored with two decimals')
        stored = page.evaluate("async () => (await api('GET', '/config')).software_meters.map(m => m.unit_cost || null)")
        self.assertEqual(stored, ['20.50', '123.45', None])
        page.fill('#metering-config', new.replace('@ 20.5', '@ 19.99'))                      # and back, so the other tests read what they were written from
        page.click('#page-reports button[data-action="saveMetering"]')
        page.wait_for_function("(c) => document.querySelector('#metering-results tbody').textContent.includes(c)", arg=euro('39.98'), timeout=30000)

    def test_a_cost_that_is_not_an_amount_is_refused_without_sending_anything(self):
        page = self.page
        sent = []
        page.on('request', lambda r: sent.append(r.url) if r.method == 'POST' and r.url.endswith('/api/config') else None)
        original = page.input_value('#metering-config')
        page.fill('#metering-config', original + '\nbroken = 3 @ 1.999')
        page.click('#page-reports button[data-action="saveMetering"]')
        page.wait_for_function("() => document.body.innerText.includes('A cost is an amount such as 49.99, with at most two decimals')", timeout=10000)
        page.wait_for_timeout(800)
        self.assertEqual(sent, [], 'a refused cost sends no request')
        page.fill('#metering-config', original)

    def test_nothing_overflows_at_three_widths_in_english_and_in_arabic(self):
        problems = {}
        try:
            for lang in ('en', 'ar'):
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(600)
                for w, h in VIEWPORTS:
                    self.page.set_viewport_size({'width': w, 'height': h})
                    self.page.wait_for_timeout(500)
                    o = self.page.evaluate("""() => { const d = document.documentElement, t = document.querySelector('#metering-results .metering-totals'), r = t.getBoundingClientRect();
                      return {page: d.scrollWidth - d.clientWidth, totals: t.scrollWidth - t.clientWidth, left: Math.round(r.left), right: Math.round(r.right), width: window.innerWidth}; }""")
                    bad = {k: v for k, v in o.items() if k in ('page', 'totals') and v > 0}
                    if o['left'] < 0 or o['right'] > o['width']:
                        bad['outside the viewport'] = o
                    if bad:
                        problems['%s %dpx' % (lang, w)] = bad
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})
            self.page.wait_for_timeout(400)
        self.assertEqual(problems, {})

    def test_german_and_arabic_reach_the_columns_the_total_and_the_sentence(self):
        want = {'de': (['Vorhanden', 'Stückkosten', 'Fehlend', 'Kaufkosten', 'Übrig', 'Rückholbare Kosten'], 'Summe der Flotte', 'Regeln ohne Kosten', 'Lizenz'),
                'ar': (['المملوكة', 'تكلفة الوحدة', 'العجز', 'تكلفة الشراء', 'الفائض', 'التكلفة القابلة للاسترداد'], 'إجمالي الأسطول', 'قواعد بلا تكلفة', 'الترخيص')}
        try:
            for lang, (cols, total, unpriced, sentence_word) in want.items():
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(700)
                t = self.table()
                for c in cols:
                    self.assertIn(c, t['th'], lang)
                self.assertIn(total, t['total'], lang)
                self.assertIn(unpriced, t['total'], lang)
                sentence = self.page.evaluate("() => document.querySelector('#metering-config').closest('.dash-card').querySelector('.page-subtitle').textContent")
                self.assertIn(sentence_word, sentence, lang)
                self.assertNotIn('Track install counts', sentence, lang)
                tip = self.page.evaluate("() => document.querySelector('#metering-results .metering-totals [title]').getAttribute('title')")
                self.assertNotIn('A rule with no cost', tip, lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.wait_for_timeout(400)

    def test_a_read_only_user_reads_no_cost_anywhere(self):
        problems = []
        page = self.sign_in('demo', problems)
        self.open_metering(page)
        t = self.table(page)
        self.assertEqual(t['th'], ['Software', 'Installed', 'Owned', 'Short by', 'Spare', 'Reclaim', 'Hosts'])
        for c in COST_COLUMNS:
            self.assertNotIn(c, t['th'])
        text = json.dumps(t)
        for amount in ('19.99', '123.45', '39.98', '370.35', 'EUR', 'USD'):
            self.assertNotIn(amount, text)
        self.assertEqual(self.by_rule(t)[next(iter(self.expect))]['Short by'], '2', 'the counts are still there')
        self.assertIn('Fleet total Short by 2 Spare 4', t['total'])
        self.assertNotIn('Rules without a cost', t['total'])
        cfg = page.evaluate("async () => (await api('GET', '/config')).software_meters")
        self.assertEqual([m['name'] for m in cfg], [r['name'] for r in self.rules], 'the rules themselves are as before')
        self.assertNotIn('unit_cost', json.dumps(cfg))
        with page.expect_download(timeout=30000) as dl:
            page.click('#page-reports button[data-action="tblExportCsv"][data-arg="metering"]')
        header = Path(dl.value.path()).read_text().split('\n')[0]
        self.assertEqual(header, 'software,installed,owned,shortfall,surplus,reclaim')
        # The Reports page asks for the report archive, which only an administrator reads: it answers a read-only user 403, as it always has. Nothing else may fail.
        http = [p for p in problems if p[0].startswith('http')]
        self.assertTrue(all(p[1].endswith('/api/report/archive') for p in http), http)
        rest = [p for p in problems if not p[0].startswith('http') and 'status of 403' not in p[1]]
        self.assertEqual(rest, [], rest)

    def test_loading_the_page_and_saving_the_rules_raised_no_error(self):
        self.assertEqual(self.problems, [], self.problems)


if __name__ == '__main__':
    unittest.main()
