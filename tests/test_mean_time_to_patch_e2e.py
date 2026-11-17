#!/usr/bin/env python3
"""The mean time to patch card of the Patches header, measured in a real browser on the seeded demo instance.

Source tests say the markup and the function are right; only a browser says the card fits. The completed patches are planted in the seeded store (the sweep that
files them is held by test_mean_time_to_patch), the real stack serves them through `GET /api/patch-report`, and the page is measured:

  * the card shows the figure the API sent and the count n, and the 90-day window is reached with the keyboard alone;
  * no horizontal overflow at 1440, 768 and 390 pixels, in English and in Arabic (right to left), and the card never leaves the viewport;
  * German and Arabic text reach every word of the card (the strings are the dictionary's, not English left in place);
  * the window select is reachable by keyboard and has a visible focus ring;
  * no console error, no page error and no failed request while the page loads and while the window changes.

The card holds no icon-only button, so there is no btn-icon to check; its icon is a decorative SVG of the stat card.

Named *e2e* so it stays off `make test-fast`.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required
import e2e_plant

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

HOUR, DAY = 3600, 86400
VIEWPORTS = ((1440, 900), (768, 1024), (390, 844))


def plant_pairs(data_dir):
    """Completed patches for seven seeded hosts: seven of 'all' (6, 12, 24, 30, 48, 100 and 200 hours, cleared in the last 20 days), three of 'sec' (4, 8, 16 hours)
    and one old one, 50 hours cleared 40 days ago, which only the 90-day window reaches. The sweep is held off for an hour so it does not add pairs of its own."""
    now = int(time.time())
    hosts = sorted(e2e_plant.load(data_dir, 'DEVICES_FILE'))[:7]
    assert len(hosts) == 7, hosts
    pairs = {}
    for i, (h, hours) in enumerate(zip(hosts, (6, 12, 24, 30, 48, 100, 200))):
        done = [[now - (i + 1) * DAY - hours * HOUR, now - (i + 1) * DAY, 'all']]
        if i < 3:
            done.append([now - (i + 1) * DAY - (4 * (i + 1)) * HOUR, now - (i + 1) * DAY, 'sec'])
        if i == 0:
            done.insert(0, [now - 40 * DAY - 50 * HOUR, now - 40 * DAY, 'all'])
        pairs[h] = {'done': done}
    e2e_plant.save(data_dir, 'PATCH_DONE_FILE', pairs)         # the pairs have a store of their own: the aging store every request reads does not carry them
    e2e_plant.update(data_dir, 'PATCH_AGE_FILE', {'_last_run': now})
    return hosts


class TestTheCardInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-mttp-e2e-')
        cls.addClassCleanup(shutil.rmtree, cls.data_dir, True)          # a class cleanup runs even when setUpClass fails after this point
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply', '--quiet'], capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        cls.hosts = plant_pairs(cls.data_dir)
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
        cls.problems.clear()                                    # what the page does on its own at sign-in is not this card's
        cls.page.evaluate("() => { try { showPage('patches') } catch (e) {} }")
        cls.page.wait_for_function("() => document.getElementById('patch-mttp-num') && document.getElementById('patch-mttp-num').textContent.trim() !== '—'", timeout=60000)
        cls.page.wait_for_timeout(1500)

    def card(self):
        return self.page.evaluate("""() => {
          const t = id => { const e = document.getElementById(id); return e ? e.textContent.replace(/\\s+/g, ' ').trim() : null; };
          const det = document.getElementById('patch-mttp-detail');
          return {num: t('patch-mttp-num'), unit: t('patch-mttp-unit'), detail: det ? Array.from(det.children).map(c => c.textContent.replace(/\\s+/g, ' ').trim()) : null,
                  label: (document.querySelector('#patch-mttp-card .stat-label') || {}).textContent};
        }""")

    def api_mttp(self):
        return self.page.evaluate("() => patchReportData && patchReportData.mttp")

    def overflow(self):
        return self.page.evaluate("""() => {
          const d = document.documentElement, c = document.getElementById('patch-mttp-card'), det = document.getElementById('patch-mttp-detail');
          const r = c.getBoundingClientRect();
          return {page: d.scrollWidth - d.clientWidth, card: c.scrollWidth - c.clientWidth, detail: det.scrollWidth - det.clientWidth,
                  left: Math.round(r.left), right: Math.round(r.right), width: window.innerWidth, hidden: getComputedStyle(c).display === 'none'};
        }""")

    def test_the_card_shows_what_the_api_sent_and_the_count(self):
        m = self.api_mttp()
        self.assertIsNotNone(m, 'the page holds the mttp block of the report')
        self.assertEqual((m['window_days'], m['fleet']['all']['n'], m['fleet']['all']['hidden']), (30, 7, False), m['fleet'])
        got = self.card()
        mean = m['fleet']['all']['mean_h']                         # 6, 12, 24, 30, 48, 100 and 200 hours: 420 / 7 = 60
        self.assertEqual(mean, 60.0)
        days = mean >= 72
        self.assertEqual(got['unit'], 'days' if days else 'hours')
        self.assertAlmostEqual(float(got['num']) * (24 if days else 1), mean, delta=1.3)
        self.assertEqual(got['label'], 'Mean time to patch')
        self.assertEqual(got['detail'][0], 'Last 30 days')
        self.assertIn('Samples (n) 7', got['detail'][1])
        self.assertIn('Median', got['detail'][1])
        self.assertIn('90th percentile', got['detail'][1])
        self.assertEqual(got['detail'][2], 'Security updates Not enough data Samples (n) 3', 'three security pairs is below the minimum of five')
        self.assertEqual(self.api_mttp()['hosts'][self.hosts[0]]['all']['n'], 1, 'the pair of 40 days ago is outside the 30-day window')

    def test_nothing_overflows_at_three_widths_in_english_and_in_arabic(self):
        problems = {}
        try:
            for lang in ('en', 'ar'):
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(600)
                for w, h in VIEWPORTS:
                    self.page.set_viewport_size({'width': w, 'height': h})
                    self.page.wait_for_timeout(500)
                    o = self.overflow()
                    bad = {k: v for k, v in o.items() if k in ('page', 'card', 'detail') and v > 0}
                    if o['hidden'] or o['left'] < 0 or o['right'] > o['width']:
                        bad['outside the viewport'] = o
                    if bad:
                        problems['%s %dpx' % (lang, w)] = bad
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})
            self.page.wait_for_timeout(400)
        self.assertEqual(problems, {})

    def test_the_card_is_on_a_row_of_its_own_under_the_five_counts_and_the_five_keep_their_width(self):
        row = self.page.evaluate("""() => {
          const cards = Array.from(document.querySelectorAll('#patch-summary > .stat-card')).map(c => { const r = c.getBoundingClientRect(); return {id: c.id, top: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height)}; });
          return cards;
        }""")
        self.assertEqual(len(row), 6, row)
        five, mttp = row[:5], row[5]
        self.assertEqual(mttp['id'], 'patch-mttp-card')
        self.assertEqual(len({c['top'] for c in five}), 1, 'the five counts share one row, as before: %s' % five)
        self.assertGreater(mttp['top'], five[0]['top'], 'the new card is under them, not squeezed in beside them')
        self.assertLessEqual(mttp['w'], 560, 'and no wider than its limit')
        self.assertGreaterEqual(min(c['w'] for c in five), 150)
        self.assertEqual(len({c['h'] for c in five}), 1, 'a count whose label wrapped would be taller than the rest: %s' % five)

    def test_german_and_arabic_reach_every_word_of_the_card(self):
        self.assertEqual(self.card()['unit'], 'hours', 'the planted mean is 60 hours, which reads in hours')
        want = {
            'de': {'label': 'Mittlere Zeit bis zum Patch', 'detail0': 'Letzte 30 Tage', 'median': 'Median', 'unit': 'Stunden', 'sec': 'Sicherheitsupdates',
                   'few': 'Nicht genug Daten', 'samples': 'Stichproben (n)'},
            'ar': {'label': 'متوسط وقت الترقيع', 'detail0': 'آخر 30 يوماً', 'median': 'الوسيط', 'unit': 'ساعات', 'sec': 'تحديثات الأمان',
                   'few': 'بيانات غير كافية', 'samples': 'العيّنات (n)'},
        }
        try:
            for lang, w in want.items():
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(700)
                got = self.card()
                self.assertEqual(got['label'].strip(), w['label'], lang)
                self.assertEqual(got['detail'][0], w['detail0'], lang)
                self.assertIn(w['median'], got['detail'][1], lang)
                self.assertIn(w['samples'], got['detail'][1], lang)
                self.assertIn(w['sec'], got['detail'][2], lang)
                self.assertIn(w['few'], got['detail'][2], lang)
                self.assertEqual(got['unit'], w['unit'], lang)
                self.assertEqual(self.page.evaluate("document.documentElement.dir"), 'rtl' if lang == 'ar' else 'ltr', lang)
                title = self.page.evaluate("document.getElementById('patch-mttp-card').getAttribute('title')")
                self.assertNotIn('hourly check', title, lang + ': the tooltip is translated')
                aria = self.page.evaluate("document.getElementById('patch-mttp-days').getAttribute('aria-label')")
                self.assertNotEqual(aria, 'Mean time to patch window', lang + ': the aria-label is translated')
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.wait_for_timeout(400)

    def test_the_window_select_is_reached_by_the_keyboard_has_a_focus_ring_and_reaches_ninety_days(self):
        page = self.page
        page.focus('#page-patches button[data-action="loadPatchReport"]')
        page.keyboard.press('Shift+Tab')
        self.assertEqual(page.evaluate("document.activeElement && document.activeElement.id"), 'patch-mttp-days', 'Shift+Tab from the Refresh button lands on the window select')
        page.keyboard.press('Tab')
        page.keyboard.press('Shift+Tab')
        self.assertEqual(page.evaluate("document.activeElement && document.activeElement.id"), 'patch-mttp-days', 'and Tab from the select goes on to the Refresh button and back')
        ring = page.evaluate("""() => { const s = getComputedStyle(document.activeElement);
          return {outline: s.outlineStyle, width: parseFloat(s.outlineWidth), shadow: s.boxShadow, border: s.borderColor}; }""")
        self.assertTrue((ring['outline'] not in ('none', 'hidden') and ring['width'] > 0) or ring['shadow'] not in ('none', ''), 'a visible focus ring: %s' % ring)
        self.problems.clear()
        with page.expect_response(lambda r: '/api/patch-report' in r.url and 'mttp_days=90' in r.url, timeout=30000) as resp:
            page.keyboard.press('ArrowDown')
        self.assertEqual(resp.value.status, 200)
        page.wait_for_function("() => (document.querySelector('#patch-mttp-detail div') || {}).textContent === 'Last 90 days'", timeout=30000)
        m = self.api_mttp()
        self.assertEqual((m['window_days'], m['fleet']['all']['n']), (90, 8), 'the pair of 40 days ago counts now')
        self.assertIn('Samples (n) 8', self.card()['detail'][1])
        with page.expect_response(lambda r: '/api/patch-report' in r.url and 'mttp_days' not in r.url, timeout=30000):
            page.keyboard.press('ArrowUp')
        page.wait_for_function("() => (document.querySelector('#patch-mttp-detail div') || {}).textContent === 'Last 30 days'", timeout=30000)
        self.assertEqual(self.problems, [], 'no console error, page error or failed request while the window changes')

    def test_loading_the_page_raised_no_console_error_and_no_failed_request(self):
        self.page.evaluate("() => { try { showPage('patches') } catch (e) {} }")
        self.page.wait_for_timeout(2500)
        self.assertEqual([p for p in self.problems if 'patch' in p[1].lower() or p[0] in ('pageerror', 'console')], [], self.problems)


if __name__ == '__main__':
    unittest.main()
