#!/usr/bin/env python3
"""The failing mark on a notification destination's card in Settings, measured in a real browser on the seeded demo instance.

A streak of four failed deliveries with a timeout is written into the stores for the demo's Discord destination, and a streak of two for the Pushover one (below the
three that count). The settings are put in test mode so the stack sends nothing while the page is open. The page is then held to:

  * the card of the failing destination shows the badge, the streak and the kind of its last error, and no other card shows a mark;
  * no horizontal overflow of the page at 1440, 768 and 390 pixels, in English, German (long words) and Arabic (right to left), and the mark stays inside its card;
  * German and Arabic reach every word of the mark;
  * changing the destination's address and saving the settings takes the mark away, and it does not come back with the next read;
  * a read-only user's settings carry no streak and no class;
  * no console error, page error or failed request while the page loads and the settings are saved.

The mark is text, not a control, so there is no new focus ring or icon-only button to check.
Named *e2e* so it stays off `make test-fast`.
"""
import json
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

VIEWPORTS = ((1440, 900), (768, 1024), (390, 844))
FAILING, QUIET = 'wh_discord_demo', 'wh_pushover_demo'


def plant(data_dir):
    now = int(time.time())
    health = {
        'wh:' + FAILING: {'fails': 4, 'since': now - 3600, 'last': now - 60, 'error': 'URLError [discord]: timed out', 'label': 'Discord', 'alerted': True},
        'wh:' + QUIET: {'fails': 2, 'since': now - 600, 'last': now - 60, 'error': 'HTTP 500 [pushover]: boom', 'label': 'Pushover', 'alerted': False},
    }
    e2e_plant.save(data_dir, 'NOTIFY_HEALTH_FILE', health)
    # notifications_test_mode: a would-be delivery is logged and not sent, and a dry run is neither a success nor a failure.
    # The Settings form posts the other four with every save and the demo has never stored them: a missing key and the default the form writes out read as a change
    # to the save, which then asks for a step-up. An installation whose settings were saved once has them, so the test starts from there.
    e2e_plant.update(data_dir, 'CONFIG_FILE', {'notifications_test_mode': True, 'mfa_required_roles': [], 'sso_only': False, 'audit_worm_path': '', 'tenancy_enforced': False})


class TestTheMarkInABrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-dest-mark-e2e-')
        cls.addClassCleanup(shutil.rmtree, cls.data_dir, True)
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply', '--quiet'], capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        plant(cls.data_dir)
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
        cls.page.evaluate("() => { showPage('settings'); switchSettingsTab('notifs'); }")
        cls.page.wait_for_selector('#webhook-dests .webhook-dest-card', timeout=60000)
        cls.page.wait_for_timeout(800)

    @classmethod
    def sign_in(cls, user, problems):
        ctx = cls.browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
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
        problems.clear()                                        # what the page does on its own at sign-in is not this card's
        return page

    def cards(self):
        """{destination name: the text of its mark, or None}."""
        return self.page.evaluate("""() => {
          const out = {};
          document.querySelectorAll('#webhook-dests .webhook-dest-card').forEach(c => {
            const name = (c.querySelector('[data-field="name"]') || {}).value || '';
            const m = c.querySelector('.dest-failing');
            out[name] = m ? m.textContent.replace(/\\s+/g, ' ').trim() : null;
          });
          return out;
        }""")

    def test_the_failing_destination_is_marked_with_its_streak_and_the_kind_of_its_last_error_and_no_other_is(self):
        got = self.cards()
        self.assertGreaterEqual(len(got), 3, got)
        marked = {n: t for n, t in got.items() if t}
        self.assertEqual(marked, {'Discord — operations channel': 'Failing Failed in a row 4 Last error Timed out'})
        self.assertIsNone(got['Pushover — critical only'], 'a streak of two is not yet news')

    def test_the_mark_holds_no_address_and_no_remote_text(self):
        html = self.page.evaluate("() => document.querySelector('#webhook-dests .dest-failing').outerHTML")
        for leak in ('discord.com', 'demo-not-a-real-webhook', 'URLError', 'timed out', 'http'):
            self.assertNotIn(leak, html)

    def test_nothing_overflows_at_three_widths_in_english_german_and_arabic(self):
        problems = {}
        try:
            for lang in ('en', 'de', 'ar'):
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(600)
                for w, h in VIEWPORTS:
                    self.page.set_viewport_size({'width': w, 'height': h})
                    self.page.wait_for_timeout(500)
                    o = self.page.evaluate("""() => { const d = document.documentElement, m = document.querySelector('#webhook-dests .dest-failing'), card = m.closest('.webhook-dest-card'),
                      r = m.getBoundingClientRect(), c = card.getBoundingClientRect();
                      return {page: d.scrollWidth - d.clientWidth, mark: m.scrollWidth - m.clientWidth, inside: r.left >= c.left - 1 && r.right <= c.right + 1,
                              left: Math.round(r.left), right: Math.round(r.right), width: window.innerWidth}; }""")
                    bad = {k: v for k, v in o.items() if k in ('page', 'mark') and v > 0}
                    if not o['inside'] or o['left'] < 0 or o['right'] > o['width']:
                        bad['outside its card or the viewport'] = o
                    if bad:
                        problems['%s %dpx' % (lang, w)] = bad
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.set_viewport_size({'width': 1440, 'height': 900})
            self.page.wait_for_timeout(400)
        self.assertEqual(problems, {})

    def test_german_and_arabic_reach_every_word_of_the_mark(self):
        want = {'de': ['Fehlschläge in Folge', 'Zeitüberschreitung'], 'ar': ['إخفاقات متتالية', 'انتهت المهلة']}
        english = self.cards()['Discord — operations channel']
        try:
            for lang, words in want.items():
                self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(700)
                got = [t for t in self.cards().values() if t]
                self.assertEqual(len(got), 1, lang)
                for w in words:
                    self.assertIn(w, got[0], lang)
                for en in ('Failed in a row', 'Timed out', 'Last error', 'Failing'):
                    self.assertNotIn(en, got[0], lang + ': ' + en + ' is translated')
                title = self.page.evaluate("() => document.querySelector('#webhook-dests .dest-failing').getAttribute('title')")
                self.assertNotIn('Deliveries to this destination', title, lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
            self.page.wait_for_timeout(400)
        self.assertEqual(self.cards()['Discord — operations channel'], english, 'and back to English')

    def test_a_read_only_users_settings_carry_no_streak_and_no_class(self):
        problems = []
        page = self.sign_in('demo', problems)
        cfg = page.evaluate("async () => (await api('GET', '/config')).webhook_urls")
        self.assertGreaterEqual(len(cfg), 3)
        self.assertNotIn('fail_', json.dumps(cfg))
        self.assertTrue(all(d.get('url') == '' and d.get('url_set') is True for d in cfg), 'and still no address, as before')
        admin = self.page.evaluate("async () => (await api('GET', '/config')).webhook_urls.filter(d => d.fail_streak).map(d => [d.id, d.fail_streak, d.fail_class])")
        self.assertEqual(admin, [[FAILING, 4, 'timeout']], 'control: the administrator reads it from the same route')

    def test_zz_changing_the_address_and_saving_takes_the_mark_away_for_good(self):
        page = self.page
        card = page.locator('#webhook-dests .webhook-dest-card', has=page.locator('.dest-failing')).first
        card.locator('[data-field="url"]').fill('https://discord.com/api/webhooks/000000000000000000/another-demo-hook')
        with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'POST', timeout=30000) as resp:
            page.click('#btn-save-settings')
        self.assertEqual(resp.value.status, 200, resp.value.text())
        page.wait_for_function("() => document.querySelectorAll('#webhook-dests .webhook-dest-card').length >= 3 && !document.querySelector('#webhook-dests .dest-failing')", timeout=30000)
        self.assertEqual([t for t in self.cards().values() if t], [])
        gone = page.evaluate("async () => (await api('GET', '/config')).webhook_urls.filter(d => d.fail_streak).length")
        self.assertEqual(gone, 0, 'it does not come back with the next read')
        health = e2e_plant.load(self.data_dir, 'NOTIFY_HEALTH_FILE')
        self.assertNotIn('wh:' + FAILING, health)
        self.assertIn('wh:' + QUIET, health, 'the other streak is left as it was')

    def test_zzz_loading_the_page_and_saving_raised_no_error(self):
        self.assertEqual(self.problems, [], self.problems)


if __name__ == '__main__':
    unittest.main()
