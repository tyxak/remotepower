#!/usr/bin/env python3
"""The Threat Intel widget on Home, in a browser on the demo seed.

The numbers are read back from the page the widget links to (`/api/ip-intel`, which the browser asks for as the same signed-in
operator) and recomputed here with the widget's own definitions: addresses seen in the last 24 hours, addresses reported in them,
blocks in force, hosts with a log source in trouble. The server and the page agree on the hosts a caller may see, so a wrong
join, a stale number or a card that paints before its data arrives fails by name. Then the link works, every language has the
words of the card, and the widget is not on until it is added (it is an add-on, not a change to anyone's Home).

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
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

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
PROBLEM_SOURCES = ('missing', 'denied', 'unparsed', 'unsupported', 'error')
PROBLEM_FEEDS = ('no_access', 'refused', 'error', 'no_account', 'no_zones')


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the widget is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-ti-widget-')
    proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f'chromium not available: {exc}')
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f'app stack not available: {exc}')
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()


def _until(fn, seconds=20, step=0.25):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(step)
    return last


class TestTheWidget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = _STATE['browser'].new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                            "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on('pageerror', lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE['base'] + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(4000)
        cls.off_at_first = cls.page.evaluate("() => document.getElementById('home-w-threatintel').classList.contains('dash-off')")
        cls.page.evaluate("""async () => {
            _uiPrefs.dashboard = _dashLayout().map(e => ({key: e.key, on: e.key === 'threatintel' ? true : e.on, size: e.size}));
            await loadHome();
        }""")
        cls.page.wait_for_selector('#home-w-threatintel:not(.dash-off)', timeout=20000)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def drawn(self):
        """The widget as drawn: the big number, the rows by label, whether there is a link."""
        return self.page.evaluate("""() => {
            const b = document.getElementById('home-w-threatintel-body');
            const rows = {};
            b.querySelectorAll('.dash-mini-row').forEach(r => { rows[r.querySelector('.dm-l').textContent.trim()] = r.querySelector('.dm-r').textContent.trim(); });
            const big = b.querySelector('.dash-big');
            return {big: big ? big.textContent.trim() : null, rows, link: !!b.querySelector('[data-action=showPage][data-arg=ipintel]'),
                    text: b.innerText};
        }""")

    def expected(self, slack=0):
        """What the page behind the widget holds, counted by the widget's rules, for the 24 hours ending `slack` seconds from now."""
        d = self.page.evaluate("async () => await api('GET', '/ip-intel?limit=5000')")
        self.assertEqual(d['attackers_total'], len(d['attackers']), 'the whole table was read')
        now = time.time() + slack
        since = now - 86400
        told = lambda a: any(isinstance(t, (int, float)) and t >= since for t in (a.get('reported') or {}).values())  # noqa: E731
        problems = sum(1 for s in d['sensors'] if any(x.get('state') in PROBLEM_SOURCES for x in s.get('sources') or []))
        edge = d.get('edge') or {}
        problems += sum(1 for k in ('cf', 'trap') if (edge.get(k) or {}).get('state') in PROBLEM_FEEDS)
        return {'seen': sum(1 for a in d['attackers'] if (a.get('last_seen') or 0) >= since),
                'reported': sum(1 for a in d['attackers'] if told(a)),
                'blocked': sum(1 for b in d['blocks'] if (b.get('until') or 0) > now), 'problems': problems}

    def test_it_is_not_on_until_it_is_added(self):
        self.assertTrue(self.off_at_first, 'an add-on widget is hidden in a layout that has never named it')

    def test_it_shows_what_the_page_behind_it_holds(self):
        got = self.drawn()
        # the card is drawn a moment after the page was asked: the 24 hours it counted end between now and then
        lo, hi = self.expected(slack=-120), self.expected(slack=+120)
        self.assertGreater(hi['seen'], 0, 'the demo has addresses: the control that the card is not counting nothing')
        self.assertTrue(lo['seen'] <= int(got['big']) <= hi['seen'] or hi['seen'] <= int(got['big']) <= lo['seen'], (got, lo, hi))
        self.assertTrue(min(lo['reported'], hi['reported']) <= int(got['rows']['Reported in 24 hours']) <= max(lo['reported'], hi['reported']), (got, lo, hi))
        self.assertTrue(min(lo['blocked'], hi['blocked']) <= int(got['rows']['Blocked now']) <= max(lo['blocked'], hi['blocked']), (got, lo, hi))
        if hi['problems']:
            self.assertEqual(int(got['rows']['Sources in trouble']), hi['problems'])
        else:
            self.assertNotIn('Sources in trouble', got['rows'])

    def test_the_link_opens_the_page(self):
        self.assertTrue(self.drawn()['link'])
        self.page.click('#home-w-threatintel [data-action=showPage][data-arg=ipintel]')
        self.page.wait_for_selector('#page-ipintel.active', timeout=15000)
        self.page.evaluate("() => showPage('home')")
        self.page.wait_for_selector('#page-home.active')

    def test_the_card_names_itself_and_says_what_it_counts(self):
        text = self.drawn()['text']
        for words in ('addresses seen in the last 24 hours', 'Reported in 24 hours', 'Blocked now', 'Open Threat Intel'):
            self.assertIn(words, text)
        self.assertEqual(self.page.inner_text('#home-w-threatintel .section-title'), 'Threat Intel')

    def test_every_word_of_the_card_has_a_translation(self):
        page = self.page
        assert page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'
        try:
            for lang in page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')"):
                page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for key in ('Threat Intel', 'addresses seen in the last 24 hours', 'Reported in 24 hours', 'Blocked now',
                            'Open Threat Intel →', 'Sources in trouble', 'Threat Intel is off.'):
                    self.assertNotEqual(page.evaluate("(k) => RPi18n.t(k)", key), key, '%s: %r has no entry' % (lang, key))
                last = []

                def probe():
                    nonlocal last
                    last = page.evaluate("""() => {
                        const out = [], w = document.createTreeWalker(document.getElementById('home-w-threatintel'), NodeFilter.SHOW_TEXT);
                        for (let n = w.nextNode(); n; n = w.nextNode()) {
                            const t = n.nodeValue.trim();
                            if (t && n.parentElement.offsetParent !== null && RPi18n.t(t) !== t) out.push(t);
                        }
                        return out; }""")
                    return not last
                _until(probe, seconds=4, step=0.2)
                self.assertEqual(last, [], '%s: text on the card that the dictionary would have translated' % lang)
        finally:
            page.evaluate("() => RPi18n.setLang('en', false)")

    def _with_datum(self, datum):
        """The card as drawn when the server's answer carries `datum` for it (None: no datum at all)."""
        page = self.page

        def rewrite(route):
            resp = route.fetch()
            body = resp.json()
            if datum is None:
                body.get('widgets', {}).pop('threatintel', None)
            else:
                body.setdefault('widgets', {})['threatintel'] = datum
            route.fulfill(response=resp, json=body)
        page.route('**/api/home*', rewrite)
        try:
            page.evaluate("async () => { await loadHome(); }")
            return self.drawn()
        finally:
            page.unroute('**/api/home*')
            page.evaluate("async () => { await loadHome(); }")

    def test_a_host_with_nothing_in_trouble_has_no_row_that_says_so(self):
        got = self._with_datum({'on': True, 'seen': 3, 'reported': 1, 'blocked': 2, 'problems': 0})
        self.assertEqual((got['big'], got['rows']), ('3', {'Reported in 24 hours': '1', 'Blocked now': '2'}))
        got = self._with_datum({'on': True, 'seen': 0, 'reported': 0, 'blocked': 0, 'problems': 4})
        self.assertEqual((got['big'], got['rows']['Sources in trouble']), ('0', '4'))

    def test_it_says_when_threat_intel_is_off_and_when_it_has_no_answer(self):
        off = self._with_datum({'on': False})
        self.assertIn('Threat Intel is off.', off['text'])
        self.assertFalse(off['link'] or off['big'])
        none = self._with_datum(None)
        self.assertNotIn('Threat Intel is off.', none['text'], 'no answer is not the same as off')
        self.assertIn('Nothing to show.', none['text'])
        empty = self._with_datum({})
        self.assertNotIn('Threat Intel is off.', empty['text'])

    def test_the_page_threw_nothing(self):
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
