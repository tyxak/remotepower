#!/usr/bin/env python3
"""Password history and maximum age: the Settings fields and the banner, measured in a browser.

The server half (what the two settings do, through the real routes) is in test_password_history_max_age. This module holds what a person
sees and can do, on the demo seed, in one Chromium session:

* the two fields under Settings > Security > Password policy: they read what is stored (0 = off), save through the page's own Save button,
  refuse a number past their limit with the server's sentence and save nothing, and are reached by keyboard with the visible focus ring;
* English, German and Arabic (right to left): the labels and the hint translate and nothing runs off the screen, at 1440, 768 and 390 px;
* no console error, no failed request and no 4xx or 5xx answer that the page was not meant to get;
* the banner of a password that has expired says so ("Your password has expired"), and an account on a default password still gets the
  banner it always had; clicking either opens the change form.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
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

import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a failure, so it is part of the class condition
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
DAY = 86400
PASSWORD = 'Banner-Passw0rd!x1'

HINT = ("Applied to new users and password changes. The length and character rules never invalidate a password someone already has; "
        "the maximum age does, at that person's next sign-in. Every rule is off until you set it.")
LABEL_HISTORY = "Passwords remembered (0 = off, at most 24). At 3, a new password cannot be the one in use now or either of the two before it"
LABEL_AGE = ("Maximum password age in days (0 = off, at most 3650). A local password older than this has to be changed at the next sign-in. "
             "Accounts that sign in through LDAP, OIDC or SAML are not affected")
REFUSAL = 'The value must be a whole number within the range this setting allows.'


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the settings page is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-pwpolicy-e2e-')
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
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()
        shutil.rmtree(_STATE.get('data_dir', ''), ignore_errors=True)


def _record_failed_request(problems, r):
    """Keep a failed request. One the page cancelled itself (a poll it replaced, a fetch it gave up on as the view changed) is aborted,
    which is not a failure of anything, and is left out."""
    if 'ERR_ABORTED' not in str(r.failure):
        problems.append('request failed: %s %s' % (r.url[-80:], r.failure))


def _context(width, height):
    ctx = _STATE['browser'].new_context(viewport={'width': width, 'height': height}, service_workers='block')
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                        "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    problems = []
    page.on('pageerror', lambda e: problems.append('pageerror: %s' % str(e)[:300]))
    page.on('console', lambda m: problems.append('console error: %s' % m.text[:300]) if m.type == 'error' else None)
    page.on('requestfailed', lambda r: _record_failed_request(problems, r))
    page.on('response', lambda r: problems.append('HTTP %d: %s' % (r.status, r.url[-80:])) if r.status >= 400 else None)
    page.goto(_STATE['base'] + '/index.html')
    return ctx, page, problems


def _sign_in(page, user, password):
    page.fill('#login-user', user)
    page.fill('#login-pass', password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)


def _signed_in_context(width, height):
    ctx, page, problems = _context(width, height)
    _sign_in(page, 'alice', 'demo')                      # the seeder builds its own operator accounts: there is no 'admin'
    problems.clear()                                     # what the sign-in itself asked for is not what is measured here
    return ctx, page, problems


def _until(fn, seconds=20, step=0.25):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(step)
    return last


def _api(page, method, path, body=None):
    """The page's own api() helper, so the session and the way it reads an answer are the ones a person gets."""
    return page.evaluate("async ([m, p, b]) => b === null ? await api(m, p) : await api(m, p, b)", [method, path, body])


def _cfg(page):
    return _api(page, 'GET', '/config')


def _off(page):
    _api(page, 'POST', '/config', {'password_history': 0, 'password_max_age_days': 0})


def _open_security(page):
    page.evaluate("showPage('settings')")
    page.evaluate("switchSettingsTab('security')")
    page.wait_for_selector('#cfg-pw-history', state='visible', timeout=30000)
    # the page fills the fields when it has read the settings: wait for it to have (the stored value is 0 or a number, never blank)
    page.wait_for_function("() => document.getElementById('cfg-pw-min-length').value !== undefined && document.getElementById('cfg-pw-history').value !== ''",
                           timeout=30000)


def _save(page):
    """Click the page's own Save. Saving the whole form can touch a switch that needs a fresh check of the password (the page asks, then
    sends the save again); answer it as a person would."""
    page.click('#btn-save-settings')
    try:
        page.wait_for_selector('#step-up-modal.active', timeout=6000)
    except Exception:
        return
    page.fill('#step-up-password', 'demo')
    page.click('#step-up-modal [data-action="stepUpSubmit"]')
    page.wait_for_selector('#step-up-modal:not(.active)', state='attached', timeout=20000)


def _without_the_step_up_question(problems):
    """The save the page makes before the password check is refused with a 403 that the page expects, and the browser logs it as an error too."""
    return [p for p in problems if '403' not in p]


_ROWS_JS = """() => {
  const vw = document.documentElement.clientWidth;
  const out = { page: document.documentElement.scrollWidth > vw + 1, rows: [] };
  for (const id of ['cfg-pw-history', 'cfg-pw-max-age']) {
    const el = document.getElementById(id), row = el.closest('.settings-row'), lab = row.querySelector('label');
    const r = row.getBoundingClientRect(), ri = el.getBoundingClientRect();
    out.rows.push({ id, right: Math.round(r.right), left: Math.round(r.left), inputRight: Math.round(ri.right), inputLeft: Math.round(ri.left),
                    labelSpill: lab.scrollWidth > lab.clientWidth + 1, vw });
  }
  return out;
}"""


def _assert_rows_inside(test, page, where):
    out = page.evaluate(_ROWS_JS)
    test.assertFalse(out['page'], 'the page scrolls sideways %s' % where)
    for r in out['rows']:
        test.assertLessEqual(r['right'], r['vw'] + 1, 'the row of %s runs off the right edge %s: %s' % (r['id'], where, r))
        test.assertGreaterEqual(r['left'], -1, 'the row of %s runs off the left edge %s: %s' % (r['id'], where, r))
        test.assertLessEqual(r['inputRight'], r['vw'] + 1, '%s runs off the right edge %s' % (r['id'], where))
        test.assertGreaterEqual(r['inputLeft'], -1, '%s runs off the left edge %s' % (r['id'], where))
        test.assertFalse(r['labelSpill'], 'the label of %s spills out of its box %s' % (r['id'], where))


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Base(unittest.TestCase):
    width = 1440
    height = 900
    lang = 'en'

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.problems = _signed_in_context(cls.width, cls.height)
        if cls.lang != 'en':
            # the account's saved language arrives with /api/me and is adopted when it does: switching before that is undone by it
            cls.page.wait_for_function("() => typeof _meCache !== 'undefined' && _meCache && _meCache.username", timeout=60000)
            cls.page.evaluate("async l => { await _ensureI18n(); RPi18n.setLang(l, false); }", cls.lang)
            assert cls.page.evaluate("() => RPi18n.current") == cls.lang, 'the language did not stay switched'

    @classmethod
    def tearDownClass(cls):
        try:
            _off(cls.page)
        finally:
            cls.ctx.close()

    def tearDown(self):
        self.page.keyboard.press('Escape')
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")
        _off(self.page)
        self.assertEqual(self.problems, [], 'the page reported: %s' % self.problems)


class TestSettingsFields(_Base):

    def test_the_fields_read_what_is_stored_and_the_defaults_read_as_off(self):
        page = self.page
        _open_security(page)
        for fid, top in (('cfg-pw-history', '24'), ('cfg-pw-max-age', '3650')):
            f = page.locator('#' + fid)
            self.assertEqual((f.get_attribute('type'), f.get_attribute('min'), f.get_attribute('max')), ('number', '0', top), fid)
            self.assertEqual(f.input_value(), '0', 'the default is off: ' + fid)
        self.assertEqual(page.inner_text('label[for=cfg-pw-history]'), LABEL_HISTORY)
        self.assertEqual(page.inner_text('label[for=cfg-pw-max-age]'), LABEL_AGE)
        self.assertIn(HINT, page.inner_text('#settings-pane-security'))
        self.assertEqual(_api(page, 'POST', '/config', {'password_history': 7, 'password_max_age_days': 120}).get('ok'), True)
        _open_security(page)
        page.reload()
        page.wait_for_selector('#app', state='visible', timeout=90000)
        self.problems.clear()
        _open_security(page)
        self.assertEqual((page.input_value('#cfg-pw-history'), page.input_value('#cfg-pw-max-age')), ('7', '120'))

    def test_the_save_button_stores_both_and_a_number_past_a_limit_is_refused_and_saves_nothing(self):
        page = self.page
        _open_security(page)
        page.fill('#cfg-pw-history', '3')
        page.fill('#cfg-pw-max-age', '45')
        _save(page)
        self.assertTrue(_until(lambda: (_cfg(page).get('password_history'), _cfg(page).get('password_max_age_days')) == (3, 45), 20),
                        'the page did not save: %s' % _cfg(page))
        before = _cfg(page)
        page.fill('#cfg-pw-history', '99')
        page.fill('#cfg-pw-max-age', '60')
        # a toast is gone a few seconds after it appears, and the save is answered while the step-up question is still being waited for
        page.evaluate("""() => { window.__toasts = [];
          new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(n => { if (n.classList && n.classList.contains('toast')) window.__toasts.push(n.innerText); })))
            .observe(document.getElementById('toast-container'), { childList: true }); }""")
        _save(page)
        toast_text = _until(lambda: ' | '.join(page.evaluate("() => window.__toasts")), 15)
        self.assertIn(REFUSAL, toast_text or '', 'the page did not show the server\'s sentence')
        after = _cfg(page)
        self.assertEqual((after['password_history'], after['password_max_age_days']), (before['password_history'], before['password_max_age_days']),
                         'a refused save stored one of its keys')
        # the refusal was an answer the page asked for: it is the one 400 of this test (and the step-up question's 403 before it)
        self.assertEqual(len([p for p in self.problems if p.startswith('HTTP 400')]), 1, self.problems)
        self.assertEqual([p for p in self.problems if '403' not in p and not p.startswith('HTTP 400') and 'status of 400' not in p], [], self.problems)
        self.problems.clear()

    def test_the_keyboard_reaches_both_fields_in_order_with_a_visible_ring(self):
        page = self.page
        _open_security(page)
        page.focus('#cfg-pw-breach')
        page.keyboard.press('Tab')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'cfg-pw-history')
        ring = "() => { const cs = getComputedStyle(document.activeElement); return cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1; }"
        self.assertTrue(page.evaluate(ring), 'the first field has no visible focus ring')
        page.keyboard.press('Tab')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'cfg-pw-max-age')
        self.assertTrue(page.evaluate(ring), 'the second field has no visible focus ring')


class _Layout:
    def test_the_rows_draw_inside_the_screen(self):
        page = self.page
        _open_security(page)
        page.fill('#cfg-pw-history', '24')
        page.fill('#cfg-pw-max-age', '3650')
        _assert_rows_inside(self, page, 'at %d px in %s' % (self.width, self.lang))


class TestDesktopLayout(_Layout, _Base):
    width, height = 1440, 900


class TestTabletLayout(_Layout, _Base):
    width, height = 768, 1024


class TestPhoneLayout(_Layout, _Base):
    width, height = 390, 800


class _Language(_Layout):
    rtl = False

    def reads(self, selector, expected, seconds=20):
        page = self.page
        ok = _until(lambda: page.inner_text(selector) == expected, seconds, 0.2)
        self.assertTrue(ok, '%s reads %r in %s, expected %r' % (selector, page.inner_text(selector), self.lang, expected))

    def tr(self, s):
        out = self.page.evaluate("s => RPi18n.t(s)", s)
        self.assertNotEqual(out, s, 'not translated into %s: %s' % (self.lang, s))
        return out

    def test_the_labels_and_the_hint_translate(self):
        page = self.page
        self.assertEqual(page.evaluate("() => document.documentElement.dir"), 'rtl' if self.rtl else 'ltr')
        _open_security(page)
        self.reads('label[for=cfg-pw-history]', self.tr(LABEL_HISTORY))
        self.reads('label[for=cfg-pw-max-age]', self.tr(LABEL_AGE))
        ok = _until(lambda: self.tr(HINT) in page.inner_text('#settings-pane-security'), 20, 0.2)
        self.assertTrue(ok, 'the hint is not translated in %s' % self.lang)


class TestGerman(_Language, _Base):
    lang = 'de'


class TestArabic(_Language, _Base):
    lang = 'ar'
    rtl = True


class TestArabicPhone(_Language, _Base):
    lang = 'ar'
    rtl = True
    width, height = 390, 800


class TestGermanPhone(_Language, _Base):
    lang = 'de'
    width, height = 390, 800


# ── the banner ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _make_account(page, name, expired_days=None, must_change=False):
    """An account with a known password, made through the page's own API, then (for an old password) aged on disk, the way a year does."""
    st = _api(page, 'POST', '/users', {'username': name, 'password': PASSWORD, 'role': 'viewer', 'must_change_password': must_change})
    assert st.get('ok'), st
    if expired_days is not None:
        path = Path(_STATE['data_dir']) / 'users.json'
        users = json.loads(path.read_text())
        users[name]['password_changed_at'] = int(time.time()) - expired_days * DAY
        path.write_text(json.dumps(users))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheBanner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.problems = _signed_in_context(1440, 900)

    @classmethod
    def tearDownClass(cls):
        try:
            _off(cls.page)
        finally:
            cls.ctx.close()

    def tearDown(self):
        _off(self.page)

    def _sign_in_as(self, name):
        ctx, page, problems = _context(1440, 900)
        _sign_in(page, name, PASSWORD)
        return ctx, page, problems

    def test_an_expired_password_says_so_and_the_banner_opens_the_change_form(self):
        _api(self.page, 'POST', '/config', {'password_max_age_days': 30})
        _make_account(self.page, 'aged-user', expired_days=45)
        ctx, page, problems = self._sign_in_as('aged-user')
        try:
            page.wait_for_selector('#default-pw-banner', state='visible', timeout=30000)
            text = page.inner_text('#default-pw-banner')
            self.assertIn('Your password has expired.', text)
            self.assertNotIn('default password', text)
            # German: the banner's own sentences are in the dictionary
            page.evaluate("async () => { await _ensureI18n(); RPi18n.setLang('de', false); }")
            self.assertTrue(_until(lambda: 'Ihr Passwort ist abgelaufen' in page.inner_text('#default-pw-banner'), 20, 0.2),
                            'the banner is not translated: %r' % page.inner_text('#default-pw-banner'))
            page.evaluate("() => RPi18n.setLang('en', false)")
            # the banner takes the person to the Password section of My Account, and its button opens the form
            page.click('#default-pw-banner')
            page.wait_for_selector('#account-password-section', state='visible', timeout=15000)
            page.click('#acct-passwd-btn')
            page.wait_for_selector('#passwd-modal.active', timeout=15000)
            page.fill('#passwd-old', PASSWORD)
            page.fill('#passwd-new', 'Fresh-Passw0rd!y2')
            page.click('#passwd-modal [data-action="submitPasswd"]')
            self.assertTrue(_until(lambda: _api(page, 'GET', '/me').get('must_change_password') is False, 20),
                            'the change did not lift the gate: %s' % _api(page, 'GET', '/me'))
            me = _api(page, 'GET', '/me')
            self.assertFalse(me.get('password_expired'), me)
            page.wait_for_selector('#default-pw-banner', state='hidden', timeout=15000)       # the banner that asked for the change goes with it
            bad = _without_the_step_up_question(problems)       # every route but the change answers 403 while the gate is up (the browser logs each as an error too)
            self.assertEqual(bad, [], 'the page reported: %s' % bad)
        finally:
            ctx.close()

    def test_a_default_password_keeps_the_banner_it_always_had(self):
        _make_account(self.page, 'fresh-user', must_change=True)
        ctx, page, problems = self._sign_in_as('fresh-user')
        try:
            page.wait_for_selector('#default-pw-banner', state='visible', timeout=30000)
            text = page.inner_text('#default-pw-banner')
            self.assertIn('This account is using the default password.', text)
            self.assertNotIn('expired', text)
        finally:
            ctx.close()

    def test_a_password_inside_the_limit_gets_no_banner(self):
        _api(self.page, 'POST', '/config', {'password_max_age_days': 30})
        _make_account(self.page, 'young-user', expired_days=5)
        ctx, page, problems = self._sign_in_as('young-user')
        try:
            page.wait_for_selector('#app', state='visible', timeout=30000)
            page.wait_for_timeout(1500)
            self.assertFalse(page.is_visible('#default-pw-banner') if page.query_selector('#default-pw-banner') else False)
            self.assertEqual(_without_the_step_up_question(problems), [], problems)      # a viewer is refused a few admin routes with a 403 by design
        finally:
            ctx.close()


class _Req:
    """What a browser hands the listener of a failed request: its url and the reason."""

    def __init__(self, url, failure):
        self.url, self.failure = url, failure


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheInstrument(unittest.TestCase):
    """Every test above ends by asking whether the page reported a problem, so an empty list is believed only after the list has been seen
    to fill: a failed request, a console error and a 404 are recorded, and a request the page cancelled itself is not."""

    def test_a_cancelled_request_is_left_out_and_any_other_failure_is_kept(self):
        seen = []
        _record_failed_request(seen, _Req('http://host/api/nav-counts', 'net::ERR_ABORTED'))
        self.assertEqual(seen, [], 'a request the page cancelled was kept')
        for why in ('net::ERR_CONNECTION_REFUSED', 'net::ERR_CONNECTION_RESET', 'net::ERR_TIMED_OUT', 'net::ERR_FAILED', None):
            _record_failed_request(seen, _Req('http://host/api/nav-counts', why))
        self.assertEqual(len(seen), 5, seen)

    def test_the_page_level_list_records_a_failed_request_a_console_error_and_a_404(self):
        ctx, page, problems = _signed_in_context(1440, 900)
        try:
            page.evaluate("""async () => {
              await fetch('http://127.0.0.1:9/control-unreachable', {mode: 'no-cors'}).catch(() => {});
              await fetch('/api/control-not-a-route').catch(() => {});
              console.error('control: a console error');
            }""")
            _until(lambda: any('control-not-a-route' in p for p in problems) and any('control-unreachable' in p for p in problems), 10)
            self.assertTrue(any(p.startswith('request failed: ') and 'control-unreachable' in p for p in problems), problems)
            self.assertTrue(any(p.startswith('HTTP 404') and 'control-not-a-route' in p for p in problems), problems)
            self.assertIn('console error: control: a console error', problems)
        finally:
            ctx.close()


if __name__ == '__main__':
    unittest.main()
