#!/usr/bin/env python3
"""Hosts that can use it: the Enroll dialog and the Add a host wizard, measured in a browser.

The unit module (test_enroll_token_many_hosts) holds what the server does with `max_uses`. This one holds what a person sees and can do,
on the demo seed, in one Chromium session:

* the number field of the Enroll dialog and of the wizard's Settings step: its default (1), its limits (1 to 1000), the notice that shows
  only above 1, and a number that is not a whole number from 1 to 1000 stopping before any token is made;
* the token a page makes carries the number (read back from the server's own list), and the dialog's list of open install commands shows
  "used 2 of 4" after two hosts enrolled through the public endpoint, with a Revoke that stops the command at once;
* the sentence under a command says "one-time" only for a command that works once;
* the new elements at 1440, 768 and 390 px: no horizontal overflow, no console error, no failed request, no 4xx or 5xx answer;
* English, German and Arabic (right to left): the label, the notice and the list's words translate, and nothing overflows in either direction;
* a keyboard reaches the field and the Revoke button, with the visible focus ring, and Enter on Revoke asks before it does anything.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
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
_COUNTER = itertools.count(1)

# the strings of the new elements, in the languages the page is checked in (the dictionary is read from i18n.js, so a typo fails here)
LABEL = 'Hosts that can use it'
NOTE = 'Anyone who holds this command can enroll that many hosts until it expires. Revoking it stops it.'


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the dialog is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-enrol-many-e2e-')
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
        # the demo data dir is tmpfs: take it away with the stack
        import shutil
        shutil.rmtree(_STATE.get('data_dir', ''), ignore_errors=True)


def _signed_in_context(width, height):
    """A fresh browser context signed in as the demo operator, with every console error, page error, failed request and 4xx or 5xx answer kept."""
    ctx = _STATE['browser'].new_context(viewport={'width': width, 'height': height}, service_workers='block')
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                        "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    problems = []
    page.on('pageerror', lambda e: problems.append('pageerror: %s' % str(e)[:300]))
    page.on('console', lambda m: problems.append('console error: %s' % m.text[:300]) if m.type == 'error' else None)
    page.on('requestfailed', lambda r: problems.append('request failed: %s %s' % (r.url[-80:], r.failure)))
    page.on('response', lambda r: problems.append('HTTP %d: %s' % (r.status, r.url[-80:])) if r.status >= 400 else None)
    page.goto(_STATE['base'] + '/index.html')
    page.fill('#login-user', 'alice')                    # the seeder builds its own operator accounts: there is no 'admin'
    page.fill('#login-pass', 'demo')
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)
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


def _register(token):
    """Enrol a host through the public endpoint, the way the installer does. Returns the status."""
    name = 'many-host-%d' % next(_COUNTER)
    body = {'enrollment_token': token, 'hostname': name, 'name': name, 'os': 'Debian 12', 'ip': '10.1.2.3', 'version': '8.0.1'}
    req = urllib.request.Request(_STATE['base'] + '/api/enroll/register', data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    for attempt in (1, 2):
        try:
            r = urllib.request.urlopen(req, timeout=30)
            return r.status
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
            if code == 429 and attempt == 1:             # ten attempts a minute per address
                time.sleep(62)
                continue
            return code
    return 0


def _tokens(page, label=None):
    rows = _api(page, 'GET', '/enrollment-tokens')
    return [r for r in rows if label is None or r.get('label') == label]


_OVERFLOW_JS = """(sel) => {
  const root = document.querySelector(sel);
  const vw = document.documentElement.clientWidth;
  const bad = [];
  root.querySelectorAll('*').forEach(el => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    let p = el.parentElement, scrolls = false;                      // a box that scrolls on its own may hold something wider than itself
    while (p && p !== root.parentElement) {
      const cs = getComputedStyle(p);
      if (/(auto|scroll)/.test(cs.overflowX) && p.scrollWidth > p.clientWidth) { scrolls = true; break; }
      p = p.parentElement;
    }
    if (!scrolls && (r.right > vw + 1 || r.left < -1)) bad.push(el.tagName + '.' + el.className + '#' + el.id + ' ' + Math.round(r.left) + '..' + Math.round(r.right));
  });
  const modal = root.querySelector('.modal') || root;
  return { page: document.documentElement.scrollWidth > vw + 1, modal: modal.scrollWidth > modal.clientWidth + 1, bad: bad.slice(0, 8), vw };
}"""


def _assert_no_overflow(test, page, sel, where):
    out = page.evaluate(_OVERFLOW_JS, sel)
    test.assertFalse(out['page'], 'the page scrolls sideways %s: %s' % (where, out))
    test.assertFalse(out['modal'], 'the dialog scrolls sideways %s: %s' % (where, out))
    test.assertEqual(out['bad'], [], 'something runs off the screen %s: %s' % (where, out))
    # a box that scrolls on its own hides what runs off inside it from the walk above, so the list of open commands is held to its own rule:
    # its rows wrap, and the list does not need a sideways scrollbar
    inner = page.evaluate("() => { const b = document.getElementById('enroll-open-list'); return b ? [b.scrollWidth, b.clientWidth] : null; }")
    if inner is not None and sel == '#enroll-modal':
        test.assertLessEqual(inner[0], inner[1] + 1, 'the list of open install commands scrolls sideways %s: %s' % (where, inner))
        # and no part of a row is wider than the box it sits in (text that spills over its neighbour does not widen the list)
        spill = page.evaluate("""() => [...document.querySelectorAll('#enroll-open-list .enroll-open-row > *')]
            .filter(e => e.clientWidth > 0 && e.scrollWidth > e.clientWidth + 1).map(e => e.className + ' ' + e.scrollWidth + '>' + e.clientWidth)""")
        test.assertEqual(spill, [], 'part of a row of the open install commands spills out of its box %s' % where)


def _open_enroll_dialog(page):
    page.evaluate("showPage('devices')")
    page.click('button[data-action="openEnrollModal"]')
    page.wait_for_selector('#enroll-modal.active')
    page.wait_for_selector('#enroll-open-list .hint, #enroll-open-list .enroll-open-row', timeout=20000)    # the list has been drawn (it is fetched with its module)


def _open_wizard_settings(page, kind='linux'):
    page.evaluate("(n) => wizOpen(n)", 'enroll')
    page.wait_for_selector('#wizard-modal.active', timeout=15000)
    page.check('#wizard-modal input[name=wiz-kind][value=%s]' % kind)
    page.click('#wiz-next')
    page.wait_for_selector('#wiz-uses')


def _visible(page, sel):
    return page.is_visible(sel)


def _row_text(page, prefix_text=None):
    rows = page.eval_on_selector_all('#enroll-open-list .enroll-open-row', 'els => els.map(e => e.innerText.replace(/\\s+/g, " ").trim())')
    return [r for r in rows if prefix_text is None or prefix_text in r]


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
            # the dictionary is fetched when a language other than English is in play, not with the page
            cls.page.evaluate("async l => { await _ensureI18n(); RPi18n.setLang(l, false); }", cls.lang)
            assert cls.page.evaluate("() => RPi18n.current") == cls.lang, 'the language did not stay switched'

    @classmethod
    def tearDownClass(cls):
        try:
            cls.ctx.close()
        except Exception:                                # pragma: no cover
            pass

    def tearDown(self):
        # nothing from one test stays open for the next, and nothing in the page broke
        self.page.keyboard.press('Escape')
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")
        self.assertEqual(self.problems, [], 'the page reported: %s' % self.problems)


class TestEnrollDialog(_Base):

    def test_the_field_defaults_to_one_has_its_limits_and_the_notice_shows_above_one_only(self):
        page = self.page
        _open_enroll_dialog(page)
        f = page.locator('#enroll-max-uses')
        self.assertEqual((f.get_attribute('type'), f.input_value(), f.get_attribute('min'), f.get_attribute('max')), ('number', '1', '1', '1000'))
        self.assertEqual(page.inner_text('label[for=enroll-max-uses]'), LABEL)
        self.assertFalse(_visible(page, '#enroll-uses-note'), 'the warning is for more than one host')
        for value, shown in (('5', True), ('1', False), ('1000', True), ('', False), ('2', True)):
            f.fill(value)
            self.assertEqual(_visible(page, '#enroll-uses-note'), shown, 'value %r' % value)
        self.assertEqual(page.inner_text('#enroll-uses-note'), NOTE)
        f.fill('1')

    def test_a_number_that_is_not_a_whole_number_from_1_to_1000_stops_before_any_token_is_made(self):
        page = self.page
        _open_enroll_dialog(page)
        page.evaluate("() => { document.getElementById('enroll-quick-result').textContent = ''; document.getElementById('enroll-docker-result').textContent = ''; }")
        before = len(_tokens(page))
        for bad in ('0', '-3', '1001', '2.5', '99999999999'):
            page.fill('#enroll-max-uses', bad)
            page.click('button[data-action="generateQuickInstall"]')
            page.wait_for_selector('#enroll-max-uses[aria-invalid="true"]')
            self.assertEqual(page.evaluate("() => document.activeElement.id"), 'enroll-max-uses', 'the field takes the focus back: %r' % bad)
            self.assertEqual(page.inner_html('#enroll-quick-result').strip(), '', 'a command was printed for %r' % bad)
            page.click('button[data-action="generateDockerEnroll"]')
            self.assertEqual(page.inner_html('#enroll-docker-result').strip(), '', 'a compose file was printed for %r' % bad)
        self.assertEqual(len(_tokens(page)), before, 'a refused number made a token')
        page.fill('#enroll-max-uses', '1')

    def test_quick_install_for_four_hosts_counts_them_in_the_list_and_revoke_stops_it(self):
        page = self.page
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '4')
        page.click('button[data-action="generateQuickInstall"]')
        page.wait_for_selector('#enroll-quick-pre-0', timeout=30000)
        token = re.search(r'install\?t=([^"]+)"', page.inner_text('#enroll-quick-pre-0'))[1]
        mine = [t for t in _tokens(page, 'quick-install') if t['max_uses'] == 4]
        self.assertEqual(len(mine), 1, 'the token the page made carries the number the field had')
        self.assertEqual((mine[0]['uses'], mine[0]['uses_left']), (0, 4))
        self.assertNotIn('One-time', page.inner_text('#enroll-quick-result'), 'the sentence under the command says one-time for a command that is not')
        self.assertIn('works for the number of hosts you set', page.inner_text('#enroll-quick-result'))
        # the list shows it at once, and counts as hosts enrol with it
        row = _until(lambda: _row_text(page, 'used 0 of 4'))
        self.assertTrue(row, 'no row says used 0 of 4: %s' % _row_text(page))
        self.assertIn(mine[0]['prefix'], row[0])
        self.assertNotIn(token, page.inner_text('#enroll-open-list'), 'the list printed the token')
        self.assertEqual([_register(token), _register(token)], [201, 201])
        page.evaluate("enrolOpenList()")
        self.assertTrue(_until(lambda: _row_text(page, 'used 2 of 4')), 'the list did not count the two hosts: %s' % _row_text(page))
        # Revoke asks first, and then the command is dead
        page.locator('#enroll-open-list .enroll-open-row', has_text='used 2 of 4').locator('button[data-action="enrolRevoke"]').click()
        page.wait_for_selector('#ui-prompt-modal.active')
        page.keyboard.press('Escape')                                 # closing the question any way but its button is a No
        page.wait_for_selector('#ui-prompt-modal:not(.active)', state='attached')
        self.assertTrue([t for t in _tokens(page) if t['prefix'] == mine[0]['prefix']], 'cancelling the question revoked the command anyway')
        page.locator('#enroll-open-list .enroll-open-row', has_text='used 2 of 4').locator('button[data-action="enrolRevoke"]').click()
        page.wait_for_selector('#ui-prompt-modal.active')
        page.click('#ui-prompt-confirm')
        self.assertTrue(_until(lambda: not _row_text(page, 'used 2 of 4')), 'the row stayed after Revoke')
        self.assertEqual(_register(token), 403, 'a revoked command still enrols a host')

    def test_a_default_command_still_says_one_time_and_is_made_for_one_host(self):
        page = self.page
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '1')
        page.click('button[data-action="generateQuickInstall"]')
        page.wait_for_selector('#enroll-quick-pre-0', timeout=30000)
        self.assertIn('One-time token', page.inner_text('#enroll-quick-result'))
        mine = [t for t in _tokens(page, 'quick-install') if t['max_uses'] == 1]
        self.assertTrue(mine, 'the default token is made for one host')
        self.assertTrue(_until(lambda: _row_text(page, 'used 0 of 1')))

    def test_the_docker_compose_takes_the_number_too(self):
        page = self.page
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '3')
        page.click('button[data-action="generateDockerEnroll"]')
        page.wait_for_selector('#enroll-docker-pre', timeout=30000)
        self.assertEqual(len([t for t in _tokens(page, 'docker-host') if t['max_uses'] == 3]), 1)
        self.assertNotIn('one-time', page.inner_text('#enroll-docker-result'))
        page.fill('#enroll-max-uses', '1')

    def test_the_keyboard_reaches_the_field_and_revoke_with_a_ring_and_enter_on_revoke_asks_first(self):
        page = self.page
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '2')
        page.click('button[data-action="generateQuickInstall"]')
        page.wait_for_selector('#enroll-quick-pre-0', timeout=30000)
        self.assertTrue(_until(lambda: _row_text(page, 'used 0 of 2')))

        def tab_to(selector):
            page.evaluate("() => document.getElementById('enroll-modal').querySelector('.modal-title').setAttribute('tabindex', '-1')")
            page.focus('#enroll-modal .modal-title')
            for _ in range(80):
                page.keyboard.press('Tab')
                if page.evaluate("(s) => !!document.activeElement && document.activeElement.matches(s)", selector):
                    return
            self.fail('Tab never reached %s' % selector)

        def ring():
            return page.evaluate("""() => { const cs = getComputedStyle(document.activeElement);
                return cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1; }""")

        tab_to('#enroll-max-uses')
        self.assertTrue(ring(), 'the field has no visible focus ring')
        tab_to('#enroll-open-list button[data-action="enrolRevoke"]')
        self.assertTrue(ring(), 'Revoke has no visible focus ring')
        page.keyboard.press('Enter')
        page.wait_for_selector('#ui-prompt-modal.active')
        self.assertIn('Revoke this install command?', page.inner_text('#ui-prompt-message'))
        page.keyboard.press('Escape')
        page.wait_for_selector('#ui-prompt-modal:not(.active)', state='attached')
        # leave nothing open for the other tests
        for t in _tokens(page, 'quick-install'):
            _api(page, 'DELETE', '/enrollment-tokens/' + t['prefix'].rstrip('…'))
        page.fill('#enroll-max-uses', '1')


class _DialogLayout:
    """The dialog with a long list row and the notice showing, at one width."""

    def test_the_new_elements_draw_inside_the_screen(self):
        page = self.page
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '7')
        page.click('button[data-action="generateQuickInstall"]')
        page.wait_for_selector('#enroll-quick-pre-0', timeout=30000)
        self.assertTrue(_until(lambda: _row_text(page, 'used 0 of 7')))
        self.assertTrue(page.is_visible('#enroll-uses-note'))
        _assert_no_overflow(self, page, '#enroll-modal', 'at %d px' % self.width)
        for t in _tokens(page, 'quick-install'):
            _api(page, 'DELETE', '/enrollment-tokens/' + t['prefix'].rstrip('…'))
        page.fill('#enroll-max-uses', '1')


class TestDialogDesktopLayout(_DialogLayout, _Base):
    width, height = 1440, 900


class TestDialogTabletLayout(_DialogLayout, _Base):
    width, height = 768, 1024


class TestDialogPhoneLayout(_DialogLayout, _Base):
    width, height = 390, 800


class TestWizard(_Base):

    def test_the_settings_step_has_the_field_and_a_bad_number_stays_on_the_step(self):
        page = self.page
        _open_wizard_settings(page)
        f = page.locator('#wiz-uses')
        self.assertEqual((f.get_attribute('type'), f.input_value(), f.get_attribute('min'), f.get_attribute('max')), ('number', '1', '1', '1000'))
        self.assertEqual(page.inner_text('label[for=wiz-uses]'), LABEL)
        self.assertFalse(_visible(page, '#wiz-uses-note'))
        f.fill('12')
        self.assertTrue(_visible(page, '#wiz-uses-note'))
        self.assertEqual(page.inner_text('#wiz-uses-note'), NOTE)
        before = len(_tokens(page))
        for bad in ('0', '1001', '2.5', ''):
            f.fill(bad)
            page.click('#wiz-next')
            page.wait_for_function("() => document.getElementById('wiz-msg').textContent.length > 0")
            self.assertEqual(page.inner_text('#wiz-msg'), 'Enter a whole number of hosts from 1 to 1000')
            self.assertEqual(page.evaluate("() => document.getElementById('wiz-uses').getAttribute('aria-invalid')"), 'true')
            self.assertEqual(page.inner_text('.wiz-step.active .wiz-lbl'), 'Settings', 'a bad number moved the wizard on: %r' % bad)
        self.assertEqual(len(_tokens(page)), before)

    def test_a_number_above_one_is_in_the_token_and_the_install_step_says_so(self):
        page = self.page
        _open_wizard_settings(page)
        page.fill('#wiz-uses', '3')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-watch')
        self.assertIn('works for as many hosts as you set', page.inner_text('#wizard-modal .wiz-body'))
        self.assertNotIn('works once', page.inner_text('#wizard-modal .wiz-body'))
        token = re.search(r'install\?t=([^"]+)"', page.inner_text('#wiz-cmd-linux'))[1]
        mine = [t for t in _tokens(page, 'guided-add-host') if t['max_uses'] == 3]
        self.assertEqual(len(mine), 1)
        self.assertEqual([_register(token) for _ in range(3)], [201, 201, 201])
        self.assertEqual(_register(token), 403)
        page.keyboard.press('Escape')

    def test_the_default_is_one_and_the_install_step_says_it_works_once(self):
        page = self.page
        _open_wizard_settings(page)
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-watch')
        self.assertIn('The command works once', page.inner_text('#wizard-modal .wiz-body'))
        token = re.search(r'install\?t=([^"]+)"', page.inner_text('#wiz-cmd-linux'))[1]
        self.assertEqual([_register(token), _register(token)], [201, 403])
        page.keyboard.press('Escape')

    def test_the_field_is_reachable_by_keyboard_with_a_ring(self):
        page = self.page
        _open_wizard_settings(page)
        page.fill('#wiz-uses', '5')
        page.focus('#wiz-ttl')
        page.keyboard.press('Tab')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'wiz-uses', 'the field is not next after Valid for')
        self.assertTrue(page.evaluate("() => { const cs = getComputedStyle(document.activeElement); return cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1; }"))


class _WizardLayout:
    def test_the_settings_and_install_steps_draw_inside_the_screen(self):
        page = self.page
        _open_wizard_settings(page)
        page.fill('#wiz-uses', '5')
        self.assertTrue(page.is_visible('#wiz-uses-note'))
        _assert_no_overflow(self, page, '#wizard-modal', 'at %d px' % self.width)
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-watch')
        _assert_no_overflow(self, page, '#wizard-modal', 'at %d px (install step)' % self.width)
        page.keyboard.press('Escape')


class TestWizardDesktopLayout(_WizardLayout, _Base):
    width, height = 1440, 900


class TestWizardTabletLayout(_WizardLayout, _Base):
    width, height = 768, 1024


class TestWizardPhoneLayout(_WizardLayout, _Base):
    width, height = 390, 800


class _Language:
    """The same elements in another language. The expected text is what the page's own engine answers for the English sentence, and it has to
    differ from the English (a sentence missing from the dictionary comes back unchanged); tests/test_enroll_many_hosts_i18n.py holds the
    dictionary entries themselves, six languages each."""
    rtl = False

    def tr(self, s):
        out = self.page.evaluate("s => RPi18n.t(s)", s)
        self.assertNotEqual(out, s, 'not translated into %s: %s' % (self.lang, s))
        return out

    def reads(self, selector, expected, seconds=20):
        """The engine translates what a script draws on the next animation frame, so what is on screen is polled, not read at once."""
        page = self.page
        ok = _until(lambda: page.inner_text(selector) == expected, seconds, 0.2)
        self.assertTrue(ok, '%s reads %r in %s, expected %r' % (selector, page.inner_text(selector), self.lang, expected))

    def test_the_dialog_translates_and_nothing_runs_off_the_screen(self):
        page = self.page
        self.assertEqual(page.evaluate("() => document.documentElement.dir"), 'rtl' if self.rtl else 'ltr')
        _open_enroll_dialog(page)
        page.fill('#enroll-max-uses', '6')
        page.click('button[data-action="generateQuickInstall"]')
        page.wait_for_selector('#enroll-quick-pre-0', timeout=30000)
        self.assertTrue(_until(lambda: page.query_selector('#enroll-open-list .enroll-open-row')))
        self.reads('label[for=enroll-max-uses]', self.tr(LABEL))
        self.reads('#enroll-uses-note', self.tr(NOTE))
        used, of, revoke = self.tr('used'), self.tr('of'), self.tr('Revoke')

        def translated_row():
            return [r for r in _row_text(page) if used in r and of in r and revoke in r and ' 0 ' in (' ' + r + ' ') and ' 6' in (' ' + r)]

        self.assertTrue(_until(translated_row, 20, 0.2),
                        'the words of the list are not translated (%s, %s, %s): %s' % (used, of, revoke, _row_text(page)))
        _assert_no_overflow(self, page, '#enroll-modal', 'in %s at %d px' % (self.lang, self.width))
        for t in _tokens(page, 'quick-install'):
            _api(page, 'DELETE', '/enrollment-tokens/' + t['prefix'].rstrip('…'))
        page.fill('#enroll-max-uses', '1')

    def test_the_wizard_translates_and_nothing_runs_off_the_screen(self):
        page = self.page
        _open_wizard_settings(page)
        page.fill('#wiz-uses', '9')
        self.reads('label[for=wiz-uses]', self.tr(LABEL))
        self.reads('#wiz-uses-note', self.tr(NOTE))
        _assert_no_overflow(self, page, '#wizard-modal', 'in %s at %d px' % (self.lang, self.width))
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-watch')
        hint = self.tr('The command works for as many hosts as you set, and stops working after the time you chose or when you revoke it.')
        ok = _until(lambda: hint in page.inner_text('#wizard-modal .wiz-body'), 20, 0.2)
        self.assertTrue(ok, 'the install step does not carry the translated sentence in %s' % self.lang)
        _assert_no_overflow(self, page, '#wizard-modal', 'in %s at %d px (install step)' % (self.lang, self.width))
        page.keyboard.press('Escape')


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestGerman(_Language, _Base):
    lang = 'de'


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestArabic(_Language, _Base):
    lang = 'ar'
    rtl = True


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestArabicPhone(_Language, _Base):
    lang = 'ar'
    rtl = True
    width, height = 390, 800


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestGermanPhone(_Language, _Base):
    lang = 'de'
    width, height = 390, 800


if __name__ == '__main__':
    unittest.main()
