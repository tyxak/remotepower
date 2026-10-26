#!/usr/bin/env python3
"""7.4.1, issue #41: what a script shows must really show, and what carries d-none must really hide.

Measured in a real browser on a seeded instance, with the controls a person uses:

  * The maintenance window form. Choosing "Recurring (cron)" must bring up the cron field and the
    duration, and editing a recurring window must show its cron text and its length in minutes.
    The row was hidden with `d-none` and shown with `style.display = ''`, which never shows it.
  * The other places that did the same: steps 2 and 3 of the ACME issue wizard, the Timeline and
    Logs tabs of the certificate dialog, the conversation tab of the IaC page, the file-path field
    and the two hints of the log rule dialog, and the "saved" badges beside the SMTP and LDAP
    passwords. Each is driven through the real buttons, radios and tabs.
  * A control that carries `d-none` must be drawn as nothing. On the released 7.3.0 the sign-in page
    showed the SSO, SAML and passkey buttons whether or not anything was configured, because a later
    `.login-btn-oidc { display: block }` outranked the plain `d-none`.
  * The census: no element with `d-none` or `hidden` and no inline display of its own is drawn, over
    the whole page after sign-in. The detector is shown an element made wrong on purpose.

The source half is test_v741_display_reveal. Self-skips without playwright/chromium/gunicorn.
"""
import json
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

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

_STACK = {}

_LOGIN_BUTTONS = ('login-oidc-btn', 'login-saml-btn', 'login-passkey-btn')

_SIGNIN_JS = """ids => Object.fromEntries(ids.map(id => {
    const e = document.getElementById(id);
    if (!e) return [id, null];
    const r = e.getBoundingClientRect();
    return [id, {dnone: e.classList.contains('d-none'), display: getComputedStyle(e).display,
                 w: Math.round(r.width), h: Math.round(r.height)}];
}))"""

# Every element that carries d-none or hidden, has no inline display of its own and is drawn anyway.
_CENSUS_JS = """() => {
    const bad = [];
    let total = 0;
    for (const el of document.querySelectorAll('.d-none, .hidden')) {
        total++;
        if (el.style.display !== '') continue;           // shown or hidden by a script on purpose
        if (getComputedStyle(el).display !== 'none') {
            const p = el.parentElement;
            bad.push((el.id ? '#' + el.id : el.tagName.toLowerCase()) + '.' + String(el.className).split(/\\s+/).join('.')
                     + (p ? '  in ' + String(p.className).split(/\\s+/).join('.') : ''));
        }
    }
    return {total, bad};
}"""


def setUpModule():
    """One seeded instance, one browser, one page: the sign-in page is measured first, then the page
    signs in as an account the seeder makes."""
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('what is measured is the page, not the backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-hidden-')
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
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f'app stack not available: {exc}')
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    page.set_default_timeout(15000)
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    page.goto(base + '/index.html')
    page.wait_for_selector('#login-form', state='visible', timeout=90000)
    page.wait_for_timeout(2500)            # the sign-in page asks which methods are on, then reveals them
    signin = page.evaluate(_SIGNIN_JS, list(_LOGIN_BUTTONS))
    page.fill('#login-user', 'alice')
    page.fill('#login-pass', 'demo')
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, signin=signin,
                  data_dir=data_dir)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK['browser'].close()
        _STACK['pw'].stop()
    finally:
        _STACK['shutdown']()
        _STACK.clear()


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.page = _STACK['page']
        cls.base = _STACK['base']

    def go(self, name, wait=1200):
        self.page.evaluate("n => showPage(n)", name)
        self.page.wait_for_timeout(wait)

    def display(self, sel):
        """The element's own computed display: right for an element inside a pane or dialog that is
        not the one on screen, where is_visible() would answer for the ancestor."""
        return self.page.evaluate("s => getComputedStyle(document.querySelector(s)).display", sel)

    def shown(self, sel):
        return self.display(sel) != 'none'

    def visible(self, sel):
        return self.page.locator(sel).first.is_visible()


class TestSignInPage(_Base):

    def test_a_button_that_carries_d_none_is_not_drawn(self):
        info = _STACK['signin']
        self.assertEqual(sorted(info), sorted(_LOGIN_BUTTONS))
        self.assertTrue(all(info.values()), 'a sign-in button is missing from the page: %s' % info)
        carrying = {k: v for k, v in info.items() if v['dnone']}
        # the seeded instance has no single sign-on, so a button that is still hidden by class is
        # what this measures; if every one had been revealed there would be nothing to look at
        self.assertTrue(carrying, 'no sign-in button carries d-none on the seeded instance: %s' % info)
        drawn = {k: v for k, v in carrying.items() if v['display'] != 'none' or v['w'] or v['h']}
        self.assertEqual(drawn, {}, 'a hidden sign-in button is drawn: %s' % drawn)


    def sign_in_page_with(self, **flags):
        """A fresh sign-in page whose public-info reply says which methods are on."""
        page = _STACK['browser'].new_page(viewport={'width': 1440, 'height': 900})
        page.set_default_timeout(15000)

        def patch(route):
            resp = route.fetch()
            info = resp.json()
            info.update(flags)
            route.fulfill(response=resp, body=json.dumps(info))
        page.route('**/api/public-info', patch)
        try:
            page.goto(self.base + '/index.html')
            page.wait_for_selector('#login-form', state='visible', timeout=60000)
            page.wait_for_timeout(2500)
            return page.evaluate(_SIGNIN_JS, list(_LOGIN_BUTTONS)), page.evaluate(
                "() => getComputedStyle(document.getElementById('login-sso-divider')).display")
        finally:
            page.close()

    def test_a_method_the_server_turns_on_still_shows_its_button(self):
        """The rule that keeps a hidden button hidden must not keep a revealed one hidden: the page
        removes d-none when public-info says the method is on."""
        info, divider = self.sign_in_page_with(oidc_enabled=True, saml_enabled=True, webauthn_enabled=True)
        for name, state in info.items():
            with self.subTest(button=name):
                self.assertFalse(state['dnone'], '%s kept d-none although the server turned it on' % name)
                self.assertNotEqual(state['display'], 'none')
                self.assertGreater(state['w'] * state['h'], 0)
        self.assertEqual(divider, 'flex', 'the divider above the extra sign-in methods is not shown')

    def test_with_every_method_off_none_is_drawn_and_neither_is_the_divider(self):
        info, divider = self.sign_in_page_with(oidc_enabled=False, saml_enabled=False, webauthn_enabled=False)
        for name, state in info.items():
            with self.subTest(button=name):
                self.assertEqual((state['display'], state['w'], state['h']), ('none', 0, 0))
        self.assertEqual(divider, 'none')

    def test_each_method_is_shown_on_its_own(self):
        for flag, button in (('oidc_enabled', 'login-oidc-btn'), ('saml_enabled', 'login-saml-btn'),
                             ('webauthn_enabled', 'login-passkey-btn')):
            with self.subTest(method=flag):
                flags = {'oidc_enabled': False, 'saml_enabled': False, 'webauthn_enabled': False, flag: True}
                info, _ = self.sign_in_page_with(**flags)
                drawn = sorted(k for k, v in info.items() if v['display'] != 'none')
                self.assertEqual(drawn, [button])


class TestMaintenanceWindowForm(_Base):
    """The report, #41: Type = "Recurring (cron)" showed neither the cron field nor the duration."""

    def setUp(self):
        self.go('maintenance', 1500)
        self.page.click('#page-maintenance button[data-action="openNewMaintModal"]')
        self.page.wait_for_selector('#new-maint-modal', state='visible')
        self.page.wait_for_timeout(500)

    def tearDown(self):
        self.page.evaluate("() => closeModal('new-maint-modal')")
        self.page.wait_for_timeout(200)

    def test_a_new_window_starts_as_a_one_shot(self):
        self.assertTrue(self.visible('#maint-oneshot-row'))
        self.assertTrue(self.visible('#maint-start'))
        self.assertFalse(self.visible('#maint-cron-row'))

    def test_recurring_brings_up_the_cron_field_and_the_duration(self):
        self.page.select_option('#maint-type', 'cron')
        self.page.wait_for_timeout(200)
        self.assertTrue(self.visible('#maint-cron-row'))
        self.assertTrue(self.visible('#maint-cron'), 'the cron expression field is not on screen')
        self.assertTrue(self.visible('#maint-duration'), 'the duration field is not on screen')
        self.assertFalse(self.visible('#maint-oneshot-row'))

    def test_one_shot_brings_back_the_dates_and_takes_the_cron_fields_away(self):
        self.page.select_option('#maint-type', 'cron')
        self.page.select_option('#maint-type', 'oneshot')
        self.page.wait_for_timeout(200)
        self.assertTrue(self.visible('#maint-start'))
        self.assertTrue(self.visible('#maint-end'))
        self.assertFalse(self.visible('#maint-cron-row'))
        self.assertFalse(self.visible('#maint-duration'))

    def test_the_fields_that_appeared_are_the_ones_that_are_saved(self):
        self.page.fill('#maint-reason', 'e2e recurring window')
        self.page.select_option('#maint-scope', 'global')
        self.page.select_option('#maint-type', 'cron')
        self.page.fill('#maint-cron', '0 3 * * SUN')
        self.page.fill('#maint-duration', '45')
        self.page.click('#new-maint-modal button[data-action="saveMaintenance"]')
        self.page.wait_for_selector('#new-maint-modal', state='hidden')
        saved = self.page.evaluate("""async () => {
            const r = await api('GET', '/maintenance');
            return (r.windows || r).find(w => w.reason === 'e2e recurring window') || null; }""")
        self.assertIsNotNone(saved, 'the window made from the form was not stored')
        self.assertEqual((saved['cron'], saved['duration']), ('0 3 * * SUN', 45 * 60))


class TestEditingARecurringWindow(_Base):

    def test_its_cron_and_length_are_on_screen_and_are_the_stored_ones(self):
        self.go('maintenance', 1500)
        win = self.page.evaluate("""async () => {
            const r = await api('GET', '/maintenance');
            return (r.windows || r).find(w => w.cron && w.duration) || null; }""")
        self.assertIsNotNone(win, 'the seeded instance has no recurring window to edit')
        row = self.page.locator('#page-maintenance tr', has_text=win['reason']).first
        row.locator('button[title="Edit"]').click()
        self.page.wait_for_selector('#new-maint-modal', state='visible')
        self.page.wait_for_timeout(500)
        try:
            self.assertTrue(self.visible('#maint-cron-row'))
            self.assertTrue(self.visible('#maint-cron'))
            self.assertTrue(self.visible('#maint-duration'))
            self.assertFalse(self.visible('#maint-oneshot-row'))
            self.assertEqual(self.page.input_value('#maint-cron'), win['cron'])
            self.assertEqual(self.page.input_value('#maint-duration'), str(round(win['duration'] / 60)))
        finally:
            self.page.evaluate("() => closeModal('new-maint-modal')")
            self.page.wait_for_timeout(200)


class TestTheAcmeIssueWizard(_Base):

    def test_each_step_and_its_buttons_show_in_turn(self):
        self.go('tls', 1500)
        self.page.wait_for_function(
            "() => typeof _acmeData !== 'undefined' && (_acmeData.devices || []).some(d => d.available)")
        self.page.click('button[data-action="acmeOpenIssue"]')
        self.page.wait_for_selector('#acme-issue-modal', state='visible')
        try:
            step = lambda n: '.acme-step[data-step="%d"]' % n          # noqa: E731
            self.assertTrue(self.visible(step(1)))
            self.assertFalse(self.visible(step(2)))
            self.assertFalse(self.visible('#acme-issue-back'))
            self.assertFalse(self.visible('#acme-issue-go'))
            self.page.fill('#acme-issue-domain', 'example.com')
            self.page.click('#acme-issue-next')
            self.assertTrue(self.visible(step(2)), 'step 2 is not on screen')
            self.assertFalse(self.visible(step(1)))
            self.assertTrue(self.visible('#acme-issue-back'))
            self.page.click('#acme-issue-next')
            self.assertTrue(self.visible(step(3)), 'step 3 is not on screen')
            self.assertFalse(self.visible('#acme-issue-next'))
            self.assertTrue(self.visible('#acme-issue-go'))
            self.page.click('#acme-issue-back')
            self.assertTrue(self.visible(step(2)))
            self.assertFalse(self.visible('#acme-issue-go'))
            self.assertTrue(self.visible('#acme-issue-next'))
        finally:
            self.page.evaluate("() => closeModal('acme-issue-modal')")
            self.page.wait_for_timeout(200)


class TestTheCertificateDialogTabs(_Base):

    def test_timeline_and_logs_show_when_their_tab_is_chosen(self):
        self.go('tls', 1500)
        self.page.wait_for_function("() => typeof _acmeData !== 'undefined' && (_acmeData.devices || []).length > 0")
        self.page.evaluate("""() => { const d = _acmeData.devices.find(x => x.available) || _acmeData.devices[0];
                                      acmeOpenDetail(d.device_id, 'demo.lab'); }""")
        self.page.wait_for_selector('#acme-detail-modal', state='visible')
        try:
            self.assertTrue(self.visible('#acme-detail-overview'))
            for tab in ('timeline', 'logs'):
                self.page.click('#acme-tab-btn-' + tab)
                self.page.wait_for_timeout(150)
                self.assertTrue(self.visible('#acme-detail-' + tab), 'the %s pane is not on screen' % tab)
                for other in ('overview', 'timeline', 'logs'):
                    if other != tab:
                        self.assertFalse(self.visible('#acme-detail-' + other))
            self.page.click('#acme-tab-btn-overview')
            self.page.wait_for_timeout(150)
            self.assertTrue(self.visible('#acme-detail-overview'))
        finally:
            self.page.evaluate("() => closeModal('acme-detail-modal')")
            self.page.wait_for_timeout(200)


class TestTheIacPage(_Base):

    def test_the_conversation_tab_shows_its_pane(self):
        self.go('iac', 1500)
        self.page.click('#iac-tab-btn-convo')
        self.assertTrue(self.shown('#iac-convo-output'), 'the conversation pane is not shown')
        self.assertFalse(self.shown('#iac-code-output'))
        self.page.click('#iac-tab-btn-code')
        self.assertTrue(self.shown('#iac-code-output'))
        self.assertFalse(self.shown('#iac-convo-output'))

    def test_the_status_line_shows_with_a_message_and_goes_without_one(self):
        self.go('iac', 1500)
        self.page.evaluate("() => _iacStatus('Working', '')")
        self.assertTrue(self.shown('#iac-status'))
        self.page.evaluate("() => _iacStatus('', '')")
        self.assertFalse(self.shown('#iac-status'))
        self.page.evaluate("() => _iacStatus('Done', 'done')")
        self.assertTrue(self.shown('#iac-status'))
        self.page.evaluate("() => _iacStatus('', '')")


class TestTheLogRuleDialog(_Base):

    def open_rule_dialog(self, tab):
        self.go('logs', 2000)
        self.page.evaluate("t => { logsRulesTab = t; }", tab)
        self.page.click('#page-logs button[data-action="openAddRuleModal"]')
        self.page.wait_for_selector('#log-rule-modal', state='visible')
        self.page.wait_for_timeout(300)

    def close(self):
        self.page.evaluate("() => closeModal('log-rule-modal')")
        self.page.wait_for_timeout(200)

    def test_the_file_path_field_appears_when_a_file_is_chosen(self):
        self.open_rule_dialog('device')
        try:
            self.assertTrue(self.visible('#log-rule-unit-row'))
            self.assertFalse(self.visible('#log-rule-path-row'))
            self.page.check('input[name="log-rule-source"][value="path"]')
            self.page.wait_for_timeout(200)
            self.assertTrue(self.visible('#log-rule-path-row'), 'the file path field is not on screen')
            self.assertFalse(self.visible('#log-rule-unit-row'))
            self.page.check('input[name="log-rule-source"][value="unit"]')
            self.page.wait_for_timeout(200)
            self.assertTrue(self.visible('#log-rule-unit-row'))
            self.assertFalse(self.visible('#log-rule-path-row'))
        finally:
            self.close()

    def test_the_fleet_wide_hints_show_for_a_fleet_wide_rule_only(self):
        self.open_rule_dialog('global')
        try:
            self.assertTrue(self.visible('#log-rule-global-hint'), 'the fleet-wide hint is not on screen')
            self.assertTrue(self.visible('#log-rule-unit-hint'), 'the unit hint is not on screen')
            self.assertFalse(self.visible('#log-rule-device-row'))
        finally:
            self.close()
        self.open_rule_dialog('device')
        try:
            self.assertFalse(self.visible('#log-rule-global-hint'))
            self.assertFalse(self.visible('#log-rule-unit-hint'))
            self.assertTrue(self.visible('#log-rule-device-row'))
        finally:
            self.close()


class TestThePasswordBadges(_Base):
    """Settings shows "saved" beside the SMTP and LDAP passwords once one is stored. The settings
    reply is changed in the page so the loader sees a stored password; the badge is the real one."""

    def load_settings_with(self, flag):
        self.page.evaluate("""f => { window.__api = window.__api || window.api;
            window.api = async (m, p, b, o) => {
                const r = await window.__api(m, p, b, o);
                if (m === 'GET' && /^\\/config(\\?|$)/.test(p) && r && typeof r === 'object') {
                    r.smtp_password_set = f; r.ldap_bind_password_set = f; }
                return r; }; }""", flag)
        self.go('settings', 2000)
        self.page.evaluate("() => loadSettings()")
        self.page.wait_for_timeout(1500)

    def tearDown(self):
        self.page.evaluate("() => { if (window.__api) { window.api = window.__api; } }")

    def test_the_badges_show_when_a_password_is_stored_and_not_otherwise(self):
        self.load_settings_with(True)
        self.assertTrue(self.shown('#cfg-smtp-pw-set-badge'), 'the SMTP "saved" badge is not shown')
        self.assertTrue(self.shown('#cfg-ldap-pw-set-badge'), 'the LDAP "saved" badge is not shown')
        self.load_settings_with(False)
        self.assertFalse(self.shown('#cfg-smtp-pw-set-badge'))
        self.assertFalse(self.shown('#cfg-ldap-pw-set-badge'))


class TestHiddenMeansHidden(_Base):

    def census(self):
        return self.page.evaluate(_CENSUS_JS)

    def test_no_element_with_d_none_and_no_inline_display_is_drawn(self):
        r = self.census()
        # the sweep covers every dialog and every page, which are all in the document at load
        self.assertGreater(r['total'], 100, 'the census looked at %d elements' % r['total'])
        self.assertEqual(r['bad'], [], 'drawn although they carry d-none or hidden:\n  ' + '\n  '.join(r['bad']))

    def test_the_census_sees_an_element_made_wrong_on_purpose(self):
        """A planted d-none element that a rule forces to display:block must be reported."""
        self.page.evaluate("""() => {
            const d = document.createElement('div');
            d.id = 'planted-d-none'; d.className = 'd-none'; d.textContent = 'planted';
            document.body.appendChild(d);
            const s = document.createElement('style');
            s.id = 'planted-style'; s.textContent = '#planted-d-none { display: block; }';
            document.head.appendChild(s); }""")
        try:
            bad = self.census()['bad']
            self.assertTrue(any(b.startswith('#planted-d-none') for b in bad), bad)
        finally:
            self.page.evaluate("""() => { document.getElementById('planted-d-none').remove();
                                          document.getElementById('planted-style').remove(); }""")
        self.assertEqual(self.census()['bad'], [])

    def test_an_inline_display_still_shows_a_control_that_carries_d_none(self):
        """The reason the rule is not !important: a few controls (the delete button of the script
        dialog, the vault button) carry d-none and are shown by an inline display."""
        self.page.evaluate("""() => {
            const b = document.createElement('button');
            b.id = 'planted-btn'; b.className = 'btn-primary d-none'; b.textContent = 'x';
            const row = document.createElement('div');
            row.className = 'modal-actions'; row.id = 'planted-row'; row.appendChild(b);
            document.body.appendChild(row); }""")
        try:
            self.assertEqual(self.display('#planted-btn'), 'none', 'd-none on a modal-footer button does not hide it')
            self.page.evaluate("() => { document.getElementById('planted-btn').style.display = 'block'; }")
            self.assertEqual(self.display('#planted-btn'), 'block')
        finally:
            self.page.evaluate("() => document.getElementById('planted-row').remove()")


if __name__ == '__main__':
    unittest.main()
