#!/usr/bin/env python3
"""Wizards: Add a host, Add a notification destination, and the step-by-step mode of four long forms.

One browser session on the demo seed holds all three (the stack takes about a minute to start, so they share it).

Add a host (8.0.0). Five kinds (Linux or macOS, Windows, Docker host, an interactive install with a PIN, a device that cannot run the agent),
the group, tags, network limit and lifetime that the one-time token carries (the token endpoint took all four since 7.4.9 and no page used
them), the command for the kind, and a wait that says when the host has checked in. The tests make the token through the page, read it
back from the server's own list, enrol a host with it through the public endpoint and watch the page notice.

Add a notification destination. The service, what that service needs (checked against the fields the editor in Settings draws for the
same format, a second implementation), a test whose answer is shown in the dialog, and what it should receive. The destination is a draft
that is switched off until the last step; a draft that never delivered is removed when the wizard is closed.

Step by step. The maintenance window, monitor, backup job and auto-patch policy dialogs open as before. A switch puts one into steps and
the choice is kept per browser. The tests derive the population from the page (every block of every form belongs to a step, every id a
step names exists), walk the steps, compare each refusal with the form's own message by running the form's own save in the one-form
mode, and save through the form's own button.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import itertools
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
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
_COUNTER = itertools.count(1)


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the wizards are backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-wizards-')
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


def _signed_in_context(width=1440, height=900, extra_init=''):
    """A fresh browser context signed in as the demo operator, with One long page chosen (a walk must see every card)."""
    ctx = _STATE['browser'].new_context(viewport={'width': width, 'height': height}, service_workers='block')
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                        "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {} " + extra_init)
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append('%s | %s' % (e, (getattr(e, 'stack', '') or '').replace('\n', ' <- ')[:400])))
    page.goto(_STATE['base'] + '/index.html')
    page.fill('#login-user', 'alice')                    # the seeder builds its own operator accounts: there is no 'admin'
    page.fill('#login-pass', 'demo')
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)
    return ctx, page, errors


def _until(fn, seconds=20, step=0.25):
    """Poll from Python (a wait_for_function with an async predicate returns at once)."""
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


def _register(token=None, pin=None, name=None):
    """Enrol a host through the public endpoint, the way the installer does. Returns (status, body)."""
    name = name or ('wiz-host-%d' % next(_COUNTER))
    body = {'hostname': name, 'name': name, 'os': 'Debian 12', 'ip': '10.1.2.3', 'version': '7.5.0'}
    if token:
        body['enrollment_token'] = token
    if pin:
        body['pin'] = pin
    req = urllib.request.Request(_STATE['base'] + '/api/enroll/register', data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    for attempt in (1, 2):
        try:
            r = urllib.request.urlopen(req, timeout=30)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            data = json.loads(e.read() or b'{}')
            e.close()
            if e.code == 429 and attempt == 1:           # ten attempts a minute per address
                time.sleep(62)
                continue
            return e.code, data
    return 0, {}


class Receiver:
    """A webhook receiver on the loopback address whose answer the test chooses."""

    def __init__(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get('Content-Length') or 0)
                outer.bodies.append(self.rfile.read(n))
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, format, *args):    # noqa: A002 - the name the base class uses
                pass

        self.status = 204
        self.bodies = []
        self.srv = HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = 'http://127.0.0.1:%d/hook' % self.srv.server_address[1]

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def _closed_port_url():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return 'http://127.0.0.1:%d/hook' % port


class _Base(unittest.TestCase):
    width = 1440
    height = 900

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _signed_in_context(cls.width, cls.height)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.ctx.close()
        except Exception:                                # pragma: no cover
            pass

    def tearDown(self):
        # nothing from one test stays open for the next, and nothing in the page threw
        self.page.keyboard.press('Escape')
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")
        self.assertEqual(self.errors, [], 'the page threw: %s' % self.errors)


# ── Add a host ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def _open_wizard(page, name):
    page.evaluate("(n) => wizOpen(n)", name)
    page.wait_for_selector('#wizard-modal.active', timeout=15000)


def _steps(page, root='#wizard-modal'):
    return page.eval_on_selector_all(root + ' .wiz-steps .wiz-lbl', 'els => els.map(e => e.textContent)')


def _active(page, root='#wizard-modal'):
    return page.inner_text(root + ' .wiz-step.active .wiz-lbl')


def _pick_kind(page, kind):
    page.check('#wizard-modal input[name=wiz-kind][value=%s]' % kind)


def _to_install(page, kind='linux', group='', tags='', cidrs='', ttl=None):
    """From step one to the install step, with the settings typed."""
    _open_wizard(page, 'enroll')
    _pick_kind(page, kind)
    page.click('#wiz-next')
    if kind != 'pin':
        page.wait_for_selector('#wiz-group')
        page.fill('#wiz-group', group)
        page.fill('#wiz-tags', tags)
        page.fill('#wiz-cidrs', cidrs)
        if ttl:
            page.select_option('#wiz-ttl', ttl)
        page.click('#wiz-next')
    page.wait_for_selector('#wiz-watch')


def _token_of(page):
    cmd = page.inner_text('#wiz-cmd-linux')
    return re.search(r'install\?t=([^"]+)"', cmd)[1]


def _wizard_tokens(page):
    rows = _api(page, 'GET', '/enrollment-tokens')
    return [t for t in rows if t.get('label') == 'guided-add-host']


class TestEnrollWizard(_Base):

    def test_it_opens_from_the_enroll_dialog_the_checklist_and_the_empty_hosts_page(self):
        page = self.page
        # from the Enroll dialog: the dialog gives way to the wizard
        page.evaluate("showPage('devices')")
        page.click('button[data-action="openEnrollModal"]')
        page.wait_for_selector('#enroll-modal.active')
        page.click('#enroll-modal button[data-action="wizOpenFrom"]')
        page.wait_for_selector('#wizard-modal.active', timeout=15000)
        self.assertFalse(page.evaluate("() => document.getElementById('enroll-modal').classList.contains('active')"),
                         'the Enroll dialog stays open behind the wizard')
        self.assertEqual(_steps(page), ['Type', 'Settings', 'Install', 'Done'])
        page.keyboard.press('Escape')
        # from the Getting started checklist: a step that is not done offers it beside Set up, one that is done does not
        def checklist(first_done, notif_done):
            return lambda r: r.fulfill(status=200, content_type='application/json', body=json.dumps({
                'done': 1, 'total': 3, 'complete': False, 'required_remaining': [], 'steps': [
                    {'id': 'admin-password', 'title': 'Set a strong admin password', 'detail': 'x', 'page': 'users', 'required': True, 'done': True},
                    {'id': 'first-device', 'title': 'Enroll your first host', 'detail': 'x', 'page': 'devices', 'required': True, 'done': first_done, 'count': 0},
                    {'id': 'notifications', 'title': 'Configure a notification channel', 'detail': 'x', 'page': 'settings', 'tab': 'notifs', 'required': False,
                     'done': notif_done}]}))

        def guides_with(first_done, notif_done):
            page.route('**/api/setup-status', checklist(first_done, notif_done))
            try:
                page.evaluate("showPage('settings')")
                page.evaluate("switchSettingsTab('install')")
                page.evaluate("loadSetup()")
                page.wait_for_function("(n) => document.querySelectorAll('#setup-steps .setup-step').length === 3", timeout=15000)
                return page.eval_on_selector_all('#setup-steps [data-action="wizOpen"]', 'els => els.map(e => e.dataset.arg)')
            finally:
                page.unroute('**/api/setup-status')

        self.assertEqual(guides_with(False, False), ['enroll', 'notify'], 'only the steps that are not done, and only those that have a wizard')
        self.assertEqual(guides_with(True, False), ['notify'], 'a step that is done has no Guide me')
        self.assertEqual(guides_with(False, True), ['enroll'])
        page.route('**/api/setup-status', checklist(False, False))
        try:
            page.evaluate("showPage('settings')")
            page.evaluate("switchSettingsTab('install')")
            page.evaluate("loadSetup()")
            page.wait_for_selector('#setup-steps [data-action="wizOpen"][data-arg="enroll"]')
            page.click('#setup-steps [data-action="wizOpen"][data-arg="enroll"]')
            page.wait_for_selector('#wizard-modal.active', timeout=15000)
            self.assertEqual(page.inner_text('#wizard-modal .modal-title'), 'Add a host')
            page.keyboard.press('Escape')
            page.click('#setup-steps [data-action="wizOpen"][data-arg="notify"]')
            page.wait_for_selector('#wizard-modal.active', timeout=15000)
            self.assertEqual(page.inner_text('#wizard-modal .modal-title'), 'Add a notification destination')
            page.keyboard.press('Escape')
        finally:
            page.unroute('**/api/setup-status')
        # from the Hosts page with no hosts
        page.route(re.compile(r'.*/api/devices(\?.*)?$'), lambda r: r.fulfill(status=200, content_type='application/json', body='[]'))
        try:
            page.evaluate("showPage('devices')")
            page.evaluate("loadDevices()")
            page.wait_for_selector('.empty-state [data-action="wizOpen"][data-arg="enroll"]', timeout=15000)
            page.click('.empty-state [data-action="wizOpen"][data-arg="enroll"]')
            page.wait_for_selector('#wizard-modal.active', timeout=15000)
        finally:
            page.unroute(re.compile(r'.*/api/devices(\?.*)?$'))

    def test_the_wizard_is_fetched_when_it_is_used_and_not_before(self):
        ctx, page, errors = _signed_in_context()
        try:
            self.assertEqual(page.evaluate("() => [typeof wizStart, _loadedJsModules.has('app-wizard.js')]"), ['undefined', False])
            page.evaluate("showPage('devices')")
            page.click('button[data-action="openEnrollModal"]')
            page.wait_for_selector('#enroll-modal.active')
            self.assertEqual(page.evaluate("() => _loadedJsModules.has('app-wizard.js')"), False, 'the dialog that is there already does not fetch it')
            page.click('#enroll-modal button[data-action="wizOpenFrom"]')
            page.wait_for_selector('#wizard-modal.active', timeout=15000)
            self.assertEqual(page.evaluate("() => [typeof wizStart, _loadedJsModules.has('app-wizard.js')]"), ['function', True])
            self.assertEqual(errors, [])
        finally:
            ctx.close()

    def test_each_kind_gets_its_own_command_and_the_settings_ride_in_the_token(self):
        page = self.page
        before = len(_wizard_tokens(page))
        _to_install(page, 'linux', group='prod', tags='web, eu , ,db', cidrs='10.0.0.0/24 192.168.1.5', ttl='3600')
        token = _token_of(page)
        origin = page.evaluate("() => location.origin")
        self.assertEqual(page.inner_text('#wiz-cmd-linux'), 'wget -qO- "%s/install?t=%s" | sudo sh' % (origin, token))
        mine = [t for t in _wizard_tokens(page) if token.startswith(t['prefix'].rstrip('…'))]
        self.assertEqual(len(mine), 1, 'the token is in the server\'s list')
        t = mine[0]
        self.assertEqual((t['default_group'], t['default_tags']), ('prod', ['web', 'eu', 'db']), 'blank tags are dropped, the rest kept')
        self.assertEqual(t['allowed_cidrs'], ['10.0.0.0/24', '192.168.1.5/32'])
        self.assertTrue(3500 < t['remaining_seconds'] <= 3600, 'valid for one hour, as chosen: %s' % t['remaining_seconds'])
        self.assertEqual(len(_wizard_tokens(page)), before + 1)
        page.keyboard.press('Escape')
        # Windows
        _to_install(page, 'windows')
        win = page.inner_text('#wiz-cmd-windows')
        self.assertTrue(win.startswith('powershell -ExecutionPolicy Bypass -Command "iwr \'%s/install.ps1?t=' % origin), win)
        self.assertEqual(page.eval_on_selector_all('#wizard-modal pre', 'els => els.length'), 1)
        page.keyboard.press('Escape')
        # Docker: the compose file the Enroll dialog prints, with a token in it
        _to_install(page, 'docker', group='lab')
        compose = page.inner_text('#wiz-cmd-docker')
        tok = re.search(r'RP_ENROLL_TOKEN: "([^"]+)"', compose)[1]
        self.assertIn('RP_SERVER: "%s"' % origin, compose)
        self.assertEqual(compose, page.evaluate("([o, t]) => dockerComposeText(o, t)", [origin, tok]))
        self.assertEqual([x['default_group'] for x in _wizard_tokens(page) if tok.startswith(x['prefix'].rstrip('…'))], ['lab'])
        page.keyboard.press('Escape')

    def test_a_pin_has_no_settings_step_and_shows_a_six_digit_pin(self):
        page = self.page
        _open_wizard(page, 'enroll')
        _pick_kind(page, 'pin')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-pin')
        self.assertEqual(_steps(page), ['Type', 'Install', 'Done'], 'a PIN carries no group or tags: the step is not drawn')
        self.assertRegex(page.inner_text('#wiz-pin'), r'^\d{6}$')
        self.assertEqual(_active(page), 'Install')

    def test_a_host_that_enrols_is_shown_with_what_the_token_gave_it(self):
        page = self.page
        _to_install(page, 'linux', group='prod', tags='web, eu')
        token = _token_of(page)
        self.assertIn('Waiting for the host to check in', page.inner_text('#wiz-watch'))
        self.assertNotRegex(page.inner_text('#wiz-watch'), r'\d{6,} s', 'the time waited starts at zero, not at the epoch')
        status, body = _register(token=token, name='wiz-arrival-host')
        self.assertEqual(status, 201, body)
        page.wait_for_function("() => /Checked in/.test((document.getElementById('wiz-watch') || {}).textContent || '')", timeout=20000)
        self.assertIn('wiz-arrival-host', page.inner_text('#wiz-watch'))
        page.click('#wiz-next')
        page.wait_for_selector('.wiz-list')
        rows = dict(zip(page.eval_on_selector_all('.wiz-list dt', 'e => e.map(x => x.textContent)'),
                        page.eval_on_selector_all('.wiz-list dd', 'e => e.map(x => x.textContent)')))
        self.assertEqual(rows['Name'], 'wiz-arrival-host')
        self.assertEqual(rows['Group'], 'prod')
        self.assertEqual(rows['Tags'], 'web, eu')
        self.assertEqual(rows['IP address'], '10.1.2.3')
        self.assertEqual(page.inner_text('#wiz-next'), 'Close')
        self.assertFalse(page.is_visible('#wiz-back'), 'nothing to go back to once the host is here')
        # Add another host: the first step again, the same settings, a new command
        page.click('#wizard-modal button[data-action="wizAddAnother"]')
        page.wait_for_selector('#wizard-modal input[name=wiz-kind]')
        self.assertEqual(_active(page), 'Type')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-group')
        self.assertEqual(page.input_value('#wiz-group'), 'prod')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-cmd-linux')
        self.assertNotEqual(_token_of(page), token, 'the next host gets a command of its own')
        self.assertIn('Waiting for the host', page.inner_text('#wiz-watch'))
        page.keyboard.press('Escape')
        # Open host: the wizard closes and the host's drawer opens
        _to_install(page, 'linux')
        status, body = _register(token=_token_of(page), name='wiz-open-host')
        self.assertEqual(status, 201, body)
        page.wait_for_function("() => /Checked in/.test((document.getElementById('wiz-watch') || {}).textContent || '')", timeout=20000)
        page.click('#wiz-next')
        page.click('#wizard-modal button[data-action="wizOpenHost"]')
        page.wait_for_selector('#device-drawer.open', timeout=15000)
        self.assertFalse(page.evaluate("() => !!document.getElementById('wizard-modal')"))
        page.evaluate("() => { if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer(); }")

    def test_the_pin_path_sees_the_host_arrive_too(self):
        page = self.page
        _open_wizard(page, 'enroll')
        _pick_kind(page, 'pin')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-pin')
        pin = page.inner_text('#wiz-pin')
        status, body = _register(pin=pin, name='wiz-pin-host')
        self.assertEqual(status, 201, body)
        page.wait_for_function("() => /Checked in/.test((document.getElementById('wiz-watch') || {}).textContent || '')", timeout=20000)
        self.assertIn('wiz-pin-host', page.inner_text('#wiz-watch'))

    def test_a_network_limit_is_checked_by_the_server_and_held_by_it(self):
        page = self.page
        _open_wizard(page, 'enroll')
        _pick_kind(page, 'linux')
        page.click('#wiz-next')
        page.fill('#wiz-cidrs', 'not-a-network')
        page.click('#wiz-next')
        page.wait_for_function("() => (document.getElementById('wiz-msg') || {}).textContent")
        self.assertIn('is not an address or a network', page.inner_text('#wiz-msg'))
        self.assertEqual(_active(page), 'Settings', 'the step stays, with the server\'s words')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'wiz-cidrs')
        # a network that does not hold this machine: the token is made, and refuses this machine
        page.fill('#wiz-cidrs', '203.0.113.0/24')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-cmd-linux')
        self.assertEqual(page.inner_text('#wiz-msg'), '')
        token = _token_of(page)
        status, body = _register(token=token, name='wiz-refused-host')
        self.assertEqual(status, 403, body)
        self.assertIn('cannot be used from this address', body.get('error', ''))
        page.keyboard.press('Escape')
        # a network that does: the same wizard, the host is let in and seen
        _to_install(page, 'linux', cidrs='127.0.0.0/8')
        status, body = _register(token=_token_of(page), name='wiz-inside-host')
        self.assertEqual(status, 201, body)
        page.wait_for_function("() => /Checked in/.test((document.getElementById('wiz-watch') || {}).textContent || '')", timeout=20000)

    def test_a_refusal_of_the_server_is_said_in_the_dialog_and_the_step_stays(self):
        page = self.page
        refuse = lambda route: route.fulfill(status=403, content_type='application/json', body='{"error": "Admin access required"}')   # noqa: E731
        page.route('**/api/enrollment-tokens', lambda r: refuse(r) if r.request.method == 'POST' else r.continue_())
        page.route('**/api/enroll/pin', refuse)
        try:
            _open_wizard(page, 'enroll')
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-group')
            page.click('#wiz-next')
            page.wait_for_function("() => (document.getElementById('wiz-msg') || {}).textContent")
            self.assertEqual(page.inner_text('#wiz-msg'), 'Admin access required')
            self.assertEqual(_active(page), 'Settings')
            self.assertFalse(page.evaluate("() => document.getElementById('wiz-next').disabled"), 'the buttons come back')
            page.click('#wiz-back')
            _pick_kind(page, 'pin')
            page.click('#wiz-next')
            page.wait_for_function("() => (document.getElementById('wiz-msg') || {}).textContent")
            self.assertEqual(page.inner_text('#wiz-msg'), 'Admin access required')
            self.assertEqual(_active(page), 'Type')
        finally:
            page.unroute('**/api/enrollment-tokens')
            page.unroute('**/api/enroll/pin')

    def test_going_back_to_a_token_after_a_pin_keeps_the_baseline_of_the_token(self):
        page = self.page
        _open_wizard(page, 'enroll')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-group')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-cmd-linux')
        token_since = page.evaluate("() => _wiz.st.since")
        self.assertGreater(token_since, 0)
        time.sleep(1.3)                                    # a PIN made now has a later baseline than the token
        page.click('#wizard-modal .wiz-step.done button.wiz-jump >> nth=0')
        page.wait_for_selector('#wizard-modal input[name=wiz-kind]')
        _pick_kind(page, 'pin')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-pin')
        pin_since = page.evaluate("() => _wiz.st.since")
        self.assertGreater(pin_since, token_since)
        page.click('#wiz-back')
        _pick_kind(page, 'linux')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-group')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-cmd-linux')
        self.assertEqual(page.evaluate("() => _wiz.st.since"), token_since, 'the token is the old one, so a host that came after it counts')

    def test_closing_the_wizard_stops_the_wait(self):
        page = self.page
        _to_install(page, 'linux')
        seen = []
        page.on('request', lambda r: seen.append(r.url) if '/api/devices' in r.url else None)
        page.keyboard.press('Escape')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        mark = len(seen)
        time.sleep(7)                                    # two polls would have gone by
        self.assertEqual(len(seen), mark, 'no request for the hosts after the dialog closed: %s' % seen[mark:])

    def test_a_device_that_cannot_run_the_agent_goes_to_its_own_form(self):
        page = self.page
        _open_wizard(page, 'enroll')
        _pick_kind(page, 'other')
        page.click('#wiz-next')
        page.wait_for_selector('#agentless-add-modal.active', timeout=15000)
        self.assertFalse(page.evaluate("() => !!document.getElementById('wizard-modal')"), 'the wizard is gone')

    def test_the_wait_says_so_after_five_minutes(self):
        ctx, page, errors = _signed_in_context()
        try:
            page.clock.install()
            _to_install(page, 'linux')
            page.clock.fast_forward(305 * 1000)
            page.wait_for_function("() => /No host has checked in after 5 minutes/.test(document.getElementById('wiz-watch').textContent)", timeout=10000)
            self.assertIn('c-amber', page.get_attribute('#wiz-watch', 'class'))
            self.assertEqual(errors, [])
        finally:
            ctx.close()

    def test_keys_and_focus(self):
        page = self.page
        _open_wizard(page, 'enroll')
        self.assertEqual(page.evaluate("() => document.activeElement.name + ':' + document.activeElement.value"), 'wiz-kind:linux',
                         'focus starts on the chosen kind')
        page.keyboard.press('Enter')                     # Enter on a radio button keeps its own meaning: nothing moves
        self.assertEqual(_active(page), 'Type')
        page.click('#wiz-next')
        page.wait_for_function("() => document.activeElement && document.activeElement.id === 'wiz-group'", timeout=5000)
        page.fill('#wiz-group', 'lab')
        page.keyboard.press('Enter')                     # Enter in a box goes on, like the button
        page.wait_for_selector('#wiz-watch')
        self.assertEqual(_active(page), 'Install')
        self.assertEqual(page.inner_text('#wiz-live'), 'Install', 'a screen reader is told the step by name')
        page.click('#wizard-modal .wiz-step.done button.wiz-jump >> nth=0')
        page.wait_for_selector('#wizard-modal input[name=wiz-kind]')
        self.assertEqual(_active(page), 'Type', 'a step that is done is a button that goes back to it')
        # the numbered list: the active step is marked, a done step is a button, a step ahead is not
        self.assertEqual(page.eval_on_selector_all('#wizard-modal .wiz-step[aria-current=step]', 'e => e.length'), 1)
        self.assertEqual(page.eval_on_selector_all('#wizard-modal .wiz-step button', 'e => e.length'), 0)
        page.keyboard.press('Control+Enter')             # the dialog's own Ctrl-Enter clicks the last primary button
        page.wait_for_selector('#wiz-group')



# ── Add a notification destination ───────────────────────────────────────────────────────────────────────────────────────────
# What the editor in Settings keeps for every destination whatever the service; the wizard does not draw these (the full editor has them).
_EDITOR_COMMON = {'enabled', 'name', 'format', 'url', 'on_ack', 'min_priority', 'digest_minutes', 'events', 'scope_type', 'scope_values',
                  'tenant_values'}
# Fields the editor has and the wizard leaves to it: request headers of a generic destination.
_EDITOR_ONLY = {'custom_headers'}


def _destinations(page):
    return _api(page, 'GET', '/config').get('webhook_urls') or []


def _set_destinations(page, rows):
    r = _api(page, 'POST', '/config', {'webhook_urls': rows})
    assert r and not r.get('error'), r


def _pick_service(page, fmt):
    _open_wizard(page, 'notify')
    page.check('#wizard-modal input[name=wiz-fmt][value=%s]' % fmt)
    page.click('#wiz-next')
    page.wait_for_selector('#wiz-name')


def _to_test(page, fmt, name, url, fields=None):
    _pick_service(page, fmt)
    page.fill('#wiz-name', name)
    page.fill('#wiz-url', url)
    for key, val in (fields or {}).items():
        page.fill('#wiz-f-' + key, val)
    page.click('#wiz-next')
    page.wait_for_selector('#wiz-test')


def _send_test(page):
    page.click('#wiz-test')
    page.wait_for_selector('#wiz-result .wiz-state', timeout=30000)     # the last answer is cleared on the click, so this is the new one


class TestNotifyWizard(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.receiver = Receiver()

    @classmethod
    def tearDownClass(cls):
        cls.receiver.stop()
        super().tearDownClass()

    def setUp(self):
        self.receiver.status = 204
        self.receiver.bodies.clear()
        _set_destinations(self.page, [])
        self.page.evaluate("showPage('settings')")
        self.page.evaluate("switchSettingsTab('notifs')")

    def tearDown(self):
        super().tearDown()
        _set_destinations(self.page, [])

    def test_every_service_is_on_the_first_step_in_one_group(self):
        page = self.page
        _open_wizard(page, 'notify')
        formats = page.evaluate("() => _WEBHOOK_FORMATS.map(f => [f[0], f[1]])")
        self.assertEqual(len(formats), 18, 'the editor offers 18 services')
        shown = page.eval_on_selector_all('#wizard-modal input[name=wiz-fmt]',
                                          "els => els.map(e => [e.value, e.closest('label').querySelector('.wiz-choice-t').textContent])")
        self.assertEqual(sorted(shown), sorted(formats), 'every service the editor knows, once, under its own name')
        groups = page.eval_on_selector_all('#wizard-modal .wiz-grp', 'els => els.map(e => e.textContent)')
        self.assertEqual(groups, ['Chat', 'Push', 'On-call', 'Tickets', 'Anything else'])
        # a service sits under exactly one heading
        placed = page.evaluate("() => _WIZ_NOTIFY_GROUPS.flatMap(g => g[1])")
        self.assertEqual(sorted(placed), sorted(f[0] for f in formats))
        self.assertEqual(page.input_value('#wizard-modal input[name=wiz-fmt]:checked'), 'discord')

    def test_the_connection_step_asks_for_what_the_editor_asks_for(self):
        page = self.page
        formats = page.evaluate("() => _WEBHOOK_FORMATS.map(f => [f[0], f[2]])")
        for fmt, example in formats:
            wanted = set(page.evaluate("""(f) => {
                _webhookDests = [{id: 'x', format: f, url: '', name: '', enabled: true}];
                renderWebhookDests();
                return [...document.querySelectorAll('#webhook-dests .webhook-dest-card [data-field]')].map(e => e.dataset.field);
            }""", fmt)) - _EDITOR_COMMON - _EDITOR_ONLY
            _pick_service(page, fmt)
            asked = set(page.eval_on_selector_all('#wizard-modal [id^=wiz-f-]', "els => els.map(e => e.id.slice(6))"))
            self.assertEqual(asked, wanted, 'the fields the wizard asks for %s are the ones the editor draws' % fmt)
            fixed = page.evaluate("(f) => (_WIZ_NOTIFY[f] || {}).url || ''", fmt)
            if fixed:
                self.assertEqual(fixed, example, 'a fixed address is the one the editor shows as its example (%s)' % fmt)
                self.assertEqual(page.input_value('#wiz-url'), fixed)
            else:
                self.assertEqual(page.get_attribute('#wiz-url', 'placeholder'), example)
            self.assertEqual(page.input_value('#wiz-name'), page.evaluate("(f) => _WEBHOOK_FORMATS.find(x => x[0] === f)[1]", fmt) + ' alerts')
            page.keyboard.press('Escape')
            page.evaluate("() => { _webhookDests = []; renderWebhookDests(); }")
        self.assertGreater(len(formats), 10)

    def test_the_connection_step_checks_before_the_test(self):
        page = self.page
        _pick_service(page, 'generic')
        page.fill('#wiz-name', '')
        page.click('#wiz-next')
        self.assertEqual(page.inner_text('#wiz-msg'), 'Name required')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'wiz-name')
        page.fill('#wiz-name', 'x')
        page.click('#wiz-next')
        self.assertEqual(page.inner_text('#wiz-msg'), 'Set a URL first')
        page.fill('#wiz-url', 'ftp://example.com/x')
        page.click('#wiz-next')
        self.assertEqual(page.inner_text('#wiz-msg'), 'The URL must start with http:// or https://')
        self.assertEqual(_active(page), 'Connection')
        page.keyboard.press('Escape')
        # a service with two secrets: each is needed, and the one missing gets the focus
        _pick_service(page, 'pushover')
        self.assertEqual(page.input_value('#wiz-url'), 'https://api.pushover.net/1/messages.json')
        page.click('#wiz-next')
        self.assertEqual(page.inner_text('#wiz-msg'), 'This field is needed')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'wiz-f-pushover_token')
        page.fill('#wiz-f-pushover_token', 'a')
        page.click('#wiz-next')
        self.assertEqual(page.evaluate("() => document.activeElement.id"), 'wiz-f-pushover_user')
        # nothing was saved by a wizard that never got to the test
        page.keyboard.press('Escape')
        self.assertEqual(_destinations(page), [])

    def test_a_delivered_test_says_so_and_the_destination_is_off_until_the_last_step(self):
        page = self.page
        _to_test(page, 'generic', 'wiz-ok', self.receiver.url)
        self.assertEqual(_destinations(page), [], 'nothing is saved before the person asks for the test')
        _send_test(page)
        self.assertEqual(page.inner_text('#wiz-result .wiz-state'), 'Delivered')
        self.assertEqual(page.inner_text('#wiz-result .wiz-chip'), '204')
        self.assertTrue(self.receiver.bodies, 'the receiver got the message')
        self.assertEqual(json.loads(self.receiver.bodies[-1]).get('event'), 'test')
        rows = _destinations(page)
        self.assertEqual([(d['name'], d['enabled']) for d in rows], [('wiz-ok', False)], 'a draft, switched off')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-prio')
        self.assertEqual(page.inner_text('#wiz-next'), 'Turn it on')
        summary = dict(zip(page.eval_on_selector_all('.wiz-list dt', 'e => e.map(x => x.textContent)'),
                           page.eval_on_selector_all('.wiz-list dd', 'e => e.map(x => x.textContent)')))
        self.assertEqual(summary, {'Service': 'Generic JSON', 'Name': 'wiz-ok',
                                   'Address': self.receiver.url.rsplit('/', 1)[0], 'Test': 'Delivered'},
                         'the address is shown without its path: a secret may be in the path')
        page.select_option('#wiz-prio', '4')
        page.click('#wiz-next')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        rows = _destinations(page)
        self.assertEqual([(d['name'], d['enabled'], d.get('min_priority')) for d in rows], [('wiz-ok', True, 4)])
        self.assertIn('Notification destination added', page.inner_text('#toast-container'))
        # the editor in Settings was drawn again with it
        self.assertEqual(page.eval_on_selector_all('#webhook-dests [data-field=name]', 'els => els.map(e => e.value)'), ['wiz-ok'])

    def test_a_refused_test_and_a_dead_address_are_said_in_words(self):
        page = self.page
        self.receiver.status = 404
        _to_test(page, 'generic', 'wiz-404', self.receiver.url)
        _send_test(page)
        self.assertEqual(page.inner_text('#wiz-result .wiz-state'), 'Not delivered')
        self.assertEqual(page.inner_text('#wiz-result .wiz-chip'), '404')
        self.assertIn('refused it', page.inner_text('#wiz-result'))
        self.assertIn('c-red', page.get_attribute('#wiz-result', 'class'))
        self.receiver.status = 503
        _send_test(page)
        self.assertEqual(page.inner_text('#wiz-result .wiz-chip'), '503')
        self.assertIn('problem on its side', page.inner_text('#wiz-result'))
        page.keyboard.press('Escape')
        _to_test(page, 'generic', 'wiz-dead', _closed_port_url())
        _send_test(page)
        self.assertEqual(page.inner_text('#wiz-result .wiz-state'), 'Not delivered')
        self.assertIn('Check the address', page.inner_text('#wiz-result'))
        self.assertTrue(page.inner_text('#wiz-result .ff-mono').strip(), 'the server\'s own words are shown')

    def test_a_refusal_of_the_test_is_said_in_the_dialog(self):
        page = self.page
        _to_test(page, 'generic', 'wiz-refused', self.receiver.url)
        page.route('**/api/webhook/test', lambda r: r.fulfill(status=403, content_type='application/json', body='{"error": "Admin access required"}'))
        try:
            _send_test(page)
            self.assertEqual(page.inner_text('#wiz-result .wiz-state'), 'Not delivered')
            self.assertIn('Admin access required', page.inner_text('#wiz-result'))
            self.assertFalse(page.evaluate("() => document.getElementById('wiz-test').disabled"), 'the button comes back, so the test can be sent again')
        finally:
            page.unroute('**/api/webhook/test')

    def test_the_verdict_of_each_answer(self):
        page = self.page
        cases = [
            (None, {'kind': 'none'}),
            ({'error': 'destination has no URL'}, {'kind': 'error', 'detail': 'destination has no URL'}),
            ({'ok': True, 'result': None}, {'kind': 'none'}),
            ({'ok': True, 'result': {'event': 'cve_found', 'status': '200'}}, {'kind': 'none'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '200'}}, {'kind': 'ok', 'code': '200'}),
            ({'ok': True, 'result': {'event': 'test', 'status': 204}}, {'kind': 'ok', 'code': '204'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '201'}}, {'kind': 'ok', 'code': '201'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '299'}}, {'kind': 'ok', 'code': '299'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '499'}}, {'kind': 'refused', 'code': '499'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '599'}}, {'kind': 'down', 'code': '599'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '404'}}, {'kind': 'refused', 'code': '404'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '401'}}, {'kind': 'refused', 'code': '401'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '503'}}, {'kind': 'down', 'code': '503'}),
            ({'ok': True, 'result': {'event': 'test', 'status': 'suppressed', 'detail': 'maintenance: patching'}},
             {'kind': 'held', 'detail': 'maintenance: patching'}),
            ({'ok': True, 'result': {'event': 'test', 'status': 'error', 'detail': 'connection refused'}},
             {'kind': 'error', 'detail': 'connection refused'}),
            ({'ok': True, 'result': {'event': 'test', 'status': '302'}}, {'kind': 'error', 'detail': '302'}),
        ]
        for given, want in cases:
            got = page.evaluate("(r) => _wizNotifyVerdict(r)", given)
            self.assertEqual(got, want, 'answer %r' % (given,))

    def test_cancelling_removes_a_draft_that_never_delivered_and_keeps_one_that_did_off(self):
        page = self.page
        self.receiver.status = 404
        _to_test(page, 'generic', 'wiz-draft-bad', self.receiver.url)
        _send_test(page)
        self.assertEqual([d['name'] for d in _destinations(page)], ['wiz-draft-bad'])
        page.keyboard.press('Escape')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        _until(lambda: _destinations(page) == [], seconds=10)
        self.assertEqual(_destinations(page), [], 'a draft that never delivered is not left behind')
        self.receiver.status = 204
        _to_test(page, 'generic', 'wiz-draft-good', self.receiver.url)
        _send_test(page)
        page.keyboard.press('Escape')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        self.assertIn('Saved, but switched off', page.inner_text('#toast-container'))
        self.assertEqual([(d['name'], d['enabled']) for d in _destinations(page)], [('wiz-draft-good', False)])

    def test_destinations_that_were_there_are_kept_with_their_secrets(self):
        page = self.page
        _set_destinations(page, [
            {'id': 'wh_keep1', 'name': 'keep-one', 'url': self.receiver.url, 'format': 'pushover', 'enabled': True,
             'pushover_token': 'tok-secret-1', 'pushover_user': 'user-secret-1'},
            {'id': 'wh_keep2', 'name': 'keep-two', 'url': self.receiver.url, 'format': 'generic', 'enabled': False}])
        _to_test(page, 'generic', 'wiz-new', self.receiver.url)
        _send_test(page)
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-prio')
        page.click('#wiz-next')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        rows = {d['name']: d for d in _destinations(page)}
        self.assertEqual(sorted(rows), ['keep-one', 'keep-two', 'wiz-new'], 'what was there is still there')
        self.assertTrue(rows['keep-one'].get('pushover_token_set') and rows['keep-one'].get('pushover_user_set'))
        self.assertFalse(rows['keep-two']['enabled'])
        # the secret survived: a test to the old destination still sends it
        self.receiver.bodies.clear()
        r = _api(page, 'POST', '/webhook/test', {'id': 'wh_keep1'})
        self.assertTrue(r.get('ok'), r)
        self.assertIn(b'tok-secret-1', b''.join(self.receiver.bodies))

    def test_a_secret_typed_in_the_wizard_is_used_and_never_shown_back(self):
        page = self.page
        _to_test(page, 'pushover', 'wiz-push', self.receiver.url, {'pushover_token': 'p-token-xyz', 'pushover_user': 'p-user-xyz'})
        _send_test(page)
        body = b''.join(self.receiver.bodies)
        self.assertIn(b'p-token-xyz', body, 'the destination was saved with its secret and used it')
        self.assertIn(b'p-user-xyz', body)
        page.keyboard.press('Escape')
        cfg = _api(page, 'GET', '/config')
        self.assertNotIn('p-token-xyz', json.dumps(cfg))
        self.assertNotIn('p-user-xyz', json.dumps(cfg))
        dest = [d for d in cfg['webhook_urls'] if d['name'] == 'wiz-push'][0]
        self.assertTrue(dest.get('pushover_token_set'))

    def test_an_edit_waiting_in_the_editor_is_neither_saved_nor_thrown_away(self):
        page = self.page
        _set_destinations(page, [{'id': 'wh_ed', 'name': 'editor-one', 'url': self.receiver.url, 'format': 'generic', 'enabled': True}])
        page.evaluate("loadSettings()")
        page.wait_for_function("() => [...document.querySelectorAll('#webhook-dests [data-field=name]')].some(e => e.value === 'editor-one')", timeout=15000)
        page.evaluate("""() => { const el = document.querySelector('#webhook-dests [data-field=name]'); el.value = 'edited-not-saved';
                                  el.dispatchEvent(new Event('input', {bubbles: true})); }""")
        _to_test(page, 'generic', 'wiz-new', self.receiver.url)
        _send_test(page)
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-prio')
        page.click('#wiz-next')
        page.wait_for_function("() => !document.getElementById('wizard-modal')")
        self.assertEqual(sorted(d['name'] for d in _destinations(page)), ['editor-one', 'wiz-new'],
                         'the server never saw the edit that was waiting in the editor')
        self.assertEqual(page.evaluate("() => _webhookDests.map(d => d.name)"), ['edited-not-saved', 'wiz-new'],
                         'the editor kept its edit and learned of the new destination')
        self.assertEqual(page.eval_on_selector_all('#webhook-dests [data-field=name]', 'els => els.map(e => e.value)'), ['edited-not-saved', 'wiz-new'])

    def test_it_opens_from_the_destinations_card_in_settings(self):
        page = self.page
        page.click('#settings-pane-notifs [data-action="wizOpen"][data-arg="notify"]')
        page.wait_for_selector('#wizard-modal.active', timeout=15000)
        self.assertEqual(_steps(page), ['Service', 'Connection', 'Test', 'Finish'])



# ── Step by step ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
# modal id -> (page that holds the button, script that opens the dialog the way the button does, the form's own save, steps of a default form)
FORMS = {
    'new-maint-modal': ('maintenance', 'openNewMaintModal()', 'saveMaintenance', ['What', 'When', 'Effects', 'Review']),
    'monitor-add-modal': ('monitor', 'openMonitorAdd()', 'addMonitor', ['What', 'Target', 'Alerting', 'Review']),
    'backupjob-modal': ('backups', 'openBackupJobCreate()', 'saveBackupJob', ['What', 'How', 'When', 'Review']),
    'autopatch-modal': ('autopatch', 'openAutopatchCreate()', 'saveAutopatch', ['What', 'When', 'Safety', 'Review']),
}

_SET = """([sel, v]) => { const e = document.getElementById(sel) || document.querySelector(sel); e.value = v;
  e.dispatchEvent(new Event('input', {bubbles: true})); e.dispatchEvent(new Event('change', {bubbles: true})); }"""
_CHECK = """([sel, on]) => { const e = document.getElementById(sel) || document.querySelector(sel); e.checked = on;
  e.dispatchEvent(new Event('change', {bubbles: true})); }"""
# the blocks of the form that are on screen, by step, and what else shows
_SHOWN = """(id) => { const F = _wizForms.get(id);
  return {steps: F.blocks.map((g, n) => g.some(b => b.offsetParent !== null) ? n : -1).filter(n => n >= 0),
          review: F.review.offsetParent !== null, submit: F.submit.offsetParent !== null,
          next: F.next.offsetParent !== null, back: F.back.offsetParent !== null,
          labels: F.def.steps.map(s => s.label)}; }"""


def _apply(page, ops):
    for kind, sel, val in ops:
        page.evaluate(_SET if kind == 'set' else _CHECK, [sel, val])


def _set_steps(page, on):
    page.evaluate("(on) => { try { if (on) localStorage.setItem('rp_formsteps', '1'); else localStorage.removeItem('rp_formsteps'); } catch (e) {} }", on)


def _open_form(page, modal_id, steps=None):
    """Open the dialog the way its button does. steps=True waits for the step mode, False for the one form."""
    pg, opener, _, _ = FORMS[modal_id]
    page.evaluate("(p) => showPage(p)", pg)
    page.wait_for_selector('#page-%s.active' % pg)
    # the list of hosts a form offers is drawn from the roster the app fetched at sign-in: a form opened before it arrives has none to offer
    page.wait_for_function("() => typeof devices !== 'undefined' && devices.length > 0", timeout=30000)
    page.evaluate(opener)
    page.wait_for_selector('#%s.active' % modal_id)
    if steps:
        page.wait_for_selector('#%s .wiz-steps' % modal_id)
    if modal_id == 'backupjob-modal':
        try:
            page.wait_for_selector('.backupjob-devchk', timeout=15000)
        except Exception:
            raise AssertionError('no host to tick in the backup job form: %s' % page.evaluate(
                "() => ({devices: typeof devices === 'undefined' ? null : devices.length, box: document.getElementById('backupjob-devices').innerHTML.slice(0, 200), "
                "steps: !!document.querySelector('#backupjob-modal .wiz-steps'), pref: localStorage.getItem('rp_formsteps')})"))


def _next(page, modal_id):
    page.click('#%s .wiz-nav.btn-primary' % modal_id)


def _stepper(page, modal_id):
    return page.eval_on_selector_all('#%s .wiz-steps .wiz-lbl' % modal_id, 'els => els.map(e => e.textContent)')


def _fill_valid(page, modal_id):
    """What a form needs to get past every step."""
    if modal_id == 'new-maint-modal':
        _apply(page, [('set', 'maint-reason', 'wiz walk')])
    elif modal_id == 'monitor-add-modal':
        _apply(page, [('set', 'mon-label', 'wiz walk'), ('set', 'mon-target', 'localhost')])
    elif modal_id == 'backupjob-modal':
        _apply(page, [('set', 'backupjob-name', 'wiz walk'), ('check', '.backupjob-devchk', True), ('set', 'backupjob-command', 'echo hi')])
    elif modal_id == 'autopatch-modal':
        _apply(page, [('set', 'autopatch-name', 'wiz walk')])


class TestFormSteps(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.page.evaluate("() => _loadJsModule('app-wizard.js')")

    def setUp(self):
        _set_steps(self.page, False)
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def tearDown(self):
        _set_steps(self.page, False)
        for mid in FORMS:                                # a form the test left in steps goes back to the one form
            self.page.evaluate("(id) => { if (typeof _wizFormDetach === 'function') _wizFormDetach(id); }", mid)
        super().tearDown()

    def test_the_forms_are_the_same_by_default(self):
        page = self.page
        for mid, (_, _, submit, _) in FORMS.items():
            _open_form(page, mid)
            self.assertEqual(page.eval_on_selector_all('#%s .wiz-steps, #%s .wiz-off' % (mid, mid), 'els => els.length'), 0,
                             '%s: no step list, nothing hidden' % mid)
            self.assertTrue(page.is_visible('#%s [data-action="%s"]' % (mid, submit)), '%s: the form\'s own button shows' % mid)
            self.assertTrue(page.is_visible('#%s .wiz-switch' % mid))
            self.assertFalse(page.is_checked('#%s .wiz-switch input' % mid))
            # focus starts on the first thing to fill in, not on the switch
            page.wait_for_function("(id) => { const a = document.activeElement; return a && a.closest('#' + id) && !a.closest('.wiz-switch') "
                                   "&& !a.classList.contains('modal-close'); }", arg=mid, timeout=5000)
            page.keyboard.press('Escape')

    def test_a_person_who_never_chooses_steps_never_loads_the_module(self):
        ctx, page, errors = _signed_in_context()
        try:
            for mid in FORMS:
                _open_form(page, mid)
                page.keyboard.press('Escape')
            self.assertEqual(page.evaluate("() => [typeof _wizFormSync, _loadedJsModules.has('app-wizard.js')]"), ['undefined', False])
            # one who did choose it has it before the first form opens
            page.evaluate("localStorage.setItem('rp_formsteps', '1')")
            page.reload()
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_function("() => _loadedJsModules.has('app-wizard.js')", timeout=10000)
            self.assertEqual(errors, [])
        finally:
            ctx.close()

    def test_the_switch_puts_a_form_into_steps_and_back_and_the_choice_is_kept(self):
        page = self.page
        mid = 'new-maint-modal'
        _open_form(page, mid)
        page.click('#%s .wiz-switch input' % mid)
        page.wait_for_selector('#%s .wiz-steps' % mid)
        self.assertEqual(_stepper(page, mid), ['What', 'When', 'Effects', 'Review'])
        shown = page.evaluate(_SHOWN, mid)
        self.assertEqual(shown['steps'], [0], 'only the first step\'s blocks show')
        self.assertEqual((shown['review'], shown['submit'], shown['next'], shown['back']), (False, False, True, False),
                         'no Back on the first step, no save until the review')
        self.assertEqual(page.evaluate("() => localStorage.getItem('rp_formsteps')"), '1')
        page.keyboard.press('Escape')
        # one choice for every form that has the switch
        _open_form(page, 'monitor-add-modal', steps=True)
        self.assertTrue(page.is_checked('#monitor-add-modal .wiz-switch input'))
        page.click('#monitor-add-modal .wiz-switch input')       # back to the one form
        page.wait_for_function("() => !document.querySelector('#monitor-add-modal .wiz-steps')")
        self.assertEqual(page.eval_on_selector_all('#monitor-add-modal .wiz-off', 'els => els.length'), 0)
        self.assertTrue(page.is_visible('#monitor-add-modal [data-action="addMonitor"]'))
        self.assertIsNone(page.evaluate("() => localStorage.getItem('rp_formsteps')"))
        page.keyboard.press('Escape')
        _open_form(page, mid)
        self.assertEqual(page.eval_on_selector_all('#%s .wiz-steps' % mid, 'els => els.length'), 0, 'the other form is the one form again')
        # kept across a reload
        _open_form(page, mid)
        page.click('#%s .wiz-switch input' % mid)
        page.wait_for_selector('#%s .wiz-steps' % mid)
        page.keyboard.press('Escape')
        page.reload()
        page.wait_for_selector('#app', state='visible', timeout=90000)
        _open_form(page, 'autopatch-modal', steps=True)
        self.assertTrue(page.is_checked('#autopatch-modal .wiz-switch input'))

    def test_every_block_of_every_form_belongs_to_a_step(self):
        page = self.page
        for mid in FORMS:
            _open_form(page, mid)
            facts = page.evaluate("""(id) => {
                const panel = document.querySelector('#' + id + ' > .modal'), def = _WIZ_FORMS[id];
                const blocks = _wizFormBlocks(panel);
                const named = def.steps.flatMap(s => s.ids);
                const hits = blocks.map(b => def.steps.map((s, n) => s.ids.some(i => { const t = panel.querySelector('#' + i); return t && (b === t || b.contains(t)); }) ? n : -1).filter(n => n >= 0));
                return {blocks: blocks.length, missing: named.filter(i => !panel.querySelector('#' + i)),
                        unclaimed: hits.map((h, i) => h.length === 0 ? (blocks[i].id || blocks[i].className) : null).filter(Boolean),
                        twice: hits.map((h, i) => h.length > 1 ? (blocks[i].id || blocks[i].className) : null).filter(Boolean)};
            }""", mid)
            self.assertGreaterEqual(facts['blocks'], 5, '%s: the population is not empty' % mid)
            self.assertEqual(facts['missing'], [], '%s: every id a step names exists' % mid)
            self.assertEqual(facts['unclaimed'], [], '%s: no block is left for the last step by default' % mid)
            self.assertEqual(facts['twice'], [], '%s: no block holds controls of two steps' % mid)
            page.keyboard.press('Escape')

    def test_next_walks_the_steps_and_ends_at_the_review(self):
        page = self.page
        for mid, (_, _, submit, labels) in FORMS.items():
            _set_steps(page, True)
            _open_form(page, mid, steps=True)
            _fill_valid(page, mid)
            seen = []
            for _ in range(8):
                label = _active(page, '#' + mid)
                shown = page.evaluate(_SHOWN, mid)
                seen.append(label)
                if label == 'Review':
                    self.assertEqual(shown['steps'], [], '%s: at the review no block of the form shows' % mid)
                    self.assertTrue(shown['review'] and shown['submit'], '%s: the list and the form\'s own button show' % mid)
                    self.assertFalse(shown['next'], '%s: nothing further than the review' % mid)
                    break
                self.assertEqual([shown['labels'][n] for n in shown['steps']], [label], '%s: only the blocks of "%s" show' % (mid, label))
                self.assertFalse(shown['submit'], '%s: the form\'s own button waits for the review' % mid)
                _next(page, mid)
            self.assertEqual(seen, labels, '%s: the steps, in order' % mid)
            # Back from the review lands on the step before it, and the first step has no Back
            page.click('#%s .wiz-nav.btn-secondary' % mid)
            self.assertEqual(_active(page, '#' + mid), labels[-2])
            for _ in range(labels.index(labels[-2])):
                page.click('#%s .wiz-nav.btn-secondary' % mid)
            self.assertEqual(_active(page, '#' + mid), labels[0])
            self.assertFalse(page.is_visible('#%s .wiz-nav.btn-secondary' % mid))
            page.keyboard.press('Escape')

    def test_a_step_the_form_hides_is_skipped_and_one_it_shows_is_there(self):
        page = self.page
        mid = 'monitor-add-modal'
        _set_steps(page, True)
        _open_form(page, mid, steps=True)
        _apply(page, [('set', 'mon-type', 'ping'), ('set', 'mon-target', 'localhost')])
        _next(page, mid)
        self.assertEqual(_stepper(page, mid), ['What', 'Target', 'Alerting', 'Review'], 'a ping has no checks to set')
        page.keyboard.press('Escape')
        _open_form(page, mid, steps=True)
        _apply(page, [('set', 'mon-type', 'http'), ('set', 'mon-target', 'https://example.com/')])
        _next(page, mid)
        self.assertEqual(_stepper(page, mid), ['What', 'Target', 'Checks', 'Alerting', 'Review'], 'an HTTP check has the status, body and TLS checks')
        _next(page, mid)
        self.assertEqual(_active(page, '#' + mid), 'Checks')
        self.assertTrue(page.is_visible('#mon-status'))
        _next(page, mid)
        self.assertEqual(_active(page, '#' + mid), 'Alerting')

    def test_the_review_lists_what_was_typed_once(self):
        page = self.page
        _set_steps(page, True)
        # maintenance: a host picker (a text box over a select) and a list of ticks
        mid = 'new-maint-modal'
        _open_form(page, mid, steps=True)
        _apply(page, [('set', 'maint-reason', 'wiz review test'), ('set', 'maint-scope', 'device')])
        page.wait_for_selector('#maint-target-device option', state='attached')
        picked = page.evaluate("() => { const s = document.getElementById('maint-target-device'); return s.options[s.selectedIndex].text; }")
        _apply(page, [('check', '.maint-event-cb[value=monitor_down]', True), ('check', '.maint-event-cb[value=cve_found]', True)])
        for _ in range(3):
            _next(page, mid)
        rows = dict(zip(page.eval_on_selector_all('#%s .wiz-review dt' % mid, 'e => e.map(x => x.textContent)'),
                        page.eval_on_selector_all('#%s .wiz-review dd' % mid, 'e => e.map(x => x.textContent)')))
        self.assertEqual(rows['Reason'], 'wiz review test')
        self.assertEqual(rows['Scope'], 'Single host')
        self.assertEqual(rows['Target'], picked, 'the host once, not the select and its search box both')
        self.assertEqual(rows['Window type'], 'One-shot (specific time)')
        self.assertEqual(rows['Events to suppress (leave empty for all)'], 'monitor_down, cve_found')
        self.assertEqual(rows['Gate command/upgrade execution to this window'], 'No')
        self.assertNotIn('Weekly schedule builder (optional)', rows, 'a block the form hides is not in the list')
        headings = page.eval_on_selector_all('#%s .wiz-review-h' % mid, 'e => e.map(x => x.textContent)')
        self.assertEqual(headings, ['What', 'When', 'Effects'])
        page.keyboard.press('Escape')
        # backup job: the box that filters the list of hosts is not a choice
        mid = 'backupjob-modal'
        _open_form(page, mid, steps=True)
        first = page.evaluate("() => document.querySelector('.backupjob-devchk').closest('label').textContent.replace(/\\s+/g, ' ').trim()")
        name = page.evaluate("() => document.querySelector('.backupjob-devchk').closest('label').querySelector('span').textContent.trim()")
        _apply(page, [('set', 'backupjob-name', 'wiz review backup'), ('set', 'backupjob-devfilter', name[:3])])
        _apply(page, [('check', '.backupjob-devchk', True), ('set', 'backupjob-command', 'echo hi')])
        for _ in range(3):
            _next(page, mid)
        rows = dict(zip(page.eval_on_selector_all('#%s .wiz-review dt' % mid, 'e => e.map(x => x.textContent)'),
                        page.eval_on_selector_all('#%s .wiz-review dd' % mid, 'e => e.map(x => x.textContent)')))
        self.assertEqual(rows['Name'], 'wiz review backup')
        self.assertEqual(rows['Hosts — apply this job to one or more (a baseline)'], first,
                         'the ticked host, without the text typed into the filter above the list')
        self.assertEqual(rows['Backup command'], 'echo hi')

    def test_each_step_refuses_what_the_form_would_refuse(self):
        page = self.page
        scenarios = [
            ('new-maint-modal', [('set', 'maint-type', 'period'), ('set', 'maint-period', '')], 'Choose a time period', 'When'),
            ('new-maint-modal', [('set', 'maint-type', 'oneshot'), ('set', 'maint-start', '')], 'Start and end are required', 'When'),
            ('monitor-add-modal', [('set', 'mon-type', 'tcp'), ('set', 'mon-target', '')], 'Target is required', 'Target'),
            ('monitor-add-modal', [('set', 'mon-type', 'http'), ('set', 'mon-target', 'not a url')], 'HTTP target must be a full URL (https://host/path)', 'Target'),
            ('backupjob-modal', [('set', 'backupjob-name', '')], 'Name is required', 'What'),
            ('backupjob-modal', [('set', 'backupjob-name', 'x')], 'Select at least one host', 'What'),
            ('backupjob-modal', [('set', 'backupjob-name', 'x'), ('check', '.backupjob-devchk', True), ('set', 'backupjob-type', 'file'),
                                 ('set', 'backupjob-paths', '')], 'Add at least one source path', 'How'),
            ('backupjob-modal', [('set', 'backupjob-name', 'x'), ('check', '.backupjob-devchk', True), ('set', 'backupjob-type', 'file'),
                                 ('set', 'backupjob-paths', '/etc'), ('set', 'backupjob-host', '')], 'Host and remote path are required', 'How'),
            ('backupjob-modal', [('set', 'backupjob-name', 'x'), ('check', '.backupjob-devchk', True), ('set', 'backupjob-type', 'command'),
                                 ('set', 'backupjob-command', '')], 'A command is required', 'How'),
            ('autopatch-modal', [('set', 'autopatch-name', '')], 'Name required', 'What'),
            ('autopatch-modal', [('set', 'autopatch-name', 'x'), ('set', 'autopatch-target-type', 'device'), ('set', 'autopatch-target-device', '')],
             'Pick a host for this policy', 'What'),
            ('autopatch-modal', [('set', 'autopatch-name', 'x'), ('check', 'autopatch-staged', True), ('set', 'autopatch-rings', '')],
             'Staged rollout needs at least one ring (e.g. "canary = tag:canary")', 'Safety'),
        ]
        for mid, ops, message, at in scenarios:
            # in steps: the message of the step, with the step that holds it still showing
            _set_steps(page, True)
            _open_form(page, mid, steps=True)
            _apply(page, ops)
            got = None
            for _ in range(6):
                if _active(page, '#' + mid) == 'Review':
                    break
                _next(page, mid)
                got = page.inner_text('#%s .wiz-msg' % mid)
                if got:
                    break
            self.assertEqual(got, message, '%s / %s: the step says it' % (mid, at))
            self.assertEqual(_active(page, '#' + mid), at, '%s: the refusal keeps the step it belongs to' % mid)
            page.keyboard.press('Escape')
            # in the one form: the form's own save says the same words
            _set_steps(page, False)
            page.evaluate("(id) => _wizFormDetach(id)", mid)
            _open_form(page, mid)
            _apply(page, ops)
            page.evaluate("() => { window.__t = []; window.__toastWas = window.toast; window.toast = (m) => { window.__t.push(String(m)); }; }")
            try:
                page.click('#%s [data-action="%s"]' % (mid, FORMS[mid][2]))
                page.wait_for_function("() => window.__t.length > 0", timeout=5000)
                form_said = page.evaluate("() => window.__t[0]")
            finally:
                page.evaluate("() => { window.toast = window.__toastWas; }")
            self.assertEqual(form_said, message, '%s: the form itself refuses with the same words' % mid)
            page.keyboard.press('Escape')

    def test_create_in_steps_saves_what_the_form_saves(self):
        page = self.page
        _set_steps(page, True)
        created = []

        def walk_and_save(mid, ops):
            _open_form(page, mid, steps=True)
            _apply(page, ops)
            for _ in range(6):
                if _active(page, '#' + mid) == 'Review':
                    break
                _next(page, mid)
            self.assertEqual(_active(page, '#' + mid), 'Review', '%s: %s' % (mid, page.inner_text('#%s .wiz-msg' % mid)))
            page.click('#%s [data-action="%s"]' % (mid, FORMS[mid][2]))
            try:
                page.wait_for_function("(id) => !document.getElementById(id).classList.contains('active')", arg=mid, timeout=15000)
            except Exception:
                self.fail('%s did not close after its own save; the page said: %s' % (mid, page.inner_text('#toast-container')))

        try:
            walk_and_save('new-maint-modal', [('set', 'maint-reason', 'wiz-steps-window'), ('set', 'maint-scope', 'global'),
                                              ('set', 'maint-start', '2031-01-01T02:00'), ('set', 'maint-end', '2031-01-01T04:00'),
                                              ('check', '.maint-event-cb[value=monitor_down]', True)])
            win = [w for w in _api(page, 'GET', '/maintenance')['windows'] if w['reason'] == 'wiz-steps-window']
            self.assertEqual(len(win), 1)
            created.append(('/maintenance/%s' % win[0]['id']))
            self.assertEqual((win[0]['scope'], win[0]['events']), ('global', ['monitor_down']))
            walk_and_save('backupjob-modal', [('set', 'backupjob-name', 'wiz-steps-backup'), ('check', '.backupjob-devchk', True),
                                              ('set', 'backupjob-command', 'echo hi'), ('set', 'backupjob-cron', '0 3 * * *')])
            job = [j for j in _api(page, 'GET', '/backup-jobs')['jobs'] if j['name'] == 'wiz-steps-backup']
            self.assertEqual(len(job), 1)
            created.append('/backup-jobs/%s' % job[0]['id'])
            self.assertEqual((job[0]['command'], job[0]['cron']), ('echo hi', '0 3 * * *'))
            walk_and_save('autopatch-modal', [('set', 'autopatch-name', 'wiz-steps-policy'), ('set', 'autopatch-cron', '0 4 * * 0')])
            pol = [p for p in _api(page, 'GET', '/autopatch')['policies'] if p['name'] == 'wiz-steps-policy']
            self.assertEqual(len(pol), 1)
            created.append('/autopatch/%s' % pol[0]['id'])
            self.assertEqual((pol[0]['target']['type'], pol[0]['cron']), ('all', '0 4 * * 0'))
            before = _api(page, 'GET', '/config')['monitors']
            walk_and_save('monitor-add-modal', [('set', 'mon-label', 'wiz-steps-monitor'), ('set', 'mon-type', 'tcp'),
                                                ('set', 'mon-target', '192.0.2.10:22')])
            after = _api(page, 'GET', '/config')['monitors']
            self.assertEqual(len(after), len(before) + 1)
            mon = [m for m in after if m['label'] == 'wiz-steps-monitor'][0]
            self.assertEqual((mon['type'], mon['target']), ('tcp', '192.0.2.10:22'))
            _api(page, 'POST', '/config', {'monitors': before})
        finally:
            for path in created:
                _api(page, 'DELETE', path)

    def test_hosts_ticked_before_the_filter_was_typed_are_kept_in_both_modes(self):
        """Found on the way: the New backup job form read only the boxes on screen, so a host that was ticked and then filtered out of the
        list was dropped without a word. The form keeps a set of the ticks; the save reads it."""
        page = self.page
        mid = 'backupjob-modal'
        for steps in (False, True):
            _set_steps(page, steps)
            _open_form(page, mid, steps=steps)
            first = page.evaluate("() => [...document.querySelectorAll('.backupjob-devchk')].slice(0, 2).map(c => [c.value, c.closest('label').querySelector('span').textContent.trim()])")
            (a_id, a_name), (b_id, b_name) = first
            _apply(page, [('set', 'backupjob-name', 'wiz-filter-%s' % steps), ('set', 'backupjob-command', 'echo hi')])
            _apply(page, [('check', '.backupjob-devchk', True)])                     # host A is ticked
            _apply(page, [('set', 'backupjob-devfilter', b_name)])                    # the filter shows only host B: A is not on screen
            self.assertEqual(page.evaluate("() => [...document.querySelectorAll('.backupjob-devchk')].map(c => c.value)"), [b_id])
            _apply(page, [('check', '.backupjob-devchk', True)])                     # host B is ticked
            if steps:
                for _ in range(3):
                    if _active(page, '#' + mid) == 'Review':
                        break
                    _next(page, mid)
                self.assertEqual(_active(page, '#' + mid), 'Review', 'a host hidden by the filter still counts as ticked: %s' % page.inner_text('#%s .wiz-msg' % mid))
                review = page.inner_text('#%s .wiz-review' % mid)
                self.assertIn(a_name, review, 'the review lists the host the filter had hidden')
                self.assertIn(b_name, review)
            page.click('#%s [data-action="saveBackupJob"]' % mid)
            page.wait_for_function("(id) => !document.getElementById(id).classList.contains('active')", arg=mid, timeout=15000)
            job = [j for j in _api(page, 'GET', '/backup-jobs')['jobs'] if j['name'] == 'wiz-filter-%s' % steps]
            try:
                self.assertEqual(len(job), 1)
                self.assertEqual(sorted(job[0]['device_ids']), sorted([a_id, b_id]), 'both hosts were saved (steps=%s)' % steps)
            finally:
                for j in job:
                    _api(page, 'DELETE', '/backup-jobs/%s' % j['id'])

    def test_a_ticked_host_that_the_filter_hides_still_lets_the_first_step_go_on(self):
        page = self.page
        mid = 'backupjob-modal'
        _set_steps(page, True)
        _open_form(page, mid, steps=True)
        b_name = page.evaluate("() => [...document.querySelectorAll('.backupjob-devchk')][1].closest('label').querySelector('span').textContent.trim()")
        _apply(page, [('set', 'backupjob-name', 'x'), ('check', '.backupjob-devchk', True), ('set', 'backupjob-devfilter', b_name)])
        self.assertEqual(page.evaluate("() => document.querySelectorAll('.backupjob-devchk:checked').length"), 0, 'the one ticked host is not on screen')
        _next(page, mid)
        self.assertEqual(page.inner_text('#%s .wiz-msg' % mid), '', 'one host is ticked, on screen or not')
        self.assertEqual(_active(page, '#' + mid), 'How')
        self.assertEqual(page.input_value('#backupjob-devfilter'), '', 'the list is whole again once the step is left')

    def test_enter_and_ctrl_enter_go_on_and_the_last_primary_button_is_the_forms_own(self):
        page = self.page
        mid = 'new-maint-modal'
        _set_steps(page, True)
        _open_form(page, mid, steps=True)
        page.fill('#maint-reason', 'enter test')
        page.press('#maint-reason', 'Enter')
        page.wait_for_function("() => document.querySelector('#new-maint-modal .wiz-step.active .wiz-lbl').textContent === 'When'")
        page.keyboard.press('Control+Enter')                 # the dialog's own shortcut clicks the last primary button: Next
        page.wait_for_function("() => document.querySelector('#new-maint-modal .wiz-step.active .wiz-lbl').textContent === 'Effects'")
        page.keyboard.press('Control+Enter')
        page.wait_for_function("() => document.querySelector('#new-maint-modal .wiz-step.active .wiz-lbl').textContent === 'Review'")
        last = page.evaluate("""() => [...document.querySelectorAll('#new-maint-modal .btn-primary:not([disabled])')]
            .filter(b => b.offsetParent !== null).pop().dataset.action""")
        self.assertEqual(last, 'saveMaintenance', 'at the review Ctrl-Enter saves, with the form\'s own function')

    def test_a_form_that_is_closed_opens_again_at_the_first_step(self):
        page = self.page
        mid = 'autopatch-modal'
        _set_steps(page, True)
        _open_form(page, mid, steps=True)
        _apply(page, [('set', 'autopatch-name', 'x')])
        _next(page, mid)
        self.assertEqual(_active(page, '#' + mid), 'When')
        page.keyboard.press('Escape')
        page.wait_for_function("() => !document.getElementById('autopatch-modal').classList.contains('active')")
        _open_form(page, mid, steps=True)
        shown = page.evaluate(_SHOWN, mid)
        self.assertEqual((_active(page, '#' + mid), shown['steps'], shown['review'], shown['submit']), ('What', [0], False, False))

    def test_an_existing_window_opens_in_steps_too(self):
        page = self.page
        _set_steps(page, True)
        page.evaluate("showPage('maintenance')")
        page.wait_for_selector('#page-maintenance.active')
        page.wait_for_selector('button[data-action-btn="_editMaintenanceBtn"]', timeout=20000)
        reason = page.evaluate("() => _evtData.get(document.querySelector('button[data-action-btn=\"_editMaintenanceBtn\"]').dataset.storeKey).reason")
        page.click('button[data-action-btn="_editMaintenanceBtn"] >> nth=0')
        page.wait_for_selector('#new-maint-modal.active')
        page.wait_for_selector('#new-maint-modal .wiz-steps')
        self.assertEqual(page.inner_text('#new-maint-modal .modal-title'), 'Edit maintenance window')
        self.assertEqual(page.input_value('#maint-reason'), reason)
        for _ in range(3):
            if _active(page, '#new-maint-modal') == 'Review':
                break
            _next(page, 'new-maint-modal')
        self.assertEqual(_active(page, '#new-maint-modal'), 'Review')
        self.assertIn(reason, page.inner_text('#new-maint-modal .wiz-review'))


# ── narrow windows, right to left, and the six languages ────────────────────────────────────────────────────────────────────
class TestWizardsNarrow(_Base):
    width = 390
    height = 844

    def test_no_wizard_step_runs_off_the_side(self):
        page = self.page
        _open_wizard(page, 'enroll')
        for _ in range(4):
            box = page.evaluate("""() => { const m = document.querySelector('#wizard-modal .modal');
                return [m.scrollWidth, m.clientWidth, document.documentElement.scrollWidth, document.documentElement.clientWidth]; }""")
            self.assertLessEqual(box[0], box[1] + 1, 'the dialog does not scroll sideways: %s' % box)
            self.assertLessEqual(box[2], box[3] + 1, 'nor does the page: %s' % box)
            if page.inner_text('#wiz-next') == 'Close':
                break
            page.click('#wiz-next')
            page.wait_for_function("() => true")
        hidden = page.evaluate("() => [...document.querySelectorAll('#wizard-modal .wiz-step:not(.active) .wiz-lbl')].map(e => getComputedStyle(e).display)")
        self.assertTrue(hidden and all(d == 'none' for d in hidden), 'only the step that shows keeps its name on a phone: %s' % hidden)
        page.keyboard.press('Escape')
        _open_wizard(page, 'notify')                           # the longest first step
        box = page.evaluate("() => { const m = document.querySelector('#wizard-modal .modal'); return [m.scrollWidth, m.clientWidth]; }")
        self.assertLessEqual(box[0], box[1] + 1)
        self.assertEqual(page.evaluate("() => getComputedStyle(document.querySelector('#wizard-modal .wiz-choices')).gridTemplateColumns.split(' ').length"), 1)

    def test_a_form_in_steps_fits_a_phone(self):
        page = self.page
        _set_steps(page, True)
        try:
            for mid in FORMS:
                _open_form(page, mid, steps=True)
                box = page.evaluate("(id) => { const m = document.querySelector('#' + id + ' > .modal'); return [m.scrollWidth, m.clientWidth]; }", mid)
                self.assertLessEqual(box[0], box[1] + 1, '%s: %s' % (mid, box))
                page.keyboard.press('Escape')
        finally:
            _set_steps(page, False)
            for mid in FORMS:
                page.evaluate("(id) => { if (typeof _wizFormDetach === 'function') _wizFormDetach(id); }", mid)


class TestWizardsRightToLeft(_Base):

    def setUp(self):
        self.page.evaluate("() => { document.documentElement.dir = 'rtl'; }")

    def tearDown(self):
        self.page.evaluate("() => { document.documentElement.dir = 'ltr'; }")
        super().tearDown()

    def test_the_step_list_and_the_switch_follow_the_direction(self):
        page = self.page
        _open_wizard(page, 'enroll')
        xs = page.eval_on_selector_all('#wizard-modal .wiz-step', 'els => els.map(e => e.getBoundingClientRect().x)')
        self.assertEqual(xs, sorted(xs, reverse=True), 'the first step is at the right: %s' % xs)
        page.keyboard.press('Escape')
        _set_steps(page, True)
        try:
            _open_form(page, 'new-maint-modal', steps=True)
            sw = page.evaluate("() => { const r = document.querySelector('#new-maint-modal .wiz-switch input').getBoundingClientRect(), "
                               "m = document.querySelector('#new-maint-modal > .modal').getBoundingClientRect(); return [r.x + r.width / 2, m.x + m.width / 2]; }")
            self.assertLess(sw[0], sw[1], 'the switch sits at the end of the row, which is the left: %s' % sw)
        finally:
            _set_steps(page, False)
            page.evaluate("(id) => { if (typeof _wizFormDetach === 'function') _wizFormDetach(id); }", 'new-maint-modal')


class TestWizardsTranslated(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        assert cls.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), 'i18n.js did not load'

    def tearDown(self):
        self.page.evaluate("() => RPi18n.setLang('en', false)")
        super().tearDown()

    def _untranslated(self, page, root):
        """Text on screen in `root` that still has a dictionary entry in this language: the engine would have translated it.
        The engine's observer works a moment after a node is added, so this looks until the list is empty or four seconds are up."""
        last = []

        def probe():
            nonlocal last
            last = page.evaluate("""(root) => {
                const out = [], w = document.createTreeWalker(document.querySelector(root), NodeFilter.SHOW_TEXT);
                for (let n = w.nextNode(); n; n = w.nextNode()) {
                    const t = n.nodeValue.trim();
                    if (t && n.parentElement.offsetParent !== null && RPi18n.t(t) !== t) out.push(t);
                }
                return out; }""", root)
            return not last

        _until(probe, seconds=4, step=0.2)
        return last

    def test_what_the_wizards_draw_is_translated(self):
        page = self.page
        langs = page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')")
        self.assertEqual(sorted(langs), ['ar', 'de', 'es', 'fr', 'hi', 'zh'])
        for lang in langs:
            title = page.evaluate("(l) => { RPi18n.setLang(l, false); return RPi18n.t('Add a host'); }", lang)
            self.assertNotEqual(title, 'Add a host', '%s: the dictionary has the title' % lang)
            _open_wizard(page, 'enroll')
            try:                                                       # the engine's observer works a moment after the node is added
                page.wait_for_function("(t) => document.querySelector('#wizard-modal .modal-title').textContent === t", arg=title, timeout=5000)
            except Exception:
                self.fail('%s: the title is drawn as %r, not %r' % (lang, page.inner_text('#wizard-modal .modal-title'), title))
            self.assertEqual(self._untranslated(page, '#wizard-modal'), [], '%s: step 1' % lang)
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-group')
            self.assertEqual(self._untranslated(page, '#wizard-modal'), [], '%s: step 2' % lang)
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-watch')
            self.assertEqual(self._untranslated(page, '#wizard-modal'), [], '%s: step 3' % lang)
            page.keyboard.press('Escape')
            _open_wizard(page, 'notify')
            self.assertEqual(self._untranslated(page, '#wizard-modal'), [], '%s: services' % lang)
            page.check('#wizard-modal input[name=wiz-fmt][value=pushover]')
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-name')
            self.assertEqual(self._untranslated(page, '#wizard-modal'), [], '%s: connection' % lang)
            page.keyboard.press('Escape')

    def test_what_the_forms_add_is_translated(self):
        page = self.page
        _set_steps(page, True)
        try:
            for lang in ('de', 'ar'):
                page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for mid in FORMS:
                    _open_form(page, mid, steps=True)
                    self.assertEqual(self._untranslated(page, '#' + mid), [], '%s %s step 1' % (lang, mid))
                    _fill_valid(page, mid)
                    for _ in range(6):
                        if page.evaluate("(id) => !document.querySelector('#' + id + ' .wiz-nav.btn-primary') || document.querySelector('#' + id + ' .wiz-nav.btn-primary').offsetParent === null", mid):
                            break
                        _next(page, mid)
                    self.assertEqual(self._untranslated(page, '#' + mid), [], '%s %s review' % (lang, mid))
                    page.keyboard.press('Escape')
        finally:
            _set_steps(page, False)
            for mid in FORMS:
                page.evaluate("(id) => { if (typeof _wizFormDetach === 'function') _wizFormDetach(id); }", mid)



# ── accessibility: axe on every step ─────────────────────────────────────────────────────────────────────────────────────────
try:
    from axe_core_python.sync_playwright import Axe
except ImportError:                                      # pragma: no cover
    Axe = None

_SETTLE_CSS = "*, *::before, *::after { animation-duration: 0s !important; animation-delay: 0s !important; transition-duration: 0s !important; transition-delay: 0s !important; }"


class TestWizardsAccessible(_Base):
    """The project's bar (tests/test_a11y_axe.py): no critical or serious violation, every default rule on, measured on the settled dialog."""

    @classmethod
    def setUpClass(cls):
        if Axe is None:
            browser_required.skip_or_fail('axe-core-python not installed')
        super().setUpClass()
        cls.axe = Axe()
        cls.page.add_style_tag(content=_SETTLE_CSS)
        cls.page.evaluate("() => _loadJsModule('app-wizard.js')")

    def _axe(self, root, label):
        page = self.page
        page.evaluate(self.axe.axe_script)
        results = page.evaluate("(root) => axe.run({include: [[root]]}, {}).then(r => r)", root)
        serious = [v for v in (results.get('violations') or []) if v.get('impact') in ('critical', 'serious')]
        self.assertEqual([(v['id'], v['impact'], [n['target'] for n in v['nodes']][:3]) for v in serious], [], label)
        self.assertGreater(len(results.get('passes') or []), 5, '%s: axe looked at something' % label)

    def test_add_a_host_on_every_step(self):
        page = self.page
        _open_wizard(page, 'enroll')
        self._axe('#wizard-modal', 'enroll: type')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-group')
        self._axe('#wizard-modal', 'enroll: settings')
        page.click('#wiz-next')
        page.wait_for_selector('#wiz-cmd-linux')
        self._axe('#wizard-modal', 'enroll: install')
        status, body = _register(token=_token_of(page), name='wiz-axe-host')
        self.assertEqual(status, 201, body)
        page.wait_for_function("() => /Checked in/.test((document.getElementById('wiz-watch') || {}).textContent || '')", timeout=20000)
        self._axe('#wizard-modal', 'enroll: install, arrived')
        page.click('#wiz-next')
        page.wait_for_selector('.wiz-list')
        self._axe('#wizard-modal', 'enroll: done')

    def test_add_a_notification_destination_on_every_step(self):
        page = self.page
        recv = Receiver()
        try:
            _set_destinations(page, [])
            _open_wizard(page, 'notify')
            self._axe('#wizard-modal', 'notify: service')
            page.check('#wizard-modal input[name=wiz-fmt][value=pushover]')
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-name')
            self._axe('#wizard-modal', 'notify: connection')
            page.fill('#wiz-url', recv.url)
            page.fill('#wiz-f-pushover_token', 't')
            page.fill('#wiz-f-pushover_user', 'u')
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-test')
            self._axe('#wizard-modal', 'notify: test, not yet sent')
            _send_test(page)
            self._axe('#wizard-modal', 'notify: test, delivered')
            recv.status = 404
            _send_test(page)
            self._axe('#wizard-modal', 'notify: test, refused')
            page.click('#wiz-next')
            page.wait_for_selector('#wiz-prio')
            self._axe('#wizard-modal', 'notify: finish')
        finally:
            page.keyboard.press('Escape')
            page.wait_for_function("() => !document.getElementById('wizard-modal')")
            _until(lambda: _destinations(page) == [], seconds=10)
            _set_destinations(page, [])
            recv.stop()

    def test_the_forms_in_steps_on_every_step(self):
        page = self.page
        _set_steps(page, True)
        try:
            for mid in FORMS:
                _open_form(page, mid, steps=True)
                _fill_valid(page, mid)
                for _ in range(8):
                    label = _active(page, '#' + mid)
                    self._axe('#' + mid, '%s: %s' % (mid, label))
                    if label == 'Review':
                        break
                    _next(page, mid)
                page.keyboard.press('Escape')
        finally:
            _set_steps(page, False)
            for mid in FORMS:
                page.evaluate("(id) => { if (typeof _wizFormDetach === 'function') _wizFormDetach(id); }", mid)


if __name__ == '__main__':
    unittest.main()
