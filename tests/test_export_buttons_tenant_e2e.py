#!/usr/bin/env python3
"""The redacted export and the calendar export, pressed in a real browser by a tenant administrator and by the platform operator.

With tenancy on the server refuses both downloads to a tenant's users (the export of every store is the platform operator's, the calendar
is the operator organisation's). The two buttons used to save the refusal as the file, under a .zip or .ics name, and say "Backup
downloaded" or "Calendar exported" over it. This module drives the real page, with real sessions on a real server:

* a tenant administrator is not shown the Backup & restore card at all (it holds four buttons the server refuses), and the Scheduled backup
  card beside it is shown, so the tab did draw;
* a tenant administrator who presses Export anyway (the card shown again by hand, a real click on the drawn button) is saved no file and the
  page says "Export failed", never "Backup downloaded"; the calendar button behaves the same;
* the platform operator, in the same stack, is shown the card and is saved a real ZIP (it opens, holds users.json, and that file carries no
  password hash) and a real calendar, with the success toast. These two are the controls of the two above: the recorder of downloads and of
  toasts is believed when it has been seen to record.

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
import zipfile
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

PW = 'Export-Probe-Passw0rd!1'
_STATE = {}

# the users, the tenant and the settings, written through the product's own storage in a data directory of this module's own
_SETUP = r"""
import os, sys, time
sys.path.insert(0, os.environ['RP_CGI'])
import api
now = int(time.time())
pw = os.environ['RP_PW']
def user(role, tenant=None):
    u = {'role': role, 'password_hash': api.hash_password(pw), 'created': now, 'password_changed_at': now}
    if tenant:
        u['tenant_id'] = tenant
    return u
api.save(api.CONFIG_FILE, {'tenancy_enforced': True, 'backup': {'enabled': False}})
api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'builtin': True, 'status': 'active', 'created': now},
                            'tenantB': {'name': 'B', 'status': 'active', 'created': now}})
api.save(api.USERS_FILE, {'operator': user('admin'), 'adminB': user('admin', 'tenantB')})
"""

# every toast the page draws is kept, as the person would have seen it
_WATCH_TOASTS = """() => {
  window.__toasts = [];
  const box = document.getElementById('toast-container');
  new MutationObserver(list => list.forEach(r => r.addedNodes.forEach(n => {
    if (n.nodeType === 1) window.__toasts.push((n.textContent || '').trim());
  }))).observe(box, {childList: true});
}"""


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the buttons are backend-agnostic: measured once, under the default backend')
    data_dir = tempfile.mkdtemp(prefix='rp-export-btn-e2e-')
    r = subprocess.run([sys.executable, '-c', _SETUP], capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, RP_DATA_DIR=data_dir, RP_CGI=str(_ROOT / 'server' / 'cgi-bin'), RP_PW=PW))
    if r.returncode != 0:
        shutil.rmtree(data_dir, ignore_errors=True)
        raise unittest.SkipTest('setup failed: ' + r.stderr[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        shutil.rmtree(data_dir, ignore_errors=True)
        browser_required.skip_or_fail(f'chromium not available: {exc}')
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        shutil.rmtree(data_dir, ignore_errors=True)
        raise unittest.SkipTest(f'app stack not available: {exc}')
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()
        shutil.rmtree(_STATE.get('data_dir', ''), ignore_errors=True)       # the data dir is tmpfs on some machines: take it away with the stack


def _until(fn, seconds=20, step=0.2):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(step)
    return last


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Session(unittest.TestCase):
    user = ''

    @classmethod
    def setUpClass(cls):
        cls.ctx = _STATE['browser'].new_context(viewport={'width': 1440, 'height': 900}, service_workers='block', accept_downloads=True)
        cls.ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                                "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.page = cls.ctx.new_page()
        cls.downloads = []
        cls.page.on('download', lambda d: cls.downloads.append(d))
        cls.page.goto(_STATE['base'] + '/index.html')
        cls.page.fill('#login-user', cls.user)
        cls.page.fill('#login-pass', PW)
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_function("() => typeof _meCache !== 'undefined' && _meCache && _meCache.username", timeout=60000)
        cls.page.evaluate(_WATCH_TOASTS)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.ctx.close()
        except Exception:                                # pragma: no cover
            pass

    def setUp(self):
        del self.downloads[:]
        self.page.evaluate("() => { window.__toasts = []; document.querySelectorAll('#toast-container .toast').forEach(e => e.remove()); }")

    def toasts(self):
        return self.page.evaluate("() => window.__toasts")

    def open_backups_tab(self):
        page = self.page
        page.evaluate("showPage('settings')")
        page.click('#settings-tab-btn-backups')
        page.wait_for_selector('#settings-pane-backups .section-title >> text=Scheduled backup', state='visible', timeout=30000)

    def show_the_card_by_hand(self):
        """What an old page, or a person with the developer tools open, would have: the card drawn although the page hid it. Put back after the test,
        because the page is shared by the tests of a class."""
        self.page.evaluate("() => { const c = document.querySelector('#settings-pane-backups [data-platform-only]'); if (c) c.classList.remove('hidden'); }")
        self.addCleanup(self.page.evaluate, "() => { if (typeof _applyPlatformOnly === 'function') _applyPlatformOnly(); }")

    def card_buttons_drawn(self):
        return self.page.evaluate("""() => ['exportBackup', 'downloadBackup', 'pickRestoreFile', 'openS3Restore'].map(a => {
            const b = document.querySelector('#settings-pane-backups button[data-action="' + a + '"]');
            if (!b) return [a, 'missing'];
            const r = b.getBoundingClientRect();
            return [a, r.width > 0 && r.height > 0];
        })""")


class TestTenantAdministrator(_Session):
    user = 'adminB'

    def test_the_session_is_a_tenant_administrators(self):
        me = self.page.evaluate("() => ({admin: _meCache.admin, tenant: _meCache.tenant})")
        self.assertEqual(me, {'admin': True, 'tenant': 'tenantB'})

    def test_the_backup_and_restore_card_is_not_drawn_and_the_card_beside_it_is(self):
        self.open_backups_tab()
        card = self.page.locator('#settings-pane-backups [data-platform-only]')
        self.assertEqual(card.count(), 1)
        self.assertFalse(card.is_visible(), 'the Backup & restore card is drawn for a tenant administrator')
        self.assertEqual(self.card_buttons_drawn(), [['exportBackup', False], ['downloadBackup', False], ['pickRestoreFile', False], ['openS3Restore', False]])
        # the control: the card above it on the same tab is drawn, so the tab did render and the card was left out on purpose
        self.assertTrue(self.page.locator('#settings-pane-backups .section-title >> text=Scheduled backup').is_visible())

    def test_pressing_export_anyway_saves_no_file_and_says_it_failed(self):
        page = self.page
        self.open_backups_tab()
        self.show_the_card_by_hand()
        page.click('#settings-pane-backups button[data-action="exportBackup"]')            # a real click on the drawn button
        self.assertTrue(_until(lambda: 'Export failed' in self.toasts()), 'no toast said the export failed: %s' % self.toasts())
        page.wait_for_timeout(500)
        self.assertEqual([d.suggested_filename for d in self.downloads], [], 'a file was saved from a refused export')
        self.assertFalse([t for t in self.toasts() if 'Backup downloaded' in t], 'the page said the backup was downloaded: %s' % self.toasts())

    def test_the_full_backup_button_is_refused_the_same_way(self):
        # the sibling that already went through the checking helper: held here so the two are seen to agree
        page = self.page
        self.open_backups_tab()
        self.show_the_card_by_hand()
        page.click('#settings-pane-backups button[data-action="downloadBackup"]')
        self.assertTrue(_until(lambda: 'Export failed' in self.toasts()), self.toasts())
        page.wait_for_timeout(500)
        self.assertEqual([d.suggested_filename for d in self.downloads], [])

    def test_the_calendar_export_saves_no_file_and_says_it_failed(self):
        page = self.page
        page.evaluate("showPage('calendar')")
        page.wait_for_selector('#page-calendar.active button[data-action="exportCalendarIcs"]', state='visible', timeout=30000)
        page.evaluate("() => { window.__toasts = []; }")
        page.click('#page-calendar button[data-action="exportCalendarIcs"]')
        self.assertTrue(_until(lambda: 'Export failed' in self.toasts()), 'no toast said the calendar export failed: %s' % self.toasts())
        page.wait_for_timeout(500)
        self.assertEqual([d.suggested_filename for d in self.downloads], [], 'a file was saved from a refused calendar export')
        self.assertFalse([t for t in self.toasts() if 'Calendar exported' in t], self.toasts())


class TestPlatformOperator(_Session):
    user = 'operator'

    def test_the_session_is_the_platform_operators(self):
        me = self.page.evaluate("() => ({admin: _meCache.admin, tenant: _meCache.tenant})")
        self.assertEqual(me, {'admin': True, 'tenant': 'default'})

    def test_the_card_is_drawn_with_all_four_buttons(self):
        self.open_backups_tab()
        self.assertTrue(self.page.locator('#settings-pane-backups [data-platform-only]').is_visible())
        self.assertEqual(self.card_buttons_drawn(), [['exportBackup', True], ['downloadBackup', True], ['pickRestoreFile', True], ['openS3Restore', True]])

    def test_export_saves_a_real_zip_without_credentials_and_says_so(self):
        page = self.page
        self.open_backups_tab()
        with page.expect_download(timeout=60000) as dl:
            page.click('#settings-pane-backups button[data-action="exportBackup"]')
        d = dl.value
        self.assertRegex(d.suggested_filename, r'^remotepower-backup-.*\.zip$')
        path = d.path()
        self.assertTrue(zipfile.is_zipfile(path), 'what was saved is not a ZIP: %r' % Path(path).read_bytes()[:80])
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            self.assertIn('users.json', names)
            users = json.loads(zf.read('users.json'))
        self.assertEqual(sorted(users), ['adminB', 'operator'], 'the export holds the accounts of every tenant: that is why it is the operator\'s')
        self.assertFalse([u for u, r in users.items() if 'password_hash' in r], 'a password hash is in the shareable export')
        self.assertTrue(_until(lambda: 'Backup downloaded' in self.toasts()), self.toasts())

    def test_the_calendar_export_saves_a_calendar_and_says_so(self):
        page = self.page
        page.evaluate("showPage('calendar')")
        page.wait_for_selector('#page-calendar.active button[data-action="exportCalendarIcs"]', state='visible', timeout=30000)
        with page.expect_download(timeout=60000) as dl:
            page.click('#page-calendar button[data-action="exportCalendarIcs"]')
        d = dl.value
        self.assertEqual(d.suggested_filename, 'remotepower-calendar.ics')
        text = Path(d.path()).read_text()
        self.assertTrue(text.startswith('BEGIN:VCALENDAR'), text[:80])
        self.assertTrue(text.rstrip().endswith('END:VCALENDAR'))
        self.assertTrue(_until(lambda: 'Calendar exported' in self.toasts()), self.toasts())


if __name__ == '__main__':
    unittest.main()
