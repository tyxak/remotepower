#!/usr/bin/env python3
"""7.4.0: the product can be used from the keyboard, measured on a seeded instance.

Four things a person who never touches the mouse needs, each measured in a real browser on the real
page, with the keys a person would press:

  * A dialog takes focus when it opens, keeps Tab inside, closes on Escape and gives focus back. The
    first control in a dialog is the Close button the app injects at the top of the panel, so "focus the
    first control" put focus on Close in 139 of 140 dialogs, and the first Enter or Space after opening
    one dismissed it. Focus now goes to the first control of the content.
  * The overlays that are not dialogs do the same: Bulk actions was built by hand with none of it (and
    its "type RUN to confirm" prompt opened behind it), the notification popover ignored Escape.
  * Everything a mouse can click has a keyboard path: the Home feed, the attention rows and the Sites
    map dots had none.
  * Focus is visible on every control that can take it.

The populations are derived (the dialogs from index.html, the pages from the sidebar), a walk that
opens or visits nothing fails, and each detector is shown a page made wrong on purpose.

Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
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
import keyboard_walk as kw  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()


_STACK = {}


def setUpModule():
    """One seeded instance, one browser and one signed-in page for the whole file: booting the stack
    costs more than any single walk. The login is an account the seeder makes."""
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('what is measured is the page, not the backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-keyboard-')
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
    # The first-run tour is tested on its own (TestTheFirstRunTour); here it would cover every walk.
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    page.goto(base + '/index.html')
    page.fill('#login-user', 'alice')
    page.fill('#login-pass', 'demo')
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector('#app', state='visible', timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK['browser'].close()
        _STACK['pw'].stop()
    finally:
        _STACK['shutdown']()
        _STACK.clear()


def _go(page, name, wait=1200):
    page.evaluate("n => showPage(n)", name)
    page.wait_for_timeout(wait)


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.page = _STACK['page']
        cls.base = _STACK['base']

    def go(self, name, wait=1200):
        _go(self.page, name, wait)


def _show(items, limit=15):
    return '\n'.join('  ' + str(i) for i in items[:limit]) + (f'\n  ... and {len(items) - limit} more' if len(items) > limit else '')


class TestEveryDialogIsAKeyboardDialog(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ids = kw.dialog_ids()
        cls.results = [kw.walk_dialog(cls.page, mid) for mid in cls.ids]
        cls.opened = [r for r in cls.results if r.get('active')]

    def test_the_walk_opened_the_dialogs(self):
        self.assertGreater(len(self.ids), 100, 'the id regex found only %d dialogs' % len(self.ids))
        self.assertGreaterEqual(len(self.opened), len(self.ids) - 2,
                                'dialogs that did not open: %s' % [r['id'] for r in self.results if not r.get('active')])

    def test_focus_goes_into_the_dialog(self):
        self.assertEqual([r['id'] for r in self.opened if not r['inside']], [])

    def test_focus_lands_on_content_not_on_close(self):
        """Close is the fallback only for a dialog that has no other control to start on."""
        bad = [(r['id'], r['landed']) for r in self.opened if r['landedOnClose'] and r['otherControls'] > 0]
        self.assertEqual(bad, [], 'these open with focus on the Close button although they have other controls:\n' + _show(bad))

    def test_tab_stays_inside(self):
        self.assertEqual([r['id'] for r in self.opened if r['tab_escaped']], [])
        self.assertEqual([r['id'] for r in self.opened if r['shift_tab_escaped']], [])

    def test_escape_closes_and_focus_goes_back(self):
        self.assertEqual([r['id'] for r in self.opened if not r['escape_closes']], [])
        self.assertEqual([r['id'] for r in self.opened if not r['focus_returned']], [])

    def test_the_walk_can_see_a_dialog_with_no_keyboard_support(self):
        """Control: a dialog that activates itself, the way a hand-built one does, has no trap, no Escape and
        no focus return. The same walk must say so."""
        self.page.evaluate("""() => {
            const o = document.createElement('div'); o.id = 'kb-control'; o.className = 'modal-overlay';
            o.innerHTML = '<div class="modal"><input id="kb-control-in"><button id="kb-control-btn">Go</button></div>';
            document.body.appendChild(o); }""")
        try:
            rec = kw.walk_dialog(self.page, 'kb-control', open_js="id => document.getElementById(id).classList.add('active')")
        finally:
            self.page.evaluate("() => document.getElementById('kb-control')?.remove()")
        self.assertTrue(rec['active'])
        self.assertFalse(rec['inside'], 'focus did not move in, and the walk missed it')
        self.assertTrue(rec['tab_escaped'], 'Tab was not trapped, and the walk missed it')
        self.assertFalse(rec['escape_closes'], 'Escape did not close it, and the walk missed it')


class TestTheFirstRunTour(_Base):
    """The tour is the first thing a new person meets, so it is the first thing a keyboard user has to drive."""

    def test_the_tour_is_a_dialog_the_keyboard_can_drive(self):
        ctx = _STACK['browser'].new_context(viewport={'width': 1440, 'height': 900})   # a fresh profile: not seen yet
        page = ctx.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.evaluate("() => showPage('home')")           # the tour starts the first time the dashboard is shown
            page.wait_for_selector('#tour-backdrop', timeout=20000)
            page.wait_for_timeout(300)
            facts = page.evaluate("""() => { const b = document.getElementById('tour-backdrop'); const a = document.activeElement;
                return {role: b.getAttribute('role'), modal: b.getAttribute('aria-modal'),
                        name: (document.getElementById(b.getAttribute('aria-labelledby')) || {}).textContent,
                        inside: b.contains(a), on: a && a.textContent}; }""")
            self.assertEqual((facts['role'], facts['modal']), ('dialog', 'true'))
            self.assertEqual(facts['name'], 'Dashboard', 'the dialog has no name')
            self.assertTrue(facts['inside'], 'focus is not in the tour: a keyboard user would Tab around the page behind it')
            self.assertEqual(facts['on'], 'Next', 'focus should start on the button that moves the tour on')
            for _ in range(8):
                page.keyboard.press('Tab')
                self.assertTrue(page.evaluate("() => document.getElementById('tour-backdrop').contains(document.activeElement)"), 'Tab left the tour')
            page.evaluate("() => [...document.querySelectorAll('#tour-backdrop button')].find(b => b.textContent === 'Next').focus()")
            page.keyboard.press('Enter')
            page.wait_for_timeout(300)
            self.assertEqual(page.evaluate("() => document.getElementById('tour-title').textContent"), 'Hosts', 'Enter on Next did not advance')
            self.assertTrue(page.evaluate("() => document.getElementById('tour-backdrop').contains(document.activeElement)"), 'focus was lost between steps')
            page.keyboard.press('Escape')
            page.wait_for_timeout(300)
            self.assertFalse(page.evaluate("() => !!document.getElementById('tour-backdrop')"), 'Escape did not end the tour')
            self.assertEqual(page.evaluate("() => localStorage.getItem('rp_tour_done')"), '1', 'the tour would come back on the next visit')
            self.assertEqual(page.evaluate("() => document.querySelectorAll('.tour-target').length"), 0, 'a nav button is still highlighted')
        finally:
            page.close()
            ctx.close()


class TestTheOverlaysThatAreNotDialogs(_Base):

    def _open_by_keyboard(self, selector):
        self.page.wait_for_selector(selector, state='visible', timeout=20000)
        self.page.evaluate("s => { const e = [...document.querySelectorAll(s)].find(x => x.offsetParent !== null); e.focus(); window.__opener = e; }", selector)
        self.page.keyboard.press('Enter')
        self.page.wait_for_timeout(800)

    def test_bulk_actions(self):
        self.go('devices', 2500)
        self._open_by_keyboard("[data-action='openBulkActions']")
        p = self.page
        self.assertTrue(p.evaluate("() => { const o = document.getElementById('bulk-modal-overlay'); return !!o && o.classList.contains('active'); }"))
        self.assertTrue(p.evaluate("() => document.getElementById('bulk-modal-overlay').contains(document.activeElement)"), 'focus did not move into Bulk actions')
        self.assertEqual(p.evaluate("() => document.getElementById('bulk-modal-overlay').getAttribute('aria-modal')"), 'true')
        for _ in range(30):
            p.keyboard.press('Tab')
            self.assertTrue(p.evaluate("() => document.getElementById('bulk-modal-overlay').contains(document.activeElement)"), 'Tab left Bulk actions')
        # Run a reboot: the confirmation prompt has to be on top of the dialog it was asked from.
        p.select_option('#bulk-action', 'reboot')
        p.click("[data-action='runBulkAction']")
        p.wait_for_timeout(700)
        covered = p.evaluate("""() => { const m = document.querySelector('#ui-prompt-modal .modal'); const r = m.getBoundingClientRect();
            const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); return !m.contains(hit); }""")
        self.assertFalse(covered, 'the "type RUN to confirm" prompt is hidden behind Bulk actions')
        p.keyboard.press('Escape')                  # the prompt first
        p.wait_for_timeout(300)
        self.assertTrue(p.evaluate("() => !!document.getElementById('bulk-modal-overlay')"), 'one Escape closed both dialogs')
        p.keyboard.press('Escape')                  # then Bulk actions
        p.wait_for_timeout(300)
        self.assertFalse(p.evaluate("() => !!document.getElementById('bulk-modal-overlay')"), 'Escape did not close Bulk actions')
        self.assertTrue(p.evaluate("() => document.activeElement === window.__opener"), 'focus did not go back to the button')
        # And it must be possible to open it again.
        p.keyboard.press('Enter')
        p.wait_for_timeout(800)
        self.assertTrue(p.evaluate("() => { const o = document.getElementById('bulk-modal-overlay'); return !!o && o.classList.contains('active'); }"),
                        'Bulk actions did not open a second time')
        p.keyboard.press('Escape')

    def test_the_shortcut_sheet(self):
        """The `?` sheet lists Esc as "close any modal"; it was hand-built and Escape did not close it."""
        self.go('home')
        p = self.page
        p.evaluate("() => { const b = document.getElementById('toast-history-btn'); b.focus(); window.__opener = b; }")
        p.keyboard.press('Shift+Slash')
        p.wait_for_timeout(500)
        self.assertTrue(p.evaluate("() => { const o = document.getElementById('kbd-cheat-overlay'); return !!o && o.classList.contains('active'); }"), '? did not open the sheet')
        self.assertEqual(p.evaluate("() => document.getElementById('kbd-cheat-overlay').getAttribute('aria-modal')"), 'true')
        self.assertTrue(p.evaluate("() => document.getElementById('kbd-cheat-overlay').contains(document.activeElement)"), 'focus did not move into the sheet')
        for _ in range(8):
            p.keyboard.press('Tab')
            self.assertTrue(p.evaluate("() => document.getElementById('kbd-cheat-overlay').contains(document.activeElement)"), 'Tab left the sheet')
        p.keyboard.press('Escape')
        p.wait_for_timeout(300)
        self.assertFalse(p.evaluate("() => !!document.getElementById('kbd-cheat-overlay')"), 'Escape did not close the sheet')
        self.assertTrue(p.evaluate("() => document.activeElement === window.__opener"), 'focus did not go back')

    def test_the_notification_popover(self):
        self.go('home')
        self.page.evaluate("() => document.getElementById('toast-history-pop').classList.add('hidden')")
        self._open_by_keyboard('#toast-history-btn')
        p = self.page
        self.assertFalse(p.evaluate("() => document.getElementById('toast-history-pop').classList.contains('hidden')"))
        self.assertTrue(p.evaluate("() => document.getElementById('toast-history-pop').contains(document.activeElement)"), 'focus did not move into the popover')
        p.keyboard.press('Escape')
        p.wait_for_timeout(200)
        self.assertTrue(p.evaluate("() => document.getElementById('toast-history-pop').classList.contains('hidden')"), 'Escape did not close the popover')
        self.assertTrue(p.evaluate("() => document.activeElement === window.__opener"), 'focus did not go back to the bell')

    def test_the_row_menu_and_the_palette_and_the_drawer_still_do_it(self):
        p = self.page
        # row menu
        self.go('alerts', 2000)
        self._open_by_keyboard("#page-alerts [data-action='rowMoreMenu']")
        self.assertTrue(p.evaluate("() => { const m = document.getElementById('row-more-pop'); return !!m && getComputedStyle(m).display !== 'none' && m.contains(document.activeElement); }"))
        p.keyboard.press('Escape')
        p.wait_for_timeout(300)
        self.assertTrue(p.evaluate("() => document.activeElement === window.__opener"), 'the row menu did not give focus back')
        # host drawer
        self.go('devices', 2500)
        self._open_by_keyboard("#page-devices button[data-action='openDeviceDrawer']")
        self.assertTrue(p.evaluate("() => document.getElementById('device-drawer').classList.contains('open') && document.getElementById('device-drawer').contains(document.activeElement)"))
        # The drawer fills in after it opens; under a loaded full run the Tabs raced that fill
        # (failed twice in the JSON gate, passed alone), so let it settle and pace the presses.
        p.wait_for_timeout(1500)
        for _ in range(40):
            p.keyboard.press('Tab')
            p.wait_for_timeout(15)
        self.assertTrue(p.evaluate("() => document.getElementById('device-drawer').contains(document.activeElement)"), 'Tab left the host drawer')
        p.keyboard.press('Escape')
        p.wait_for_timeout(500)
        self.assertFalse(p.evaluate("() => document.getElementById('device-drawer').classList.contains('open')"))
        self.assertTrue(p.evaluate("() => document.activeElement === window.__opener"), 'the drawer did not give focus back')
        # command palette
        p.evaluate("() => document.getElementById('toast-history-btn').focus()")
        p.keyboard.press('Control+k')
        p.wait_for_timeout(500)
        self.assertTrue(p.evaluate("() => { const c = document.querySelector('[aria-label=\"Command palette\"]'); return !!c && c.contains(document.activeElement); }"))
        p.keyboard.press('Escape')
        p.wait_for_timeout(400)
        self.assertEqual(p.evaluate("() => document.activeElement && document.activeElement.id"), 'toast-history-btn')

    def test_an_async_button_keeps_focus(self):
        """_btnInflight disables the button while its handler runs, which drops focus to <body>. It is given
        back when the button is enabled again."""
        self.go('home')
        ok = self.page.evaluate("""async () => {
            const b = document.createElement('button'); b.id = 'kb-async'; b.textContent = 'x'; document.body.appendChild(b);
            window.kbAsyncHandler = () => new Promise(r => setTimeout(r, 120));
            b.setAttribute('data-action', 'kbAsyncHandler'); b.focus();
            b.click();
            const during = document.activeElement === b;
            await new Promise(r => setTimeout(r, 400));
            const after = document.activeElement === b;
            b.remove();
            return {during, after};
        }""")
        self.assertTrue(ok['after'], 'focus was not given back to the button after its handler finished: %s' % ok)


class TestEveryClickableThingHasAKeyboardPath(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pages = kw.nav_pages()
        cls.walk = {}
        for name in cls.pages:
            _go(cls.page, name, 500)
            cls.page.keyboard.press('Shift')          # a keyboard event, so a programmatic focus() matches :focus-visible
            cls.walk[name] = cls.page.evaluate(kw.MEASURE_PAGE, name)

    def test_the_walk_visited_the_pages(self):
        self.assertGreater(len(self.pages), 70)
        self.assertGreater(sum(w['listed'] for w in self.walk.values()), 2000, 'almost no controls were listed')
        self.assertGreater(sum(w['focused'] for w in self.walk.values()), 2000, 'almost no control took focus')

    def test_no_control_is_reachable_only_with_a_mouse(self):
        hits = [(n, m['el'], m['action'], m['text']) for n, w in self.walk.items() for m in w['mouseOnly']]
        self.assertEqual(hits, [], 'these have a click handler and cannot be focused:\n' + _show(hits))

    def test_nothing_that_looks_clickable_is_unreachable(self):
        hits = [(n, m['el'], m['text']) for n, w in self.walk.items() for m in w['pointerOnly']]
        self.assertEqual(hits, [], 'these show a pointer cursor and have no keyboard path:\n' + _show(hits))

    def test_no_positive_tabindex(self):
        self.assertEqual({n: w['positiveTabindex'] for n, w in self.walk.items() if w['positiveTabindex']}, {})

    def test_every_control_shows_focus(self):
        hits = [(n, d) for n, w in self.walk.items() for d in w['noChange']]
        self.assertEqual(hits, [], 'these look the same focused and not focused:\n' + _show(hits))

    def test_the_fixed_controls_work_from_the_keyboard(self):
        """Press Enter on each of the three that had no keyboard path, and see its handler run."""
        p = self.page
        self.go('home', 2500)
        # spy on the handler the feed rows dispatch to
        p.evaluate("() => { window.__navCalls = 0; const o = window._homeNavAction; window._homeNavAction = function () { window.__navCalls++; return o && o.apply(this, arguments); }; }")
        n = p.evaluate("() => document.querySelectorAll('#page-home .dash-feed-item.pointer').length")
        self.assertGreater(n, 0, 'the seeded Home page has no activity feed rows to test')
        p.evaluate("() => { const r = document.querySelector('#page-home .dash-feed-item.pointer'); r.focus(); }")
        self.assertTrue(p.evaluate("() => document.activeElement.classList.contains('dash-feed-item')"), 'a feed row cannot take focus')
        p.keyboard.press('Enter')
        p.wait_for_timeout(300)
        self.assertGreater(p.evaluate("() => window.__navCalls"), 0, 'Enter on a feed row did nothing')
        self.go('sites', 2500)
        p.evaluate("() => { window.__dot = 0; const o = window.siteMapClick; window.siteMapClick = function () { window.__dot++; return o && o.apply(this, arguments); }; }")
        dots = p.evaluate("() => document.querySelectorAll('#page-sites circle.site-map-dot').length")
        self.assertGreater(dots, 0, 'the seeded Sites page has no map dots to test')
        p.evaluate("() => document.querySelector('#page-sites circle.site-map-dot').focus()")
        self.assertTrue(p.evaluate("() => document.activeElement.classList.contains('site-map-dot')"), 'a map dot cannot take focus')
        self.assertTrue(p.evaluate("() => !!document.activeElement.getAttribute('aria-label')"), 'a map dot has no name')
        p.keyboard.press('Enter')
        p.wait_for_timeout(300)
        self.assertGreater(p.evaluate("() => window.__dot"), 0, 'Enter on a map dot did nothing')

    def test_the_detectors_can_see_what_they_look_for(self):
        """Controls: a clickable div with no tabindex, a pointer-cursor box, and every outline removed."""
        self.go('home', 800)
        self.page.evaluate("""() => {
            const root = document.getElementById('page-home');
            const a = document.createElement('div'); a.id = 'kb-c1'; a.setAttribute('data-action', 'noop'); a.textContent = 'mouse only'; root.appendChild(a);
            const b = document.createElement('span'); b.id = 'kb-c2'; b.style.cursor = 'pointer'; b.textContent = 'looks clickable'; root.appendChild(b);
            const s = document.createElement('style'); s.id = 'kb-c3'; s.textContent = '*,*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}'; document.head.appendChild(s);
        }""")
        try:
            self.page.keyboard.press('Shift')
            w = self.page.evaluate(kw.MEASURE_PAGE, 'home')
        finally:
            self.page.evaluate("() => ['kb-c1', 'kb-c2', 'kb-c3'].forEach(i => document.getElementById(i)?.remove())")
        self.assertIn('div#kb-c1', [m['el'] for m in w['mouseOnly']], 'the data-action detector missed a clickable div')
        self.assertIn('span#kb-c2', [m['el'] for m in w['pointerOnly']], 'the pointer detector missed a pointer-cursor box')
        self.assertGreater(len(w['noChange']), w['focused'] // 2, 'with every outline removed the detector still found focus visible: %d of %d' % (len(w['noChange']), w['focused']))


if __name__ == '__main__':
    unittest.main()
