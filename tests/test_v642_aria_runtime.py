"""v6.4.2: ARIA state must actually CHANGE, not just ship as a literal.

An earlier pass added `aria-expanded` to all 12 sidebar toggles and a full
tablist/tab/tabpanel skeleton to all 5 tab widgets — in the HTML only. Nothing
updated them at runtime, so every group announced itself as collapsed forever
(including the open one) and every tab stayed frozen at its page-load
`aria-selected`. A state attribute that never changes is worse than none: it
actively lies to a screen reader (WCAG 2.1 SC 4.1.2).

No source-text test can catch that class — the attribute IS in the markup and a
grep is satisfied. These drive a real browser and read the live DOM.

Guarded on `browser_available()` (an actual chromium launch), not on
`import playwright` — the two are different questions and the wrong guard turns
a missing browser into an ERROR instead of a skip.

Run: python3 -m pytest tests/test_v642_aria_runtime.py -q
"""

import os
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from e2e_harness import browser_available, start_stack  # noqa: E402


@unittest.skipUnless(browser_available(),
                     'playwright + chromium + gunicorn not available')
class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:                       # pragma: no cover
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack()
        except Exception as exc:                       # pragma: no cover
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls._shutdown()
        finally:
            cls.browser.close()
            cls._pw.stop()

    def setUp(self):
        self.page = self.browser.new_page()
        self.page.goto(self.base + '/index.html')
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        self.page.wait_for_selector('#page-home.active', timeout=15000)

    def tearDown(self):
        self.page.close()


class TestSidebarAccordionAnnouncesItsState(_Base):
    def _expanded(self):
        """{group name: aria-expanded} for every sidebar group toggle."""
        return self.page.evaluate("""() => {
            const out = {};
            document.querySelectorAll('.sidebar-group').forEach(g => {
                const t = g.querySelector('.sidebar-group-toggle');
                if (t) out[g.dataset.group] = t.getAttribute('aria-expanded');
            });
            return out;
        }""")

    def test_opening_a_group_sets_exactly_one_expanded(self):
        groups = list(self._expanded())
        self.assertGreaterEqual(len(groups), 2, 'need >=2 groups to test the accordion')
        target = groups[0]
        self.page.evaluate(f"_openSidebarGroup({target!r})")
        state = self._expanded()
        self.assertEqual(state[target], 'true',
                         'the opened group still reports aria-expanded=false')
        others = [g for g, v in state.items() if g != target and v != 'false']
        self.assertEqual(others, [], f'these stayed expanded: {others}')

    def test_opening_a_second_group_closes_the_first(self):
        """The accordion's one-open-at-a-time contract, in ARIA not just CSS."""
        groups = list(self._expanded())
        a, b = groups[0], groups[1]
        self.page.evaluate(f"_openSidebarGroup({a!r})")
        self.page.evaluate(f"_openSidebarGroup({b!r})")
        state = self._expanded()
        self.assertEqual(state[b], 'true')
        self.assertEqual(state[a], 'false', 'the previous group stayed expanded')

    def test_the_attribute_tracks_the_class_it_ships_beside(self):
        """The drift this whole fix exists to make impossible."""
        groups = list(self._expanded())
        self.page.evaluate(f"_openSidebarGroup({groups[1]!r})")
        mismatches = self.page.evaluate("""() => {
            const bad = [];
            document.querySelectorAll('.sidebar-group').forEach(g => {
                const t = g.querySelector('.sidebar-group-toggle');
                if (!t) return;
                const open = !g.classList.contains('collapsed');
                if (t.getAttribute('aria-expanded') !== String(open)) {
                    bad.push(g.dataset.group);
                }
            });
            return bad;
        }""")
        self.assertEqual(mismatches, [],
                         f'class and aria-expanded disagree on: {mismatches}')

    def test_a_restored_group_is_painted_on_load(self):
        """_restoreSidebarGroups must paint the attribute too — otherwise the
        announcement is wrong from the very first frame, before any click."""
        groups = list(self._expanded())
        target = groups[1]
        self.page.evaluate(
            f"localStorage.setItem('sidebar.open_group', {target!r})")
        self.page.reload()
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        self.assertEqual(self._expanded()[target], 'true',
                         'restored group did not get aria-expanded on load')


class TestTabWidgetsAnnounceSelection(_Base):
    def _tablists(self):
        """Discover tablists from the DOM rather than hardcoding — a sixth tab
        widget added later is then covered without editing this test."""
        return self.page.evaluate("""() =>
            Array.from(document.querySelectorAll('[role="tablist"]'))
                 .map(l => l.getAttribute('aria-label') || '(unnamed)')""")

    def test_every_tablist_has_exactly_one_selected_tab(self):
        bad = self.page.evaluate("""() => {
            const bad = [];
            document.querySelectorAll('[role="tablist"]').forEach(l => {
                const tabs = Array.from(l.querySelectorAll('[role="tab"]'));
                if (!tabs.length) return;
                const sel = tabs.filter(t => t.getAttribute('aria-selected') === 'true');
                if (sel.length !== 1) {
                    bad.push((l.getAttribute('aria-label') || '?') + ': ' + sel.length);
                }
            });
            return bad;
        }""")
        self.assertEqual(bad, [], f'tablists without exactly one selected tab: {bad}')

    def test_switching_a_settings_tab_moves_aria_selected(self):
        self.page.evaluate("showPage('settings')")
        self.page.wait_for_selector('#page-settings.active', timeout=15000)
        tabs = self.page.evaluate(
            """() => Array.from(document.querySelectorAll('.settings-tab'))
                          .map(b => b.dataset.tab).filter(Boolean)""")
        self.assertGreaterEqual(len(tabs), 2)
        target = tabs[1]
        self.page.evaluate(f"switchSettingsTab({target!r})")
        state = self.page.evaluate("""() => {
            const out = {};
            document.querySelectorAll('.settings-tab').forEach(b => {
                if (b.dataset.tab) out[b.dataset.tab] = b.getAttribute('aria-selected');
            });
            return out;
        }""")
        self.assertEqual(state[target], 'true')
        self.assertEqual([t for t, v in state.items() if t != target and v == 'true'], [])

    def test_roving_tabindex_keeps_one_tab_stop_per_tablist(self):
        bad = self.page.evaluate("""() => {
            const bad = [];
            document.querySelectorAll('[role="tablist"]').forEach(l => {
                const tabs = Array.from(l.querySelectorAll('[role="tab"]'));
                if (!tabs.length) return;
                const stops = tabs.filter(t => t.tabIndex === 0);
                if (stops.length !== 1) {
                    bad.push((l.getAttribute('aria-label') || '?') + ': ' + stops.length);
                }
            });
            return bad;
        }""")
        self.assertEqual(bad, [], f'tablists that are not a single tab stop: {bad}')

    def test_arrow_keys_move_focus_without_activating(self):
        """Manual activation is deliberate: automatic activation would fire a
        handful of per-tab API loads just arrowing across the Settings strip."""
        self.page.evaluate("showPage('settings')")
        self.page.wait_for_selector('#page-settings.active', timeout=15000)
        before = self.page.evaluate(
            """() => document.querySelector('.settings-pane.active')?.id || ''""")
        self.page.evaluate(
            """() => document.querySelector('.settings-tab[aria-selected="true"]').focus()""")
        self.page.keyboard.press('ArrowDown')
        moved = self.page.evaluate(
            """() => document.activeElement?.dataset?.tab || ''""")
        after_pane = self.page.evaluate(
            """() => document.querySelector('.settings-pane.active')?.id || ''""")
        self.assertTrue(moved, 'ArrowDown did not move focus to another tab')
        self.assertEqual(after_pane, before,
                         'arrowing changed the visible panel — that is automatic '
                         'activation, which fires per-tab network loads')


class TestCommandPaletteIsADialog(_Base):
    def _open(self):
        self.page.evaluate("openCommandPalette()")
        self.page.wait_for_selector('#cmd-palette-input', timeout=10000)

    def test_it_exposes_dialog_and_combobox_semantics(self):
        self._open()
        got = self.page.evaluate("""() => {
            const o = document.getElementById('cmd-palette-overlay');
            const i = document.getElementById('cmd-palette-input');
            const r = document.getElementById('cmd-palette-results');
            return {
                role: o?.getAttribute('role'),
                modal: o?.getAttribute('aria-modal'),
                named: !!o?.getAttribute('aria-label'),
                inputRole: i?.getAttribute('role'),
                controls: i?.getAttribute('aria-controls'),
                inputNamed: !!i?.getAttribute('aria-label'),
                listRole: r?.getAttribute('role'),
            };
        }""")
        self.assertEqual(got['role'], 'dialog')
        self.assertEqual(got['modal'], 'true')
        self.assertTrue(got['named'], 'the palette dialog has no accessible name')
        self.assertEqual(got['inputRole'], 'combobox')
        self.assertEqual(got['controls'], 'cmd-palette-results')
        self.assertTrue(got['inputNamed'])
        self.assertEqual(got['listRole'], 'listbox')

    def test_activedescendant_tracks_the_highlighted_row(self):
        """Focus stays on the input, so the highlight is conveyed ONLY by
        aria-activedescendant. If it does not track, the row a screen-reader
        user is about to activate is never announced."""
        self._open()
        self.page.wait_for_selector('.cmd-palette-row', timeout=10000)
        self.page.keyboard.press('ArrowDown')
        ok = self.page.evaluate("""() => {
            const inp = document.getElementById('cmd-palette-input');
            const id = inp.getAttribute('aria-activedescendant');
            const act = document.querySelector('.cmd-palette-active');
            return !!id && !!act && act.id === id
                   && act.getAttribute('aria-selected') === 'true';
        }""")
        self.assertTrue(ok, 'aria-activedescendant does not match the highlighted row')

    def test_activedescendant_survives_a_re_render(self):
        """_palRender rebuilds innerHTML on every keystroke — an id captured
        once at open time would dangle immediately."""
        self._open()
        self.page.wait_for_selector('.cmd-palette-row', timeout=10000)
        self.page.fill('#cmd-palette-input', 'a')
        self.page.wait_for_timeout(150)
        dangling = self.page.evaluate("""() => {
            const inp = document.getElementById('cmd-palette-input');
            const id = inp.getAttribute('aria-activedescendant');
            if (!id) return false;                 // no rows is legitimate
            return !document.getElementById(id);   // set but pointing nowhere
        }""")
        self.assertFalse(dangling, 'aria-activedescendant points at a removed node')

    def test_closing_restores_focus(self):
        self.page.evaluate(
            """() => document.querySelector('.nav-btn[data-page="devices"]').focus()""")
        before = self.page.evaluate("() => document.activeElement?.dataset?.page || ''")
        self.assertEqual(before, 'devices')
        self._open()
        self.page.keyboard.press('Escape')
        self.page.wait_for_timeout(120)
        after = self.page.evaluate("() => document.activeElement?.dataset?.page || ''")
        self.assertEqual(after, 'devices',
                         'focus did not return to where the palette was opened from')


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TestLoginErrorsAreAnnounced(_Base):
    """The product's front door. A blank-field submit used to clear the previous
    message and return — the error was detected and shown to nobody, sighted or
    not (WCAG 2.1 SC 3.3.1, Level A). The credential error was also a plain div
    with no role, so a failed sign-in was silent to a screen reader (SC 4.1.3).
    """

    def setUp(self):
        # Deliberately NOT logged in — that is the state under test.
        self.page = self.browser.new_page()
        self.page.goto(self.base + '/index.html')
        self.page.wait_for_selector('#login-user', timeout=15000)

    def test_blank_submit_says_something(self):
        self.page.fill('#login-user', '')
        self.page.fill('#login-pass', '')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_timeout(200)
        shown = self.page.evaluate("""() => {
            const e = document.getElementById('login-error');
            return {visible: e.classList.contains('show'), text: e.textContent.trim()};
        }""")
        self.assertTrue(shown['visible'], 'a blank login submit still shows nothing')
        self.assertTrue(shown['text'], 'the error element is shown but empty')

    def test_it_names_and_focuses_the_missing_field(self):
        self.page.fill('#login-user', '')
        self.page.fill('#login-pass', 'x')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_timeout(200)
        got = self.page.evaluate("""() => ({
            focused: document.activeElement?.id || '',
            invalid: document.getElementById('login-user').getAttribute('aria-invalid'),
            text: document.getElementById('login-error').textContent.trim(),
        })""")
        self.assertEqual(got['focused'], 'login-user')
        self.assertEqual(got['invalid'], 'true')
        self.assertIn('username', got['text'].lower())

    def test_the_error_region_is_announceable(self):
        role = self.page.get_attribute('#login-error', 'role')
        self.assertEqual(role, 'alert',
                         'the login error is a plain div — a screen reader is '
                         'never told the sign-in failed')
        self.assertEqual(self.page.get_attribute('#login-oidc-error', 'role'), 'alert')

    def test_a_valid_retry_clears_the_invalid_marker(self):
        """A stale aria-invalid would keep announcing a fixed field as broken."""
        self.page.fill('#login-user', '')
        self.page.fill('#login-pass', '')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_timeout(150)
        self.page.fill('#login-user', 'admin')
        self.page.fill('#login-pass', 'remotepower')
        self.page.click('#login-form button[type="submit"]')
        self.page.wait_for_selector('#app', state='visible', timeout=15000)
        left = self.page.evaluate(
            """() => document.querySelectorAll('#login-form [aria-invalid="true"]').length""")
        self.assertEqual(left, 0, 'aria-invalid survived a successful login')
