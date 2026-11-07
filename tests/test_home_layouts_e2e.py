#!/usr/bin/env python3
"""Home: the fleet heat map groups and colours by more than the health score, and the dashboard keeps named layouts.

One browser session on the demo seed holds both features (the stack takes about a minute to start, so the two share it).

Heat map (8.0.0). One cell per host as before. Group by (none by default) cuts the grid into labelled blocks, Colour by (health score
by default) picks what the colour means. The tests read the data the card was drawn from and recompute every block and every cell
colour in Python, a second implementation of `_heatBucket` / `_heatLook`, so a wrong join between the health rows and the host rows
fails by name. With the defaults the card is the grid of 7.5.0: one grid, no blocks, no legend.

Layouts (8.0.0). The dashboard keeps named layouts next to the saved one: a layout is a name and the widgets it shows, made from the
current layout, a ready-made one (Fleet overview, Security, Patching, Capacity) or empty, switched from the top of Home, edited in the
Customize panel without touching the saved layout, kept in the account (ui_prefs, so a reload and another browser see it), renamed,
deleted with an undo, and rotated through by a wall display (`?kiosk=1&cycle=30&pages=home&sets=all`) without saving the rotation.
The page and the server share the limits (8 layouts, 3,000 characters together): what the page accepts, the server keeps.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import collections
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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('layout is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-home-layouts-')
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


def _signed_in_context(width=1440, height=900):
    """A fresh browser context signed in as the demo operator, with One long page chosen (a walk must see every card)."""
    ctx = _STATE['browser'].new_context(viewport={'width': width, 'height': height}, service_workers='block')
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                        "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
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


# ── the heat map ─────────────────────────────────────────────────────────────
GROUPS = ('group', 'site', 'os', 'type', 'agent', 'status')
COLOURS = ('finding', 'updates', 'seen')


def _bucket(by, h):
    """Python twin of _heatBucket."""
    if h is None:
        return ''
    if by == 'group':
        return (h.get('group') or '').strip()
    if by == 'site':
        return (h.get('site') or '').strip()
    if by == 'os':
        return (h.get('os') or '').strip()
    if by == 'type':
        return str(h.get('device_type') or ('agentless' if h.get('agentless') else 'agent')).strip()
    if by == 'agent':
        return '' if h.get('agentless') else str(h.get('version') or '').strip()
    if by == 'status':
        return 'Online' if h.get('online') else 'Offline'
    return ''


def _colour(by, row, h, cuts, now):
    """Python twin of _heatLook's colour; None when a host sits too close to a time boundary to call (the clocks differ by a second)."""
    if by == 'finding':
        return ('var(--red)' if row.get('critical') else 'var(--amber)' if row.get('warning')
                else 'var(--muted)' if row.get('info') else 'var(--green)')
    if by == 'updates':
        n = None if (h is None or h.get('agentless')) else h.get('upgradable')
        if not isinstance(n, (int, float)) or isinstance(n, bool):
            return 'var(--muted)'
        return 'var(--green)' if n == 0 else 'var(--amber)' if n < 10 else 'var(--orange)' if n < 30 else 'var(--red)'
    if by == 'seen':
        if h is None or h.get('agentless') or not h.get('last_seen'):
            return 'var(--muted)'
        age = max(0, now - h['last_seen'])
        if any(abs(age - edge) < 5 for edge in (300, 3600, 86400)):
            return None
        return 'var(--green)' if age < 300 else 'var(--amber)' if age < 3600 else 'var(--orange)' if age < 86400 else 'var(--red)'
    s = row['score']
    return 'var(--green)' if s >= cuts['good'] else '#d4a017' if s >= cuts['fair'] else '#ff8c00' if s >= cuts['poor'] else 'var(--red)'


class TestHeatmap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _signed_in_context()
        cls.page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def setUp(self):
        self._errors_before = len(self.errors)
        self.addCleanup(lambda: self.assertEqual(self.errors[self._errors_before:], [], 'a page error came up in this test'))
        self._choose('none', 'score')

    # helpers
    def _choose(self, group, colour):
        self.page.select_option('#heat-group', group)
        self.page.select_option('#heat-color', colour)
        self.page.wait_for_function("([g, c]) => document.getElementById('heat-group').value === g && document.getElementById('heat-color').value === c", arg=[group, colour])

    def _data(self):
        return self.page.evaluate("""() => ({
            rows: _heatData.health.devices.map(r => ({device_id: r.device_id, device_name: r.device_name, score: r.score,
                                                      critical: r.critical, warning: r.warning, info: r.info})),
            cuts: Object.assign({good: 90, fair: 70, poor: 40}, _heatData.health.grades || {}),
            hosts: _heatData.hosts.map(h => ({id: h.id, name: h.name, group: h.group, site: h.site, os: h.os, version: h.version,
                device_type: h.device_type, agentless: h.agentless, online: h.online, last_seen: h.last_seen,
                upgradable: (h.sysinfo && h.sysinfo.packages) ? h.sysinfo.packages.upgradable : null})),
            none: _HEAT_NONE, now: Date.now() / 1000})""")

    def _cells(self):
        self.page.mouse.move(1, 1)          # app-tooltip.js takes the title off the element under the pointer
        return self.page.eval_on_selector_all('#home-heatmap .heatmap-cell',
                                              'els => els.map(e => ({id: e.dataset.arg, bg: e.dataset.bg, title: e.getAttribute("title") || ""}))')

    def _blocks(self):
        return self.page.eval_on_selector_all(
            '#home-heatmap .heatmap-block',
            "els => els.map(b => ({label: b.querySelector('.heatmap-block-head span').textContent, "
            "n: parseInt(b.querySelector('.heatmap-block-n').textContent, 10), cells: b.querySelectorAll('.heatmap-cell').length}))")

    # the tests
    def test_the_defaults_draw_the_grid_of_7_5_0(self):
        data = self._data()
        self.assertEqual(self.page.eval_on_selector('#heat-group', 'e => e.value'), 'none')
        self.assertEqual(self.page.eval_on_selector('#heat-color', 'e => e.value'), 'score')
        self.assertEqual(self.page.locator('#home-heatmap .heatmap-grid').count(), 1, 'one grid')
        self.assertEqual(self.page.locator('#home-heatmap .heatmap-block').count(), 0, 'no blocks without a grouping')
        self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 0, 'the score keeps the sentence in the header, not a legend')
        cells = self._cells()
        self.assertEqual(len(cells), len(data['rows']), 'one cell per host that has a health row')
        self.assertGreaterEqual(len(cells), 2)
        note = self.page.eval_on_selector('#home-heatmap-note', 'e => e.textContent')
        self.assertEqual(note, 'health score per host — green healthy, red needs attention')
        by_id = {r['device_id']: r for r in data['rows']}
        for c in cells:
            row = by_id[c['id']]
            self.assertEqual(c['bg'], _colour('score', row, None, data['cuts'], data['now']), c)
            want = f"{row['device_name']} — health {row['score']}/100"
            if row['critical']:
                want += f" · {row['critical']} critical"
            if row['warning']:
                want += f" · {row['warning']} warning"
            self.assertEqual(c['title'], want, 'the hover text of 7.5.0 is unchanged')

    def test_a_grouping_cuts_the_grid_into_blocks_that_add_up(self):
        for by in GROUPS:
            with self.subTest(group=by):
                self._choose(by, 'score')
                data = self._data()
                hosts = {h['id']: h for h in data['hosts']}
                want = collections.Counter(_bucket(by, hosts.get(r['device_id'])) for r in data['rows'])
                want = {(k or data['none'][by]): n for k, n in want.items()}
                blocks = self._blocks()
                got = {b['label']: b['n'] for b in blocks}
                self.assertEqual(got, want, f'blocks for Group by {by}')
                for b in blocks:
                    self.assertEqual(b['n'], b['cells'], f'the count of {b["label"]} is the cells it holds')
                self.assertEqual(sum(b['n'] for b in blocks), len(data['rows']), 'every host is in exactly one block')
                self.assertEqual(len(self._cells()), len(data['rows']))
                labels = [b['label'] for b in blocks]
                named = [lb for lb in labels if lb != data['none'][by]]
                order = self.page.evaluate("(l) => l.slice().sort((a, b) => a.localeCompare(b, undefined, {numeric: true, sensitivity: 'base'}))", named)
                self.assertEqual(named, order, 'named blocks are sorted')
                if data['none'][by] in labels and want.get(data['none'][by]):
                    self.assertEqual(labels[-1], data['none'][by], 'the "not set" block comes last')

    def test_the_demo_fleet_has_groups_and_the_site_comes_from_the_home_payload(self):
        # a Group by that drew one block for everything would pass the sum test above, so ask for more than one
        self._choose('group', 'score')
        self.assertGreaterEqual(len(self._blocks()), 2, 'the demo seed has hosts in several groups')
        self.assertTrue(self.page.evaluate("async () => (await api('GET', '/home')).devices.every(d => 'site' in d)"),
                        'the Home payload carries the site of each host')

    def test_a_colour_choice_recolours_every_cell_and_shows_its_legend(self):
        for colour in COLOURS:
            with self.subTest(colour=colour):
                self._choose('none', colour)
                data = self._data()
                hosts = {h['id']: h for h in data['hosts']}
                rows = {r['device_id']: r for r in data['rows']}
                legend = self.page.eval_on_selector_all('#home-heatmap-legend .heatmap-legend .ts-leg',
                                                        "els => els.map(e => ({bg: e.querySelector('.ts-dot').dataset.bg, text: e.textContent.trim()}))")
                self.assertGreaterEqual(len(legend), 4, 'a legend with the colours of the choice')
                swatches = {x['bg'] for x in legend}
                checked = 0
                for c in self._cells():
                    want = _colour(colour, rows[c['id']], hosts.get(c['id']), data['cuts'], data['now'])
                    if want is None:
                        continue
                    self.assertEqual(c['bg'], want, f'{rows[c["id"]]["device_name"]} under Colour by {colour}')
                    self.assertIn(c['bg'], swatches, 'every colour a cell can have is in the legend')
                    checked += 1
                self.assertGreater(checked, 0)
                note = self.page.eval_on_selector('#home-heatmap-note', 'e => e.textContent')
                self.assertNotEqual(note, 'health score per host — green healthy, red needs attention', 'the sentence follows the choice')

    def test_grouping_and_colour_work_together(self):
        self._choose('os', 'finding')
        data = self._data()
        self.assertGreaterEqual(len(self._blocks()), 1)
        self.assertEqual(len(self._cells()), len(data['rows']))
        self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 1)

    def test_a_cell_still_opens_the_host_timeline(self):
        self._choose('group', 'score')
        first = self.page.locator('#home-heatmap .heatmap-cell').first
        device = first.get_attribute('data-arg')
        first.click()
        self.page.wait_for_selector('#page-timeline.active', timeout=20000)
        self.assertEqual(self.page.evaluate('() => window._timelinePendingDevice !== undefined'), True)
        self.assertTrue(device)
        self.page.evaluate("() => showPage('home')")
        self.page.wait_for_selector('#page-home.active')

    def test_the_choice_is_kept_in_this_browser_and_survives_a_reload(self):
        self._choose('os', 'updates')
        self.assertEqual(self.page.evaluate("() => [localStorage.getItem('rp_heat_group'), localStorage.getItem('rp_heat_color')]"), ['os', 'updates'])
        self.page.reload()
        self.page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)
        self.assertEqual(self.page.eval_on_selector('#heat-group', 'e => e.value'), 'os')
        self.assertEqual(self.page.eval_on_selector('#heat-color', 'e => e.value'), 'updates')
        self.assertGreaterEqual(self.page.locator('#home-heatmap .heatmap-block').count(), 1)
        self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 1)

    def test_a_value_that_is_not_a_choice_falls_back_to_the_default(self):
        self.page.evaluate("() => { localStorage.setItem('rp_heat_group', 'banana'); localStorage.setItem('rp_heat_color', '<b>'); }")
        self.page.reload()
        self.page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)
        self.assertEqual(self.page.eval_on_selector('#heat-group', 'e => e.value'), 'none')
        self.assertEqual(self.page.eval_on_selector('#heat-color', 'e => e.value'), 'score')
        self.assertEqual(self.page.locator('#home-heatmap .heatmap-block').count(), 0)

    def test_a_browser_that_refuses_storage_keeps_the_choice_until_the_page_reloads(self):
        self.page.evaluate("""() => {
            window._origSet = Storage.prototype.setItem;
            Storage.prototype.setItem = function (k, v) { if (String(k).indexOf('rp_heat_') === 0) throw new Error('storage refused'); return window._origSet.call(this, k, v); };
        }""")
        try:
            self._choose('status', 'seen')
            self.assertGreaterEqual(self.page.locator('#home-heatmap .heatmap-block').count(), 1, 'the grouping applied without storage')
            self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 1)
        finally:
            self.page.evaluate("() => { Storage.prototype.setItem = window._origSet; }")

    def test_the_legend_is_outside_the_scrolling_area_and_blocks_flow_side_by_side(self):
        self._choose('os', 'finding')
        inside = self.page.evaluate("() => document.getElementById('home-heatmap').contains(document.querySelector('.heatmap-legend'))")
        self.assertFalse(inside, 'a long grouping must not push the legend out of sight')
        self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 1)
        tops = self.page.eval_on_selector_all('#home-heatmap .heatmap-block', 'els => els.map(e => Math.round(e.getBoundingClientRect().top))')
        self.assertGreaterEqual(len(tops), 3)
        self.assertLess(len(set(tops)), len(tops), 'at 1440 px two blocks share a row: they flow, they do not stack')
        self._choose('none', 'score')
        self.assertEqual(self.page.locator('#home-heatmap-legend .heatmap-legend').count(), 0, 'the legend goes with the colour choice')

    def test_names_are_escaped_in_blocks_and_hover_text(self):
        # the group of a host is operator text: it must reach the page as text
        self.page.evaluate("""() => {
            _heatData.hosts.forEach((h, i) => { if (i === 0) { h.group = '<img src=x data-probe=1>'; } });
            _heatMem.group = 'group'; _paintHeatmap();
        }""")
        try:
            self.assertEqual(self.page.locator('#home-heatmap img').count(), 0, 'no element was made from a group name')
            labels = [b['label'] for b in self._blocks()]
            self.assertIn('<img src=x data-probe=1>', labels, 'the name is shown as text')
        finally:
            self.page.evaluate("() => { delete _heatMem.group; }")


class TestHeatmapNarrow(unittest.TestCase):
    """A phone: the two choices share a row and nothing runs off the card."""

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _signed_in_context(390, 844)
        cls.page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def test_the_card_fits_the_width_with_a_grouping_and_a_legend(self):
        self.page.select_option('#heat-group', 'group')
        self.page.select_option('#heat-color', 'updates')
        self.page.wait_for_selector('#home-heatmap .heatmap-block')
        wide = self.page.evaluate("""() => { const c = document.getElementById('home-heatmap-card');
            return [c.scrollWidth, c.clientWidth, document.documentElement.scrollWidth, innerWidth]; }""")
        self.assertLessEqual(wide[0], wide[1], f'the card scrolls sideways: {wide}')
        self.assertLessEqual(wide[2], wide[3], f'the page scrolls sideways: {wide}')

    def test_the_two_choices_share_one_row(self):
        tops = self.page.eval_on_selector_all('#heat-group, #heat-color', 'els => els.map(e => Math.round(e.getBoundingClientRect().top))')
        self.assertEqual(len(tops), 2)
        self.assertLess(abs(tops[0] - tops[1]), 4, f'the selects are on different lines: {tops}')


# ── the layouts ──────────────────────────────────────────────────────────────
GRID_WIDGETS = "() => [...document.querySelectorAll('#dash-grid [data-widget]')].filter(n => !n.classList.contains('dash-off')).map(n => n.dataset.widget)"


class _LayoutsBase(unittest.TestCase):
    """One signed-in page; every test starts from an account that has no layouts and the default saved one."""

    RESET = """async () => {
        _uiPrefs = {}; _dashSetOverride = null; await flushUiPrefs(); applyDashboardLayout();
        const p = document.getElementById('dash-edit-panel'); if (p) p.classList.add('hidden');
    }"""

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _signed_in_context()
        cls.page.wait_for_function("() => typeof flushUiPrefs === 'function' && _uiPrefsLoaded")
        cls.page.evaluate(cls.RESET)           # the account is shared by every class: start from no layouts and the default saved one
        cls.page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.page.evaluate(cls.RESET)       # and leave it that way for the next class
        finally:
            cls.ctx.close()

    def setUp(self):
        self._errors_before = len(self.errors)
        self.addCleanup(lambda: self.assertEqual(self.errors[self._errors_before:], [], 'a page error came up in this test'))
        self.page.evaluate(self.RESET)

    # helpers
    def _open_panel(self):
        if self.page.locator('#dash-edit-panel.hidden').count():
            self.page.click('.dash-customize-btn')
        self.page.wait_for_selector('#dash-set-manage .dash-set-new', timeout=15000)      # the manager is a lazy module: it has arrived

    def _create(self, name='', start='copy'):
        self._open_panel()
        self.page.fill('#dash-set-name', name)
        self.page.select_option('#dash-set-from', start)
        self.page.click('#dash-set-manage [data-action="dashSetCreate"]')

    def _stored(self):
        return self.page.evaluate("async () => { await flushUiPrefs(); return await api('GET', '/ui-prefs'); }")

    def _widgets(self):
        return self.page.evaluate(GRID_WIDGETS)

    def _set_in_use(self):
        return self.page.evaluate("() => _dashSetId()")

    def _sets(self):
        return self.page.evaluate("() => JSON.parse(JSON.stringify(_dashSets()))")

    def _bar_options(self):
        return self.page.eval_on_selector_all('#dash-set-select option', 'els => els.map(e => e.textContent)')

    def _toast(self, text):
        return self.page.locator('#toast-container .toast', has_text=text).count() > 0

    def _make(self, name, start='empty'):
        """A layout, made through the panel, and wait until it is the one in use."""
        before = len(self._sets())
        self._create(name, start)
        self.assertTrue(_until(lambda: len(self._sets()) == before + 1 and self._set_in_use() == self._sets()[-1]['id']), f'layout {name} was not made')
        return self._sets()[-1]['id']


class TestLayouts(_LayoutsBase):
    def test_nothing_changes_until_a_layout_is_made(self):
        self.assertTrue(self.page.eval_on_selector('#dash-set-bar', 'e => e.classList.contains("d-none")'), 'no switcher without a named layout')
        self._open_panel()
        self.assertEqual(self.page.locator('#dash-set-manage .dash-set-list').count(), 0, 'no list: there is only the saved layout')
        want = self.page.evaluate("() => _dashBaseLayout([]).filter(e => e.on && e.key !== 'askai').map(e => e.key)")
        self.assertEqual(self._widgets(), want, 'the default widgets, as before')
        self.assertNotIn('dashboard_sets', self._stored())

    def test_a_ready_made_layout_shows_its_widgets_and_leaves_the_saved_layout_alone(self):
        self.page.evaluate("() => dashToggle('offline')")                       # a change to the saved layout
        saved = self.page.evaluate("() => JSON.parse(JSON.stringify(_uiPrefs.dashboard))")
        self.assertTrue(any(e['key'] == 'offline' and e['on'] for e in saved))
        sid = self._make('', 'security')                                        # no name typed: the ready-made layout's own name
        presets = {p['id']: p for p in self.page.evaluate("() => _DASH_PRESETS.map(p => ({id: p.id, label: p.label, w: p.w}))")}
        want = [k for k in presets['security']['w'] if k != 'askai']
        self.assertTrue(_until(lambda: self._widgets() == want), f'shown: {self._widgets()}')
        self.assertEqual(self._bar_options(), ['My layout', 'Security'])
        self.assertEqual(self.page.eval_on_selector('#dash-set-select', 'e => e.value'), sid)
        self.assertEqual(self.page.evaluate("() => JSON.parse(JSON.stringify(_uiPrefs.dashboard))"), saved, 'the saved layout was not touched')
        stored = self._stored()
        self.assertEqual(stored['dashboard_sets'], [{'id': sid, 'name': 'Security', 'w': presets['security']['w']}])
        self.assertEqual(stored['dashboard_set'], sid)
        self.assertEqual(stored['dashboard'], saved)

    def test_switching_back_restores_the_saved_layout(self):
        self.page.evaluate("() => dashToggle('offline')")
        classic = self.page.evaluate("() => _dashBaseLayout(_uiPrefs.dashboard).filter(e => e.on && e.key !== 'askai').map(e => e.key)")
        self._make('Night', 'empty')
        self.assertTrue(_until(lambda: self._widgets() == []), 'an empty layout shows no widget')
        self.page.select_option('#dash-set-select', '')
        self.assertTrue(_until(lambda: self._widgets() == classic), f'shown: {self._widgets()}')
        stored = self._stored()
        self.assertNotIn('dashboard_set', stored, 'My layout is "no layout in use"')
        self.assertEqual(len(stored['dashboard_sets']), 1, 'switching does not delete anything')

    def test_every_ready_made_layout_is_made_of_widgets_the_page_has(self):
        self._open_panel()
        info = self.page.evaluate("() => ({presets: _DASH_PRESETS.map(p => ({id: p.id, w: p.w})), keys: _DASH_KEYS})")
        self.assertEqual([p['id'] for p in info['presets']], ['fleet', 'security', 'patching', 'capacity'])
        for p in info['presets']:
            with self.subTest(preset=p['id']):
                self.assertEqual(len(p['w']), len(set(p['w'])), 'a widget twice')
                self.assertTrue(set(p['w']) <= set(info['keys']), sorted(set(p['w']) - set(info['keys'])))
                self.assertTrue(8 <= len(p['w']) <= 16, len(p['w']))
        # and each one can be made and shows exactly its widgets, in its order
        for p in info['presets']:
            with self.subTest(made=p['id']):
                self._make('Layout ' + p['id'], p['id'])
                want = [k for k in p['w'] if k != 'askai']
                self.assertTrue(_until(lambda: self._widgets() == want), f'{p["id"]}: {self._widgets()}')

    def test_editing_a_layout_changes_only_that_layout(self):
        saved = self.page.evaluate("() => JSON.parse(JSON.stringify(_uiPrefs.dashboard || null))")
        sid = self._make('Security', 'security')
        self._open_panel()
        self.page.click('#dash-edit-panel [data-action="dashSize"][data-arg="crittotal"][data-arg2="lg"]')
        self.assertTrue(_until(lambda: 'crittotal:lg' in self._sets()[0]['w']), 'a size that is not the default is kept as key:size')
        self.assertTrue(self.page.eval_on_selector('#page-home [data-widget="crittotal"]', 'e => e.classList.contains("dash-w-lg")'))
        self.page.click('#dash-edit-panel [data-action="dashToggle"][data-arg="tls"]')
        self.assertTrue(_until(lambda: 'tls' not in [x.split(':')[0] for x in self._sets()[0]['w']]), 'a widget taken out leaves the list')
        self.page.select_option('#dash-add-select', 'monitors')
        self.assertTrue(_until(lambda: 'monitors' in self._sets()[0]['w']), 'a widget added joins it')
        self.assertEqual(self.page.evaluate("() => JSON.parse(JSON.stringify(_uiPrefs.dashboard || null))"), saved, 'the saved layout was not touched')
        self.assertEqual(self._stored()['dashboard_sets'][0]['w'], self._sets()[0]['w'])
        # the undo arrow takes the last change back
        self.page.click('#topbar-undo')
        self.assertTrue(_until(lambda: 'monitors' not in self._sets()[0]['w']))
        # My layout still has the widget at its own size
        self.page.select_option('#dash-set-select', '')
        self.assertTrue(_until(lambda: self._set_in_use() == ''))
        self.assertTrue(self.page.eval_on_selector('#page-home [data-widget="crittotal"]', 'e => e.classList.contains("dash-w-sm")'))
        self.assertEqual(sid, self._sets()[0]['id'])

    def test_an_undo_goes_to_the_layout_that_was_changed(self):
        a = self._make('Alpha', 'copy')
        self._open_panel()
        self.page.click('#dash-edit-panel [data-action="dashToggle"][data-arg="tickets"]')
        self.assertTrue(_until(lambda: 'tickets' not in self._sets()[0]['w']))
        b = self._make('Beta', 'copy')
        beta_before = self._sets()[1]['w']
        self.page.click('#topbar-undo')
        self.assertTrue(_until(lambda: 'tickets' in self._sets()[0]['w']), 'the change was taken back in Alpha')
        self.assertEqual(self._sets()[1]['w'], beta_before, 'Beta, the layout in use, was not touched')
        self.assertEqual(self._set_in_use(), b)
        self.assertNotEqual(a, b)

    def test_a_layout_survives_a_reload_and_is_still_in_use(self):
        sid = self._make('Patching', 'patching')
        want = self._widgets()
        self.page.evaluate("async () => { await flushUiPrefs(); }")
        self.page.reload()
        # the heat map is not in the Patching layout, so wait for the account's preferences, not for a card
        self.page.wait_for_function("() => typeof _uiPrefsLoaded !== 'undefined' && _uiPrefsLoaded", timeout=60000)
        self.assertTrue(_until(lambda: self._set_in_use() == sid), 'the layout in use came back')
        self.assertTrue(_until(lambda: not self.page.eval_on_selector('#dash-set-bar', 'e => e.classList.contains("d-none")')), 'the switcher is shown')
        self.assertEqual(self.page.eval_on_selector('#dash-set-select', 'e => e.value'), sid)
        self.assertTrue(_until(lambda: self._widgets() == want), f'shown: {self._widgets()}')

    def test_rename_and_delete_with_an_undo(self):
        sid = self._make('Plan', 'empty')
        self._make('Other', 'empty')
        self.page.click(f'#dash-set-manage [data-action="dashSetRename"][data-arg="{sid}"]')
        self.page.wait_for_selector('#ui-prompt-modal.active')
        self.assertEqual(self.page.eval_on_selector('#ui-prompt-input', 'e => e.value'), 'Plan', 'the prompt starts from the current name')
        self.page.fill('#ui-prompt-input', 'Other')
        self.page.click('#ui-prompt-confirm')
        self.assertTrue(_until(lambda: self._toast('A layout with that name already exists')), 'a name that is taken is refused')
        self.assertEqual([s['name'] for s in self._sets()], ['Plan', 'Other'])
        self.page.click(f'#dash-set-manage [data-action="dashSetRename"][data-arg="{sid}"]')
        self.page.wait_for_selector('#ui-prompt-modal.active')
        self.page.fill('#ui-prompt-input', 'Day shift')
        self.page.click('#ui-prompt-confirm')
        self.assertTrue(_until(lambda: self._sets()[0]['name'] == 'Day shift'))
        self.assertIn('Day shift', self._bar_options(), 'the switcher shows the new name')
        # delete the one in use (Other), then take it back
        other = self._sets()[1]['id']
        self.assertEqual(self._set_in_use(), other)
        self.page.click(f'#dash-set-manage [data-action="dashSetDelete"][data-arg="{other}"]')
        self.page.wait_for_selector('#ui-prompt-modal.active')
        self.page.click('#ui-prompt-confirm')
        self.assertTrue(_until(lambda: [s['name'] for s in self._sets()] == ['Day shift']))
        self.assertEqual(self._set_in_use(), '', 'deleting the layout in use goes back to the saved one')
        self.page.click('#topbar-undo')
        self.assertTrue(_until(lambda: [s['name'] for s in self._sets()] == ['Day shift', 'Other']), 'the layout is back, where it was')
        self.assertEqual(self._set_in_use(), other, 'and in use again')
        stored = self._stored()
        self.assertEqual([s['name'] for s in stored['dashboard_sets']], ['Day shift', 'Other'])
        self.assertEqual(stored['dashboard_set'], other)

    def test_the_new_layout_row_is_empty_again_after_a_layout_is_made(self):
        self._make('Typed', 'empty')
        self.assertEqual(self.page.eval_on_selector('#dash-set-name', 'e => e.value'), '', 'the name that was used is not left in the box')

    def test_what_is_typed_in_the_new_layout_row_survives_a_redraw_of_the_panel(self):
        self._open_panel()
        self.page.fill('#dash-set-name', 'Half typed')
        self.page.select_option('#dash-set-from', 'patching')
        self.page.click('#dash-edit-panel [data-action="dashToggle"][data-arg="tickets"]')     # any change of the layout redraws the panel
        self.assertTrue(_until(lambda: 'tickets' not in [x.split(':')[0] for x in self.page.evaluate("() => _dashLayoutToSet(_dashLayout())")]))
        self.assertEqual(self.page.eval_on_selector('#dash-set-name', 'e => e.value'), 'Half typed')
        self.assertEqual(self.page.eval_on_selector('#dash-set-from', 'e => e.value'), 'patching')

    def test_a_name_is_needed_and_must_be_new(self):
        self._open_panel()
        self.page.fill('#dash-set-name', '')
        self.page.select_option('#dash-set-from', 'copy')
        self.page.click('#dash-set-manage [data-action="dashSetCreate"]')
        self.assertTrue(_until(lambda: self._toast('Give the layout a name')))
        self.assertEqual(self._sets(), [])
        self._make('Same', 'empty')
        self._create('same', 'empty')
        self.assertTrue(_until(lambda: self._toast('A layout with that name already exists')), 'names are compared without case')
        self.assertEqual(len(self._sets()), 1)

    def test_a_name_reaches_the_page_as_text(self):
        evil = '<img src=x data-probe=1>'
        self._make(evil, 'empty')
        self.assertEqual(self.page.locator('#dash-set-bar img, #dash-set-manage img').count(), 0, 'no element was made from a name')
        self.assertIn(evil, self._bar_options())
        self.assertEqual(self._stored()['dashboard_sets'][0]['name'], evil)

    def test_a_long_name_is_cut_where_the_server_cuts_it(self):
        self._make('N' * 80, 'empty')
        self.assertEqual(len(self._sets()[0]['name']), 40)
        self.assertEqual(self._stored()['dashboard_sets'][0]['name'], 'N' * 40)

    def test_what_the_page_accepts_the_server_keeps(self):
        # eight layouts is the most: the ninth is refused with the reason, and the server holds exactly what the page shows
        for i in range(8):
            self._make(f'L{i}', 'empty')
        self._create('L8', 'empty')
        self.assertTrue(_until(lambda: self._toast('You can keep up to 8 layouts')), 'the ninth is refused')
        self.assertEqual(len(self._sets()), 8)
        self.assertEqual(len(self._stored()['dashboard_sets']), 8, 'nothing was dropped on the way to the server')

    def test_a_layout_that_would_not_fit_is_refused_instead_of_lost(self):
        # every widget on in the saved layout, then copies of it: about 900 characters each, so the third is the last that fits
        self.page.evaluate("""() => { _uiPrefs.dashboard = _DASH_KEYS.map(k => ({key: k, on: true, size: _dashDefaultSize(k)})); applyDashboardLayout(); }""")
        made = 0
        for i in range(6):
            before = len(self._sets())
            self._create(f'Full {i}', 'copy')
            _until(lambda: len(self._sets()) > before or self._toast('There is no room for another layout'), seconds=6)
            if len(self._sets()) == before:
                break
            made += 1
            self.page.select_option('#dash-set-select', '')       # copy the saved layout again, not the one just made
            _until(lambda: self._set_in_use() == '')
        self.assertTrue(2 <= made < 6, f'{made} full layouts fit')
        self.assertTrue(self._toast('There is no room for another layout'), 'the one that does not fit is refused with the reason')
        stored = self._stored()
        self.assertEqual(len(stored['dashboard_sets']), made, 'the server keeps every layout the page accepted')
        size = len(self.page.evaluate("() => JSON.stringify(_dashSets())"))
        self.assertLessEqual(size, 3000)

    def test_a_change_that_would_not_fit_is_refused_and_leaves_the_layout_as_it_was(self):
        # three layouts of every widget fit (about 830 characters each); a fourth of them does not, so growing a small one to every
        # widget is the change that is refused
        self.page.evaluate("""() => { _uiPrefs.dashboard = _DASH_KEYS.map(k => ({key: k, on: true, size: _dashDefaultSize(k)})); applyDashboardLayout(); }""")
        for name in ('Full one', 'Full two', 'Full three'):
            self._make(name, 'copy')
            self.page.select_option('#dash-set-select', '')
            self.assertTrue(_until(lambda: self._set_in_use() == ''))
        self._make('Small', 'empty')
        small = self._sets()[3]
        before = small['w']
        self.page.evaluate("() => { const all = _DASH_KEYS.map(k => ({key: k, on: true, size: _dashDefaultSize(k)})); _dashSave(all); }")
        self.assertTrue(_until(lambda: self._toast('This layout is full')), 'the change is refused with the reason')
        self.assertEqual(self._sets()[3]['w'], before, 'the layout is as it was')
        self.assertEqual(len(self._stored()['dashboard_sets']), 4, 'and the server kept all four')

    def test_reset_in_a_layout_gives_it_the_default_widgets(self):
        self._make('Mine', 'empty')
        self._open_panel()
        self.page.click('#dash-edit-panel [data-action="dashReset"]')
        self.page.wait_for_selector('#ui-prompt-modal.active')
        self.page.click('#ui-prompt-confirm')
        default_on = self.page.evaluate("() => _dashBaseLayout([]).filter(e => e.on).map(e => e.key)")
        self.assertTrue(_until(lambda: [x.split(':')[0] for x in self._sets()[0]['w']] == default_on), self._sets()[0]['w'])
        self.assertEqual(self._set_in_use(), self._sets()[0]['id'], 'the reset stays in the layout')


class TestLayoutsLoadOnDemand(unittest.TestCase):
    """The manager is a lazy module: nobody who never opens Customize downloads it."""

    def test_the_manager_arrives_with_the_panel(self):
        ctx, page, errors = _signed_in_context()
        try:
            page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)
            self.assertEqual(page.evaluate("() => [typeof renderDashSetManage, _loadedJsModules.has('app-dashsets.js')]"), ['undefined', False])
            page.click('.dash-customize-btn')
            page.wait_for_selector('#dash-set-manage .dash-set-new', timeout=15000)
            self.assertEqual(page.evaluate("() => [typeof renderDashSetManage, _loadedJsModules.has('app-dashsets.js')]"), ['function', True])
            self.assertEqual(errors, [])
        finally:
            ctx.close()


class TestWallRotation(_LayoutsBase):
    """A wall display with sets=all shows the saved layout and each named one in turn, and does not save what it showed."""

    def test_the_kiosk_rotates_through_the_layouts_without_saving_the_rotation(self):
        self._make('Alpha', 'security')
        self._make('Beta', 'capacity')
        self.page.select_option('#dash-set-select', '')
        saved = self._stored()
        ids = {s['id'] for s in saved['dashboard_sets']}
        ctx, page, errors = _signed_in_context()
        try:
            page.goto(_STATE['base'] + '/index.html?kiosk=1&cycle=5&pages=home&sets=all')
            page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)
            seen, shown = [], []
            deadline = time.time() + 26
            while time.time() < deadline and len(set(seen)) < 3:
                cur = page.evaluate("() => _dashSetId()")
                if not seen or seen[-1] != cur:
                    seen.append(cur)
                    shown.append(page.evaluate(GRID_WIDGETS))
                time.sleep(0.5)
            self.assertEqual(set(seen), ids | {''}, f'every layout, and the saved one, came up: {seen}')
            self.assertEqual(len({tuple(w) for w in shown}), len(shown), 'each layout showed different widgets')
            self.assertEqual(page.evaluate("async () => { await flushUiPrefs(); return await api('GET', '/ui-prefs'); }").get('dashboard_set'), None,
                             'the rotation was not saved to the account')
            page.evaluate("() => exitKiosk()")
            self.assertTrue(_until(lambda: page.evaluate("() => _dashSetId()") == '' and page.evaluate("() => _dashSetOverride") is None),
                            'leaving the kiosk goes back to the layout the account chose')
            self.assertEqual(errors, [])
        finally:
            ctx.close()

    def test_without_sets_the_cycle_is_what_it_was(self):
        ctx, page, errors = _signed_in_context()
        try:
            page.goto(_STATE['base'] + '/index.html?kiosk=1&cycle=5&pages=home,alerts')
            page.wait_for_selector('#home-heatmap .heatmap-cell', timeout=60000)
            seen = set()
            deadline = time.time() + 14
            while time.time() < deadline and len(seen) < 2:
                seen.add(page.evaluate("() => (document.querySelector('.page.active') || {}).id"))
                time.sleep(0.5)
            self.assertEqual(seen, {'page-home', 'page-alerts'}, 'two pages still rotate')
            self.assertEqual(errors, [])
        finally:
            ctx.close()

    def test_the_wall_link_names_the_kiosk_and_the_rotation(self):
        self._make('Alpha', 'empty')
        self._make('Beta', 'empty')
        self._open_panel()
        self.assertEqual(self.page.locator('#dash-set-manage [data-action="dashSetWallLink"]').count(), 1, 'offered once there is a layout to rotate to')
        self.page.evaluate("() => { window._copied = null; Object.defineProperty(navigator, 'clipboard', {value: {writeText: t => { window._copied = t; return Promise.resolve(); }}, configurable: true}); }")
        self.page.click('#dash-set-manage [data-action="dashSetWallLink"]')
        self.assertTrue(_until(lambda: self.page.evaluate("() => window._copied")))
        link = self.page.evaluate("() => window._copied")
        self.assertIn('?kiosk=1&cycle=30&pages=home&sets=all', link)
        self.assertTrue(link.startswith('http'))


if __name__ == '__main__':
    unittest.main()
