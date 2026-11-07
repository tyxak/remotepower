#!/usr/bin/env python3
"""Home: the fleet heat map groups and colours by more than the health score, and the dashboard keeps named layouts.

One browser session on the demo seed holds both features (the stack takes about a minute to start, so the two share it).

Heat map (8.0.0). One cell per host as before. Group by (none by default) cuts the grid into labelled blocks, Colour by (health score
by default) picks what the colour means. The tests read the data the card was drawn from and recompute every block and every cell
colour in Python, a second implementation of `_heatBucket` / `_heatLook`, so a wrong join between the health rows and the host rows
fails by name. With the defaults the card is the grid of 7.5.0: one grid, no blocks, no legend.

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


if __name__ == '__main__':
    unittest.main()
