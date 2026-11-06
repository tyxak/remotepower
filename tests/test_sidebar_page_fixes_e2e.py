#!/usr/bin/env python3
"""Fixes to single sidebar pages that need a browser to prove: a layout measured, a message read, a card folded.

The class-wide questions (a word, a placeholder, a row of buttons) are in test_sidebar_pages_rendered_e2e.py. These are the
page-specific ones found by looking at every page of the seeded demo:

* Logs said "none match the current filter" with no filter set. The live tail asks for the last ten minutes, and the lines in the
  buffer were older, so it sent people to clear a filter that was not there.
* Documentation led with twelve paragraphs of release notes on every visit; it folds after the first visit to a version.
* Software Policy put each rule's remove button on a line under the rule (the class it used, `row-flex`, had no style).
* The Threat Intel attackers table gave the Evidence and Status columns about 100 px each, so a row ran to five lines.
* The Timesheet put an entry's Edit above its Delete.
* My Account reached from the user menu named itself "account" in the top bar.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
import re
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


class TestSidebarPageFixes(unittest.TestCase):
    page = None

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic: measured once, under the default backend')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        data_dir = tempfile.mkdtemp(prefix='rp-pagefix-')
        proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
            return
        try:
            cls._base, cls._shutdown = start_stack(data_dir=data_dir)
        except Exception as exc:
            cls._browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')
        cls._ctx = cls._browser.new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        cls._ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); } catch (e) {}")
        cls.page = cls._ctx.new_page()
        cls.page.goto(cls._base + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(5000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._ctx.close()
            cls._browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def _show(self, name, wait=1800):
        self.page.evaluate("n => showPage(n)", name)
        self.page.wait_for_timeout(wait)

    # ── Logs ────────────────────────────────────────────────────────────────
    def _logs_with_an_empty_tail(self, filtered):
        stats = {'total_lines': 24, 'devices_reporting': 4, 'alert_rules': 3}
        self.page.route('**/api/logs/tail*', lambda route: route.fulfill(
            status=200, content_type='application/json', body='{"lines": [], "newest_ts": 0, "stats": %s}' % __import__('json').dumps(stats)))
        try:
            self._show('logs', 1200)
            # the filters keep their value from one visit to the next: set them, whichever way the last test left them
            self.page.evaluate("""(filtered) => { const d = document.getElementById('logs-device-filter'), u = document.getElementById('logs-unit-filter');
                                          u.value = ''; d.value = filtered ? [...d.options].find(o => o.value).value : ''; startLogsTail(); }""", filtered)
            self.page.wait_for_timeout(800)
            return self.page.inner_text('#logs-viewer')
        finally:
            self.page.unroute('**/api/logs/tail*')

    def test_logs_with_no_filter_says_the_tail_shows_ten_minutes(self):
        text = self._logs_with_an_empty_tail(filtered=False)
        self.assertIn('24 lines in the buffer, but none from the last 10 minutes', text)
        self.assertNotIn('none match the current filter', text)

    def test_logs_with_a_filter_still_blames_the_filter(self):
        text = self._logs_with_an_empty_tail(filtered=True)
        self.assertIn('none match the current filter', text)

    # ── Documentation ───────────────────────────────────────────────────────
    def test_whats_new_opens_once_per_version_and_folds_after(self):
        def first_card_open():
            return self.page.evaluate("document.querySelector('#page-docs details.doc-card').open")
        self._show('docs', 400)      # the page is built on its first visit
        version = self.page.evaluate("(/\\bv\\d+\\.\\d+\\.\\d+/.exec(document.querySelector('#page-docs details.doc-card').dataset.keywords) || [''])[0]")
        self.assertRegex(version, r'^v\d+\.\d+\.\d+$')
        self.page.evaluate("localStorage.removeItem('rp_whatsnew_seen')")
        self._show('docs', 400)
        self.assertTrue(first_card_open(), 'the first visit shows the release notes')
        self.assertEqual(self.page.evaluate("localStorage.getItem('rp_whatsnew_seen')"), version)
        self._show('home', 300)
        self._show('docs', 400)
        self.assertFalse(first_card_open(), 'the second visit folds them, so the quick reference is on the screen')
        self.page.evaluate("localStorage.setItem('rp_whatsnew_seen', 'v0.0.1')")
        self._show('home', 300)
        self._show('docs', 400)
        self.assertTrue(first_card_open(), 'a new version opens it again')

    # ── Software Policy ─────────────────────────────────────────────────────
    def test_a_policy_rule_and_its_remove_button_share_a_line(self):
        self._show('software-policy')
        rows = self.page.evaluate("""() => [...document.querySelectorAll('#swpol-rules .swpol-rule')].map(r => {
            const t = r.firstElementChild.getBoundingClientRect(), b = r.querySelector('button').getBoundingClientRect();
            return {textMid: (t.top + t.bottom) / 2, btnMid: (b.top + b.bottom) / 2, h: r.getBoundingClientRect().height}; })""")
        self.assertGreaterEqual(len(rows), 3, 'control: the seeded policy has rules')
        for r in rows:
            self.assertLess(abs(r['textMid'] - r['btnMid']), 12, r)
            self.assertLess(r['h'], 60, r)

    # ── Threat Intel ────────────────────────────────────────────────────────
    def test_the_attackers_table_gives_evidence_and_status_room(self):
        self._show('ipintel', 2500)
        m = self.page.evaluate("""() => { const q = (s) => [...document.querySelectorAll(s)].map(e => e.getBoundingClientRect().width);
            const rows = [...document.querySelectorAll('#page-ipintel tbody tr')].filter(r => r.querySelector('.ipi-actions')).map(r => r.getBoundingClientRect().height);
            return {ev: q('.ipi-evidence-cell'), st: q('.ipi-status-cell'), rows}; }""")
        self.assertTrue(m['ev'] and m['st'] and m['rows'], 'control: the seeded attackers table has rows')
        self.assertGreaterEqual(min(m['ev']), 215)
        self.assertGreaterEqual(min(m['st']), 145)

    # ── Timesheet ───────────────────────────────────────────────────────────
    def test_an_entrys_edit_and_delete_sit_side_by_side(self):
        self._show('timesheet', 2200)
        pairs = self.page.evaluate("""() => [...document.querySelectorAll('.ts-entry')].map(e => [...e.querySelectorAll('.btn-icon')].map(b => b.getBoundingClientRect()))
                                              .filter(p => p.length === 2).map(p => [p[0].top, p[1].top, p[0].left, p[1].left])""")
        self.assertTrue(pairs, 'control: the seeded week has entries that can be edited')
        for top1, top2, left1, left2 in pairs:
            self.assertLess(abs(top1 - top2), 3, 'edit above delete')
            self.assertLess(left1, left2)

    # ── Compliance ──────────────────────────────────────────────────────────
    def test_the_openscap_notes_are_folded_behind_a_short_lead(self):
        self._show('compliance', 2500)
        m = self.page.evaluate("""() => { const card = document.getElementById('scap-card'); const d = card.querySelector('details');
            const lead = card.querySelector(':scope > .hint'); return {open: d.open, leadH: lead.getBoundingClientRect().height, cardH: card.getBoundingClientRect().height,
              leadText: lead.textContent.slice(0, 40)}; }""")
        self.assertFalse(m['open'], 'the notes start folded')
        self.assertLess(m['leadH'], 50, 'the lead is a line or two, not nine')
        self.assertTrue(m['leadText'].startswith('Scores a host'), m)
        self.page.click('#scap-card details > summary')
        self.assertTrue(self.page.evaluate("document.querySelector('#scap-card details').open"))
        self.assertIn('oscap xccdf eval', self.page.inner_text('#scap-card details'))

    # ── Cron, File manager and App Catalog: the hosts used last ─────────────
    _PICKERS = (('cron', 'cron'), ('files', 'fm'), ('catalog', 'catalog'))   # (page, id prefix)

    def _recent_hosts_reset(self, entries):
        """The state of a first visit: nothing picked, and the recent-hosts list as given.

        An entry that is a number is the demo host at that index; a string is an id no host has (a host that was deleted)."""
        for page, _ in self._PICKERS:
            self._show(page, 900)                    # the three page scripts load on the first visit
        return self.page.evaluate("""async (entries) => {
            _cronDev = null; _fmDev = null; _catalogDev = null;
            for (const k of Object.keys(_recentChipIds)) delete _recentChipIds[k];
            const hosts = (await _scanDeviceList()).slice(0, 4).map(d => ({id: String(d.id), name: d.name || String(d.id)}));
            localStorage.setItem('rp_recent_devices', JSON.stringify(entries.map(e => typeof e === 'number' ? hosts[e] : {id: e, name: e})));
            return hosts; }""", entries)

    def _recent_row(self, prefix):
        return self.page.evaluate("""(p) => { const row = document.getElementById(p + '-device-recent');
            return {hidden: row.classList.contains('hidden'), label: row.querySelector('.hint').textContent, role: row.getAttribute('role'),
                    labelledby: row.getAttribute('aria-labelledby'), labelId: row.querySelector('.hint').id,
                    chips: [...row.querySelectorAll('button.host-chip')].map(b => [b.textContent, b.getAttribute('aria-pressed'), b.getBoundingClientRect().height])}; }""", prefix)

    def test_each_picker_offers_the_last_three_hosts_that_still_exist(self):
        hosts = self._recent_hosts_reset([0, 'gone-host', 1, 0, 2, 3])
        self.assertGreaterEqual(len(hosts), 4, 'control: the demo fleet has hosts to offer')
        for page, prefix in self._PICKERS:
            self._show(page, 1200)
            got = self._recent_row(prefix)
            self.assertFalse(got['hidden'], page)
            self.assertEqual(got['label'], 'Recent hosts')
            self.assertEqual((got['role'], got['labelledby']), ('group', got['labelId']), 'a screen reader reads the label with the buttons')
            # the host that is gone and the repeat are skipped, the cap is three, so the fourth host is left out
            self.assertEqual([c[0] for c in got['chips']], [h['name'] for h in hosts[:3]], page)
            self.assertEqual({c[1] for c in got['chips']}, {'false'}, 'nothing is picked yet')
            self.assertGreaterEqual(min(c[2] for c in got['chips']), 24, 'a button the pointer can hit')

    def test_with_no_recent_hosts_the_row_is_not_drawn(self):
        self._recent_hosts_reset([])
        for page, prefix in self._PICKERS:
            self._show(page, 1200)
            got = self._recent_row(prefix)
            self.assertTrue(got['hidden'], page)
            self.assertEqual(got['chips'], [], page)

    def test_a_click_on_a_recent_host_picks_it_like_a_search_result(self):
        hosts = self._recent_hosts_reset([0, 1, 2])
        names = [h['name'] for h in hosts]
        # a pick can ask the host for something (the crontab, a directory listing): the test is about which host is picked
        self.page.evaluate("""() => { window.__calls = []; window.__orig = {cronRefresh: window.cronRefresh, fmListPath: window.fmListPath};
            window.cronRefresh = () => window.__calls.push('cron'); window.fmListPath = (p) => window.__calls.push('fm:' + p); }""")
        first_id = lambda: self.page.evaluate("() => (JSON.parse(localStorage.getItem('rp_recent_devices')) || [])[0].id")
        try:
            # Cron: the second button
            self._show('cron', 1200)
            self.page.click('#cron-device-recent-chips button:nth-child(2)')
            self.page.wait_for_timeout(400)
            self.assertEqual(self.page.inner_text('#cron-device-current'), 'Host: ' + names[1])
            self.assertFalse(self.page.evaluate("document.getElementById('cron-body').classList.contains('hidden')"))
            self.assertEqual(self.page.evaluate("String(_cronDev.id)"), hosts[1]['id'])
            got = self._recent_row('cron')
            self.assertEqual([c[0] for c in got['chips']], names[:3], 'the buttons do not jump under the pointer')
            self.assertEqual([c[1] for c in got['chips']], ['false', 'true', 'false'])
            self.assertEqual(first_id(), hosts[1]['id'], 'a pick is remembered')
            self.assertEqual(self.page.evaluate("window.__calls"), ['cron'])
            # a host picked from the search results comes first, and the oldest button gives way
            hit = '#cron-device-results [data-action="pickCronDevice"][data-arg="%s"]' % hosts[3]['id']   # the name may match other hosts too
            self.page.fill('#cron-device-search', names[3])
            self.page.wait_for_selector(hit, timeout=5000)
            self.page.click(hit)
            self.page.wait_for_timeout(400)
            got = self._recent_row('cron')
            self.assertEqual([c[0] for c in got['chips']], [names[3], names[0], names[1]])
            self.assertEqual([c[1] for c in got['chips']], ['true', 'false', 'false'])
            # File manager: the list is shared, so the host picked on Cron leads; the second button lists /etc as a search result does
            self._show('files', 1200)
            got = self._recent_row('fm')
            self.assertEqual([c[0] for c in got['chips']][:2], [names[3], names[1]])
            self.page.click('#fm-device-recent-chips button:nth-child(2)')
            self.page.wait_for_timeout(400)
            self.assertEqual(self.page.inner_text('#fm-device-current'), 'Host: ' + names[1])
            self.assertFalse(self.page.evaluate("document.getElementById('fm-browser').classList.contains('hidden')"))
            self.assertEqual(self.page.evaluate("String(_fmDev.id)"), hosts[1]['id'])
            self.assertEqual(self.page.evaluate("window.__calls"), ['cron', 'cron', 'fm:/etc'])
            self.assertEqual(first_id(), hosts[1]['id'])
            # App Catalog: the id stays a string (the page's own rule), and the target line names the host
            self._show('catalog', 1200)
            got = self._recent_row('catalog')
            self.assertEqual(len(got['chips']), 3)
            self.page.click('#catalog-device-recent-chips button:nth-child(3)')
            self.page.wait_for_timeout(400)
            third = got['chips'][2][0]
            self.assertEqual(self.page.inner_text('#catalog-device-current'), 'Target: ' + third)
            self.assertEqual(self.page.evaluate("typeof _catalogDev.id"), 'string')
            self.assertEqual(self.page.evaluate("_catalogDev.name"), third)
            self.assertEqual(self.page.evaluate("(JSON.parse(localStorage.getItem('rp_recent_devices')) || [])[0].name"), third)
            self.assertEqual([c[1] for c in self._recent_row('catalog')['chips']], ['false', 'false', 'true'])
        finally:
            self.page.evaluate("""() => { window.cronRefresh = window.__orig.cronRefresh; window.fmListPath = window.__orig.fmListPath;
                _cronDev = null; _fmDev = null; _catalogDev = null; }""")

    # ── Pentest ─────────────────────────────────────────────────────────────
    def test_the_new_scan_form_is_its_own_card_apart_from_the_table_controls(self):
        self._show('scans', 2200)
        m = self.page.evaluate("""() => {
            const title = el => { const c = el && el.closest('.dash-card'); const t = c && c.querySelector(':scope > .section-title'); return t ? t.textContent.trim() : null; };
            const q = s => document.querySelector('#page-scans ' + s);
            const form = ['#scan-device-search', '#scan-tool', '#scan-profile', '#scan-intensity', '#scan-vhost', '#scan-satellite', '#scan-attest', '#scan-override',
                          '[data-action="queueScan"]'].map(s => title(q(s)));
            const table = ['#scans-filter', '[data-action="loadScans"]', '[data-action="clearScans"]', '#scans-thead'].map(s => title(q(s)));
            const a = q('#scan-tool').closest('.dash-card'), b = q('#scans-filter').closest('.dash-card');
            return {form, table, distinct: a !== b, above: a.getBoundingClientRect().bottom <= b.getBoundingClientRect().top + 1}; }""")
        self.assertEqual(len(m['form']), 9, 'control: the form has nine controls')
        self.assertEqual(set(m['form']), {'New scan'}, m)
        self.assertEqual(set(m['table']), {'Scans'}, m)
        self.assertTrue(m['distinct'])
        self.assertTrue(m['above'], 'the form is above the table it adds to')

    def test_the_host_search_results_open_under_the_search_and_push_the_rest_down(self):
        self._show('scans', 2200)
        self.page.fill('#scan-device-search', 'a')
        self.page.wait_for_selector('#scan-device-results:not(.hidden)', timeout=5000)
        self.page.wait_for_timeout(300)
        r = self.page.evaluate("""() => { const b = id => document.getElementById(id).getBoundingClientRect();
            return {search: b('scan-device-search'), results: b('scan-device-results'), vhost: b('scan-vhost'),
                    rows: document.querySelectorAll('#scan-device-results > *').length}; }""")
        self.assertGreater(r['rows'], 0, 'control: the demo fleet has hosts with an a in the name')
        self.assertGreaterEqual(r['results']['top'], r['search']['bottom'] - 1, 'the list starts under the field it belongs to')
        self.assertGreaterEqual(r['vhost']['top'], r['results']['bottom'] - 1, 'the next row moves down instead of sitting under the list')
        self.page.fill('#scan-device-search', '')
        self.page.evaluate("() => document.getElementById('scan-device-results').classList.add('hidden')")

    # ── Fleet Query ─────────────────────────────────────────────────────────
    def _fq_group(self, title):
        return self.page.evaluate("""(t) => { const d = [...document.querySelectorAll('#fq-groups details.fq-group')]
                .find(x => x.querySelector('summary').childNodes[0].textContent.trim() === t);
            const b = d.querySelector('.fq-count'); return {n: b.textContent, hidden: b.classList.contains('d-none'), open: d.open, title: b.getAttribute('title')}; }""", title)

    def test_the_fleet_query_criteria_sit_in_six_groups_each_in_exactly_one(self):
        self._show('query', 1500)
        m = self.page.evaluate("""() => { const groups = [...document.querySelectorAll('#fq-groups details.fq-group')];
            const ids = Object.values(_FQ_FIELDS);
            return {groups: groups.map(d => d.querySelector('summary').childNodes[0].textContent.trim()),
                    per: ids.map(id => groups.filter(d => d.querySelector('#' + id)).length),
                    ids: ids.length, fields: document.querySelectorAll('#fq-groups .form-group').length,
                    loose: document.querySelectorAll('#page-query .settings-section > .settings-row').length}; }""")
        self.assertEqual(m['groups'], ['Identity', 'State', 'Patching', 'Resources', 'Problems', 'Security posture'])
        self.assertGreaterEqual(m['ids'], 50, 'control: the page filters on some fifty criteria')
        self.assertEqual(set(m['per']), {1}, 'every criterion is in exactly one group')
        self.assertEqual(m['fields'], m['ids'], 'no field outside _FQ_FIELDS, none missing from it')
        self.assertEqual(m['loose'], 0, 'no criteria outside a group')

    def test_the_identity_group_starts_open_and_the_others_closed(self):
        import re
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        opens = re.findall(r'<details class="fq-group"( open)?>', html)
        self.assertEqual(len(opens), 6, 'control: six groups in the markup')
        self.assertEqual([bool(o) for o in opens], [True, False, False, False, False, False])

    def _fq_reset(self):
        """First-visit state: no criterion has a value, Identity is open and the other groups are closed."""
        self._show('query', 1500)
        self.page.evaluate("""() => { document.querySelectorAll('#fq-groups input, #fq-groups select').forEach(el => { el.value = ''; });
            document.querySelectorAll('#fq-groups details').forEach((d, i) => { d.open = (i === 0); }); _fqRefreshCounts(false); }""")

    def test_a_group_counts_the_criteria_set_in_it_and_opens_when_a_saved_query_fills_it(self):
        self._fq_reset()
        self.assertEqual(self._fq_group('Patching'), {'n': '', 'hidden': True, 'open': False, 'title': 'Criteria set in this group'})
        # open a group by its heading as a person would, and type into two of its criteria
        heading = '#fq-groups details.fq-group:nth-of-type(3) > summary'
        self.page.click(heading)
        self.page.fill('#fq-pending', '3')
        self.page.fill('#fq-cve', '5')
        got = self._fq_group('Patching')
        self.assertEqual((got['n'], got['hidden'], got['open']), ('2', False, True))
        # closing the group forgets nothing: the count stays and Run and Save still send the values
        self.page.click(heading)
        got = self._fq_group('Patching')
        self.assertEqual((got['n'], got['hidden'], got['open']), ('2', False, False))
        self.assertEqual(self.page.evaluate("[_fqFields().pending_gt, _fqFields().cve_min]"), ['3', '5'])
        # a saved query replaces every criterion and opens the groups it fills; a select counts like a field
        self.page.evaluate("() => { _fqSaved = [{id: 'zz9', name: 'sweep', params: {cpu_gt: '90', brute_force: '1'}}]; applyFleetQuery('q-zz9'); }")
        self.page.wait_for_timeout(600)
        usage, security, patching = self._fq_group('Resources'), self._fq_group('Security posture'), self._fq_group('Patching')
        self.assertEqual((usage['n'], usage['open']), ('1', True))
        self.assertEqual((security['n'], security['open']), ('1', True))
        self.assertEqual((patching['n'], patching['hidden']), ('', True), 'the earlier criteria are gone, so is their count')

    def test_clear_criteria_empties_every_field_and_every_count_and_leaves_the_groups_alone(self):
        self._fq_reset()
        self.page.click('#fq-groups details.fq-group:nth-of-type(3) > summary')        # Patching
        self.page.fill('#fq-pending', '3')
        self.page.click('#fq-groups details.fq-group:nth-of-type(6) > summary')        # Security posture
        self.page.select_option('#fq-brute', '1')
        self.assertEqual((self._fq_group('Patching')['n'], self._fq_group('Security posture')['n']), ('1', '1'), 'control: two criteria are set')
        self.page.click('[data-action="clearFleetQuery"]')
        left = self.page.evaluate("""() => [...document.querySelectorAll('#fq-groups input, #fq-groups select')].filter(el => (el.value || '') !== '').length""")
        self.assertEqual(left, 0, 'a field kept its value')
        self.assertEqual(self.page.evaluate("Object.values(_fqFields()).filter(v => v !== '').length"), 0, 'Run and Save would still send one')
        for title in ('Identity', 'State', 'Patching', 'Resources', 'Problems', 'Security posture'):
            got = self._fq_group(title)
            self.assertEqual((got['n'], got['hidden']), ('', True), title)
        # the groups stay as they were: the two the person opened are still open
        self.assertTrue(self._fq_group('Patching')['open'] and self._fq_group('Security posture')['open'])

    # ── Schedules in words ──────────────────────────────────────────────────
    def test_the_four_tables_that_show_a_schedule_show_it_in_words(self):
        for page, body in (('autopatch', '#autopatch-tbody'), ('schedule', '#schedule-tbody'), ('maintenance', '#maint-tbody'), ('backups', '#backups-tbody')):
            self._show(page, 2500)
            got = self.page.evaluate("""(body) => [...document.querySelectorAll(body + ' tr')].map(tr => {
                    const raw = tr.querySelector('div.hint.mono-12'); if (!raw) return null;
                    const words = raw.previousElementSibling ? raw.previousElementSibling.textContent : '';
                    return {raw: raw.textContent, words, expected: cronWords(raw.textContent)}; }).filter(Boolean)""", body)
            self.assertGreaterEqual(len(got), 3, page + ': control: the demo has scheduled rows')
            for g in got:
                self.assertTrue(g['words'], g)
                self.assertEqual(g['words'], g['expected'], g)
                self.assertRegex(g['raw'], r'^\S+( \S+){4}$', 'the expression itself stays under the words')

    def test_the_scheduled_scans_of_pentest_show_their_schedule_in_words_with_the_expression_on_hover(self):
        self._show('scans', 2600)
        self.page.mouse.move(1, 1)                  # the tooltip script takes the title off the element under the pointer
        got = self.page.evaluate("""() => [...document.querySelectorAll('#scan-schedules-list .hint > span[title]')]
                .map(s => ({words: s.textContent, raw: s.title, expected: cronWords(s.title)}))""")
        self.assertGreaterEqual(len(got), 2, 'control: the demo has two scheduled scans')
        for g in got:
            self.assertTrue(g['words'], g)
            self.assertEqual(g['words'], g['expected'], g)
            self.assertRegex(g['raw'], r'^\S+( \S+){4}$')

    def test_maintenance_keeps_its_length_on_the_first_line_of_the_words(self):
        self._show('maintenance', 2500)
        text = self.page.evaluate("""() => { const raw = [...document.querySelectorAll('#maint-tbody div.hint.mono-12')].find(d => d.textContent === '0 1 1 * *');
            return raw ? raw.parentElement.innerText.replace(/\\s+/g, ' ').trim() : null; }""")
        self.assertEqual(text, 'Monthly on day 1 at 01:00 for 180min 0 1 1 * *')

    # ── The Time display setting reaches the table cells ────────────────────
    # (page, selector of the converted cells, how many the seeded demo draws today)
    _TIME_CELLS = (
        ('scans', '#scans-tbody td.meta-sm-nm time', 6), ('backups', '#backups-tbody td.hint time', 4),
        ('apikeys', '#apikeys-tbody td.hint time', 4), ('sites', '#sites-tbody td.hint time', 3),
        ('business-services', '#page-business-services td.meta-sm-nm time', 5), ('dmarc', '#page-dmarc td.meta-sm-nm time', 8),
        ('drift', '#page-drift td.hint time', 5), ('dns', '#page-dns td.meta-sm-nm time', 3), ('tls', '#page-tls td.hint-nowrap time', 3),
        ('services', '#page-services td.meta-sm-nm time', 12), ('patchsnapshots', '#page-patchsnapshots span.hint time', 3),
        ('self', '#page-self time', 1),
    )

    def test_the_time_display_setting_flips_the_converted_table_cells(self):
        read = """(sel) => [...document.querySelectorAll(sel)].map(t => [t.textContent, t.title, t.getAttribute('datetime')])"""
        relative = re.compile(r'^(?:\d+\w* ago|just now)$')

        def flipped(cells, mode, at_least):
            """Do these cells read as the setting says? Relative in place and exact on hover; the setting swaps them."""
            if len(cells) < at_least:
                return False
            for text, title, iso in cells:
                rel, exact = (text, title) if mode == 'relative' else (title, text)
                if not (relative.match(rel) and not re.search(r'\bago$', exact) and re.match(r'^\d{4}-\d\d-\d\dT', iso or '')):
                    return False
            return True
        try:
            for mode in ('relative', 'absolute'):
                self.page.evaluate("(m) => { _uiPrefs.time_display = m; }", mode)
                for page, sel, at_least in self._TIME_CELLS:
                    self._show(page, 800)
                    # a page fetches before it draws: poll from here until the cells show the setting, then assert what is there
                    cells = []
                    for _ in range(40):
                        # the tooltip script takes the title off the element under the pointer: park it in a corner first
                        self.page.mouse.move(1, 1)
                        cells = self.page.evaluate(read, sel)
                        if flipped(cells, mode, at_least):
                            break
                        self.page.wait_for_timeout(300)
                    self.assertTrue(flipped(cells, mode, at_least), f'{page} ({mode}): wanted at least {at_least} cells in the setting, saw {cells[:3]}')
        finally:
            self.page.evaluate("() => { _uiPrefs.time_display = 'relative'; }")

    # ── The tab title ───────────────────────────────────────────────────────
    def test_the_tab_title_keeps_the_alert_count_and_the_page(self):
        self._show('cve', 600)
        base = self.page.title()
        self.assertIn(' — ', base)
        page_label = base.split(' — ')[0].lstrip('0123456789() ')
        self.page.evaluate("() => { _tabBadgeN = -1; _paintTabAlertBadge(7); }")
        with_count = self.page.title()
        self.assertTrue(with_count.startswith('(7) '), with_count)
        self.assertIn(page_label, with_count)
        self.page.evaluate("() => { _paintTabAlertBadge(0); }")
        self.assertFalse(self.page.title().startswith('('), 'the count is gone with the alerts')
        self.assertIn(page_label, self.page.title())

    # ── Forecast ────────────────────────────────────────────────────────────
    def test_the_word_projected_is_not_struck_through_by_the_projection(self):
        self._show('forecast', 2500)
        m = self.page.evaluate("""() => {
            const svg = [...document.querySelectorAll('#page-forecast svg')].find(s => [...s.querySelectorAll('text')].some(t => t.textContent === 'projected'));
            if (!svg) return null;
            const word = [...svg.querySelectorAll('text')].find(t => t.textContent === 'projected').getBoundingClientRect();
            const line = svg.querySelector('line[stroke-dasharray="6 5"]');
            if (!line) return {word: [word.left, word.top, word.bottom], line: null};
            const l = line.getBoundingClientRect();
            return {word: [word.left, word.top, word.bottom], line: [l.left, l.top, l.right, l.bottom], x1: +line.getAttribute('x1'), y1: +line.getAttribute('y1'),
                    x2: +line.getAttribute('x2'), y2: +line.getAttribute('y2')}; }""")
        self.assertIsNotNone(m, 'control: the seeded forecast draws a chart with a projected region')
        self.assertIsNotNone(m['line'], 'control: and a projection line')
        # the line's own y at the word's x, in screen coordinates (the box of a diagonal says nothing about where it passes)
        l_left, l_top, l_right, l_bottom = m['line']
        w_left, w_top, w_bottom = m['word']
        w_mid_x, w_mid_y = w_left + 20, (w_top + w_bottom) / 2
        if l_right > l_left:
            frac = min(1, max(0, (w_mid_x - l_left) / (l_right - l_left)))
            rising = m['y2'] < m['y1']
            y_at = (l_bottom - frac * (l_bottom - l_top)) if rising else (l_top + frac * (l_bottom - l_top))
            self.assertGreater(abs(w_mid_y - y_at), 10, 'the projection line passes through the word')

    # ── Advisory ────────────────────────────────────────────────────────────
    def test_the_advisory_builds_itself_the_first_time(self):
        self.page.evaluate("_advLast = null")
        self._show('advisory', 2500)
        findings = self.page.inner_text('#adv-findings')
        self.assertNotIn('Choose a scope and build', findings)
        self.assertGreater(len(self.page.query_selector_all('#adv-summary .adv-tile')), 2, 'the summary tiles are drawn')
        self.assertGreater(len(findings), 40, 'the findings are drawn')

    # ── My Account ──────────────────────────────────────────────────────────
    def test_my_account_names_itself_in_the_top_bar(self):
        self.page.evaluate("openAccount()")
        self.page.wait_for_timeout(600)
        crumb = self.page.inner_text('#topbar-crumb')
        self.assertNotEqual(crumb.strip().lower(), 'account', 'the raw page name')
        self.assertRegex(crumb, r'(?i)my account|account')
        self.assertNotRegex(crumb.strip(), r'^account$')


if __name__ == '__main__':
    unittest.main()
