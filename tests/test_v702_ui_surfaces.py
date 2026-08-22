#!/usr/bin/env python3
"""Four UI surfaces that were missing, frozen, or unbounded.

**The alert wall never refreshed, and neither did 81 of 83 pages.**
`startRefreshCycle()` is the product's only periodic UI refresh, and its tick
called exactly three things: `loadDevices()`, `loadHome()` (when the dashboard
is showing) and `_refreshTopBadges()`. Nothing else. So an operator with the
Alerts, Checks, Needs Attention, CVE or Exposure page open watched a snapshot
taken at load time, with the topbar countdown ticking beside it implying
otherwise — and the alert WALL, a feature whose whole purpose is to be left on a
screen, showed the inbox as it was when the browser opened and never again.

The fix hangs a page-refresher map off the one existing tick rather than
starting a timer per page: leaving a page stops its refresher because the lookup
stops matching, so there is nothing to leak. The one real timer added is the
wall's 1 Hz age stamp, and this file pins its teardown, because a leaked
setInterval in an SPA is its own bug.

**Two endpoints had no surface.** `GET /api/privacy/subject` and `POST
/api/privacy/erase` (GDPR Article 15/17) and `POST /api/autonomy/preview` (the
blast-radius pre-flight) were implemented, scoped and audited with no UI at all,
while `docs/features.md` sells the first as a headline capability. The tests
here pin the wiring and, for privacy, that the RETAINED column exists — that is
the half of a subject-access report that protects the operator, since the
hash-chained audit log is lawfully retained and a report listing only deletions
would misdescribe what the instance holds.

**Four JS-built panels grew without limit.** The rack elevation renders one 18px
row per rack unit and measured 758px with no cap on any ancestor; it was never
caught because the wrap starts hidden and the rendered sweeps skip a
`display: none` element. Measured, not read: the ratio over the whole population
of JS row-sinks is in the docstring of `TestUncappedPanels`.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_HTML = _ROOT / 'server' / 'html' / 'index.html'
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')


def _app():
    return (_JS / 'app.js').read_text()


def _all_js():
    return {f.name: f.read_text() for f in sorted(_JS.glob('app*.js'))}


def _run_node(script):
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-uisurf-'))
    f = d / 't.js'
    f.write_text(script)
    r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(f'node failed: {r.stderr[:2000]}')
    return r.stdout.strip()


# The stub document/timers the refresh tick needs. Kept here so both the
# positive case (an alerting page refreshes) and the negative one (a settings
# page does not) run the SAME real source.
_TICK_HARNESS = r'''
const calls = [];
const ACTIVE = process.argv[2];
function mkEl(id){return {id, classList:{contains:(c)=>c==='active'}};}
global.document = {
  hidden: false,
  getElementById: (id) => (id === 'page-' + ACTIVE ? mkEl(id) : null),
  querySelector: (sel) => (sel === '.page.active' ? mkEl('page-' + ACTIVE) : null),
};
let refreshInterval = 2, refreshTimer = null;
const timers = [];
global.setInterval = (fn) => { timers.push(fn); return timers.length; };
global.clearInterval = () => {};
function loadDevices(){calls.push('loadDevices');}
function loadHome(){calls.push('loadHome');}
function _refreshTopBadges(){calls.push('_refreshTopBadges');}
global.window = {};
__REFRESHERS__
__SRC__
for (const n of Object.values(PAGE_REFRESHERS).map(s => s.fn))
  window[n] = () => calls.push(n);
startRefreshCycle();
for (let i = 0; i < 3; i++) timers.forEach(f => f());
console.log(JSON.stringify(calls));
'''


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheTickRefreshesTheVisiblePage(unittest.TestCase):
    """Runs the real startRefreshCycle, rather than reading it.

    A source pin would have passed against the broken version too: the tick
    always CONTAINED a page refresh, it was just hardcoded to the dashboard.
    """

    @classmethod
    def setUpClass(cls):
        app = _app()
        cls.parts = '\n'.join(
            srcpin.js_function(app, n)
            for n in ('_refreshShouldPause', '_refreshActivePage', 'startRefreshCycle'))
        cls.refreshers = (srcpin.balanced_block(app, 'const PAGE_REFRESHERS = {')
                          + '\nconst _lastPageRefresh = {};')

    def _tick(self, page):
        script = (_TICK_HARNESS.replace('__REFRESHERS__', self.refreshers)
                               .replace('__SRC__', self.parts))
        return json.loads(_run_node(script.replace(
            "process.argv[2]", json.dumps(page))))

    def test_an_alerting_page_is_refreshed_by_the_tick(self):
        for page, fn in (('alerts', 'loadAlerts'), ('checks', 'loadChecks'),
                         ('attention', 'loadAttentionPage')):
            with self.subTest(page=page):
                self.assertIn(fn, self._tick(page),
                              f'{page} is showing and the tick never refreshed it')

    def test_a_configuration_page_is_left_alone(self):
        """The counter-direction, or "refresh everything" would also pass.

        Redrawing a Settings pane under the operator's hand is a worse bug than
        a stale one, so the map has to be selective and this is what says so.
        """
        calls = self._tick('settings')
        self.assertIn('loadDevices', calls)     # the tick did run
        self.assertEqual([c for c in calls if c.startswith('load')
                          and c != 'loadDevices'], [],
                         'a configuration page was refreshed under the operator')


class TestPageRefresherMapResolves(unittest.TestCase):
    """Every name in the map must be a real loader and a real page.

    The map holds NAMES, not references, because most of these loaders live in
    lazily-fetched modules that are not defined at boot — which means a typo
    fails silently at 60-second intervals rather than at load. Same shape as
    test_ui_wiring's dispatch-name check, for the same reason.
    """

    def setUp(self):
        block = srcpin.balanced_block(_app(), 'const PAGE_REFRESHERS = {')
        self.pairs = re.findall(r"(\w+):\s*\{\s*fn:\s*'(\w+)'", block)
        self.assertGreaterEqual(len(self.pairs), 4,
                                'the map parsed empty — the test would pass vacuously')

    def test_every_refresher_is_a_defined_function(self):
        src = '\n'.join(_all_js().values())
        for page, fn in self.pairs:
            with self.subTest(page=page):
                self.assertRegex(src, r'\b(async\s+)?function\s+%s\s*\(' % re.escape(fn),
                                 f'{page} refreshes with {fn}(), which is defined nowhere')

    def test_every_refreshed_page_exists(self):
        html = _HTML.read_text()
        for page, _fn in self.pairs:
            with self.subTest(page=page):
                self.assertIn('id="page-%s"' % page, html)

    def test_the_tick_calls_it(self):
        body = srcpin.js_function(_app(), 'startRefreshCycle')
        self.assertIn('_refreshActivePage()', body,
                      'the map exists but nothing on the tick reads it')


class TestAlertWallStaysCurrent(unittest.TestCase):
    """The wall refreshes, and its one timer is torn down by every exit route."""

    def test_alerts_is_in_the_refresher_map(self):
        block = srcpin.balanced_block(_app(), 'const PAGE_REFRESHERS = {')
        self.assertIn("alerts:", block,
                      'the wall shows #page-alerts; without a refresher it is frozen')

    def test_the_wall_starts_the_age_stamp(self):
        self.assertIn('_startAlertWallStamp()', srcpin.js_function(_app(), 'enterAlertWall'))

    def test_every_exit_route_clears_the_interval(self):
        app = _app()
        self.assertIn('_stopAlertWallStamp()', srcpin.js_function(app, 'exitAlertWall'),
                      'Exit full screen leaves a 1 Hz interval running')
        self.assertIn('_stopAlertWallStamp()', srcpin.js_function(app, '_stopPagePollers'),
                      'navigating away leaves a 1 Hz interval running')
        # Esc / F11 / the OS leaving fullscreen goes through this listener and
        # nothing else, so it needs its own teardown.
        i = app.index("document.addEventListener('fullscreenchange'")
        self.assertIn('_stopAlertWallStamp()', app[i:i + 400],
                      'leaving fullscreen by Esc leaves a 1 Hz interval running')

    def test_the_stamp_has_somewhere_to_render(self):
        self.assertIn('id="alertwall-stamp"', _HTML.read_text())
        css = _CSS.read_text()
        self.assertIn('body.alertwall .alertwall-stamp', css,
                      'the stamp element exists but is never shown in wall mode')

    @unittest.skipUnless(_NODE, 'node not installed')
    def test_the_stamp_reads_stale_when_the_data_is_old(self):
        """A wall that has lost its session must not look like a quiet fleet."""
        app = _app()
        src = '\n'.join(srcpin.js_function(app, n) for n in ('_paintAlertWallStamp',))
        script = (
            'const el = {textContent: "", classList: {_s: new Set(),'
            ' toggle(c, on){ on ? this._s.add(c) : this._s.delete(c); },'
            ' remove(c){ this._s.delete(c); }, has(c){ return this._s.has(c); }}};\n'
            'global.document = { getElementById: () => el };\n'
            'const PAGE_REFRESHERS = { alerts: { fn: "loadAlerts", every: 60 } };\n'
            'const _lastPageRefresh = {};\n'
            + src +
            '\n_lastPageRefresh["alerts"] = Date.now() - 5000;\n'
            '_paintAlertWallStamp();\n'
            'const fresh = {t: el.textContent, stale: el.classList.has("stale")};\n'
            '_lastPageRefresh["alerts"] = Date.now() - 600000;\n'
            '_paintAlertWallStamp();\n'
            'const old = {t: el.textContent, stale: el.classList.has("stale")};\n'
            'console.log(JSON.stringify({fresh, old}));\n')
        r = json.loads(_run_node(script))
        self.assertIn('5s ago', r['fresh']['t'])
        self.assertFalse(r['fresh']['stale'])
        self.assertTrue(r['old']['stale'],
                        'a ten-minute-old inbox rendered as though it were current')


class TestUncappedPanels(unittest.TestCase):
    """Four JS-built panels grew without limit; here they are bounded.

    The population was enumerated mechanically (322 element ids that app*.js
    fills one node per record) and the instrument was wrong three times before
    it was right — the first pass reported 87 of 95 capped because it could not
    see the shape the rack uses. Ratio on the fourth pass, with all four
    known-bad panels asserted as positive controls first: 322 sinks — 124
    capped, 51 uncapped, 115 native (a `<select>`/`<datalist>`/`<tbody>`, whose
    cap lives on an ancestor), 32 with no static node.

    Of the 51, nine were plausible variable-length panels and were MEASURED in a
    browser against the real stylesheet. Four were real; five were refuted:
    `mttr-hosts` slices to 12, `kmip-server-status` renders a fixed row set,
    `scan-detail`'s body already carries `.scroll-cap`, `virtualization-body`
    emits a `.table-card` at runtime, and `compliance-body`'s per-framework
    tables each sit in `.audit-scroll`.
    """

    def test_the_rack_elevation_caps(self):
        css = _CSS.read_text()
        rule = re.search(r'^\.rack-elev \{([^}]*)\}', css, re.M)
        self.assertIsNotNone(rule, '.rack-elev rule not found')
        self.assertIn('max-height', rule.group(1),
                      '42U x 18px = 756px with nothing capping it')
        self.assertIn('overflow-y: auto', rule.group(1))

    def test_the_three_html_panels_carry_a_cap_class(self):
        html = _HTML.read_text()
        for eid, cls in (('ai-insights-grid', 'scroll-cap-lg'),
                         ('qe-conditions', 'scroll-cap'),
                         ('declarative-import-result', 'scroll-cap')):
            with self.subTest(eid=eid):
                m = re.search(r'<div id="%s"[^>]*>' % re.escape(eid), html)
                self.assertIsNotNone(m, f'#{eid} not found')
                self.assertIn(cls, m.group(0),
                              f'#{eid} renders one row per record with no cap')


class TestPrivacyDsarSurface(unittest.TestCase):
    """GDPR Article 15/17 had two audited endpoints and no way to reach them."""

    def setUp(self):
        self.html = _HTML.read_text()
        self.js = (_JS / 'app-compliance.js').read_text()

    def test_the_card_is_on_the_compliance_page(self):
        page = srcpin.html_page(self.html, 'compliance')
        self.assertIn('id="privacy-card"', page,
                      'the DSAR card must be on the page a compliance officer opens')
        self.assertIn('data-action="runPrivacySubjectReport"', page)
        self.assertIn('data-action="erasePrivacySubject"', page)

    def test_both_handlers_exist(self):
        for fn in ('runPrivacySubjectReport', 'erasePrivacySubject'):
            with self.subTest(fn=fn):
                self.assertRegex(self.js, r'\basync function %s\s*\(' % fn)

    def test_it_calls_the_real_endpoints(self):
        self.assertIn('/privacy/subject', self.js)
        self.assertIn("'/privacy/erase'", self.js)

    def test_retained_records_are_shown_not_only_erasable_ones(self):
        """The retained half is what protects the operator.

        The hash-chained audit log is kept as evidence on purpose. A report that
        rendered only what could be deleted would misdescribe what the instance
        still holds, which is the one thing a DSAR reply has to get right.
        """
        self.assertIn('Retained', self.js)
        self.assertIn('Erasable', self.js)
        page = srcpin.html_page(self.html, 'compliance')
        self.assertIn('data-col="disposition"', page,
                      'the table has no column saying which records survive')
        self.assertIn('id="privacy-notes"', page,
                      "the server's own explanation of what is retained is not rendered")

    def test_erasure_keeps_the_servers_typed_confirmation_contract(self):
        """`confirm` must repeat the subject exactly — the server refuses otherwise."""
        body = srcpin.js_function(self.js, 'erasePrivacySubject')
        self.assertIn('confirm: typed', body)
        self.assertIn('withStepUp', body,
                      'erasure is exactly the shape step-up exists for')

    def test_the_sortable_table_is_wired(self):
        page = srcpin.html_page(self.html, 'compliance')
        for col in ('kind', 'store', 'ref', 'detail', 'disposition'):
            self.assertIn('data-col="%s"' % col, page)
        self.assertIn("wireSortOnly('privacy-subject-head'", self.js)


class TestAutonomyPreviewSurface(unittest.TestCase):
    """POST /api/autonomy/preview shipped with no UI, doc or tool."""

    def setUp(self):
        self.html = _HTML.read_text()
        self.js = (_JS / 'app-autonomy.js').read_text()

    def test_the_card_is_on_the_autonomy_page(self):
        page = srcpin.html_page(self.html, 'autonomy')
        self.assertIn('id="autonomy-preview-result"', page)
        self.assertIn('data-action="previewAutonomyBlastRadius"', page)

    def test_the_handler_exists_and_posts_to_the_endpoint(self):
        self.assertRegex(self.js, r'\basync function previewAutonomyBlastRadius\s*\(')
        body = srcpin.js_function(self.js, 'previewAutonomyBlastRadius')
        self.assertIn("'/autonomy/preview'", body)
        self.assertIn('device_id', body)

    def test_it_renders_every_component_the_contract_returns(self):
        """`blast_radius` carries four components and the score is their sum.

        Showing only the score answers "how big" and not "of what", which is the
        question someone about to reboot a host is actually asking.
        """
        body = srcpin.js_function(self.js, 'previewAutonomyBlastRadius')
        for field in ('monitors', 'containers', 'status_services', 'peers'):
            with self.subTest(field=field):
                self.assertIn('b.%s' % field, body)
        self.assertIn('exceeds_policy', body)
        self.assertIn('policy_limit', body)

    def test_the_action_picker_comes_from_the_server_catalog(self):
        """A hardcoded <option> list would be a second taxonomy to keep in step."""
        body = srcpin.js_function(self.js, '_fillAutonomyPreviewPickers')
        self.assertIn('_autonomyActionClasses', body)
        page = srcpin.html_page(self.html, 'autonomy')
        m = re.search(r'<select id="autonomy-preview-action"[^>]*>(.*?)</select>',
                      page, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn('<option', m.group(1),
                         'the action list is hardcoded in markup')


class TestNoInlineHandlersOrStyles(unittest.TestCase):
    """CSP: script-src 'self' with no unsafe-inline. An inline handler or a
    style="" in an innerHTML string dies silently in production."""

    def test_the_new_markup_is_clean(self):
        html = _HTML.read_text()
        for eid in ('privacy-card', 'autonomy-preview-result', 'alertwall-stamp'):
            i = html.index('id="%s"' % eid)
            block = html[max(0, i - 2500):i + 2500]
            self.assertNotRegex(block, r'\son[a-z]+\s*=\s*"',
                                f'inline event handler near #{eid}')
            self.assertNotRegex(block, r'<[^>]+\sstyle\s*=\s*"',
                                f'inline style attribute near #{eid}')

    def test_the_new_js_sets_no_style_strings(self):
        for name in ('app-compliance.js', 'app-autonomy.js'):
            src = (_JS / name).read_text()
            self.assertNotRegex(src, r'style="\$\{', f'{name} builds a style="" string')


if __name__ == '__main__':
    unittest.main()
