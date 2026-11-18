#!/usr/bin/env python3
"""Keyboard focus rings inside the lists that scroll (`scroll-cap-lg`), in a browser on the demo seed.

A list that scrolls clips what it draws, so a ring drawn outside a control in the first column, the first row or the last row is cut by the list's own
edge. The rule that draws the ring inside (`outline-offset: -2px`) named .scroll-cap, .scroll-cap-sm, the heat map and one Threat Intel list, and not
.scroll-cap-lg. Measured in Chromium and Firefox before the rule was widened: 15 of the first 60 AI Insights cards were cut by 3 px at a side and 3 at the
bottom, the links in the first column by 3 px (the last one at the bottom too), the Knowledge base article's buttons by 3 px at the top and the right, and
every CMDB document heading by 2 px on all four sides.

What is held: the ring of each control in each list is inside the list's own edge (half a pixel at the sides, a pixel at the top and bottom, because a list
scrolls to a whole pixel), the instrument can see a cut ring (a control that moves the ring outside again), and every `scroll-cap-lg` element of the page is
either measured here, measured by the Threat Intel module, or listed with the reason it holds nothing a keyboard can reach.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import os
import re
import shutil
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
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail('playwright not installed')
    if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
        raise unittest.SkipTest('the page is backend-agnostic: measured once, under the default backend')
    seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
    if not seeder.is_file():
        raise unittest.SkipTest('demo seeder not in this tree')
    data_dir = tempfile.mkdtemp(prefix='rp-rings-')
    proc = subprocess.run([sys.executable, str(seeder), '--data-dir', data_dir, '--apply'], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        shutil.rmtree(data_dir, ignore_errors=True)
        browser_required.skip_or_fail('demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
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
        browser_required.skip_or_fail(f'app stack not available: {exc}')
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE['browser'].close()
        _STATE['pw'].stop()
    finally:
        if _STATE.get('shutdown'):
            _STATE['shutdown']()
        shutil.rmtree(_STATE.get('data_dir', ''), ignore_errors=True)       # tmpfs: the seeded data dir goes with the module


# Where the ring of the focused control is drawn against the edges of the list that clips it (negative: cut). The ring's outer edge is the border box
# grown by the outline's width and offset.
MEASURE = """(boxSel) => {
    const a = document.activeElement, box = document.querySelector(boxSel);
    if (!a || !box || !box.contains(a)) return null;
    a.scrollIntoView({block: 'nearest', inline: 'nearest'});
    const cs = getComputedStyle(a), r = a.getBoundingClientRect(), b = box.getBoundingClientRect();
    const grow = (cs.outlineStyle === 'none' ? 0 : parseFloat(cs.outlineWidth)) + (parseFloat(cs.outlineOffset) || 0);
    const L = b.left + box.clientLeft, T = b.top + box.clientTop, R = L + box.clientWidth, B = T + box.clientHeight;
    return {what: a.tagName.toLowerCase() + '.' + String(a.className).split(' ')[0] + ' ' + (a.textContent || '').trim().slice(0, 24).replace(/\\s+/g, ' '),
            style: cs.outlineStyle, visible: a.matches(':focus-visible'),
            left: r.left - grow - L, top: r.top - grow - T, right: R - (r.right + grow), bottom: B - (r.bottom + grow)};
}"""

FOCUSABLE = 'a, button, summary, [tabindex]:not([tabindex="-1"])'

# The lists measured here: the page, the element that clips, and what to do so that it holds what a person sees.
LISTS = (
    dict(name='AI Insights cards', page='ai', box='#ai-insights-grid',
         # the card is hidden until a model provider is configured, and the seed has none: show it, render it as the page does
         prepare="""async () => { const w = document.getElementById('ai-insights-wrap'); if (w) w.classList.remove('d-none'); _renderAIInsights();
                    await new Promise(r => setTimeout(r, 300));
                    for (let n = document.getElementById('ai-insights-grid'); n && n.id !== 'page-ai'; n = n.parentElement) if (getComputedStyle(n).display === 'none') n.style.display = 'block'; }"""),
    dict(name='Knowledge base article', page='kb', box='#kb-view',
         prepare="""async () => { const el = document.querySelector('#kb-list .kb-item'); if (el) el.click(); await new Promise(r => setTimeout(r, 1800)); }"""),
    dict(name='Links', page='links', box='#links-grid', prepare=None),
    dict(name='CMDB documents', page='cmdb', box='#cmdb-docs-list', minimum=1,       # the first asset with a document may have just the one: its heading is the first and the last row
         prepare="""async () => { const id = window.__cmdbDocAsset; if (!id) return; await cmdbOpenAsset(id); await new Promise(r => setTimeout(r, 1200));
                    const tab = document.querySelector('#cmdb-tab-btn-docs'); if (tab) tab.click(); await new Promise(r => setTimeout(r, 600)); }"""),
)

# Every element of the page that carries scroll-cap-lg and an id, and why it is not in LISTS.
ELSEWHERE = {
    'ipintel-ignore-classes': 'measured by tests/test_v801_threatintel_e2e.py (a Tab walk through its 31 boxes)',
    'patch-plan-body': 'the text of a plan a host sent, in a dialog: no control of its own, the dialog\'s buttons sit outside the list',
}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheRingsInTheListsThatScroll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = _STATE['browser'].new_context(viewport={'width': 1440, 'height': 900}, service_workers='block')
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page = ctx, ctx.new_page()
        cls.page.goto(_STATE['base'] + '/index.html')
        cls.page.fill('#login-user', 'alice')            # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill('#login-pass', 'demo')
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector('#app', state='visible', timeout=90000)
        cls.page.wait_for_timeout(4000)
        # a host whose CMDB record has documents, for the last list: asked of the app, which is where a person would find one
        cls.asset = cls.page.evaluate("""async () => { const r = await api('GET', '/cmdb'); const list = Array.isArray(r) ? r : ((r && (r.assets || r.items)) || []);
                                          const a = list.find(x => x && x.has_documentation); return a ? a.device_id : null; }""")
        cls.page.evaluate('(d) => { window.__cmdbDocAsset = d; }', cls.asset)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def walk(self, spec):
        """Focus each control of the list from the keyboard's side and measure its ring. Returns the rows."""
        page = self.page
        page.evaluate('(p) => showPage(p)', spec['page'])
        page.wait_for_selector('#page-%s.active' % spec['page'], timeout=20000)
        page.wait_for_timeout(1500)
        if spec['prepare']:
            page.evaluate(spec['prepare'])
        page.keyboard.press('Tab')                       # a key first, so that a script's focus() counts as the keyboard's for :focus-visible
        rows = []
        for el in page.query_selector_all(', '.join('%s %s' % (spec['box'], part.strip()) for part in FOCUSABLE.split(','))):
            if not el.is_visible():
                continue
            el.focus()
            got = page.evaluate(MEASURE, spec['box'])
            if got:
                rows.append(got)
            if len(rows) >= 60:
                break
        return rows

    def test_the_ring_of_each_control_is_inside_the_edge_of_its_list(self):
        for spec in LISTS:
            with self.subTest(list=spec['name']):
                if spec['name'] == 'CMDB documents':
                    self.assertTrue(self.asset, 'the control: the seed has an asset with documents')
                rows = self.walk(spec)
                self.assertGreaterEqual(len(rows), spec.get('minimum', 2), 'the control: the list holds controls, %r' % rows)
                for row in rows:
                    where = '%s: %r' % (spec['name'], row)
                    self.assertTrue(row['visible'] and row['style'] != 'none', 'the focused control shows no ring. ' + where)
                    for side, room in (('left', 0.5), ('right', 0.5), ('top', 1.0), ('bottom', 1.0)):
                        self.assertGreaterEqual(row[side], -room, 'the ring is cut at the %s edge of the list. %s' % (side, where))

    def test_the_instrument_sees_a_cut_ring(self):
        """The control for the test above: put the ring outside again and the same measurement reports a cut, so a pass is not a blind pass."""
        self.page.add_style_tag(content='.scroll-cap-lg :focus-visible { outline-offset: 2px !important; }')
        try:
            cut = []
            for spec in LISTS:
                rows = self.walk(spec)
                cut.append(sum(1 for r in rows if min(r['left'], r['right']) < -0.5 or min(r['top'], r['bottom']) < -1.0))
            self.assertTrue(all(n > 0 for n in cut), 'every list shows a cut ring once the ring is drawn outside: %r' % cut)
        finally:
            self.page.evaluate("() => document.querySelectorAll('style').forEach(s => { if (s.textContent.includes('outline-offset: 2px !important')) s.remove(); })")

    def test_every_scrolling_list_of_the_page_is_measured_or_listed(self):
        """The population is the class, not the four lists somebody remembered: every element with an id and the class in index.html is in LISTS or
        listed with the reason; the one built by script (the AI debug view) is a <pre>, which holds text and no control."""
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        ids = set()
        for tag in re.findall(r'<[a-z][^>]*\bclass="[^"]*\bscroll-cap-lg\b[^"]*"[^>]*>', html):
            m = re.search(r'\bid="([^"]+)"', tag)
            self.assertTrue(m, 'a scroll-cap-lg element without an id is not measurable: ' + tag[:120])
            ids.add(m.group(1))
        self.assertGreaterEqual(len(ids), 6, 'the control: the class is found on the page %r' % sorted(ids))
        known = {spec['box'].lstrip('#') for spec in LISTS} | set(ELSEWHERE)
        self.assertEqual(sorted(ids - known), [], 'a scrolling list that nothing measures: add it to LISTS, or to ELSEWHERE with the reason')
        self.assertEqual(sorted(known - ids), [], 'listed here and no longer on the page')
        built = [p.name for p in (_ROOT / 'server' / 'html' / 'static' / 'js').glob('app*.js')
                 if re.search(r'class="[^"]*scroll-cap-lg', p.read_text(encoding='utf-8'))]
        self.assertEqual(built, ['app-ai.js'], 'a script builds a scrolling list: say what it holds')


if __name__ == '__main__':
    unittest.main()
