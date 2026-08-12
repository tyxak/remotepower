#!/usr/bin/env python3
"""Does a box actually render taller than the rule allows? Only the DOM knows.

CLAUDE.md's rule is that every panel with a variable row count caps at about
15 lines and scrolls internally. The existing guards are static: they check that
a `<table>` sits inside a wrapper class. That catches a missing wrapper and
cannot catch the case that actually shipped — a table that IS wrapped, by code
whose threshold is wrong.

The device list wrapped itself only above TWENTY rows while the documented cap
is fifteen, so any fleet of 16-20 devices rendered a table five rows past the
rule. Three separate copies of that threshold existed and all three disagreed
with the documentation. No amount of reading the markup finds this: the markup
is correct at any threshold. Rendering it and measuring is what finds it.

So this boots the real stack against the DEMO SEEDER's data — an empty install
renders every table's empty state, which is the blind spot that made the a11y
walk useless until v6.4.3 — logs in, visits every sidebar page, and measures.

A box is a violation when it is tall, holds many children, and NEITHER it nor
any ancestor scrolls. The ancestor walk is load-bearing: a `<tbody>` never
scrolls, its wrapper does, and a first version of this measurement without it
reported all nine correctly-wrapped tables as broken.
"""
import json
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

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

# Page-level containers that legitimately grow with the page rather than
# scrolling inside a panel. Each needs a reason: an undeclared exemption is
# indistinguishable from a box nobody has looked at.
EXEMPT = {
    'docs-container': 'the Documentation page IS a document — it scrolls at '
                      'page level, like every other long-form page',
    'dash-grid': 'the dashboard widget grid is the page layout, not a list; '
                 'capping it would put the page inside a box',
    'self-status-body': 'a vertical stack of distinct status CARDS, not rows — '
                        'each card caps its own content',
}

# ~15 rows at the app's row height, plus header and padding.
_TALL_PX = 620
_MANY_CHILDREN = 12

_MEASURE = """() => {
  const out = [], seen = new Set();
  document.querySelectorAll('#app .page.active *').forEach(el => {
    const st = getComputedStyle(el);
    if (st.display === 'none' || st.visibility === 'hidden') return;
    const sh = el.scrollHeight;
    if (sh < %d) return;
    if (el.children.length < %d) return;
    if (el.id && /^page-/.test(el.id)) return;
    for (let a = el; a && a !== document.body; a = a.parentElement) {
      const as = getComputedStyle(a);
      if (['auto','scroll'].includes(as.overflowY) && a.clientHeight > 0
          && a.clientHeight < sh) return;
      const c = a.classList;
      if (c && (c.contains('scrollable-table-wrap') || c.contains('scroll-cap')
          || c.contains('scroll-cap-sm') || c.contains('audit-scroll')
          || c.contains('table-card'))) return;
    }
    const key = (el.id || '') + '|' + el.className;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({id: el.id || '', cls: String(el.className).slice(0, 60),
              tag: el.tagName, h: sh, kids: el.children.length});
  });
  return out;
}""" % (_TALL_PX, _MANY_CHILDREN)


class TestNoBoxGrowsUnbounded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            raise unittest.SkipTest('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic — measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-boxes-')
        proc = subprocess.run(
            [sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
            capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest(
                'demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            raise unittest.SkipTest(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close(); cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def _pages(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        seen, out = set(), []
        for m in re.finditer(r'class="nav-btn[^"]*" data-page="([a-z-]+)"', html):
            if m.group(1) not in seen:
                seen.add(m.group(1)); out.append(m.group(1))
        return out

    def test_every_page_caps_its_variable_row_boxes(self):
        pages = self._pages()
        self.assertGreater(len(pages), 50, 'page enumeration found almost nothing')
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        findings, measured = {}, 0
        try:
            page.goto(self.base + '/index.html')
            # The seeder builds its own operator accounts; there is no 'admin'.
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(6000)
            for name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", name)
                page.wait_for_timeout(1200)
                measured += 1
                bad = [b for b in page.evaluate(_MEASURE) if b['id'] not in EXEMPT]
                if bad:
                    findings[name] = bad
        finally:
            page.close(); ctx.close()

        self.assertGreater(measured, 50, 'the walk visited almost no pages')
        self.assertEqual(findings, {}, 'These boxes render past the ~15-line cap '
                         'and neither they nor any ancestor scroll:\n' +
                         json.dumps(findings, indent=2))

    def test_the_measurement_can_actually_see_a_violation(self):
        """Positive control. Every assertion above is 'nothing was found', which
        is exactly the shape that passes when the instrument is broken — a bad
        selector, a failed login, a page that never rendered. Force a tall
        uncapped box into a live page and require the measurement to report it."""
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        try:
            page.goto(self.base + '/index.html')
            page.fill('#login-user', 'alice')
            page.fill('#login-pass', 'demo')
            page.click('#login-form button[type="submit"]')
            page.wait_for_selector('#app', state='visible', timeout=90000)
            page.wait_for_timeout(4000)
            page.evaluate("""() => {
              const p = document.querySelector('#app .page.active');
              const d = document.createElement('div');
              d.id = 'rp-probe-tall-box';
              for (let i = 0; i < 40; i++) {
                const r = document.createElement('div');
                r.style.height = '40px'; r.textContent = 'row ' + i;
                d.appendChild(r);
              }
              p.appendChild(d);
            }""")
            found = [b['id'] for b in page.evaluate(_MEASURE)]
            self.assertIn('rp-probe-tall-box', found,
                          'the measurement cannot see a 1600px 40-child box — '
                          'it would report a clean sweep no matter what shipped')
        finally:
            page.close(); ctx.close()


class TestTheExemptionsAreHonest(unittest.TestCase):
    """No browser needed — cheap checks that keep the exemption list from
    rotting into a place to hide a real box."""

    def test_every_exemption_states_a_reason(self):
        for eid, why in EXEMPT.items():
            with self.subTest(box=eid):
                self.assertGreater(len(why), 30, f'{eid} has no real reason')

    def test_every_exempt_id_still_exists(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        for eid in EXEMPT:
            with self.subTest(box=eid):
                self.assertIn(f'id="{eid}"', html,
                              f'{eid} is exempt but no longer in the markup')

    def test_the_row_threshold_matches_the_documented_rule(self):
        """The bug this file was written for: three copies of the threshold,
        all disagreeing with the ~15-line rule. One constant now, and it has to
        stay 15 or the measurement above is checking a different policy than
        the code applies."""
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('const ROW_SCROLL_THRESHOLD = 15', js)
        self.assertEqual(js.count('const SCROLL_THRESHOLD = ROW_SCROLL_THRESHOLD'), 3,
                         'a call site stopped using the shared threshold')


if __name__ == '__main__':
    unittest.main()
