#!/usr/bin/env python3
"""Six panels grew one section per item with no outer cap.

Each of them reads as capped in source, because the thing INSIDE every section
is capped: a 340px rule list, a 360px table wrap, a scroll-cap-sm evidence list.
It is the outer accumulator that had nothing, so the height is (number of items)
x (capped section) and grows without limit.

Worst cases taken from the producers rather than guessed:

  #fail2ban-detail    the agent sends up to 50 jails x 200 banned IPs; an
                      ordinary internet-facing box with 10 jails is ~3,700px
  #firewall-detail    one section per present backend
  #adv-findings       groups by finding id, and application findings use the
                      SCANNER's rule id, so a nuclei/nikto-scanned fleet yields
                      50-200 distinct ids
  #sla-targets-editor one row per group + tag + DEVICE target, Save at the end
  #wp-login-panels    one card per configured instance; 20 sites is ~9,000px
  #dns-block-panels   same shape

All six are behind a click or start hidden, which is why
test_v643_box_overflow_rendered never saw them: it calls showPage(name) and
never presses a button.

This gate does not boot the stack. It loads the real stylesheet, fills each
panel with its worst case and measures — which is what the fault needs (every
CSS rule involved is individually correct) without adding minutes to every gate
run. The filenames carry no 'e2e', so this runs in make test-fast too; keeping
it to one page load is what makes that acceptable.
"""
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import browser_required                                  # noqa: E402

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'
_HTML = _ROOT / 'server' / 'html' / 'index.html'

try:
    from playwright.sync_api import sync_playwright
    _PW = True
except ImportError:                                      # pragma: no cover
    _PW = False


def _browser_available():
    if not _PW:
        return False
    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


def _rows(n, inner):
    return ''.join(inner.format(i=i) for i in range(n))


# id -> (worst-case content, what produces that many)
PANELS = {
    'fail2ban-detail': (
        _rows(10, '<div class="section-title">jail{i}</div>'
                  '<div class="scroll-cap mt-8 fw-rules">'
                  + ''.join(f'<div>10.0.0.{k}</div>' for k in range(200))
                  + '</div>'),
        '10 jails x 200 banned IPs'),
    'firewall-detail': (
        _rows(5, '<div class="section-title">backend{i}</div>'
                 '<div class="scroll-cap mt-8 fw-rules">'
                 + ''.join(f'<div>rule {k}</div>' for k in range(200))
                 + '</div>'),
        '5 firewall backends x 200 rules'),
    'adv-findings': (
        _rows(80, '<div class="dash-card"><div class="section-title">'
                  'app.nuclei.rule{i}</div>'
                  '<ul class="scroll-cap-sm"><li>evidence</li></ul></div>'),
        '80 distinct scanner rule ids'),
    'sla-targets-editor': (
        _rows(100, '<div class="sla-tgt-row"><select><option>g{i}</option>'
                   '</select><input><input></div>'),
        '100 per-device SLA targets'),
    'wp-login-panels': (
        _rows(20, '<div class="dash-card"><div class="section-title">site{i}'
                  '</div><div class="scrollable-table-wrap audit-scroll">'
                  '<table><tbody>'
                  + ''.join('<tr><td>row</td></tr>' for _ in range(30))
                  + '</tbody></table></div></div>'),
        '20 WordPress instances'),
    'dns-block-panels': (
        _rows(20, '<div class="dash-card"><div class="section-title">'
                  'blocker{i}</div></div>'),
        '20 DNS blockers'),
}

_VIEWPORT_H = 900
# 70vh of a 900px viewport, with a little slack for a fractional layout.
_CEILING = int(_VIEWPORT_H * 0.70) + 4


# RP_BROWSER_REQUIRE turns "no browser here" from a silent pass into a
# failure. It has to be folded into the CLASS condition: a class-level
# skipUnless never reaches setUpClass, so skip_or_fail alone could not see
# a missing browser at all. The probe launches a browser, so cache it.
_OK = _browser_available()


@unittest.skipUnless(_OK or browser_required.required(),
                     'no Chromium available')
class TestEveryAccumulatorCapsAndScrolls(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _OK:
            browser_required.skip_or_fail('no Chromium available')
        body = ''.join(f'<div id="{k}">{v[0]}</div>' for k, v in PANELS.items())
        page = ('<!doctype html><html><head><style>__CSS__</style></head>'
                '<body><div id="app"><div class="container">'
                + body + '</div></div>'
                # A control element with no cap, so the measurement below is
                # shown to be capable of reporting an uncapped panel.
                '<div id="uncapped-control">' + PANELS['adv-findings'][0]
                + '</div></body></html>').replace('__CSS__', _CSS.read_text())
        cls._pw = sync_playwright().start()
        cls._b = cls._pw.chromium.launch()
        cls.page = cls._b.new_page()
        cls.page.set_viewport_size({'width': 1280, 'height': _VIEWPORT_H})
        cls.page.set_content(page)

    @classmethod
    def tearDownClass(cls):
        cls._b.close()
        cls._pw.stop()

    def _measure(self, el_id):
        return self.page.evaluate("""(id)=>{
            const e = document.getElementById(id);
            if (!e) return null;
            return {h: e.getBoundingClientRect().height,
                    content: e.scrollHeight,
                    overflow: getComputedStyle(e).overflowY,
                    scrolls: e.scrollHeight > e.clientHeight + 1};
        }""", el_id)

    def test_the_measurement_can_report_an_uncapped_panel(self):
        """Positive control. Without it, a stylesheet that failed to load makes
        every panel measure zero and the whole class passes."""
        m = self._measure('uncapped-control')
        self.assertIsNotNone(m)
        self.assertGreater(m['h'], _CEILING,
                           'the control is capped — either the stylesheet did '
                           'not load or a rule now catches everything')

    def test_each_panel_is_capped(self):
        for el_id, (_, why) in PANELS.items():
            with self.subTest(panel=el_id):
                m = self._measure(el_id)
                self.assertIsNotNone(m, f'#{el_id} is gone from the page')
                self.assertLessEqual(
                    m['h'], _CEILING,
                    f'#{el_id} grows unbounded with {why} — '
                    f'{int(m["h"])}px rendered')

    def test_a_capped_panel_can_still_reach_its_content(self):
        """A cap that clips without scrolling hides rows entirely, which is
        worse than a long page."""
        for el_id, (_, why) in PANELS.items():
            with self.subTest(panel=el_id):
                m = self._measure(el_id)
                if m['content'] <= m['h'] + 1:
                    continue          # fits; nothing to scroll
                self.assertIn(m['overflow'], ('auto', 'scroll'),
                              f'#{el_id} clips {why} with no way to scroll')

    def test_no_panel_nests_two_scrollers(self):
        """A 340px scroller inside a 70vh one puts two scrollbars on one panel
        and the inner one swallows the wheel."""
        for el_id in ('fail2ban-detail', 'firewall-detail'):
            with self.subTest(panel=el_id):
                inner = self.page.evaluate("""(id)=>{
                    const e = document.getElementById(id);
                    return [...e.querySelectorAll('*')].filter(c => {
                        const s = getComputedStyle(c);
                        return (s.overflowY === 'auto' || s.overflowY === 'scroll')
                               && c.scrollHeight > c.clientHeight + 1
                               && c.clientHeight > 200;
                    }).length;
                }""", el_id)
                self.assertEqual(0, inner,
                                 f'#{el_id} still nests a tall inner scroller')


class TestTheRuleIsInTheStylesheet(unittest.TestCase):
    """Source backstop that cannot skip, so a browserless run still catches a
    deletion."""

    def test_every_panel_has_a_cap_rule(self):
        css = re.sub(r'/\*.*?\*/', '', _CSS.read_text(), flags=re.S)
        for el_id in PANELS:
            self.assertRegex(
                css, re.compile(r'#' + re.escape(el_id) + r'\b[^{]*\{[^}]*max-height',
                                re.S),
                f'#{el_id} has no max-height rule')

    def test_every_panel_still_exists_in_the_markup(self):
        """A cap for an id that no longer exists is not protection; it is dead
        CSS that reads like protection."""
        html = _HTML.read_text()
        for el_id in PANELS:
            self.assertIn(f'id="{el_id}"', html)


if __name__ == '__main__':
    unittest.main()
