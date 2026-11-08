"""The top bar fits between a phone and a wide desktop, so no page loses its theme button off the right edge.

The controls of the bar need 733 px with the fleet readout and 825 px with its trend line and the Auto-refresh label, and the 248px sidebar leaves a 768 px window 327 px
and a 1024 px window 575 to 660. body{overflow-x:hidden} hid the overflow, so the theme and top-bar buttons were off screen, and the census of looks, themes and widths found
82 of 85 pages affected at 768 and 1024 px. This loads the real index.html and stylesheet, shows every control that is hidden until the app has data (the readout with its trend
line, quiet hours, the install button), gives the breadcrumb its longest realistic text, and measures the bar at twelve widths.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required   # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except Exception:       # pragma: no cover
    _HAVE_PLAYWRIGHT = False

_GATE = _HAVE_PLAYWRIGHT or browser_required.required()
_INDEX = Path(__file__).resolve().parent.parent / 'server' / 'html' / 'index.html'

# between the phone layout (up to 720) and the width the whole bar has always fitted (1440)
WIDTHS = (722, 768, 800, 880, 900, 1024, 1100, 1180, 1220, 1240, 1260, 1279, 1280, 1366, 1440, 1920)

_SETUP = """() => {
  document.getElementById('app').classList.remove('d-none');
  document.getElementById('quiet-hours-ind').classList.remove('d-none');
  document.getElementById('pwa-install-btn').classList.remove('isl-6');
  document.getElementById('pwa-install-btn').style.display = '';
  document.getElementById('site-health').className = 'site-health ok';
  document.getElementById('site-health').innerHTML = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 4v5c0 5-3 8-8 9-5-1-8-4-8-9V7z"/></svg>Healthy';
  document.getElementById('last-refresh-label').textContent = 'Auto-refresh \\u00b7 51s';
  document.getElementById('topbar-crumb').textContent = 'Security \\u203a Email authentication and DMARC aggregate reports';
  document.getElementById('header-vitals').innerHTML =
    '<span class="vital bad"><svg viewBox=\"0 0 24 24\" width=\"12\" height=\"12\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"6\"/></svg><b>15</b> offline</span><span class="vitals-sep"></span><span class="vital bad"><svg viewBox=\"0 0 24 24\" width=\"12\" height=\"12\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"6\"/></svg><b>51</b> alerts</span><span class="vitals-sep"></span>'
    + '<span class="vital bad"><svg viewBox=\"0 0 24 24\" width=\"12\" height=\"12\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"6\"/></svg><b>11</b> down</span><span class="vitals-sep"></span><canvas id="fleet-pulse" width="64" height="16"></canvas>';
}"""

_MEASURE = """() => {
  const vw = document.documentElement.clientWidth;
  const hr = document.querySelector('.header-right');
  const vis = c => c.getBoundingClientRect().width > 0 && getComputedStyle(c).display !== 'none';
  const past = [...hr.children].filter(vis).filter(c => c.getBoundingClientRect().right > vw + 0.5).map(c => c.id || c.className);
  return {vw, docw: document.documentElement.scrollWidth, right: Math.round(hr.getBoundingClientRect().right),
          theme: Math.round(document.querySelector('.theme-btn').getBoundingClientRect().right),
          banner: Math.round(document.querySelector('.banner-toggle').getBoundingClientRect().right), past,
          shown: [...hr.children].filter(vis).map(c => c.id || c.className.split(' ')[0])};
}"""


@unittest.skipUnless(_GATE, 'playwright is not installed')
class TestTopbarFitsATablet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _HAVE_PLAYWRIGHT:
            browser_required.skip_or_fail('playwright is not installed')
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:                    # pragma: no cover
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def measure(self, width):
        ctx = self._browser.new_context(viewport={'width': width, 'height': 800})
        page = ctx.new_page()
        try:
            page.goto(_INDEX.as_uri())
            page.evaluate(_SETUP)
            page.wait_for_timeout(150)
            return page.evaluate(_MEASURE)
        finally:
            ctx.close()

    def test_no_control_is_past_the_right_edge_at_any_width(self):
        bad = {}
        for w in WIDTHS:
            m = self.measure(w)
            if m['past'] or m['docw'] > m['vw'] or m['theme'] > m['vw'] or m['banner'] > m['vw']:
                bad[w] = m
        self.assertEqual(bad, {}, 'the bar runs off the right edge at these widths: %r' % bad)

    def test_the_theme_and_top_bar_buttons_are_always_shown(self):
        for w in WIDTHS:
            shown = self.measure(w)['shown']
            self.assertIn('theme-btn', shown, w)
            self.assertIn('btn-icon', ' '.join(shown), w)

    def test_a_wide_bar_keeps_the_readout_and_its_trend_line(self):
        m = self.measure(1440)
        self.assertIn('header-vitals', m['shown'], 'control: at 1440 nothing has given way')
        self.assertIn('status-bar', m['shown'], 'the Auto-refresh label is there at 1440')
        self.assertIn('topbar-undo', m['shown'])

    def test_a_narrow_bar_gives_up_the_least_useful_controls_first(self):
        narrow = self.measure(800)['shown']
        self.assertNotIn('header-vitals', narrow)
        self.assertNotIn('status-bar', narrow, 'the Auto-refresh label is the first thing to go')
        self.assertNotIn('status-bar', self.measure(1280)['shown'])
        self.assertNotIn('topbar-undo', narrow)
        self.assertIn('toast-history-btn', narrow, 'the notification centre stays')
        mid = self.measure(1100)['shown']
        self.assertNotIn('header-vitals', mid)
        self.assertIn('topbar-undo', mid, 'undo and redo are given up only on a narrow bar')


if __name__ == '__main__':
    unittest.main()
