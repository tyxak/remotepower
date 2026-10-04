"""The topbar's controls fit a phone, so no page scrolls sideways.

The right-hand cluster of the topbar is six icon buttons (seven when quiet hours are on) at 46px
each with a 10px gap: 320-376px. On a 390px phone that is wider than the bar, so the document was
2-58px wider than the screen on every page and the whole app panned sideways. The walk at 390px
found it on 97 of 97 pages in English and German alike; nothing about it was page-specific.

Below 480px the buttons take tighter padding and the cluster a smaller gap (~250px). This loads the
real index.html and stylesheet, shows the controls that are hidden until the app has data, and
measures the bar at three phone widths.
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

_MEASURE = """() => {
  document.getElementById('app').classList.remove('d-none');
  // the quiet-hours indicator appears once a refresh finds the window active
  const q = document.getElementById('quiet-hours-ind');
  if (q) q.classList.remove('d-none');
  const hr = document.querySelector('.header-right');
  const kids = [...hr.children].filter(c => c.getBoundingClientRect().width > 0);
  return {
    vw: window.innerWidth,
    docw: document.documentElement.scrollWidth,
    right: Math.round(hr.getBoundingClientRect().right),
    visible: kids.length,
    cluster: Math.round(hr.getBoundingClientRect().width),
  };
}"""


@unittest.skipUnless(_GATE, 'playwright is not installed')
class TestTopbarFitsAPhone(unittest.TestCase):

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
        page = self._browser.new_page(viewport={'width': width, 'height': 800})
        try:
            page.goto(_INDEX.as_uri())
            page.wait_for_load_state('load')
            return page.evaluate(_MEASURE)
        finally:
            page.close()

    def test_the_cluster_is_measured_with_its_buttons_showing(self):
        """Control: if nothing were visible the width checks below would pass for the wrong reason."""
        m = self.measure(390)
        self.assertGreaterEqual(m['visible'], 6, m)
        self.assertGreater(m['cluster'], 150, m)

    def test_no_phone_width_scrolls_sideways_because_of_the_topbar(self):
        for width in (390, 375, 360):
            m = self.measure(width)
            self.assertLessEqual(m['right'], m['vw'], '%dpx: the control cluster ends at %d' % (width, m['right']))
            self.assertLessEqual(m['docw'], m['vw'], '%dpx: the document is %dpx wide' % (width, m['docw']))


if __name__ == '__main__':
    unittest.main()
