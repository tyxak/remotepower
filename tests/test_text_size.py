#!/usr/bin/env python3
"""Text size: the user menu and My Account -> Appearance zoom the whole page from one variable.

The 6.3.0 "Interface size" setting (Small / Default / Large, 90 and 110 percent) sat under
Display units and was easy to miss. It is a row in the user menu now and ten steps (80 to
300 percent), and the same stored value (`rp_uiscale`) drives both controls.

CSS zoom has two side effects that make a bigger size look broken, and both are held here:

* zoom scales viewport units, so a dialog of `88vh` was taller than the window at 150
  percent and its top was cut off. Every vh / vw length in the stylesheet is divided by the
  zoom now (`calc(88vh / var(--rp-zoom, 1))`).
* getBoundingClientRect(), pointer coordinates and innerWidth are screen pixels while a
  popup's left / top are page pixels, so a menu placed from a measured rect landed `zoom`
  times too far from its anchor. Every place that does that goes through `uiRectCss`,
  `uiViewportCss` or `uiZoomRatio` (app.js measures the ratio instead of trusting the
  variable, so an engine that reports unzoomed rects is left alone).

The browser half is in test_text_size_e2e.py.
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
_HTML = _ROOT / 'server' / 'html'
_JS = _HTML / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')
_CSS = (_HTML / 'static' / 'css' / 'styles.css').read_text(encoding='utf-8')
_INDEX = (_HTML / 'index.html').read_text(encoding='utf-8')
_APP = (_JS / 'app.js').read_text(encoding='utf-8')

_COMMENT = re.compile(r'/\*.*?\*/', re.S)
_VIEWPORT_LENGTH = re.compile(r'(?<![\w.-])(\d+(?:\.\d+)?)(vh|vw|dvh|dvw|svh|svw|lvh|lvw|vmin|vmax)\b')
_WRAPPED_TAIL = re.compile(r'\s*/\s*var\(--rp-zoom,\s*1\)')


def viewport_lengths(css):
    """(wrapped, bare): the vh / vw lengths of a stylesheet that are divided by the zoom, and the ones that are not."""
    wrapped, bare = [], []
    for seg in _COMMENT.split(css):
        for m in _VIEWPORT_LENGTH.finditer(seg):
            (wrapped if _WRAPPED_TAIL.match(seg, m.end()) else bare).append(m.group(0))
    return wrapped, bare


# A pixel placement: left / top set from a number. A percentage, '0px' and a bare '0' are not measured from anything.
_PLACE = re.compile(r'\.style\.(?:left|top)\s*=\s*(?P<rhs>[^;\n]+)')
_ZOOM_HELPERS = ('uiRectCss', 'uiViewportCss', 'uiZoomRatio')


def unzoomed_placements(src, window=45):
    """Pixel placements of left / top with no zoom helper in the `window` lines above them."""
    lines = src.split('\n')
    out = []
    for i, line in enumerate(lines):
        m = _PLACE.search(line)
        if not m:
            continue
        rhs = m.group('rhs').strip()
        if re.fullmatch(r"'0(px)?'", rhs) or "'%'" in rhs:
            continue
        if not any(h in '\n'.join(lines[max(0, i - window):i + 1]) for h in _ZOOM_HELPERS):
            out.append((i + 1, line.strip()[:100]))
    return out


class TestViewportUnitsAreDividedByTheZoom(unittest.TestCase):

    def test_the_root_is_zoomed_from_one_variable_and_paper_is_not(self):
        self.assertIn('html { zoom: var(--rp-zoom, 1); }', _CSS)
        self.assertRegex(_CSS, r'@media print \{ html \{ zoom: 1 !important; \} \}')

    def test_no_viewport_length_is_left_bare(self):
        wrapped, bare = viewport_lengths(_CSS)
        self.assertEqual(bare, [], 'a vh/vw length that is not divided by the zoom is taller or wider than the window '
                                  'at any size above 100 percent: write it as calc(Nvh / var(--rp-zoom, 1))')
        # control: the scan must be looking at something (it found 67 when the stylesheet was converted)
        self.assertGreater(len(wrapped), 50)

    def test_the_scan_fails_on_a_bare_length_and_passes_a_wrapped_one(self):
        self.assertEqual(viewport_lengths('.a { max-height: 90vh; }')[1], ['90vh'])
        self.assertEqual(viewport_lengths('.a { width: min(960px, 94vw); }')[1], ['94vw'])
        self.assertEqual(viewport_lengths('.a { max-height: calc(90vh / var(--rp-zoom, 1)); }'), (['90vh'], []))
        self.assertEqual(viewport_lengths('/* a 90vh comment */ .a { top: 0; }'), ([], []))


class TestPopupsArePlacedInPagePixels(unittest.TestCase):

    def test_every_pixel_placement_uses_a_zoom_helper(self):
        found = 0
        for f in sorted(_JS.glob('*.js')):
            if f.name == 'i18n.js':
                continue
            src = f.read_text(encoding='utf-8')
            found += len([1 for line in src.split('\n') if _PLACE.search(line)])
            self.assertEqual(unzoomed_placements(src), [],
                             f'{f.name}: left/top set from a measured rect or the pointer without uiRectCss / '
                             'uiViewportCss / uiZoomRatio lands zoom times too far from its anchor')
        # control: the scan saw the placements (14 assignment lines when this was written, 7 of them popups)
        self.assertGreater(found, 10)

    def test_the_scan_fails_when_a_helper_is_taken_out(self):
        src = (_JS / 'app.js').read_text(encoding='utf-8')
        mutated = src.replace('uiRectCss(', 'plainRect(').replace('uiViewportCss(', 'plainViewport(').replace('uiZoomRatio(', 'plainRatio(')
        self.assertNotEqual(mutated, src)
        self.assertGreater(len(unzoomed_placements(mutated)), 5)


_FUNCTIONS = ('_uiScaleChosen', '_uiScaleMax', '_uiScaleShown', '_paintUiScaleControls', 'applyUiScale', 'setUiScale', 'uiScaleStep')
_CONSTANTS = re.compile(r'^const (?:UI_SCALE_PRESETS|UI_SCALE_MIN_PAGE_WIDTH|UI_SCALE_MIN_NARROW_PAGE_WIDTH|UI_NARROW_LAYOUT_MAX_WIDTH) = .*;$', re.M)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheSizeLogic(unittest.TestCase):
    """The real functions of app.js, run under node with a stubbed window and storage."""

    @classmethod
    def setUpClass(cls):
        consts = _CONSTANTS.findall(_APP)
        assert len(consts) == 4, consts
        bodies = '\n'.join(srcpin.js_function(_APP, name) for name in _FUNCTIONS)
        cls.script = '\n'.join(consts) + '\nlet _uiZoomCache = null;\n' + bodies

    def _run(self, cases):
        """cases: [(stored, width, [steps])] -> [{shown, var, zoomAfterSteps}]"""
        driver = r"""
const CASES = %s;
const out = [];
for (const [stored, width, steps] of CASES) {
  const store = {}; if (stored !== null) store.rp_uiscale = stored;
  const vars = {};
  globalThis.window = { innerWidth: width };
  globalThis.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
  globalThis.document = { documentElement: { style: { setProperty: (k, v) => { vars[k] = v; }, removeProperty: k => { delete vars[k]; } } },
                          getElementById: () => null };
  const seen = [_uiScaleShown()];
  applyUiScale();
  const first = vars['--rp-zoom'] === undefined ? null : vars['--rp-zoom'];
  for (const s of steps) { uiScaleStep(s); seen.push(_uiScaleShown()); }
  out.push({ shown: seen[0], first, seen, stored: store.rp_uiscale === undefined ? null : store.rp_uiscale,
             zoomVar: vars['--rp-zoom'] === undefined ? null : vars['--rp-zoom'] });
}
console.log(JSON.stringify(out));
""" % json.dumps(cases)
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'run.js'
            p.write_text(self.script + '\n' + driver)
            r = subprocess.run([str(_NODE), str(p)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_a_stored_choice_is_held_to_what_the_window_can_show(self):
        widths = (390, 768, 1000, 1280, 1440, 1920, 2560, 3840)
        got = self._run([['300', w, []] for w in widths])
        # 720 page pixels for the desktop layout, 340 for the narrow one (at or below 720 wide)
        self.assertEqual([c['shown'] for c in got], [110, 100, 125, 175, 200, 250, 300, 300])

    def test_what_6_3_0_wrote_still_means_what_it_meant(self):
        got = self._run([['s', 1440, []], ['l', 1440, []], ['m', 1440, []], ['l', 768, []]])
        self.assertEqual([c['shown'] for c in got], [90, 110, 100, 100])   # a 768 tablet cannot spare the 110

    def test_a_value_that_is_not_a_step_is_the_default(self):
        got = self._run([[None, 1440, []], ['garbage', 1440, []], ['85', 1440, []], ['', 1440, []], ['9999', 1440, []]])
        self.assertEqual([c['shown'] for c in got], [100] * 5)

    def test_the_variable_is_removed_at_100_and_set_otherwise(self):
        got = self._run([[None, 1440, []], ['125', 1440, []], ['80', 1440, []]])
        self.assertEqual([c['first'] for c in got], [None, '1.25', '0.8'])

    def test_larger_and_smaller_walk_the_steps_and_stop_at_the_ends(self):
        got = self._run([[None, 1440, [1] * 7], [None, 1440, [-1] * 4], ['300', 3840, [1]], [None, 390, [1, 1]]])
        self.assertEqual(got[0]['seen'], [100, 110, 125, 150, 175, 200, 200, 200])   # 1440 wide shows 200 at most
        self.assertEqual(got[1]['seen'], [100, 90, 80, 80, 80])
        self.assertEqual(got[2]['seen'], [300, 300])                                  # nothing above 300
        self.assertEqual(got[3]['seen'], [100, 110, 110])                             # a phone gets one step
        self.assertEqual(got[0]['stored'], '200')

    def test_a_step_stores_the_new_size_for_next_time(self):
        got = self._run([[None, 1440, [1, 1]], ['150', 1440, [-1]]])
        self.assertEqual([c['stored'] for c in got], ['125', '125'])


class TestTheControls(unittest.TestCase):

    def test_the_user_menu_has_the_row(self):
        dd = _INDEX[_INDEX.index('id="acct-dropdown"'):]
        dd = dd[:dd.index('</nav>')]
        self.assertIn('id="acct-textsize-down"', dd)
        self.assertIn('id="acct-textsize-up"', dd)
        self.assertIn('id="acct-textsize-val"', dd)
        self.assertRegex(dd, r'id="acct-textsize-down"[^>]*data-action="uiScaleStep"[^>]*data-arg="-1"|data-action="uiScaleStep"[^>]*data-arg="-1"[^>]*id="acct-textsize-down"')
        for label in ('aria-label="Smaller text"', 'aria-label="Larger text"'):
            self.assertIn(label, dd)

    def test_my_account_has_the_steps_under_appearance_and_the_old_select_is_gone(self):
        self.assertIn('id="cfg-ui-scale"', _INDEX)
        self.assertNotIn('<select id="cfg-ui-scale"', _INDEX)
        appearance = _INDEX[_INDEX.index('<div class="section-title">Appearance</div>'):]
        self.assertLess(appearance.index('id="cfg-ui-scale"'), appearance.index('Display units'))

    def test_the_steps_are_the_ones_the_script_offers(self):
        m = re.search(r'const UI_SCALE_PRESETS = \[([^\]]*)\]', _APP)
        assert m is not None
        self.assertEqual([int(x) for x in m.group(1).split(',')], [80, 90, 100, 110, 125, 150, 175, 200, 250, 300])

    def test_every_new_string_has_all_six_languages(self):
        i18n = (_JS / 'i18n.js').read_text(encoding='utf-8')
        for key in ('Text size', 'Smaller text', 'Larger text',
                    'Makes everything on the page larger or smaller, buttons and tables included. It applies to this browser only. '
                    'A narrow window limits the largest sizes so the layout stays usable.'):
            m = re.search(r'^    ' + re.escape(json.dumps(key, ensure_ascii=False)) + r': \{(.*)\},?$', i18n, re.M)
            assert m is not None, key
            for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr'):
                self.assertRegex(m.group(1), r'"%s": "[^"]+"' % lang, f'{key!r} in {lang}')


if __name__ == '__main__':
    unittest.main()
