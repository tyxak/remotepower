"""v6.3.0 stat-tile eye candy — project-wide living stat tiles.

One MutationObserver drives count-up, a meaning-aware ▲/▼ delta chip, a persisted
sparkline and a state-reactive tone on every `.stat-value` in the app. These pins
guard the mechanism (so a refactor can't quietly drop it), the CSP-safe rendering
(no inline `style=` strings in innerHTML), and the tone tags on the dashboard trio
and the security/services danger tiles.
"""

import unittest
from pathlib import Path

from tests import srcpin

_ROOT = Path(__file__).parent.parent
_JS = _ROOT / "server/html/static/js"


def _app():
    return (_JS / "app.js").read_text()


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _css():
    return (_ROOT / "server/html/static/css/styles.css").read_text()


class TestStatTileModule(unittest.TestCase):
    def test_module_and_observer(self):
        app = _app()
        self.assertIn("const statTiles", app)
        self.assertIn("MutationObserver", srcpin.js_function(app, "init"))
        # init is wired to run on load
        self.assertIn("statTiles.init()", app)

    def test_count_up_self_loop_guard(self):
        # enhance must record the value and early-return when unchanged, or the
        # count-up's own textContent writes would re-trigger the observer forever.
        enhance = srcpin.js_function(_app(), "enhance")
        self.assertIn("dataset.animating", enhance)
        self.assertIn("if (prev === n) return", enhance)

    def test_meaning_aware_delta(self):
        app = _app()
        # good/bad tone flips the sign meaning of an increase
        self.assertIn("data-stat-tone", _html())
        self.assertIn("sd-good", app)
        self.assertIn("sd-bad", app)

    def test_sparkline_is_persisted(self):
        app = _app()
        self.assertIn("rp_stat_hist", app)
        self.assertIn("localStorage", srcpin.js_function(app, "enhance") + app)

    def test_no_inline_style_string_in_propbar(self):
        # CSP: widths are set via .style.width on created nodes, never a
        # style="width:…" attribute inside an innerHTML string.
        prop = srcpin.js_function(_app(), "_fleetPropBar")
        self.assertNotIn('style="', prop)
        self.assertIn(".style.width", prop)

    def test_statnav_drilldown(self):
        self.assertIn("function statNav", _app())


class TestStatTileMarkup(unittest.TestCase):
    def test_trio_clickable_and_toned(self):
        html = _html()
        self.assertIn('data-stat-tone="good"', html)  # Online
        self.assertIn('data-stat-tone="bad"', html)   # Offline
        self.assertIn('data-action="statNav" data-arg="devices"', html)
        self.assertIn('id="fleet-propbar"', html)

    def test_danger_tiles_toned(self):
        html = _html()
        # each danger tile sits in a data-stat-tone="bad" card
        for anchor in ('cve-stat-critical', 'scan-stat-critical', 'services-stat-down'):
            idx = html.index(f'id="{anchor}"')
            card_start = html.rfind('<div class="stat-card', 0, idx)
            card_open = html[card_start:idx]
            self.assertIn('data-stat-tone="bad"', card_open, anchor)


class TestStatTileCss(unittest.TestCase):
    def test_classes_present(self):
        css = _css()
        for cls in ('.stat-meta', '.stat-spark', '.stat-delta', '.stat-alert',
                    '.stat-propbar', '@keyframes stat-pulse'):
            self.assertIn(cls, css)

    def test_pulse_keyframe_is_transform_only(self):
        css = _css()
        i = css.index('@keyframes stat-pulse')
        block = css[i:css.index('}', css.index('}', i) + 1) + 1]
        # perf rule: keyframes animate transform/opacity only
        self.assertIn('transform: scale', block)
        for banned in ('width:', 'height:', 'left:', 'top:', 'margin', 'color:'):
            self.assertNotIn(banned, block)

    def test_reduced_motion_guard(self):
        css = _css()
        self.assertIn('prefers-reduced-motion', css)


if __name__ == "__main__":
    unittest.main()
