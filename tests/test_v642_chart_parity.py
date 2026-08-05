"""v6.4.2 — the chart an operator opens during an incident gets the interaction.

`renderTimeSeries(elId, series, opts)` is a real chart component: multi-series,
y-axis units, legend, a hover crosshair with a value tooltip, drag-to-zoom,
double-click reset, and an exact from/to entry bar with Apply/Reset. It had
five call sites — three Trends charts and thermal.

Every other chart rendered a static `<svg class="metric-svg">` with no pointer
interaction at all. Including the device Metrics modal (Devices → a host →
Metrics), which is *the* chart an operator opens during an incident:
`_metricSeriesChart` emitted a fixed `role="img"` SVG whose only numbers were a
header line reading `now 91.4% · min 3 · avg 22 · max 97`.

So to answer "what was CPU at 02:40, when the alert fired?" the operator could
hover the Trends chart and read the value — but on the per-host chart they
could only eyeball a pixel against a gridline. And the 30d/90d ranges compress
days into a few pixels with no way to zoom in. Two charts in the same product,
one page apart, behaving completely differently.

Not converted, deliberately: `_renderForecastChart` plots observed points, a
fitted trend line, a wash over the projected region and a fill-date marker.
Reshaping it into a generic multi-series history chart would strip the
projection semantics that make it a forecast rather than a chart of the past.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js" / "app.js"


def _fn(js, name, kw="function"):
    i = js.index(f"{kw} {name}(")
    return js[i:js.index("\n}\n", i)]


class TestTheMetricsModalDelegates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()

    def test_the_bespoke_renderers_are_gone(self):
        for dead in ("_metricSeriesChart", "_metricsOverlayChart"):
            with self.subTest(fn=dead):
                self.assertNotIn(dead, self.js)

    def test_the_charts_go_through_the_shared_component(self):
        body = _fn(self.js, "_paintMetricCharts")
        self.assertIn("renderTimeSeries(", body)

    def test_they_get_the_crosshair_and_the_zoom(self):
        """The two things the operator could not do: read a value at a point in
        time, and zoom into a 30d/90d range."""
        body = _fn(self.js, "_paintMetricCharts")
        self.assertIn("zoom: true", body)
        self.assertIn("crosshair: true", body)

    def test_the_axis_stays_a_percentage_scale(self):
        """A CPU chart auto-scaled to its own max makes a flat 4% line look
        like a spike."""
        body = _fn(self.js, "_paintMetricCharts")
        self.assertIn("yMin: 0", body)
        self.assertIn("yMax: 100", body)
        self.assertIn("yUnit: '%'", body)

    def test_the_charts_are_painted_after_the_container_is_in_the_dom(self):
        """renderTimeSeries takes an element ID and attaches pointer handlers,
        so a call before the innerHTML assignment finds nothing and silently
        renders no chart at all."""
        body = _fn(self.js, "_loadMetrics", kw="async function")
        self.assertLess(body.index("body.innerHTML ="),
                        body.index("_paintMetricCharts(metrics)"))

    def test_the_stats_header_survives(self):
        """`now / min / avg / max` is the one thing the old chart did give, and
        losing it to gain a crosshair would be a trade, not a fix."""
        body = _fn(self.js, "_metricChartShell")
        for w in ("now", "min", "avg", "max"):
            with self.subTest(stat=w):
                self.assertIn(w, body)

    def test_an_empty_series_still_says_no_data(self):
        body = _fn(self.js, "_metricChartShell")
        self.assertIn("no data", body)

    def test_the_overlay_still_needs_two_series(self):
        """One series overlaid on itself is just the single chart again."""
        body = _fn(self.js, "_metricsOverlayShell")
        self.assertIn("present.length < 2", body)

    def test_the_hint_tells_the_operator_the_interaction_exists(self):
        """A crosshair nobody knows about is a crosshair nobody uses."""
        body = _fn(self.js, "_loadMetrics", kw="async function")
        self.assertIn("drag across the chart to zoom", body)


class TestColoursSurvivedTheMove(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()

    def test_a_series_may_carry_its_own_colour(self):
        """The device charts have always drawn CPU/mem/disk/swap in a fixed
        palette; moving them onto the shared component must not silently
        recolour them to the generic sequence."""
        body = _fn(self.js, "renderTimeSeries")
        self.assertIn("s.color || _CHART_COLORS[i % _CHART_COLORS.length]", body)

    def test_the_legend_and_tooltip_use_it_too(self):
        body = _fn(self.js, "renderTimeSeries")
        self.assertEqual(
            body.count("s.color || _CHART_COLORS[i % _CHART_COLORS.length]"), 3,
            "line, legend swatch and tooltip dot must all agree")

    def test_the_metric_series_pass_theirs(self):
        body = _fn(self.js, "_paintMetricCharts")
        self.assertEqual(body.count("color: s.color"), 2)

    def test_a_series_without_a_colour_still_works(self):
        """Every existing caller passes none."""
        for call in ("trend-health", "trend-compliance"):
            with self.subTest(chart=call):
                i = self.js.index(f"renderTimeSeries('{call}'")
                self.assertNotIn("color:", self.js[i:i + 260])


class TestAnnotationsMovedToTheComponent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()

    def test_the_old_annotation_renderer_is_gone(self):
        self.assertNotIn("_mcAnnotations", self.js)

    def test_the_component_draws_them(self):
        body = _fn(self.js, "renderTimeSeries")
        self.assertIn("opts.annotations", body)
        self.assertIn("_TS_ANNO_COLOR", body)

    def test_the_metrics_modal_still_passes_them(self):
        """"Why did it change THERE?" is answered by a reboot / command / drift
        marker on the axis. Losing them in the move would be a regression the
        crosshair does not make up for."""
        body = _fn(self.js, "_paintMetricCharts")
        self.assertIn("annotations: _metricAnnotations", body)

    def test_every_kind_kept_its_colour(self):
        i = self.js.index("const _TS_ANNO_COLOR = {")
        block = self.js[i:self.js.index("};", i)]
        for kind in ("reboot", "command", "drift", "oom"):
            with self.subTest(kind=kind):
                self.assertIn(kind + ":", block)

    def test_an_out_of_window_annotation_is_skipped(self):
        """Zoomed in, a marker for an event outside the window would be drawn
        at the plot edge and read as happening at that moment."""
        body = _fn(self.js, "renderTimeSeries")
        self.assertIn("a.ts < minX || a.ts > maxX", body)

    def test_the_label_is_escaped(self):
        body = _fn(self.js, "renderTimeSeries")
        i = body.index("opts.annotations")
        self.assertIn("escHtml(a.label", body[i:i + 1200])


class TestTheDeadHelpersWentWithIt(unittest.TestCase):
    """The bespoke chart's private helpers had no other caller. Removed one
    exact-text edit at a time with `node --check` after each — brace-counting
    through template literals is how ~300 lines of live code got eaten once."""

    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()

    def test_they_are_gone(self):
        for dead in ("_mcX", "_mcY", "_mcLine", "_mcGrid", "_MC_ANNO_COLOR"):
            with self.subTest(fn=dead):
                self.assertNotRegex(self.js, rf"\b{dead}\b")

    def test_the_geometry_constant_went_too(self):
        self.assertNotRegex(self.js, r"\b_MC\b")

    def test_the_helpers_that_are_still_used_stayed(self):
        """_metricPts and _METRIC_SERIES feed the new path; deleting them with
        the rest would have been the classic over-reach."""
        for live in ("_metricPts", "_METRIC_SERIES", "_metricAnnotations"):
            with self.subTest(fn=live):
                self.assertGreater(len(re.findall(rf"\b{live}\b", self.js)), 1)


class TestTheForecastChartIsDeliberatelyUntouched(unittest.TestCase):
    """Stated rather than silently skipped: it plots a fitted projection with a
    wash over the unobserved region and a fill-date marker. Reshaping it into a
    generic multi-series history chart would strip exactly what makes it a
    forecast."""

    @classmethod
    def setUpClass(cls):
        if not _JS.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = _JS.read_text()

    def test_it_still_draws_its_projection(self):
        body = _fn(self.js, "_renderForecastChart")
        self.assertIn("fill_date_ts", body)
        self.assertIn("intercept", body)


if __name__ == "__main__":
    unittest.main()
