"""The Thermal page charts any sensor of a host, and the Disk chart fits its axis.

The page's own functions are run under node, because what matters is what they do with the values the page
hands them (a numeric-looking host id, a label that holds markup, a 2-year range chosen for the hottest reading
and carried over to a sensor). The server side is held by test_thermal_sensor_history, and the rendered page by
test_thermal_sensor_e2e. Self-skips without node.
"""
import json
import random
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
POWER = (ROOT / "server/html/static/js/app-power.js").read_text()
APP = (ROOT / "server/html/static/js/app.js").read_text()
NODE = shutil.which("node")

STUBS = """
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const escAttr = escHtml;
let renders = 0;
function _renderThermal() { renders++; }
"""


def const_block(src, name):
    """`const NAME = ...;` as written: through `];` that closes an array literal, or the first `;` that ends a
    line (a trailing comment may follow it)."""
    m = re.search(r"^const %s = .*?(?:\n\];|;[ \t]*(?://[^\n]*)?$)" % re.escape(name), src, re.S | re.M)
    if not m:
        raise AssertionError(f"const not found: {name}")
    return m.group(0)


def page(body):
    """Run `body` (JavaScript that `return`s a value) against the page's own thermal functions."""
    if NODE is None:
        raise unittest.SkipTest("node is not installed")
    parts = [STUBS]
    parts += [const_block(POWER, n) for n in ("_THERMAL_RANGES", "_thermalRange", "_thermalSensor", "_THERMAL_SENSOR_RANGES")]
    parts += [srcpin.js_function(POWER, n) for n in ("_thermalRangeDef", "_thermalRangeFor", "_thermalCacheKey", "_thermalChartHead",
                                                     "_thermalTimelineInner", "thermalPickSensor")]
    script = "\n".join(parts) + "\nconst result = (() => {\n" + body + "\n})();\nconsole.log(JSON.stringify(result));\n"
    done = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise AssertionError(done.stderr)
    return json.loads(done.stdout)


class TestChoosingASensor(unittest.TestCase):

    def test_a_sensor_starts_on_its_24_hour_ring(self):
        got = page("thermalPickSensor('th-d1', 'sensor|Core 0'); const r = _thermalRangeFor('d1'); return [r.key, r.tier];")
        self.assertEqual(got, ["24h", "raw"])

    def test_the_hottest_reading_starts_where_it_always_did(self):
        got = page("const r = _thermalRangeFor('d1'); return [r.key, r.tier];")
        self.assertEqual(got, ["24h", "fivemin"])
        self.assertEqual(page("return _THERMAL_RANGES.map(r => [r.key, r.tier]);"),
                         [["24h", "fivemin"], ["8d", "fivemin"], ["30d", "hourly"], ["2y", "daily"]])

    def test_a_sensor_has_no_two_year_range(self):
        self.assertEqual(page("return _THERMAL_SENSOR_RANGES.map(r => [r.key, r.tier]);"),
                         [["24h", "raw"], ["8d", "hourly"], ["30d", "hourly"]])

    def test_the_two_years_chosen_for_the_hottest_reading_become_the_longest_a_sensor_has(self):
        got = page("_thermalRange.set('d1', '2y'); thermalPickSensor('th-d1', 'sensor|a'); const r = _thermalRangeFor('d1'); return [r.key, r.tier];")
        self.assertEqual(got, ["30d", "hourly"])

    def test_a_range_a_sensor_has_is_kept(self):
        got = page("_thermalRange.set('d1', '8d'); thermalPickSensor('th-d1', 'disk|/dev/sda'); return _thermalRangeFor('d1').key;")
        self.assertEqual(got, "8d")

    def test_going_back_to_the_hottest_reading_restores_the_two_year_range(self):
        got = page("_thermalRange.set('d1', '2y'); thermalPickSensor('th-d1', 'sensor|a'); thermalPickSensor('th-d1', ''); return _thermalRangeFor('d1').key;")
        self.assertEqual(got, "2y")

    def test_choosing_the_charted_sensor_again_goes_back_to_the_hottest_reading(self):
        got = page("thermalPickSensor('th-d1', 'sensor|a'); const on = _thermalSensor.has('d1'); thermalPickSensor('th-d1', 'sensor|a'); return [on, _thermalSensor.has('d1')];")
        self.assertEqual(got, [True, False])

    def test_the_empty_string_the_dispatcher_turns_into_zero_clears_it(self):
        got = page("thermalPickSensor('th-d1', 'sensor|a'); thermalPickSensor('th-d1', 0); return _thermalSensor.has('d1');")
        self.assertFalse(got)

    def test_a_key_that_is_not_a_kind_and_a_label_is_not_taken(self):
        for bad in ("Core 0", "|x", 5, None, [], {}):
            with self.subTest(bad=bad):
                got = page("thermalPickSensor('th-d1', %s); return _thermalSensor.has('d1');" % json.dumps(bad))
                self.assertFalse(got)

    def test_a_host_id_that_looks_like_a_number_stays_a_string(self):
        got = page("thermalPickSensor('th-123', 'sensor|a'); return [[..._thermalSensor.keys()], typeof [..._thermalSensor.keys()][0]];")
        self.assertEqual(got, [["123"], "string"])

    def test_two_hosts_choose_independently(self):
        got = page("thermalPickSensor('th-d1', 'sensor|a'); thermalPickSensor('th-d2', 'gpu|b'); return [_thermalSensor.get('d1'), _thermalSensor.get('d2')];")
        self.assertEqual(got, ["sensor|a", "gpu|b"])

    def test_every_choice_repaints_the_table(self):
        got = page("thermalPickSensor('th-d1', 'sensor|a'); thermalPickSensor('th-d1', ''); return renders;")
        self.assertEqual(got, 2)

    def test_the_cache_keeps_a_chart_for_each_sensor_and_tier(self):
        keys = page("""
            const hot = _thermalRangeFor('d1'); const a = _thermalCacheKey('d1', hot);
            thermalPickSensor('th-d1', 'sensor|a'); const raw = _thermalRangeFor('d1'); const b = _thermalCacheKey('d1', raw);
            _thermalRange.set('d1', '30d'); const hourly = _thermalRangeFor('d1'); const c = _thermalCacheKey('d1', hourly);
            thermalPickSensor('th-d1', 'sensor|b'); const d = _thermalCacheKey('d1', _thermalRangeFor('d1'));
            return [a, b, c, d];""")
        self.assertEqual(len(set(keys)), 4, keys)
        self.assertEqual(keys[0], "d1|fivemin|")
        self.assertEqual(keys[1], "d1|raw|sensor|a")


class TestTheHeadingAndThePicker(unittest.TestCase):

    def test_the_hottest_reading_says_so_and_offers_four_ranges(self):
        html = page("return _thermalTimelineInner('d1');")
        self.assertIn("Charting the hottest reading. Select a sensor below to chart it instead.", html)
        self.assertEqual(html.count('data-action="thermalSetRange"'), 4)
        self.assertNotIn("thermalPickSensor", html)

    def test_a_sensor_names_itself_and_offers_three_ranges_and_the_way_back(self):
        html = page("thermalPickSensor('th-d1', 'sensor|coretemp Core 0'); return _thermalTimelineInner('d1');")
        self.assertIn("<strong>coretemp Core 0</strong>", html)
        self.assertEqual(html.count('data-action="thermalSetRange"'), 3)
        self.assertNotIn('data-arg2="2y"', html)
        self.assertIn('data-action="thermalPickSensor" data-arg="th-d1" data-arg2=""', html)
        self.assertIn(">Hottest reading</button>", html)

    def test_the_selected_range_is_marked(self):
        html = page("_thermalRange.set('d1', '8d'); thermalPickSensor('th-d1', 'sensor|a'); return _thermalTimelineInner('d1');")
        self.assertRegex(html, r'metric-range-btn sel"[^>]*data-arg2="8d"[^>]*aria-pressed="true"')

    def test_a_label_that_holds_markup_is_text(self):
        evil = '<img src=x onerror=alert(1)>"\'&'
        html = page("thermalPickSensor('th-d1', %s); return _thermalTimelineInner('d1');" % json.dumps("sensor|" + evil))
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_a_host_id_that_holds_markup_cannot_break_an_attribute(self):
        html = page("thermalPickSensor('th-%s', 'sensor|a'); return _thermalTimelineInner(%s);" % ('"><script>x', json.dumps('"><script>x')))
        self.assertNotIn("<script>", html)


class TestTheTableAndTheWiring(unittest.TestCase):

    def test_every_sensor_row_has_a_chart_button_that_names_its_series(self):
        body = srcpin.js_function(POWER, "_renderThermal")
        self.assertIn('data-action="thermalPickSensor"', body)
        self.assertIn("const skey = `${s.type}|${s.label || 'sensor'}`;", body,
                      "the key is the type and the label, which is what the server builds from a report")
        self.assertIn("aria-pressed", body)
        self.assertIn("thermal-sensor-on", body)

    def test_the_button_is_for_every_reader_and_ignoring_stays_for_administrators(self):
        body = srcpin.js_function(POWER, "_renderThermal")
        self.assertIn("${chartBtn}${(canIgnore && s.type === 'sensor') ? ' ' + act : ''}", body)

    def test_the_request_carries_the_sensor_and_drops_a_chart_that_was_overtaken(self):
        body = srcpin.js_function(POWER, "_thermalLoadChart")
        self.assertIn("&sensor=${encodeURIComponent(sensor)}", body)
        self.assertIn("(_thermalSensor.get(devId) || '') !== sensor", body)

    def test_the_styles_the_page_uses_exist(self):
        css = (ROOT / "server/html/static/css/styles.css").read_text()
        for cls in ("thermal-sensor-on", "thermal-chart-on"):
            self.assertIn(cls, css)

    def test_the_new_strings_are_translated_into_the_six_languages(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for text in ("Charting", "Hottest reading", "Chart the hottest reading of this host", "Chart this sensor’s temperature history",
                     "Charting the hottest reading. Select a sensor below to chart it instead.",
                     "No history for this sensor yet. A point is added about every 15 minutes, so the 24-hour view fills first and the longer views follow once an hour.",
                     "Linux reports the root filesystem (/), Windows and macOS the fullest volume. The axis is fitted to the data."):
            with self.subTest(text=text[:40]):
                m = re.search(r"^    (['\"])%s\1: \{(.*)\},$" % re.escape(text), i18n, re.M)
                self.assertIsNotNone(m, "no dictionary entry")
                for lang in ("fr", "de", "zh", "hi", "es", "ar"):
                    self.assertRegex(m.group(2), r"\b%s: ['\"]" % lang)


class TestTheFittedAxis(unittest.TestCase):

    @staticmethod
    def axes(cases):
        if NODE is None:
            raise unittest.SkipTest("node is not installed")
        script = srcpin.js_function(APP, "_tsFitAxis") + "\nconst cases = JSON.parse(process.argv[1]);\nconsole.log(JSON.stringify(cases.map(c => _tsFitAxis(c[0], c[1]))));\n"
        done = subprocess.run([NODE, "-e", script, json.dumps(cases)], capture_output=True, text=True, timeout=30)
        if done.returncode != 0:
            raise AssertionError(done.stderr)
        return json.loads(done.stdout)

    def test_a_flat_series_gets_a_narrow_axis_around_it(self):
        self.assertEqual(self.axes([[[33.0, 33.0, 33.0], 4]]), [{"yMin": 29, "yMax": 37}])

    def test_a_slow_drift_fills_the_chart(self):
        got = self.axes([[[32.5, 33.9], 4]])[0]
        self.assertEqual((got["yMin"], got["yMax"]), (29, 37))

    def test_the_axis_is_kept_inside_zero_and_a_hundred(self):
        low, high, whole = self.axes([[[0.5, 1.0], 4], [[99.0, 100.0], 4], [[0.0, 100.0], 4]])
        self.assertEqual((low["yMin"], low["yMax"]), (0, 8))
        self.assertEqual((high["yMin"], high["yMax"]), (92, 100))
        self.assertEqual((whole["yMin"], whole["yMax"]), (0, 100))

    def test_every_axis_holds_its_values_and_labels_whole_numbers(self):
        rng = random.Random(7)
        cases = []
        for _ in range(400):
            lo = rng.uniform(0, 100)
            hi = min(100.0, lo + rng.choice([0, 0.1, 1, 5, 20, 80]) * rng.random())
            cases.append([[lo, hi], rng.choice([1, 4, 10])])
        # Ranges around the size of the smallest window (4), at every fractional position: where a window
        # that is only as wide as the padded range can miss one end of the values.
        for width in (2.9, 3.05, 3.2, 3.3, 3.5, 3.9, 4.2, 5.0, 6.5, 7.9, 8.1):
            for frac in (0.0, 0.1, 0.5, 0.9, 0.99):
                lo = 40 + frac
                cases.append([[lo, lo + width], 1])
        for (values, floor), axis in zip(cases, self.axes(cases)):
            with self.subTest(values=values, floor=floor):
                span = axis["yMax"] - axis["yMin"]
                self.assertGreaterEqual(axis["yMin"], 0)
                self.assertLessEqual(axis["yMax"], 100)
                self.assertLessEqual(axis["yMin"], min(values))
                self.assertGreaterEqual(axis["yMax"], max(values))
                self.assertEqual(span % 4, 0, "the five gridlines would not be whole numbers")
                self.assertGreaterEqual(span, min(floor, 100))
                self.assertEqual(axis["yMin"], int(axis["yMin"]))

    def test_only_the_disk_chart_asks_for_it(self):
        paint = srcpin.js_function(APP, "_paintMetricCharts")
        self.assertIn("s.key === 'disk' ? { ...opts, yMin: null, yMax: null, yFit: 4 } : opts", paint)
        self.assertEqual(paint.count("yFit"), 1)

    def test_a_chart_that_does_not_ask_keeps_its_axis(self):
        """The opt-in leaves every other chart as it was: the branch needs yFit, and the explicit bounds
        still win over it."""
        body = srcpin.js_function(APP, "renderTimeSeries")
        self.assertIn("opts.yFit > 0 && opts.yMin == null && opts.yMax == null", body)


if __name__ == "__main__":
    unittest.main()
