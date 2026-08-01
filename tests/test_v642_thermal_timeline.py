"""Long-range thermal history, and time-pinpointing on the shared chart.

The Thermal page could only ever show about a day: `THERMAL_HIST_FILE` keeps a
flat 288-sample buffer per host at the ~5-minute hardware cadence, and nothing
older. Metrics have folded into hourly/daily roll-ups since W4-10, which is why
the Trends page has a range picker and Thermal had a 110x20 sparkline headed
"Trend (~24h)".

Thermal now folds through the same machinery, and the shared axis-chart helper
gained time-pinpointing — drag to select a window, exact from/to entry, reset —
so the Trends charts get it in the same change.
"""

import ast
import importlib.util
import math
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
_CSS = ROOT / "server" / "html" / "static" / "css"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-therm-"))

_spec = importlib.util.spec_from_file_location("api_v642_therm", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules["api_v642_therm"] = api
_spec.loader.exec_module(api)


def _js_function(src, name):
    m = re.search(r"\nfunction %s\s*\([^)]*\)\s*\{" % re.escape(name), src)
    if not m:
        raise AssertionError(f"js function not found: {name}")
    i = m.start() + 1
    k = src.index("{", i)
    depth = 0
    while True:
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return src[i:k + 1]


class _RollupBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-therm-run-"))
        self._files = {}
        for attr in ("DEVICES_FILE", "THERMAL_HIST_FILE", "THERMAL_ROLLUP_FILE",
                     "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(str(getattr(api, attr))).name)
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {"d1": {"name": "jaove", "last_seen": self.now}})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def _seed(self, days=10):
        """A diurnal temperature curve at the real 5-minute hardware cadence."""
        pts = []
        for i in range(days * 24 * 12):
            ts = self.now - i * 300
            pts.append({"ts": ts, "temp": round(45 + 6 * math.sin(ts / 86400 * 6.283), 1)})
        api.save(api.THERMAL_HIST_FILE, {"d1": {"samples": list(reversed(pts))}})
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        return pts


class TestThermalRollsUpBeyondADay(_RollupBase):

    def test_ten_days_of_samples_reach_every_tier(self):
        self._seed(days=10)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        for tier in ("fivemin", "hourly", "daily"):
            with self.subTest(tier=tier):
                self.assertTrue(rec.get(tier), f"{tier} tier is empty")
        span = lambda t: (rec[t][-1]["ts"] - rec[t][0]["ts"]) / 86400
        self.assertGreater(span("hourly"), 1.0,
                           "the whole point is history older than the 24h buffer")

    def test_the_bucket_carries_min_avg_max(self):
        self._seed(days=3)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        # The shaper is generalised over its keys (one shaper, two roll-ups),
        # so a thermal read passes the thermal key set — calling it bare
        # returns {ts} only, which is what my first draft asserted against.
        pts = api._rollup_read_shape(rec.get("hourly") or [],
                                     api._THERMAL_ROLLUP_KEYS)
        self.assertTrue(pts)
        p = pts[0]
        self.assertEqual(set(p), {"ts", "temp"})
        self.assertGreaterEqual(set(p["temp"]), {"min", "avg", "max"})
        self.assertLessEqual(p["temp"]["min"], p["temp"]["avg"])
        self.assertLessEqual(p["temp"]["avg"], p["temp"]["max"])

    def test_the_five_minute_tier_is_pruned_to_its_window(self):
        """It is the incident-zoom band, not an archive — unbounded growth here
        is what the tiering exists to avoid."""
        self._seed(days=10)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        pts = rec.get("fivemin") or []
        self.assertTrue(pts)
        span_days = (pts[-1]["ts"] - pts[0]["ts"]) / 86400
        self.assertLessEqual(span_days, api.ROLLUP_5MIN_KEEP / 86400 + 0.1)

    def test_folding_twice_does_not_double_count(self):
        """The sweep runs on a cadence; it must be idempotent over samples it
        has already folded."""
        self._seed(days=2)
        api.run_thermal_rollup_if_due()
        first = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        before = [dict(b) for b in (first.get("hourly") or [])]
        meta = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "_meta", {}) or {}
        meta["last_run"] = 0                      # force it due again
        with api._LockedUpdate(api.THERMAL_ROLLUP_FILE) as st:
            st["_meta"] = meta
        api.run_thermal_rollup_if_due()
        after = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}).get("hourly") or []
        self.assertEqual(len(before), len(after), "re-folding changed the bucket count")
        for b0, b1 in zip(before, after):
            self.assertEqual(b0["temp"]["n"], b1["temp"]["n"],
                             "a sample was counted twice")

    def test_the_due_stamp_refreshes_even_when_nothing_changed(self):
        """The metric roll-up shipped with exactly this defect: the stamp was
        written only on the path where something folded, so an idle fleet
        un-gated an O(fleet) locked sweep on every cadence tick."""
        self._seed(days=1)
        api.run_thermal_rollup_if_due()
        first = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "_meta", {}) or {}).get("last_run")
        self.assertTrue(first, "no due stamp written at all")
        api.save(api.THERMAL_HIST_FILE, {})        # nothing left to fold
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        with api._LockedUpdate(api.THERMAL_ROLLUP_FILE) as st:
            m = dict(st.get("_meta") or {})
            m["last_run"] = 0
            st["_meta"] = m
        api.run_thermal_rollup_if_due()
        again = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "_meta", {}) or {}).get("last_run")
        self.assertTrue(again, "the stamp was not refreshed on the no-op path")

    def test_a_host_with_no_temperatures_is_simply_absent(self):
        api.save(api.THERMAL_HIST_FILE, {})
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        self.assertFalse(rec.get("hourly"))


class TestThermalRollupEndpoint(_RollupBase):

    def _call(self, dev_id, qs=""):
        cap = {}

        def _resp(s, b=None):
            cap["s"], cap["b"] = s, b
            raise api.HTTPError(s, b)
        orig = (api.respond, api.require_auth, api._caller_scope)
        api.respond, api.require_auth, api._caller_scope = _resp, (lambda: "jakob"), (lambda: None)
        os.environ["QUERY_STRING"] = qs
        try:
            api.handle_device_thermal_rollup(dev_id)
        except api.HTTPError:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope = orig
            os.environ.pop("QUERY_STRING", None)
        return cap

    def test_it_answers_the_contracted_shape(self):
        self._seed(days=3)
        api.run_thermal_rollup_if_due()
        cap = self._call("d1", "tier=hourly")
        self.assertEqual(cap["s"], 200)
        b = cap["b"]
        self.assertEqual(b["device_id"], "d1")
        self.assertEqual(b["tier"], "hourly")
        self.assertTrue(b["points"])
        self.assertEqual(set(b["points"][0]), {"ts", "temp"})

    def test_an_unknown_tier_falls_back_like_its_metrics_sibling(self):
        self._seed(days=2)
        api.run_thermal_rollup_if_due()
        self.assertEqual(self._call("d1", "tier=wat")["b"]["tier"], "daily")
        self.assertEqual(self._call("d1", "")["b"]["tier"], "daily")

    def test_an_unknown_device_is_not_found(self):
        self.assertEqual(self._call("../etc/passwd")["s"], 404)

    def test_it_is_scope_gated(self):
        """A device outside the caller's role scope must not be readable — the
        metrics sibling gates this way and a divergence here would be a leak."""
        self._seed(days=1)
        api.run_thermal_rollup_if_due()
        cap = {}

        def _resp(s, b=None):
            cap["s"] = s
            raise api.HTTPError(s, b)
        orig = (api.respond, api.require_auth, api._caller_scope, api._device_in_scope)
        api.respond, api.require_auth = _resp, (lambda: "viewer")
        api._caller_scope = lambda: {"type": "group", "value": "other"}
        api._device_in_scope = lambda scope, dev: False
        os.environ["QUERY_STRING"] = "tier=hourly"
        try:
            api.handle_device_thermal_rollup("d1")
        except api.HTTPError:
            pass
        finally:
            (api.respond, api.require_auth, api._caller_scope,
             api._device_in_scope) = orig
            os.environ.pop("QUERY_STRING", None)
        self.assertEqual(cap.get("s"), 403)


class TestThermalSweepIsRegisteredEverywhere(unittest.TestCase):
    """A cadence sweep lives in TWO registries — `main()` and scheduler.py's
    CADENCE tuple. Adding it to one is a sweep that never runs under the
    out-of-band scheduler, which is the default deployment."""

    def test_both_registries_carry_it(self):
        self.assertIn("run_thermal_rollup_if_due", (_CGI / "api.py").read_text())
        tree = ast.parse((_CGI / "scheduler.py").read_text())
        cadence = next((n.value for n in ast.walk(tree)
                        if isinstance(n, ast.Assign) and len(n.targets) == 1
                        and getattr(n.targets[0], "id", "") == "CADENCE"), None)
        self.assertIsNotNone(cadence, "CADENCE is no longer a module-level literal")
        self.assertIn("run_thermal_rollup_if_due", ast.unparse(cadence))


class TestChartTimePinpointing(unittest.TestCase):
    """The chart already read out a timestamp on hover (v6.3.0), so what was
    missing was narrowing the view to a chosen moment or window. Drag-select,
    exact from/to entry and reset all live on the SHARED helper, so the Trends
    charts gained it in the same change."""

    def setUp(self):
        self.app = (_JS / "app.js").read_text()

    def test_the_shared_helper_supports_zoom(self):
        body = _js_function(self.app, "renderTimeSeries")
        self.assertIn("opts.zoom", body, "the shared helper has no zoom option")

    def test_it_offers_exact_time_entry_not_only_dragging(self):
        """A drag-only control cannot be operated from a keyboard, and an
        operator chasing an incident usually knows the timestamp."""
        self.assertIn("datetime-local", self.app,
                      "no exact from/to entry — dragging is not enough")

    def test_the_trends_page_opts_in(self):
        self.assertRegex(self.app, r"zoom:\s*true",
                         "the metrics charts did not get time-pinpointing")

    def test_the_thermal_chart_opts_in(self):
        self.assertRegex((_JS / "app-power.js").read_text(), r"zoom:\s*true",
                         "the thermal timeline did not get time-pinpointing")

    def test_no_inline_handler_or_style_attribute(self):
        """CSP is `script-src 'self'` with no unsafe-inline: an inline handler
        or a style="" in an innerHTML string dies silently in production."""
        for f in ("app.js", "app-power.js"):
            raw = (_JS / f).read_text()
            # Strip // comments first. app.js documents the pre-CSP era with a
            # literal `onclick="foo(\'${x}\')"` example, and matching that made
            # this fail against compliant code — the ninth time in this sweep a
            # check has matched prose instead of code.
            src = "\n".join(re.sub(r"//.*$", "", l) for l in raw.splitlines())
            # (?<![-\w]) so `data-bd-style="…"` — a data attribute the page
            # applies properly in JS — is not mistaken for a real inline
            # style attribute. Substring-matching an attribute NAME is its own
            # flavour of the same mistake.
            for pat in (r'(?<![-\w])on(?:click|change|input|mousedown|mouseup|submit)\s*=\s*["\']',
                        r'(?<![-\w])style\s*=\s*"'):
                for m in re.finditer(pat, src):
                    line = src[:m.start()].count("\n") + 1
                    seg = src[max(0, m.start() - 200):m.start()]
                    if "addEventListener" in seg or ".onclick" in seg:
                        continue
                    self.fail(f"{f}:{line} inline handler/style in a template: "
                              f"{src[m.start():m.start()+60]!r}")

    def test_every_new_class_is_styled(self):
        """A class with no rule renders as an unstyled box — silently."""
        css = (_CSS / "styles.css").read_text()
        body = _js_function(self.app, "renderTimeSeries")
        for cls in set(re.findall(r"className\s*=\s*'([a-z][a-z0-9 -]*)'", body)):
            for one in cls.split():
                with self.subTest(cls=one):
                    self.assertIn("." + one, css, f".{one} has no CSS rule")


class TestThermalRangePicker(unittest.TestCase):

    def test_the_ranges_map_onto_real_server_tiers(self):
        src = (_JS / "app-power.js").read_text()
        m = re.search(r"tier:\s*'(fivemin|hourly|daily)'", src)
        self.assertIsNotNone(m, "the picker offers no server tier")
        for tier in re.findall(r"tier:\s*'([a-z]+)'", src):
            self.assertIn(tier, ("fivemin", "hourly", "daily"),
                          f"'{tier}' is not a tier the server serves")

    def test_it_requests_the_endpoint_that_exists(self):
        src = (_JS / "app-power.js").read_text()
        self.assertIn("/thermal/rollup?tier=", src)

    def test_the_collapsed_sparkline_survives(self):
        """It is a good at-a-glance summary; replacing rather than
        supplementing it would be a regression."""
        self.assertIn("renderSparkline", (_JS / "app-power.js").read_text())


if __name__ == "__main__":
    unittest.main()
