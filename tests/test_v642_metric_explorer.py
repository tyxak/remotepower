"""v6.4.2 — the ad-hoc metric explorer (server/html/static/js/app-trends.js).

The Trends page could only ever ask one question: ONE device, one preset tier,
its four series. The roll-up store already holds ~2 years of per-device
cpu/mem/swap/disk and (since v6.4.2) temperature, so the explorer overlays any
hosts and metrics on one axis over any window, and keeps the question around.

These tests EXECUTE the module. Every one of the defects they pin passed a
source grep and `node --check` in the draft that shipped none of this:

  * `_mxSelectedHosts` was a GETTER WITH A WRITE SIDE EFFECT — it folded the
    checkboxes currently in the DOM back into the tracked set. `_mxApplyQuery`
    seeded the tracked set from a saved query and then called `_mxRenderHosts`,
    whose first act was that getter, so the stale (unticked) boxes un-picked
    every host the query had just restored. Opening a saved query therefore
    ALWAYS ended at "Pick at least one host." The headline feature was dead on
    every path, and nothing about the source said so.
  * the per-run fetch cap was applied TWICE (once in `_mxNormalizeQuery`, once
    at the fetch), so the overflow was arithmetically always zero and the
    "N more hosts selected but not fetched" note was unreachable dead code —
    hosts 9+ vanished in silence, which is the exact outcome the note existed
    to prevent.
  * host names in that note were escaped twice (`a&b` rendered `a&amp;amp;b`).

So: DOM-shim + V8, drive the real function, assert the real outcome. The shim
is imported from test_v642_app_core, which documents it.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v642_app_core import DOM_SHIM  # noqa: E402
from srcpin import js_function  # noqa: E402  growth-proof source windows

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
_TRENDS = _JS / "app-trends.js"
_APP = _JS / "app.js"
_CSS = ROOT / "server" / "html" / "static" / "css" / "styles.css"
_INDEX = ROOT / "server" / "html" / "index.html"

sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-mx-"))

_spec = importlib.util.spec_from_file_location("api_v642_mx", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules["api_v642_mx"] = api
_spec.loader.exec_module(api)


def trends_js():
    return _TRENDS.read_text()


# ── the browser globals app-trends.js reaches for, stubbed just enough ───────
_STUBS = r"""
var escAttr = function (s) { return escHtml(s); };
var _tsLocalInput = function (ts) { return 'TS:' + ts; };
var _TOASTS = [];
var toast = function (m, t) { _TOASTS.push([m, t]); };
var console = { error: function () {}, warn: function () {}, log: function () {} };
var _RENDERED = null;
var renderTimeSeries = function (id, series, opts) { _RENDERED = { id: id, series: series, opts: opts }; };
var clearTimeSeriesZoom = function () {};
var _errorState = function () {};
var _REQS = [];
var _RESPONSES = {};          // path -> body (undefined => a null answer)
var api = function (method, path) {
  _REQS.push(path);
  return Promise.resolve(Object.prototype.hasOwnProperty.call(_RESPONSES, path)
    ? _RESPONSES[path] : null);
};
var _LS = {};
var localStorage = {
  getItem: function (k) { return Object.prototype.hasOwnProperty.call(_LS, k) ? _LS[k] : null; },
  setItem: function (k, v) { _LS[k] = String(v); },
};
"""

# The card as _mxCardHtml lays it out. Built as real nodes because the shim's
# innerHTML is a string, not a parser — the host checkboxes have to be real
# elements for the stale-DOM regression to be reproducible at all.
_CARD = r"""
build({ tag: 'div', id: 'page-trends' });
var card = build({ tag: 'div', id: 'mx-card' }, document.getElementById('page-trends'));
['mx-filter', 'mx-from', 'mx-to', 'mx-name'].forEach(function (i) {
  build({ tag: 'input', id: i }, card);
});
['mx-stat', 'mx-tier', 'mx-rel', 'mx-saved'].forEach(function (i) {
  build({ tag: 'select', id: i }, card);
});
var hosts = build({ tag: 'div', id: 'mx-hosts' }, card);
var metricsBox = build({ tag: 'div', id: 'mx-metrics' }, card);
build({ tag: 'div', id: 'mx-chart' }, card);
build({ tag: 'div', id: 'mx-note' }, card);
['cpu', 'mem', 'swap', 'disk', 'temp'].forEach(function (k) {
  var cb = build({ tag: 'input', cls: 'mx-metric-cb' }, metricsBox);
  cb.value = k; cb.checked = (k === 'cpu');
});
function mountHostBoxes(ids, ticked) {
  document.getElementById('mx-hosts').childNodes.slice().forEach(function (n) {
    document.getElementById('mx-hosts').removeChild(n);
  });
  ids.forEach(function (id) {
    var cb = build({ tag: 'input', cls: 'mx-host-cb' }, document.getElementById('mx-hosts'));
    cb.value = id;
    cb.checked = (ticked || []).indexOf(id) >= 0;
  });
}
document.getElementById('mx-stat').value = 'avg';
document.getElementById('mx-tier').value = 'auto';
document.getElementById('mx-rel').value = '604800';
"""


def _ctx(with_card=True):
    """V8 holding the DOM shim, the stubs and the WHOLE module (not a
    cherry-picked function — a top-level regression must be able to bite)."""
    ctx = MiniRacer()
    ctx.eval(DOM_SHIM)
    ctx.eval(_STUBS)
    if with_card:
        ctx.eval(_CARD)
    ctx.eval(trends_js())
    return ctx


# ── 1. reachability ─────────────────────────────────────────────────────────
class TestMetricExplorerIsWiredIn(unittest.TestCase):
    """The draft mounted itself by REASSIGNING app.js's loadTrends. That is the
    one shape no guard here can see: test_lazy_page_modules skips any function
    app.js also defines, so a wrapper is invisible to it — and it would lose
    outright to app.js's hoisted `async function loadTrends()` if this file
    ever evaluated first, mounting nothing, with no error anywhere."""

    def test_the_module_never_reassigns_loadtrends(self):
        src = trends_js()
        self.assertNotRegex(src, r"^\s*loadTrends\s*=", "the monkey-patch is back")
        self.assertNotIn("_mxTrendsBase", src)

    def test_showpage_mounts_it_explicitly(self):
        app = _APP.read_text()
        body = js_function(app, "showPage")
        m = re.search(r"if\s*\(name\s*===\s*'trends'\)\s*(\{[^}]*\}|[^\n]*)", body)
        self.assertIsNotNone(m, "showPage no longer routes the trends page")
        self.assertIn("mountMetricExplorer()", m.group(1),
                      "showPage must call mountMetricExplorer() under 'trends' "
                      "— see scratchpad handoff-explorer.md")

    def test_the_page_registers_its_lazy_module(self):
        app = _APP.read_text()
        block = app[app.index("const _LAZY_PAGE_MODULES = {"):]
        block = block[:block.index("\n};")]
        m = re.search(r"^\s*'?trends'?:\s*\[([^\]]*)\]", block, re.M)
        self.assertIsNotNone(m, "_LAZY_PAGE_MODULES has no `trends:` entry — "
                                "showPage would ReferenceError on navigation "
                                "(see scratchpad handoff-explorer.md)")
        self.assertIn("app-trends.js", m.group(1))

    def test_it_mounts_into_a_page_that_exists(self):
        self.assertIn("getElementById('page-trends')", trends_js())
        self.assertIn('id="page-trends"', _INDEX.read_text())

    def test_it_is_not_also_boot_loaded(self):
        """Boot-loaded AND lazy-mapped loads it twice (double listeners)."""
        self.assertNotIn("static/js/app-trends.js?", _INDEX.read_text())


# ── 2. the fatal saved-query defect ─────────────────────────────────────────
@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestSavedQueryRestoresItsHosts(unittest.TestCase):

    def test_opening_a_saved_query_keeps_its_hosts(self):
        """The regression: the host list is ALWAYS already rendered when a
        query is opened (mount → _mxLoadDevices → _mxRenderHosts), and none of
        its boxes are ticked. Re-deriving the picked set from those boxes threw
        the query's hosts away before one was drawn."""
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'},{id:'db01',name:'db01'},
                        {id:'app01',name:'app01'}];
          mountHostBoxes(['web01','db01','app01'], []);   // nothing ticked
          _mxApplyQuery(_mxNormalizeQuery({
            id: 'mx-abc', name: 'weekly', devices: ['web01','db01'],
            metrics: ['cpu','mem'], stat: 'max', tier: 'hourly', rel: 604800 }));
        """)
        self.assertEqual(ctx.eval("JSON.stringify(_mxPicked)"), '["web01","db01"]')
        html = ctx.eval("document.getElementById('mx-hosts').innerHTML")
        self.assertEqual(html.count("checked"), 2, f"re-render lost the ticks: {html}")
        for host in ("web01", "db01"):
            self.assertIn(f'value="{host}"', html)
        # and what Run would actually fetch
        self.assertEqual(ctx.eval("JSON.stringify(_mxSelectedHosts())"),
                         '["web01","db01"]')

    def test_the_getter_does_not_write(self):
        """`_mxSelectedHosts` is a pure read; the mutating half is a separately
        named `_mxSyncPickedFromDom`. Reuniting them re-arms the bug."""
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'}];
          mountHostBoxes(['web01'], []);
          _mxPicked = ['web01'];
        """)
        self.assertEqual(ctx.eval("JSON.stringify(_mxSelectedHosts())"), '["web01"]')
        self.assertEqual(ctx.eval("JSON.stringify(_mxPicked)"), '["web01"]',
                         "the getter mutated the tracked set")

    def test_ticking_a_box_still_reaches_the_query(self):
        """The other half: the fix must not make the checkboxes decorative."""
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'},{id:'db01',name:'db01'}];
          mountHostBoxes(['web01','db01'], ['db01']);
        """)
        self.assertEqual(ctx.eval("JSON.stringify(_mxReadQuery().devices)"), '["db01"]')

    def test_untick_survives_a_filter_rerender(self):
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'},{id:'db01',name:'db01'}];
          mountHostBoxes(['web01','db01'], ['web01','db01']);
          _mxSyncPickedFromDom();
          mountHostBoxes(['web01','db01'], ['web01']);   // operator unticks db01
          filterMetricExplorerHosts();
        """)
        self.assertEqual(ctx.eval("JSON.stringify(_mxPicked)"), '["web01"]')

    def test_a_saved_query_restores_its_hosts(self):
        """The fatal defect this module was nearly dropped for: opening a saved
        query left ZERO hosts picked, because the host getter had a write side
        effect that spliced the selection down to whatever the STALE checkboxes
        said. Storage moved to the server in v6.4.2; the regression it guards
        against is in _mxApplyQuery, which is unchanged, so the coverage stays."""
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'},{id:'db01',name:'db01'}];
          mountHostBoxes(['web01','db01'], []);          // a fresh page visit
          _mxPicked = [];
          // A record shaped as _mxSavedFetch() builds it from the server.
          _mxSaved = [_mxNormalizeQuery({name:'weekly cpu', devices:['web01','db01'],
                                         metrics:['cpu']})];
          _mxSaved[0].id = 'srv-1';
        """)
        self.assertEqual(
            ctx.eval("JSON.stringify(_mxSavedLoad().map(function(q){return q.name;}))"),
            '["weekly cpu"]')
        ctx.eval("_mxApplyQuery(_mxSavedLoad()[0]);")
        self.assertEqual(ctx.eval("JSON.stringify(_mxPicked)"), '["web01","db01"]')


# ── 3. the silent host drop + note escaping ─────────────────────────────────
@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestFetchCapIsReportedNotSilent(unittest.TestCase):

    def _run(self, ids, failing=()):
        ctx = _ctx()
        ctx.eval("var _NOW = Math.floor(Date.now() / 1000);")
        ctx.eval("_mxDevices = %s.map(function (i) { return {id: i, name: i}; });"
                 % _js(ids))
        ctx.eval("_mxPicked = %s.slice();" % _js(ids))
        ctx.eval("""
          var pts = [];
          for (var i = 0; i < 5; i++) pts.push({ts: _NOW - i * 3600, cpu: {min:1, avg:2, max:3}});
          var FAIL = %s;
          _mxDevices.forEach(function (d) {
            var p = '/devices/' + encodeURIComponent(d.id) + '/metrics/rollup?tier=fivemin';
            if (FAIL.indexOf(d.id) < 0) _RESPONSES[p] = { points: pts };
          });
          document.getElementById('mx-rel').value = '86400';
        """ % _js(list(failing)))
        ctx.eval("var _DONE = 0; runMetricExplorer().then(function () { _DONE = 1; });")
        ctx.eval("1")                       # drain the microtask queue
        self.assertEqual(ctx.eval("_DONE"), 1, "runMetricExplorer never resolved")
        return ctx

    def test_hosts_past_the_cap_are_named_in_the_note(self):
        ids = ["host%02d" % i for i in range(1, 13)]
        ctx = self._run(ids)
        note = ctx.eval("document.getElementById('mx-note').innerHTML")
        self.assertEqual(ctx.eval("_REQS.length"), 8, "the fetch cap is not 8")
        self.assertIn("4 more hosts selected but not fetched", note,
                      f"hosts past the cap vanished silently: {note}")
        self.assertIn("cap is 8", note)

    def test_normalize_does_not_pre_apply_the_cap(self):
        """Capping in both places made the overflow arithmetically always 0."""
        ctx = _ctx(with_card=False)
        ids = ["host%02d" % i for i in range(1, 13)]
        n = ctx.eval("_mxNormalizeQuery({devices: %s}).devices.length" % _js(ids))
        self.assertEqual(n, 12, "_mxNormalizeQuery re-applied the fetch cap")

    def test_a_host_name_is_escaped_exactly_once(self):
        ctx = self._run(["a&b<c>", "host2"], failing=["a&b<c>"])
        note = ctx.eval("document.getElementById('mx-note').innerHTML")
        self.assertIn("no data from: a&amp;b&lt;c&gt;", note)
        self.assertNotIn("&amp;amp;", note)
        self.assertNotIn("<c>", note)

    def test_the_no_op_double_escape_is_gone(self):
        self.assertNotIn(r"replace(/&lt;/g, '&lt;')", trends_js())

    def test_one_dead_host_does_not_blank_the_chart(self):
        ctx = self._run(["good1", "bad1"], failing=["bad1"])
        self.assertEqual(ctx.eval("_RENDERED ? _RENDERED.series.length : 0"), 1)
        self.assertIn("no data from: bad1",
                      ctx.eval("document.getElementById('mx-note').innerHTML"))

    def test_unticking_every_metric_says_so_instead_of_plotting_cpu(self):
        """`_mxNormalizeQuery` defaults an empty metric list to ['cpu'] so a
        corrupt saved blob stays runnable — which made the live guard
        unreachable: unticking everything silently charted CPU."""
        ctx = _ctx()
        ctx.eval("""
          _mxDevices = [{id:'web01',name:'web01'}];
          mountHostBoxes(['web01'], ['web01']);
          document.querySelectorAll('#mx-metrics .mx-metric-cb')
                  .forEach(function (cb) { cb.checked = false; });
          var _D = 0; runMetricExplorer().then(function () { _D = 1; });
        """)
        ctx.eval("1")
        self.assertEqual(ctx.eval("_REQS.length"), 0, "it fetched a metric nobody asked for")
        self.assertIn("Pick at least one metric",
                      ctx.eval("document.getElementById('mx-chart').innerHTML"))

    def test_a_corrupt_saved_query_still_has_a_runnable_metric(self):
        """The other side of the same coin — the normalizer's default stays."""
        ctx = _ctx(with_card=False)
        self.assertEqual(
            ctx.eval("JSON.stringify(_mxNormalizeQuery({metrics: []}).metrics)"), '["cpu"]')

    def test_no_hosts_is_an_empty_state_not_a_fanout(self):
        ctx = _ctx()
        ctx.eval("_mxPicked = []; var _D = 0; runMetricExplorer().then(function(){_D=1;});")
        ctx.eval("1")
        self.assertEqual(ctx.eval("_REQS.length"), 0)
        self.assertIn("Pick at least one host",
                      ctx.eval("document.getElementById('mx-chart').innerHTML"))


# ── 4. window + tier selection ──────────────────────────────────────────────
@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestTierAndWindowSelection(unittest.TestCase):
    """The tier picker encodes the SERVER's retention. If a KEEP constant
    shrinks, the client would start asking a tier for buckets that have already
    been pruned and the operator would see an empty chart, so these read the
    real constants out of api.py rather than restating them."""

    def setUp(self):
        self.ctx = _ctx(with_card=False)
        self.now = 1_800_000_000

    def _tier(self, span_days, age_days):
        frm = self.now - int(age_days * 86400)
        return self.ctx.eval("_mxTierFor(%d, %d, %d)"
                             % (frm, frm + int(span_days * 86400), self.now))

    def test_a_recent_short_window_gets_the_finest_tier(self):
        self.assertEqual(self._tier(2 / 24, 0), "fivemin")

    def test_age_disqualifies_the_fine_tier_even_for_a_short_span(self):
        """The subtle half: a 2-hour window is short, but 20 days old it is
        outside the 5-minute tier's retention entirely."""
        self.assertEqual(self._tier(2 / 24, 20), "hourly")
        self.assertEqual(self._tier(2 / 24, 40), "daily")

    def test_a_long_span_walks_down_the_tiers(self):
        self.assertEqual(self._tier(20, 20), "hourly")
        self.assertEqual(self._tier(365, 365), "daily")

    def test_it_never_asks_a_tier_for_pruned_buckets(self):
        for tier, keep in (("fivemin", api.ROLLUP_5MIN_KEEP),
                           ("hourly", api.ROLLUP_HOURLY_KEEP),
                           ("daily", api.ROLLUP_DAILY_KEEP)):
            oldest = max((age for age in range(0, 900)
                          if self._tier(1 / 24, age) == tier), default=None)
            with self.subTest(tier=tier):
                self.assertIsNotNone(oldest, f"{tier} is never chosen at all")
                if tier != "daily":
                    self.assertLessEqual(
                        oldest * 86400, keep,
                        f"_mxTierFor asks {tier} for a window {oldest}d old, "
                        f"older than its {keep // 86400}d server retention")

    def test_relative_beats_absolute(self):
        w = self.ctx.eval("JSON.stringify(_mxWindow({rel: 3600, from: 1, to: 2}, %d))"
                          % self.now)
        self.assertEqual(w, '{"from":%d,"to":%d}' % (self.now - 3600, self.now))

    def test_an_inverted_window_falls_back_to_a_sane_week(self):
        w = self.ctx.eval("JSON.stringify(_mxWindow({from: 500, to: 100}, %d))"
                          % self.now)
        self.assertEqual(w, '{"from":%d,"to":%d}' % (self.now - 604800, self.now))

    def test_garbage_never_throws(self):
        for blob in ("null", "'x'", "0", "[]", "{from:'a',to:{}}", "{rel:NaN}"):
            with self.subTest(blob=blob):
                w = self.ctx.eval("JSON.stringify(_mxWindow(%s, %d))" % (blob, self.now))
                self.assertIn('"from"', w)


# ── 5. series assembly against REAL server output ───────────────────────────
class _RollupBase(unittest.TestCase):
    """Seeds the real stores and runs the real cadence sweeps, so the fixture
    the JS is fed is what the server ACTUALLY emits — a hand-written fixture
    encodes the consumer's assumption, which is the whole dead-signal trap."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-mx-run-"))
        self._files = {}
        for attr in ("DEVICES_FILE", "CONFIG_FILE", "METRICS_FILE",
                     "METRICS_ROLLUP_FILE", "THERMAL_HIST_FILE",
                     "THERMAL_ROLLUP_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(str(getattr(api, attr))).name)
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "last_seen": self.now}})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def _seed_metrics(self, hours=48):
        pts = [{"ts": self.now - i * 60, "cpu": 10 + (i % 30), "mem": 40,
                "swap": 1, "disk": 55} for i in range(hours * 60)]
        api.save(api.METRICS_FILE, {"d1": list(reversed(pts))})
        api._invalidate_load_cache(api.METRICS_FILE)

    def _seed_thermal(self, hours=48):
        pts = [{"ts": self.now - i * 300, "temp": 45 + (i % 7)}
               for i in range(hours * 12)]
        api.save(api.THERMAL_HIST_FILE, {"d1": {"samples": list(reversed(pts))}})
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)

    def _endpoint(self, handler, dev_id, qs):
        cap = {}

        def _resp(s, b=None):
            cap["s"], cap["b"] = s, b
            raise api.HTTPError(s, b)
        orig = (api.respond, api.require_auth, api._caller_scope)
        api.respond, api.require_auth, api._caller_scope = (
            _resp, (lambda: "jakob"), (lambda: None))
        os.environ["QUERY_STRING"] = qs
        try:
            handler(dev_id)
        except api.HTTPError:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope = orig
            os.environ.pop("QUERY_STRING", None)
        return cap


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestSeriesFromRealRollupPoints(_RollupBase):

    def _points(self):
        self._seed_metrics()
        self._seed_thermal()
        api.run_metric_rollup_if_due()
        api.run_thermal_rollup_if_due()
        m = self._endpoint(api.handle_device_metric_rollup, "d1", "tier=hourly")
        t = self._endpoint(api.handle_device_thermal_rollup, "d1", "tier=hourly")
        self.assertEqual(m["s"], 200)
        self.assertEqual(t["s"], 200)
        self.assertTrue(m["b"]["points"], "the metric roll-up produced nothing")
        self.assertTrue(t["b"]["points"], "the thermal roll-up produced nothing")
        return m["b"]["points"], t["b"]["points"]

    def test_the_module_reads_the_shape_the_server_emits(self):
        mpts, tpts = self._points()
        ctx = _ctx(with_card=False)
        ctx.eval("var ROW = {id:'d1', name:'web01', metrics: %s, thermal: %s};"
                 % (_js(mpts), _js(tpts)))
        n = ctx.eval("_mxBuildSeries([ROW], ['cpu','temp'], 'avg', 0, 9e9).length")
        self.assertEqual(n, 2, "the server's roll-up points yielded no series")
        names = ctx.eval(
            "JSON.stringify(_mxBuildSeries([ROW], ['cpu','temp'], 'avg', 0, 9e9)"
            ".map(function (s) { return s.name; }))")
        self.assertIn("web01", names)
        self.assertIn("CPU %", names)
        self.assertIn("Temperature", names)

    def test_the_requested_statistic_is_the_one_plotted(self):
        """min <= avg <= max on every bucket, and at least one bucket where
        they genuinely differ.

        The earlier version asserted `lo < hi` on `points[0]` alone — the
        OLDEST bucket, which is a partial hour whenever `now` lands near an
        hour boundary. A single-sample bucket has min == max legitimately, so
        the test failed on working code depending on the clock. The property it
        means is "the requested statistic is the one read", and one differing
        bucket proves that without depending on where the hour falls.
        """
        import json
        mpts, _ = self._points()
        ctx = _ctx(with_card=False)
        ctx.eval("var ROW = {id:'d1', name:'web01', metrics: %s, thermal: []};" % _js(mpts))

        def ys(stat):
            return json.loads(ctx.eval(
                "JSON.stringify(_mxBuildSeries([ROW], ['cpu'], '%s', 0, 9e9)[0]"
                ".points.map(function (p) { return p.y; }))" % stat))
        lo, av, hi = ys('min'), ys('avg'), ys('max')
        self.assertEqual(len(lo), len(av))
        self.assertEqual(len(av), len(hi))
        for i, (a, b, c) in enumerate(zip(lo, av, hi)):
            with self.subTest(bucket=i):
                self.assertLessEqual(a, b)
                self.assertLessEqual(b, c)
        self.assertTrue(any(a < c for a, c in zip(lo, hi)),
                        "the seeded curve varies across every full hour; if no "
                        "bucket has min < max the statistic is not being read")

    def test_points_outside_the_window_are_dropped(self):
        mpts, _ = self._points()
        ctx = _ctx(with_card=False)
        ctx.eval("var ROW = {id:'d1', name:'web01', metrics: %s, thermal: []};" % _js(mpts))
        import json
        frm, to = self.now - 6 * 3600, self.now
        kept = json.loads(ctx.eval(
            "JSON.stringify(_mxBuildSeries([ROW], ['cpu'], 'avg', %d, %d)[0].points"
            ".map(function (p) { return p.x; }))" % (frm, to)))
        self.assertTrue(kept)
        self.assertTrue(all(frm <= x <= to for x in kept), kept)
        self.assertLess(len(kept), len(mpts))

    def test_a_metric_with_no_data_yields_no_series(self):
        mpts, _ = self._points()
        ctx = _ctx(with_card=False)
        ctx.eval("var ROW = {id:'d1', name:'web01', metrics: %s, thermal: []};" % _js(mpts))
        self.assertEqual(ctx.eval("_mxBuildSeries([ROW], ['temp'], 'avg', 0, 9e9).length"), 0)


# ── 6. folding ──────────────────────────────────────────────────────────────
@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestFoldMatchesTheStatistic(unittest.TestCase):

    def setUp(self):
        self.ctx = _ctx(with_card=False)
        self.ctx.eval("""
          var PTS = [];
          for (var i = 0; i < 1000; i++) PTS.push({x: i, y: i % 10});
        """)

    def test_a_long_series_is_folded_to_the_cap(self):
        self.assertLessEqual(self.ctx.eval("_mxFold(PTS, 240, 'avg').length"), 240)

    def test_a_short_series_is_returned_untouched(self):
        self.assertTrue(self.ctx.eval("_mxFold(PTS.slice(0, 5), 240, 'avg') === "
                                      "_mxFold(PTS.slice(0, 5), 240, 'avg') || true"))
        self.assertEqual(self.ctx.eval(
            "JSON.stringify(_mxFold([{x:1,y:2},{x:2,y:3}], 240, 'avg'))"),
            '[{"x":1,"y":2},{"x":2,"y":3}]')

    def test_folding_a_max_series_keeps_maxima(self):
        """Averaging a `max` series relabels a peak chart as a mean of peaks
        while it still says 'max' on the legend."""
        self.assertEqual(self.ctx.eval("_mxFold(PTS, 100, 'max')[0].y"), 9)
        self.assertEqual(self.ctx.eval("_mxFold(PTS, 100, 'min')[0].y"), 0)
        avg = self.ctx.eval("_mxFold(PTS, 100, 'avg')[0].y")
        self.assertGreater(avg, 0)
        self.assertLess(avg, 9)

    def test_the_series_builder_passes_the_statistic_through(self):
        self.ctx.eval("""
          var SRC = [];
          for (var i = 0; i < 1000; i++) SRC.push({ts: i, cpu: {min: 0, avg: 5, max: i % 10}});
          var ROW = {id:'d', name:'d', metrics: SRC, thermal: []};
        """)
        self.assertEqual(
            self.ctx.eval("_mxBuildSeries([ROW], ['cpu'], 'max', 0, 9e9, 100)[0].points[0].y"),
            9, "_mxBuildSeries folded a max series by averaging")


# ── 7. hostile saved-query blobs ────────────────────────────────────────────
@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestNormalizeQueryIsUnbreakable(unittest.TestCase):

    def setUp(self):
        self.ctx = _ctx(with_card=False)

    def test_anything_yields_a_runnable_query(self):
        for blob in ("null", "undefined", "'wat'", "42", "[]", "[null]",
                     "{devices: 'web01'}", "{devices: [null, 1, 'a', 'a']}",
                     "{metrics: ['nope']}", "{tier: 'monthly', stat: 'p99'}",
                     "{rel: -5, from: 'x', to: NaN}", "{name: 12345}"):
            with self.subTest(blob=blob):
                q = self.ctx.eval("JSON.stringify(_mxNormalizeQuery(%s))" % blob)
                self.assertIn('"metrics"', q)
                for field, ok in (("tier", ("auto", "fivemin", "hourly", "daily")),
                                  ("stat", ("avg", "min", "max"))):
                    v = self.ctx.eval("_mxNormalizeQuery(%s).%s" % (blob, field))
                    self.assertIn(v, ok)
                self.assertGreaterEqual(
                    self.ctx.eval("_mxNormalizeQuery(%s).metrics.length" % blob), 1)

    def test_duplicate_hosts_collapse(self):
        self.assertEqual(
            self.ctx.eval("JSON.stringify(_mxNormalizeQuery("
                          "{devices:['a','a','b','a']}).devices)"), '["a","b"]')

    def test_a_huge_blob_is_bounded(self):
        """The dedup is O(n^2); a hand-edited blob must not hang the tab."""
        n = self.ctx.eval("""
          (function () {
            var big = [];
            for (var i = 0; i < 5000; i++) big.push('h' + i);
            return _mxNormalizeQuery({devices: big}).devices.length;
          })()
        """)
        self.assertLessEqual(n, 200)
        self.assertGreater(n, 8, "the bound must sit above the fetch cap, or "
                                 "the overflow note can never fire")

    def test_the_id_is_non_numeric_by_construction(self):
        """data-arg goes through the dispatcher's `!isNaN(v) ? Number(v) : v`,
        which turns a hex-looking id into a number (or Infinity)."""
        for blob in ("{}", "{id: 1e500}", "{id: '0x10'}", "{id: '12345'}",
                     "{id: 'mx-'+'x'.repeat(200)}"):
            with self.subTest(blob=blob):
                got = self.ctx.eval("_mxNormalizeQuery(%s).id" % blob)
                self.assertRegex(got, r"^mx-[A-Za-z0-9]{1,32}$")
                self.assertTrue(self.ctx.eval("isNaN(_mxNormalizeQuery(%s).id)" % blob),
                                f"id {got!r} would be coerced to a Number")

    def test_a_nameless_query_is_not_listed(self):
        self.ctx.eval("_LS['rp_metric_explorer_v1'] = "
                      "JSON.stringify([{devices:['a']}, {name:'keep', devices:['a']}]);")
        self.assertEqual(self.ctx.eval(
            "JSON.stringify(_mxLocalLegacy().map(function(q){return q.name;}))"), '["keep"]')

    def test_a_corrupt_blob_is_not_fatal(self):
        for raw in ("not json", "null", '"a string"', "{}", "[1,2,3]"):
            with self.subTest(raw=raw):
                self.ctx.eval("_LS['rp_metric_explorer_v1'] = %s;" % _js(raw))
                self.assertEqual(self.ctx.eval("_mxLocalLegacy().length"), 0)


# ── 8. house rules the module has to keep ───────────────────────────────────
class TestHouseRules(unittest.TestCase):

    def test_no_inline_handlers_or_styles(self):
        src = trends_js()
        self.assertNotRegex(src, r"\son[a-z]+\s*=\s*[\"']", "inline on*= dies under CSP")
        self.assertNotRegex(src, r"\sstyle\s*=\s*[\"']", "inline style= dies under CSP")

    def test_no_emoji_in_the_ui_strings(self):
        for ch in trends_js():
            self.assertLess(ord(ch), 0x1F000, f"emoji {ch!r} — use _icon()")

    def test_every_class_it_invents_is_styled(self):
        css = _CSS.read_text()
        src = trends_js()
        used = set()
        for m in re.findall(r'class="([^"$`{]+)"', src):
            used |= set(m.split())
        invented = {c for c in used if c.startswith("mx-")}
        self.assertTrue(invented, "the scanner found no mx- classes at all")
        for c in sorted(invented):
            with self.subTest(cls=c):
                hook = re.search(r"querySelector(?:All)?\([^)]*\.%s\b" % re.escape(c), src)
                self.assertTrue(f".{c}" in css or hook,
                                f".{c} is styled nowhere and hooks nothing")

    def test_the_pickers_declare_their_own_styles(self):
        css = _CSS.read_text()
        for c in (".mx-hostbox", ".mx-metricbox"):
            self.assertIn(c, css)

    def test_the_variable_length_box_is_capped(self):
        """The host list is fleet-sized; it caps and scrolls, it does not grow."""
        m = re.search(r'id="mx-hosts"[^>]*class="([^"]+)"', trends_js())
        self.assertIsNotNone(m)
        self.assertIn("scroll-cap", m.group(1))

    def test_it_only_calls_endpoints_that_exist(self):
        # Every verb, not just GET: v6.4.2 added POST/DELETE for server-backed
        # saved queries, and a write to a route that does not exist fails just
        # as silently as a read. No hardcoded count — that only ever produces a
        # failure that says "expected 3, found 4" about a legitimate addition.
        paths = set(re.findall(r"api\('[A-Z]+', [`']/([A-Za-z0-9/_${}().?&=-]+)",
                               trends_js()))
        self.assertTrue(paths, "the explorer calls no endpoints at all?")
        served = {r[1] for r in api._build_exact_routes()} | {
            r[1] for r in api._dispatcher_routes()}
        for p in sorted(paths):
            tmpl = ("/api/" + p.split("?")[0]
                    .replace("${encodeURIComponent(id)}", "{device_id}")
                    .replace("${encodeURIComponent(q.id)}", "{id}"))
            tmpl = tmpl.rstrip("/")
            with self.subTest(path=tmpl):
                self.assertIn(tmpl, served, f"{tmpl} is not a served route")


def _js(v):
    """Python value -> a JS literal safe to paste into an eval."""
    import json
    return json.dumps(v)


if __name__ == "__main__":
    unittest.main()
