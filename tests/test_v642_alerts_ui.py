"""v6.4.2 — the alert inbox: server-side paging/search, escalation, resolve notes.

These drive the REAL functions in `app-alerts.js` under V8 with a scripted DOM
stub, so a passing test means the code ran and produced the asserted output — a
source-text grep would prove only that a line exists (the false-green class this
project keeps re-learning).

What is pinned:
  * GET /api/alerts carries offset/limit and, when set, q / severity /
    device_id — the inbox used to request a flat limit=500 and never read
    `total`, so alert 501 was unreachable and the filter box searched only the
    loaded slice (an operator hunting the host their pager fired on got "No
    alerts in this view").
  * The pager quotes the SERVER's total, not the page length, and its Prev/Next
    clamp at both ends.
  * `escalated_tiers` / `escalated_at` render as a text badge (the string
    "escalated" appeared nowhere under server/html before this), and `first_seen`
    drives an age that a repeating alert cannot understate.
  * The resolve flow can carry a `note`, sends it only when given, and shows a
    stored `resolve_note` (HTML-escaped) on the resolved row.
  * The keyboard inbox, the optimistic resolve + Undo and the deep-link widening
    still work after the rewrite.
"""

import json
import unittest
from pathlib import Path

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                   # pragma: no cover
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js" / "app-alerts.js"

# A scripted DOM: getElementById is a registry, appendChild/insertBefore
# register any child that has an id (so JS-created controls become findable
# exactly as in a browser), and setTimeout is a queue the test drains by hand.
_STUB = r"""
var __els = {}, __listeners = {}, __timers = [], __calls = [], __toasts = [];
var __prompt = null, __devices = [];
function __mkEl(id) {
  var el = {
    id: id || '', value: '', checked: false, innerHTML: '', textContent: '',
    placeholder: '', dataset: {}, className: '', children: [], parentNode: null,
    nextSibling: null, offsetParent: {}, tagName: 'DIV', disabled: false,
    classList: {
      _s: {},
      add: function (c) { this._s[c] = 1; },
      remove: function (c) { delete this._s[c]; },
      contains: function (c) { return !!this._s[c]; },
      toggle: function (c, on) {
        if (on === undefined) on = !this._s[c];
        if (on) this._s[c] = 1; else delete this._s[c];
        return !!on;
      }
    },
    appendChild: function (c) { this.children.push(c); c.parentNode = this;
                                if (c.id) __els[c.id] = c; return c; },
    insertBefore: function (n) { this.children.push(n); n.parentNode = this;
                                 if (n.id) __els[n.id] = n; return n; },
    querySelector: function () { return null; },
    querySelectorAll: function () { return []; },
    closest: function () { return null; },
    setAttribute: function () {}, getAttribute: function () { return null; },
    scrollIntoView: function () {}, remove: function () {},
    focus: function () {}, select: function () {}
  };
  if (id) __els[id] = el;
  return el;
}
function __el(id) { return __els[id] || __mkEl(id); }

var __rows = [];
// Elements the code writes as an innerHTML string resolve too — the stub has
// no HTML parser, so a lookup for an id that appears in some element's markup
// materialises it, the way the browser's parser would have.
function __fromMarkup(id) {
  for (var k in __els) {
    var h = __els[k].innerHTML;
    if (h && String(h).indexOf('id="' + id + '"') >= 0) return __mkEl(id);
  }
  return null;
}
var document = {
  body: __mkEl('body'),
  getElementById: function (id) { return __els[id] || __fromMarkup(id); },
  createElement: function () { return __mkEl(''); },
  querySelector: function () { return null; },
  querySelectorAll: function (sel) {
    if (String(sel).indexOf('alerts-row') >= 0) return __rows.slice();
    return [];
  },
  addEventListener: function (t, f) { (__listeners[t] = __listeners[t] || []).push(f); }
};
var window = { _modules: {}, _ticketsOn: false };
var navigator = { clipboard: null };
var location = { origin: 'https://x', pathname: '/' };
function setTimeout(fn) { __timers.push(fn); return __timers.length; }
function clearTimeout(i) { if (i) __timers[i - 1] = null; }
function __flush() {
  var t = __timers; __timers = [];
  for (var i = 0; i < t.length; i++) if (t[i]) t[i]();
}
function Option(text, value) { return { text: text, value: value, id: '' }; }

// ── app.js helpers app-alerts.js depends on ──────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escAttr(s) { return escHtml(s); }
function _escapeHtml(s) { return escHtml(s == null ? '' : s); }
function _safeHttpHref(u) { return String(u); }
function _icon() { return '<svg></svg>'; }
function _formatTs(ts) { return ts ? 'TS' + ts : ''; }
function _fmtDuration(s) { return 'DUR' + (parseInt(s, 10) || 0); }
function _tkNo(n) { return 'TK' + n; }
function _rpNo(n) { return 'RP' + n; }
function getMe() { return 'operator'; }
function toast(msg, type) { __toasts.push([msg, type || 'info']); }
function refreshAlertsBadge() {}
function loadHome() {}
function showPage() {}
function openModal() {}
function openMitigateModal() {}
function aiThinkingHtml() { return ''; }
function pushUndoableAction() {}
function uiConfirm() { return Promise.resolve(true); }
function uiPrompt() { return Promise.resolve(__prompt); }
function _scanDeviceList() { return Promise.resolve(__devices); }
var uiUndoCtl = { push: function () {} };
var statTiles = { enhanceAll: function () {} };
var tableCtl = {
  wireSortOnly: function () {},
  sortRows: function (n, rows) { return rows; },
  renderChunked: function (id, html) { __el(id).innerHTML = html.join(''); }
};

// Scripted transport: every call is recorded, the reply comes from __replies.
var __replies = {};
function api(method, path, body) {
  __calls.push({ method: method, path: path, body: body === undefined ? null : body });
  var key = method + ' ' + String(path).split('?')[0];
  var r = __replies[key];
  if (typeof r === 'function') r = r(path, body);
  return Promise.resolve(r === undefined ? { ok: true } : r);
}
function __seedPage(alerts, total, offset, limit) {
  __replies['GET /alerts'] = function (path) {
    var m = /offset=(\d+)/.exec(path), o = m ? parseInt(m[1], 10) : 0;
    var l = /limit=(\d+)/.exec(path);
    return {
      alerts: alerts, total: total, offset: offset === undefined ? o : offset,
      limit: limit === undefined ? (l ? parseInt(l[1], 10) : 100) : limit,
      summary: null, ack_comment_enabled: false
    };
  };
}
function __lastGet() {
  for (var i = __calls.length - 1; i >= 0; i--)
    if (__calls[i].method === 'GET') return __calls[i].path;
  return '';
}
function __posts(prefix) {
  return __calls.filter(function (c) {
    return c.method === 'POST' && c.path.indexOf(prefix) === 0;
  });
}
// The page's own controls, as index.html declares them.
__mkEl('alerts-filter-status').value = 'open';
__mkEl('alerts-filter-text').value = '';
__mkEl('alerts-group-host').checked = false;
__mkEl('alerts-summary');
__mkEl('alerts-tbody');
__mkEl('page-alerts').classList.add('active');
__el('alerts-summary').parentNode = __mkEl('card-summary');
__el('alerts-tbody').parentNode = __mkEl('card-table');
"""


def _js(extra=""):
    return _STUB + "\n" + _JS.read_text() + "\n" + extra


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class _V8(unittest.TestCase):
    def ctx(self, setup=""):
        c = MiniRacer()
        c.eval(_js(setup))
        return c

    def run_js(self, c, *chunks):
        """Each chunk is its own script so V8 drains the microtask queue between
        them — an async loader's `await` has NOT resolved yet inside the same
        eval that called it (two tests silently asserted nothing before this)."""
        for chunk in chunks:
            c.eval(chunk)

    def jeval(self, c, expr):
        return json.loads(c.eval("JSON.stringify(%s)" % expr))

    def assertLoaded(self, c):
        """loadAlerts swallows its own exceptions into a toast, so an assertion
        on the recorded request can pass while the render half threw."""
        self.assertNotIn("Failed to load alerts",
                         [t[0] for t in self.jeval(c, "__toasts")])


class TestServerSidePaging(_V8):
    def test_request_carries_limit_and_offset(self):
        c = self.ctx("__seedPage([], 0);")
        c.eval("loadAlerts();")
        path = self.jeval(c, "__lastGet()")
        self.assertLoaded(c)
        self.assertIn("status=open", path)
        self.assertIn("offset=0", path)
        self.assertIn("limit=", path)
        # The old flat cap is gone; nothing may hardcode 500 rows.
        self.assertNotIn("limit=500&", path + "&")

    def test_search_severity_and_device_go_to_the_server(self):
        c = self.ctx("__seedPage([], 0);")
        c.eval("loadAlerts();")
        c.eval("__el('alerts-filter-sev').value = 'critical,high';"
               "__el('alerts-filter-device').value = 'dev-7';"
               "alertsFilterChanged();")
        path = self.jeval(c, "__lastGet()")
        self.assertIn("severity=critical%2Chigh", path)
        self.assertIn("device_id=dev-7", path)
        self.assertIn("offset=0", path)

    def test_typing_triggers_a_server_search_not_a_local_one(self):
        c = self.ctx("__seedPage([], 0);")
        c.eval("loadAlerts();")
        c.eval("__el('alerts-filter-text').value = 'web01'; renderAlerts(); __flush();")
        path = self.jeval(c, "__lastGet()")
        self.assertIn("q=web01", path)
        self.assertIn("offset=0", path)

    def test_pager_quotes_the_server_total_not_the_page_length(self):
        c = self.ctx("__seedPage(__mkRows(100), 4213, 0, 100);"
                     "function __mkRows(n){var a=[];for(var i=0;i<n;i++)"
                     "a.push({id:'a'+i, ts:1, severity:'low'});return a;}")
        c.eval("loadAlerts();")
        html = self.jeval(c, "__el('alerts-pager').innerHTML")
        self.assertLoaded(c)
        self.assertIn("Showing 1–100 of 4213", html)
        self.assertIn('data-action="alertsPage"', html)

    def test_next_advances_prev_clamps_and_the_end_is_disabled(self):
        c = self.ctx("function __mkRows(n){var a=[];for(var i=0;i<n;i++)"
                     "a.push({id:'a'+i, ts:1, severity:'low'});return a;}"
                     "__seedPage(__mkRows(100), 250, undefined, 100);")
        c.eval("loadAlerts();")
        c.eval("alertsPage(-1);")           # already on page 1 — no-op
        self.assertIn("offset=0", self.jeval(c, "__lastGet()"))
        c.eval("alertsPage(1);")
        self.assertIn("offset=100", self.jeval(c, "__lastGet()"))
        c.eval("alertsPage(1);")
        self.assertIn("offset=200", self.jeval(c, "__lastGet()"))
        # 200 + 100 >= 250 → Next is refused and disabled.
        before = self.jeval(c, "__calls.length")
        c.eval("alertsPage(1);")
        self.assertEqual(self.jeval(c, "__calls.length"), before)
        self.assertIn("disabled", self.jeval(c, "__el('alerts-pager').innerHTML"))

    def test_page_size_change_returns_to_the_first_page(self):
        c = self.ctx("function __mkRows(n){var a=[];for(var i=0;i<n;i++)"
                     "a.push({id:'a'+i, ts:1, severity:'low'});return a;}"
                     "__seedPage(__mkRows(50), 900, undefined, undefined);")
        self.run_js(c, "loadAlerts();", "alertsPage(1);")
        self.assertIn("offset=100", self.jeval(c, "__lastGet()"))
        self.run_js(c, "__el('alerts-page-size').value = '200'; alertsPageSize();")
        path = self.jeval(c, "__lastGet()")
        self.assertIn("limit=200", path)
        self.assertIn("offset=0", path)

    def test_a_server_clamped_page_size_is_listed_not_silently_wrong(self):
        c = self.ctx("function __mkRows(n){var a=[];for(var i=0;i<n;i++)"
                     "a.push({id:'a'+i, ts:1, severity:'low'});return a;}"
                     "__seedPage(__mkRows(10), 5000, 0, 1000);")   # server clamp
        c.eval("loadAlerts();")
        html = self.jeval(c, "__el('alerts-pager').innerHTML")
        self.assertIn('<option value="1000" selected>1000/page</option>', html)

    def test_empty_result_under_a_filter_says_so_and_offers_a_way_out(self):
        c = self.ctx("__seedPage([], 0);")
        self.run_js(c, "loadAlerts();",
                    "__el('alerts-filter-device').value = 'dev-9'; alertsFilterChanged();")
        html = self.jeval(c, "__el('alerts-tbody').innerHTML")
        self.assertLoaded(c)
        self.assertIn("No alerts match this search", html)
        self.assertIn('data-action="clearAlertFilters"', html)
        self.run_js(c, "clearAlertFilters();")
        path = self.jeval(c, "__lastGet()")
        self.assertNotIn("device_id=", path)
        self.assertNotIn("q=", path)


class TestEscalationAndAgeAreVisible(_V8):
    def _row(self, c, alert):
        c.eval("__A = %s;" % json.dumps(alert))
        return self.jeval(c, "_alertRowHtml(__A, '')")

    def test_escalated_alert_shows_the_tier_reached(self):
        c = self.ctx()
        html = self._row(c, {"id": "a1", "ts": 100, "severity": "high",
                             "escalated_tiers": [1, 2, 3], "escalated_at": 900})
        self.assertIn("escalated · tier 3", html)
        self.assertIn("TS900", html)          # when, in the tooltip

    def test_a_never_escalated_alert_gets_no_badge(self):
        c = self.ctx()
        html = self._row(c, {"id": "a1", "ts": 100, "severity": "high"})
        self.assertNotIn("escalated", html)

    def test_age_comes_from_first_seen_not_the_last_occurrence(self):
        c = self.ctx()
        c.eval("Date.now = function(){ return 10000 * 1000; };")
        html = self._row(c, {"id": "a1", "ts": 9000, "first_seen": 1000,
                             "severity": "high"})
        self.assertIn("age DUR9000", html)    # 10000 - 1000, not 10000 - 9000
        self.assertIn("First seen TS1000", html)

    def test_resolved_alert_reports_how_long_it_stayed_open(self):
        c = self.ctx()
        html = self._row(c, {"id": "a1", "ts": 500, "first_seen": 100,
                             "resolved_at": 700, "resolved_by": "kim",
                             "severity": "low"})
        self.assertIn("open for DUR600", html)


class TestResolutionNotes(_V8):
    def test_plain_resolve_sends_no_note(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);")
        self.run_js(c, "loadAlerts();", "resolveAlert('a1');")
        posts = self.jeval(c, "__posts('/alerts/a1/resolve')")
        self.assertEqual(len(posts), 1, posts)
        self.assertEqual(posts[0]["body"], {})

    def test_resolve_with_a_note_posts_it(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);"
                     "__prompt = '  restarted postfix  ';")
        self.run_js(c, "loadAlerts();", "resolveAlertWithNote('a1');", "0;")
        posts = self.jeval(c, "__posts('/alerts/a1/resolve')")
        self.assertEqual(len(posts), 1, posts)
        self.assertEqual(posts[0]["body"], {"note": "restarted postfix"})

    def test_cancelling_the_note_prompt_resolves_nothing(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);"
                     "__prompt = null;")
        self.run_js(c, "loadAlerts();", "resolveAlertWithNote('a1');", "0;")
        self.assertEqual(self.jeval(c, "__posts('/alerts/a1/resolve').length"), 0)

    def test_an_empty_note_still_resolves(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);"
                     "__prompt = '   ';")
        self.run_js(c, "loadAlerts();", "resolveAlertWithNote('a1');", "0;")
        posts = self.jeval(c, "__posts('/alerts/a1/resolve')")
        self.assertEqual(len(posts), 1, posts)
        self.assertEqual(posts[0]["body"], {})

    def test_stored_note_renders_on_the_resolved_row_and_is_escaped(self):
        c = self.ctx()
        c.eval("__A = {id:'a1', ts:1, severity:'low', resolved_at:2,"
               "resolved_by:'kim', resolve_note:'<img src=x onerror=1>'};")
        html = self.jeval(c, "_alertRowHtml(__A, '')")
        self.assertIn("Fixed by:", html)
        self.assertIn("&lt;img src=x onerror=1&gt;", html)
        self.assertNotIn("<img src=x", html)

    def test_the_note_button_is_offered_only_while_the_alert_is_open(self):
        c = self.ctx()
        c.eval("__OPEN = {id:'a1', ts:1, severity:'low'};"
               "__DONE = {id:'a2', ts:1, severity:'low', resolved_at:2};")
        self.assertIn('data-action="resolveAlertWithNote"',
                      self.jeval(c, "_alertRowHtml(__OPEN, '')"))
        self.assertNotIn('data-action="resolveAlertWithNote"',
                         self.jeval(c, "_alertRowHtml(__DONE, '')"))


class TestExistingBehaviourSurvives(_V8):
    def test_keyboard_j_then_r_still_resolves_the_selected_row(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);")
        c.eval("loadAlerts();")
        c.eval("var row = __mkEl(''); row.dataset.alertId = 'a1'; __rows = [row];"
               "var kd = __listeners['keydown'][0];"
               "var ev = function(k){ return {key:k, target:{tagName:'BODY'},"
               "  preventDefault:function(){}}; };"
               "kd(ev('j')); kd(ev('r'));")
        self.assertEqual(self.jeval(c, "__posts('/alerts/a1/resolve').length"), 1)

    def test_optimistic_resolve_flips_the_row_before_the_server_answers(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);")
        self.run_js(c, "loadAlerts();", "resolveAlert('a1');")
        self.assertTrue(self.jeval(c, "!!_alertsCache[0].resolved_at"))
        self.assertEqual(self.jeval(c, "_alertsCache[0].resolved_by"), "operator")

    def test_a_failed_resolve_reverts_the_optimistic_flip(self):
        c = self.ctx("__seedPage([{id:'a1', ts:1, severity:'low'}], 1);"
                     "__replies['POST /alerts/a1/resolve'] = {error:'nope'};")
        self.run_js(c, "loadAlerts();", "resolveAlert('a1', 'a note');", "0;")
        self.assertFalse(self.jeval(c, "!!_alertsCache[0].resolved_at"))
        self.assertFalse(self.jeval(c, "!!_alertsCache[0].resolve_note"))

    def test_deep_link_widening_also_clears_a_leftover_search(self):
        c = self.ctx("__seedPage([], 0);")
        self.run_js(c, "loadAlerts();",
                    "__el('alerts-filter-text').value = 'nothing-matches'; renderAlerts();",
                    "__flush();",                  # the q round trip lands
                    "window._pendingAlertDeepLink = 'a1'; _focusPendingAlert();")
        path = self.jeval(c, "__lastGet()")
        self.assertNotIn("q=", path)
        self.assertEqual(self.jeval(c, "__el('alerts-filter-status').value"), "all")
        self.assertEqual(self.jeval(c, "__el('alerts-filter-text').value"), "")

    def test_deep_link_gives_up_once_instead_of_looping(self):
        c = self.ctx("__seedPage([], 0);")
        self.run_js(c, "loadAlerts();",
                    "window._pendingAlertDeepLink = 'a1'; _focusPendingAlert();",
                    "_focusPendingAlert();")
        msgs = [m[0] for m in self.jeval(c, "__toasts")]
        self.assertIn("Alert not found — it may have been purged", msgs)
        self.assertIsNone(self.jeval(c, "window._pendingAlertDeepLink"))


class TestDeviceFilterIsBuiltSafely(_V8):
    def test_device_names_never_reach_an_html_parser(self):
        c = self.ctx("__devices = [{id:'d1', name:'<script>x</script>'}];"
                     "__seedPage([], 0);")
        c.eval("loadAlerts();")
        opts = self.jeval(c, "__el('alerts-filter-device').children.map("
                             "function(o){return o.text;})")
        self.assertIn("<script>x</script>", opts)   # a text node, not markup
        self.assertEqual(self.jeval(c, "__el('alerts-filter-device').innerHTML"), "")


if __name__ == "__main__":
    unittest.main()
