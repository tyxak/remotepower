"""v6.4.2 — the Needs Attention page, the tag/group registry, and the two new
fleet events, driven rather than grepped.

Every assertion here EXECUTES the real app.js source: the functions under test
are lifted out of app.js with srcpin (never a fixed window) and evaluated in V8
against a small hand-written DOM/`tableCtl` double that records what the code
actually did. A substring check on app.js would prove a line exists; it would
not have caught the severity column sorting alphabetically (critical < info <
warning), a filter that reads the wrong element id, or a row template that
silently emits an inline handler under CSP.

The two source-level classes that genuinely have no runtime (the FLEET_EVENTS
allowlist and the routing switch are both consumed only by the browser) are
still cross-checked against the SERVER's registry, which is what test_v223 /
test_v225 do for every other event.
"""

import os as _rp_os
import tempfile as _rp_tempfile

_rp_os.environ.setdefault("RP_DATA_DIR", _rp_tempfile.mkdtemp())

import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clientjs import client_js
from srcpin import balanced_block, js_function

_ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:
    _HAVE_V8 = False

_spec = importlib.util.spec_from_file_location("api_v642_attn", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


# ── V8 harness ───────────────────────────────────────────────────────────────
# Deliberately NOT the permissive proxy stub used by _jsload_harness: a proxy
# that answers every call with itself makes a broken renderer look fine. These
# doubles record calls so the test can assert on the values that were produced.
_HARNESS = r"""
var __calls = {render: [], renderChunked: [], toast: [], api: [], showPage: []};
var __dom = {};            // id -> {value, textContent, innerHTML, ...}
function __el(id, props) {
  var e = {id: id, value: '', textContent: '', innerHTML: '', children: [],
           classList: {contains: function(){ return false; }},
           replaceChildren: function(){ this.children = []; },
           add: function(o){ this.children.push(o); }};
  for (var k in (props || {})) e[k] = props[k];
  __dom[id] = e;
  return e;
}
var document = {
  getElementById: function(id) { return __dom[id] || null; },
  querySelector: function() { return null; },
  querySelectorAll: function() { return []; },
  addEventListener: function() {},
  createElement: function() { return {style: {}, classList: {add: function(){}}}; },
};
function Option(label, value) { return {label: label, value: value}; }
var tableCtl = {
  register: function(o) { __calls.register = o; },
  render: function(name, rows) { __calls.render.push({name: name, rows: rows}); },
  renderChunked: function(t, html) { __calls.renderChunked.push(html); },
  wireSortOnly: function(thead, prefs) { __calls.wire = [thead, prefs]; },
  sortRows: function(name, rows) { return rows; },
};
function toast(msg, kind) { __calls.toast.push([msg, kind]); }
function api(method, path, body) {
  __calls.api.push([method, path, body || null]);
  return Promise.resolve(__apiReply);
}
var __apiReply = null;
function showPage(name) { __calls.showPage.push(name); }
function loadDevices() {}
function setTagFilter(t) { __calls.tagFilter = t; }
function openModal() {}
function closeModal() {}
function uiConfirm() { return Promise.resolve(true); }
function uiPrompt() { return Promise.resolve(__promptReply); }
var __promptReply = null;
var _meCache = {admin: true};
function openDetail() {}
function statTiles() {}
"""


_APP_JS = _ROOT / "server" / "html" / "static" / "js" / "app.js"


def app_js():
    """The shipped app.js on its own. client_js() concatenates every module, so
    an anchor could match a same-named helper in another file."""
    return _APP_JS.read_text()


def _js_oneliner(src, name):
    """The single source LINE defining `name`. srcpin's brace scanner cannot
    walk escHtml — its body holds `/'/g`, a regex literal containing a quote,
    which the scanner reads as the start of a string and then desyncs. These
    helpers are genuinely one-liners, so the line IS the definition."""
    for line in src.splitlines():
        if line.startswith(f"function {name}("):
            return line
    raise AssertionError(f"one-line helper not found: {name}")


def _js_fn(src, name):
    """srcpin's anchor list tries `function <name>(` before
    `async function <name>(`, so for an async function it returns the body
    WITHOUT the `async` keyword — which then fails to parse on its first
    `await`. Put the keyword back when the source actually has it."""
    body = js_function(src, name)
    i = src.index(body)
    return ("async " + body) if src[max(0, i - 6):i] == "async " else body


def _js_slice(names, blocks=()):
    """Real source for the named functions (+ literal blocks), in order."""
    src = app_js()
    out = [balanced_block(src, a, o, c) + ";" for (a, o, c) in blocks]
    for n in names:
        out.append(_js_oneliner(src, n) if n in _ONELINERS
                   else _js_fn(src, n))
    return "\n".join(out)


_ONELINERS = {"escHtml", "escAttr"}


class _V8(unittest.TestCase):
    """Base: build a context holding the real helpers every renderer needs."""

    COMMON = ["escHtml", "escAttr", "_icon"]
    COMMON_BLOCKS = (("const _ICONS = ", "{", "}"),)

    def ctx(self, names, blocks=()):
        c = MiniRacer()
        c.eval(_HARNESS)
        c.eval(_js_slice(self.COMMON + list(names),
                         tuple(self.COMMON_BLOCKS) + tuple(blocks)))
        return c


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestAttentionItemRow(_V8):
    """The per-item controls are now built ONCE and shared by the Home card and
    the page — so a divergence between the two surfaces is impossible."""

    NAMES = ["_naItemButtons", "_naItemTitle"]

    def test_plain_item_gets_snooze_and_ignore_only(self):
        c = self.ctx(self.NAMES)
        html = c.eval("_naItemButtons({device:'web1', summary:'Offline',"
                      " kind:'offline', _ignore_key:'k1', device_id:'d1'})")
        self.assertIn('data-action="snoozeAttention"', html)
        self.assertIn('data-action="ignoreAttention"', html)
        # log-alert-only controls must not appear on a non-log item
        self.assertNotIn('data-action="openLogsForLogAlert"', html)
        self.assertNotIn('data-action="clearLogLine"', html)
        # no mitigation_kind on the item → no Investigate button
        self.assertNotIn('data-action="openMitigateModal"', html)

    def test_log_alert_item_gets_the_log_controls(self):
        c = self.ctx(self.NAMES)
        html = c.eval("_naItemButtons({device:'web1', summary:'oops',"
                      " kind:'log_alert', _ignore_key:'k', device_id:'d1',"
                      " unit:'nginx', pattern:'ERR', samples:['boom']})")
        self.assertIn('data-action="openLogsForLogAlert"', html)
        self.assertIn('data-action="clearLogLine"', html)

    def test_mitigable_item_gets_investigate(self):
        c = self.ctx(self.NAMES)
        html = c.eval("_naItemButtons({device:'web1', summary:'x', kind:'disk',"
                      " _ignore_key:'k', device_id:'d1',"
                      " mitigation_kind:'disk', mitigation_target:'/var'})")
        self.assertIn('data-action="openMitigateModal"', html)
        self.assertIn('data-arg3="/var"', html)

    def test_no_inline_handlers_or_styles_under_csp(self):
        c = self.ctx(self.NAMES)
        html = c.eval("_naItemButtons({device:'a', summary:'b', kind:'log_alert',"
                      " _ignore_key:'k', device_id:'d', samples:['s'], pattern:'p'})")
        for bad in ('onclick=', 'onmouseover=', 'style="'):
            self.assertNotIn(bad, html, f'CSP: {bad} in a Needs-Attention row')

    def test_hostile_device_name_cannot_break_out_of_the_attribute(self):
        c = self.ctx(self.NAMES)
        html = c.eval(
            "_naItemButtons({device:'\"><img src=x onerror=alert(1)>',"
            " summary:'s', kind:'offline', _ignore_key:'k', device_id:'d'})")
        self.assertNotIn('<img', html)
        self.assertIn('&quot;', html)

    def test_title_surfaces_every_captured_log_line(self):
        c = self.ctx(self.NAMES)
        t = c.eval("_naItemTitle({kind:'log_alert', pattern:'ERR',"
                   " samples:['one','two']})")
        self.assertIn('ERR', t)
        self.assertIn('1. one', t)
        self.assertIn('2. two', t)
        plain = c.eval("_naItemTitle({kind:'offline'})")
        self.assertEqual(plain, 'Click for details')


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestAttentionPageFilters(_V8):
    """The page's whole reason to exist is enumerating what the Home card cuts
    off, so the filters and the counts are driven with real rows."""

    NAMES = ["_naItemButtons", "_naItemTitle", "renderAttentionPage",
             "_renderAttentionCounts", "attentionFilterSeverity",
             "_fillAttentionFilterOptions", "_registerAttentionTable"]
    BLOCKS = (("const PAGE_FOR = ", "{", "}"), ("const NA_PILL = ", "{", "}"))

    ROWS = [
        {"severity": "critical", "kind": "offline", "device": "web1",
         "summary": "Offline for 30 min", "_ignore_key": "a", "device_id": "d1"},
        {"severity": "warning", "kind": "patches", "device": "web1",
         "summary": "42 updates pending", "_ignore_key": "b", "device_id": "d1"},
        {"severity": "info", "kind": "patches", "device": "db1",
         "summary": "3 updates pending", "_ignore_key": "c", "device_id": "d2"},
    ]

    def _ready(self, sev="all", kind="all", dev="all"):
        c = self.ctx(self.NAMES, self.BLOCKS)
        c.eval("__el('attention-tbody'); __el('attention-counts');")
        c.eval(f"__el('attention-sev-filter', {{value: {json.dumps(sev)}}});")
        c.eval(f"__el('attention-kind-filter', {{value: {json.dumps(kind)}}});")
        c.eval(f"__el('attention-device-filter', {{value: {json.dumps(dev)}}});")
        c.eval("var _attentionRows = " + json.dumps(self.ROWS) + ";")
        c.eval("var _attentionTotal = _attentionRows.length;")
        c.eval("var _attentionRegistered = false;")
        return c

    def _rendered(self, c):
        c.eval("renderAttentionPage()")
        calls = c.eval("JSON.stringify(__calls.render)")
        return json.loads(calls)

    def test_unfiltered_renders_every_item_not_just_ten(self):
        c = self._ready()
        rows = self._rendered(c)[-1]["rows"]
        self.assertEqual(len(rows), 3)

    def test_severity_filter_narrows_the_rows(self):
        c = self._ready(sev="critical")
        rows = self._rendered(c)[-1]["rows"]
        self.assertEqual([r["kind"] for r in rows], ["offline"])

    def test_kind_and_device_filters_compose(self):
        c = self._ready(kind="patches", dev="web1")
        rows = self._rendered(c)[-1]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["device"], "web1")
        self.assertEqual(rows[0]["severity"], "warning")

    def test_counts_are_over_the_unfiltered_set(self):
        # Filtering to one severity must NOT rewrite the headline counts —
        # they are what tells the operator what else is waiting.
        c = self._ready(sev="critical")
        c.eval("renderAttentionPage()")
        html = c.eval("__dom['attention-counts'].innerHTML")
        self.assertIn('data-arg="critical"', html)
        self.assertIn('data-arg="warning"', html)
        self.assertIn('data-arg="info"', html)
        # one of each severity in ROWS, three in total
        self.assertEqual(html.count('status-pill'), 4)

    def test_count_chip_sets_the_severity_filter(self):
        c = self._ready()
        c.eval("attentionFilterSeverity('warning')")
        self.assertEqual(c.eval("__dom['attention-sev-filter'].value"), "warning")
        rows = json.loads(c.eval("JSON.stringify(__calls.render)"))[-1]["rows"]
        self.assertEqual([r["severity"] for r in rows], ["warning"])

    def test_severity_sorts_by_rank_not_alphabetically(self):
        # The trap this pins: 'critical' < 'info' < 'warning' as strings, which
        # would put the least urgent rows first on the first click.
        c = self._ready()
        c.eval("_registerAttentionTable(); renderAttentionPage()")
        self.assertIsNotNone(c.eval("__calls.register"))
        crit = c.eval("__calls.register.getColumns({severity:'critical'}).severity")
        warn = c.eval("__calls.register.getColumns({severity:'warning'}).severity")
        info = c.eval("__calls.register.getColumns({severity:'info'}).severity")
        self.assertGreater(crit, warn)
        self.assertGreater(warn, info)

    def test_filter_options_only_offer_values_that_occur(self):
        c = self._ready()
        c.eval("_fillAttentionFilterOptions()")
        kinds = json.loads(c.eval(
            "JSON.stringify(__dom['attention-kind-filter'].children)"))
        self.assertEqual([o["value"] for o in kinds], ["all", "offline", "patches"])
        devs = json.loads(c.eval(
            "JSON.stringify(__dom['attention-device-filter'].children)"))
        self.assertEqual([o["value"] for o in devs], ["all", "db1", "web1"])

    def test_a_still_present_selection_survives_a_refresh(self):
        c = self._ready(kind="patches")
        c.eval("_fillAttentionFilterOptions()")
        self.assertEqual(c.eval("__dom['attention-kind-filter'].value"), "patches")

    def test_a_vanished_selection_resets_to_all(self):
        # The kind was fixed between polls; keeping a now-empty filter would
        # show an empty page with no explanation.
        c = self._ready(kind="drift")
        c.eval("_fillAttentionFilterOptions()")
        self.assertEqual(c.eval("__dom['attention-kind-filter'].value"), "all")

    def test_row_template_escapes_and_stays_csp_clean(self):
        c = self._ready()
        c.eval("_registerAttentionTable(); renderAttentionPage()")
        html = c.eval("__calls.register.row("
                      "{severity:'critical', kind:'offline',"
                      " device:'<script>x</script>', summary:'a\"b',"
                      " _ignore_key:'k', device_id:'d'})")
        self.assertNotIn('<script>', html)
        self.assertNotIn('onclick=', html)
        self.assertNotIn('style="', html)
        self.assertIn('data-action-btn="_showPageBtn"', html)

    def test_loader_noops_without_the_page_shell(self):
        # Another agent owns index.html; a missing shell must not throw and
        # take the rest of the page's JS down with it.
        c = self.ctx(self.NAMES, self.BLOCKS)
        c.eval("var _attentionRows = []; var _attentionTotal = 0;")
        c.eval("var _attentionRegistered = false;")
        c.eval("renderAttentionPage()")   # no __el() calls → every lookup null
        self.assertEqual(json.loads(c.eval("JSON.stringify(__calls.render)")), [])


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestAttentionRoutingTable(_V8):
    """PAGE_FOR is now shared by the card and the page — one table, so a kind
    can never route one way from the dashboard and another way from the list."""

    def test_every_route_target_is_a_real_page(self):
        c = MiniRacer()
        c.eval(balanced_block(client_js(), "const PAGE_FOR = ", "{", "}") + ";")
        pages = json.loads(c.eval("JSON.stringify(Object.values(PAGE_FOR))"))
        html = (_ROOT / "server/html/index.html").read_text()
        for p in sorted(set(pages)):
            self.assertIn(f'id="page-{p}"', html,
                          f"PAGE_FOR routes to a page that does not exist: {p}")

    def test_severity_pill_classes_are_real_status_pill_variants(self):
        c = MiniRacer()
        c.eval(balanced_block(client_js(), "const NA_PILL = ", "{", "}") + ";")
        css = (_ROOT / "server/html/static/css/styles.css").read_text()
        for v in json.loads(c.eval("JSON.stringify(Object.values(NA_PILL))")):
            self.assertIn(f".status-pill.{v}", css,
                          f"NA_PILL maps to an unstyled pill variant: {v}")

    def test_every_attention_kind_the_server_emits_is_routed(self):
        # A kind with no PAGE_FOR entry silently falls back to the dashboard,
        # so the click-through lands nowhere useful.
        c = MiniRacer()
        c.eval(balanced_block(client_js(), "const PAGE_FOR = ", "{", "}") + ";")
        known = set(json.loads(c.eval("JSON.stringify(Object.keys(PAGE_FOR))")))
        src = (_CGI_BIN / "api.py").read_text()
        import re
        body = src[src.index("def _compute_attention("):]
        body = body[:body.index("\ndef ", 10)]
        emitted = set(re.findall(r"'kind':\s*'([a-z_]+)'", body))
        self.assertTrue(emitted, "could not read the emitted NA kinds")
        self.assertEqual(emitted - known, set(),
                         "NA kinds emitted by the server with no PAGE_FOR route")


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestHomeCardLinksToTheFullList(_V8):
    """The card's ten-item cut-off was the actual defect: no total, no way on."""

    NAMES = ["_naItemButtons", "_naItemTitle", "_renderHomeAttention"]
    BLOCKS = (("const PAGE_FOR = ", "{", "}"), ("const NA_PILL = ", "{", "}"))

    def _render(self, n_items, total=None):
        c = self.ctx(self.NAMES, self.BLOCKS)
        c.eval("__el('home-attention');")
        c.eval("var _attentionRows = []; var _attentionTotal = 0;")
        items = [{"severity": "warning", "kind": "patches", "device": f"h{i}",
                  "summary": "x", "_ignore_key": f"k{i}", "device_id": f"d{i}"}
                 for i in range(n_items)]
        payload = {"items": items,
                   "total": total if total is not None else n_items}
        c.eval("_renderHomeAttention(" + json.dumps(payload) + ")")
        return c

    def test_card_still_shows_at_most_ten_rows(self):
        c = self._render(25)
        html = c.eval("__dom['home-attention'].innerHTML")
        self.assertEqual(html.count('data-action="ignoreAttention"'), 10)

    def test_card_names_the_hidden_remainder_and_links_to_the_page(self):
        c = self._render(25)
        html = c.eval("__dom['home-attention'].innerHTML")
        self.assertIn('15 more items not shown', html)
        self.assertIn('data-page="attention"', html)

    def test_short_list_still_offers_the_full_page(self):
        c = self._render(3)
        html = c.eval("__dom['home-attention'].innerHTML")
        self.assertIn('3 open items', html)
        self.assertIn('data-page="attention"', html)

    def test_card_warms_the_page_cache(self):
        # Opening the page after the dashboard has loaded must not blank out.
        c = self._render(4)
        self.assertEqual(c.eval("_attentionRows.length"), 4)
        self.assertEqual(c.eval("_attentionTotal"), 4)

    def test_empty_digest_keeps_the_all_clear_state(self):
        c = self._render(0)
        html = c.eval("__dom['home-attention'].innerHTML")
        self.assertIn('All clear', html)
        self.assertNotIn('data-page="attention"', html)


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestTaxonomyCounts(_V8):
    """Counts are derived from the device list the caller can already see, so
    they inherit its scope filtering — assert on what the renderer produces."""

    NAMES = ["_renderTaxonomy", "_taxonomyDeviceIdsWithTag", "_taxonomyTagNames",
             "_taxonomyCleanTag", "showDevicesForTag", "showDevicesForGroup"]

    DEVS = [
        {"id": "d1", "name": "web1", "group": "prod", "tags": ["web", "eu"]},
        {"id": "d2", "name": "web2", "group": "prod", "tags": ["web"]},
        {"id": "d3", "name": "db1", "group": "", "tags": []},
        {"id": "d4", "name": "db2", "group": "staging", "tags": ["eu"]},
    ]

    def _ready(self):
        c = self.ctx(self.NAMES)
        c.eval("__el('taxonomy-tags-tbody'); __el('taxonomy-groups-tbody');")
        c.eval("__el('taxonomy-summary'); __el('device-search-input');")
        c.eval("var _taxonomyDevices = " + json.dumps(self.DEVS) + ";")
        return c

    def _tables(self, c):
        c.eval("_renderTaxonomy()")
        calls = json.loads(c.eval("JSON.stringify(__calls.render)"))
        return {x["name"]: x["rows"] for x in calls}

    def test_tag_counts_are_per_device_occurrences(self):
        t = self._tables(self._ready())["taxonomy_tags"]
        self.assertEqual({r["name"]: r["device_count"] for r in t},
                         {"web": 2, "eu": 2})

    def test_group_counts_ignore_ungrouped_devices(self):
        g = self._tables(self._ready())["taxonomy_groups"]
        self.assertEqual({r["name"]: r["device_count"] for r in g},
                         {"prod": 2, "staging": 1})

    def test_rows_are_ordered_by_device_count_then_name(self):
        g = self._tables(self._ready())["taxonomy_groups"]
        self.assertEqual([r["name"] for r in g], ["prod", "staging"])

    def test_summary_reports_ungrouped_and_untagged(self):
        c = self._ready()
        c.eval("_renderTaxonomy()")
        txt = c.eval("__dom['taxonomy-summary'].textContent")
        self.assertIn("4 device(s)", txt)
        self.assertIn("2 group(s)", txt)
        self.assertIn("1 ungrouped", txt)
        self.assertIn("2 tag(s)", txt)
        self.assertIn("1 untagged", txt)

    def test_tag_lookup_returns_the_right_device_ids(self):
        c = self._ready()
        ids = json.loads(c.eval("JSON.stringify(_taxonomyDeviceIdsWithTag('eu'))"))
        self.assertEqual(sorted(ids), ["d1", "d4"])

    def test_a_numeric_tag_name_survives_the_data_arg_number_coercion(self):
        # The data-action dispatcher turns a numeric-looking data-arg into a
        # Number, so a tag literally named "2024" arrives as 2024.
        c = self.ctx(self.NAMES)
        c.eval("var _taxonomyDevices = [{id:'d1', name:'a', tags:['2024']}];")
        ids = json.loads(c.eval("JSON.stringify(_taxonomyDeviceIdsWithTag(2024))"))
        self.assertEqual(ids, ["d1"])

    def test_clean_tag_mirrors_the_server_charset_rule(self):
        c = self.ctx(self.NAMES)
        self.assertEqual(c.eval("_taxonomyCleanTag('prod team!')"), "prodteam")
        self.assertEqual(c.eval("_taxonomyCleanTag('a-b_c/d')"), "a-b_c/d")
        self.assertEqual(c.eval("_taxonomyCleanTag('***')"), "")

    def test_show_devices_drills_through_to_the_devices_page(self):
        c = self._ready()
        c.eval("showDevicesForTag('eu')")
        self.assertEqual(c.eval("__calls.tagFilter"), "eu")
        self.assertEqual(json.loads(c.eval("JSON.stringify(__calls.showPage)")),
                         ["devices"])
        c.eval("showDevicesForGroup('prod')")
        self.assertEqual(c.eval("__dom['device-search-input'].value"), "prod")

    def test_render_noops_without_the_page_shell(self):
        c = self.ctx(self.NAMES)
        c.eval("var _taxonomyDevices = " + json.dumps(self.DEVS) + ";")
        c.eval("_renderTaxonomy()")
        self.assertEqual(json.loads(c.eval("JSON.stringify(__calls.render)")), [])


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestTaxonomyWrites(_V8):
    """Tag rename / merge / delete ride the ONE shipped bulk endpoint, so the
    rewrite is a single server-side locked read-modify-write."""

    NAMES = ["_taxonomyCleanTag", "_taxonomyDeviceIdsWithTag", "_taxonomyTagNames",
             "_taxonomyBulkTags", "renameTag", "mergeTag", "deleteTag",
             "_renderTaxonomy", "loadTaxonomy"]

    DEVS = [
        {"id": "d1", "name": "web1", "group": "prod", "tags": ["web", "eu"]},
        {"id": "d2", "name": "web2", "group": "prod", "tags": ["web"]},
    ]

    def _ready(self, prompt_reply):
        c = self.ctx(self.NAMES)
        c.eval("__el('taxonomy-tags-tbody'); __el('taxonomy-groups-tbody');")
        c.eval("__el('taxonomy-summary');")
        c.eval("var _taxonomyDevices = " + json.dumps(self.DEVS) + ";")
        c.eval("__promptReply = " + json.dumps(prompt_reply) + ";")
        c.eval("__apiReply = {ok: true, updated: 2};")
        return c

    def _bulk_call(self, c):
        calls = json.loads(c.eval("JSON.stringify(__calls.api)"))
        bulk = [x for x in calls if x[1] == "/devices/bulk-tags"]
        self.assertTrue(bulk, f"no bulk-tags call was made; saw {calls}")
        return bulk[0]

    def test_rename_sends_one_bulk_request_with_add_and_remove(self):
        c = self._ready("prodweb")
        c.eval("renameTag('web')")
        c.eval("")   # let the promise chain settle
        method, path, body = self._bulk_call(c)
        self.assertEqual(method, "POST")
        self.assertEqual(sorted(body["device_ids"]), ["d1", "d2"])
        self.assertEqual(body["add"], ["prodweb"])
        self.assertEqual(body["remove"], ["web"])

    def test_rename_applies_the_server_charset_rule_before_sending(self):
        c = self._ready("prod web!")
        c.eval("renameTag('web')")
        _, _, body = self._bulk_call(c)
        self.assertEqual(body["add"], ["prodweb"])

    def test_rename_to_an_empty_name_is_refused_not_sent(self):
        c = self._ready("***")
        c.eval("renameTag('web')")
        calls = json.loads(c.eval("JSON.stringify(__calls.api)"))
        self.assertEqual([x for x in calls if x[1] == "/devices/bulk-tags"], [])
        self.assertTrue(json.loads(c.eval("JSON.stringify(__calls.toast)")))

    def test_cancelling_the_prompt_sends_nothing(self):
        c = self._ready(None)
        c.eval("renameTag('web')")
        self.assertEqual(json.loads(c.eval("JSON.stringify(__calls.api)")), [])

    def test_merge_moves_only_the_source_tags_devices(self):
        c = self._ready("eu")
        c.eval("mergeTag('web')")
        _, _, body = self._bulk_call(c)
        self.assertEqual(sorted(body["device_ids"]), ["d1", "d2"])
        self.assertEqual(body["add"], ["eu"])
        self.assertEqual(body["remove"], ["web"])

    def test_delete_removes_without_adding(self):
        c = self._ready(None)
        c.eval("deleteTag('eu')")
        _, _, body = self._bulk_call(c)
        self.assertEqual(body["device_ids"], ["d1"])
        self.assertEqual(body["add"], [])
        self.assertEqual(body["remove"], ["eu"])

    def test_the_bulk_endpoint_this_ui_calls_actually_exists(self):
        # A client-only feature is the classic dead end — pin the route.
        self.assertIn(("POST", "/api/devices/bulk-tags"),
                      set(api._build_exact_routes().keys()))

    def test_groups_offer_the_three_write_actions_and_their_routes_exist(self):
        """Groups were read-only here until v6.4.2 for a real reason: the only
        primitive was PATCH-per-device, which can half-apply and leave a group
        split across two names. `/api/taxonomy/groups/*` is a single atomic
        read-modify-write, so the actions are now correct — this test is the
        positive inverse of the one that guarded the old state.

        Both halves are pinned: the buttons exist AND the routes they call are
        registered. Either alone is a dead end.
        """
        src = client_js()
        row = js_function(src, "_registerTaxonomyTables")
        groups = row[row.index("name: 'taxonomy_groups'"):]
        for act in ('renameGroup', 'mergeGroup', 'deleteGroup'):
            self.assertIn(act, groups,
                          f"the groups table is missing the {act} write action")
        routes = set(api._build_exact_routes().keys())
        for p in ('/api/taxonomy/groups/rename', '/api/taxonomy/groups/merge',
                  '/api/taxonomy/groups/delete'):
            self.assertIn(('POST', p), routes,
                          f"{p} is not registered — the button is a dead end")

    def test_group_writes_do_not_go_through_the_tag_bulk_helper(self):
        """The point of the endpoint is that there is no client-side loop; a
        group op routed through _taxonomyBulkTags would reintroduce one."""
        src = client_js()
        for fn in ('renameGroup', 'mergeGroup', 'deleteGroup'):
            body = js_function(src, fn)
            self.assertNotIn('_taxonomyBulkTags', body,
                             f"{fn} must call the atomic group endpoint")
            self.assertIn('_taxonomyGroupOp', body)


class TestNewFleetEvents(unittest.TestCase):
    """Both halves of a new event must land or it vanishes from the feed."""

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()
        cls.events = balanced_block(cls.js, "const FLEET_EVENTS = new Set(", "(", ")")
        cls.attrs = js_function(cls.js, "_homeActivityAttrs")

    def test_new_events_exist_in_the_server_registry(self):
        for ev in ("device_enrolled", "control_plane_security_change"):
            self.assertIn(ev, api.EVENT_REGISTRY,
                          f"{ev} is routed client-side but the server never fires it")

    def test_new_events_are_in_the_dashboard_allowlist(self):
        for ev in ("device_enrolled", "control_plane_security_change"):
            self.assertIn(f"'{ev}'", self.events,
                          f"{ev} would be filtered out of the activity feed")

    def test_new_events_have_a_click_through_route(self):
        for ev in ("device_enrolled", "control_plane_security_change"):
            self.assertIn(f"case '{ev}'", self.attrs,
                          f"{ev} falls through to the default route")

    def test_control_plane_change_routes_to_the_audit_log(self):
        # It has no device_id by construction — the audit log holds the actor.
        i = self.attrs.index("case 'control_plane_security_change':")
        self.assertIn('data-home-act="audit"', self.attrs[i:i + 200])

    def test_device_enrolled_opens_the_new_device(self):
        i = self.attrs.index("case 'device_enrolled':")
        self.assertIn("'detail'", self.attrs[i:i + 220])

    def test_allowlist_still_equals_the_server_event_set(self):
        import re
        js_set = set(re.findall(r"'([^']+)'", self.events))
        self.assertEqual(js_set, set(api.WEBHOOK_EVENT_NAMES))


class TestPagesAreReachable(unittest.TestCase):
    """A loader nobody calls is the same as no loader."""

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()
        cls.show = js_function(cls.js, "showPage")

    def test_showpage_dispatches_both_new_pages(self):
        self.assertIn("loadAttentionPage()", self.show)
        self.assertIn("loadTaxonomy()", self.show)

    def test_the_loaders_hit_endpoints_that_exist(self):
        routes = set(api._build_exact_routes().keys()) | set(api._dispatcher_routes())
        self.assertIn(("GET", "/api/attention"), routes)
        self.assertIn(("GET", "/api/devices"), routes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
