"""v6.4.2 — app.js core UI behaviour.

These tests EXECUTE the functions they cover. app.js is browser code, so each
test extracts the function under test with srcpin and evaluates it in V8
(py_mini_racer) against a purpose-built DOM shim defined below — small enough
to read, real enough that a wrong class name, a wrong selector or a missing
insert shows up as a failing assertion instead of a green grep.

The shim's selector matcher supports exactly `tag`, `#id`, `.a.b`, `[attr]`,
`[attr="v"]` and the descendant combinator; nothing here relies on anything
more exotic.

Covers:
  1. failed-load error states (_errorState / uiRetry, plus the loaders wired to them)
  2. the command palette's page index (_palettePages, derived from the nav)
  3. mid-session bare-page-hash routing (_routeBarePageHash)
  4. destructive-confirmation styling (uiConfirm danger)
  5. zero-match filter state (filterRows / _filterRowsNoMatch)
  6. in-app-language date formatting (_localeTag / _fmtAbs*)
  7. first-run password nudge routing (gotoPasswordChange)
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from srcpin import balanced_block, js_function  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "server" / "html" / "static" / "js" / "app.js"
I18N_JS = ROOT / "server" / "html" / "static" / "js" / "i18n.js"
INDEX = ROOT / "server" / "html" / "index.html"


def app_js():
    return APP_JS.read_text()


def index_html():
    return INDEX.read_text()


def page_ids():
    """Every `id="page-<x>"` in index.html — the set showPage() can reach."""
    return set(re.findall(r'id="page-([A-Za-z0-9_-]+)"', index_html()))


def nav_entries():
    """[(page, label)] for every sidebar .nav-btn[data-page] in index.html."""
    out = []
    for m in re.finditer(
            r'<button[^>]*class="nav-btn[^"]*"[^>]*data-page="([A-Za-z0-9_-]+)"[^>]*>(.*?)</button>',
            index_html(), re.S):
        page, inner = m.group(1), m.group(2)
        spans = re.findall(r'<span(?![^>]*nav-badge)[^>]*>([^<]*)</span>', inner)
        out.append((page, spans[0].strip() if spans else ''))
    return out


# ── the DOM shim ────────────────────────────────────────────────────────────
DOM_SHIM = r"""
function _splitSelector(sel) { return String(sel).trim().split(/\s+/).filter(Boolean); }
function _parseSimple(part) {
  const out = { tag: null, id: null, classes: [], attrs: [] };
  const attrRe = /\[([A-Za-z-]+)(?:=("([^"]*)"|'([^']*)'|[^\]]*))?\]/g;
  let m;
  while ((m = attrRe.exec(part))) {
    let v = m[2];
    if (v !== undefined) v = (m[3] !== undefined) ? m[3] : (m[4] !== undefined ? m[4] : v);
    out.attrs.push([m[1], v]);
  }
  const rest = part.replace(attrRe, '');
  for (const h of rest.split(/(?=[.#])/)) {
    if (!h) continue;
    if (h[0] === '#') out.id = h.slice(1);
    else if (h[0] === '.') out.classes.push(h.slice(1));
    else out.tag = h.toUpperCase();
  }
  return out;
}
function _matchSimple(el, s) {
  if (s.tag && el.tagName !== s.tag) return false;
  if (s.id && el.id !== s.id) return false;
  for (const c of s.classes) if (!el.classList.contains(c)) return false;
  for (const kv of s.attrs) {
    const have = el.getAttribute(kv[0]);
    if (have === null || have === undefined) return false;
    if (kv[1] !== undefined && String(have) !== String(kv[1])) return false;
  }
  return true;
}
function _matches(el, sel) {
  const parts = _splitSelector(sel).map(_parseSimple);
  if (!_matchSimple(el, parts[parts.length - 1])) return false;
  let node = el.parentNode;
  for (let i = parts.length - 2; i >= 0; i--) {
    let ok = false;
    while (node) {
      if (_matchSimple(node, parts[i])) { ok = true; node = node.parentNode; break; }
      node = node.parentNode;
    }
    if (!ok) return false;
  }
  return true;
}
function ClassList(el) { this._el = el; this._set = []; }
ClassList.prototype.contains = function (c) { return this._set.indexOf(c) >= 0; };
ClassList.prototype.add = function () {
  for (const c of arguments) if (c && this._set.indexOf(c) < 0) this._set.push(c);
};
ClassList.prototype.remove = function () {
  for (const c of arguments) { const i = this._set.indexOf(c); if (i >= 0) this._set.splice(i, 1); }
};
ClassList.prototype.toggle = function (c, force) {
  const want = (force === undefined) ? !this.contains(c) : !!force;
  if (want) this.add(c); else this.remove(c);
  return want;
};
ClassList.prototype.toString = function () { return this._set.join(' '); };
function El(tag) {
  this.tagName = String(tag).toUpperCase();
  this.childNodes = []; this.parentNode = null;
  this._attrs = {}; this.dataset = {}; this.classList = new ClassList(this);
  this._text = ''; this._listeners = {};
  this.scrolledIntoView = false; this.focused = false; this.clicks = 0; this.value = '';
}
Object.defineProperty(El.prototype, 'children',
  { get: function () { return this.childNodes.filter(n => n instanceof El); } });
Object.defineProperty(El.prototype, 'className', {
  get: function () { return this.classList.toString(); },
  set: function (v) { this.classList._set = String(v).split(/\s+/).filter(Boolean); } });
Object.defineProperty(El.prototype, 'id', {
  get: function () { return this._attrs.id || ''; },
  set: function (v) { this._attrs.id = String(v); } });
Object.defineProperty(El.prototype, 'firstChild',
  { get: function () { return this.childNodes.length ? this.childNodes[0] : null; } });
Object.defineProperty(El.prototype, 'textContent', {
  get: function () {
    if (!this.childNodes.length) return this._text;
    return this.childNodes.map(n => (n instanceof El) ? n.textContent : n.data).join('');
  },
  set: function (v) { this.childNodes = []; this._text = String(v); } });
Object.defineProperty(El.prototype, 'colSpan', {
  get: function () { return parseInt(this._attrs.colspan || '1', 10); },
  set: function (v) { this._attrs.colspan = String(v); } });
Object.defineProperty(El.prototype, 'innerHTML', {
  get: function () { return this._html === undefined ? '' : this._html; },
  set: function (v) { this._html = String(v); this.childNodes = []; this._text = ''; } });
El.prototype.setAttribute = function (k, v) {
  this._attrs[k] = String(v);
  if (k === 'class') this.className = v;
  if (k.indexOf('data-') === 0)
    this.dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(v);
};
El.prototype.getAttribute = function (k) {
  if (k in this._attrs) return this._attrs[k];
  if (k.indexOf('data-') === 0) {
    const key = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (key in this.dataset) return this.dataset[key];
  }
  if (k === 'class') return this.classList.toString();
  return null;
};
El.prototype.appendChild = function (n) {
  if (n.parentNode) n.parentNode.removeChild(n);
  n.parentNode = this; this.childNodes.push(n); this._text = ''; return n;
};
El.prototype.insertBefore = function (n, ref) {
  if (n.parentNode) n.parentNode.removeChild(n);
  n.parentNode = this;
  const i = ref ? this.childNodes.indexOf(ref) : -1;
  if (i < 0) this.childNodes.push(n); else this.childNodes.splice(i, 0, n);
  return n;
};
El.prototype.removeChild = function (n) {
  const i = this.childNodes.indexOf(n);
  if (i >= 0) this.childNodes.splice(i, 1);
  n.parentNode = null; return n;
};
El.prototype._walk = function (out) {
  for (const c of this.childNodes) { if (!(c instanceof El)) continue; out.push(c); c._walk(out); }
  return out;
};
El.prototype.querySelectorAll = function (sel) {
  return this._walk([]).filter(e => _matches(e, sel));
};
El.prototype.querySelector = function (sel) {
  const r = this.querySelectorAll(sel); return r.length ? r[0] : null;
};
El.prototype.closest = function (sel) {
  let n = this; while (n) { if (_matches(n, sel)) return n; n = n.parentNode; } return null;
};
El.prototype.addEventListener = function (ev, fn) {
  (this._listeners[ev] = this._listeners[ev] || []).push(fn);
};
El.prototype.click = function () {
  this.clicks++;
  for (const fn of (this._listeners.click || [])) fn.call(this, { target: this });
};
El.prototype.scrollIntoView = function () { this.scrolledIntoView = true; };
El.prototype.focus = function () { this.focused = true; };
function TextNode(data) { this.data = String(data); this.parentNode = null; }
var document = new El('document');
document.createElement = function (t) { return new El(t); };
document.createTextNode = function (d) { return new TextNode(d); };
document.getElementById = function (id) {
  for (const e of document._walk([])) if (e.id === id) return e;
  return null;
};
document.body = new El('body');
document.appendChild(document.body);
function build(spec, parent) {
  const el = new El(spec.tag || 'div');
  if (spec.id) el.id = spec.id;
  if (spec.cls) el.className = spec.cls;
  for (const k in (spec.attrs || {})) el.setAttribute(k, spec.attrs[k]);
  if (spec.text !== undefined) el.textContent = spec.text;
  (parent || document.body).appendChild(el);
  for (const k of (spec.kids || [])) build(k, el);
  return el;
}
// ambient browser globals the functions under test touch
var window = { RPi18n: { current: 'en' } };
var location = { hash: '' };
var _CALLS = [];
function _rec(name) { return function () { _CALLS.push([name].concat([].slice.call(arguments))); }; }
var setTimeout = function (fn) { fn(); return 0; };
var escHtml = function (s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
};
var _icon = function () { return '<svg></svg>'; };
"""


def _ctx(*fn_names, extra=""):
    """A V8 context holding the DOM shim plus the named app.js functions."""
    src = app_js()
    ctx = MiniRacer()
    ctx.eval(DOM_SHIM)
    for name in fn_names:
        ctx.eval(js_function(src, name))
    if extra:
        ctx.eval(extra)
    return ctx


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestErrorStates(unittest.TestCase):
    """1. A failed data load must leave a Retry in the panel, not just a toast."""

    def test_error_state_renders_a_working_retry(self):
        ctx = _ctx("_errorState", "uiRetry", extra="""
          var _retryReg = {}, _retrySeq = 0, retried = 0;
          build({ tag: 'div', id: 'box' });
        """)
        # _errorState/uiRetry close over the module-level registry, so re-declare
        # it above and re-evaluate them against it.
        ctx.eval(js_function(app_js(), "_errorState"))
        ctx.eval(js_function(app_js(), "uiRetry"))
        ctx.eval("_errorState('box', function () { retried++; }, {msg: 'Failed to load devices.'});")
        html = ctx.eval("document.getElementById('box').innerHTML")
        self.assertIn("Failed to load devices.", html)
        self.assertIn('data-action="uiRetry"', html)
        key = re.search(r'data-arg="(r\d+)"', html)
        self.assertIsNotNone(key, f"no retry key in {html}")
        ctx.eval(f"uiRetry('{key.group(1)}')")
        self.assertEqual(ctx.eval("retried"), 1, "Retry did not re-invoke the loader")
        # one-shot: the registry entry is consumed so a stale DOM can't re-fire
        ctx.eval(f"uiRetry('{key.group(1)}')")
        self.assertEqual(ctx.eval("retried"), 1)

    def test_error_state_in_a_tbody_spans_the_table(self):
        ctx = _ctx("_errorState", extra="""
          var _retryReg = {}, _retrySeq = 0;
          build({ tag: 'tbody', id: 'tb' });
        """)
        ctx.eval(js_function(app_js(), "_errorState"))
        ctx.eval("_errorState('tb', function(){}, {colspan: 5});")
        html = ctx.eval("document.getElementById('tb').innerHTML")
        self.assertIn('colspan="5"', html)
        self.assertIn("<tr>", html)

    def test_core_loaders_are_wired_to_an_error_state(self):
        """The wiring half — each loader's own body must reference _errorState.

        (Driving these end to end would need the whole api()/tableCtl stack;
        this asserts the call is present in the specific function, extracted by
        srcpin, not merely somewhere in the 27k-line file.)
        """
        src = app_js()
        for fn in ("loadDevices", "loadHome", "loadUsers", "loadAuditLog",
                   "loadRoles", "loadCommandQueue", "loadConfirmations",
                   "loadInboundWebhooks", "loadRisk", "loadProcesses",
                   "loadListeningPorts", "loadBatchJobs", "loadIntegrationsPage"):
            self.assertIn("_errorState(", js_function(src, fn),
                          f"{fn} still fails a load with no inline Retry")

    def test_error_state_call_sites_grew_beyond_the_modules(self):
        """app.js had ZERO of the 17 _errorState call sites before v6.4.2."""
        n = len(re.findall(r"_errorState\(", app_js()))
        # 1 definition + 1 doc reference in the comment block + the call sites
        self.assertGreaterEqual(n, 13, "core-loader error states regressed")


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestPalettePageIndex(unittest.TestCase):
    """2. Ctrl-K "Go to page" is derived from the nav and cannot drift."""

    def _run(self, entries, extra_specs=()):
        kids = []
        for page, label, cls in entries:
            kids.append({"tag": "button", "cls": cls, "attrs": {"data-page": page},
                         "kids": [{"tag": "svg"}, {"tag": "span", "text": label}]})
        ctx = _ctx("_palettePages", extra="""
          var PALETTE_PAGE_ALIASES = %s;
        """ % _aliases_literal())
        ctx.eval(js_function(app_js(), "_palettePages"))
        ctx.eval("build(%s);" % _json(
            {"tag": "div", "id": "sidebar", "kids": kids + list(extra_specs)}))
        return ctx.eval("JSON.stringify(_palettePages())")

    def test_every_palette_target_is_a_real_page(self):
        import json
        entries = [(p, lbl or p, "nav-btn") for p, lbl in nav_entries()]
        out = json.loads(self._run(entries))
        pages = page_ids()
        for label, page in out:
            self.assertIn(page, pages,
                          f"palette entry {label!r} routes to #{page}, which has no "
                          f'id="page-{page}" in index.html')
            self.assertTrue(label, f"palette entry for {page} has an empty label")

    def test_the_dead_ansible_entry_is_gone(self):
        self.assertNotIn("ansible", page_ids(),
                         "index.html grew a page-ansible; revisit the palette")
        self.assertNotIn("ansible", {p for _, p in nav_entries()})
        self.assertNotIn("ansible", {p for _, p in _alias_pairs()},
                         "the removed Ansible palette entry came back as an alias")
        self.assertNotIn("['Ansible', 'ansible']", app_js(),
                         "the hand-maintained palette array came back")

    def test_pages_missing_from_the_old_hardcoded_array_are_reachable(self):
        import json
        entries = [(p, lbl or p, "nav-btn") for p, lbl in nav_entries()]
        got = {p for _, p in json.loads(self._run(entries))}
        # the 16 nav destinations the hand-maintained array had drifted past
        for page in ("kb", "kmip", "vpn", "tuning", "contacts", "billing",
                     "board", "catalog", "cron", "files", "netmetrics",
                     "protect", "provisioning", "tickets", "timesheet", "advisory"):
            self.assertIn(page, got, f"{page} is still unreachable from the palette")

    def test_module_gated_and_pinned_clones_are_excluded(self):
        import json
        entries = [("home", "Dashboard", "nav-btn"),
                   ("kb", "Knowledge base", "nav-btn d-none")]
        clone = {"tag": "div", "id": "nav-favorites", "kids": [
            {"tag": "button", "cls": "nav-btn", "attrs": {"data-page": "home"},
             "kids": [{"tag": "span", "text": "Dashboard"}]}]}
        out = json.loads(self._run(entries, [clone]))
        pages = [p for _, p in out]
        self.assertNotIn("kb", pages, "a switched-off module is still offered")
        self.assertEqual(pages.count("home"), 1, "pinned clone listed the page twice")

    def test_curated_aliases_survive_and_point_at_real_pages(self):
        import json
        entries = [(p, lbl or p, "nav-btn") for p, lbl in nav_entries()]
        out = json.loads(self._run(entries))
        by_label = {lbl: pg for lbl, pg in out}
        for label, page in (("Fleet Query", "query"), ("Network Map", "netmap"),
                            ("Command Library", "cmdlib"), ("Monitoring", "monitor")):
            self.assertEqual(by_label.get(label), page,
                             f"curated palette alias {label!r} was lost")
        for _, page in _alias_pairs():
            self.assertIn(page, page_ids(),
                          f"alias points at #{page}, which is not a real page")

    def test_alias_for_a_gated_page_is_gated_too(self):
        import json
        out = json.loads(self._run([("query", "Query", "nav-btn d-none")]))
        self.assertEqual(out, [], "an alias leaked a switched-off page back in")


def _alias_pairs():
    block = balanced_block(app_js(), "const PALETTE_PAGE_ALIASES = ", "[", "]")
    return re.findall(r"\['([^']+)',\s*'([^']+)'\]", block)


def _aliases_literal():
    return "[" + ",".join("['%s','%s']" % p for p in _alias_pairs()) + "]"


def _json(obj):
    import json
    return json.dumps(obj)


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestBarePageHashRouting(unittest.TestCase):
    """3. A page hash pasted into a running tab must actually navigate."""

    def _ctx(self, active="home", pages=("home", "thermal", "risk", "settings")):
        kids = [{"tag": "div", "id": "page-" + p,
                 "cls": "page active" if p == active else "page"} for p in pages]
        ctx = _ctx("_routeBarePageHash", extra="""
          var shown = [], tabs = [];
          function showPage(n, b) { shown.push(n); }
          function switchSettingsTab(t) { tabs.push(t); }
        """)
        ctx.eval(js_function(app_js(), "_routeBarePageHash"))
        ctx.eval("build(%s);" % _json({"tag": "div", "id": "app", "kids": kids}))
        return ctx

    def test_bare_hash_navigates(self):
        ctx = self._ctx()
        ctx.eval("location.hash = '#thermal'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("JSON.stringify(shown)"), '["thermal"]')

    def test_lazy_page_template_counts_as_known(self):
        ctx = self._ctx(pages=("home",))
        ctx.eval("build({tag:'template', attrs:{'data-page-tpl':'risk'}});")
        ctx.eval("location.hash = '#risk'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("JSON.stringify(shown)"), '["risk"]')

    def test_unknown_page_is_ignored(self):
        ctx = self._ctx()
        ctx.eval("location.hash = '#nope'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("shown.length"), 0)

    def test_device_and_alert_deep_links_are_left_to_their_own_handlers(self):
        ctx = self._ctx()
        for h in ("#device/abc", "#devices?view=x", "#alerts/a1b2"):
            ctx.eval(f"location.hash = '{h}'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("shown.length"), 0,
                         "bare-hash routing stole a dedicated deep link")

    def test_settings_subtab_is_honoured(self):
        ctx = self._ctx()
        ctx.eval("location.hash = '#settings/notifs'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("JSON.stringify(shown)"), '["settings"]')
        self.assertEqual(ctx.eval("JSON.stringify(tabs)"), '["notifs"]')

    def test_already_on_the_page_does_not_re_navigate(self):
        """showPage re-runs the page's loaders; the hash sync must not loop."""
        ctx = self._ctx(active="thermal")
        ctx.eval("location.hash = '#thermal'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("shown.length"), 0)

    def test_already_on_settings_still_switches_the_tab(self):
        ctx = self._ctx(active="settings")
        ctx.eval("location.hash = '#settings/notifs'; _routeBarePageHash();")
        self.assertEqual(ctx.eval("shown.length"), 0)
        self.assertEqual(ctx.eval("JSON.stringify(tabs)"), '["notifs"]')

    def test_listener_is_registered_and_uses_replacestate_routing(self):
        src = app_js()
        self.assertIn("window.addEventListener('hashchange', _routeBarePageHash)", src)
        # the single-history-entry contract: routing goes through showPage,
        # which replaceStates — never a pushState of its own.
        self.assertNotIn("pushState", js_function(src, "_routeBarePageHash"))


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestDestructiveConfirmations(unittest.TestCase):
    """4. A confirmation that destroys data must not look like Save."""

    def test_danger_flag_paints_the_shutdown_button(self):
        ctx = _ctx("uiConfirm", extra="""
          var _uiPromptResolve = null, _uiPromptConfirmMode = false;
          function openModal() {}
          for (const id of ['ui-prompt-title','ui-prompt-message','ui-prompt-input',
                            'ui-prompt-textarea','ui-prompt-confirm'])
            build({tag: 'div', id: id});
        """)
        ctx.eval(js_function(app_js(), "uiConfirm"))
        ctx.eval("uiConfirm({message: 'x', confirmText: 'Delete', danger: true});")
        btn = "document.getElementById('ui-prompt-confirm')"
        self.assertTrue(ctx.eval(f"{btn}.classList.contains('btn-shutdown')"))
        self.assertFalse(ctx.eval(f"{btn}.classList.contains('btn-primary')"))
        self.assertEqual(ctx.eval(f"{btn}.textContent"), "Delete")
        ctx.eval("uiConfirm({message: 'x'});")
        self.assertTrue(ctx.eval(f"{btn}.classList.contains('btn-primary')"))
        self.assertFalse(ctx.eval(f"{btn}.classList.contains('btn-shutdown')"))

    def test_every_irreversible_confirmation_is_marked_danger(self):
        """Ratchet: a confirmation whose own words promise destruction gets red."""
        from srcpin import _scan_balanced
        src = app_js()
        promises = re.compile(
            r"cannot be undone|permanently|irreversible|OVERWRITES|"
            r"stops working|will be discarded|will be cleared|"
            r"None of them will be delivered|removes them",
            re.I)
        offenders = []
        for m in re.finditer(r"uiConfirm\(", src):
            o = src.index("(", m.start() + len("uiConfirm") - 1)
            try:
                end = _scan_balanced(src, o, "(", ")")
            except ValueError:
                continue
            call = src[m.start():end]
            if call.startswith("uiConfirm(opts"):
                continue                      # the definition itself
            if promises.search(call) and "danger" not in call:
                offenders.append(" ".join(call.split())[:110])
        self.assertEqual(offenders, [],
                         "destructive confirmations still styled as Save: %s" % offenders)

    def test_navigational_confirms_were_left_alone(self):
        """danger is a signal; applying it everywhere would destroy the signal."""
        src = app_js()
        for benign in ("Apply this policy now (queue upgrades to all targeted devices)?",
                       "Regenerate the runbook?"):
            i = src.find(benign)
            self.assertGreater(i, 0, f"anchor moved: {benign!r}")
            self.assertNotIn("danger", src[max(0, i - 120):i + len(benign) + 120])


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestFilterRowsZeroMatch(unittest.TestCase):
    """5. A filter matching nothing must say so, not silently empty the panel."""

    def _ctx(self, tag="div", cols=1):
        rows = []
        for i, txt in enumerate(("alpha", "beta", "gamma")):
            kids = [{"tag": "td", "text": txt}] * cols if tag == "tr" else []
            rows.append({"tag": tag, "cls": "row", "text": None if kids else txt,
                         "kids": kids})
        for r in rows:
            if r.get("text") is None:
                r.pop("text")
        ctx = _ctx("filterRows", "_filterRowsNoMatch")
        ctx.eval("build(%s);" % _json({"tag": "tbody" if tag == "tr" else "div",
                                       "id": "host", "kids": rows}))
        ctx.eval("""
          var inp = document.createElement('input');
          inp.setAttribute('data-filter-target', '.row');
          document.body.appendChild(inp);
        """)
        return ctx

    def test_zero_match_line_appears_with_a_working_clear(self):
        ctx = self._ctx()
        ctx.eval("inp.value = 'zzz'; filterRows(inp);")
        nm = "document.querySelector('.filter-no-match')"
        self.assertTrue(ctx.eval(f"!!{nm}"), "no zero-match state was rendered")
        self.assertIn('No matches for "zzz".', ctx.eval(f"{nm}.textContent"))
        self.assertTrue(ctx.eval(f"{nm}.classList.contains('empty-state')"),
                        "zero-match line is unstyled")
        # it lands inside the same container as the rows it replaces
        self.assertEqual(ctx.eval(f"{nm}.parentNode.id"), "host")
        # Clear restores every row and removes the line
        ctx.eval(f"{nm}.querySelector('button').click();")
        self.assertFalse(ctx.eval("!!document.querySelector('.filter-no-match')"))
        self.assertEqual(ctx.eval("inp.value"), "")
        self.assertEqual(
            ctx.eval("document.querySelectorAll('.row').filter("
                     "r => r.classList.contains('row-hidden')).length"), 0)

    def test_no_zero_match_line_when_something_matches(self):
        ctx = self._ctx()
        ctx.eval("inp.value = 'beta'; filterRows(inp);")
        self.assertFalse(ctx.eval("!!document.querySelector('.filter-no-match')"))
        ctx.eval("inp.value = ''; filterRows(inp);")
        self.assertFalse(ctx.eval("!!document.querySelector('.filter-no-match')"))

    def test_the_zero_match_row_is_a_tr_inside_a_table(self):
        ctx = self._ctx(tag="tr", cols=4)
        ctx.eval("inp.value = 'zzz'; filterRows(inp);")
        self.assertEqual(ctx.eval("document.querySelector('.filter-no-match').tagName"), "TR")
        self.assertEqual(
            ctx.eval("document.querySelector('.filter-no-match').firstChild.colSpan"), 4,
            "the zero-match cell does not span the table")

    def test_the_zero_match_node_never_counts_itself(self):
        """It matches the broad selectors some pages use — and its own text
        contains the query, so counting it would make the state flap."""
        ctx = self._ctx()
        ctx.eval("inp.setAttribute('data-filter-count', 'cnt');"
                 "build({tag: 'span', id: 'cnt'});")
        ctx.eval("inp.value = 'zzz'; filterRows(inp);")
        first = ctx.eval("document.getElementById('cnt').textContent")
        ctx.eval("filterRows(inp);")
        self.assertEqual(ctx.eval("document.getElementById('cnt').textContent"), first)
        self.assertEqual(first, "0 of 3")
        self.assertEqual(ctx.eval("document.querySelectorAll('.filter-no-match').length"), 1,
                         "the zero-match node was duplicated on re-filter")

    def test_query_is_rendered_as_text_not_markup(self):
        ctx = self._ctx()
        ctx.eval("inp.value = '<img src=x>'; filterRows(inp);")
        node = "document.querySelector('.filter-no-match')"
        self.assertIn("<img src=x>", ctx.eval(f"{node}.textContent"))
        self.assertEqual(ctx.eval(f"{node}.querySelectorAll('img').length"), 0,
                         "the query was interpolated as markup")


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestLocaleAwareDates(unittest.TestCase):
    """6. Timestamps must follow the in-app language picker, not the browser."""

    def _ctx(self):
        return _ctx("_localeTag", "_fmtAbsTs", "_fmtAbsDate", "_fmtAbsTime", extra="""
          var seen = [];
          Date.prototype.toLocaleString     = function (l) { seen.push(['s', l]); return 'S'; };
          Date.prototype.toLocaleDateString = function (l) { seen.push(['d', l]); return 'D'; };
          Date.prototype.toLocaleTimeString = function (l) { seen.push(['t', l]); return 'T'; };
        """)

    def test_every_ui_language_has_a_locale_tag(self):
        langs = re.search(r"var LANGS = \[([^\]]*)\]", I18N_JS.read_text()).group(1)
        langs = re.findall(r"'([a-z]{2})'", langs)
        self.assertIn("de", langs)
        self.assertIn("fr", langs)
        ctx = self._ctx()
        for lang in langs:
            ctx.eval(f"window.RPi18n.current = '{lang}';")
            tag = ctx.eval("_localeTag()")
            if lang == "en":
                self.assertEqual(tag, "en")
            else:
                self.assertNotEqual(tag, "en",
                                    f"UI language {lang!r} silently formats as en")
                self.assertTrue(tag.startswith(lang), f"{lang} -> {tag}")

    def test_helpers_pass_the_app_locale_through(self):
        ctx = self._ctx()
        ctx.eval("window.RPi18n.current = 'fr';")
        self.assertEqual(ctx.eval("_fmtAbsTs(1700000000)"), "S")
        self.assertEqual(ctx.eval("_fmtAbsDate(1700000000)"), "D")
        self.assertEqual(ctx.eval("_fmtAbsTime(1700000000)"), "T")
        self.assertEqual(ctx.eval("JSON.stringify(seen)"),
                         '[["s","fr-FR"],["d","fr-FR"],["t","fr-FR"]]')
        ctx.eval("window.RPi18n.current = 'de'; seen = [];")
        ctx.eval("_fmtAbsTs(0)")
        self.assertEqual(ctx.eval("seen[0][1]"), "de-DE")

    def test_helpers_take_the_unix_seconds_the_call_sites_pass(self):
        """The sweep rewrote `new Date(x * 1000)` to `_fmtAbsTs(x)` — the *1000
        has to live in the helper or every timestamp lands in 1970."""
        ctx = _ctx("_localeTag", "_fmtAbsTs")
        ctx.eval("Date.prototype.toLocaleString = function () { return String(this.getTime()); };")
        self.assertEqual(ctx.eval("_fmtAbsTs(1700000000)"), "1700000000000")
        self.assertEqual(ctx.eval("_fmtAbsTs(null)"), "0")

    def test_no_browser_locale_timestamp_calls_remain_in_app_js(self):
        """Ratchet on the pattern the sweep removed: a Date formatted with no
        locale argument (or the `[]`/`undefined` placeholders) follows the
        BROWSER, which is the bug."""
        src = app_js()
        bad = re.findall(
            r"new Date\([^;\n]*?\)\.toLocale(?:Date|Time)?String\(\s*(?:\)|\[\]|undefined)",
            src)
        self.assertEqual(bad, [], f"bare-locale timestamp formatting came back: {bad}")


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestPasswordNudgeRouting(unittest.TestCase):
    """7. "Change your password" must land where the password field is."""

    def _ctx(self, with_section):
        kids = [{"tag": "div", "id": "page-account", "cls": "page"}]
        if with_section:
            kids[0]["kids"] = [{"tag": "div", "id": "account-password-section", "kids": [
                {"tag": "button", "attrs": {"data-action": "openPasswd"}, "text": "Change password"}]}]
        ctx = _ctx("gotoPasswordChange", extra="""
          var shown = [], opened = [];
          var _meCache = { username: 'admin' };
          function showPage(n) { shown.push(n); }
          function openPasswd(u) { opened.push(u); }
        """)
        ctx.eval(js_function(app_js(), "gotoPasswordChange"))
        ctx.eval("build(%s);" % _json({"tag": "div", "id": "app", "kids": kids}))
        return ctx

    def test_routes_to_the_account_page_and_opens_the_section(self):
        ctx = self._ctx(with_section=True)
        ctx.eval("gotoPasswordChange();")
        self.assertEqual(ctx.eval("JSON.stringify(shown)"), '["account"]',
                         "the nudge still lands on Settings, which has no password field")
        sec = "document.getElementById('account-password-section')"
        self.assertTrue(ctx.eval(f"{sec}.scrolledIntoView"))
        self.assertEqual(ctx.eval(f"{sec}.querySelector('button').clicks"), 1)

    def test_falls_back_to_the_password_modal_when_the_section_is_absent(self):
        ctx = self._ctx(with_section=False)
        ctx.eval("gotoPasswordChange();")
        self.assertEqual(ctx.eval("JSON.stringify(shown)"), '["account"]')
        self.assertEqual(ctx.eval("JSON.stringify(opened)"), '["admin"]',
                         "with no Account section the nudge is a dead end again")

    def test_both_nudges_call_it(self):
        src = app_js()
        self.assertIn("banner.onclick = () => gotoPasswordChange();", src,
                      "the default-password banner still routes to Settings")
        self.assertEqual(len(re.findall(r"gotoPasswordChange\(\)", src)), 3,
                         "expected the banner, the 403 interceptor and the definition")


if __name__ == "__main__":
    unittest.main()
