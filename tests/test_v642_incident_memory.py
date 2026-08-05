"""v6.4.2 — incident memory gets a HUMAN view.

RemotePower has harvested resolved incidents into a durable outcome store since
v6.3.1 and wired it to the MACHINE in three places (the RAG corpus, the triage
loop's `prior_incidents` evidence tool, and the AI advisor). It was readable by
a human in NONE of them: the model could consult the team's own incident
history, the team could not.

This file pins BOTH halves, because either alone is a dead end:

  * the SERVER half — `/api/ai/incident-memory` is a registered route, and the
    record it actually returns has the field names the renderer reads. That
    half is DRIVEN (seed the real producer path, call the real handler, read
    the real body), never grepped: a source-text assertion proves a line
    exists, never that it works, and this codebase has repeatedly shipped
    renderers reading keys no producer writes.

  * the CLIENT half — the card markup exists in index.html and app-alerts.js
    renders it, sorts it, caps it, and escapes it.

The JS assertions are necessarily source-level (there is no DOM here); the
`test_jsload` / `test_js_noundef` / `test_ui_wiring` / `test_css_class_parity`
gates cover what source text cannot.
"""

import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-incmem642-"))

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html"
_JS = _HTML / "static" / "js"

sys.path.insert(0, str(ROOT / "tests"))
import srcpin  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "api", str(ROOT / "server" / "cgi-bin" / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


def _alerts_js():
    return (_JS / "app-alerts.js").read_text()


def _index():
    return (_HTML / "index.html").read_text()


def _strip_js_comments(t):
    t = re.sub(r"^\s*//.*$", "", t, flags=re.M)
    return re.sub(r"/\*.*?\*/", "", t, flags=re.S)


# The field names the renderer is allowed to rely on. Asserted against a DRIVEN
# response below — if the producer ever renames one, this list is what fails.
EXPECTED_OUTCOME_KEYS = {
    "alert_id", "captured_at", "confidence", "device_id", "device_name",
    "event", "kind", "rating", "recommended_action", "resolution",
    "resolved_at", "root_cause", "severity", "source", "tenant",
}


def _drive_endpoint():
    """Seed via the REAL producer (alerts -> run_incident_memory_if_due), then
    call the REAL handler and return its parsed body. Only verify_token is
    stubbed — stubbing require_auth would happily pass a handler with no gate
    at all."""
    now = int(time.time())
    api.save(api.DEVICES_FILE,
             {"db": {"name": "db-03", "tenant": "default", "last_seen": now}})
    api.save(api.INCIDENT_MEMORY_FILE, {})
    api.save(api.ALERTS_FILE, {"alerts": [
        # an AI-verdict alert, rated helpful
        {"id": "a1", "event": "service_down", "severity": "high",
         "device_id": "db", "device_name": "db-03",
         "resolved_at": now - 500, "resolved_by": "auto",
         "ai_triage": {"verdict": {"root_cause": "postgres OOM-killed",
                                   "confidence": "high",
                                   "recommended_action": "add 4G swap"},
                       "by": "auto", "feedback": {"helpful": True}}},
        # a HUMAN-resolved alert with only a resolve_note and no AI at all
        {"id": "a2", "event": "disk_full", "severity": "medium",
         "device_id": "db", "device_name": "db-03",
         "resolved_at": now - 200, "resolved_by": "jakob",
         "resolve_note": "journald had eaten 40G; capped SystemMaxUse=2G"},
    ], "alert_seq": 2})
    api.run_incident_memory_if_due()

    real_verify = getattr(api, "verify_token", None)
    api.verify_token = lambda *a, **k: {"user": "admin", "role": "admin"}
    try:
        api.handle_ai_incident_memory()
        raise AssertionError("handler did not respond")
    except api.HTTPError as e:
        body = e.body
        return e.status, (json.loads(body)
                          if isinstance(body, (str, bytes)) else body)
    finally:
        if real_verify is not None:
            api.verify_token = real_verify   # never leak the stub (false-green #2)


class TestServerHalf(unittest.TestCase):
    """The endpoint exists, is reachable, and returns what the renderer reads."""

    def test_route_is_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(("GET", "/api/ai/incident-memory"), routes,
                      "the card's only data source is not a registered route")

    def test_route_is_documented_in_openapi_surface(self):
        # _dispatcher_routes() + the exact table is what feeds the OpenAPI spec;
        # a route missing from both is invisible to the generated docs.
        paths = set(api._build_exact_routes().keys()) | set(api._dispatcher_routes())
        self.assertTrue(
            any(p == ("GET", "/api/ai/incident-memory")
                or (isinstance(p, tuple) and p[-1] == "/api/ai/incident-memory")
                or p == "/api/ai/incident-memory" for p in paths),
            "route absent from both the exact table and the dispatcher scan")

    def test_auth_gate_is_require_auth_not_admin(self):
        """Any authenticated operator must be able to read this — it is the
        team's own incident history, and an admin-only gate would put it on the
        wrong page. Tenant scoping is enforced separately (_tenant_gate)."""
        src = srcpin.py_function(
            (ROOT / "server" / "cgi-bin" / "ai_triage_handlers.py").read_text(),
            "handle_ai_incident_memory")
        self.assertIn("A.require_auth()", src)
        self.assertNotIn("require_admin_auth", src)
        self.assertIn("_tenant_gate", src,
                      "outcomes are tenant-tagged; the read must be gated")

    def test_driven_response_shape(self):
        status, body = _drive_endpoint()
        self.assertEqual(status, 200)
        self.assertEqual(sorted(body), ["count", "outcomes"])
        self.assertEqual(body["count"], 2)
        keys = set(body["outcomes"][0])
        self.assertEqual(
            keys, EXPECTED_OUTCOME_KEYS,
            "the outcome record's field names changed — the renderer in "
            "app-alerts.js reads these by name and will silently render "
            "blanks:\n  missing: %s\n  new: %s"
            % (sorted(EXPECTED_OUTCOME_KEYS - keys), sorted(keys - EXPECTED_OUTCOME_KEYS)))

    def test_driven_human_resolved_alert_is_captured(self):
        """An install with no AI provider configured must still accumulate
        memory — otherwise the card is empty for exactly the users the product
        is aimed at."""
        _s, body = _drive_endpoint()
        by_id = {o["alert_id"]: o for o in body["outcomes"]}
        self.assertIn("a2", by_id)
        self.assertEqual(by_id["a2"]["source"], "operator")
        self.assertEqual(by_id["a2"]["root_cause"],
                         "journald had eaten 40G; capped SystemMaxUse=2G")

    def test_driven_resolution_is_how_it_closed_not_the_fix(self):
        """Pins the semantics the column headings depend on: `resolution` says
        how the alert CLOSED; the what-happened text lives in `root_cause`."""
        _s, body = _drive_endpoint()
        by_id = {o["alert_id"]: o for o in body["outcomes"]}
        self.assertEqual(by_id["a1"]["resolution"], "auto-resolved (recover event)")
        self.assertEqual(by_id["a2"]["resolution"], "resolved by jakob")
        self.assertEqual(by_id["a1"]["rating"], "up")

    def test_driven_similar_incidents_ranking_contract(self):
        """The client mirrors this ordering; pin the server behaviour it
        mirrors so a change on either side is visible."""
        _drive_endpoint()
        got = api._similar_incidents("service_down", "service", "default")
        self.assertTrue(got)
        self.assertEqual(got[0]["event"], "service_down",
                         "same-event must rank above same-kind-only")


class TestClientHalf(unittest.TestCase):
    """app-alerts.js renders, sorts, caps and escapes the same record."""

    def setUp(self):
        self.js = _alerts_js()
        self.src = _strip_js_comments(self.js)

    def test_renderer_and_deeplink_exist(self):
        for fn in ("loadIncidentMemory", "_renderIncidentMemory",
                   "showPriorIncidents", "clearIncidentFilter",
                   "_priorIncidentBadge", "_incidentMemMatches"):
            self.assertRegex(self.src, r"\bfunction\s+%s\s*\(" % re.escape(fn),
                             "%s is missing — the card has no renderer" % fn)

    def test_it_calls_the_real_endpoint(self):
        self.assertIn("api('GET', '/ai/incident-memory')", self.src)

    def test_wired_into_the_alerts_page(self):
        """Dead unless something calls it: loadAlerts must fetch it and the
        alert row must carry the deep-link badge."""
        self.assertIn("loadIncidentMemory();",
                      srcpin.js_function(self.src, "loadAlerts"))
        self.assertIn("_priorIncidentBadge(a)",
                      srcpin.js_function(self.src, "_alertRowHtml"))

    def test_deeplink_does_not_require_an_ai_verdict(self):
        """The whole point of putting the button on the ROW: an alert nobody
        ran triage on is exactly the one whose history is worth surfacing."""
        badge = srcpin.js_function(self.src, "_priorIncidentBadge")
        self.assertNotIn("ai_triage", badge)
        self.assertIn("showPriorIncidents", badge)

    def test_renderer_reads_the_driven_field_names(self):
        """Every outcome field the renderer touches must be one the endpoint
        actually returns (guards the invented-key class)."""
        body = srcpin.js_function(self.src, "_renderIncidentMemory")
        read = set(re.findall(r"\bo\.([a-z_]+)", body))
        read |= set(re.findall(r"\bo\.([a-z_]+)",
                               srcpin.js_function(self.src, "_incidentMemMatches")))
        unknown = read - EXPECTED_OUTCOME_KEYS
        self.assertEqual(
            unknown, set(),
            "renderer reads outcome fields the endpoint never returns: %s"
            % sorted(unknown))
        # and it must actually surface the load-bearing ones
        for field in ("root_cause", "resolution", "resolved_at", "rating",
                      "event", "kind", "device_name"):
            self.assertIn("o.%s" % field, body,
                          "%s is captured but rendered nowhere" % field)

    def test_sort_getter_keys_match_the_thead_data_cols(self):
        body = srcpin.js_function(self.src, "_renderIncidentMemory")
        getter = srcpin.balanced_block(body, "sortRows('incidentmem'")
        js_keys = set(re.findall(r"^\s{4}([a-z_]+):", getter, re.M))
        html = _index()
        thead = html[html.index('id="incident-mem-thead"'):]
        thead = thead[:thead.index("</thead>")]
        html_cols = set(re.findall(r'data-col="([^"]+)"', thead))
        self.assertEqual(
            js_keys, html_cols,
            "every sortable <th> data-col must match a sortRows getter key, or "
            "clicking that header silently sorts on undefined")

    def test_sort_is_wired_eagerly(self):
        """Before the empty/error branches — otherwise the sort indicators only
        appear once data arrives."""
        body = srcpin.js_function(self.src, "_renderIncidentMemory")
        wire = body.index("wireSortOnly")
        self.assertLess(wire, body.index("empty-state"),
                        "wireSortOnly must run before the empty-state branch")

    def test_free_text_is_escaped(self):
        """root_cause / resolution / recommended_action are operator-authored
        free text going straight into innerHTML."""
        body = srcpin.js_function(self.src, "_renderIncidentMemory")
        for field in ("root_cause", "resolution", "recommended_action",
                      "event", "kind"):
            self.assertRegex(
                body, r"_escapeHtml\(o\.%s\b" % field,
                "o.%s reaches innerHTML unescaped" % field)
        self.assertNotRegex(body, r"\$\{o\.(root_cause|resolution)\}",
                            "raw interpolation of operator free text")

    def test_no_inline_handlers_or_styles(self):
        """CSP: script-src 'self'; style-src 'self' with no unsafe-inline."""
        for fn in ("_renderIncidentMemory", "_priorIncidentBadge",
                   "_incidentSourceBadge", "_incidentRatingCell"):
            body = srcpin.js_function(self.src, fn)
            self.assertNotRegex(body, r"\son[a-z]+\s*=\s*[\"']",
                                "%s emits an inline event handler" % fn)
            self.assertNotRegex(body, r"style\s*=\s*[\"']",
                                "%s emits an inline style attribute" % fn)

    def test_degrades_without_the_card_markup(self):
        """The JS lands before the index.html card; it must no-op, not throw."""
        body = srcpin.js_function(self.src, "_renderIncidentMemory")
        head = body[:body.index("wireSortOnly")]
        self.assertIn("if (!tb) return;", head)

    def test_does_not_fetch_when_the_card_is_absent(self):
        """The fetch is guarded on the card being hydrated — BEFORE any state
        flag or the api() call. Two things depend on it: a page that never
        shows the card issues no second request, and GET /api/alerts stays the
        last request loadAlerts() makes (an unguarded fetch here broke
        test_v642_alerts_ui's `__lastGet()` paging assertions)."""
        body = srcpin.js_function(self.src, "loadIncidentMemory")
        guard = body.index("if (!document.getElementById('incident-mem-tbody')) return;")
        self.assertLess(guard, body.index("api('GET'"),
                        "the card-presence guard must precede the fetch")
        self.assertLess(guard, body.index("_incidentMemLoading = true"),
                        "the guard must precede any state mutation")


class TestCardMarkup(unittest.TestCase):
    """The index.html half. Without it the renderer is unreachable."""

    def setUp(self):
        self.html = _index()

    def test_card_is_on_the_alerts_page(self):
        page = srcpin.html_page(self.html, "alerts")   # srcpin adds the page- prefix
        self.assertIn('id="incident-mem-card"', page,
                      "the Prior incidents card is not on the Alerts page")
        self.assertIn('id="incident-mem-tbody"', page)
        self.assertIn('id="incident-mem-thead"', page)

    def test_section_title_is_the_first_child_of_the_card(self):
        i = self.html.index('id="incident-mem-card"')
        after = self.html[i:i + 400]
        m = re.search(r'<div class="section-title">([^<]+)</div>', after)
        self.assertIsNotNone(m, "card header must be a .section-title div")
        self.assertEqual(m.group(1).strip(), "What happened last time")

    def test_variable_row_list_is_capped_and_scrolls(self):
        """Box-overflow rule — a variable-row table caps at ~15 rows."""
        i = self.html.index('id="incident-mem-card"')
        card = self.html[i:self.html.index("</table>", i)]
        self.assertIn("scrollable-table-wrap audit-scroll", card,
                      "uncapped table — it grows unbounded on a real fleet")

    def test_i18n_dict_covers_the_new_chrome(self):
        dict_js = (_JS / "i18n.js").read_text()
        for s in ("What happened last time", "Show all"):
            self.assertRegex(
                dict_js, r"""["']%s["']\s*:""" % re.escape(s),
                "'%s' is gate-scanned chrome with no DICT entry" % s)


class TestDemoSeederFeedsTheRealConsumers(unittest.TestCase):
    """The seeder wrote a shape NOTHING reads, and every existing test passed.

    `build_incident_memory` returned `{'incidents': [...]}` with
    `summary`/`opened`/`helpful`; every consumer reads `{'outcomes': [...]}` with
    `root_cause`/`resolved_at`/`rating`. So on a demo install the new card was
    empty, the `incident_memory` RAG source contributed zero docs, and the triage
    `prior_incidents` tool had no priors — silently, since the seeder's launch.

    A shape assertion would be the same mistake in a new place (it would encode
    MY assumption). These drive the seeder's real output through the four real
    consumers instead.
    """

    @classmethod
    def setUpClass(cls):
        seeder = ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.exists():
            raise unittest.SkipTest("seeder excluded from this tree")
        spec = importlib.util.spec_from_file_location("_seed_demo", seeder)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.store = mod.build_incident_memory()

    def test_handler_returns_the_seeded_rows(self):
        api.save(api.INCIDENT_MEMORY_FILE, self.store)
        real_verify = api.verify_token
        api.verify_token = lambda *a, **k: {"user": "admin", "role": "admin"}
        try:
            api.handle_ai_incident_memory()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        finally:
            api.verify_token = real_verify
        self.assertGreater(body["count"], 0,
                           "demo seed produces an EMPTY incident-memory card — "
                           "the store key/field names don't match the handler")

    def test_rag_source_gets_documents(self):
        sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
        try:
            import rag_index
        finally:
            sys.path.pop(0)
        docs = rag_index.build_incident_memory_corpus(self.store, now=0)
        self.assertTrue(docs, "the incident_memory RAG source contributes "
                              "nothing on a demo install")

    def test_similar_incidents_can_match_a_seeded_row(self):
        """Both halves that were wrong: the event must be a REAL registry event
        (else same-event ranking never fires) and the tenant must be what
        `_device_tenant` returns for an untenanted device — DEFAULT_TENANT, not
        None. Either mistake alone makes the evidence tool return nothing."""
        api.save(api.INCIDENT_MEMORY_FILE, self.store)
        row = self.store["outcomes"][0]
        self.assertIn(row["event"], api.EVENT_REGISTRY,
                      "seeded event is not a real event — same-event ranking "
                      "can never fire and the kind is unmapped")
        self.assertEqual(row["kind"], api.EVENT_KIND_MAP.get(row["event"]),
                         "seeded kind disagrees with EVENT_KIND_MAP")
        hits = api._similar_incidents(row["event"], row["kind"],
                                      api.DEFAULT_TENANT)
        self.assertTrue(hits, "the prior_incidents evidence tool finds no "
                              "priors on a demo install")

    def test_harvester_will_not_re_add_the_seeded_rows(self):
        """`seen` keeps the cadence sweep idempotent against the seed."""
        seen = set(self.store.get("seen") or [])
        ids = {o["alert_id"] for o in self.store["outcomes"]}
        self.assertTrue(ids and ids <= seen,
                        "seeded outcomes are missing from `seen` — the "
                        "harvester would duplicate them")


if __name__ == "__main__":
    unittest.main()
