"""v6.4.2 — the retrieval index stops being a diagnostic and becomes a search box.

Neither search box reached tickets, KB articles, CMDB assets, contacts, sites,
saved-script content or the documentation. The command palette indexed devices,
pages, actions, open alerts, CVE rollups and command history; the sidebar box
indexed nav labels and Settings tabs.

Meanwhile `POST /api/ai/rag/search` runs lexical+semantic retrieval over the
34-source RAG corpus — which explicitly includes `tickets`, `kb`, `cmdb`,
`contacts`, `network_map`, `provisioning`, `history`, `drift` and `firewall` —
with no LLM call and no tokens spent. It was exposed in exactly one place: a
card in Settings → AI titled "Test retrieval", described as a coverage check
for a feature the operator may have switched off. And its result rows were
inert: `<td><code>${escHtml(r.id)}</code></td>`, no link, no click-through to
the entity found.

So an operator who remembered there was a ticket about a failing NIC on a host
whose name they could not recall opened Tickets and searched, then KB, then
CMDB, then Contacts. The one box that answers it in a single query was filed
under AI settings — and even when it found the ticket, the row was plain text.

Two upstream limits are deliberate and stay: the endpoint 403s any role-scoped
OR tenant-scoped caller (the corpus is fleet-wide with no scope tags, so
refusing beats leaking — a v6.4.2 security fix), and 400s when RAG is off. The
palette section therefore has to degrade SILENTLY for those callers.
"""

import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts that directory on sys.path for
# free, so the omission is invisible there; `python3 -m unittest
# tests.<this>` reaches the method and fails on the import.
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HTML = ROOT / "server" / "html" / "index.html"
_JS = ROOT / "server" / "html" / "static" / "js"
_CGI = ROOT / "server" / "cgi-bin"


def _routes(js):
    i = js.index("const _RAG_ROUTES = {")
    return js[i:js.index("\n};", i)]


class TestTheRouter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = (_JS / "app.js").read_text()
        cls.html = _HTML.read_text()
        cls.routes = _routes(cls.js)

    def test_every_page_it_routes_to_exists(self):
        """showPage() on a page id that does not exist just returns — a dead
        click with no error anywhere."""
        pages = set(re.findall(r'id="page-([a-z0-9_-]+)"', self.html))
        bad = sorted({t for t in re.findall(r"showPage\('([a-z0-9_-]+)'\)", self.routes)
                      if t not in pages})
        self.assertEqual(bad, [], f"no such page: {bad}")

    def test_it_covers_the_prefixes_the_corpus_actually_emits(self):
        """The chunk-id prefixes come from rag_index.py's make_doc calls. A
        prefix the corpus emits and the router does not know lands the operator
        on the AI page instead of the entity — the fallback is deliberate, but
        the common ones should be real routes."""
        rag = (_CGI / "rag_index.py").read_text()
        emitted = set(re.findall(r'f?"([a-z_]+)/[^"]*"', rag))
        known = set(re.findall(r"^\s+'?([a-z_]+)'?:\s", self.routes, re.M))
        # The ones an operator searches for by name.
        for p in ("ticket", "kb", "cmdb", "contacts", "docs", "live", "drift"):
            with self.subTest(prefix=p):
                self.assertIn(p, emitted, "the corpus no longer emits this")
                self.assertIn(p, known, "the router does not know it")

    def test_an_unknown_prefix_is_not_a_dead_click(self):
        """A new RAG source can ship before its route does."""
        body = self.js[self.js.index("function ragOpenHit("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("showPage('ai')", body)

    def test_the_entity_id_is_extracted_not_guessed(self):
        """Chunk ids are `<prefix>/<entity>[/more][#section]` — "ticket/42#body"
        must open ticket 42, not "42#body"."""
        body = self.js[self.js.index("function _ragSeg("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("split('#')[0]", body)
        self.assertIn("split('/')[1]", body)

    def test_the_fleet_wide_chunk_does_not_open_a_device_drawer(self):
        """`live/_fleet#cves` is a rollup, not a host."""
        body = self.js[self.js.index("function _ragOpenDevice("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("_fleet", body)

    def test_the_lazy_module_hop_is_polled_not_raced(self):
        """openTicket lives in app-tickets.js and openKbArticle in app-kb.js,
        both lazy. A single setTimeout races the fetch on a cold page and
        silently does nothing."""
        body = self.js[self.js.index("function _ragGo("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("typeof fn === 'function'", body)
        self.assertIn("setTimeout(tick", body)

    def test_the_openers_it_names_are_real(self):
        """A `window[name]` lookup on a typo is an undefined global that dies
        silently in a branch nobody exercises."""
        for name, mod in (("openTicket", "app-tickets.js"),
                          ("openKbArticle", "app-kb.js"),
                          ("openDeviceDrawer", "app.js"),
                          ("openDocViewer", "app.js")):
            with self.subTest(fn=name):
                self.assertIn(name, self.routes + self.js)
                self.assertRegex((_JS / mod).read_text(),
                                 rf"\bfunction {name}\s*\(")


class TestThePaletteSection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = _JS / "app.js"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = p.read_text()
        cls.body = cls.js[cls.js.index("async function _palKnowledge("):]
        cls.body = cls.body[:cls.body.index("\n}\n")]

    def test_it_queries_the_endpoint_that_already_existed(self):
        self.assertIn("'/ai/rag/search'", self.body)

    def test_it_degrades_silently_for_a_scoped_caller(self):
        """403 (scoped/tenant caller) and 400 (RAG off) are both by design. A
        toast on every keystroke for a role that can never use this would be
        worse than the feature not being there."""
        self.assertIn("_ragPalOff = true", self.body)
        self.assertNotIn("toast(", self.body)

    def test_it_stops_asking_once_refused(self):
        """Permanent for the session — otherwise it fires a request per
        keystroke forever against an endpoint that will always refuse."""
        self.assertIn("if (_ragPalOff", self.body)

    def test_short_queries_do_not_hit_the_server(self):
        self.assertIn("query.length < 3", self.body)

    def test_results_are_cached_per_query(self):
        self.assertIn("_ragPalCache.q === query", self.body)

    def test_a_hit_opens_the_entity(self):
        self.assertIn("ragOpenHit(h.id)", self.body)

    def test_the_palette_appends_rather_than_reranking(self):
        """A local page or device match is usually what the operator meant.
        Merging async results into the ranking would move the row under their
        finger a beat after they started reading it."""
        r = self.js[self.js.index("function _palRender()"):]
        r = r[:r.index("\nfunction ", 10)]
        self.assertIn("filtered.concat(_ragPalCache.rows)", r)

    def test_a_stale_response_does_not_repaint(self):
        """The user keeps typing while the request is in flight."""
        r = self.js[self.js.index("function _palRender()"):]
        r = r[:r.index("\nfunction ", 10)]
        self.assertIn("cur === q", r)

    def test_the_scope_prefixes_skip_it(self):
        """'>' is actions-only and '#' is devices-only — a knowledge hit in
        either would break the contract those prefixes advertise."""
        r = self.js[self.js.index("function _palRender()"):]
        r = r[:r.index("\nfunction ", 10)]
        self.assertIn("if (q && !kindFilter)", r)


class TestTheSettingsCardStoppedBeingInert(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = _JS / "app-ai.js"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.ai = p.read_text()
        cls.html = _HTML.read_text()

    def test_every_row_routes_somewhere(self):
        """It found the ticket, named it, and gave no way to open it."""
        i = self.ai.index("const rows = sorted.map(")
        seg = self.ai[i:i + 900]
        self.assertIn('data-action="ragOpenHit"', seg)
        self.assertIn("escAttr(r.id)", seg)

    def test_the_row_is_keyboard_reachable(self):
        i = self.ai.index("const rows = sorted.map(")
        self.assertIn('tabindex="0"', self.ai[i:i + 900])

    def test_the_card_no_longer_calls_itself_a_test(self):
        """"Test retrieval … useful for checking coverage" is an accurate
        description of a diagnostic and a misleading one for a search box."""
        self.assertNotIn("Test retrieval", self.html)
        self.assertIn("Knowledge search", self.html)

    def test_the_card_says_what_it_searches(self):
        i = self.html.index("Knowledge search")
        seg = self.html[i:i + 900]
        for word in ("tickets", "KB articles", "CMDB", "contacts"):
            with self.subTest(word=word):
                self.assertIn(word, seg)

    def test_it_points_at_the_palette(self):
        i = self.html.index("Knowledge search")
        self.assertIn("command palette", self.html[i:i + 900])

    def test_it_states_the_by_design_restriction(self):
        """A full-access-only feature that says nothing about it reads as
        broken to every scoped operator who tries it."""
        i = self.html.index("Knowledge search")
        self.assertIn("Full-access roles only", self.html[i:i + 900])


class TestTheServerSideIsUnchanged(unittest.TestCase):
    """This finding is entirely a front-end wiring gap — the endpoint, the
    corpus and the security posture were already right. Pin that nothing was
    loosened to make the UI nicer."""

    def test_the_scope_refusal_is_still_there(self):
        src = (_CGI / "api.py").read_text()
        from srcpin import py_function
        body = py_function(src, "handle_ai_rag_search")
        self.assertIn("_caller_scope() is not None or _tenant_gate() is not None",
                      body)
        self.assertIn("respond(403", body)

    def test_rag_disabled_still_400s(self):
        src = (_CGI / "api.py").read_text()
        from srcpin import py_function
        body = py_function(src, "handle_ai_rag_search")
        self.assertIn("respond(400, {'error': 'RAG is disabled.", body)


if __name__ == "__main__":
    unittest.main()
