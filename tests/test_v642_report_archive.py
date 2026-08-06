"""v6.4.2 — a past-dated posture report becomes something you can hand over.

Every report path — `_build_fleet_report`, the evidence pack, the scheduled
email — computed from live state and threw the result away. Nothing wrote a
generated report to a store, and no report endpoint accepted an as-of date.

That would be recoverable if the inputs had history, but they largely do not.
Fleet health score and fleet compliance % are sampled daily; CVE counts, patch
backlog and per-framework control pass/fail have no history at all. So a
past-dated posture report was not merely unstored, it was unreconstructable.

An ISO 27001 auditor asks for the posture report as it stood at the end of Q1.
The operator had the March email in their inbox — plain text, if it was even
scheduled — and nothing else: no artifact to hand over, no way to regenerate.

Separately, `handle_evidence_pack?days=90` returned a document labelled
`period_days: 90` / `period_start: <ts>` whose `posture` block is today's
numbers. The docstring said "current" and the field is plainly named `posture`,
so it was loosely labelled rather than actively misrepresenting — but a
document an auditor reads should not need that defence.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-rptarch-"))

_spec = importlib.util.spec_from_file_location("api_rptarch", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = ROOT / "server" / "html" / "index.html"
_JS = ROOT / "server" / "html" / "static" / "js" / "app.js"


def _report(ts, score=80, site_name=""):
    r = {"generated_ts": ts, "server_version": "6.4.2", "server_name": "Acme",
         "health": {"score": score, "grade": "B"},
         "devices": {"total": 10, "online": 10, "offline": 0}}
    if site_name:
        r["site_name"] = site_name
    return r


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("REPORT_ARCHIVE_FILE", "CONFIG_FILE", "AUDIT_LOG_FILE",
                     "COMPLIANCE_HIST_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "require_admin_or_auditor_auth",
                       "audit_log", "respond", "method", "_env")}
        api.require_admin_auth = lambda: "jakob"
        api.require_admin_or_auditor_auth = lambda: "jakob"
        api.audit_log = lambda *a, **k: None
        self._qs = ""
        _real_env = self._orig["_env"]
        api._env = lambda k, d="": (self._qs if k == "QUERY_STRING"
                                    else _real_env(k, d))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "GET"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def fresh(self):
        api._invalidate_load_cache(api.REPORT_ARCHIVE_FILE)


class TestArchiving(_Base):
    def test_a_delivered_report_is_kept_whole(self):
        """Not a summary — the artifact the auditor asks for is the document
        that was sent."""
        rid = api._archive_report(_report(1000), "schedule")
        self.assertTrue(rid.startswith("rpt-"))
        self.fresh()
        e = (api.load(api.REPORT_ARCHIVE_FILE) or {})["entries"][0]
        self.assertEqual(e["report"]["health"]["score"], 80)

    def test_the_metadata_is_queryable_without_loading_bodies(self):
        api._archive_report(_report(1000, 80), "schedule", name="monthly")
        self.fresh()
        idx = api._archive_index()
        self.assertEqual(idx[0]["name"], "monthly")
        self.assertEqual(idx[0]["health"], 80)
        self.assertNotIn("report", idx[0])

    def test_a_site_scoped_report_records_which_customer(self):
        api._archive_report(_report(1000, site_name="Acme Ltd"), "definition",
                            name="Acme monthly", site="s1")
        self.fresh()
        self.assertEqual(api._archive_index()[0]["site_name"], "Acme Ltd")

    def test_newest_first(self):
        for ts in (1000, 3000, 2000):
            api._archive_report(_report(ts), "schedule")
        self.fresh()
        self.assertEqual([e["ts"] for e in api._archive_index()], [3000, 2000, 1000])

    def test_it_is_capped(self):
        # Patch the BOUND MODULE, not api: `_archive_report` reads the constant
        # as its own module-level global, and api merely re-imports the name.
        # Setting api._REPORT_ARCHIVE_MAX changes nothing the function reads —
        # a false green that would have reported an uncapped store as capped.
        mod = api.reports_handlers_mod
        real = mod._REPORT_ARCHIVE_MAX
        try:
            mod._REPORT_ARCHIVE_MAX = 3
            for ts in range(1000, 1006):
                api._archive_report(_report(ts), "schedule")
        finally:
            mod._REPORT_ARCHIVE_MAX = real
        self.fresh()
        self.assertEqual([e["ts"] for e in api._archive_index()],
                         [1005, 1004, 1003])

    def test_an_archive_failure_never_costs_the_delivery(self):
        """The email already went out. Raising here would turn a bookkeeping
        problem into a failed report."""
        real = api._LockedUpdate
        api._LockedUpdate = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        try:
            self.assertEqual(api._archive_report(_report(1000), "schedule"), "")
        finally:
            api._LockedUpdate = real

    def test_a_window_filters_both_ends(self):
        for ts in (1000, 2000, 3000):
            api._archive_report(_report(ts), "schedule")
        self.fresh()
        self.assertEqual([e["ts"] for e in api._archive_index(since=1500, until=2500)],
                         [2000])


class TestTheAsOfQuestion(_Base):
    """The auditor's question is "what did this look like at the end of Q1?"."""

    def setUp(self):
        super().setUp()
        for ts in (1000, 2000, 3000):
            api._archive_report(_report(ts), "schedule")
        self.fresh()

    def test_it_returns_the_nearest_report_at_or_before(self):
        self._qs = "as_of=2500"
        r = self.call(api.handle_report_archive)
        self.assertEqual(r["entry"]["ts"], 2000)

    def test_it_never_returns_one_from_after_the_date(self):
        """A report generated a week later looks like an answer and is not
        one — silently handing it over is worse than handing over nothing."""
        self._qs = "as_of=500"
        r = self.call(api.handle_report_archive)
        self.assertIsNone(r["entry"])

    def test_an_exact_match_counts_as_at_or_before(self):
        self._qs = "as_of=2000"
        self.assertEqual(self.call(api.handle_report_archive)["entry"]["ts"], 2000)

    def test_it_says_how_many_it_had_to_choose_from(self):
        self._qs = "as_of=3000"
        self.assertEqual(self.call(api.handle_report_archive)["count"], 3)


class TestTheEndpoints(_Base):
    def test_listing_reports_the_cap_and_the_losses(self):
        """An archive that quietly stopped keeping things is worse than no
        archive — the operator believes they have coverage they do not."""
        api._archive_report(_report(1000), "schedule")
        self.fresh()
        r = self.call(api.handle_report_archive)
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["cap"], api._REPORT_ARCHIVE_MAX)
        self.assertIn("trimmed", r)

    def test_one_entry_comes_back_whole(self):
        rid = api._archive_report(_report(1000, 71), "schedule")
        self.fresh()
        r = self.call(api.handle_report_archive_entry, rid)
        self.assertEqual(r["report"]["health"]["score"], 71)
        self.assertNotIn("report", r["entry"])   # metadata block stays light

    def test_an_unknown_id_404s(self):
        self.call(api.handle_report_archive_entry, "rpt-nope")
        self.assertEqual(self.cap["s"], 404)

    def test_delete_removes_it(self):
        rid = api._archive_report(_report(1000), "schedule")
        self.fresh()
        api.method = lambda: "DELETE"
        self.assertTrue(self.call(api.handle_report_archive_entry, rid)["ok"])
        self.fresh()
        self.assertEqual(api._archive_index(), [])

    def test_delete_of_an_unknown_id_404s(self):
        api.method = lambda: "DELETE"
        self.call(api.handle_report_archive_entry, "rpt-nope")
        self.assertEqual(self.cap["s"], 404)

    def test_reading_is_admin_or_auditor(self):
        """An auditor is exactly the role that needs this and cannot mutate."""
        seen = []
        api.require_admin_or_auditor_auth = lambda: (seen.append(1), "j")[1]
        self.call(api.handle_report_archive)
        self.assertEqual(len(seen), 1)

    def test_deleting_needs_admin_not_just_auditor(self):
        seen = []
        api.require_admin_auth = lambda: (seen.append(1), "j")[1]
        api.method = lambda: "DELETE"
        self.call(api.handle_report_archive_entry, "rpt-x")
        self.assertEqual(len(seen), 1)


class TestTheDeliveryPathsArchive(unittest.TestCase):
    """The whole finding is that reports were computed and discarded. A store
    nothing writes to is the same as no store."""

    @classmethod
    def setUpClass(cls):
        cls.src = (_CGI / "reports_handlers.py").read_text()

    def test_the_fleet_schedule_archives(self):
        from srcpin import py_function
        self.assertIn("_archive_report(report, 'schedule')",
                      py_function(self.src, "_maybe_send_scheduled_report"))

    def test_custom_definitions_archive_with_their_name_and_site(self):
        from srcpin import py_function
        body = py_function(self.src, "_maybe_send_report_definitions")
        self.assertIn("_archive_report(report, 'definition'", body)
        self.assertIn("site=_site", body)

    def test_an_on_demand_download_does_not_archive(self):
        """Only DELIVERIES are kept. Archiving every page view would fill the
        cap with reports nobody sent and evict the ones somebody did."""
        from srcpin import py_function
        self.assertNotIn("_archive_report",
                         py_function(self.src, "handle_fleet_report"))


class TestTheEvidencePackStoppedBeingLooselyLabelled(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = (_CGI / "reports_handlers.py").read_text()

    def test_it_says_the_posture_block_is_current(self):
        """`period_days: 90` sitting next to a `posture` block of today's
        numbers reads like a period summary and is not one."""
        from srcpin import py_function
        body = py_function(self.src, "handle_evidence_pack")
        self.assertIn("posture_note", body)
        self.assertIn("not an average", body)

    def test_it_carries_the_reports_that_do_cover_the_period(self):
        from srcpin import py_function
        body = py_function(self.src, "handle_evidence_pack")
        self.assertIn("'archived_reports': _archive_index(since=since, until=now)",
                      body)


class TestRoutes(unittest.TestCase):
    def test_both_routes_resolve(self):
        exact = api._build_exact_routes()
        self.assertIn(("GET", "/api/report/archive"), exact)
        src = (_CGI / "api.py").read_text()
        self.assertIn("/api/report/archive/", src)
        self.assertIn("handle_report_archive_entry", src)

    def test_the_handlers_live_in_the_bound_module(self):
        """api.py is at the inline-handler ratchet ceiling."""
        self.assertEqual(api.handle_report_archive.__module__, "reports_handlers")


class TestTheUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()
        cls.js = _JS.read_text()

    def test_the_card_exists_on_the_reports_page(self):
        i = self.html.index('id="page-reports"')
        j = self.html.index('<div id="page-', i + 10)
        self.assertIn('id="rarch-tbody"', self.html[i:j])

    def test_the_page_divs_stay_balanced(self):
        # From the OPENING tag — starting at the id attribute drops the `<div`
        # and reports every balanced page as off by one.
        i = self.html.index('<div id="page-reports"')
        j = self.html.index('<div id="page-', i + 10)
        seg = self.html[i:j]
        self.assertEqual(len(re.findall(r"<div\b", seg)),
                         len(re.findall(r"</div>", seg)))

    def test_every_dispatch_name_is_real(self):
        for fn in ("loadReportArchive", "reportArchiveAsOf",
                   "downloadArchivedReport", "deleteArchivedReport"):
            with self.subTest(fn=fn):
                self.assertIn(fn, self.html + self.js)
                self.assertRegex(self.js, rf"\bfunction {fn}\s*\(")

    def test_it_loads_with_the_page(self):
        self.assertIn("loadReportArchive()", self.js)
        i = self.js.index("if (name === 'reports')")
        self.assertIn("loadReportArchive", self.js[i:i + 120])

    def test_the_table_is_sortable(self):
        self.assertIn('id="rarch-thead"', self.html)
        self.assertIn("wireSortOnly('rarch-thead'", self.js)

    def test_as_of_uses_the_end_of_the_chosen_day(self):
        """"As of 31 March" means the close of business, not midnight at its
        start — otherwise the report delivered that morning is excluded."""
        body = self.js[self.js.index("async function reportArchiveAsOf("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("T23:59:59", body)

    def test_a_miss_explains_itself(self):
        body = self.js[self.js.index("async function reportArchiveAsOf("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("only holds reports this server actually emailed", body)

    def test_delete_is_a_hard_confirm_not_an_undo_toast(self):
        """This is the only copy, and it cannot be regenerated — a deferred
        commit would make destroying evidence a one-click accident."""
        body = self.js[self.js.index("async function deleteArchivedReport("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("uiConfirm(", body)
        self.assertNotIn("undoableDelete", body)
        self.assertIn("only copy", body)

    def test_a_non_admin_sees_the_page_without_an_error_card(self):
        body = self.js[self.js.index("async function loadReportArchive("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("classList.add('d-none')", body)


if __name__ == "__main__":
    unittest.main()


class TestScopedCallersCannotReadTheArchive(_Base):
    """v6.4.2 (adversarial audit of the session diff): the archive was gated on
    admin-or-auditor alone.

    A TENANT admin's role is `admin`, so `_caller_scope()` returns None and
    every gate shaped "if scope is not None" waves them through — the documented
    trap in this codebase. They could therefore download another tenant's
    whole-fleet posture report: device counts, health score, CVE totals, site
    names. A role-scoped admin could read the same for hosts outside their
    scope.

    Filtering after the fact is impossible: a stored report is an AGGREGATE,
    not rows carrying device ids. So it refuses, exactly as handle_ai_rag_search
    refuses the RAG corpus for the same reason.
    """

    def _scoped(self, scope=None, tenant=None):
        api._caller_scope = lambda: scope
        api._tenant_gate = lambda: tenant

    def setUp(self):
        super().setUp()
        self._cs, self._tg = api._caller_scope, api._tenant_gate
        self.addCleanup(lambda: setattr(api, "_caller_scope", self._cs))
        self.addCleanup(lambda: setattr(api, "_tenant_gate", self._tg))
        self._scoped()

    def test_a_full_access_admin_still_reads_it(self):
        """The under-permissive direction: the people it is FOR must keep it."""
        api._archive_report(_report(1000), "schedule")
        self.fresh()
        self.assertEqual(self.call(api.handle_report_archive)["total"], 1)

    def test_a_tenant_admin_is_refused(self):
        api._archive_report(_report(1000), "schedule")
        self.fresh()
        self._scoped(tenant="acme")
        self.call(api.handle_report_archive)
        self.assertEqual(self.cap["s"], 403)

    def test_a_role_scoped_caller_is_refused(self):
        api._archive_report(_report(1000), "schedule")
        self.fresh()
        self._scoped(scope={"type": "groups", "values": ["web"]})
        self.call(api.handle_report_archive)
        self.assertEqual(self.cap["s"], 403)

    def test_the_body_endpoint_is_refused_too(self):
        """The list leaks site names and health scores; the entry leaks the
        entire report. Both need the gate."""
        rid = api._archive_report(_report(1000), "schedule")
        self.fresh()
        self._scoped(tenant="acme")
        self.call(api.handle_report_archive_entry, rid)
        self.assertEqual(self.cap["s"], 403)

    def test_the_refusal_explains_itself_and_points_somewhere(self):
        """A bare 403 on a page an operator can see reads as a bug."""
        self._scoped(tenant="acme")
        self.call(api.handle_report_archive)
        msg = self.cap["b"]["error"]
        self.assertIn("full-access", msg)
        self.assertIn("site-scoped report", msg)
