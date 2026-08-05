"""v6.4.2 — the artifacts that leave the box stop being uninterpreted numbers.

The narrative capability already existed: `SYSTEM_PROMPTS['ai_briefing']` plus
the "Daily fleet briefing" insight card. Headless scheduled AI already existed
too — `run_ai_triage_if_due` sits in scheduler.py's CADENCE. But the briefing
was reachable only by an operator clicking it in AI Insights: no cadence hook,
no recipient list, no path into a scheduled report, a custom report, the
posture digest or the evidence pack.

So every artifact that actually left the box was numbers with zero
interpretation. The person who needs a report most is the one who never logs
in — the manager, or the customer. They receive "Fleet health score: 82/100 ·
Patches: 9 device(s) pending, 37 update(s)" and have no idea whether that is
good, what is driving it, or what they are being asked to approve. The
operator ends up writing the covering paragraph by hand every month — the
exact paragraph the model already generates on demand.

The constraint that shapes the fix: no install may start paying for tokens it
did not ask for. So `summary` is deliberately NOT in the default section
tuple — `sections or list(_REPORT_SECTIONS)` would otherwise switch AI billing
on for everyone who has ever saved a report definition.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-rptsum-"))

_spec = importlib.util.spec_from_file_location("api_rptsum", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_REPORT = {
    "generated_ts": 1_700_000_000, "server_version": "6.4.2",
    "server_name": "Acme Ops",
    "health": {"score": 82, "grade": "B"},
    "devices": {"total": 40, "online": 38, "offline": 2},
    "attention": {"critical": 1, "warning": 4, "info": 9},
    "patches": {"devices_with_patches": 9, "total_pending": 37},
    "cve": {"critical": 2, "high": 5, "medium": 11, "devices_affected": 7},
    "sla": {"days": 30, "fleet_uptime_pct": 99.4},
    "period": {"alerts_opened": 12},
}


class _AiBase(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n) for n in ("_ai_cfg",)}
        self._chat = api.ai_provider.chat
        self.sent = []

        def _chat(cfg, messages, system=None, **kw):
            self.sent.append({"cfg": cfg, "messages": messages, "system": system,
                              "kw": kw})
            return {"ok": True, "text": "The fleet is in good shape.",
                    "model": "test-model"}
        api.ai_provider.chat = _chat
        api._ai_cfg = lambda: {"enabled": True, "provider": "anthropic"}

    def tearDown(self):
        api.ai_provider.chat = self._chat
        for n, v in self._orig.items():
            setattr(api, n, v)


class TestNobodyPaysForTokensTheyDidNotAskFor(unittest.TestCase):
    def test_summary_is_not_in_the_default_section_set(self):
        """`sections or list(_REPORT_SECTIONS)` is the default in
        `_clean_report_def`. Putting `summary` in that tuple would switch AI
        billing on for every install that has ever saved a report."""
        self.assertNotIn("summary", api._REPORT_SECTIONS)
        self.assertIn("summary", api._REPORT_OPT_IN_SECTIONS)
        self.assertIn("summary", api._ALL_REPORT_SECTIONS)

    def test_it_is_still_a_savable_section(self):
        self.assertIn("summary", api._ALL_REPORT_SECTIONS)
        kept = api._filter_report_sections(dict(_REPORT, summary={"text": "x"}),
                                           ["health", "summary"])
        self.assertEqual(sorted(kept["sections"]), ["health", "summary"])
        self.assertEqual(kept["summary"], {"text": "x"})

    def test_not_asking_for_it_makes_no_ai_call(self):
        calls = []
        real = api.ai_provider.chat
        api.ai_provider.chat = lambda *a, **k: calls.append(1)
        try:
            api._attach_report_summary(dict(_REPORT), ["health", "cve"])
            api._attach_report_summary(dict(_REPORT), [])
            api._attach_report_summary(dict(_REPORT), None)
        finally:
            api.ai_provider.chat = real
        self.assertEqual(calls, [])

    def test_ai_disabled_is_not_an_error_anyone_has_to_configure_away(self):
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        self.assertIn("disabled", r["summary"]["error"])


class TestTheSummary(_AiBase):
    def test_it_asks_the_provider_and_stores_the_text(self):
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        self.assertEqual(r["summary"]["text"], "The fleet is in good shape.")
        self.assertEqual(r["summary"]["model"], "test-model")
        self.assertTrue(r["summary"]["generated_ts"])

    def test_it_uses_the_report_summary_prompt(self):
        api._build_report_summary(dict(_REPORT))
        self.assertIs(self.sent[0]["system"],
                      api.ai_provider.SYSTEM_PROMPTS["report_summary"])

    def test_the_prompt_forbids_inventing_numbers(self):
        """A covering paragraph a customer reads has to be defensible."""
        p = api.ai_provider.SYSTEM_PROMPTS["report_summary"]
        self.assertIn("Never invent a number", p)

    def test_only_the_figures_are_sent_not_the_whole_report(self):
        """The report carries per-device rows — names, IPs, scores — and this
        goes to a possibly-cloud provider. The projection is the thing that
        cannot leak a hostname the operator forgot to redact."""
        big = dict(_REPORT, devices=dict(_REPORT["devices"], worst=[
            {"name": "db-prod-01", "ip": "10.0.0.9", "score": 31}]))
        ctx = api._report_summary_context(big)
        blob = repr(ctx)
        self.assertNotIn("db-prod-01", blob)
        self.assertNotIn("10.0.0.9", blob)
        self.assertEqual(ctx["devices"], {"total": 40, "online": 38, "offline": 2})

    def test_a_site_scoped_report_says_so(self):
        ctx = api._report_summary_context(dict(_REPORT, site_name="Acme"))
        self.assertIn("Acme", ctx["scope"])

    def test_empty_sections_are_dropped_from_the_context(self):
        """Handing the model `{"cve": {}}` invites it to talk about CVEs it has
        no figures for."""
        ctx = api._report_summary_context({"health": {"score": 90}})
        self.assertEqual(list(ctx), ["health"])


class TestItNeverCostsTheOperatorTheReport(_AiBase):
    def test_a_provider_failure_returns_a_reason(self):
        api.ai_provider.chat = lambda *a, **k: {"ok": False, "error": "502 upstream"}
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        self.assertIn("502 upstream", r["summary"]["error"])
        self.assertNotIn("text", r["summary"])

    def test_a_provider_exception_does_not_propagate(self):
        """A provider outage must cost the covering paragraph, not the artifact
        the operator scheduled."""
        api.ai_provider.chat = lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        self.assertIn("boom", r["summary"]["error"])
        self.assertEqual(r["health"], _REPORT["health"])   # report intact

    def test_an_empty_model_response_is_an_error_not_a_blank_summary(self):
        api.ai_provider.chat = lambda *a, **k: {"ok": True, "text": "   "}
        self.assertIn("empty", api._build_report_summary(dict(_REPORT))["error"])


class TestItIsRenderedWhereItIsRead(_AiBase):
    def test_the_email_leads_with_it(self):
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        _subject, body = api._render_report_email(r)
        lines = [ln for ln in body.split("\n") if ln.strip()]
        i = next(n for n, ln in enumerate(lines) if "good shape" in ln)
        j = next(n for n, ln in enumerate(lines) if "Fleet health score" in ln)
        self.assertLess(i, j, "the narrative exists for the reader who stops "
                              "before the figures")

    def test_a_failure_says_so_rather_than_going_quiet(self):
        """Silence is indistinguishable from a report that was never configured
        for a summary — so nobody notices it has been missing for a month."""
        api.ai_provider.chat = lambda *a, **k: {"ok": False, "error": "rate limited"}
        r = dict(_REPORT)
        api._attach_report_summary(r, ["summary"])
        _s, body = api._render_report_email(r)
        self.assertIn("AI summary unavailable", body)
        self.assertIn("rate limited", body)

    def test_a_report_without_one_is_unchanged(self):
        _s, body = api._render_report_email(dict(_REPORT))
        self.assertNotIn("Summary", body)
        self.assertIn("Fleet health score", body)

    def test_the_printable_view_renders_it_first(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "report.js")
        if not js.exists():
            self.skipTest("excluded from this tree")
        src = js.read_text()
        i = src.index("let html = ''")
        seg = src[i:i + 900]
        self.assertIn("rep.summary", seg)
        self.assertIn("<h2>Summary</h2>", seg)
        self.assertIn("esc(sm.text)", seg, "the model's text is untrusted output")

    def test_the_print_style_exists(self):
        css = (ROOT / "server" / "html" / "static" / "css" / "report.css")
        if not css.exists():
            self.skipTest("excluded from this tree")
        self.assertIn(".pr-summary", css.read_text())


class TestTheScheduledPathIsWired(unittest.TestCase):
    """The whole finding is that the capability existed and nothing delivered
    it. A prompt with no caller is the same as no prompt."""

    def test_the_scheduler_attaches_it(self):
        src = (_CGI / "reports_handlers.py").read_text()
        from srcpin import py_function
        body = py_function(src, "_maybe_send_report_definitions")
        self.assertIn("_attach_report_summary(report, d.get('sections'))", body)

    def test_the_fleet_endpoint_attaches_it_only_when_asked(self):
        src = (_CGI / "reports_handlers.py").read_text()
        from srcpin import py_function
        body = py_function(src, "handle_fleet_report")
        self.assertIn("_attach_report_summary(report, _want)", body)
        # …and never on the unsectioned default path, which is what the UI hits
        # on every page view.
        self.assertEqual(body.count("_attach_report_summary"), 1)

    def test_the_definition_can_store_it(self):
        cleaned = api._clean_report_def({"name": "monthly",
                                         "sections": ["health", "summary"]})
        self.assertIn("summary", cleaned["sections"])

    def test_an_unsectioned_definition_still_means_everything_but_summary(self):
        cleaned = api._clean_report_def({"name": "monthly"})
        self.assertEqual(cleaned["sections"], list(api._REPORT_SECTIONS))
        self.assertNotIn("summary", cleaned["sections"])


class TestTheUiOffersIt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ROOT / "server" / "html" / "static" / "js" / "app.js"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = p.read_text()

    def test_the_section_has_a_label(self):
        """`_REPORT_SECTION_LABELS` is a second registry — a section the server
        knows about but this map does not renders as its raw slug."""
        i = self.js.index("_REPORT_SECTION_LABELS")
        self.assertIn("summary:", self.js[i:i + 400])

    def test_the_server_ships_the_opt_in_list(self):
        src = (_CGI / "reports_handlers.py").read_text()
        self.assertIn("'opt_in_sections': list(_REPORT_OPT_IN_SECTIONS)", src)

    def test_an_opt_in_section_renders_unchecked(self):
        i = self.js.index("const optIn = new Set(")
        seg = self.js[i:i + 900]
        self.assertIn("opt_in_sections", seg)
        self.assertIn("optIn.has(s) ? '' : ' checked'", seg)

    def test_it_says_what_it_costs(self):
        self.assertIn("costs tokens", self.js)


if __name__ == "__main__":
    unittest.main()
