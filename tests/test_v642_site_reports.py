"""v6.4.2 — a scheduled report can be scoped to one customer.

`GET /api/report/site/{id}` has built a full posture report scoped to one site
(= one customer, per docs/sites.md) since v5.0.1, and the Sites table has a
Report button. But the report-definition schema had no site field, so the
scheduler could only ever send the WHOLE-FLEET report.

An MSP with 12 customer sites, per-site billing and per-site RBAC already
configured could not say "email Acme their monthly report on the 1st". Their
options were: hand-download a JSON blob per customer per month, or send all 12
customers the whole fleet's numbers — which leaks every other customer's device
counts, CVE totals and health.

The download half was smaller than the finding suggested and worth stating
precisely: the endpoint has always accepted `?format=csv` and the client
function has always taken a format argument. The Sites-row button simply never
passed one, so `fmt` fell back to 'json' and the operator got a raw blob.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sitereport642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestTheDefinitionCarriesASite(unittest.TestCase):
    def setUp(self):
        api.save(api.SITES_FILE, {"s1": {"name": "Acme", "slug": "acme"}})
        api._LOAD_CACHE.clear()

    def test_a_valid_site_is_stored(self):
        d = api._clean_report_def({"name": "Acme monthly", "site": "s1",
                                   "cron": "0 8 1 * *", "enabled": True,
                                   "recipients": ["am@acme.test"]})
        self.assertEqual(d["site"], "s1")

    def test_no_site_still_means_whole_fleet(self):
        """Every existing definition has no site key — the field must be
        additive or a saved report changes meaning on upgrade."""
        d = api._clean_report_def({"name": "Fleet monthly"})
        self.assertEqual(d["site"], "")

    def test_an_unknown_site_is_refused_not_dropped(self):
        """A silently-dropped site schedules a WHOLE-FLEET report to a
        customer's account manager — the exact leak the field exists to stop."""
        self.assertEqual(api._clean_report_def({"name": "x", "site": "nope"}),
                         "badsite")

    def test_the_save_handler_surfaces_the_refusal(self):
        src = (_CGI / "reports_handlers.py").read_text()
        fn = src[src.index("def handle_report_defs_save"):]
        fn = fn[:fn.index("\ndef ")]
        self.assertIn("badsite", fn)
        self.assertIn("unknown site", fn)

    def test_the_scheduler_actually_scopes_the_build(self):
        """`_build_fleet_report` has taken site_id since the per-site download
        shipped; the scheduled sender simply never passed it, which is the whole
        finding."""
        src = (_CGI / "reports_handlers.py").read_text()
        sys.path.insert(0, str(ROOT / "tests"))
        import srcpin
        fn = srcpin.py_function(src, "_maybe_send_report_definitions")
        self.assertIn("_build_fleet_report(site_id=", fn,
                      "the scheduled sender still builds the whole-fleet report")
        self.assertIn("d.get('site')", fn,
                      "the scope comes from the definition, not a constant")

    def test_the_field_survives_a_round_trip(self):
        d = api._clean_report_def({"name": "Acme", "site": "s1"})
        again = api._clean_report_def(d)
        self.assertEqual(again["site"], "s1")


class TestTheDownloadOffersCsv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()

    def test_the_sites_row_passes_a_format(self):
        """The function has always taken one; the button never passed it, so
        `fmt` fell back to 'json' and the operator hand-converted a raw blob."""
        i = self.js.index('data-action="downloadSiteReport"')
        seg = self.js[i:i + 400]
        self.assertIn("data-arg3=", seg,
                      "still no format argument — the button hands over JSON")

    def test_both_formats_are_reachable(self):
        seg = self.js[self.js.index('data-action="downloadSiteReport"'):][:800]
        self.assertIn('data-arg3="csv"', seg)
        self.assertIn('data-arg3="json"', seg)

    def test_the_endpoint_accepts_csv(self):
        src = (_CGI / "reports_handlers.py").read_text()
        fn = src[src.index("def handle_site_report("):]
        fn = fn[:fn.index("\ndef ")]
        self.assertIn("format", fn)
        self.assertIn("csv", fn)


class TestTheEditor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()
        cls.html = (ROOT / "server" / "html" / "index.html").read_text()

    def test_the_field_exists(self):
        self.assertIn('id="rdef-site"', self.html)

    def test_it_is_saved_loaded_and_reset(self):
        for fn, needle in (("saveReportDef", "site:"),
                           ("editReportDef", "d.site"),
                           ("resetReportDef", "'rdef-site'")):
            with self.subTest(fn=fn):
                body = self.js[self.js.index("function " + fn):]
                body = body[:body.index("\n}\n")]
                self.assertIn(needle, body)

    def test_the_saved_row_says_which_scope_it_is(self):
        """A scheduled report that silently covers the whole fleet when the
        operator meant one customer is the failure this prevents — so the scope
        belongs on the row, not only in the editor."""
        self.assertIn("whole fleet", self.js)
        self.assertIn("_rdefSiteName", self.js)

    def test_the_picker_is_populated_rather_than_left_empty(self):
        """An empty dropdown reads as "no sites exist", not "the Sites page has
        not been opened this session"."""
        self.assertRegex(self.js, r"\basync function _rdefPopulateSites\s*\(")
        self.assertIn("_rdefPopulateSites();", self.js)


if __name__ == "__main__":
    unittest.main()
