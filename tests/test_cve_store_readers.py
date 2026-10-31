"""Every function that reads the CVE findings store is accounted for.

The rule "leave out what is accepted as a risk, and with the count option on what no update can clear" was written
down and applied in most places, and missed in a few: the sidebar badge and the Checks count counted accepted risks
for years, and none of the six counters looked at a fix status. A rule that is applied in most places reads as
enforced, so this file enumerates the population instead of spot-checking it.

The census is derived from the source: every top-level function in server/cgi-bin that names CVE_FINDINGS_FILE
(32 on 2026-10-31). Each is classified below as a reader that produces a NUMBER an operator reads (it must follow the
count option and leave out accepted risks) or as one that counts or lists every finding on purpose (reports,
compliance evidence, the assistant's context, the scanner itself). A new reader fails the census until it is placed,
so the decision cannot be skipped by accident.
"""
import ast
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"

# What the source of a reader is searched for. They are text markers, not a parser of intent: the point is that a
# reader which stops mentioning them has stopped following the rule, and the test says so.
COUNT_RULE = ("cve_fixes.counted", "_counted_cve_findings", "get_cve_count_fixable_only", "_cve_count_rule")
ACCEPTED_RISK = ("CVE_IGNORE_FILE", "apply_ignore_list", "cve_ignore_applies", "ignore_ids", "ignore_data",
                 "get('ignored')", "'ignored'")
SEVERITY = ("'critical'", '"critical"', "'high'", '"high"', "severity")

NUMBERS = "a number an operator reads: follows the count option and leaves out accepted risks"
EVERYTHING = "counts or lists every finding on purpose"

READERS = {
    # the six counters
    "api.py:handle_nav_counts": (NUMBERS, "sidebar badge"),
    "api.py:handle_home": (NUMBERS, "dashboard tile"),
    "api.py:_compute_attention": (NUMBERS, "Needs attention"),
    "api.py:_compute_fleet_risk": (NUMBERS, "risk score; hands the option to _device_risk"),
    "api.py:_cve_high_counts": (NUMBERS, "Checks, and the Needs attention preview"),
    "cve_handlers.py:handle_cve_findings": (NUMBERS, "CVE page totals and host rows"),
    # everything else
    "advisory_handlers.py:_build_advisory": (EVERYTHING, "the Security Advisory ranks problems from the decorated list"),
    "ai_triage_handlers.py:_triage_tools": (EVERYTHING, "the assistant's context"),
    "api.py:_alert_ticket_detail": (EVERYTHING, "the text of a ticket lists the findings"),
    "api.py:_purge_device": (EVERYTHING, "deletes a host's rows"),
    "api.py:_qe_cve_rows": (EVERYTHING, "Fleet query rows"),
    "api.py:_rag_source_files": (EVERYTHING, "the files whose change re-indexes the assistant"),
    "api.py:_rag_build_corpus": (EVERYTHING, "the assistant's corpus"),
    "api.py:_compliance_facts": (EVERYTHING, "compliance evidence"),
    "api.py:_build_runbook_snapshot": (EVERYTHING, "runbook text"),
    "api.py:_cve_fixable_by_device": (EVERYTHING, "the Patches link counts the findings a pending patch fixes"),
    "api.py:handle_fleet_query": (EVERYTHING, "an ad-hoc query over the stored findings"),
    "api.py:_compute_compliance": (EVERYTHING, "compliance evidence"),
    "api.py:_timeline_collect": (EVERYTHING, "timeline events"),
    "api.py:_timeline_etag_source": (EVERYTHING, "the timeline's cache key"),
    "api.py:_build_posture_digest": (EVERYTHING, "the scheduled posture digest is a report"),
    "api.py:_cve_scan_worker": (EVERYTHING, "the scanner writes the store"),
    "api.py:_collect_finding_cve_ids": (EVERYTHING, "the ids whose details are cached"),
    "api.py:run_cve_campaign_sample_if_due": (EVERYTHING, "campaign progress"),
    "api.py:_sbom_stores": (EVERYTHING, "SBOM export"),
    "api.py:_build_metrics_ctx": (EVERYTHING, "metrics export"),
    "api.py:_autoheal_recheck": (EVERYTHING, "re-checks a host after a fix"),
    "cve_handlers.py:handle_cve_realert": (EVERYTHING, "re-alert backlog: it has the alert option, not the count option"),
    "cve_handlers.py:handle_cve_campaigns": (EVERYTHING, "campaign status"),
    "cve_handlers.py:handle_cve_exposure_ranked": (EVERYTHING, "the ranking weights a fixable finding higher"),
    "cve_handlers.py:handle_cve_device": (EVERYTHING, "the host view lists every finding with its fix status"),
    "reports_handlers.py:_build_fleet_report": (EVERYTHING, "the printable report"),
}

# Readers that mention a severity and never mention the accepted-risk list: they count accepted risks too. They
# are reports, compliance evidence, the assistant's context, an ad-hoc query and the scanner itself, so it was left
# alone when the six counters were fixed. The list can only shrink: a reader that starts applying the list must
# come off it, and a new reader that counts by severity must apply the list or be added here with a reason.
COUNTS_ACCEPTED_RISKS = {
    "api.py:_rag_build_corpus": "the assistant's corpus",
    "api.py:handle_fleet_query": "an ad-hoc query: hosts with at least N critical or high findings",
    "api.py:_compute_compliance": "compliance evidence",
    "api.py:_build_posture_digest": "the scheduled digest",
    "api.py:_cve_scan_worker": "the scanner; the alert path applies the list",
}


def census():
    """{'file.py:function': source} for every top-level function that names CVE_FINDINGS_FILE."""
    out = {}
    for path in sorted(CGI.glob("*.py")):
        src = path.read_text()
        lines = src.splitlines()
        for fn in ast.parse(src).body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            hit = any((isinstance(n, ast.Name) and n.id == "CVE_FINDINGS_FILE")
                      or (isinstance(n, ast.Attribute) and n.attr == "CVE_FINDINGS_FILE")
                      for n in ast.walk(fn))
            if hit:
                out[f"{path.name}:{fn.name}"] = "\n".join(lines[fn.lineno - 1:fn.end_lineno])
    return out


def mentions(src, markers):
    return any(m in src for m in markers)


class TestTheCensusIsAccountedFor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = census()

    def test_the_census_is_not_empty_and_sees_known_readers(self):
        """A gate can inspect nothing and pass. 32 readers today; the known-good ones must be in it."""
        self.assertGreaterEqual(len(self.found), 30)
        for known in ("api.py:handle_nav_counts", "cve_handlers.py:handle_cve_findings", "api.py:_compute_attention"):
            self.assertIn(known, self.found)

    def test_every_reader_is_classified_and_every_classification_is_a_reader(self):
        found, listed = set(self.found), set(READERS)
        self.assertEqual(sorted(found - listed), [],
                         "a function reads the CVE findings store and is not classified in READERS: decide whether "
                         "its number follows the count option (NUMBERS) or counts everything on purpose (EVERYTHING)")
        self.assertEqual(sorted(listed - found), [],
                         "READERS lists a function that no longer reads the CVE findings store")


class TestTheSixCountersFollowTheRule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = census()
        cls.numbers = sorted(k for k, (kind, _) in READERS.items() if kind == NUMBERS)

    def test_there_are_six_and_the_population_is_not_empty(self):
        self.assertEqual(len(self.numbers), 6)

    def test_each_one_follows_the_count_option(self):
        for key in self.numbers:
            self.assertTrue(mentions(self.found[key], COUNT_RULE), f"{key} stopped following the count option")

    def test_each_one_leaves_out_accepted_risks(self):
        for key in self.numbers:
            self.assertTrue(mentions(self.found[key], ACCEPTED_RISK), f"{key} counts accepted risks")

    def test_no_other_reader_follows_the_option_without_being_classified_as_a_counter(self):
        """If a reader picks the rule up, READERS must say so, or the table stops being true."""
        for key, (kind, _) in READERS.items():
            if kind == EVERYTHING:
                self.assertFalse(mentions(self.found[key], COUNT_RULE),
                                 f"{key} follows the count option but READERS calls it EVERYTHING")

    def test_the_risk_score_gets_the_option_from_its_caller_and_applies_it(self):
        src = (CGI / "api.py").read_text()
        body = src[src.index("def _device_risk("):]
        body = body[:body.index("\ndef ", 10)]
        self.assertIn("cve_fixable_only=None", body)
        self.assertIn("cve_fixes.counted(f, True)", body)


class TestAcceptedRisksAreLeftOutWhereverACountIsShown(unittest.TestCase):
    def test_the_frozen_list_matches_the_readers_that_ignore_the_accepted_risk_list(self):
        found = census()
        ignoring = {k for k, src in found.items() if mentions(src, SEVERITY) and not mentions(src, ACCEPTED_RISK)}
        self.assertEqual(sorted(ignoring - set(COUNTS_ACCEPTED_RISKS)), [],
                         "a reader counts by severity and never applies the accepted-risk list: apply it "
                         "(cve_ignore_applies / apply_ignore_list) or add it to COUNTS_ACCEPTED_RISKS with a reason")
        self.assertEqual(sorted(set(COUNTS_ACCEPTED_RISKS) - ignoring), [],
                         "a reader listed in COUNTS_ACCEPTED_RISKS now applies the list (or is gone): remove it")


if __name__ == "__main__":
    unittest.main()
