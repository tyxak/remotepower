#!/usr/bin/env python3
"""v7.4.6, issue #57: a CVE finding says whether a fix exists for the host's own release.

"On one host I checked every finding: none had a fix installable today. About half have no fix anywhere
yet; the other half are fixed only in newer Debian. Each finding records a fixed version, but nothing says
whether that fix reached the host's release."

OSV keeps one entry per release, and the scanner folded them into one string, so a Debian 12 host was
shown a version only Debian 13 has. The records here have the shapes OSV serves today for curl (read from
api.osv.dev on 2026-10-30), and the scan, the alerts and the report run through the real functions:

  * the pure rules (`cve_fixes`), as tables;
  * `scan_device` with only the two OSV calls and the version comparison replaced;
  * the alert path with the option on and off, and the re-alert;
  * the report counts and the readers that call a finding "fixable".
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_improvements_w3 import _HandlerBase, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import cve_fixes  # noqa: E402
import cve_scanner  # noqa: E402


def entry(ecosystem, fixed=None, name="curl"):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
        "ecosystem_specific": {"urgency": "medium"},
    }


def record(vuln_id, severity, entries):
    return {
        "id": vuln_id,
        "summary": f"{vuln_id} in curl",
        "aliases": [],
        "database_specific": {"severity": severity},
        "affected": [entry(*e) for e in entries],
    }


# The four shapes of the report, as OSV serves them for curl on Debian 12:
FIXED_HERE = record("DEBIAN-CVE-2024-11053", "high",
                    [("Debian:12", "7.88.1-10+deb12u10"), ("Debian:13", "8.11.1-1"), ("Debian:14", "8.11.1-1")])
NEWER_13 = record("DEBIAN-CVE-2024-2379", "high",
                  [("Debian:12", None), ("Debian:13", "8.7.1-1"), ("Debian:14", "8.7.1-1")])
NEWER_14 = record("DEBIAN-CVE-2025-10966", "critical",
                  [("Debian:12", None), ("Debian:13", None), ("Debian:14", "8.17.0~rc2-1")])
NO_FIX = record("DEBIAN-CVE-2026-107928", "critical",
                [("Debian:12", None), ("Debian:13", None), ("Debian:14", None)])
FIXED_OLDER_ONLY = record("DEBIAN-CVE-2024-9999", "high", [("Debian:11", "7.74.0-1.3+deb11u14"), ("Debian:12", None)])
RECORDS = {r["id"]: r for r in (FIXED_HERE, NEWER_13, NEWER_14, NO_FIX, FIXED_OLDER_ONLY)}


def naive_ge(installed, fixed):
    """Stands in for `dpkg --compare-versions`, which the machine running the tests may not have: compares the
    numbers in the two strings in order. Enough for the versions used here."""
    def nums(v):
        return tuple(int(n) for n in re.findall(r"\d+", v))
    return nums(installed) >= nums(fixed)


class TestTheRulesAsATable(unittest.TestCase):

    def fixes(self, rec):
        return cve_fixes.extract(rec)

    def test_a_release_is_read_from_the_ecosystem_name(self):
        self.assertEqual(cve_fixes.release_of("Debian:12"), ("Debian", (12,)))
        self.assertEqual(cve_fixes.release_of("Alpine:v3.19"), ("Alpine", (3, 19)))
        for named_without_release in ("Ubuntu", "Rocky Linux", "AlmaLinux", "Red Hat", "Debian:", "Debian:x",
                                      "Alpine:edge", "Debian:12:extra", "", None, 12, ["Debian:12"]):
            self.assertIsNone(cve_fixes.release_of(named_without_release), named_without_release)

    def test_every_entry_of_the_record_is_kept_apart(self):
        self.assertEqual(
            self.fixes(NEWER_13),
            {"Debian:12": {"curl": []}, "Debian:13": {"curl": ["8.7.1-1"]}, "Debian:14": {"curl": ["8.7.1-1"]}},
        )

    def test_fixed_in_the_hosts_own_release(self):
        c = cve_fixes.classify(self.fixes(FIXED_HERE), "Debian:12", "curl")
        self.assertEqual((c["status"], c["fixed"], c["elsewhere"]), ("fixed", ["7.88.1-10+deb12u10"], {}))

    def test_fixed_only_in_a_newer_release_names_the_nearest_first(self):
        c = cve_fixes.classify(self.fixes(NEWER_13), "Debian:12", "curl")
        self.assertEqual(c["status"], "newer_release")
        self.assertEqual(c["fixed"], [])
        self.assertEqual(list(c["elsewhere"]), ["Debian:13", "Debian:14"])

    def test_no_release_has_a_fix(self):
        c = cve_fixes.classify(self.fixes(NO_FIX), "Debian:12", "curl")
        self.assertEqual((c["status"], c["fixed"], c["elsewhere"]), ("none", [], {}))

    def test_the_same_record_reads_differently_for_each_release(self):
        fixes = self.fixes(NEWER_14)
        self.assertEqual(cve_fixes.classify(fixes, "Debian:12", "curl")["status"], "newer_release")
        self.assertEqual(cve_fixes.classify(fixes, "Debian:13", "curl")["status"], "newer_release")
        self.assertEqual(cve_fixes.classify(fixes, "Debian:14", "curl")["status"], "fixed")

    def test_a_fix_in_an_older_release_is_not_a_fix_for_this_one(self):
        c = cve_fixes.classify(self.fixes(FIXED_OLDER_ONLY), "Debian:12", "curl")
        self.assertEqual(c["status"], "none")
        self.assertEqual(cve_fixes.patched_by(self.fixes(FIXED_OLDER_ONLY), "Debian:12", "curl"), [])

    def test_alpine_is_told_apart_by_its_release_too(self):
        rec = record("ALPINE-1", "high", [("Alpine:v3.18", None, "zlib"), ("Alpine:v3.19", "1.3-r0", "zlib"),
                                           ("Alpine:v3.20", "1.3-r0", "zlib")])
        fixes = cve_fixes.extract(rec)
        self.assertEqual(cve_fixes.classify(fixes, "Alpine:v3.18", "zlib")["status"], "newer_release")
        self.assertEqual(cve_fixes.classify(fixes, "Alpine:v3.19", "zlib")["status"], "fixed")

    def test_a_distribution_without_the_release_in_its_name_is_unknown(self):
        rec = record("USN-1", "high", [("Ubuntu:22.04:LTS", "1.2-3ubuntu0.1", "zlib")])
        self.assertEqual(cve_fixes.extract(rec), {})
        self.assertEqual(cve_fixes.classify({}, "Ubuntu", "zlib")["status"], "unknown")

    def test_a_record_cached_before_the_entries_were_kept_apart_is_unknown(self):
        self.assertEqual(cve_fixes.classify(None, "Debian:12", "curl")["status"], "unknown")

    def test_a_record_with_no_entry_for_the_package_is_unknown_and_not_none(self):
        """Saying "no fix exists" about a package the record does not mention would be a claim, not a gap."""
        self.assertEqual(cve_fixes.classify(self.fixes(NO_FIX), "Debian:12", "openssl")["status"], "unknown")

    def test_junk_neither_raises_nor_decides(self):
        for junk in (None, 3, "x", [], {"affected": "x"}, {"affected": [None, 3, {"package": 5}, {"package": {}}]},
                     {"affected": [{"package": {"ecosystem": "Debian:12", "name": ""}}]},
                     {"affected": [{"package": {"ecosystem": "Debian:12", "name": "curl"}, "ranges": [None, 3, {"events": "x"}]}]}):
            out = cve_fixes.extract(junk)
            self.assertIsInstance(out, dict)
        for junk_fixes in ("x", 3, [], {"Debian:12": "x"}, {"Debian:12": {"curl": "x"}}, {"Debian:12": {"curl": [None, 3]}}):
            c = cve_fixes.classify(junk_fixes, "Debian:12", "curl")
            self.assertIn(c["status"], cve_fixes.STATUSES)

    def test_a_hostile_record_cannot_fill_the_cache(self):
        rec = {"affected": [entry("Debian:12", None) for _ in range(1)]}
        rec["affected"][0]["ranges"] = [{"events": [{"fixed": f"1.{i}"} for i in range(500)]}]
        self.assertEqual(len(cve_fixes.extract(rec)["Debian:12"]["curl"]), cve_fixes.MAX_FIXED_PER_ENTRY)

    def test_a_version_or_a_name_past_its_bound_is_left_out(self):
        """An enormous string from a record would otherwise be copied into the cache and into every finding."""
        rec = {"affected": [entry("Debian:12", None)]}
        rec["affected"][0]["ranges"] = [{"events": [{"fixed": "9" * (cve_fixes.MAX_VERSION_LEN + 1)}, {"fixed": "1.2-3"}]}]
        self.assertEqual(cve_fixes.extract(rec), {"Debian:12": {"curl": ["1.2-3"]}})
        long_name = {"affected": [entry("Debian:12", "1", "p" * (cve_fixes.MAX_NAME_LEN + 1))]}
        self.assertEqual(cve_fixes.extract(long_name), {})

    def test_a_record_cannot_name_more_entries_than_the_bound(self):
        rec = {"affected": [entry("Debian:12", "1", f"pkg{i}") for i in range(cve_fixes.MAX_ENTRIES + 50)]}
        out = cve_fixes.extract(rec)
        self.assertEqual(sum(len(p) for p in out.values()), cve_fixes.MAX_ENTRIES)
        # a package left out reads "unknown", the older behaviour, and never "no fix exists"
        self.assertEqual(cve_fixes.classify(out, "Debian:12", f"pkg{cve_fixes.MAX_ENTRIES + 10}")["status"], "unknown")

    def test_what_counts_as_fixable(self):
        self.assertTrue(cve_fixes.is_fixable({"fix_status": "fixed", "fixed_version": "1"}))
        self.assertFalse(cve_fixes.is_fixable({"fix_status": "newer_release", "fixed_version": "8.7.1-1"}))
        self.assertFalse(cve_fixes.is_fixable({"fix_status": "none"}))
        # unknown, and a finding scanned before 7.4.6, keep the old meaning of a fixed version
        self.assertTrue(cve_fixes.is_fixable({"fix_status": "unknown", "fixed_version": "1"}))
        self.assertTrue(cve_fixes.is_fixable({"fixed_version": "1"}))
        self.assertFalse(cve_fixes.is_fixable({"fixed_version": " "}))
        self.assertFalse(cve_fixes.is_fixable({}))
        self.assertFalse(cve_fixes.is_fixable(None))

    def test_the_counts_add_up_to_the_findings_that_are_not_ignored(self):
        findings = [
            {"vuln_id": "A", "fix_status": "fixed", "fixed_version": "1"},
            {"vuln_id": "B", "fix_status": "newer_release"},
            {"vuln_id": "C", "fix_status": "none"},
            {"vuln_id": "D", "fix_status": "unknown"},
            {"vuln_id": "E", "fixed_version": "2"},  # scanned before 7.4.6
            {"vuln_id": "F"},
            {"vuln_id": "G", "fix_status": "fixed", "fixed_version": "1"},  # ignored
        ]
        self.assertEqual(cve_fixes.summarize(findings, {"G"}),
                         {"fixable": 2, "newer_release": 1, "none": 1, "unchecked": 2})

    def test_a_known_exploited_finding_is_found_by_any_of_its_names(self):
        kev = {"CVE-2024-2379"}
        self.assertTrue(cve_fixes.finding_is_kev({"vuln_id": "cve-2024-2379"}, kev))
        self.assertTrue(cve_fixes.finding_is_kev({"vuln_id": "DEBIAN-CVE-2024-2379", "aliases": ["CVE-2024-2379"]}, kev))
        self.assertFalse(cve_fixes.finding_is_kev({"vuln_id": "DEBIAN-CVE-2024-2379"}, kev))
        self.assertFalse(cve_fixes.finding_is_kev({"vuln_id": "x"}, set()))

    def test_the_alert_rule(self):
        unfixable = {"vuln_id": "A", "fix_status": "newer_release"}
        fixable = {"vuln_id": "B", "fix_status": "fixed", "fixed_version": "1"}
        exploited = {"vuln_id": "C", "fix_status": "none", "aliases": ["CVE-1"]}
        kev = {"CVE-1"}
        for f in (unfixable, fixable, exploited):
            self.assertTrue(cve_fixes.alert_candidate(f, False, kev), f)
        self.assertFalse(cve_fixes.alert_candidate(unfixable, True, kev))
        self.assertTrue(cve_fixes.alert_candidate(fixable, True, kev))
        self.assertTrue(cve_fixes.alert_candidate(exploited, True, kev))


class _Scan(unittest.TestCase):
    """`scan_device` with the two OSV calls and the version comparison replaced. Nothing else is."""

    def setUp(self):
        self.cache = Path(tempfile.mkdtemp(prefix="rp-v746-cve-"))
        self.detail_calls = []

        def details(vuln_id):
            self.detail_calls.append(vuln_id)
            return json.loads(json.dumps(RECORDS[vuln_id]))

        def querybatch(queries):
            return [{"vulns": [{"id": v} for v in self.hits.get(q["package"]["name"], [])]} for q in queries]

        self.hits = {}
        for patcher in (
            mock.patch.object(cve_scanner, "_osv_querybatch", querybatch),
            mock.patch.object(cve_scanner, "_osv_vuln_details", details),
            mock.patch.object(cve_scanner, "_dpkg_ge", naive_ge),
            mock.patch.object(cve_scanner, "_debian_severity_fallback", side_effect=AssertionError("network")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, ecosystem, version, ids, package="curl"):
        self.hits = {package: list(ids)}
        out = cve_scanner.scan_device("d1", [{"name": package, "version": version}], ecosystem, self.cache)
        self.assertNotIn("error", out, out.get("error"))
        return {f["vuln_id"]: f for f in out["findings"]}, out


class TestAScanOfADebianTwelveHost(_Scan):
    IDS = [FIXED_HERE["id"], NEWER_13["id"], NEWER_14["id"], NO_FIX["id"]]

    def test_the_report_of_the_issue_each_finding_says_where_it_stands(self):
        found, _ = self.scan("Debian:12", "7.88.1-10+deb12u5", self.IDS)
        self.assertEqual({k: v["fix_status"] for k, v in found.items()},
                         {"DEBIAN-CVE-2024-11053": "fixed", "DEBIAN-CVE-2024-2379": "newer_release",
                          "DEBIAN-CVE-2025-10966": "newer_release", "DEBIAN-CVE-2026-107928": "none"})

    def test_the_fixed_version_is_the_one_the_host_can_install(self):
        found, _ = self.scan("Debian:12", "7.88.1-10+deb12u5", self.IDS)
        self.assertEqual(found["DEBIAN-CVE-2024-11053"]["fixed_version"], "7.88.1-10+deb12u10")
        for vuln_id in ("DEBIAN-CVE-2024-2379", "DEBIAN-CVE-2025-10966", "DEBIAN-CVE-2026-107928"):
            self.assertEqual(found[vuln_id]["fixed_version"], "", vuln_id)

    def test_a_finding_fixed_in_a_newer_release_names_where(self):
        found, _ = self.scan("Debian:12", "7.88.1-10+deb12u5", self.IDS)
        self.assertEqual(found["DEBIAN-CVE-2024-2379"]["fixed_elsewhere"],
                         {"Debian:13": "8.7.1-1", "Debian:14": "8.7.1-1"})
        self.assertEqual(found["DEBIAN-CVE-2025-10966"]["fixed_elsewhere"], {"Debian:14": "8.17.0~rc2-1"})
        self.assertNotIn("fixed_elsewhere", found["DEBIAN-CVE-2024-11053"])
        self.assertNotIn("fixed_elsewhere", found["DEBIAN-CVE-2026-107928"])

    def test_the_counts_of_the_report_come_out_right(self):
        _, out = self.scan("Debian:12", "7.88.1-10+deb12u5", self.IDS)
        self.assertEqual(cve_fixes.summarize(out["findings"], set()),
                         {"fixable": 1, "newer_release": 2, "none": 1, "unchecked": 0})

    def test_the_same_record_on_debian_thirteen_is_fixed_where_thirteen_has_the_fix(self):
        found, _ = self.scan("Debian:13", "8.7.0-1", self.IDS)
        self.assertEqual({k: v["fix_status"] for k, v in found.items()},
                         {"DEBIAN-CVE-2024-11053": "fixed", "DEBIAN-CVE-2024-2379": "fixed",
                          "DEBIAN-CVE-2025-10966": "newer_release", "DEBIAN-CVE-2026-107928": "none"})
        self.assertEqual(found["DEBIAN-CVE-2024-2379"]["fixed_version"], "8.7.1-1")

    def test_a_package_past_a_newer_releases_fix_is_already_patched(self):
        """A backport newer than Debian 13's curl holds that release's fixes, whatever Debian 12 says."""
        found, out = self.scan("Debian:12", "8.14.1-1~bpo12+1", self.IDS)
        self.assertEqual(sorted(found), ["DEBIAN-CVE-2025-10966", "DEBIAN-CVE-2026-107928"])
        self.assertEqual(out["suppressed_patched"], 2)

    def test_a_fix_in_an_older_release_does_not_hide_a_finding(self):
        """The old rule folded Debian 11's fix in, and a Debian 12 package is past it, so the finding vanished."""
        found, out = self.scan("Debian:12", "7.88.1-10+deb12u5", [FIXED_OLDER_ONLY["id"]])
        self.assertEqual(sorted(found), ["DEBIAN-CVE-2024-9999"])
        self.assertEqual(found["DEBIAN-CVE-2024-9999"]["fix_status"], "none")
        self.assertEqual(out["suppressed_patched"], 0)


class TestADistributionThatCannotBeToldApart(_Scan):

    def test_ubuntu_keeps_the_old_meaning_and_says_unknown(self):
        usn = {"id": "USN-9999-1", "summary": "zlib", "aliases": [], "database_specific": {"severity": "high"},
               "affected": [entry("Ubuntu:22.04:LTS", "1.2.11-1ubuntu0.1", "zlib"),
                            entry("Ubuntu:24.04:LTS", "1.3-1ubuntu1", "zlib")]}
        RECORDS["USN-9999-1"] = usn
        self.addCleanup(RECORDS.pop, "USN-9999-1", None)
        found, _ = self.scan("Ubuntu", "1.2.11-1", ["USN-9999-1"], package="zlib")
        finding = found["USN-9999-1"]
        self.assertEqual(finding["fix_status"], "unknown")
        self.assertEqual(finding["fixed_version"], "1.3-1ubuntu1")  # the folded string, as before
        self.assertNotIn("fixed_elsewhere", finding)
        self.assertTrue(cve_fixes.is_fixable(finding))


class TestTheDetailsCache(_Scan):

    def test_the_cache_keeps_the_fixes_of_every_release(self):
        self.scan("Debian:12", "7.88.1-10+deb12u5", [NEWER_13["id"]])
        cached = json.loads((self.cache / "cve_details_cache.json").read_text())
        self.assertEqual(cached["DEBIAN-CVE-2024-2379"]["eco_fix"]["Debian:13"], {"curl": ["8.7.1-1"]})

    def test_an_entry_from_before_7_4_6_is_fetched_again_once(self):
        old = {"summary": "x", "severity": "high", "severity_source": "database_specific", "aliases": [],
               "cached_at": 2**31, "fixed_versions": {"curl": "8.7.1-1"}}
        (self.cache / "cve_details_cache.json").write_text(json.dumps({"DEBIAN-CVE-2024-2379": old}))
        found, _ = self.scan("Debian:12", "7.88.1-10+deb12u5", [NEWER_13["id"]])
        self.assertEqual(self.detail_calls, ["DEBIAN-CVE-2024-2379"])
        self.assertEqual(found["DEBIAN-CVE-2024-2379"]["fix_status"], "newer_release")
        self.scan("Debian:12", "7.88.1-10+deb12u5", [NEWER_13["id"]])
        self.assertEqual(self.detail_calls, ["DEBIAN-CVE-2024-2379"], "a current entry must not be fetched again")

    def test_a_fresh_entry_is_not_fetched_again(self):
        self.scan("Debian:12", "7.88.1-10+deb12u5", [NEWER_13["id"]])
        self.scan("Debian:12", "7.88.1-10+deb12u5", [NEWER_13["id"]])
        self.assertEqual(self.detail_calls, ["DEBIAN-CVE-2024-2379"])


# ── the alert path and the report, through the real functions ───────────────────────────────────────────

def finding(vuln_id, severity="critical", status="fixed", fixed="1.0", **extra):
    f = {"vuln_id": vuln_id, "package": "curl", "version": "7", "severity": severity, "fix_status": status,
         "fixed_version": fixed if status == "fixed" else "", "aliases": []}
    f.update(extra)
    return f


class _Alerts(_HandlerBase):

    def setUp(self):
        super().setUp()
        for attr in ("CVE_FINDINGS_FILE", "CVE_IGNORE_FILE", "KEV_EPSS_FILE", "PACKAGES_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.fired = []
        api.fire_webhook = lambda ev, p=None: self.fired.append((ev, p))
        api.save(api.DEVICES_FILE, {"d1": {"name": "web"}})
        api.save(api.CVE_IGNORE_FILE, {})
        api.save(api.KEV_EPSS_FILE, {"kev": [], "epss": {}})
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def option(self, on):
        api.save(api.CONFIG_FILE, {"cve_alert_fixable_only": on})
        api._LOAD_CACHE.clear()

    def scan(self, previous, current):
        api._detect_new_cve_and_fire_webhook("d1", {"d1": {"name": "web"}}, previous, current)
        return [p for e, p in self.fired if e == "cve_found"]

    def cleared(self):
        return [p for e, p in self.fired if e == "cve_cleared"]


class TestTheAlertOption(_Alerts):

    def test_off_every_new_finding_in_the_severity_filter_alerts_as_before(self):
        sent = self.scan([], [finding("A", status="fixed"), finding("B", status="none"), finding("C", status="newer_release")])
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["count"], 3)

    def test_on_only_a_finding_an_update_can_clear_alerts(self):
        self.option(True)
        sent = self.scan([], [finding("A", status="fixed"), finding("B", status="none"), finding("C", status="newer_release")])
        self.assertEqual(len(sent), 1)
        self.assertEqual((sent[0]["count"], sent[0]["critical"]), (1, 1))
        self.assertEqual([s["id"] for s in sent[0]["sample"]], ["A"])

    def test_on_a_host_with_nothing_fixable_raises_nothing(self):
        self.option(True)
        self.assertEqual(self.scan([], [finding("B", status="none"), finding("C", status="newer_release")]), [])

    def test_a_known_exploited_finding_alerts_whatever_its_fix_status(self):
        self.option(True)
        api.save(api.KEV_EPSS_FILE, {"kev": ["CVE-2024-2379"], "epss": {}})
        api._LOAD_CACHE.clear()
        sent = self.scan([], [finding("DEBIAN-CVE-2024-2379", status="newer_release", aliases=["CVE-2024-2379"]),
                              finding("B", status="none")])
        self.assertEqual([s["id"] for s in sent[0]["sample"]], ["DEBIAN-CVE-2024-2379"])

    def test_a_finding_that_waited_for_a_fix_alerts_when_the_fix_arrives(self):
        """The case the option exists for, and the one an alert that only looked at new ids would miss."""
        self.option(True)
        waiting = finding("A", status="newer_release")
        self.assertEqual(self.scan([], [waiting]), [])
        arrived = finding("A", status="fixed", fixed="7.88.1-10+deb12u10")
        sent = self.scan([waiting], [arrived])
        self.assertEqual([s["id"] for s in sent[0]["sample"]], ["A"])

    def test_a_finding_that_already_alerted_does_not_alert_again(self):
        self.option(True)
        same = finding("A", status="fixed")
        self.assertEqual(self.scan([same], [same]), [])

    def test_off_a_finding_seen_before_never_alerts_again_whatever_changed(self):
        waiting = finding("A", status="newer_release")
        arrived = finding("A", status="fixed")
        self.assertEqual(self.scan([waiting], [arrived]), [])

    def test_the_severity_filter_and_the_accepted_risk_list_still_apply(self):
        self.option(True)
        api.save(api.CVE_IGNORE_FILE, {"C": {"scope": "global"}})
        api._LOAD_CACHE.clear()
        sent = self.scan([], [finding("A", severity="medium"), finding("B", severity="high"), finding("C")])
        self.assertEqual([s["id"] for s in sent[0]["sample"]], ["B"])

    def test_a_finding_scanned_before_7_4_6_counts_by_its_fixed_version(self):
        self.option(True)
        old_fixable = {"vuln_id": "A", "package": "curl", "severity": "high", "fixed_version": "2.0"}
        old_unfixable = {"vuln_id": "B", "package": "curl", "severity": "high", "fixed_version": ""}
        sent = self.scan([], [old_fixable, old_unfixable])
        self.assertEqual([s["id"] for s in sent[0]["sample"]], ["A"])

    def test_the_recovery_is_not_changed_by_the_option(self):
        """cve_cleared closes the cve_found alert; a switch turned on while one is open must not strand it."""
        self.option(True)
        self.scan([finding("B", status="none")], [])
        self.assertEqual(len(self.cleared()), 1)

    def test_only_the_word_true_turns_it_on(self):
        for value, expected in ((True, True), (False, False), ("true", False), ("false", False), (1, False), (None, False)):
            api.save(api.CONFIG_FILE, {"cve_alert_fixable_only": value})
            api._LOAD_CACHE.clear()
            self.assertIs(api.get_cve_alert_fixable_only(), expected, value)


class TestTheRealert(_Alerts):

    def setUp(self):
        super().setUp()
        api.method = lambda: "POST"
        api.save(api.CVE_FINDINGS_FILE, {"d1": {"findings": [finding("A", status="fixed"), finding("B", status="none")]}})
        api._LOAD_CACHE.clear()

    def realert(self):
        out = self.call(api.handle_cve_realert)
        sent = [p for e, p in self.fired if e == "cve_found"]
        return out, sent

    def test_off_it_raises_the_whole_backlog(self):
        _, sent = self.realert()
        self.assertEqual(sent[0]["count"], 2)

    def test_on_it_raises_what_the_scan_would(self):
        self.option(True)
        _, sent = self.realert()
        self.assertEqual((sent[0]["count"], [s["id"] for s in sent[0]["sample"]]), (1, ["A"]))

    def test_on_a_host_with_nothing_that_would_alert_is_not_counted(self):
        self.option(True)
        api.save(api.CVE_FINDINGS_FILE, {"d1": {"findings": [finding("B", status="none")]}})
        api._LOAD_CACHE.clear()
        out, sent = self.realert()
        self.assertEqual((out["devices"], sent), (0, []))


class TestTheSettingIsSavedAndRead(_Alerts):

    def save(self, **body):
        api.method = lambda: "POST"
        api.get_json_body = lambda: body
        self.call(api.handle_config_save)
        api._LOAD_CACHE.clear()

    def test_it_defaults_to_off_and_is_read_back(self):
        api.method = lambda: "GET"
        self.assertIs(self.call(api.handle_config_get)["cve_alert_fixable_only"], False)
        self.save(cve_alert_fixable_only=True)
        self.assertIs(api.get_cve_alert_fixable_only(), True)
        api.method = lambda: "GET"
        self.assertIs(self.call(api.handle_config_get)["cve_alert_fixable_only"], True)

    def test_it_can_be_turned_off_again(self):
        self.save(cve_alert_fixable_only=True)
        self.save(cve_alert_fixable_only=False)
        self.assertIs(api.get_cve_alert_fixable_only(), False)

    def test_a_save_that_does_not_mention_it_leaves_it(self):
        self.save(cve_alert_fixable_only=True)
        self.save(server_name="x")
        self.assertIs(api.get_cve_alert_fixable_only(), True)


class TestTheReportAndTheReadersAgree(_Alerts):

    def setUp(self):
        super().setUp()
        api.method = lambda: "GET"
        api.save(api.PACKAGES_FILE, {"d1": {"ecosystem": "Debian:12", "count": 4}})
        api.save(api.CVE_FINDINGS_FILE, {"d1": {"scanned_at": 5, "findings": [
            finding("A", status="fixed"),
            finding("B", status="newer_release", fixed_elsewhere={"Debian:13": "8.7.1-1"}),
            finding("C", status="none"),
            finding("D", status="fixed"),                       # ignored below
            {"vuln_id": "E", "severity": "high", "fixed_version": "2.0"},   # scanned before 7.4.6
        ]}})
        api.save(api.CVE_IGNORE_FILE, {"D": {"scope": "global"}})
        api._LOAD_CACHE.clear()

    def test_the_summary_and_the_host_carry_the_counts(self):
        report = self.call(api.handle_cve_findings)
        expected = {"fixable": 2, "newer_release": 1, "none": 1, "unchecked": 0}
        self.assertEqual(report["summary"]["fix"], expected)
        self.assertEqual(report["devices"][0]["fix"], expected)

    def test_the_host_view_keeps_the_status_and_where_the_fix_is(self):
        out = self.call(lambda: api.handle_cve_device("d1"))
        by_id = {f["vuln_id"]: f for f in out["findings"]}
        self.assertEqual(by_id["B"]["fix_status"], "newer_release")
        self.assertEqual(by_id["B"]["fixed_elsewhere"], {"Debian:13": "8.7.1-1"})
        self.assertEqual(by_id["B"]["fixed_version"], "")

    def test_needs_attention_and_the_patches_link_count_only_what_an_update_clears(self):
        # A and E are fixable, B and C are not (D is ignored): the same two the report counts
        self.assertEqual(api._cve_fixable_by_device(), {"d1": 2})

    def test_the_ticket_body_counts_and_describes_each_finding_by_its_status(self):
        api.save(api.CVE_FINDINGS_FILE, {"d1": {"findings": [
            finding("A", status="fixed"), finding("B", status="newer_release"), finding("C", status="none"),
            {"vuln_id": "E", "package": "curl", "severity": "high", "fixed_version": "2.0"}]}})  # scanned before 7.4.6
        api._LOAD_CACHE.clear()
        body = api._alert_ticket_detail({"event": "cve_found", "device_id": "d1", "payload": {}}, {"name": "web"})
        self.assertIn("2 fixable", body)  # A and the finding scanned before 7.4.6, not B or C
        lines = {l.split(" · ")[0].split("] ")[1]: l for l in body.splitlines() if l.startswith("  - [")}
        self.assertIn("fix in 1.0", lines["A"])
        self.assertIn("fixed only in a newer release", lines["B"])
        self.assertIn("no fix yet", lines["C"])


if __name__ == "__main__":
    unittest.main()
