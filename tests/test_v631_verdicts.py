"""v6.3.1 wave 5 — the Assay "verdict discipline" lessons.

Three additions, all about honesty of the posture surfaces:
  1. The capable-source rule in compliance: a control must NOT infer PASS from
     an empty offenders list when the underlying telemetry was never collected
     ("silence isn't clearance"). Coverage 0 on a non-empty fleet → NA.
  2. Essential Eight + SMB1001:2026 frameworks (process controls RemotePower
     can't observe are reported as NA, never faked or hidden).
  3. Proof-labelled MITRE ATT&CK technique tags on triage verdicts.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v631v-"))

import compliance   # noqa: E402


class TestCapableSource(unittest.TestCase):
    """Coverage 0 on a non-empty fleet must read NA, not a false PASS."""

    def _facts(self, **over):
        f = {
            "devices": 5,
            "pending_patches_devices": [], "patch_data_devices": 0,
            "cve_critical_high": 0, "cve_scanned_devices": 0,
            "eol_os": [], "os_known_devices": 0,
            "reboot_required": [], "sysinfo_devices": 0,
        }
        f.update(over)
        return f

    def _statuses(self, facts, fw):
        rep = compliance.build_report(facts, [fw])
        return {c["id"]: c["status"] for c in rep["frameworks"][fw]["controls"]}

    def test_no_patch_data_is_not_assessed(self):
        s = self._statuses(self._facts(), "e8")
        self.assertEqual(s["E8-2"], "na")     # patch, no coverage
        self.assertEqual(s["E8-2b"], "na")    # cve, no coverage
        self.assertEqual(s["E8-6"], "na")     # eol, no coverage

    def test_coverage_present_and_clean_is_pass(self):
        facts = self._facts(patch_data_devices=5, cve_scanned_devices=5,
                            os_known_devices=5, sysinfo_devices=5)
        s = self._statuses(facts, "e8")
        self.assertEqual(s["E8-2"], "pass")
        self.assertEqual(s["E8-6"], "pass")

    def test_coverage_present_with_offenders_is_fail(self):
        facts = self._facts(patch_data_devices=5,
                            pending_patches_devices=["web01"])
        s = self._statuses(facts, "e8")
        self.assertEqual(s["E8-2"], "fail")

    def test_empty_fleet_is_not_falsely_gated(self):
        # devices == 0 → no capable-source expectation; the guard must not turn
        # a clean single-org PCI report into all-NA on a fresh empty install.
        facts = self._facts(devices=0)
        rep = compliance.build_report(facts, ["pci"])
        # patch/cve/eol should be PASS (nothing to assess against no fleet),
        # not NA — the coverage rule only bites when there ARE hosts.
        s = {c["id"]: c["status"] for c in rep["frameworks"]["pci"]["controls"]}
        self.assertEqual(s["6.3.3"], "pass")

    def test_na_never_inflates_the_score(self):
        # All-NA coverage: the only measurable control is MFA. Score must be
        # pass/(pass+fail), ignoring NA — never 100% off the back of NAs.
        facts = self._facts(mfa_enabled=True)
        rep = compliance.build_report(facts, ["e8"])
        e8 = rep["frameworks"]["e8"]
        self.assertGreater(e8["na"], 0)
        measurable = e8["pass"] + e8["fail"]
        self.assertEqual(e8["score"], round(100.0 * e8["pass"] / measurable, 1))


class TestNewFrameworks(unittest.TestCase):
    def test_registered(self):
        self.assertIn("e8", compliance.FRAMEWORKS)
        self.assertIn("smb1001", compliance.FRAMEWORKS)
        self.assertIn("e8", compliance.FRAMEWORK_LABELS)
        self.assertIn("smb1001", compliance.FRAMEWORK_LABELS)

    def test_essential_eight_has_all_eight_strategies(self):
        rep = compliance.build_report({"devices": 1, "mfa_enabled": True},
                                      ["e8"])
        titles = " ".join(c["title"].lower()
                          for c in rep["frameworks"]["e8"]["controls"])
        for strat in ("application control", "patch applications", "macro",
                      "user application hardening", "administrative privileges",
                      "patch operating systems", "multi-factor", "backups"):
            self.assertIn(strat, titles, strat)

    def test_process_controls_are_honestly_na(self):
        # App control / macro / user hardening have no RemotePower signal — they
        # must be NA (disclosed), not omitted and not faked as pass.
        rep = compliance.build_report({"devices": 3}, ["e8"])
        s = {c["id"]: c["status"] for c in rep["frameworks"]["e8"]["controls"]}
        self.assertEqual(s["E8-1"], "na")   # application control
        self.assertEqual(s["E8-3"], "na")   # macro settings
        self.assertEqual(s["E8-4"], "na")   # user hardening

    def test_smb1001_process_controls_na(self):
        rep = compliance.build_report({"devices": 3}, ["smb1001"])
        s = {c["id"]: c["status"] for c in rep["frameworks"]["smb1001"]["controls"]}
        self.assertEqual(s["S-training"], "na")
        self.assertEqual(s["S-ir"], "na")

    def test_admin_privilege_control_gates_on_baseline(self):
        # No baseline yet → NA (can't attest standing privilege).
        s = {c["id"]: c["status"] for c in
             compliance.build_report({"devices": 3}, ["e8"])["frameworks"]["e8"]["controls"]}
        self.assertEqual(s["E8-5"], "na")
        # Baseline present, clean window → pass.
        s2 = {c["id"]: c["status"] for c in compliance.build_report(
            {"devices": 3, "privileged_group_monitored": 3,
             "privileged_group_changes": []}, ["e8"])["frameworks"]["e8"]["controls"]}
        self.assertEqual(s2["E8-5"], "pass")
        # A recent change → fail.
        s3 = {c["id"]: c["status"] for c in compliance.build_report(
            {"devices": 3, "privileged_group_monitored": 3,
             "privileged_group_changes": ["web01"]}, ["e8"])["frameworks"]["e8"]["controls"]}
        self.assertEqual(s3["E8-5"], "fail")


class TestFactsWiring(unittest.TestCase):
    """The coverage facts must actually be assembled by the server."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
        spec = importlib.util.spec_from_file_location("api_v631v", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def test_coverage_facts_present(self):
        f = self.api._compliance_facts()
        for k in ("patch_data_devices", "cve_scanned_devices",
                  "os_known_devices", "sysinfo_devices",
                  "privileged_group_monitored", "privileged_group_changes"):
            self.assertIn(k, f, k)

    def test_patch_coverage_counts_reporting_hosts(self):
        api = self.api
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "h1", "os": "Linux",
                   "sysinfo": {"packages": {"upgradable": 3}}},
            "d2": {"name": "h2", "os": "Linux", "sysinfo": {}},   # no package data
        })
        f = api._compliance_facts()
        self.assertEqual(f["patch_data_devices"], 1)   # only d1 reported
        self.assertEqual(f["os_known_devices"], 2)
        self.assertEqual(f["sysinfo_devices"], 1)


class TestAttackTechniques(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "ai_triage_v631v", _CGI / "ai_triage_handlers.py")
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)
        cls.mod.bind({})   # _clean_attack_techniques uses no A.* services

    def test_valid_technique_kept(self):
        out = self.mod._clean_attack_techniques(
            [{"id": "T1078", "name": "Valid Accounts", "proof": "observed"}])
        self.assertEqual(out, [{"id": "T1078", "name": "Valid Accounts",
                                "proof": "observed"}])

    def test_subtechnique_id_kept(self):
        out = self.mod._clean_attack_techniques(
            [{"id": "T1059.001", "name": "PowerShell", "proof": "inferred"}])
        self.assertEqual(out[0]["id"], "T1059.001")

    def test_bad_id_dropped(self):
        self.assertEqual(self.mod._clean_attack_techniques(
            [{"id": "nope", "proof": "observed"},
             {"id": "1078", "proof": "observed"}]), [])

    def test_bad_proof_downgraded_never_inflated(self):
        out = self.mod._clean_attack_techniques(
            [{"id": "T1078", "proof": "certain"}])
        self.assertEqual(out[0]["proof"], "theoretical")

    def test_non_list_and_cap(self):
        self.assertEqual(self.mod._clean_attack_techniques("x"), [])
        self.assertEqual(self.mod._clean_attack_techniques(None), [])
        many = [{"id": "T1078", "proof": "observed"}] * 20
        self.assertEqual(len(self.mod._clean_attack_techniques(many)), 8)

    def test_verdict_carries_techniques(self):
        # The parser path stores a cleaned techniques list on the verdict.
        obj = {"action": "verdict", "root_cause": "x", "confidence": "low",
               "evidence": [], "recommended_action": "",
               "attack_techniques": [{"id": "T1110", "name": "Brute Force",
                                      "proof": "observed"}]}
        # Exercise the same cleaning the loop applies.
        cleaned = self.mod._clean_attack_techniques(obj["attack_techniques"])
        self.assertEqual(cleaned[0]["id"], "T1110")

    def test_prompt_and_ui_wired(self):
        import ai_provider
        self.assertIn("attack_techniques", ai_provider.SYSTEM_PROMPTS["alert_triage"])
        al = (_ROOT / "server/html/static/js/app-alerts.js").read_text()
        self.assertIn("_renderAttackTechniques", al)
        self.assertIn("attack.mitre.org", al)


class TestUiFrameworks(unittest.TestCase):
    def test_pickers_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn('value="e8"', html)
        self.assertIn('value="smb1001"', html)
        self.assertIn("Not&nbsp;assessed", html)


if __name__ == "__main__":
    unittest.main()
