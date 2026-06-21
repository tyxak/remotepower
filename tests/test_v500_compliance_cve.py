"""v5.0.0: the Compliance "outstanding critical/high CVEs" count must EXCLUDE
ignored (accepted-risk) findings — so it agrees with the CVE Findings page and the
Needs-Attention banner. A bug counted ignored findings too, so Compliance showed a
larger number (e.g. 140) than the CVE page (e.g. 76)."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v500_compl", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestComplianceCveExcludesIgnored(unittest.TestCase):
    def _seed(self, findings_by_dev, ignore):
        api.save(api.CVE_FINDINGS_FILE, findings_by_dev)
        api.save(api.CVE_IGNORE_FILE, ignore)
        api._LOAD_CACHE.clear()

    def test_ignored_findings_not_counted(self):
        self._seed({
            "dev1": {"findings": [
                {"vuln_id": "CVE-A", "severity": "critical"},
                {"vuln_id": "CVE-B", "severity": "high"},
                {"vuln_id": "CVE-C", "severity": "high"},    # ignored globally
                {"vuln_id": "CVE-D", "severity": "medium"},  # not crit/high
            ]},
            "dev2": {"findings": [
                {"vuln_id": "CVE-E", "severity": "high"},
                {"vuln_id": "CVE-F", "severity": "critical"},  # ignored for dev2
            ]},
        }, {
            "CVE-C": {"scope": "global"},
            "CVE-F": {"scope": "dev2"},
        })
        facts = api._compliance_facts()
        # crit/high, minus the two ignored (CVE-C, CVE-F) → A, B, E = 3
        self.assertEqual(facts["cve_critical_high"], 3)

    def test_no_ignores_counts_all_crit_high(self):
        self._seed({
            "dev1": {"findings": [
                {"vuln_id": "CVE-A", "severity": "critical"},
                {"vuln_id": "CVE-B", "severity": "high"},
                {"vuln_id": "CVE-D", "severity": "low"},
            ]},
        }, {})
        facts = api._compliance_facts()
        self.assertEqual(facts["cve_critical_high"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
