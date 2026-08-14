"""v6.4.2 (data-binding): PCI 1.2.1 assesses host firewall state instead of
returning a blanket "cannot assess".

The agent has reported per-host firewall active-ruleset state since v3.12.0, so
the old hardcoded NA was a stale premise — a false blind spot in the audit
artefact. Now it FAILs on a host with no active ruleset, PASSes when every
reporting host has one, and is NA only when genuinely no host reported.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-cfw-"))

_spec = importlib.util.spec_from_file_location("compliance_fw", _CGI / "compliance.py")
compliance = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compliance)


class TestTrafficRestrictControl(unittest.TestCase):
    def _status(self, facts):
        st, _msg = compliance._traffic_restrict_control(facts)
        return st

    def test_no_firewall_data_is_na(self):
        self.assertEqual(self._status({}), compliance.NA)
        self.assertEqual(self._status({"firewall_data_devices": 0}), compliance.NA)

    def test_a_host_with_no_active_ruleset_fails(self):
        st = self._status({"firewall_off": ["db1"], "firewall_data_devices": 3})
        self.assertEqual(st, compliance.FAIL)

    def test_all_reporting_hosts_active_passes(self):
        st = self._status({"firewall_off": [], "firewall_data_devices": 3})
        self.assertEqual(st, compliance.PASS)

    def test_the_fail_message_names_the_hosts(self):
        _st, msg = compliance._traffic_restrict_control(
            {"firewall_off": ["db1", "web2"], "firewall_data_devices": 5})
        self.assertIn("db1", msg)

    def test_no_longer_claims_it_cannot_assess(self):
        src = (_CGI / "compliance.py").read_text()
        from srcpin import py_function
        body = py_function(src, "_traffic_restrict_control")
        # the old blanket-NA string must be gone from the return path
        self.assertNotIn("does not assess", body)


class TestComplianceFactsCarryFirewall(unittest.TestCase):
    """The fact the control reads is actually assembled from stored sysinfo."""

    def test_facts_include_firewall_off_and_data_count(self):
        _s = importlib.util.spec_from_file_location("api_cfw", _CGI / "api.py")
        api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(api)
        devices = {
            "off": {"name": "off", "monitored": True,
                    "sysinfo": {"firewall": {"active": False}}},
            "on": {"name": "on", "monitored": True,
                   "sysinfo": {"firewall": {"active": True}}},
            "unknown": {"name": "unknown", "monitored": True,
                        "sysinfo": {"firewall": {"active": None}}},
        }
        facts = api._compliance_facts(devices)
        self.assertEqual(facts["firewall_off"], ["off"])
        self.assertEqual(facts["firewall_data_devices"], 2)  # off + on, not unknown


if __name__ == "__main__":
    unittest.main()
