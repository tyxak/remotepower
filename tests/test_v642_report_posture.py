"""v6.4.2 (data-binding): the fleet report carries a host security-posture section.

Firewall, sshd hardening, encryption and auto-update reached the Checks page and
the risk score but never the report an auditor is handed. Each dimension carries
its own reporting denominator so an absent signal is never a pass.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-rptpos-"))

_spec = importlib.util.spec_from_file_location("api_rptpos", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestReportPostureSection(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._df = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        now = api.time.time()
        api.save(api.DEVICES_FILE, {
            "bad": {"name": "bad", "monitored": True, "last_seen": now,
                    "sysinfo": {"firewall": {"active": False},
                                "ssh_config": {"permit_root_login": "yes"},
                                "autoupdate": {"enabled": False},
                                "mac_posture": {"filevault": False}}},
            "good": {"name": "good", "monitored": True, "last_seen": now,
                     "sysinfo": {"firewall": {"active": True},
                                 "ssh_config": {"permit_root_login": "no",
                                                "password_authentication": "no",
                                                "permit_empty_passwords": "no"},
                                 "autoupdate": {"enabled": True},
                                 "mac_posture": {"filevault": True}}},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        api.DEVICES_FILE = self._df

    def _posture(self):
        rep = api.reports_handlers_mod._build_fleet_report()
        return rep["posture"]

    def test_the_section_exists_and_names_offenders(self):
        p = self._posture()
        self.assertEqual(p["firewall_off"], ["bad"])
        self.assertEqual(p["ssh_weak"], ["bad"])
        self.assertEqual(p["autoupdate_off"], ["bad"])
        self.assertEqual(p["encryption_off"], ["bad"])

    def test_each_dimension_has_a_reporting_denominator(self):
        p = self._posture()
        self.assertEqual(p["firewall_reporting"], 2)
        self.assertEqual(p["ssh_reporting"], 2)
        self.assertEqual(p["encryption_reporting"], 2)

    def test_counts_are_present(self):
        p = self._posture()
        self.assertEqual(p["firewall_off_count"], 1)

    def test_posture_is_a_report_section(self):
        self.assertIn("posture", api.reports_handlers_mod._REPORT_SECTIONS)
        self.assertIn("posture", api.reports_handlers_mod._ALL_REPORT_SECTIONS)


if __name__ == "__main__":
    unittest.main()
