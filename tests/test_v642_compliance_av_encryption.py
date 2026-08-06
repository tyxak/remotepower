"""v6.4.2 (data-binding): AV/malware posture and encryption-at-rest are
compliance controls.

HIPAA's "Protection from malicious software" was evidenced by PATCH counts (a
mismapping — the one control literally named for malware), and encryption-at-rest
(BitLocker/FileVault), though checked and risk-scored, mapped to no control at
all. Both now assess, and are NA (score-neutral — the score is pass/(pass+fail))
when no host reports the data.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-avenc-"))

_spec = importlib.util.spec_from_file_location("api_avenc", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
compliance = api.compliance


class TestAvControl(unittest.TestCase):
    def _s(self, facts):
        return compliance._av_control(facts)[0]

    def test_no_av_data_is_na(self):
        self.assertEqual(self._s({}), compliance.NOT_ASSESSED)

    def test_infection_or_realtime_off_fails(self):
        self.assertEqual(self._s({"av_bad": ["h1"], "av_data_devices": 3}),
                         compliance.FAIL)

    def test_clean_reporting_fleet_passes(self):
        self.assertEqual(self._s({"av_bad": [], "av_data_devices": 3}),
                         compliance.PASS)


class TestEncryptionControl(unittest.TestCase):
    def _s(self, facts):
        return compliance._encryption_at_rest_control(facts)[0]

    def test_no_encryption_data_is_na(self):
        self.assertEqual(self._s({}), compliance.NOT_ASSESSED)

    def test_encryption_off_fails(self):
        self.assertEqual(self._s({"encryption_off": ["h1"],
                                  "encryption_data_devices": 2}), compliance.FAIL)

    def test_all_encrypted_passes(self):
        self.assertEqual(self._s({"encryption_off": [],
                                  "encryption_data_devices": 2}), compliance.PASS)


class TestFactsAndWiring(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._df, self._af = api.DEVICES_FILE, api.AV_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        api.AV_FILE = self.d / "av.json"
        api.save(api.DEVICES_FILE, {
            "w1": {"name": "w1", "monitored": True,
                   "sysinfo": {"win_posture": {"bitlocker": [{"status": "Off"}]}}},
            "m1": {"name": "m1", "monitored": True,
                   "sysinfo": {"mac_posture": {"filevault": True}}},
        })
        api.save(api.AV_FILE, {"w1": {"defender": {"infected": 1, "realtime": True}}})
        for f in (api.DEVICES_FILE, api.AV_FILE):
            api._invalidate_load_cache(f)

    def tearDown(self):
        api.DEVICES_FILE, api.AV_FILE = self._df, self._af

    def test_facts_compute_av_and_encryption(self):
        facts = api._compliance_facts(api.load(api.DEVICES_FILE))
        self.assertEqual(facts["av_bad"], ["w1"])
        self.assertEqual(facts["av_data_devices"], 1)
        self.assertEqual(facts["encryption_off"], ["w1"])
        self.assertEqual(facts["encryption_data_devices"], 2)

    def test_the_new_controls_appear_in_the_report(self):
        rep = compliance.build_report(api._compliance_facts(api.load(api.DEVICES_FILE)))
        rows = {c["id"]: c["status"] for fw in rep["frameworks"].values()
                for c in fw["controls"]}
        self.assertEqual(rows.get("3.5.1"), "fail")           # PCI encryption
        self.assertEqual(rows.get("5.2.1"), "fail")           # PCI anti-malware
        self.assertEqual(rows.get("164.312(a)(2)(iv)"), "fail")  # HIPAA encryption

    def test_hipaa_malware_is_now_av_evidenced_not_patch(self):
        """The remap: with an infection present it FAILs on AV, and its
        remediation no longer says 'apply patches'."""
        rep = compliance.build_report(api._compliance_facts(api.load(api.DEVICES_FILE)))
        ctl = next(c for fw in rep["frameworks"].values() for c in fw["controls"]
                   if c["id"] == "164.308(a)(5)(ii)(B)")
        self.assertEqual(ctl["status"], "fail")
        self.assertIn("anti-malware", ctl.get("remediation", "").lower())


if __name__ == "__main__":
    unittest.main()
