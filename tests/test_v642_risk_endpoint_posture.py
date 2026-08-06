"""v6.4.2 (data-binding): Windows/macOS endpoint posture feeds the risk score.

_device_risk read only the Linux firewall, so a Windows host with BitLocker off,
firewall profiles off (and Defender off) scored IDENTICALLY to a hardened one,
and disk-encryption-off had no risk factor for any OS. Drives the real
_device_risk.
"""

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-riskpost-"))

_spec = importlib.util.spec_from_file_location("api_riskpost", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _risk(sysinfo):
    dev = {"name": "h", "monitored": True, "last_seen": time.time(),
           "sysinfo": sysinfo}
    r = api._device_risk("d", dev, {}, {}, {}, int(time.time()), 180)
    return r.get("score") if isinstance(r, dict) else r


class TestWindowsPostureRisk(unittest.TestCase):
    def test_bitlocker_and_firewall_off_scores_higher_than_hardened(self):
        hardened = _risk({"win_posture": {"firewall": [{"name": "Domain", "enabled": True}],
                                          "bitlocker": [{"status": "On"}]}})
        wide_open = _risk({"win_posture": {"firewall": [{"name": "Domain", "enabled": False}],
                                           "bitlocker": [{"status": "Off"}]}})
        self.assertGreater(wide_open, hardened)

    def test_a_fully_hardened_windows_host_scores_zero_for_posture(self):
        self.assertEqual(_risk({"win_posture": {"firewall": [{"name": "Domain", "enabled": True}],
                                                "bitlocker": [{"status": "Encrypted"}]}}), 0)


class TestMacPostureRisk(unittest.TestCase):
    def test_filevault_and_firewall_off_scores(self):
        self.assertGreater(
            _risk({"mac_posture": {"filevault": False, "firewall": False}}),
            _risk({"mac_posture": {"filevault": True, "firewall": True}}))


class TestEncryptionFactorExists(unittest.TestCase):
    def test_encryption_off_is_a_risk_weight(self):
        self.assertIn("encryption_off", api._RISK_WEIGHTS)

    def test_it_is_operator_tunable(self):
        """Derived into risk_weight_* by _risk_weights()."""
        self.assertIn("encryption_off", api._risk_weights())


if __name__ == "__main__":
    unittest.main()
