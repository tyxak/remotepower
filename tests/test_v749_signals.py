#!/usr/bin/env python3
"""Signals the agents already send reach three more destinations (7.4.9, the signal-to-destination matrix).

A matrix of 98 signals over 11 destinations found the read side applying a rule in most places and missing it in two or three. The
Linux agent's disk-encryption state reached risk, compliance, the report, the Explorer and the digest and had no Advisory finding
(FileVault and BitLocker have one). The always-on AI digest carried about a dozen conditions and none of the distro's security
updates, uncorrectable memory errors or an unreachable gateway. The RAG hardware line read `util`, and the agent stores `util_pct`.

The fixtures have the shapes the agent sends (`disk_encryption` {encrypted, crypt_count, dm_count}, `ecc` {ce, ue, controllers},
`gateway` {reachable}, `gpus[].util_pct`), not the shapes a consumer assumed: a fixture that assumes the consumer's shape is how
the GPU key was wrong for a release.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-signals-"))
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import advisory  # noqa: E402
import ai_context  # noqa: E402

LINUX_OFF = {"encrypted": False, "crypt_devices": [], "crypt_count": 0, "dm_count": 6}
LINUX_ON = {"encrypted": True, "crypt_devices": [{"dm": "dm-0", "name": "root", "type": "LUKS2"}], "crypt_count": 1, "dm_count": 3}


def ids(devs, **kw):
    return {f["id"] for f in advisory.build(devs, **kw)["findings"]}


class TestTheAdvisoryKnowsLinuxDiskEncryption(unittest.TestCase):

    def test_an_unencrypted_linux_host_gets_a_finding_when_the_check_is_on(self):
        devs = {"d1": {"name": "srv", "sysinfo": {"disk_encryption": LINUX_OFF}}}
        adv = advisory.build(devs, disk_encryption_checks=True)
        g = [f for f in adv["findings"] if f["id"] == "data.luks"]
        self.assertEqual(len(g), 1)
        self.assertEqual((g[0]["layer"], g[0]["severity"]), ("data", "medium"))

    def test_it_is_opt_in_like_the_checks_row(self):
        devs = {"d1": {"name": "srv", "sysinfo": {"disk_encryption": LINUX_OFF}}}
        self.assertNotIn("data.luks", ids(devs))
        self.assertNotIn("data.luks", ids(devs, disk_encryption_checks=False))

    def test_an_encrypted_host_and_one_whose_device_mapper_cannot_be_seen_say_nothing(self):
        for de in (LINUX_ON, {}):
            with self.subTest(de=bool(de)):
                self.assertNotIn("data.luks", ids({"d1": {"name": "srv", "sysinfo": {"disk_encryption": de}}}, disk_encryption_checks=True))

    def test_windows_and_macos_keep_their_own_findings_and_get_no_luks_one(self):
        win = {"d1": {"name": "win", "sysinfo": {"win_posture": {"bitlocker": [{"mount": "C:", "status": "FullyDecrypted"}]}}}}
        mac = {"d1": {"name": "mac", "sysinfo": {"mac_posture": {"filevault": False}}}}
        self.assertEqual(ids(win, disk_encryption_checks=True) & {"data.bitlocker", "data.luks"}, {"data.bitlocker"})
        self.assertEqual(ids(mac, disk_encryption_checks=True) & {"data.filevault", "data.luks"}, {"data.filevault"})

    def test_the_handler_passes_the_switch(self):
        src = (_CGI / "advisory_handlers.py").read_text()
        self.assertIn("disk_encryption_checks=bool(A._config_ro().get('disk_encryption_checks', False))", src)


class TestTheDigestCarriesWhatTheAlertsDo(unittest.TestCase):

    def flags(self, si):
        return ai_context._device_flags({"sysinfo": si})

    def test_security_updates_are_a_flag(self):
        self.assertIn("2 security updates pending", self.flags({"packages": {"upgradable": 7, "security_updates": 2}}))
        self.assertIn("1 security update pending", self.flags({"packages": {"security_updates": 1}}))

    def test_uncorrectable_memory_errors_and_an_unreachable_gateway_are_flags(self):
        flags = self.flags({"ecc": {"ce": 900, "ue": 5, "controllers": []}, "gateway": {"reachable": False}})
        self.assertIn("ECC uncorrectable errors", flags)
        self.assertIn("gateway unreachable", flags)

    def test_a_healthy_host_adds_nothing(self):
        self.assertEqual(self.flags({"packages": {"upgradable": 3, "security_updates": 0}, "ecc": {"ce": 4, "ue": 0},
                                     "gateway": {"reachable": True}}), [])

    def test_unknown_and_malformed_values_say_nothing(self):
        for si in ({"gateway": {"reachable": None}}, {"packages": {"security_updates": True}}, {"packages": "x"},
                   {"ecc": {"ue": "5"}}, {"ecc": []}, {"gateway": 7}, {"packages": {"security_updates": -1}}):
            with self.subTest(si=si):
                self.assertEqual(self.flags(si), [])

    def test_the_cap_still_holds(self):
        many = {"reboot_required": True, "failed_units": ["a", "b"], "mount_issues": [{"x": 1}], "packages": {"security_updates": 3},
                "ecc": {"ue": 1}, "gateway": {"reachable": False}, "cpu_percent": 99}
        self.assertEqual(len(self.flags(many)), ai_context._MAX_FLAGS_PER_DEVICE)


class TestTheRagGpuLineReadsTheKeyTheAgentStores(unittest.TestCase):

    def corpus(self, gpus):
        import rag_index
        devices = {"d1": {"name": "box", "hostname": "box", "sysinfo": {}}}
        hw = {"d1": {"gpus": gpus, "ts": 1}}
        chunks = rag_index.build_hardware_corpus(hw, devices)
        return " ".join(str(c.get("text") or c.get("content") or c) for c in chunks)

    def test_utilisation_from_util_pct_is_in_the_line(self):
        text = self.corpus([{"vendor": "nvidia", "name": "RTX 3060", "util_pct": 99, "temp_c": 86.0}])
        self.assertIn("util 99%", text)
        self.assertIn("86.0°C", text)

    def test_the_old_key_still_reads(self):
        self.assertIn("util 30%", self.corpus([{"model": "RTX", "util": 30, "temp_c": 60}]))

    def test_neither_key_is_not_a_zero(self):
        self.assertNotIn("util", self.corpus([{"name": "RTX", "temp_c": 60}]))


if __name__ == "__main__":
    unittest.main()
