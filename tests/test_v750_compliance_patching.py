#!/usr/bin/env python3
"""PCI 6.3.3, SOC 2 CC6.7, E8-2 and CC7.4 no longer pass a host that is visibly behind.

The patch control compared the TOTAL pending count with one threshold (50 by default) and the reboot control read
`reboot_required` alone. A host with 30 security updates waiting, a newer kernel installed and not running, and no
automatic updates passed all four: nothing in the report mentioned the security flag the distribution sets, the
kernel flag (the only reboot signal on a distribution without /run/reboot-required) or the operator's own patch SLA.

The payloads are the shapes the heartbeat stores. A host that patches itself is not an offender for a few waiting
updates, a Windows host (no security count) is not read as zero, and a fleet that never scanned is Not assessed.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-patch-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import compliance  # noqa: E402


def host(name, sec=None, upg=None, autoupdate=None, **si):
    packages = {"manager": "apt"}
    if sec is not None:
        packages["security_updates"] = sec
    if upg is not None:
        packages["upgradable"] = upg
    sysinfo = {"packages": packages}
    if autoupdate is not None:
        sysinfo["autoupdate"] = {"enabled": autoupdate, "mechanism": "unattended-upgrades"}
    sysinfo.update(si)
    return {"name": name, "tenant": "default", "token_hash": "x", "last_seen": int(time.time()),
            "monitored": True, "os": "Debian", "sysinfo": sysinfo}


class _F(_Base):
    STORES = _Base.STORES + ("HARDWARE_FILE", "PATCH_AGE_FILE")

    def setUp(self):
        super().setUp()
        api.save(api.HARDWARE_FILE, {})
        api.save(api.PATCH_AGE_FILE, {})
        api._LOAD_CACHE.clear()

    def facts(self, devs, **cfg):
        c = api.load(api.CONFIG_FILE) or {}
        c.update(cfg)
        api.save(api.CONFIG_FILE, c)
        api._LOAD_CACHE.clear()
        return api._compliance_facts(devs)

    def patch(self, devs, **cfg):
        return compliance._patch_control(self.facts(devs, **cfg))


class TestSecurityUpdates(_F):

    def test_thirty_waiting_and_no_automatic_updates_fails_and_names_the_host(self):
        st, ev = self.patch({"a": host("web01", sec=30, upg=30, autoupdate=False)})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn("web01 (30 security updates)", ev)

    def test_a_host_that_patches_itself_is_not_an_offender(self):
        st, ev = self.patch({"a": host("web01", sec=30, upg=30, autoupdate=True)})
        self.assertEqual(st, compliance.PASS, ev)
        self.assertIn("within a normal cycle", ev)

    def test_a_host_that_has_not_said_is_treated_as_not_patching_itself(self):
        st, _ev = self.patch({"a": host("web01", sec=30, upg=30)})
        self.assertEqual(st, compliance.FAIL)

    def test_a_few_waiting_is_a_normal_cycle(self):
        st, ev = self.patch({"a": host("web01", sec=3, upg=3, autoupdate=False)})
        self.assertEqual(st, compliance.PASS, ev)
        self.assertIn("1 host has security updates waiting", ev)

    def test_the_line_is_ten(self):
        self.assertEqual(compliance.SECURITY_PENDING_FAIL, 10, "docs/compliance.md says ten")
        n = compliance.SECURITY_PENDING_FAIL
        self.assertEqual(self.patch({"a": host("w", sec=n - 1, upg=n, autoupdate=False)})[0], compliance.PASS)
        self.assertEqual(self.patch({"a": host("w", sec=n, upg=n, autoupdate=False)})[0], compliance.FAIL)

    def test_a_host_with_no_security_count_is_not_read_as_zero_and_not_as_many(self):
        f = self.facts({"a": host("win01", sec=None, upg=2)})
        self.assertEqual(f["security_data_devices"], 0)
        self.assertEqual(f["security_pending_bad"], [])
        self.assertEqual(compliance._patch_control(f)[0], compliance.PASS)

    def test_a_count_of_the_wrong_kind_is_not_a_count(self):
        for bad in (True, "30", 3.5, None, [30]):
            f = self.facts({"a": host("w", sec=bad, upg=1, autoupdate=False)})
            self.assertEqual(f["security_data_devices"], 0, bad)

    def test_the_total_threshold_still_applies(self):
        st, ev = self.patch({"a": host("web01", sec=0, upg=80, autoupdate=True)})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn("over the patch threshold", ev)

    def test_both_findings_are_reported_together(self):
        st, ev = self.patch({"a": host("web01", sec=30, upg=80, autoupdate=False)})
        self.assertIn("over the patch threshold", ev)
        self.assertIn("security updates waiting", ev)

    def test_nothing_reported_is_not_assessed_never_a_pass(self):
        f = self.facts({"a": {"name": "x", "monitored": True, "sysinfo": {"cpu_percent": 1}}})
        self.assertEqual(compliance._patch_control(f)[0], compliance.NOT_ASSESSED)

    def test_an_unmonitored_host_is_left_out(self):
        h = host("lab01", sec=50, upg=50, autoupdate=False)
        h["monitored"] = False
        self.assertEqual(self.facts({"a": h})["security_pending_bad"], [])

    def test_every_framework_that_maps_the_control_sees_it(self):
        rep = compliance.build_report(self.facts({"a": host("web01", sec=30, upg=30, autoupdate=False)}))
        by = {(fw, c["id"]): c["status"] for fw, d in rep["frameworks"].items() for c in d["controls"]}
        for key in (("pci", "6.3.3"), ("soc2", "CC6.7"), ("e8", "E8-2"), ("smb1001", "S-patch")):
            self.assertEqual(by[key], compliance.FAIL, key)


class TestTheKernelAndTheReboot(_F):

    def _kernel(self, did, flag):
        api.save(api.HARDWARE_FILE, {did: {"kernel": {"running": "6.1.0", "latest_installed": "6.1.9",
                                                      "reboot_for_kernel": flag}}})
        api._LOAD_CACHE.clear()

    def test_a_newer_kernel_installed_and_not_running_is_a_pending_reboot(self):
        self._kernel("a", True)
        f = self.facts({"a": host("arch01", sec=0, upg=0)})
        self.assertEqual(f["reboot_required"], ["arch01 (a newer kernel is installed and not running)"])
        st, ev = compliance._reboot_control(f)
        self.assertEqual(st, compliance.FAIL)
        self.assertIn("arch01", ev)

    def test_the_kernel_flag_off_is_nothing(self):
        self._kernel("a", False)
        self.assertEqual(self.facts({"a": host("arch01", sec=0, upg=0)})["reboot_required"], [])

    def test_a_host_already_flagged_by_the_file_is_listed_once(self):
        self._kernel("a", True)
        f = self.facts({"a": host("deb01", sec=0, upg=0, reboot_required=True)})
        self.assertEqual(f["reboot_required"], ["deb01"])

    def test_the_kernel_of_a_host_outside_the_view_is_not_read(self):
        self._kernel("other", True)
        self.assertEqual(self.facts({"a": host("arch01", sec=0, upg=0)})["reboot_required"], [])

    def test_a_malformed_kernel_record_is_no_flag(self):
        for junk in ("x", 5, [], {"kernel": "x"}, {"kernel": []}):
            api.save(api.HARDWARE_FILE, {"a": junk})
            api._LOAD_CACHE.clear()
            self.assertEqual(self.facts({"a": host("arch01", sec=0, upg=0)})["reboot_required"], [], junk)


class TestThePatchSla(_F):

    RULE = {"match_type": "all", "pattern": "", "sec_days": 7, "all_days": 0}

    def test_a_host_past_the_operators_sla_fails(self):
        api.save(api.PATCH_AGE_FILE, {"a": {"sec_first": int(time.time()) - 20 * 86400}})
        st, ev = self.patch({"a": host("web01", sec=3, upg=3, autoupdate=False)}, patch_sla=[self.RULE])
        self.assertEqual(st, compliance.FAIL)
        self.assertIn("past the patch SLA", ev)
        self.assertIn("web01", ev)

    def test_a_host_inside_the_sla_passes(self):
        api.save(api.PATCH_AGE_FILE, {"a": {"sec_first": int(time.time()) - 2 * 86400}})
        st, _ev = self.patch({"a": host("web01", sec=3, upg=3, autoupdate=False)}, patch_sla=[self.RULE])
        self.assertEqual(st, compliance.PASS)

    def test_without_rules_the_sla_is_not_consulted_and_nothing_is_written(self):
        before = api.load(api.PATCH_AGE_FILE)
        f = self.facts({"a": host("web01", sec=3, upg=3, autoupdate=False)})
        self.assertEqual(f["patch_sla_breach"], [])
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.PATCH_AGE_FILE), before)

    def test_building_the_facts_with_rules_does_not_write_the_aging_store(self):
        api.save(api.PATCH_AGE_FILE, {})
        self.facts({"a": host("web01", sec=3, upg=3, autoupdate=False)}, patch_sla=[self.RULE])
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.PATCH_AGE_FILE), {}, "the report only reads the aging store")


if __name__ == "__main__":
    unittest.main()
