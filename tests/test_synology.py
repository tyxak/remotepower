#!/usr/bin/env python3
"""v3.3.4: Synology DSM SNMP poller (poll_synology).

Mocks snmp_get / snmp_walk so the parsing + status-code mapping is tested
without a real NAS. OID layout follows Synology's published MIBs
(SYNOLOGY-SYSTEM-MIB / -DISK-MIB / -RAID-MIB under 1.3.6.1.4.1.6574).
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "server" / "cgi-bin"))
import snmp

SYS = {
    "1.3.6.1.4.1.6574.1.1.0": 1,                 # systemStatus -> normal
    "1.3.6.1.4.1.6574.1.2.0": 42,                # temperature
    "1.3.6.1.4.1.6574.1.3.0": 1,                 # power -> normal
    "1.3.6.1.4.1.6574.1.4.1.0": 1,               # system fan -> normal
    "1.3.6.1.4.1.6574.1.4.2.0": 2,               # cpu fan -> failed
    "1.3.6.1.4.1.6574.1.5.1.0": "DS920+",
    "1.3.6.1.4.1.6574.1.5.2.0": "2000ABC",
    "1.3.6.1.4.1.6574.1.5.3.0": "DSM 7.2-64570",
    "1.3.6.1.4.1.6574.1.5.4.0": 1,               # upgrade -> available
}

# disk table (one disk) + raid table (one degraded volume), keyed by full OID
WALKS = {
    "1.3.6.1.4.1.6574.2.1.1.2": {"1.3.6.1.4.1.6574.2.1.1.2.0": "Disk 1"},
    "1.3.6.1.4.1.6574.2.1.1.3": {"1.3.6.1.4.1.6574.2.1.1.3.0": "WD Red"},
    "1.3.6.1.4.1.6574.2.1.1.4": {"1.3.6.1.4.1.6574.2.1.1.4.0": "SATA"},
    "1.3.6.1.4.1.6574.2.1.1.5": {"1.3.6.1.4.1.6574.2.1.1.5.0": 1},     # normal
    "1.3.6.1.4.1.6574.2.1.1.6": {"1.3.6.1.4.1.6574.2.1.1.6.0": 38},    # temp
    "1.3.6.1.4.1.6574.3.1.1.2": {"1.3.6.1.4.1.6574.3.1.1.2.0": "Volume 1"},
    "1.3.6.1.4.1.6574.3.1.1.3": {"1.3.6.1.4.1.6574.3.1.1.3.0": 11},    # degraded
}


def _fake_get(host, community, oids, port=161, timeout=2.0):
    return {oid: SYS[oid] for oid in oids if oid in SYS}


def _fake_walk(host, community, oid, port=161, timeout=2.0, retries=0, max_results=64):
    return WALKS.get(oid, {})


class TestPollSynology(unittest.TestCase):
    def test_parses_system_disks_volumes(self):
        with patch.object(snmp, "snmp_get", side_effect=_fake_get), \
             patch.object(snmp, "snmp_walk", side_effect=_fake_walk):
            res = snmp.poll_synology("10.0.0.9", "public")
        sysd = res["system"]
        self.assertEqual(sysd["model"], "DS920+")
        self.assertEqual(sysd["dsm_version"], "DSM 7.2-64570")
        self.assertEqual(sysd["system"], "normal")
        self.assertEqual(sysd["power"], "normal")
        self.assertEqual(sysd["fan"], "normal")
        self.assertEqual(sysd["cpu_fan"], "failed")
        self.assertEqual(sysd["temperature_c"], 42)
        self.assertEqual(sysd["upgrade"], "available")

        self.assertEqual(len(res["disks"]), 1)
        d = res["disks"][0]
        self.assertEqual(d["id"], "Disk 1")
        self.assertEqual(d["status"], "normal")
        self.assertEqual(d["temperature_c"], 38)

        self.assertEqual(len(res["volumes"]), 1)
        self.assertEqual(res["volumes"][0]["name"], "Volume 1")
        self.assertEqual(res["volumes"][0]["status"], "degraded")

    def test_probe_gate_returns_empty_for_non_synology(self):
        # No Synology MIB answer -> {} and (crucially) no disk/RAID walks.
        walk_calls = []

        def spy_walk(*a, **k):
            walk_calls.append(a)
            return {}

        with patch.object(snmp, "snmp_get", side_effect=lambda *a, **k: {}), \
             patch.object(snmp, "snmp_walk", side_effect=spy_walk):
            res = snmp.poll_synology("10.0.0.9", "public")
        self.assertEqual(res, {})
        self.assertEqual(walk_calls, [])

    def test_get_error_returns_empty(self):
        with patch.object(snmp, "snmp_get", side_effect=snmp.SnmpError("timeout")):
            res = snmp.poll_synology("10.0.0.9", "public")
        self.assertEqual(res, {})


# ── v3.4.0: Synology DSM update status flows into the Patches report ────────
import importlib.util as _ilu  # noqa: E402
import io as _io               # noqa: E402
import json as _json          # noqa: E402
import os as _os              # noqa: E402
import tempfile as _tf        # noqa: E402

_os.environ["RP_DATA_DIR"] = _tf.mkdtemp()
_os.environ.setdefault("REQUEST_METHOD", "GET")
_os.environ.setdefault("PATH_INFO", "/")
_os.environ.setdefault("CONTENT_LENGTH", "0")
_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
_spec = _ilu.spec_from_file_location("api_syno", _CGI / "api.py")
_api = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_api)


class _Cap(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body


_api.respond = lambda s, d: (_ for _ in ()).throw(_Cap(s, d))


class TestSynologyPatchReport(unittest.TestCase):
    def setUp(self):
        for f in (_api.DEVICES_FILE, _api.TOKENS_FILE, _api.SNMP_DATA_FILE):
            _api.save(f, {})
        _api.require_auth = lambda **k: "admin"

    def _report(self):
        try:
            _api.handle_patch_report()
        except _Cap as c:
            return c.body
        return None

    def _row(self, body, dev_id):
        return next(d for d in body["devices"] if d["device_id"] == dev_id)

    def test_upgrade_available_shows_as_patch(self):
        _api.save(_api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                  "manual_status": True}})
        _api.save(_api.SNMP_DATA_FILE, {"nas1": {"synology": {"system": {
            "dsm_version": "DSM 7.2-64570", "upgrade": "available"}}}})
        row = self._row(self._report(), "nas1")
        self.assertEqual(row["pkg_manager"], "synology")
        self.assertEqual(row["upgradable"], 1)
        self.assertEqual(row["patch_status"], "patches_available")
        self.assertEqual(row["firmware"]["installed"], "DSM 7.2-64570")

    def test_upgrade_unavailable_is_fully_patched(self):
        _api.save(_api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                  "manual_status": True}})
        _api.save(_api.SNMP_DATA_FILE, {"nas1": {"synology": {"system": {
            "dsm_version": "DSM 7.2-64570", "upgrade": "unavailable"}}}})
        row = self._row(self._report(), "nas1")
        self.assertEqual(row["upgradable"], 0)
        self.assertEqual(row["patch_status"], "fully_patched")

    def test_unknown_upgrade_state_is_no_data(self):
        # connecting/disconnected/others -> can't tell -> no_data (not 0/1)
        _api.save(_api.DEVICES_FILE, {"nas1": {"name": "nas", "agentless": True,
                  "manual_status": True}})
        _api.save(_api.SNMP_DATA_FILE, {"nas1": {"synology": {"system": {
            "dsm_version": "DSM 7.2", "upgrade": "connecting"}}}})
        row = self._row(self._report(), "nas1")
        self.assertIsNone(row["upgradable"])
        self.assertEqual(row["patch_status"], "no_data")


class TestSnmpOsLabel(unittest.TestCase):
    """v3.4.0: derive an OS string for agentless devices from SNMP data so the
    Devices list OS column isn't blank."""

    def setUp(self):
        self.f = _api._snmp_os_label

    def test_synology_prefers_dsm_version(self):
        self.assertEqual(
            self.f({"synology": {"system": {"dsm_version": "DSM 7.3-86009"}},
                    "sysDescr": "Linux nas 4.4"}),
            "Synology DSM 7.3-86009")

    def test_routeros_version_not_board_number(self):
        self.assertEqual(self.f({"sysDescr": "RouterOS RB5009 7.14"}), "RouterOS 7.14")
        self.assertEqual(self.f({"sysDescr": "RouterOS RB5009UPr+S+"}), "RouterOS")

    def test_opnsense_and_pfsense(self):
        self.assertEqual(self.f({"sysDescr": "FreeBSD OPNsense01 14.3-RELEASE"}), "OPNsense")
        self.assertEqual(self.f({"sysDescr": "FreeBSD pfSense.local 14.0"}), "pfSense")

    def test_generic_unix(self):
        self.assertEqual(self.f({"sysDescr": "FreeBSD host 14.3-RELEASE"}), "FreeBSD 14.3-RELEASE")
        self.assertTrue(self.f({"sysDescr": "Linux pmg 6.1.0-21-amd64 #1"}).startswith("Linux 6.1.0"))

    def test_empty(self):
        self.assertEqual(self.f({}), "")
        self.assertEqual(self.f({"sysDescr": ""}), "")


if __name__ == "__main__":
    unittest.main()
