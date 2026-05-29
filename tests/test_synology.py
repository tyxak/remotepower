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


if __name__ == "__main__":
    unittest.main()
