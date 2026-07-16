#!/usr/bin/env python3
"""v6.2.2: live-state RAG corpus — dead-chunk fixes + posture enrichment.

Two chunks in ``rag_index.build_live_state_corpus`` were reading a sysinfo
field under the WRONG shape, so they never fired:

  * the disk/hardware chunk read ``sysinfo.disks`` — the heartbeat sanitizer
    stores per-mount capacity under ``sysinfo.mounts`` (see api.py safe_si).
  * the failing-custom-checks chunk did ``isinstance(ccr, list)`` — safe_si
    stores ``custom_check_results`` as a DICT ``{cid: {status, output}}``.

Plus an enrichment pass adds the host-posture facts the operator sees in the
drawer but the AI corpus had none of: storage/RAID pool health, failed
systemd units/timers, ECC memory errors, clock skew, gateway reachability,
OOM kills, mail-queue depth, Windows security posture, and the vendor
security-update count folded into the patches chunk.

Pure-module: rag_index imports standalone (no api.py exec, network-free).
"""
import sys
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import rag_index  # noqa: E402


def _corpus(dev):
    return rag_index.build_live_state_corpus([dev], now=1000)


def _by_id(docs, suffix):
    for d in docs:
        if d["id"].endswith(suffix):
            return d
    return None


class TestLiveStateDeadChunks(unittest.TestCase):
    def _rich_device(self):
        # Field names/shapes mirror api.py safe_si exactly.
        return {
            "id": "web01", "name": "web01", "os": "Debian 13",
            "upgradable": 5,
            "sysinfo": {
                "kernel": "6.1.0",
                # Bug 1: real per-mount shape (used_gb/total_gb/percent).
                "mounts": [
                    {"path": "/", "percent": 92.0, "used_gb": 46.0,
                     "total_gb": 50.0, "fstype": "ext4", "inode_percent": 40.0},
                    {"path": "/data", "percent": 12.0, "used_gb": 120.0,
                     "total_gb": 1000.0, "fstype": "xfs"},
                    {"path": "/mnt/nas", "network": True, "server": "nas01",
                     "stalled": True, "fstype": "nfs"},
                ],
                # Bug 2: DICT shape.
                "custom_check_results": {
                    "disk-free": {"status": "ok", "output": "fine"},
                    "cert-expiry": {"status": "critical",
                                    "output": "expires in 2 days"},
                    "backup-job": {"status": "warning", "output": "stale"},
                },
                # Enrichment posture facts.
                "storage_health": [
                    {"name": "tank", "kind": "zfs", "state": "DEGRADED",
                     "capacity": 71, "scrub": "in progress",
                     "last_snapshot": 0},
                    {"name": "md0", "kind": "mdadm", "state": "active",
                     "last_snapshot": 1699999999},
                ],
                "failed_units": ["nginx.service", "postgres.service"],
                "timers": [
                    {"unit": "backup.timer", "activates": "backup.service",
                     "failed": True},
                    {"unit": "logrotate.timer", "failed": False},
                ],
                "ecc": {"ce": 12, "ue": 1, "controllers": 2},
                "clock": {"synced": False, "offset_ms": 4200.0, "skewed": True},
                "gateway": {"ip": "192.168.1.1", "reachable": False},
                "last_oom_ts": 1699000000, "last_oom_proc": "chrome",
                "mailq": 37,
                "win_posture": {
                    "firewall": [{"name": "Domain", "enabled": False}],
                    "bitlocker": [{"mount": "C:", "status": "FullyDecrypted"}],
                    "defender_realtime": False,
                    "defender_sig_age_days": 9,
                    "wu_service": "stopped",
                },
                "packages": {"manager": "apt", "security_updates": 3},
            },
        }

    def test_bug1_disk_chunk_fires_from_mounts(self):
        docs = _corpus(self._rich_device())
        hw = _by_id(docs, "#hardware")
        self.assertIsNotNone(hw, "disk/hardware chunk did not fire from mounts")
        txt = hw["text"]
        self.assertIn("/data", txt)
        self.assertIn("92.0% used", txt)          # root mount percent
        self.assertIn("50.0 GB", txt)             # total_gb rendered
        self.assertIn("inodes 40.0%", txt)        # inode_percent rendered
        self.assertIn("STALLED", txt)             # stalled net share flagged
        self.assertIn("nas01", txt)

    def test_bug2_failing_checks_chunk_fires_from_dict(self):
        docs = _corpus(self._rich_device())
        chk = _by_id(docs, "#checks")
        self.assertIsNotNone(chk, "failing-checks chunk did not fire from dict")
        txt = chk["text"]
        self.assertIn("cert-expiry", txt)         # the critical check
        self.assertIn("backup-job", txt)          # the warning check
        self.assertNotIn("disk-free", txt)        # the ok check is excluded

    def test_storage_health_chunk(self):
        docs = _corpus(self._rich_device())
        st = _by_id(docs, "#storage")
        self.assertIsNotNone(st)
        txt = st["text"]
        self.assertIn("tank", txt)
        self.assertIn("DEGRADED", txt)
        self.assertIn("no snapshots", txt)        # last_snapshot == 0

    def test_posture_chunk_has_all_facts(self):
        docs = _corpus(self._rich_device())
        p = _by_id(docs, "#posture")
        self.assertIsNotNone(p)
        txt = p["text"]
        self.assertIn("nginx.service", txt)                 # failed unit
        self.assertIn("backup.timer", txt)                  # failed timer
        self.assertNotIn("logrotate.timer", txt)            # non-failed timer
        self.assertIn("12 correctable", txt)                # ecc ce
        self.assertIn("1 uncorrectable", txt)               # ecc ue
        self.assertIn("clock skew", txt.lower())            # clock
        self.assertIn("4200", txt)                          # offset_ms
        self.assertIn("UNREACHABLE", txt)                   # gateway
        self.assertIn("192.168.1.1", txt)
        self.assertIn("OOM", txt)                            # last_oom
        self.assertIn("chrome", txt)                         # oom proc
        self.assertIn("mail queue depth: 37", txt)           # mailq
        self.assertIn("BitLocker", txt)                      # win_posture
        self.assertIn("Defender", txt)

    def test_security_updates_folded_into_patches(self):
        docs = _corpus(self._rich_device())
        pat = _by_id(docs, "#patches")
        self.assertIsNotNone(pat)
        self.assertIn("vendor security updates pending: 3", pat["text"])
        self.assertIn("package manager: apt", pat["text"])

    def test_chunk_ids_stable_and_unique(self):
        docs = _corpus(self._rich_device())
        ids = [d["id"] for d in docs]
        self.assertEqual(len(ids), len(set(ids)), "duplicate chunk ids")
        for suffix in ("#summary", "#hardware", "#checks",
                       "#storage", "#posture", "#patches"):
            self.assertIn(f"live/web01{suffix}", ids)

    def test_gateway_latency_when_reachable(self):
        dev = {"id": "g1", "name": "g1", "sysinfo": {
            "gateway": {"ip": "10.0.0.1", "reachable": True,
                        "latency_ms": 3.4}}}
        p = _by_id(_corpus(dev), "#posture")
        self.assertIsNotNone(p)
        self.assertIn("latency 3.4 ms", p["text"])
        self.assertNotIn("UNREACHABLE", p["text"])


class TestLiveStateDefensiveShape(unittest.TestCase):
    def test_missing_posture_fields_do_not_crash(self):
        # A device with none of the enriched fields must build cleanly and
        # simply omit the posture/storage/checks chunks.
        dev = {"id": "bare", "name": "bare", "sysinfo": {"kernel": "6.1"}}
        docs = _corpus(dev)
        ids = {d["id"] for d in docs}
        self.assertIn("live/bare#summary", ids)
        self.assertNotIn("live/bare#posture", ids)
        self.assertNotIn("live/bare#storage", ids)
        self.assertNotIn("live/bare#checks", ids)
        self.assertNotIn("live/bare#hardware", ids)

    def test_odd_shapes_do_not_crash(self):
        # load() may hand us junk — non-dict items, wrong types, empty lists.
        dev = {"id": "odd", "name": "odd", "sysinfo": {
            "mounts": ["not-a-dict", {"path": "/", "percent": 5},
                       {"no": "path"}, 42],
            "custom_check_results": ["should-be-a-dict"],   # wrong shape
            "storage_health": [None, {"no": "name"},
                               {"name": "p", "state": "online"}],
            "failed_units": [None, "", "real.service"],
            "timers": ["x", {"unit": "t.timer", "failed": True}],
            "ecc": "not-a-dict",
            "clock": [1, 2],
            "gateway": "nope",
            "last_oom_ts": "bad",
            "mailq": "bad",
            "win_posture": [],
            "packages": ["not", "a", "dict"],
        }}
        # Must not raise.
        docs = _corpus(dev)
        ids = {d["id"] for d in docs}
        # hardware still fires from the one valid mount
        self.assertIn("live/odd#hardware", ids)
        # posture fires from failed_units + the one valid timer
        p = _by_id(docs, "#posture")
        self.assertIsNotNone(p)
        self.assertIn("real.service", p["text"])
        self.assertIn("t.timer", p["text"])
        # custom_check_results as a list of strings yields no failing checks
        self.assertNotIn("live/odd#checks", ids)

    def test_empty_device_list(self):
        self.assertEqual(rag_index.build_live_state_corpus([]), [])
        self.assertEqual(rag_index.build_live_state_corpus(None), [])


if __name__ == "__main__":
    unittest.main()
