#!/usr/bin/env python3
"""v4.10.0: three new RAG corpus sources — host firewall + fail2ban posture,
homelab integration health, and backup freshness."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("rag_index_v4100", _CGI / "rag_index.py")
ri = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ri)

_API_SRC = (_CGI / "api.py").read_text()


class TestFirewallCorpus(unittest.TestCase):
    DEVS = [
        {"id": "d1", "name": "web01", "sysinfo": {
            "firewall": {"active": True, "backends": [
                {"name": "nftables", "present": True, "active": True, "rules": 57, "policy": "drop"},
                {"name": "ufw", "present": True, "active": False, "rules": 0}]},
            "fail2ban": {"available": True, "jails": [
                {"name": "sshd", "banned_count": 2}, {"name": "postfix", "banned_count": 0}]}}},
        {"id": "d2", "name": "box2", "sysinfo": {
            "firewall": {"active": False, "backends": [
                {"name": "nftables", "present": True, "active": False, "rules": 0}]}}},
        {"id": "d3", "name": "nofw", "sysinfo": {}},  # nothing reported -> skipped
    ]

    def test_per_device_and_fleet(self):
        docs = ri.build_firewall_corpus(self.DEVS, now=1)
        by = {d["id"]: d for d in docs}
        self.assertIn("firewall/d1", by)
        self.assertEqual(by["firewall/d1"]["device"], "d1")
        self.assertIn("nftables: active, 57 rule(s)", by["firewall/d1"]["text"])
        self.assertIn("fail2ban: 2 jail(s), 2 banned", by["firewall/d1"]["text"])
        # d3 reported nothing -> no chunk
        self.assertNotIn("firewall/d3", by)
        # fleet rollup names the host with no active firewall
        self.assertIn("firewall/_fleet", by)
        self.assertIn("box2", by["firewall/_fleet"]["text"])

    def test_no_counters_leak(self):
        # the builder shows rule COUNTS, never raw packet/byte counters
        docs = ri.build_firewall_corpus(self.DEVS, now=1)
        for d in docs:
            self.assertNotIn("counter packets", d["text"])


class TestIntegrationsCorpus(unittest.TestCase):
    LATEST = {
        "i1": {"label": "Pi-hole", "type": "pihole", "status": "ok", "detail": "blocking on"},
        "i2": {"label": "TrueNAS", "type": "truenas", "status": "critical", "detail": "pool DEGRADED"},
    }

    def test_health_and_down_rollup(self):
        docs = ri.build_integrations_corpus(self.LATEST, now=1)
        by = {d["id"]: d for d in docs}
        self.assertIn("integrations/_all", by)
        self.assertIn("Pi-hole", by["integrations/_all"]["text"])
        self.assertIn("integrations/_down", by)
        self.assertIn("TrueNAS", by["integrations/_down"]["text"])

    def test_empty(self):
        self.assertEqual(ri.build_integrations_corpus({}, now=1), [])


class TestBackupsCorpus(unittest.TestCase):
    STATE = {"d1:/etc": {"ok": True, "age_h": 3}, "d1:/srv": {"ok": False, "age_h": 50},
             "d2:/data": {"ok": True, "age_h": 1}}

    def test_per_device_and_stale_rollup(self):
        docs = ri.build_backups_corpus(self.STATE, [{"path": "/srv", "label": "srv backup"}], now=1)
        by = {d["id"]: d for d in docs}
        self.assertIn("backups/d1", by)
        self.assertEqual(by["backups/d1"]["device"], "d1")
        self.assertIn("srv backup: STALE", by["backups/d1"]["text"])
        self.assertIn("backups/_fleet", by)
        self.assertIn("d1", by["backups/_fleet"]["text"])

    def test_resolver_unifies_identity(self):
        # a hostname key must resolve to the canonical id so it associates with
        # the host's other chunks
        docs = ri.build_backups_corpus({"web01:/etc": {"ok": True, "age_h": 1}}, [],
                                       resolve_device=lambda x: "d1" if x == "web01" else x, now=1)
        self.assertEqual(docs[0]["device"], "d1")


class TestApiWiring(unittest.TestCase):
    def test_sources_wired_in_orchestrator(self):
        for fn in ("build_firewall_corpus", "build_integrations_corpus", "build_backups_corpus"):
            self.assertIn(f"rag_index.{fn}", _API_SRC, fn)

    def test_sources_default_on(self):
        # the three new sources are enabled by default
        for key in ("'firewall':", "'integrations':", "'backups':"):
            self.assertIn(key, _API_SRC, key)

    def test_staleness_files_registered(self):
        self.assertIn("if sources.get('integrations'):", _API_SRC)
        self.assertIn("files.append(INTEG_STATE_FILE)", _API_SRC)


if __name__ == "__main__":
    unittest.main()
