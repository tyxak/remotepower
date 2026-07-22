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


class TestDnsEmailCorpus(unittest.TestCase):
    DMARC = {"t1": {"domain": "tvipper.com", "status": "pass",
                    "dmarc": {"policy": "reject"}, "spf": {"record": "v=spf1 -all"},
                    "dkim": {"selector": "default"}, "reasons": []}}
    REP = {"r1": {"ip": "1.2.3.4", "label": "mx", "listed_count": 1,
                  "listed_on": [{"name": "zen.spamhaus.org"}], "errors": {}}}
    RES = [{"resolver": "1.1.1.1", "healthy": True, "latency_ms": 12}]

    def test_domains_reputation_resolvers(self):
        docs = ri.build_dns_email_corpus(self.DMARC, self.REP, self.RES, now=1)
        by = {d["id"]: d for d in docs}
        self.assertIn("email/tvipper.com", by)
        self.assertIn("p=reject", by["email/tvipper.com"]["text"])
        self.assertIn("reputation/1.2.3.4", by)
        self.assertIn("LISTED", by["reputation/1.2.3.4"]["text"])
        self.assertIn("reputation/_fleet", by)        # blacklist rollup
        self.assertIn("dns/resolvers", by)

    def test_empty_and_malformed_safe(self):
        self.assertEqual(ri.build_dns_email_corpus({}, [], None), [])
        # non-dict/non-list stores must not raise
        self.assertEqual(ri.build_dns_email_corpus(42, "x", 3.14), [])


class TestPostureCorpus(unittest.TestCase):
    # v5.0.0: fleet security-control posture corpus.
    DEVICES = {
        "d1": {"id": "d1", "name": "web01", "mtls_fingerprint": "ab:cd",
               "sysinfo": {"audit_mode": True}},
        "d2": {"id": "d2", "name": "db01"},
    }

    def test_mtls_backup_audit_control(self):
        docs = ri.build_posture_corpus(
            config={"require_agent_mtls": True, "breakglass_required": True,
                    "maintenance_mode": {"enabled": True}},
            devices=self.DEVICES,
            backup={"encryption_armed": True, "encryption_available": True}, now=1)
        by = {d["id"]: d for d in docs}
        self.assertIn("posture/mtls", by)
        self.assertIn("ENFORCED", by["posture/mtls"]["text"])
        self.assertIn("1 of 2", by["posture/mtls"]["text"])      # one pinned host
        self.assertIn("posture/backup_encryption", by)
        self.assertIn("ARMED", by["posture/backup_encryption"]["text"])
        self.assertIn("posture/audit_mode", by)                  # web01 in audit mode
        self.assertIn("web01", by["posture/audit_mode"]["text"])
        self.assertIn("posture/control_plane", by)
        self.assertIn("ON", by["posture/control_plane"]["text"])  # maintenance ON

    def test_no_secrets_leak(self):
        # passphrases / fingerprintable secrets must never appear in the corpus
        docs = ri.build_posture_corpus(
            config={"require_agent_mtls": False}, devices=self.DEVICES,
            backup={"encryption_armed": False}, now=1)
        blob = " ".join(d["text"] for d in docs)
        self.assertNotIn("RP_BACKUP_PASSPHRASE", blob)
        self.assertIn("NOT enforced", blob)

    def test_empty_and_malformed_safe(self):
        # non-dict/non-list stores must not raise; off-state still yields summaries
        self.assertTrue(ri.build_posture_corpus(config=42, devices="x", backup=3.14))
        self.assertTrue(ri.build_posture_corpus())


class TestVpnCorpus(unittest.TestCase):
    # v5.2.0: WG Access posture corpus.
    STORE = {'tunnels': [
        {'id': 'wgt_a', 'name': 'HQ', 'listen_port': 51820, 'enabled': True,
         'allow_internet': False, 'reach_scope_type': 'site',
         'reach_scope_value': 'oslo', 'dns': '10.0.0.1', 'expires_at': None,
         'clients': [{'name': 'laptop', 'address': '10.97.0.2/32',
                      'last_handshake': 10 ** 12, 'endpoint': '1.2.3.4:5',
                      'enabled': True, 'expires_at': None}]},
        {'id': 'wgt_b', 'name': 'OldNet', 'enabled': False,
         'allow_internet': True, 'clients': []},
    ]}

    def test_tunnels_fleet_and_state(self):
        docs = ri.build_vpn_corpus(self.STORE, now=10 ** 12 + 5)
        by = {d["id"]: d for d in docs}
        self.assertIn("vpn/wgt_a", by)
        self.assertIn("vpn/_fleet", by)
        self.assertIn("connected", by["vpn/wgt_a"]["text"])
        self.assertIn("site oslo", by["vpn/wgt_a"]["text"])
        self.assertIn("DISABLED", by["vpn/_fleet"]["text"])
        self.assertIn("full tunnel", by["vpn/_fleet"]["text"])

    def test_no_secrets_leak(self):
        # public addresses/state only — never a private key
        blob = str(ri.build_vpn_corpus(self.STORE, now=1)).lower()
        self.assertNotIn("privkey", blob)
        self.assertNotIn("private", blob)

    def test_empty_and_malformed_safe(self):
        self.assertEqual(ri.build_vpn_corpus({}, now=1), [])
        self.assertEqual(ri.build_vpn_corpus(None, now=1), [])
        self.assertEqual(ri.build_vpn_corpus({"tunnels": "x"}, now=1), [])


class TestApiWiring(unittest.TestCase):
    def test_sources_wired_in_orchestrator(self):
        for fn in ("build_firewall_corpus", "build_integrations_corpus",
                   "build_backups_corpus", "build_dns_email_corpus",
                   "build_posture_corpus", "build_vpn_corpus",
                   # v6.3.1 advisor-grounding sources
                   "build_incident_memory_corpus", "build_image_cves_corpus",
                   "build_scap_corpus", "build_security_findings_corpus", "build_hardware_corpus", "build_billing_corpus", "build_remediations_corpus", "build_config_revisions_corpus",
                   "build_automation_rules_corpus"):
            self.assertIn(f"rag_index.{fn}", _API_SRC, fn)

    def test_sources_default_on(self):
        # the new sources are enabled by default
        for key in ("'firewall':", "'integrations':", "'backups':", "'dns_email':",
                    "'posture':", "'vpn':",
                    "'incident_memory':", "'image_cves':", "'scap':",
                    "'security_findings':", "'automation_rules':"):
            self.assertIn(key, _API_SRC, key)

    def test_staleness_files_registered(self):
        self.assertIn("if sources.get('integrations'):", _API_SRC)
        self.assertIn("files.append(INTEG_STATE_FILE)", _API_SRC)
        self.assertIn("if sources.get('dns_email'):", _API_SRC)
        self.assertIn("if sources.get('posture'):", _API_SRC)
        self.assertIn("if sources.get('vpn'):", _API_SRC)
        self.assertIn("files.append(VPN_FILE)", _API_SRC)
        for key in ("incident_memory", "image_cves", "scap",
                    "security_findings", "automation_rules"):
            self.assertIn(f"if sources.get('{key}'):", _API_SRC, key)
        self.assertIn("files.append(INCIDENT_MEMORY_FILE)", _API_SRC)
        self.assertIn("files += [SECRETS_FILE, PII_FILE, AV_FILE]", _API_SRC)

    def test_dns_email_save_whitelisted(self):
        # the save-handler whitelist must include every default source, or its
        # UI toggle silently won't persist (the v4.10.0 firewall/integrations/
        # backups toggle-persistence bug). posture added in v5.0.0; vpn in v5.2.0.
        for key in ("'firewall'", "'integrations'", "'backups'", "'dns_email'",
                    "'posture'", "'vpn'",
                    "'incident_memory'", "'image_cves'", "'scap'",
                    "'security_findings'", "'automation_rules'"):
            self.assertIn(key, _API_SRC, key)


if __name__ == "__main__":
    unittest.main()
