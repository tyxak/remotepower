#!/usr/bin/env python3
"""
Tests for v3.11.0 — fleet posture batch (strict pins).

Covers the seven v3.11.0 features and the version bump:
  1. Version bump consistency (server, agent, sw.js, index.html, README,
     CHANGELOG top entry, docs/v3.11.0.md, agent extensionless sync).
  2. Event wiring for the eight new webhook events across every registry
     (WEBHOOK_EVENTS, _ALERT_RULES, CHANNEL_KINDS/EVENT_KIND_MAP,
     _webhook_title, _webhook_message).
  3. Software policy: version compare + banned / required / min_version
     evaluation and edge-triggered violation firing.
  4. Storage posture: scrub-age parse + degraded/recovered transitions.
  5. Exposure: socket-scope classification (agent helper).
"""

import os
import tempfile
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v3110", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

VERSION = "3.11.0"

_NEW_FIRING = [
    "port_exposed_world", "software_policy_violation", "storage_degraded",
    "scrub_overdue", "login_new_source", "firewall_changed", "timer_failed",
]
_NEW_RECOVER = ["storage_recovered"]


class TestVersionBumps(unittest.TestCase):
    # v3.12.0: loosened from the exact 3.11.0 pins (the live strict pin moved to
    # tests/test_v3120.py) so a later bump doesn't fail this file.
    def test_server_version(self):
        import re as _re
        self.assertRegex(api.SERVER_VERSION, r'^3\.\d+\.\d+$')

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertRegex(txt, r"\nVERSION\s*=\s*'3\.\d+\.\d+'")

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertRegex(txt, r"remotepower-shell-v3\.\d+\.\d+")

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertRegex(txt, r"\?v=3\.\d+\.\d+")

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertRegex(txt, r"version-3\.\d+\.\d+-blue")

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(txt[:2000], r"v3\.\d+\.\d+")

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{VERSION}.md").exists())


class TestEventWiring(unittest.TestCase):
    def test_events_registered(self):
        for ev in _NEW_FIRING + _NEW_RECOVER:
            self.assertIn(ev, api.WEBHOOK_EVENT_NAMES, f"{ev} missing from WEBHOOK_EVENTS")

    def test_alert_rules_present(self):
        for ev in _NEW_FIRING:
            self.assertIn(ev, api._ALERT_RULES, f"{ev} missing from _ALERT_RULES (silent inbox drop)")

    def test_kind_map_resolves(self):
        for ev in _NEW_FIRING + _NEW_RECOVER:
            self.assertIn(ev, api.EVENT_KIND_MAP, f"{ev} not mapped to a channel kind")

    def test_recover_wired(self):
        self.assertEqual(api._ALERT_RECOVER.get("storage_recovered"), "storage_degraded")
        self.assertIn("scrub_overdue", api._ALERT_RECOVER_EXTRA.get("storage_recovered", ()))

    def test_titles_specific(self):
        for ev in _NEW_FIRING + _NEW_RECOVER:
            title = api._webhook_title(ev)
            self.assertFalse(title.startswith("RemotePower: "), f"{ev} has no friendly title")


class TestSoftwarePolicy(unittest.TestCase):
    def test_ver_key_compare(self):
        self.assertLess(api._ver_key("8.9"), api._ver_key("9.0"))
        self.assertLess(api._ver_key("1:9.6p1-3"), api._ver_key("1:9.7p1-1"))
        self.assertGreaterEqual(api._ver_key("2.0"), api._ver_key("2.0"))

    def _set_policy(self, rules):
        api.save(api.SOFTWARE_POLICY_FILE, {"rules": rules})

    def _clear(self):
        for f in (api.SOFTWARE_POLICY_FILE, api.SOFTWARE_VIOLATIONS_FILE):
            if f.exists():
                f.unlink()

    def setUp(self):
        self._clear()
        self._fired = []
        self._orig = api.fire_webhook
        api.fire_webhook = lambda ev, p: self._fired.append((ev, p))

    def tearDown(self):
        api.fire_webhook = self._orig
        self._clear()

    def test_banned(self):
        self._set_policy([{"id": "no-telnet", "type": "banned", "package": "telnetd"}])
        v = api._eval_software_policy("d1", "host1",
                                      [{"name": "telnetd", "version": "1.0"}], [])
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["type"], "banned")
        self.assertTrue(any(e[0] == "software_policy_violation" for e in self._fired))

    def test_required_missing(self):
        self._set_policy([{"id": "need-f2b", "type": "required", "package": "fail2ban"}])
        v = api._eval_software_policy("d1", "host1",
                                      [{"name": "nginx", "version": "1.0"}], [])
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["type"], "required")

    def test_min_version(self):
        self._set_policy([{"type": "min_version", "package": "openssh-server", "version": "9.0"}])
        v = api._eval_software_policy("d1", "host1",
                                      [{"name": "openssh-server", "version": "8.9p1"}], [])
        self.assertEqual(len(v), 1)
        # a compliant version yields no violation
        v2 = api._eval_software_policy("d2", "host2",
                                       [{"name": "openssh-server", "version": "9.6p1"}], [])
        self.assertEqual(len(v2), 0)

    def test_tag_scope(self):
        self._set_policy([{"type": "banned", "package": "telnetd", "tags": ["servers"]}])
        # device without the tag is not evaluated against this rule
        v = api._eval_software_policy("d1", "ws", [{"name": "telnetd"}], ["workstations"])
        self.assertEqual(len(v), 0)
        v2 = api._eval_software_policy("d2", "srv", [{"name": "telnetd"}], ["servers"])
        self.assertEqual(len(v2), 1)

    def test_edge_triggered(self):
        self._set_policy([{"id": "no-telnet", "type": "banned", "package": "telnetd"}])
        api._eval_software_policy("d1", "h", [{"name": "telnetd"}], [])
        n_after_first = len([e for e in self._fired if e[0] == "software_policy_violation"])
        api._eval_software_policy("d1", "h", [{"name": "telnetd"}], [])
        n_after_second = len([e for e in self._fired if e[0] == "software_policy_violation"])
        self.assertEqual(n_after_first, n_after_second, "steady-state breach re-alerted")


class TestStoragePosture(unittest.TestCase):
    def test_scrub_age_parse(self):
        self.assertIsNone(api._scrub_age_days("scrub in progress"))
        # a clearly old date should parse to a positive age
        age = api._scrub_age_days("scrub repaired 0B with 0 errors on Mon Jan  2 03:10:00 2023")
        self.assertIsNotNone(age)
        self.assertGreater(age, 365)

    def setUp(self):
        # Backend-agnostic reset: clear the per-device posture state (unlink is a
        # no-op under SQLite, where the data lives in the DB, not on disk).
        api.save(api.POSTURE_STATE_FILE, {})
        self._fired = []
        self._orig = api.fire_webhook
        api.fire_webhook = lambda ev, p: self._fired.append((ev, p))

    def tearDown(self):
        api.fire_webhook = self._orig
        api.save(api.POSTURE_STATE_FILE, {})

    def _events(self):
        return [e[0] for e in self._fired]

    def test_degraded_then_recovered(self):
        # first contact seeds silently (online pool)
        api._ingest_posture_v3110("d1", "nas", {"storage_health": [
            {"name": "tank", "kind": "zfs", "state": "ONLINE"}]})
        self.assertNotIn("storage_degraded", self._events())
        # transition to degraded fires once
        api._ingest_posture_v3110("d1", "nas", {"storage_health": [
            {"name": "tank", "kind": "zfs", "state": "DEGRADED"}]})
        self.assertIn("storage_degraded", self._events())
        n = self._events().count("storage_degraded")
        # steady-state degraded does not re-fire
        api._ingest_posture_v3110("d1", "nas", {"storage_health": [
            {"name": "tank", "kind": "zfs", "state": "DEGRADED"}]})
        self.assertEqual(self._events().count("storage_degraded"), n)
        # recovery fires storage_recovered
        api._ingest_posture_v3110("d1", "nas", {"storage_health": [
            {"name": "tank", "kind": "zfs", "state": "ONLINE"}]})
        self.assertIn("storage_recovered", self._events())

    def test_firewall_drift(self):
        # v3.12.0: firewall_changed is gated behind the (off-by-default)
        # port_audit_enabled host-audit toggle — opt in for this test.
        api.save(api.CONFIG_FILE, {"port_audit_enabled": True})
        api._ingest_posture_v3110("d1", "h", {"firewall_fp": {"backend": "nftables", "rules": 10, "fp": "aaa"}})
        self.assertNotIn("firewall_changed", self._events())
        api._ingest_posture_v3110("d1", "h", {"firewall_fp": {"backend": "nftables", "rules": 12, "fp": "bbb"}})
        self.assertIn("firewall_changed", self._events())

    def test_timer_and_login(self):
        api._ingest_posture_v3110("d1", "h", {
            "timers": [{"unit": "backup.timer", "activates": "backup.service", "failed": False}],
            "auth": {"sources": ["10.0.0.5"], "recent_logins": [{"user": "root", "source": "10.0.0.5"}]}})
        base = self._events()
        self.assertNotIn("timer_failed", base)
        self.assertNotIn("login_new_source", base)
        api._ingest_posture_v3110("d1", "h", {
            "timers": [{"unit": "backup.timer", "activates": "backup.service", "failed": True}],
            "auth": {"sources": ["10.0.0.5", "203.0.113.9"],
                     "recent_logins": [{"user": "root", "source": "203.0.113.9"}]}})
        self.assertIn("timer_failed", self._events())
        self.assertIn("login_new_source", self._events())


if __name__ == "__main__":
    unittest.main(verbosity=2)
