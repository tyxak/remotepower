#!/usr/bin/env python3
"""Four readers that asked for a key the producer never wrote (7.5.0 signals review, G05 to G08).

G05  The IaC export of a host read watched_services, drift_files and cmd_allowlist from the host record. The update endpoint takes
     those names and stores services_watched, watched_files and allowed_commands, so the export listed no watched unit, no watched
     file and no allowed command for any host. Driven round trip: the real endpoint writes, the export reads.
G06  The never-block list read sysinfo.ip_addresses, which no agent sends. A host's second NIC, its IPv6 address or a public address
     were not protected from the blocklist it feeds. It reads host_addresses and the interface list, which are what the agent sends.
G07  The triage "services" tool read the configured name list: "(no watched services)" for a host with four stored states, and a
     failed unit was never in the evidence. It reads services.json, which is what the Services page shows.
G08  The runbook snapshot's container `state` was null for every container (the row holds `status`) and no host problem reached it.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-sigread-"))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import ip_intel  # noqa: E402


class TestIacExportReadsWhatTheEndpointStores(_Base):

    def test_the_round_trip(self):
        st, d = self.call(api.handle_device_save_bulk, "devB",
                          body={"watched_services": ["nginx.service", "postgresql.service"],
                                "watched_files": ["/etc/ssh/sshd_config", "/etc/nginx/nginx.conf"],
                                "cmd_allowlist": ["uptime", "systemctl status nginx"]})
        self.assertEqual(st, 200, d)
        api._LOAD_CACHE.clear()
        dev = api.load(api.DEVICES_FILE)["devB"]
        out = api._iac_collect_server_side("devB", dev, ["remotepower"])["remotepower"]
        self.assertEqual(out["watched_services"], ["nginx.service", "postgresql.service"])
        self.assertEqual(out["cmd_allowlist"], ["uptime", "systemctl status nginx"])
        paths = [f if isinstance(f, str) else f.get("path") for f in out["drift_files"]]
        self.assertEqual(sorted(paths), ["/etc/nginx/nginx.conf", "/etc/ssh/sshd_config"])

    def test_a_host_with_nothing_set_exports_empty_lists(self):
        out = api._iac_collect_server_side("x", {"group": "g"}, ["remotepower"])["remotepower"]
        self.assertEqual((out["watched_services"], out["drift_files"], out["cmd_allowlist"]), ([], [], []))

    def test_the_old_request_names_are_not_read_from_the_record(self):
        """A record that carries the request names (it never did) must not shadow the stored ones."""
        dev = {"services_watched": ["a.service"], "watched_services": ["WRONG"], "cmd_allowlist": ["WRONG"], "allowed_commands": ["ok"]}
        out = api._iac_collect_server_side("x", dev, ["remotepower"])["remotepower"]
        self.assertEqual((out["watched_services"], out["cmd_allowlist"]), (["a.service"], ["ok"]))


class TestTheNeverBlockListHoldsTheHostsOwnAddresses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import importlib.util
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-sigread-ip-")
        spec = importlib.util.spec_from_file_location("api_v750_sigread_ip", ROOT / "server/cgi-bin/api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def nets(self, sysinfo, **dev):
        mod = self.api.ip_intel_handlers_mod
        return mod._protected_networks({}, {"d1": {"name": "web01", "sysinfo": sysinfo, **dev}})

    def test_every_address_the_agent_reports_is_protected(self):
        nets = self.nets({"host_addresses": ["203.0.113.7", "2001:db8::5", "10.1.2.3"],
                          "network": [{"iface": "eth1", "ip": "198.51.100.9", "mac": "aa:bb"}]})
        for ip in ("203.0.113.7", "2001:db8::5", "10.1.2.3", "198.51.100.9"):
            self.assertTrue(ip_intel.in_any(ip, nets), ip)

    def test_an_address_of_nobody_in_the_fleet_is_not(self):
        nets = self.nets({"host_addresses": ["203.0.113.7"]})
        self.assertFalse(ip_intel.in_any("203.0.113.8", nets))
        self.assertFalse(ip_intel.in_any("2001:db8::6", nets))

    def test_the_older_fields_still_count(self):
        nets = self.nets({}, ip="192.0.2.10", public_ip="192.0.2.11", wan_ip="192.0.2.12")
        for ip in ("192.0.2.10", "192.0.2.11", "192.0.2.12"):
            self.assertTrue(ip_intel.in_any(ip, nets), ip)

    def test_the_first_sixty_four_addresses_count_and_no_more(self):
        """The agent sends at most 64 (it sends none beyond that); the reader keeps to the same bound."""
        addrs = [f"203.0.113.{i}" for i in range(1, 66)]            # 65 addresses
        nets = self.nets({"host_addresses": addrs})
        self.assertTrue(ip_intel.in_any("203.0.113.5", nets))       # inside the first handful: a cap of 4 would lose the fifth
        self.assertTrue(ip_intel.in_any("203.0.113.64", nets))
        self.assertFalse(ip_intel.in_any("203.0.113.65", nets))

    def test_junk_in_the_lists_is_skipped(self):
        nets = self.nets({"host_addresses": [None, 5, {"address": "203.0.113.20"}, "not an address", ["x"]],
                          "network": ["x", None, {"ip": None}, {"ip": "198.51.100.30"}]})
        self.assertTrue(ip_intel.in_any("203.0.113.20", nets))
        self.assertTrue(ip_intel.in_any("198.51.100.30", nets))
        for junk in (None, [], "x", 5):
            self.nets(junk if isinstance(junk, dict) else {"host_addresses": junk, "network": junk})        # must not raise


class TestTheTriageServicesToolShowsStates(_Base):

    def tool(self, dev, dev_id="devB"):
        tools = api._triage_tools(dev_id, dev)
        return tools["services"]({}) if isinstance(tools, dict) else dict(tools)["services"]({})

    def test_stored_states_are_the_answer(self):
        api.save(api.SERVICES_FILE, {"devB": {"updated_at": 1, "services": [
            {"unit": "nginx.service", "active": "active", "sub": "running", "since": 1},
            {"unit": "postgresql.service", "active": "failed", "sub": "failed", "since": 1}]}})
        api._LOAD_CACHE.clear()
        text = self.tool({"services_watched": ["nginx.service", "postgresql.service"]})
        self.assertIn("nginx.service: active (running)", text)
        self.assertIn("postgresql.service: failed (failed)", text)
        self.assertNotIn("no watched services", text)

    def test_the_configured_names_are_the_fallback_for_a_host_that_has_not_reported(self):
        api.save(api.SERVICES_FILE, {})
        api._LOAD_CACHE.clear()
        text = self.tool({"services_watched": ["nginx.service"]})
        self.assertIn("nginx.service: no state reported yet", text)

    def test_nothing_at_all_says_so(self):
        api.save(api.SERVICES_FILE, {})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.tool({}), "(no watched services)")

    def test_another_hosts_states_are_not_shown(self):
        api.save(api.SERVICES_FILE, {"other": {"services": [{"unit": "secret.service", "active": "active", "sub": "running"}]}})
        api._LOAD_CACHE.clear()
        self.assertNotIn("secret.service", self.tool({"services_watched": ["nginx.service"]}))


class TestTheRunbookSnapshot(_Base):

    def snap(self, dev, extra=None):
        devs = api.load(api.DEVICES_FILE)
        devs["devB"].update(dev)
        api.save(api.DEVICES_FILE, devs)
        api.save(api.CONTAINERS_FILE, {"devB": {"items": extra or []}})
        api._LOAD_CACHE.clear()
        return api._build_runbook_snapshot("devB", api.load(api.DEVICES_FILE))

    def test_a_container_carries_its_status_and_health(self):
        s = self.snap({}, [{"name": "web", "image": "nginx:1", "status": "Up 2 hours (unhealthy)", "health": "unhealthy"},
                           {"name": "db", "image": "postgres:16", "status": "Up 3 days"}])
        self.assertEqual([(c["name"], c["state"], c["health"]) for c in s["containers"]],
                         [("web", "Up 2 hours (unhealthy)", "unhealthy"), ("db", "Up 3 days", None)])

    def test_the_host_problems_come_from_its_sysinfo(self):
        import time
        s = self.snap({"sysinfo": {"reboot_required": True, "failed_units": [{"unit": "foo.service"}, "bar.service"],
                                   "mount_issues": [{"path": "/mnt/a"}, {"path": "/mnt/b"}], "gateway": {"reachable": False},
                                   "last_oom_ts": int(time.time()) - 60, "clock": {"skewed": True}}})
        self.assertEqual(s["problems"], [
            "a reboot is required", "failed systemd units: foo.service, bar.service", "2 mount problems",
            "the default gateway does not answer", "the kernel killed a process for lack of memory in the last 24 hours",
            "the clock is off by more than the limit"])

    def test_a_healthy_host_has_none_and_old_events_do_not_count(self):
        import time
        self.assertEqual(self.snap({"sysinfo": {"cpu": "x"}})["problems"], [])
        s = self.snap({"sysinfo": {"last_oom_ts": int(time.time()) - 3 * 86400, "gateway": {"reachable": True},
                                   "failed_units": [], "mount_issues": [], "clock": {"skewed": False}}})
        self.assertEqual(s["problems"], [])

    def test_junk_in_the_flags_does_not_break_the_snapshot(self):
        for si in ({"failed_units": "x", "mount_issues": 7, "gateway": "x", "last_oom_ts": True, "clock": 5},
                   {"failed_units": [None, 5, {}], "gateway": None}, {"mount_issues": {"a": 1}}):
            self.assertIsInstance(self.snap({"sysinfo": si})["problems"], list)

    def test_the_snapshot_is_still_json(self):
        json.dumps(self.snap({"sysinfo": {"reboot_required": True}}, [{"name": "w", "status": "Up"}]))


class TestTheAnomalyScanSeesThePorts(_Base):
    """G04: the prompt asks about suspicious ports and the snapshot carried none."""

    def lines(self, ports):
        devs = api.load(api.DEVICES_FILE)
        devs["devB"]["sysinfo"] = {"cpu_percent": 5, "listening_ports": ports}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        seen = {}
        real_prompt, real_run = api.ai_insights.anomaly_prompt, api._ai_run
        api.ai_insights.anomaly_prompt = lambda summary: (seen.setdefault("s", summary), ("sys", []))[1]
        api._ai_run = lambda *a, **k: ({"text": "[]"}, 0, 100)
        try:
            st, d = self.call(api.handle_ai_anomaly)
        finally:
            api.ai_insights.anomaly_prompt, api._ai_run = real_prompt, real_run
        self.assertEqual(st, 200, d)
        return [ln for ln in seen["s"].splitlines() if "name=b1" in ln]

    def test_world_reachable_ports_are_in_the_line_by_number_and_protocol_only(self):
        got = self.lines([{"port": 22, "proto": "tcp", "process": "sshd", "scope": "world"},
                          {"port": 5432, "proto": "tcp", "process": "postgres", "scope": "lan"},
                          {"port": 53, "proto": "udp", "process": "dnsmasq", "scope": "world"}])
        self.assertEqual(len(got), 1)
        self.assertIn("world_ports=22/tcp,53/udp", got[0])
        self.assertNotIn("5432", got[0])
        for secret in ("sshd", "postgres", "dnsmasq"):
            self.assertNotIn(secret, got[0])

    def test_none_reachable_adds_nothing_and_junk_is_skipped(self):
        self.assertNotIn("world_ports", self.lines([{"port": 5432, "proto": "tcp", "scope": "lan"}])[0])
        got = self.lines([None, "x", {"port": "22", "scope": "world"}, {"port": True, "scope": "world"}, {"port": 80, "scope": "world"}])
        self.assertIn("world_ports=80/tcp", got[0])

    def test_at_most_eight(self):
        got = self.lines([{"port": 1000 + i, "proto": "tcp", "scope": "world"} for i in range(12)])[0]
        self.assertEqual(len(got.split("world_ports=")[1].split(",")), 8)

    def test_a_port_listed_twice_is_named_once(self):
        got = self.lines([{"port": 1000, "proto": "tcp", "scope": "world"}, {"port": 1000, "proto": "tcp", "scope": "world"},
                          {"port": 1001, "proto": "tcp", "scope": "world"}])[0]
        self.assertIn("world_ports=1000/tcp,1001/tcp", got)


if __name__ == "__main__":
    unittest.main()
