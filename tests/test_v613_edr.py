"""v6.2.0 — EDR connectors + coverage cross-reference (gap item #10).

Three read-only EDR connectors (Wazuh, CrowdStrike Falcon, SentinelOne). Each is
a pure parser over the SSRF-safe client, tested here with a fake client.

But the connectors are not the feature. A tile reading "EDR: healthy" while three
servers have no agent on them is worse than no tile, because it is *reassuring*.
The feature is `GET /api/edr/coverage`: cross-reference the hosts each EDR says it
protects against the hosts we actually know about, and name the gap.

The two properties worth being paranoid about, both pinned below:
  1. HOSTNAME MATCHING. Consoles and agents disagree about case and domain suffix
     ('WEB01' vs 'web01.corp.example.com'). Match naively and almost everything
     reports as uncovered — the failure mode that makes operators stop trusting
     the page and ignore a real gap.
  2. TENANT ISOLATION. A fleet-aggregate that filters on `_caller_scope()` alone
     leaks the whole fleet to a tenant admin (whose role scope is None) — the
     exact class of bug the v6.1.1 sweep found six times. This one routes through
     `_scope_filter_devices`.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import integrations as I                      # noqa: E402
from integrations import HTTPClient, Resp, IntegrationError   # noqa: E402


class FakeClient(HTTPClient):
    def __init__(self, routes):
        super().__init__("http://edr.local")
        self.routes = routes
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append({"method": method, "path": path, "headers": headers or {}})
        base = path.split("?", 1)[0]
        r = self.routes.get((method, base))
        if r is None:
            return Resp(404, "")
        return r(path) if callable(r) else r


# ── Wazuh ────────────────────────────────────────────────────────────────────
def _wazuh_routes(agents):
    return {
        ("GET", "/security/user/authenticate"):
            Resp(200, json.dumps({"data": {"token": "JWT"}})),
        ("GET", "/agents"): Resp(200, json.dumps({
            "data": {"affected_items": agents, "total_affected_items": len(agents)}})),
    }


class TestWazuh(unittest.TestCase):
    def test_reports_protected_hosts(self):
        c = FakeClient(_wazuh_routes([
            {"name": "web01", "status": "active", "version": "v4.7.0",
             "lastKeepAlive": "2026-07-13T10:00:00Z"},
            {"name": "db01", "status": "disconnected", "version": "v4.7.0",
             "lastKeepAlive": "2026-07-01T10:00:00Z"},
        ]))
        out = I.CONNECTORS["wazuh"]["health"]({"username": "u", "secret": "p"}, c)
        self.assertEqual(2, out["metrics"]["agents_total"])
        self.assertEqual(1, out["metrics"]["agents_active"])
        self.assertEqual(1, out["metrics"]["agents_stale"])
        self.assertEqual({"web01", "db01"},
                         {h["hostname"] for h in out["edr_hosts"]})

    def test_the_manager_is_not_an_endpoint(self):
        """Wazuh registers itself as agent 000. Counting it as a protected
        endpoint would inflate coverage with a machine that isn't one."""
        c = FakeClient(_wazuh_routes([
            {"name": "wazuh-manager", "status": "active"},
            {"name": "web01", "status": "active"},
        ]))
        out = I.CONNECTORS["wazuh"]["health"]({}, c)
        self.assertEqual(["web01"], [h["hostname"] for h in out["edr_hosts"]])

    def test_a_stale_agent_downgrades_health(self):
        """An agent that stopped reporting is an agent that is protecting nothing."""
        c = FakeClient(_wazuh_routes([{"name": "web01", "status": "disconnected"}]))
        out = I.CONNECTORS["wazuh"]["health"]({}, c)
        self.assertEqual(I.CRIT, out["status"])   # zero active

    def test_all_active_is_ok(self):
        c = FakeClient(_wazuh_routes([{"name": "web01", "status": "active"}]))
        self.assertEqual(I.OK, I.CONNECTORS["wazuh"]["health"]({}, c)["status"])

    def test_bad_credentials_raise(self):
        routes = _wazuh_routes([])
        routes[("GET", "/security/user/authenticate")] = Resp(200, json.dumps({"data": {}}))
        with self.assertRaises(IntegrationError):
            I.CONNECTORS["wazuh"]["health"]({}, FakeClient(routes))

    def test_the_agent_call_is_authenticated_with_the_jwt(self):
        c = FakeClient(_wazuh_routes([]))
        I.CONNECTORS["wazuh"]["health"]({}, c)
        agents = [x for x in c.calls if x["path"].startswith("/agents")][0]
        self.assertEqual("Bearer JWT", agents["headers"].get("Authorization"))


# ── CrowdStrike ──────────────────────────────────────────────────────────────
def _cs_routes(devices):
    ids = [f"id{i}" for i in range(len(devices))]
    return {
        ("POST", "/oauth2/token"): Resp(200, json.dumps({"access_token": "TOK"})),
        ("GET", "/devices/queries/devices/v1"): Resp(200, json.dumps({
            "resources": ids, "meta": {"pagination": {"total": len(ids)}}})),
        ("GET", "/devices/entities/devices/v2"): Resp(200, json.dumps({
            "resources": devices})),
    }


class TestCrowdStrike(unittest.TestCase):
    def test_reports_protected_hosts(self):
        c = FakeClient(_cs_routes([
            {"hostname": "WEB01", "agent_version": "7.1", "status": "normal",
             "last_seen": "2026-07-13T10:00:00Z"},
            {"hostname": "db01", "agent_version": "7.1", "status": "containment"},
        ]))
        out = I.CONNECTORS["crowdstrike"]["health"](
            {"username": "cid", "secret": "sec"}, c)
        self.assertEqual(2, out["metrics"]["agents_total"])
        self.assertEqual(1, out["metrics"]["agents_active"])
        # Containment is not full protection — it must not read as 'active'.
        self.assertEqual(1, out["metrics"]["agents_stale"])

    def test_the_entities_call_is_authenticated_and_relative(self):
        """A provider-RELATIVE path is what keeps the SSRF guard's host binding
        intact — the client rejects an absolute URL outright."""
        c = FakeClient(_cs_routes([{"hostname": "web01", "status": "normal"}]))
        I.CONNECTORS["crowdstrike"]["health"]({}, c)
        ent = [x for x in c.calls if x["path"].startswith("/devices/entities")][0]
        self.assertEqual("Bearer TOK", ent["headers"].get("Authorization"))
        self.assertFalse(ent["path"].startswith("http"))
        self.assertIn("ids=id0", ent["path"])

    def test_an_empty_estate_does_not_call_entities(self):
        c = FakeClient(_cs_routes([]))
        out = I.CONNECTORS["crowdstrike"]["health"]({}, c)
        self.assertEqual([], out["edr_hosts"])
        self.assertFalse([x for x in c.calls if "entities" in x["path"]])

    def test_auth_failure_raises(self):
        routes = _cs_routes([])
        routes[("POST", "/oauth2/token")] = Resp(401, "")
        with self.assertRaises(IntegrationError):
            I.CONNECTORS["crowdstrike"]["health"]({}, FakeClient(routes))


# ── SentinelOne ──────────────────────────────────────────────────────────────
def _s1_routes(agents):
    return {("GET", "/web/api/v2.1/agents"): Resp(200, json.dumps({
        "data": agents, "pagination": {"totalItems": len(agents)}}))}


class TestSentinelOne(unittest.TestCase):
    def test_reports_protected_hosts(self):
        c = FakeClient(_s1_routes([
            {"computerName": "web01", "agentVersion": "23.1", "isActive": True},
            {"computerName": "db01", "agentVersion": "23.1", "isActive": False},
        ]))
        out = I.CONNECTORS["sentinelone"]["health"]({"secret": "t"}, c)
        self.assertEqual(1, out["metrics"]["agents_active"])
        self.assertEqual(1, out["metrics"]["agents_stale"])

    def test_an_infected_endpoint_is_critical(self):
        """This is the alarm, not the tally — it must outrank a merely stale agent."""
        c = FakeClient(_s1_routes([
            {"computerName": "web01", "isActive": True, "infected": True},
        ]))
        out = I.CONNECTORS["sentinelone"]["health"]({}, c)
        self.assertEqual(I.CRIT, out["status"])
        self.assertEqual(1, out["metrics"]["infected"])
        self.assertIn("infected", out["detail"])

    def test_the_token_is_sent(self):
        c = FakeClient(_s1_routes([]))
        I.CONNECTORS["sentinelone"]["health"]({"secret": "TOKEN"}, c)
        self.assertEqual("ApiToken TOKEN", c.calls[0]["headers"].get("Authorization"))


class TestRegistration(unittest.TestCase):
    def test_all_three_are_registered_under_security(self):
        for t in ("wazuh", "crowdstrike", "sentinelone"):
            self.assertIn(t, I.CONNECTORS)
            self.assertEqual("security", I.CONNECTORS[t]["category"])

    def test_credentials_are_named_so_the_scrubber_redacts_them(self):
        """A field must be called 'secret' or the config-secret scrubber will
        happily hand an EDR API token back out of GET /api/config."""
        for t in ("wazuh", "crowdstrike", "sentinelone"):
            keys = {f["key"] for f in I.CONNECTORS[t]["fields"]}
            self.assertIn("secret", keys, t)
            self.assertFalse(keys - {"secret", "username"}, t)


# ── the actual feature: coverage cross-reference ─────────────────────────────
class TestCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v613-edr-")
        spec = importlib.util.spec_from_file_location("api_v613_edr", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        self.captured = {}
        self.role = "admin"

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda t: ("alice", self.role)
        api._get_integrations = lambda cfg=None: [
            {"id": "e1", "type": "wazuh", "label": "Wazuh", "enabled": True},
        ]
        api.save(api.INTEG_STATE_FILE, {"latest": {"e1": {"edr_hosts": [
            # The console's spelling: uppercase, fully-qualified.
            {"hostname": "WEB01.corp.example.com", "agent_version": "4.7",
             "status": "active"},
            {"hostname": "db01", "agent_version": "4.7", "status": "stale"},
        ]}}})
        api.save(api.DEVICES_FILE, {
            "d1": {"hostname": "web01"},                        # covered
            "d2": {"hostname": "db01"},                         # covered but stale
            "d3": {"hostname": "mail01"},                       # NOT covered
            "d4": {"hostname": "old01", "decommissioned": True},  # retired
        })
        api._LOAD_CACHE.clear()

    def _get(self):
        self.captured = {}
        try:
            self.api.handle_edr_coverage()
        except self.api.HTTPError:
            pass
        return self.captured.get("data") or {}

    def _row(self, data, hostname):
        return next(r for r in data["hosts"] if r["hostname"] == hostname)

    def test_hostname_matching_survives_case_and_domain_suffix(self):
        """'WEB01.corp.example.com' from the console IS 'web01' in the fleet. Get
        this wrong and everything reports uncovered, and the page gets ignored."""
        d = self._get()
        self.assertTrue(self._row(d, "web01")["covered"])

    def test_an_uncovered_host_is_named(self):
        """The entire reason the connectors exist."""
        d = self._get()
        self.assertFalse(self._row(d, "mail01")["covered"])
        self.assertEqual(1, d["summary"]["uncovered"])

    def test_a_stale_agent_is_not_silently_counted_as_protection(self):
        """An EDR rollout's most likely failure is an agent that installed and
        then stopped reporting. Folding that into 'covered' hides exactly it."""
        d = self._get()
        row = self._row(d, "db01")
        self.assertTrue(row["covered"])
        self.assertTrue(row["stale"])
        self.assertEqual(1, d["summary"]["stale"])

    def test_decommissioned_hosts_are_excluded(self):
        """A retired asset with no EDR is not a finding; leaving it in trains
        operators to ignore the list."""
        d = self._get()
        self.assertNotIn("old01", [r["hostname"] for r in d["hosts"]])

    def test_uncovered_hosts_sort_first(self):
        d = self._get()
        self.assertEqual("mail01", d["hosts"][0]["hostname"])

    def test_the_covering_vendor_is_named(self):
        d = self._get()
        self.assertEqual("wazuh", self._row(d, "web01")["by"][0]["vendor"])

    def test_scope_filtering_goes_through_scope_filter_devices(self):
        """A fleet aggregate that only checks `_caller_scope()` leaks the whole
        fleet to a tenant admin (role scope None) — the v6.1.1 bug class, found
        six times. Prove the filter is actually consulted."""
        called = {}
        real = self.api._scope_filter_devices

        def _spy(devices, scope=None):
            called["yes"] = True
            return {k: v for k, v in devices.items() if k == "d3"}

        self.api._scope_filter_devices = _spy
        try:
            d = self._get()
        finally:
            self.api._scope_filter_devices = real
        self.assertTrue(called.get("yes"))
        self.assertEqual(["mail01"], [r["hostname"] for r in d["hosts"]])


if __name__ == "__main__":
    unittest.main()
