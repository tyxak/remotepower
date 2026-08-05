"""v6.4.2 — an assistant can finally see what is on fire.

The MCP server exposed 18 tools and a case-insensitive search for "alert"
across the whole file returned NOTHING — no list_alerts, get_attention,
acknowledge_alert, monitor or ticket tool. So an assistant could reboot a host
(a far riskier action, and one that IS exposed and gated) and could not read the
Alerts inbox, which is the product's own primary triage surface with severity,
ack state, correlation and root-cause tagging.

Asked "what's on fire right now?", the only honest option was list_devices and
eyeballing online flags. `search_fleet` does retrieve alert text through the
RAG, but as ranked prose chunks — not structured rows an assistant can count,
filter by severity, or act on.

Every endpoint these call already existed and was already role-gated; this was
missing client wiring plus one narrow write.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-mcpalerts642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_MCP = ROOT / "mcp" / "remotepower-mcp.py"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestTheToolsExist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _MCP.exists():
            raise unittest.SkipTest("MCP server excluded from this tree")
        cls.src = _MCP.read_text()

    def test_the_word_alert_appears_at_all(self):
        """The finding in one assertion: a case-insensitive search for 'alert'
        across the whole file used to return nothing."""
        self.assertTrue(re.search(r"alert", self.src, re.I))

    def test_the_three_tools_are_defined_and_registered(self):
        for name in ("list_alerts", "get_attention", "acknowledge_alert"):
            with self.subTest(tool=name):
                self.assertRegex(self.src, r"\bdef tool_%s\s*\(" % name,
                                 "handler missing")
                self.assertIn('"%s": {' % name, self.src,
                              "defined and never registered — invisible to "
                              "the host")
                self.assertIn("tool_%s," % name, self.src,
                              "registry entry does not point at the handler")

    def test_every_registry_entry_has_a_real_handler(self):
        """A registry naming a function that does not exist is a NameError at
        import, which would take the whole MCP server down rather than one
        tool."""
        for m in re.finditer(r'"handler":\s*(tool_\w+)', self.src):
            with self.subTest(handler=m.group(1)):
                self.assertRegex(self.src, r"\bdef %s\s*\(" % m.group(1))

    def test_list_alerts_trims_the_payload(self):
        """A stored alert carries a full payload plus an AI-triage blob; fifty
        of those would eat the context budget this tool exists to protect."""
        body = self.src[self.src.index("def tool_list_alerts"):]
        body = body[:body.index("\ndef ")]
        self.assertIn("'severity'", body)
        self.assertNotIn("return rows", body,
                         "returning the raw rows defeats the point")

    def test_list_alerts_surfaces_the_correlation_facts(self):
        """Root-cause / collateral / incident are what change what an operator
        should DO — an assistant that cannot see them will recommend fixing
        twenty downstream hosts."""
        body = self.src[self.src.index("def tool_list_alerts"):]
        body = body[:body.index("\ndef ")]
        for k in ("_root_cause", "_collateral_of", "incident_id"):
            with self.subTest(field=k):
                self.assertIn(k, body)

    def test_acknowledge_cannot_resolve(self):
        """Closing an alert is a judgement that the problem is GONE. That stays
        an operator action."""
        body = self.src[self.src.index("def tool_acknowledge_alert"):]
        body = body[:body.index("\nTOOLS") if "\nTOOLS" in body else len(body)]
        self.assertNotIn("/resolve", body)
        self.assertIn("acknowledge_alert", body)

    def test_the_write_rides_the_audited_mcp_path(self):
        body = self.src[self.src.index("def tool_acknowledge_alert"):]
        body = body[:body.index("\nTOOLS") if "\nTOOLS" in body else len(body)]
        self.assertIn("/api/mcp/acknowledge_alert", body)
        self.assertIn("mcp_prompt", body,
                      "the originating prompt must reach the audit log")


class TestTheServerHalf(unittest.TestCase):
    def setUp(self):
        n = int(time.time())
        self._saved = {k: getattr(api, k, None) for k in
                       ("require_mcp_action", "get_mcp_attribution", "audit_log",
                        "method", "get_json_body", "_alert_mutable_by_caller")}
        api.require_mcp_action = lambda a: "mcpkey"
        api.get_mcp_attribution = lambda: ("Claude Desktop", "ack it")
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"
        api._alert_mutable_by_caller = lambda a: True
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "mcpa1", "event": "disk_full", "severity": "high",
             "device_id": "mh1", "device_name": "web01", "ts": n,
             "title": "Disk full"},
            {"id": "mcpa2", "event": "x", "severity": "low",
             "device_id": "mh1", "ts": n, "resolved_at": n},
        ], "alert_seq": 2})

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                setattr(api, k, v)

    def _ack(self, **body):
        api.get_json_body = lambda: body
        try:
            api.handle_mcp_acknowledge_alert()
            return None, None
        except api.HTTPError as e:
            return e.status, e.body

    def test_it_acknowledges(self):
        status, body = self._ack(alert_id="mcpa1", note="jakob is on it")
        self.assertEqual(status, 200, body)
        row = next(a for a in api.load(api.ALERTS_FILE)["alerts"]
                   if a["id"] == "mcpa1")
        self.assertEqual(row["acknowledged_by"], "mcpkey")
        self.assertEqual(row["ack_note"], "jakob is on it")
        self.assertIsNone(row.get("resolved_at"),
                          "acknowledging must never resolve")

    def test_double_ack_is_refused(self):
        self._ack(alert_id="mcpa1")
        self.assertEqual(self._ack(alert_id="mcpa1")[0], 409)

    def test_a_resolved_alert_is_refused(self):
        self.assertEqual(self._ack(alert_id="mcpa2")[0], 409)

    def test_an_unknown_id_404s(self):
        self.assertEqual(self._ack(alert_id="nope")[0], 404)

    def test_a_missing_id_400s(self):
        self.assertEqual(self._ack()[0], 400)

    def test_an_invisible_alert_404s_not_403(self):
        """Same visibility gate the human ack uses. This route is not under
        /api/devices/, so _enforce_device_scope never runs for it — an MCP key
        confined to a tenant must not be able to ack outside it, and the answer
        is 404 so it cannot be used to probe which ids exist."""
        api._alert_mutable_by_caller = lambda a: False
        self.assertEqual(self._ack(alert_id="mcpa1")[0], 404)

    def test_it_is_gated_by_the_mcp_allowlist(self):
        """A leaked MCP key stays confined to the allowlist; the action being
        absent from it would make the endpoint unreachable, and the action being
        present without the gate would make it un-audited."""
        self.assertIn("acknowledge_alert", api.MCP_ACTION_ALLOWLIST)
        src = (_CGI / "attention_handlers.py").read_text()
        fn = src[src.index("def handle_mcp_acknowledge_alert"):]
        self.assertIn("require_mcp_action('acknowledge_alert')", fn)

    def test_the_route_is_registered(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from routing_harness import routes_to
        self.assertEqual(routes_to("POST", "/api/mcp/acknowledge_alert"),
                         "handle_mcp_acknowledge_alert")


if __name__ == "__main__":
    unittest.main()


class TestPrometheusServiceDiscovery(unittest.TestCase):
    """RemotePower already tracks every host's name, IP, group, tag, site and
    online state, and re-syncs cloud instances automatically — and Prometheus
    could consume none of it. An operator scraping node_exporter alongside had
    to hand-maintain a second target list, so a newly-enrolled or decommissioned
    host silently drifted out of prometheus.yml until someone noticed a missing
    graph."""

    def setUp(self):
        n = int(time.time())
        self.now = n
        self._saved = {k: getattr(api, k, None) for k in
                       ("require_auth", "_caller_scope", "_tenant_gate", "_env",
                        "_scope_filter_devices")}
        api.require_auth = lambda *a, **k: "jakob"
        api._caller_scope = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api.save(api.CONFIG_FILE, {"status_token": "stok", "online_ttl": 300,
                                   "min_online_ttl": 150})
        api.save(api.DEVICES_FILE, {
            "sd1": {"name": "web01", "ip": "10.0.0.1", "group": "prod",
                    "site": "fra", "os": "Ubuntu", "tags": ["web", "edge"],
                    "last_seen": n},
            "sd2": {"name": "db01", "ip": "10.0.0.2", "last_seen": n - 99999},
            "sd3": {"name": "switch", "ip": "10.0.0.3", "agentless": True,
                    "last_seen": n},
            "sd4": {"name": "gone", "ip": "10.0.0.4", "decommissioned": True,
                    "last_seen": n},
            "sd5": {"name": "Display Name Only", "last_seen": n},
            "sd6": {"name": "byhost", "hostname": "db.lan", "last_seen": n},
        })
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                setattr(api, k, v)

    def _sd(self, qs="token=stok"):
        api._env = lambda k, d="": qs if k == "QUERY_STRING" else d
        try:
            api.handle_prometheus_sd()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            return e.status, e.body

    def _targets(self, qs="token=stok"):
        return [t["targets"][0] for t in self._sd(qs)[1]]

    def test_it_returns_http_sd_shape(self):
        _s, body = self._sd()
        self.assertIsInstance(body, list)
        for e in body:
            with self.subTest(entry=e):
                self.assertIsInstance(e["targets"], list)
                self.assertIsInstance(e["labels"], dict)

    def test_an_agentless_device_is_omitted(self):
        """A switch has no node_exporter — including it hands Prometheus a
        target that can only ever be down."""
        self.assertNotIn("10.0.0.3:9100", self._targets())

    def test_a_decommissioned_device_is_omitted(self):
        self.assertNotIn("10.0.0.4:9100", self._targets())

    def test_the_display_name_is_never_used_as_an_address(self):
        """`name` is operator-editable and explicitly decoupled from the
        reported hostname since v6.4.1. Scraping it produces a permanently-down
        job the moment anyone renames a device for readability."""
        self.assertNotIn("Display Name Only:9100", self._targets())
        self.assertFalse(any("Display" in t for t in self._targets()))

    def test_it_falls_back_to_the_reported_hostname(self):
        self.assertIn("db.lan:9100", self._targets())

    def test_an_offline_host_is_still_a_target_by_default(self):
        """Prometheus wants to know a host is DOWN. Omitting it would make the
        outage invisible rather than red."""
        self.assertIn("10.0.0.2:9100", self._targets())

    def test_online_1_narrows_it(self):
        self.assertNotIn("10.0.0.2:9100", self._targets("token=stok&online=1"))

    def test_the_port_is_settable_and_bounded(self):
        self.assertIn("10.0.0.1:9256", self._targets("token=stok&port=9256"))
        for bad in ("0", "70000", "abc"):
            with self.subTest(port=bad):
                self.assertIn("10.0.0.1:9100",
                              self._targets(f"token=stok&port={bad}"))

    def test_the_labels_carry_what_a_relabel_rule_needs(self):
        row = next(t for t in self._sd()[1]
                   if t["targets"][0] == "10.0.0.1:9100")
        for k in ("__meta_remotepower_id", "__meta_remotepower_name",
                  "__meta_remotepower_group", "__meta_remotepower_site",
                  "__meta_remotepower_online", "instance"):
            with self.subTest(label=k):
                self.assertIn(k, row["labels"])

    def test_tags_use_the_conventional_delimited_shape(self):
        """Prometheus SD has no list label type; a separator-wrapped string is
        what a relabel regex expects."""
        row = next(t for t in self._sd()[1]
                   if t["targets"][0] == "10.0.0.1:9100")
        self.assertEqual(row["labels"]["__meta_remotepower_tags"], ",web,edge,")

    def test_instance_is_the_stable_name_not_the_address(self):
        """Prometheus keys a series on `instance`; using the IP would make a
        re-addressed host look like a brand-new one and break its history."""
        row = next(t for t in self._sd()[1]
                   if t["targets"][0] == "10.0.0.1:9100")
        self.assertEqual(row["labels"]["instance"], "web01")

    def test_a_bad_status_token_is_401(self):
        self.assertEqual(self._sd("token=nope")[0], 401)

    def test_a_session_caller_is_scope_filtered(self):
        """A status-token scrape is the same trust level as /api/metrics (whole
        fleet); a SESSION caller must not be, or this becomes a way around role
        scope and the tenant gate."""
        api._scope_filter_devices = lambda d: {k: v for k, v in d.items()
                                               if k != "sd1"}
        self.assertNotIn("10.0.0.1:9100", self._targets(""))

    def test_the_route_is_registered(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from routing_harness import routes_to
        self.assertEqual(routes_to("GET", "/api/prometheus/sd"),
                         "handle_prometheus_sd")
