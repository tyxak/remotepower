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
