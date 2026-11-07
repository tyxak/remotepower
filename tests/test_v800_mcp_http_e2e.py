#!/usr/bin/env python3
"""8.0.0: the hosted MCP endpoint against a real server, over HTTP, on the demo seed.

tests/test_v800_mcp_http.py runs the handlers in-process. This file runs what a client would: the gunicorn stack, a signed-in token and API keys
with the options of the Admin dialog (role, host scope, allowed address, rate limit), and a plain HTTP client that speaks JSON-RPC. What it
holds: the endpoint answers 404 until the module is switched on; a caller sees through it exactly what the dashboard's own request shows the same
key (the whole fleet, a host-scoped subset, nothing for a revoked or address-limited key); the key's own rate limit counts; a write tool does not
exist; a cross-origin POST is refused by the gate main() runs; and a tool call leaves a line in the audit log.

Self-skips without gunicorn. No browser is involved, so the file is not in the e2e-only exclusion of make test-fast by name alone: it carries
'e2e' in its name because it boots a stack.
"""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

_ROOT = Path(__file__).resolve().parent.parent
_STATE = {}


def setUpModule():
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the endpoint is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-mcp-http-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    try:
        from e2e_harness import start_stack
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    if _STATE.get("shutdown"):
        _STATE["shutdown"]()


def http_call(method, path, body=None, token=None, headers=None):
    u = urlparse(_STATE["base"])
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode() if not isinstance(body, bytes) else body
        h.setdefault("Content-Type", "application/json")
    if token:
        h.setdefault("Authorization", "Bearer " + token)
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    raw = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    try:
        parsed = json.loads(raw) if raw.strip() else None
    except ValueError:
        parsed = raw
    return resp.status, hdrs, parsed


def rpc(method, params=None, msg_id=1):
    m = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        m["id"] = msg_id
    if params is not None:
        m["params"] = params
    return m


class TestTheHostedEndpointOverHttp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        status, _, body = http_call("POST", "/api/login", {"username": "alice", "password": "demo"})
        assert status == 200, body
        cls.token = body["token"]
        cls.keys = []

    @classmethod
    def tearDownClass(cls):
        for kid in cls.keys:
            http_call("DELETE", "/api/apikeys/" + kid, token=cls.token)
        http_call("POST", "/api/config", {"mcp_module_enabled": False}, token=cls.token)

    def setUp(self):
        self.switch(True)

    # ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def switch(self, on):
        status, _, body = http_call("POST", "/api/config", {"mcp_module_enabled": on}, token=self.token)
        self.assertEqual(status, 200, body)

    def key(self, **kw):
        status, _, body = http_call("POST", "/api/apikeys", dict({"name": "mcp-test", "role": "viewer"}, **kw), token=self.token)
        self.assertEqual(status, 201, body)
        self.keys.append(body["id"])
        return body["key"], body["id"]

    def ask(self, message, token=None, **kw):
        return http_call("POST", "/api/mcp", message, token=token or self.token, **kw)

    def tool(self, name, arguments=None, token=None, **kw):
        status, _, body = self.ask(rpc("tools/call", {"name": name, "arguments": arguments or {}}), token=token, **kw)
        self.assertEqual(status, 200, body)
        return body

    def dashboard_names(self, token):
        status, _, body = http_call("GET", "/api/devices", token=token)
        self.assertEqual(status, 200, body)
        devs = body if isinstance(body, list) else body.get("devices", [])
        return sorted(d["name"] for d in devs)

    def mcp_names(self, token):
        body = self.tool("list_devices", token=token)
        self.assertFalse(body["result"]["isError"], body)
        return sorted(h["name"] for h in json.loads(body["result"]["content"][0]["text"]))

    # ── off, and who may ask ────────────────────────────────────────────────────────────────────────────────────────────────
    def test_it_answers_404_until_the_module_is_switched_on_and_again_when_it_is_switched_off(self):
        self.switch(False)
        status, _, body = self.ask(rpc("ping"))
        self.assertEqual(status, 404, body)
        self.assertEqual(body.get("module_disabled"), "mcp")
        self.switch(True)
        self.assertEqual(self.ask(rpc("ping"))[0], 200)
        self.switch(False)
        self.assertEqual(self.ask(rpc("ping"))[0], 404)

    def test_a_caller_with_no_token_or_a_wrong_one_gets_401_and_a_bearer_challenge(self):
        for token in (None, "not-a-token"):
            u = urlparse(_STATE["base"])
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
            conn.request("POST", "/api/mcp", body=json.dumps(rpc("ping")), headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 401, token)
            self.assertIn("Bearer", resp.getheader("WWW-Authenticate") or "", token)
            conn.close()

    def test_a_get_and_a_delete_answer_405_and_say_post(self):
        # the transport lets a server offer a stream on GET and end a session on DELETE; this one does neither. Any other verb meets the router's 404.
        for verb in ("GET", "DELETE"):
            status, headers, _ = http_call(verb, "/api/mcp", token=self.token)
            self.assertEqual(status, 405, verb)
            self.assertEqual(headers.get("allow"), "POST", verb)
        self.assertEqual(http_call("PUT", "/api/mcp", rpc("ping"), token=self.token)[0], 404)

    def test_a_cross_origin_post_is_refused_by_the_gate_that_runs_before_the_handler(self):
        status, _, body = self.ask(rpc("ping"), headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403, body)

    def test_the_session_token_of_a_signed_in_user_works_as_a_bearer_token_and_as_x_token(self):
        self.assertEqual(self.ask(rpc("ping"))[0], 200)
        status, _, body = http_call("POST", "/api/mcp", rpc("ping"), headers={"X-Token": self.token})
        self.assertEqual((status, body["result"]), (200, {}))

    # ── the conversation ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_initialize_list_and_call_work_as_a_client_does_them(self):
        status, _, body = self.ask(rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}))
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(body["result"]["serverInfo"]["name"], "remotepower")
        status, _, body = self.ask(rpc("notifications/initialized", msg_id=None))
        self.assertEqual(status, 202)
        status, _, body = self.ask(rpc("tools/list", msg_id=2))
        self.assertEqual(body["id"], 2)
        names = sorted(t["name"] for t in body["result"]["tools"])
        self.assertEqual(len(names), 8)
        for write in ("reboot_device", "run_saved_script", "force_package_scan", "force_acme_rescan", "acknowledge_alert"):
            self.assertNotIn(write, names)
            body = self.ask(rpc("tools/call", {"name": write, "arguments": {"name": "x", "alert_id": "x"}}))[2]
            self.assertEqual(body["error"]["code"], -32602, write)

    def test_a_malformed_message_gets_a_json_rpc_error_not_a_stack_trace(self):
        status, _, body = http_call("POST", "/api/mcp", b"{not json", token=self.token)
        self.assertEqual((status, body["error"]["code"]), (400, -32700))
        status, _, body = self.ask([rpc("ping"), rpc("ping", msg_id=2)])
        self.assertEqual((status, body["error"]["code"]), (400, -32600))

    def test_the_answer_is_not_compressed_even_when_the_client_accepts_gzip(self):
        status, headers, body = self.ask(rpc("tools/call", {"name": "list_devices", "arguments": {}}), headers={"Accept-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertNotIn("content-encoding", headers)
        self.assertFalse(body["result"]["isError"], body)
        self.assertGreater(len(json.loads(body["result"]["content"][0]["text"])), 5, "the seeded fleet came back through the read that would have been compressed")

    # ── what is read is what the caller may read ────────────────────────────────────────────────────────────────────────────
    def test_the_whole_fleet_for_the_administrator_is_the_dashboards_own_list(self):
        mine = self.mcp_names(self.token)
        self.assertEqual(mine, self.dashboard_names(self.token)[:200])
        self.assertGreater(len(mine), 10)

    def test_a_viewer_key_sees_what_the_dashboard_shows_that_key(self):
        key, _ = self.key(role="viewer")
        self.assertEqual(self.mcp_names(key), self.dashboard_names(key)[:200])

    def test_a_key_confined_to_a_group_sees_only_that_group_through_the_endpoint_too(self):
        _, _, body = http_call("GET", "/api/devices", token=self.token)
        devs = body if isinstance(body, list) else body.get("devices", [])
        groups = sorted({d.get("group") for d in devs if d.get("group")})
        self.assertGreaterEqual(len(groups), 2, "the seed has groups to confine a key to")
        group = groups[0]
        inside = sorted(d["name"] for d in devs if d.get("group") == group)
        outside = sorted(d["name"] for d in devs if d.get("group") != group)
        self.assertTrue(inside and outside)
        key, _ = self.key(role="viewer", scope={"type": "groups", "values": [group]})
        self.assertEqual(self.dashboard_names(key), inside, "the dashboard's own answer for this key")
        self.assertEqual(self.mcp_names(key), inside, "and so is the endpoint's")
        refused = self.tool("get_device", {"name": outside[0]}, token=key)
        self.assertTrue(refused["result"]["isError"])
        self.assertEqual(refused["result"]["content"][0]["text"], "No host named '%s'" % outside[0])
        found = self.tool("get_device", {"name": inside[0]}, token=key)
        self.assertFalse(found["result"]["isError"])

    def test_a_key_limited_to_one_address_is_refused_from_any_other_through_the_endpoint_too(self):
        key, _ = self.key(role="viewer", ip_allow=["10.255.255.1/32"])
        direct = http_call("GET", "/api/devices", token=key, headers={"X-Forwarded-For": "203.0.113.9"})[0]
        self.assertIn(direct, (401, 403), "the dashboard's own request is refused")
        status, _, _ = self.ask(rpc("ping"), token=key, headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertIn(status, (401, 403))
        self.assertEqual(self.ask(rpc("ping"), token=key, headers={"X-Forwarded-For": "10.255.255.1"})[0], 200, "and allowed from the address it names")

    def test_a_revoked_key_stops_working(self):
        key, kid = self.key(role="viewer")
        self.assertEqual(self.ask(rpc("ping"), token=key)[0], 200)
        self.assertEqual(http_call("DELETE", "/api/apikeys/" + kid, token=self.token)[0], 200)
        self.keys.remove(kid)
        self.assertEqual(self.ask(rpc("ping"), token=key)[0], 401)

    def test_a_keys_own_rate_limit_counts_for_every_message(self):
        key, _ = self.key(role="viewer", rate_limit=5)
        statuses = [self.ask(rpc("ping", msg_id=i), token=key)[0] for i in range(12)]
        self.assertIn(429, statuses, statuses)
        self.assertEqual(statuses[0], 200)

    def test_a_module_that_is_off_is_a_404_in_the_tool_answer_too(self):
        self.assertEqual(http_call("POST", "/api/config", {"alerts_enabled": False}, token=self.token)[0], 200)
        try:
            body = self.tool("list_alerts")
            self.assertTrue(body["result"]["isError"])
            self.assertTrue(body["result"]["content"][0]["text"].startswith("HTTP 404"), body)
        finally:
            http_call("POST", "/api/config", {"alerts_enabled": True}, token=self.token)

    def test_a_tool_call_is_in_the_audit_log_with_the_tool_and_what_it_was_asked(self):
        marker = "audit-marker-host"
        self.tool("get_device", {"name": marker})
        status, _, body = http_call("GET", "/api/audit-log?limit=200", token=self.token)
        self.assertEqual(status, 200)
        rows = body if isinstance(body, list) else body.get("entries") or body.get("log") or body.get("rows") or []
        text = json.dumps(rows)
        self.assertIn("mcp_http_call", text)
        self.assertIn(marker, text)
        self.assertNotIn(self.token, text)


if __name__ == "__main__":
    unittest.main()
