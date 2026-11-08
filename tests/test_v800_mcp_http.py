#!/usr/bin/env python3
"""8.0.0: the hosted, read-only MCP endpoint (POST /api/mcp).

What it must be, and how each is held:

  * Off until the `mcp` optional module is switched on: the module gate answers 404.
  * No authority of its own. Every read a tool makes runs the REAL request, as the caller, in this process, through the same gate chain and the
    same handler, so a tenant sees its own hosts and a switched-off module is a 404 here too. The tests compare what the endpoint returns with what
    the dashboard's own handler returns for the same caller, and a ratchet compares the endpoint's gate list with the _enforce_* calls in main().
  * Read-only by construction: the method of a read is always GET, a path must sit under /api/, and no write tool of the local bridge exists here.
  * The same tools as the local bridge for the ones it shares: names, descriptions and schemas are compared word for word with
    mcp/remotepower-mcp.py, so a model connected both ways reads one tool.
  * The caller's request is whole afterwards: the nested read restores the thread-local context it borrowed.

The protocol part is tested with a fake `fetch`; the server part runs the real handlers over a small seeded store.
"""
import ast
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import api  # noqa: E402  (one shared import of api.py, with RP_DATA_DIR pinned before it)

import mcp_http as M  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "mcp" / "remotepower-mcp.py"


def rpc(method, params=None, msg_id=1):
    m = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        m["id"] = msg_id
    if params is not None:
        m["params"] = params
    return m


def call_tool(name, arguments=None, msg_id=1):
    return rpc("tools/call", {"name": name, "arguments": arguments or {}}, msg_id)


class _Fetch:
    """A fake of the host's read: answers from a table and remembers every path it was asked for."""

    def __init__(self, table):
        self.table, self.paths, self.posts = table, [], []

    def __call__(self, path, method="GET", body=None):
        if method == "POST":
            self.posts.append((path, body))
            value = self.table.get("POST " + path)
            if isinstance(value, M.FetchError):
                raise value
            if value is None:
                raise M.FetchError(404, "Not found")
            return value
        self.paths.append(path)
        for key, value in self.table.items():
            if path == key or path.startswith(key + "?"):
                if isinstance(value, M.FetchError):
                    raise value
                return value
        raise M.FetchError(404, "Not found")


DEVS = [{"id": "d1", "name": "web01", "os": "linux", "online": True, "ip": "10.0.0.1", "token": "SECRETTOKEN", "sysinfo": {"packages": {"manager": "apt"}, "api_secret": "S"}},
        {"id": "d2", "name": "web02", "os": "linux", "online": False, "ip": "10.0.0.2"},
        {"id": "d3", "name": "db01", "os": "linux", "online": True, "ip": "10.0.0.3"}]


def text_of(answer):
    return answer["result"]["content"][0]["text"]


class TestTheProtocol(unittest.TestCase):

    def test_initialize_answers_with_the_clients_version_when_it_is_one_the_server_speaks(self):
        for version in M.PROTOCOL_VERSIONS:
            status, answer = M.handle(rpc("initialize", {"protocolVersion": version}), None, "8.0.0")
            self.assertEqual(status, 200)
            self.assertEqual(answer["result"]["protocolVersion"], version)
        self.assertEqual(M.handle(rpc("initialize", {"protocolVersion": "1999-01-01"}), None, "8.0.0")[1]["result"]["protocolVersion"], M.PROTOCOL_VERSIONS[0])
        self.assertEqual(M.handle(rpc("initialize"), None, "8.0.0")[1]["result"]["protocolVersion"], M.PROTOCOL_VERSIONS[0])

    def test_initialize_says_what_this_server_is(self):
        result = M.handle(rpc("initialize", {"protocolVersion": "2025-06-18"}), None, "8.0.0")[1]["result"]
        self.assertEqual(result["serverInfo"], {"name": "remotepower", "version": "8.0.0"})
        self.assertEqual(result["capabilities"], {"tools": {"listChanged": False}})
        self.assertIn("Read-only", result["instructions"])

    def test_a_notification_gets_202_and_no_answer(self):
        for method in ("notifications/initialized", "notifications/cancelled", "something/unknown"):
            self.assertEqual(M.handle(rpc(method, msg_id=None), None, "x"), (202, None), method)

    def test_what_is_not_one_json_rpc_request_is_refused_with_400(self):
        for message in ([rpc("ping")], "ping", 5, None, {"id": 1, "method": "ping"}, {"jsonrpc": "1.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 1}, {"jsonrpc": "2.0", "id": 1, "method": 5}):
            with self.subTest(repr(message)[:50]):
                status, answer = M.handle(message, None, "x")
                self.assertEqual(status, 400)
                self.assertEqual(answer["error"]["code"], M.INVALID_REQUEST)

    def test_an_id_is_a_string_or_an_integer(self):
        for bad in (True, 1.5, [1], {"a": 1}, None):
            with self.subTest(repr(bad)):
                status, answer = M.handle({"jsonrpc": "2.0", "id": bad, "method": "ping"}, None, "x")
                self.assertEqual((status, answer["error"]["code"]), (400, M.INVALID_REQUEST))
        for good in ("abc", 7, 0):
            self.assertEqual(M.handle({"jsonrpc": "2.0", "id": good, "method": "ping"}, None, "x"), (200, {"jsonrpc": "2.0", "id": good, "result": {}}))

    def test_params_must_be_an_object_and_an_unknown_method_is_not_found(self):
        status, answer = M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [1]}, None, "x")
        self.assertEqual((status, answer["error"]["code"]), (200, M.INVALID_PARAMS))
        status, answer = M.handle(rpc("resources/list"), None, "x")
        self.assertEqual((status, answer["error"]["code"]), (200, M.METHOD_NOT_FOUND))
        self.assertEqual(answer["id"], 1)

    def test_tools_list_offers_sixteen_read_tools_each_marked_read_only(self):
        tools = M.handle(rpc("tools/list"), None, "x")[1]["result"]["tools"]
        self.assertEqual(sorted(t["name"] for t in tools), sorted(["list_alerts", "get_attention", "list_devices", "get_device", "get_services", "get_containers", "get_cves", "get_patches",
                                                                   "get_journal", "get_drift", "get_recent_commands", "get_runbook", "get_tls", "get_snmp_data", "search_devices", "search_fleet"]))
        for t in tools:
            self.assertTrue(t["annotations"]["readOnlyHint"], t["name"])
            self.assertFalse(t["annotations"]["destructiveHint"], t["name"])
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertGreater(len(t["description"]), 40)


class TestTheToolsAreTheBridgesTools(unittest.TestCase):
    """The hosted endpoint shares the local bridge's read tools. The text the model reads is held equal, and no write tool is in the hosted list."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("rp_mcp_bridge", BRIDGE)
        cls.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bridge)

    def test_each_hosted_tool_is_a_bridge_tool_with_the_same_description_and_schema(self):
        self.assertGreater(len(M.TOOLS), 5)
        for name, tool in M.TOOLS.items():
            with self.subTest(name):
                self.assertIn(name, self.bridge.TOOLS)
                self.assertEqual(tool["description"], self.bridge.TOOLS[name]["description"])
                self.assertEqual(tool["inputSchema"], self.bridge.TOOLS[name]["inputSchema"])

    def test_no_write_tool_of_the_bridge_is_offered_over_http(self):
        writes = set()
        for name, tool in self.bridge.TOOLS.items():
            src = ast.get_source_segment(BRIDGE.read_text(), next(n for n in ast.walk(ast.parse(BRIDGE.read_text())) if isinstance(n, ast.FunctionDef) and n.name == tool["handler"].__name__))
            if '"POST"' in src or "'POST'" in src or '"PUT"' in src or '"DELETE"' in src or '"PATCH"' in src:
                writes.add(name)
        # search_fleet POSTs a question to the knowledge index and changes nothing: it is the one POST that is offered, through the host's own list
        # of POST paths that read (mcp_http.READ_POSTS), which the tests of the host module hold to that one path
        self.assertEqual(writes, {"reboot_device", "run_saved_script", "force_package_scan", "force_acme_rescan", "acknowledge_alert", "search_fleet"},
                         "the population of tools that use a method other than GET was derived from the bridge")
        self.assertEqual(writes & set(M.TOOLS), {"search_fleet"})

    def test_the_bridge_tools_not_offered_here_are_exactly_the_five_that_change_something(self):
        left = set(self.bridge.TOOLS) - set(M.TOOLS)
        self.assertEqual(left, {"reboot_device", "run_saved_script", "force_package_scan", "force_acme_rescan", "acknowledge_alert"})
        self.assertEqual(len(M.TOOLS), 16)


class TestTheTools(unittest.TestCase):

    def run_tool(self, name, arguments, table):
        fetch = _Fetch(table)
        status, answer = M.handle(call_tool(name, arguments), fetch, "x")
        self.assertEqual(status, 200)
        return answer, fetch

    def test_list_alerts_builds_its_query_from_checked_values_only(self):
        answer, fetch = self.run_tool("list_alerts", {"status": "ALL", "severity": "high", "limit": 9999}, {"/api/alerts": {"alerts": []}})
        self.assertEqual(fetch.paths, ["/api/alerts?status=all&severity=high&limit=200"])
        answer, fetch = self.run_tool("list_alerts", {"status": "x; rm -rf", "severity": "../..", "limit": "ten"}, {"/api/alerts": []})
        self.assertEqual(fetch.paths, ["/api/alerts?limit=50"], "an unknown status, an unknown severity and a limit that is not a number are left out")
        answer, fetch = self.run_tool("list_alerts", {}, {"/api/alerts": []})
        self.assertEqual(fetch.paths, ["/api/alerts?status=open&limit=50"])

    def test_list_alerts_trims_a_stored_alert_to_what_a_model_needs(self):
        row = {"id": "a1", "alertid": "RP1", "severity": "high", "event": "device_offline", "title": "web01 offline", "device_name": "web01", "ts": 5,
               "payload": {"huge": "x" * 5000}, "triage": {"blob": 1}, "_root_cause": True, "incident_id": "i1"}
        answer, _ = self.run_tool("list_alerts", {}, {"/api/alerts": {"alerts": [row]}})
        shown = json.loads(text_of(answer))
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0]["device"], "web01")
        self.assertTrue(shown[0]["root_cause"])
        self.assertNotIn("payload", shown[0])
        self.assertNotIn("huge", text_of(answer))

    def test_a_host_is_found_by_name_exact_then_prefix_then_substring_and_an_ambiguous_one_is_an_error_that_names_them(self):
        table = {"/api/devices": DEVS}
        for name, want in (("web01", "web01"), ("WEB01", "web01"), ("db", "db01"), ("eb01", "web01")):       # exact, exact in another case, prefix, substring
            answer, _ = self.run_tool("get_device", {"name": name}, table)
            self.assertFalse(answer["result"]["isError"], name)
            self.assertEqual(json.loads(text_of(answer))["name"], want)
        answer, _ = self.run_tool("get_device", {"name": "web"}, table)
        self.assertTrue(answer["result"]["isError"])
        self.assertIn("ambiguous", text_of(answer))
        self.assertIn("web01", text_of(answer))
        self.assertIn("web02", text_of(answer))
        answer, _ = self.run_tool("get_device", {"name": "nothing"}, table)
        self.assertEqual((answer["result"]["isError"], text_of(answer)), (True, "No host named 'nothing'"))

    def test_a_host_comes_back_without_any_key_that_names_a_credential(self):
        answer, _ = self.run_tool("get_device", {"name": "web01"}, {"/api/devices": DEVS})
        text = text_of(answer)
        self.assertNotIn("SECRETTOKEN", text)
        self.assertNotIn("api_secret", text)
        self.assertIn("web01", text)
        self.assertEqual(json.loads(text)["sysinfo"]["packages"]["manager"], "apt")

    def test_the_arguments_are_checked(self):
        table = {"/api/devices": DEVS}
        for tool in ("get_device", "get_services", "get_containers", "get_journal", "get_recent_commands", "get_runbook", "get_snmp_data"):
            for args, words in (({}, "'name' argument required"), ({"name": 5}, "'name' must be text"), ({"name": "x" * 500}, "too long")):
                with self.subTest(tool=tool, args=repr(args)[:30]):
                    answer, fetch = self.run_tool(tool, args, table)
                    self.assertTrue(answer["result"]["isError"])
                    self.assertIn(words, text_of(answer))
                    self.assertEqual(fetch.paths, [], "a refused argument reaches no read")

    def test_an_id_that_is_not_plain_never_reaches_a_path(self):
        devs = [{"id": "../../etc/passwd", "name": "evil01"}, {"id": "ok space", "name": "evil02"}, {"id": "", "name": "evil03"}]
        for name in ("evil01", "evil02", "evil03"):
            for tool in ("get_services", "get_containers", "get_cves", "get_journal", "get_recent_commands", "get_runbook", "get_drift", "get_snmp_data"):
                answer, fetch = self.run_tool(tool, {"name": name}, {"/api/devices": devs})
                self.assertTrue(answer["result"]["isError"], (tool, name))
                self.assertEqual(fetch.paths, ["/api/devices"], "only the list was read: " + tool)

    def test_get_services_and_containers_read_the_hosts_own_page_and_trim(self):
        table = {"/api/devices": DEVS, "/api/devices/d1/services": {"updated_at": 9, "services": [{"unit": "nginx", "active": "active", "sub": "running", "restarts": 0, "log": "x" * 999}]},
                 "/api/devices/d1/containers": {"items": [{"name": "app", "image": "i", "status": "Up", "sparkline": [1, 2, 3]}], "summary": {"n": 1}}}
        answer, fetch = self.run_tool("get_services", {"name": "web01"}, table)
        self.assertEqual(json.loads(text_of(answer))["services"], [{"unit": "nginx", "active": "active", "sub": "running", "restarts": 0}])
        self.assertEqual(fetch.paths, ["/api/devices", "/api/devices/d1/services"])
        answer, _ = self.run_tool("get_containers", {"name": "web01"}, table)
        self.assertEqual(json.loads(text_of(answer))["containers"], [{"name": "app", "image": "i", "status": "Up"}])

    def test_get_cves_is_fleet_wide_without_a_name_and_one_host_with_one(self):
        table = {"/api/devices": DEVS, "/api/cve/findings": {"findings": [{"id": "CVE-1"}]}, "/api/devices/d3/cves": {"findings": [{"id": "CVE-2"}]}}
        answer, fetch = self.run_tool("get_cves", {}, table)
        self.assertEqual(json.loads(text_of(answer)), {"findings": [{"id": "CVE-1"}]})
        self.assertEqual(fetch.paths, ["/api/cve/findings"])
        answer, _ = self.run_tool("get_cves", {"name": "db01"}, table)
        self.assertEqual(json.loads(text_of(answer))["findings"], [{"id": "CVE-2"}])

    def test_get_patches(self):
        report = {"devices": [{"device_id": "d1", "name": "web01", "upgradable": 4, "security_updates": 1, "patch_status": "pending", "online": True, "secret_extra": 1},
                              {"device_id": "d2", "name": "web02", "upgradable": 0}], "summary": {"hosts": 2}}
        table = {"/api/devices": DEVS, "/api/patch-report": report}
        answer, _ = self.run_tool("get_patches", {}, table)
        shown = json.loads(text_of(answer))
        self.assertEqual([r["name"] for r in shown["fleet"]], ["web01"], "only hosts with updates pending")
        self.assertNotIn("secret_extra", text_of(answer))
        answer, _ = self.run_tool("get_patches", {"name": "web01"}, table)
        self.assertEqual(json.loads(text_of(answer))["upgradable"], 4)

    def test_a_read_the_server_refuses_is_the_tools_answer_in_the_servers_words(self):
        answer, _ = self.run_tool("list_alerts", {}, {"/api/alerts": M.FetchError(403, "Forbidden for this role")})
        self.assertTrue(answer["result"]["isError"])
        self.assertEqual(text_of(answer), "HTTP 403: Forbidden for this role")

    def test_an_unknown_tool_and_arguments_that_are_not_an_object_are_protocol_errors(self):
        for name in ("reboot_device", "acknowledge_alert", "nothing", "", None, 5, ["list_alerts"]):
            status, answer = M.handle(call_tool(name), _Fetch({}), "x")
            self.assertEqual((status, answer["error"]["code"]), (200, M.INVALID_PARAMS), repr(name))
        status, answer = M.handle(rpc("tools/call", {"name": "list_alerts", "arguments": "all"}), _Fetch({}), "x")
        self.assertEqual(answer["error"]["code"], M.INVALID_PARAMS)
        status, answer = M.handle(rpc("tools/call", {"name": "list_alerts", "arguments": None}), _Fetch({"/api/alerts": []}), "x")
        self.assertFalse(answer["result"]["isError"])

    def test_every_read_any_tool_makes_is_a_path_under_api_without_spaces(self):
        fetch = _Fetch({"/api/devices": DEVS, "/api/alerts": [], "/api/attention": [], "/api/patch-report": {}, "/api/cve/findings": {}})
        for name in M.TOOLS:
            M.handle(call_tool(name, {"name": "web01"}), fetch, "x")
        self.assertGreater(len(fetch.paths), 8)
        for path in fetch.paths:
            self.assertTrue(path.startswith("/api/"), path)
            self.assertFalse(any(c.isspace() for c in path), path)
            self.assertNotIn("..", path)

    def test_an_answer_over_the_budget_is_cut_from_the_end_and_stays_valid_json(self):
        rows = [{"name": "h%04d" % i, "os": "linux", "ip": "10.0.%d.%d" % (i // 250, i % 250), "tags": ["x" * 40] * 5} for i in range(3000)]
        answer, _ = self.run_tool("list_devices", {}, {"/api/devices": rows})
        text = text_of(answer)
        self.assertLessEqual(len(text), M.MAX_RESULT_CHARS)
        shown = json.loads(text)
        self.assertTrue(shown["truncated"], "200 rows of this size do not fit")
        self.assertEqual(shown["total"], M.MAX_ROWS, "the tool's own cap came first")
        self.assertEqual(len(shown["items"]), shown["shown"])
        self.assertGreater(shown["shown"], 0)
        big = M._fit({"device": "x", "services": [{"unit": "u" * 600} for _ in range(400)]})
        wrapped = json.loads(big)
        self.assertLessEqual(len(big), M.MAX_RESULT_CHARS)
        self.assertTrue(wrapped["truncated"])
        self.assertEqual(wrapped["total"], 400)
        self.assertEqual(len(wrapped["services"]), wrapped["shown"])
        self.assertEqual(wrapped["device"], "x")
        self.assertTrue(json.loads(M._fit({"blob": "y" * (M.MAX_RESULT_CHARS + 10)}))["truncated"])


class TestTheEightMoreTools(unittest.TestCase):
    """The tools of the bridge that read and were left for later: each one's shape, its trimming, and that what a model is shown is masked."""

    def run_tool(self, name, arguments, table):
        fetch = _Fetch(table)
        status, answer = M.handle(call_tool(name, arguments), fetch, "x")
        self.assertEqual(status, 200)
        return answer, fetch

    def test_get_journal_gives_the_newest_lines_cuts_a_long_one_and_masks_credentials(self):
        journal = ["line %d" % i for i in range(50)] + ["app: login password=hunter2 ok", 'curl -H "Authorization: Bearer ' + 'abcdef123' + '" https://x', "z" * 900]
        table = {"/api/devices": DEVS, "/api/devices/d1/sysinfo": {"journal": journal}}
        answer, fetch = self.run_tool("get_journal", {"name": "web01"}, table)
        shown = json.loads(text_of(answer))
        self.assertEqual(fetch.paths, ["/api/devices", "/api/devices/d1/sysinfo"])
        self.assertEqual(len(shown["journal"]), 30, "the bridge's default")
        self.assertEqual(shown["journal"][0], "line 23")
        self.assertEqual(len(shown["journal"][-1]), 400, "a line is cut at 400 characters")
        text = text_of(answer)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abcdef123", text)
        self.assertIn("password=***", text)
        self.assertIn("Bearer ***", text)
        answer, _ = self.run_tool("get_journal", {"name": "web01", "limit": 3}, table)
        self.assertEqual(len(json.loads(text_of(answer))["journal"]), 3)
        answer, _ = self.run_tool("get_journal", {"name": "web01", "limit": 0}, table)
        self.assertEqual(len(json.loads(text_of(answer))["journal"]), 1, "a limit of 0 is one line here; the bridge's journal[-0:] returned all of them")

    def test_get_drift_is_a_fleet_overview_without_a_name_and_one_host_with_one(self):
        table = {"/api/devices": DEVS, "/api/drift": {"devices": [{"name": "web01", "drifted": 1}], "api_token": "T"}, "/api/devices/d3/drift": {"files": ["/etc/ssh/sshd_config"], "secret": "S"}}
        answer, fetch = self.run_tool("get_drift", {}, table)
        self.assertEqual(fetch.paths, ["/api/drift"])
        self.assertEqual(json.loads(text_of(answer)), {"devices": [{"name": "web01", "drifted": 1}]})
        answer, _ = self.run_tool("get_drift", {"name": "db01"}, table)
        self.assertEqual(json.loads(text_of(answer)), {"files": ["/etc/ssh/sshd_config"]})
        answer, _ = self.run_tool("get_drift", {}, {"/api/drift": None})
        self.assertEqual(json.loads(text_of(answer)), {"devices": []})

    def test_get_recent_commands_keeps_the_newest_trims_and_masks(self):
        outputs = [{"ts": i, "cmd": "cmd%d" % i, "rc": 0, "output": "out%d" % i, "actor": "alice", "token": "T"} for i in range(15)]
        outputs[-1].update(cmd="deploy --token s3cr3t " + "c" * 600, output="DB_PASSWORD=hunter2\n" + "o" * 3000)
        answer, fetch = self.run_tool("get_recent_commands", {"name": "web01"}, {"/api/devices": DEVS, "/api/devices/d1/output": {"outputs": outputs}})
        shown = json.loads(text_of(answer))["commands"]
        self.assertEqual(fetch.paths[-1], "/api/devices/d1/output")
        self.assertEqual([c["ts"] for c in shown], list(range(5, 15)), "the last ten, oldest first")
        self.assertEqual(set(shown[0]), {"ts", "cmd", "rc", "output"})
        self.assertLessEqual(len(shown[-1]["cmd"]), 500)
        self.assertLessEqual(len(shown[-1]["output"]), 2000)
        self.assertNotIn("s3cr3t", text_of(answer))
        self.assertNotIn("hunter2", text_of(answer))
        self.assertIn("--token ***", shown[-1]["cmd"])

    def test_runbook_tls_and_snmp_come_back_without_a_credential(self):
        table = {"/api/devices": DEVS, "/api/devices/d1/runbook": {"exists": True, "text": "purpose", "api_key": "K"},
                 "/api/tls/targets": {"targets": [{"host": "a.example", "days": 12, "secret": "S"}]},
                 "/api/devices/d3/snmp": {"config": {"enabled": True, "community_preview": "pub…", "has_community": True, "has_v3_auth_secret": True, "version": "2c"},
                                          "data": {"sysName": "sw1"}}}
        answer, _ = self.run_tool("get_runbook", {"name": "web01"}, table)
        self.assertEqual(json.loads(text_of(answer)), {"exists": True, "text": "purpose"})
        answer, fetch = self.run_tool("get_tls", {}, table)
        self.assertEqual(fetch.paths, ["/api/tls/targets"])
        self.assertEqual(json.loads(text_of(answer)), {"targets": [{"host": "a.example", "days": 12}]})
        answer, _ = self.run_tool("get_snmp_data", {"name": "db01"}, table)
        shown = json.loads(text_of(answer))
        self.assertEqual(shown["data"], {"sysName": "sw1"})
        self.assertEqual(shown["config"], {"enabled": True, "version": "2c"}, "not even the first letters of a community string")
        answer, _ = self.run_tool("get_tls", {}, {"/api/tls/targets": None})
        self.assertEqual(json.loads(text_of(answer)), {"targets": []})

    def test_get_snmp_data_finds_a_host_by_name_id_or_one_substring_and_says_when_it_cannot(self):
        table = {"/api/devices": DEVS, "/api/devices/d1/snmp": {"config": {}}, "/api/devices/d2/snmp": {"config": {"enabled": False}}, "/api/devices/d3/snmp": {"config": {"enabled": True}}}
        for args, path in (({"name": "web01"}, "/api/devices/d1/snmp"), ({"name": "d2"}, "/api/devices/d2/snmp"), ({"device": "db01"}, "/api/devices/d3/snmp"), ({"name": "db0"}, "/api/devices/d3/snmp")):
            answer, fetch = self.run_tool("get_snmp_data", args, table)
            self.assertEqual(fetch.paths[-1], path, args)
        for args in ({"name": "web"}, {"name": "nothing"}):                  # two hosts contain it; none does
            answer, fetch = self.run_tool("get_snmp_data", args, table)
            self.assertEqual(json.loads(text_of(answer)), {"ok": False, "error": 'No host matching "%s"' % args["name"]})
            self.assertFalse(answer["result"]["isError"], "the bridge answers this as data, not as a failure")
            self.assertEqual(fetch.paths, ["/api/devices"])

    def test_search_devices_matches_the_fields_the_bridge_matches_and_counts_past_the_cap(self):
        devs = [{"id": "a", "name": "alpha", "os": "Debian", "group": "prod", "ip": "10.1.1.1", "hostname": "alpha.lan", "tags": ["rack7"], "notes": "owner: sam", "token": "T"},
                {"id": "b", "name": "bravo", "os": "Alpine", "group": "lab", "ip": "10.2.2.2", "tags": [], "notes": ""}]
        for q, names in (("ALPHA", ["alpha"]), ("debian", ["alpha"]), ("prod", ["alpha"]), ("10.2.", ["bravo"]), ("rack7", ["alpha"]), ("sam", ["alpha"]), ("alpha.lan", ["alpha"]), ("al", ["alpha", "bravo"]), ("zzz", [])):
            answer, _ = self.run_tool("search_devices", {"query": q}, {"/api/devices": devs})
            shown = json.loads(text_of(answer))
            self.assertEqual([m["name"] for m in shown["matches"]], names, q)
            self.assertEqual(shown["count"], len(names))
        answer, _ = self.run_tool("search_devices", {"query": "T"}, {"/api/devices": devs})
        self.assertNotIn("token", text_of(answer), "the token key of a host is not something a search returns")
        many = [{"id": "h%d" % i, "name": "host%03d" % i} for i in range(250)]
        shown = json.loads(text_of(self.run_tool("search_devices", {"query": "host"}, {"/api/devices": many})[0]))
        self.assertEqual((len(shown["matches"]), shown["count"]), (M.MAX_ROWS, 250))
        answer, _ = self.run_tool("search_devices", {}, {"/api/devices": devs})
        self.assertIn("'query' argument required", text_of(answer))

    def test_search_fleet_posts_one_question_to_the_index_and_nothing_else(self):
        reply = {"ok": True, "semantic": True, "results": [{"id": "c%d" % i, "excerpt": "e"} for i in range(40)], "debug": "x"}
        answer, fetch = self.run_tool("search_fleet", {"query": "worst cves in the fleet"}, {"POST /api/ai/rag/search": reply})
        self.assertEqual(fetch.posts, [("/api/ai/rag/search", {"query": "worst cves in the fleet"})])
        self.assertEqual(fetch.paths, [], "no GET")
        shown = json.loads(text_of(answer))
        self.assertEqual(set(shown), {"query", "semantic", "results"})
        self.assertTrue(shown["semantic"])
        self.assertEqual(len(shown["results"]), 30, "the index's own ceiling")
        answer, fetch = self.run_tool("search_fleet", {"query": "q", "top_n": 5}, {"POST /api/ai/rag/search": {"results": []}})
        self.assertEqual(fetch.posts[0][1], {"query": "q", "top_n": 5})
        for bad in (True, "5", 5.5, None, [5]):
            answer, fetch = self.run_tool("search_fleet", {"query": "q", "top_n": bad}, {"POST /api/ai/rag/search": {"results": []}})
            self.assertEqual(fetch.posts[0][1], {"query": "q"}, "a top_n that is not an integer is left to the server's default: %r" % (bad,))
        for args, words in (({}, "'query' argument required"), ({"query": 5}, "'query' must be text"), ({"query": "x" * 500}, "too long")):
            answer, fetch = self.run_tool("search_fleet", args, {})
            self.assertIn(words, text_of(answer))
            self.assertEqual(fetch.posts, [], "a refused argument reaches no read")
        answer, _ = self.run_tool("search_fleet", {"query": "q"}, {"POST /api/ai/rag/search": M.FetchError(403, "RAG search is limited to full-access roles")})
        self.assertEqual((answer["result"]["isError"], text_of(answer)), (True, "HTTP 403: RAG search is limited to full-access roles"))

    def test_the_only_post_any_tool_makes_is_the_one_on_the_list(self):
        fetch = _Fetch({"/api/devices": DEVS, "POST /api/ai/rag/search": {"results": []}})
        for name in M.TOOLS:
            M.handle(call_tool(name, {"name": "web01", "query": "x"}), fetch, "x")
        self.assertEqual({path for path, _ in fetch.posts}, set(M.READ_POSTS))
        self.assertEqual(M.READ_POSTS, ("/api/ai/rag/search",))


# ── the server part ────────────────────────────────────────────────────────────────────────────────────────────────────────
def _context(env, body=b""):
    return {"environ": env, "stdin": body, "out": io.BytesIO()}


class _OutProxy:
    """What wsgi.py puts in place of sys.stdout: a write goes to the buffer of the request that is running on this thread (api._RCTX.out_text and
    .out), and to the real stdout when there is none. The nested read depends on it, because a response is printed. wsgi.py binds it to its own
    import of api.py, which is not the instance these tests load, so the test installs the same thing for its own."""

    def __init__(self, real):
        self.real = real

    def write(self, s):
        target = getattr(api._RCTX, "out_text", None)
        return (target if target is not None else self.real).write(s)

    def flush(self):
        target = getattr(api._RCTX, "out_text", None)
        (target if target is not None else self.real).flush()

    @property
    def buffer(self):
        return getattr(api._RCTX, "out", None) or self.real.buffer

    def __getattr__(self, name):
        return getattr(self.real, name)


_KEEP_STDOUT = []


def setUpModule():
    _KEEP_STDOUT.append(sys.stdout)
    sys.stdout = _OutProxy(sys.stdout)


def tearDownModule():
    sys.stdout = _KEEP_STDOUT.pop()


class _Served(unittest.TestCase):
    """handle_mcp() as it is served: the thread-local context of a request, the real auth and gate chain, only verify_token replaced."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {"mcp_module_enabled": True, "tenancy_enforced": True})
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": 1}, "tenantB": {"name": "B", "status": "active", "created": 1}})
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1},
                                  "tadmin": {"role": "admin", "tenant_id": "tenantA", "password_hash": "x", "created": 1},
                                  "tviewer": {"role": "viewer", "tenant_id": "tenantA", "password_hash": "x", "created": 1}})
        api.save(api.DEVICES_FILE, {
            "hostA": {"id": "hostA", "name": "alpha01", "tenant": "tenantA", "token": "ta", "last_seen": 0, "sysinfo": {}},
            "hostB": {"id": "hostB", "name": "bravo01", "tenant": "tenantB", "token": "tb", "last_seen": 0, "sysinfo": {}}})
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "event": "device_offline", "severity": "high", "device_id": "hostA", "device_name": "alpha01", "title": "alpha01 offline", "ts": 5, "resolved_at": None},
            {"id": "a2", "event": "device_offline", "severity": "high", "device_id": "hostB", "device_name": "bravo01", "title": "bravo01 offline", "ts": 6, "resolved_at": None}]})
        api._LOAD_CACHE.clear()
        self.audit = []

    def serve(self, message, user="alice", token="good", verb="POST", raw=None, extra_env=None, path="/api/mcp"):
        """Returns (status, body, headers). The nested reads and the outer answer both go through the real functions."""
        body = raw if raw is not None else json.dumps(message).encode()
        env = {"REQUEST_METHOD": verb, "PATH_INFO": path, "QUERY_STRING": "", "CONTENT_LENGTH": str(len(body)), "REMOTE_ADDR": "127.0.0.1", "HTTP_HOST": "rp.test",
               "HTTP_ORIGIN": "https://evil.example", "HTTP_ACCEPT_ENCODING": "gzip", "HTTP_IF_NONE_MATCH": "x"}
        if token:
            env["HTTP_AUTHORIZATION"] = "Bearer " + token
        env.update(extra_env or {})
        names = ("verify_token", "audit_log")
        saved = {n: getattr(api, n) for n in names}
        role = (api.load(api.USERS_FILE) or {}).get(user, {}).get("role", "viewer")
        api.verify_token = lambda t: (user, role) if t == "good" else (None, None)
        api.audit_log = lambda *a, **k: self.audit.append(a)
        ctx = api._RCTX
        keep = {a: getattr(ctx, a, None) for a in ("environ", "stdin", "out", "out_text")}
        self.outer = _context(env, body)
        ctx.environ, ctx.stdin, ctx.out, ctx.out_text = self.outer["environ"], self.outer["stdin"], self.outer["out"], None
        try:
            try:
                api.handle_mcp()
                result = (None, None, [])
            except api.HTTPError as e:
                result = (e.status, e.body, e.headers)
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
            self.after = {a: getattr(ctx, a, None) for a in ("environ", "stdin", "out", "out_text")}
            for a, v in keep.items():
                setattr(ctx, a, v)
            api._LOAD_CACHE.clear()
        return result

    def tool(self, name, arguments=None, **kw):
        status, body, _ = self.serve(call_tool(name, arguments), **kw)
        self.assertEqual(status, 200, body)
        return body


class TestWhoMayAsk(_Served):

    def test_it_is_off_until_the_module_is_switched_on(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        with self.assertRaises(api.HTTPError) as c:
            api._enforce_module_gate("/api/mcp")
        self.assertEqual(c.exception.status, 404)
        api.save(api.CONFIG_FILE, {"mcp_module_enabled": True})
        api._LOAD_CACHE.clear()
        api._enforce_module_gate("/api/mcp")                               # no refusal

    def test_the_module_is_in_the_registry_with_the_prefix_and_off_by_default(self):
        key, default, prefixes = api._MODULES["mcp"]
        self.assertEqual((key, default, prefixes), ("mcp_module_enabled", False, ("/api/mcp",)))

    def test_a_caller_without_a_token_or_with_a_bad_one_gets_401_and_a_bearer_challenge(self):
        for token in (None, "wrong"):
            status, body, headers = self.serve(rpc("ping"), token=token)
            self.assertEqual(status, 401, token)
            self.assertIn(("WWW-Authenticate", 'Bearer realm="RemotePower"'), headers)

    def test_a_get_and_a_delete_get_405_and_say_which_method_it_takes(self):
        for verb in ("GET", "DELETE", "PUT"):
            status, body, headers = self.serve(rpc("ping"), verb=verb)
            self.assertEqual(status, 405, verb)
            self.assertIn(("Allow", "POST"), headers)

    def test_the_token_may_come_as_x_token_too(self):
        status, body, _ = self.serve(rpc("ping"), token=None, extra_env={"HTTP_X_TOKEN": "good"})
        self.assertEqual((status, body["result"]), (200, {}))

    def test_a_viewer_and_a_tenant_administrator_may_ask_with_their_own_rights(self):
        for user in ("tviewer", "tadmin", "alice"):
            status, body, _ = self.serve(rpc("ping"), user=user)
            self.assertEqual((status, body["result"]), (200, {}), user)


class TestWhatIsReadIsWhatTheCallerMayRead(_Served):

    def names(self, user):
        return sorted(h["name"] for h in json.loads(text_of(self.tool("list_devices", user=user))))

    def test_a_tenant_sees_its_own_hosts_as_the_dashboard_lists_them(self):
        self.assertEqual(self.names("alice"), ["alpha01", "bravo01"], "the platform operator sees both")
        self.assertEqual(self.names("tadmin"), ["alpha01"])
        self.assertEqual(self.names("tviewer"), ["alpha01"])

    def test_it_is_what_the_dashboards_own_handler_answers_for_the_same_caller(self):
        for user in ("alice", "tadmin", "tviewer"):
            with self.subTest(user):
                api._LOAD_CACHE.clear()
                box = {}
                names = ("verify_token", "get_token_from_request", "method")
                saved = {n: getattr(api, n) for n in names}
                role = api.load(api.USERS_FILE)[user]["role"]
                api.verify_token = lambda t: (user, role)
                api.get_token_from_request = lambda: "good"
                api.method = lambda: "GET"
                ctx = api._RCTX
                keep = {a: getattr(ctx, a, None) for a in ("environ", "stdin", "out")}
                ctx.environ, ctx.stdin, ctx.out = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/devices", "REMOTE_ADDR": "127.0.0.1"}, b"", io.BytesIO()
                try:
                    try:
                        api.handle_devices_list()
                    except api.HTTPError as e:
                        box["body"] = e.body
                finally:
                    for n, v in saved.items():
                        setattr(api, n, v)
                    for a, v in keep.items():
                        setattr(ctx, a, v)
                body = box["body"]
                direct = sorted(d["name"] for d in (body if isinstance(body, list) else body.get("devices", [])))
                self.assertEqual(self.names(user), direct)

    def test_another_tenants_host_cannot_be_read_by_name(self):
        for tool in ("get_device", "get_services", "get_containers", "get_cves"):
            body = self.tool(tool, {"name": "bravo01"}, user="tadmin")
            self.assertTrue(body["result"]["isError"], tool)
            self.assertEqual(text_of(body), "No host named 'bravo01'")
        self.assertFalse(self.tool("get_device", {"name": "bravo01"}, user="alice")["result"]["isError"])
        self.assertIn("bravo01", text_of(self.tool("get_device", {"name": "bravo"}, user="alice")))
        self.assertTrue(self.tool("get_device", {"name": "brav"}, user="tadmin")["result"]["isError"], "a prefix does not find it either")

    def test_the_alerts_of_another_tenant_are_not_listed(self):
        mine = json.loads(text_of(self.tool("list_alerts", user="tadmin")))
        self.assertEqual([a["device"] for a in mine], ["alpha01"])
        both = json.loads(text_of(self.tool("list_alerts", user="alice")))
        self.assertEqual(sorted(a["device"] for a in both), ["alpha01", "bravo01"])

    def test_a_module_that_is_switched_off_is_a_404_here_too(self):
        api.save(api.CONFIG_FILE, {"mcp_module_enabled": True, "alerts_enabled": False})
        api._LOAD_CACHE.clear()
        body = self.tool("list_alerts")
        self.assertTrue(body["result"]["isError"])
        self.assertTrue(text_of(body).startswith("HTTP 404"), text_of(body))
        self.assertFalse(self.tool("list_devices")["result"]["isError"], "the other tools go on")

    def test_a_refusal_of_the_real_handler_is_the_answer(self):
        # the attention digest is not for a caller whose role the real handler turns away; here the handler is replaced by one that refuses
        saved = api._dispatch

        def refuse(pi, m):
            api.respond(403, {"error": "Not for your role"})
        api._dispatch = refuse
        try:
            body = self.tool("get_attention", user="tviewer")
        finally:
            api._dispatch = saved
        self.assertEqual(text_of(body), "HTTP 403: Not for your role")


class TestAReadIsAlwaysAGetUnderApi(_Served):

    def test_the_method_is_get_whatever_the_outer_request_was_and_nothing_of_the_outer_body_or_headers_goes_along(self):
        seen = []
        saved = api._dispatch

        def spy(pi, m):
            seen.append((pi, m, api.method(), api._env("QUERY_STRING"), api._env("HTTP_ORIGIN"), api._env("HTTP_ACCEPT_ENCODING"), api._env("HTTP_IF_NONE_MATCH"),
                         api._env("CONTENT_LENGTH"), api._RCTX.stdin, api._env("HTTP_AUTHORIZATION"), api._env("REMOTE_ADDR")))
            api.respond(200, {"alerts": []})
        api._dispatch = spy
        try:
            self.tool("list_alerts", {"status": "all"})
        finally:
            api._dispatch = saved
        self.assertEqual(len(seen), 1)
        pi, m, meth, query, origin, enc, inm, clen, stdin, auth, addr = seen[0]
        self.assertEqual((pi, m, meth), ("/api/alerts", "GET", "GET"))
        self.assertEqual(query, "status=all&limit=50")
        self.assertEqual((origin, enc, inm, clen, stdin), (None, None, None, "0", b""))
        self.assertEqual((auth, addr), ("Bearer good", "127.0.0.1"), "the caller's token and address stay as they arrived")

    def test_a_path_that_is_not_a_plain_path_under_api_is_refused_before_anything_runs(self):
        ran = []
        saved = api._dispatch
        api._dispatch = lambda pi, m: ran.append(pi)
        try:
            for path in ("/etc/passwd", "api/devices", "/api", "/apix/devices", "/api/../etc/passwd", "/api//devices", "/api/devices x", "/api/devices\n/api/x",
                         "/api/devices\x00", "/api/" + "a" * 500, 5, None):
                with self.subTest(repr(path)[:40]):
                    with self.assertRaises(M.FetchError) as c:
                        api._mcp_get(path)
                    self.assertEqual(c.exception.status, 400)
        finally:
            api._dispatch = saved
        self.assertEqual(ran, [])

    def test_the_gates_of_the_chain_all_run_for_a_read(self):
        order = []
        gates = ("_enforce_read_only", "_enforce_same_origin", "_enforce_ip_allowlist", "_enforce_password_change", "_enforce_mfa_enrollment", "_enforce_device_scope",
                 "_enforce_module_gate", "_enforce_platform_routes", "_enforce_operator_org_routes")
        saved = {g: getattr(api, g) for g in gates}
        saved_dispatch = api._dispatch
        for g in gates:
            setattr(api, g, (lambda name: lambda *a: order.append(name))(g))
        api._dispatch = lambda pi, m: api.respond(200, {})
        try:
            api._mcp_get("/api/devices")
        finally:
            for g, f in saved.items():
                setattr(api, g, f)
            api._dispatch = saved_dispatch
        self.assertEqual(order, list(gates), "every gate, in main()'s order")

    def test_the_gate_list_is_the_enforce_calls_of_main(self):
        """A gate added to main() and not to the chain would let a read skip it. Population: every _enforce_* call in main()'s own body."""
        tree = ast.parse((ROOT / "server" / "cgi-bin" / "api.py").read_text())

        def enforce_calls(fn):
            return [n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id.startswith("_enforce_")]
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        in_main = enforce_calls(main)
        handlers = ast.parse((ROOT / "server" / "cgi-bin" / "mcp_http_handlers.py").read_text())
        chain_fn = next(n for n in handlers.body if isinstance(n, ast.FunctionDef) and n.name == "_mcp_gates")
        chain = [n.func.attr for n in ast.walk(chain_fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith("_enforce_")]
        self.assertGreaterEqual(len(in_main), 8, "the population is not empty")
        self.assertEqual(chain, in_main, "the chain a read passes is the chain main() runs, in the same order")

    def test_the_outer_request_is_whole_afterwards(self):
        self.tool("list_devices")
        for a in ("environ", "stdin", "out"):
            self.assertIs(self.after[a], self.outer[a] if a != "stdin" else self.outer["stdin"], a)
        self.assertEqual(self.outer["out"].getvalue(), b"", "the nested read wrote nothing into the outer response")
        self.assertEqual(self.outer["environ"]["REQUEST_METHOD"], "POST", "the borrowed environment was a copy")
        self.assertEqual(self.outer["environ"]["PATH_INFO"], "/api/mcp")


class _FakeIndex:
    """The knowledge index, as the search handler uses it, answering one chunk and remembering what it was asked."""

    def __init__(self):
        self.asked = []

    def has_embeddings(self):
        return False

    def search(self, query, top_n=8, query_vec=None):
        self.asked.append((query, top_n, query_vec))
        return [{"id": "c1", "title": "T", "source": "cve", "type": "rollup", "device": "alpha01", "ts": 5, "text": "excerpt body"}]


class TestAReadThatNeedsABody(_Served):
    """search_fleet asks the knowledge index a question, which the REST API takes in a POST body. It is the one POST a tool may make: it only reads,
    the host allows it by path, and it is the caller's own request through the same gates, so the handler's own refusals are the answer."""

    def setUp(self):
        super().setUp()
        self.index = _FakeIndex()
        self.saved_ai = {n: getattr(api, n) for n in ("_ai_cfg", "_rag_get_index", "_rag_embeddings_active", "_is_demo_read_only")}
        api._ai_cfg = lambda: {"rag": {"enabled": True, "max_chunks": 8}}
        api._rag_get_index = lambda cfg: self.index
        api._rag_embeddings_active = lambda cfg: False

    def tearDown(self):
        for n, v in self.saved_ai.items():
            setattr(api, n, v)

    def test_the_search_runs_the_real_handler_as_the_caller_and_the_index_gets_the_question(self):
        answer = self.tool("search_fleet", {"query": "which hosts need a reboot", "top_n": 3})
        self.assertFalse(answer["result"]["isError"], text_of(answer))
        shown = json.loads(text_of(answer))
        self.assertEqual(shown["query"], "which hosts need a reboot")
        self.assertFalse(shown["semantic"])
        self.assertEqual([(r["id"], r["device"], r["excerpt"]) for r in shown["results"]], [("c1", "alpha01", "excerpt body")])
        self.assertEqual(self.index.asked, [("which hosts need a reboot", 3, None)])
        self.tool("search_fleet", {"query": "q"})
        self.assertEqual(self.index.asked[-1][1], 8, "without top_n the handler uses its configured default")

    def test_a_tenant_caller_is_refused_before_the_handler_by_the_gate_that_keeps_the_installation_to_its_operator(self):
        for user in ("tadmin", "tviewer"):
            answer = self.tool("search_fleet", {"query": "everything"}, user=user)
            self.assertTrue(answer["result"]["isError"], user)
            self.assertEqual(text_of(answer), "HTTP 403: This belongs to the whole installation and is managed by the platform operator.")
        self.assertEqual(self.index.asked, [], "the knowledge index is not scoped per tenant, so it was never read for them")

    def test_a_caller_whose_key_is_scoped_to_some_hosts_is_refused_by_the_handlers_own_rule(self):
        api._RCTX.key_scope = {"type": "group", "value": "g"}
        try:
            answer = self.tool("search_fleet", {"query": "everything"}, user="alice")
        finally:
            api._RCTX.key_scope = None
        self.assertTrue(answer["result"]["isError"])
        self.assertEqual(text_of(answer), "HTTP 403: RAG search is limited to full-access roles \u2014 the knowledge index is not scoped per role or tenant.")
        self.assertEqual(self.index.asked, [], "the index holds every host, so a caller who may see some of them is not answered from it")
        answer = self.tool("search_fleet", {"query": "everything"}, user="alice")
        self.assertFalse(answer["result"]["isError"], "control: the same caller without the scope is answered")

    def test_rag_that_is_switched_off_is_the_handlers_own_400(self):
        api._ai_cfg = lambda: {"rag": {"enabled": False}}
        answer = self.tool("search_fleet", {"query": "q"})
        self.assertEqual((answer["result"]["isError"], text_of(answer)), (True, "HTTP 400: RAG is disabled. Enable it in Settings \u2192 AI assistant."))
        self.assertEqual(self.index.asked, [])

    def test_the_post_is_the_callers_own_with_the_body_and_nothing_of_the_outer_request(self):
        seen = []
        saved = api._dispatch

        def spy(pi, m):
            seen.append((pi, m, api.method(), api._env("CONTENT_TYPE"), api._env("CONTENT_LENGTH"), api._RCTX.stdin, api._env("HTTP_AUTHORIZATION"),
                         api._env("HTTP_ORIGIN"), api._env("HTTP_ACCEPT_ENCODING"), api._env("REMOTE_ADDR"), api._env("QUERY_STRING")))
            api.respond(200, {"ok": True, "results": []})
        api._dispatch = spy
        try:
            self.tool("search_fleet", {"query": "hello", "top_n": 3})
        finally:
            api._dispatch = saved
        self.assertEqual(len(seen), 1)
        pi, m, meth, ctype, clen, stdin, auth, origin, enc, addr, query = seen[0]
        self.assertEqual((pi, m, meth, query), ("/api/ai/rag/search", "POST", "POST", ""))
        self.assertEqual(json.loads(stdin), {"query": "hello", "top_n": 3})
        self.assertEqual((ctype, clen), ("application/json", str(len(stdin))))
        self.assertEqual((auth, addr), ("Bearer good", "127.0.0.1"), "the caller's token and address stay as they arrived")
        self.assertEqual((origin, enc), (None, None))
        for a in ("environ", "stdin", "out"):
            self.assertIs(self.after[a], self.outer[a], a)
        self.assertEqual(self.outer["environ"]["PATH_INFO"], "/api/mcp", "the borrowed environment was a copy")

    def test_only_the_listed_path_can_be_read_with_a_post_and_only_with_a_small_object_and_only_by_get_or_post(self):
        ran = []
        saved = api._dispatch
        api._dispatch = lambda pi, m: ran.append((pi, m))
        try:
            cases = [("/api/devices", "POST", {}), ("/api/mcp", "POST", {}), ("/api/devices/hostA/exec", "POST", {"cmd": "id"}), ("/api/ai/rag/search?x=1", "POST", {"query": "q"}),
                     ("/api/ai/rag/search/", "POST", {"query": "q"}), ("/api/ai/rag/search", "POST", ["q"]), ("/api/ai/rag/search", "POST", "q"), ("/api/ai/rag/search", "POST", None),
                     ("/api/ai/rag/search", "POST", {"query": "x" * 5000}), ("/api/ai/rag/search", "PUT", {"query": "q"}), ("/api/ai/rag/search", "DELETE", {}),
                     ("/api/ai/rag/search", "get", {}), ("/api/devices", "PATCH", {})]
            for path, method, body in cases:
                with self.subTest(path=path, method=method, body=repr(body)[:20]):
                    with self.assertRaises(M.FetchError) as c:
                        api._mcp_get(path, method, body)
                    self.assertEqual(c.exception.status, 400)
        finally:
            api._dispatch = saved
        self.assertEqual(ran, [], "nothing ran for any of them")

    def test_the_gates_of_the_chain_run_for_the_post_too_and_see_it_as_a_post(self):
        order, methods = [], []
        gates = ("_enforce_read_only", "_enforce_same_origin", "_enforce_ip_allowlist", "_enforce_password_change", "_enforce_mfa_enrollment", "_enforce_device_scope",
                 "_enforce_module_gate", "_enforce_platform_routes", "_enforce_operator_org_routes")
        saved = {g: getattr(api, g) for g in gates}
        saved_dispatch = api._dispatch
        for g in gates:
            setattr(api, g, (lambda name: lambda *a: (order.append(name), methods.append(a[1] if len(a) > 1 else None)))(g))
        api._dispatch = lambda pi, m: api.respond(200, {})
        try:
            api._mcp_get("/api/ai/rag/search", "POST", {"query": "q"})
        finally:
            for g, f in saved.items():
                setattr(api, g, f)
            api._dispatch = saved_dispatch
        self.assertEqual(order, list(gates))
        self.assertEqual([m for m in methods if m is not None], ["POST"], "_enforce_platform_routes is told the method")

    def test_a_demo_server_refuses_the_post_by_the_same_gate_as_any_other_write(self):
        api._is_demo_read_only = lambda: True
        answer = self.tool("search_fleet", {"query": "q"})
        self.assertTrue(answer["result"]["isError"])
        self.assertIn("HTTP 403", text_of(answer))
        self.assertIn("read-only sandbox", text_of(answer))
        self.assertEqual(self.index.asked, [])


class TestTheEnvelope(_Served):

    def test_a_cross_origin_post_is_refused_by_the_gate_main_runs_before_the_handler(self):
        # handle_mcp does not repeat it: main() runs _enforce_same_origin for every POST, and an MCP client sends no Origin
        with self.assertRaises(api.HTTPError) as c:
            saved = api._RCTX.environ
            api._RCTX.environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/api/mcp", "HTTP_ORIGIN": "https://evil.example", "HTTP_HOST": "rp.test"}
            try:
                api._enforce_same_origin()
            finally:
                api._RCTX.environ = saved
        self.assertEqual(c.exception.status, 403)

    def test_a_body_that_is_not_json_or_is_empty_is_400_with_a_parse_error(self):
        for raw in (b"{not json", b"", b"   "):
            status, body, _ = self.serve(None, raw=raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(body["error"]["code"], M.PARSE_ERROR)
            self.assertIsNone(body["id"])

    def test_a_batch_is_refused_with_400(self):
        status, body, _ = self.serve([rpc("ping"), rpc("ping", msg_id=2)])
        self.assertEqual((status, body["error"]["code"]), (400, M.INVALID_REQUEST))

    def test_a_body_over_the_limit_is_413(self):
        status, body, _ = self.serve(None, raw=b"{}", extra_env={"CONTENT_LENGTH": str(api.MAX_BODY_BYTES + 1)})
        self.assertEqual(status, 413)

    def test_a_protocol_version_the_server_does_not_speak_is_400(self):
        status, body, _ = self.serve(rpc("ping"), extra_env={"HTTP_MCP_PROTOCOL_VERSION": "1999-01-01"})
        self.assertEqual(status, 400)
        for version in M.PROTOCOL_VERSIONS:
            self.assertEqual(self.serve(rpc("ping"), extra_env={"HTTP_MCP_PROTOCOL_VERSION": version})[0], 200)

    def test_a_notification_is_202(self):
        status, body, _ = self.serve(rpc("notifications/initialized", msg_id=None))
        self.assertEqual(status, 202)

    def test_the_client_address_is_rate_limited(self):
        saved = api._ip_ratelimit
        seen = []
        api._ip_ratelimit = lambda scope, ip, n, window=60: (seen.append((scope, ip, n, window)), False)[1]
        try:
            status, body, _ = self.serve(rpc("ping"))
        finally:
            api._ip_ratelimit = saved
        self.assertEqual(status, 429)
        self.assertEqual(seen, [("mcp", "127.0.0.1", 300, 60)])

    def test_a_tool_call_is_in_the_audit_trail_with_its_arguments_and_the_rest_is_not(self):
        self.serve(call_tool("get_device", {"name": "alpha01"}))
        self.serve(rpc("initialize", {"protocolVersion": "2025-06-18"}))
        self.serve(rpc("tools/list"))
        self.serve(rpc("ping"))
        self.assertEqual(len(self.audit), 1)
        actor, action, detail = self.audit[0]
        self.assertEqual((actor, action), ("alice", "mcp_http_call"))
        self.assertIn("get_device", detail)
        self.assertIn("alpha01", detail)
        self.assertNotIn("good", detail, "the token is not in the trail")

    def test_the_audit_line_is_capped(self):
        self.serve(call_tool("get_device", {"name": "x" * 150, "pad": "y" * 5000}))
        self.assertLessEqual(len(self.audit[0][2]), 270)


if __name__ == "__main__":
    unittest.main()
