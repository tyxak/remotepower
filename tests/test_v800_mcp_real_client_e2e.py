#!/usr/bin/env python3
"""8.0.0: the hosted MCP endpoint against the official MCP client (the `mcp` Python package), over HTTP, on the demo seed.

tests/test_v800_mcp_http_e2e.py speaks JSON-RPC with a plain HTTP client, so it can only show that the endpoint answers the way its author reads the protocol. This file
runs what an AI host runs: the package's streamable-HTTP client and session. It negotiates the protocol version, parses every answer into its own typed models and raises on
a message that does not fit them, so a field the specification requires and the endpoint leaves out fails here and nowhere else.

What it holds: the session is negotiated and the 16 read tools are listed with the schemas the bridge declares; a tool answers with the same hosts the dashboard shows the same
key, for the whole fleet and for a key confined to a group; a host that is not there, a missing argument and a tool that does not exist are answered in the protocol's own
ways (a tool result with isError, and a protocol error); a wrong key and a switched-off module fail at the first message instead of hanging.

Skips when the `mcp` package is not installed. It is not one of the packages the CI installs, so this runs where someone has the client, and the skip says so; the other MCP
files do not need it. Self-skips without gunicorn, and under the shared guard of the e2e files (playwright, Chromium and gunicorn present, or RP_BROWSER_REQUIRE set so that an
absence fails). The stack is booted from the demo seed, so what is probed is a fake fleet: no real AI host was connected.
"""
import asyncio
import http.client
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()
_HAVE_CLIENT = importlib.util.find_spec("mcp") is not None
_STATE = {}


def setUpModule():
    if not _GATE:
        raise unittest.SkipTest(SKIP_REASON)
    if not _HAVE_CLIENT:
        raise unittest.SkipTest("the mcp package (the official MCP client) is not installed: pip install mcp")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the endpoint is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-mcp-real-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    try:
        from e2e_harness import start_stack
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(base=base, shutdown=shutdown)


def tearDownModule():
    if _STATE.get("shutdown"):
        _STATE["shutdown"]()


def http_call(method, path, body=None, token=None):
    u = urlparse(_STATE["base"])
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = "Bearer " + token
    conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw.strip() else {})


def leaves(exc):
    """The exceptions at the bottom of an ExceptionGroup, which is how the client reports a failure inside its task group."""
    subs = getattr(exc, "exceptions", None)
    return [x for s in subs for x in leaves(s)] if subs else [exc]


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheOfficialClientAgainstTheHostedEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        status, body = http_call("POST", "/api/login", {"username": "alice", "password": "demo"})
        assert status == 200 and isinstance(body, dict), body
        cls.token = body["token"]
        cls.keys = []

    @classmethod
    def tearDownClass(cls):
        for kid in cls.keys:
            http_call("DELETE", "/api/apikeys/" + kid, token=cls.token)
        http_call("POST", "/api/config", {"mcp_module_enabled": False}, token=cls.token)

    def setUp(self):
        self.switch(True)

    def switch(self, on):
        status, body = http_call("POST", "/api/config", {"mcp_module_enabled": on}, token=self.token)
        self.assertEqual(status, 200, body)

    def key(self, **kw):
        status, body = http_call("POST", "/api/apikeys", dict({"name": "real-client", "role": "viewer"}, **kw), token=self.token)
        self.assertEqual(status, 201, body)
        self.keys.append(body["id"])
        return body["key"]

    def session(self, key, work, seconds=90):
        """Open the official client's session with the key, initialise it, run `work(session, init)` and return what it returns."""
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        async def go():
            async with streamablehttp_client(_STATE["base"] + "/api/mcp", headers={"Authorization": "Bearer " + key}) as (read, write, _session_id):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    return await work(session, init)
        return asyncio.run(asyncio.wait_for(go(), seconds))

    def dashboard_names(self, key):
        status, body = http_call("GET", "/api/devices", token=key)
        self.assertEqual(status, 200, body)
        return sorted(d["name"] for d in (body if isinstance(body, list) else body.get("devices", [])))

    def test_the_client_negotiates_a_session_and_lists_the_sixteen_read_tools_with_the_bridges_schemas(self):
        sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
        import mcp_http

        async def work(session, init):
            return init, await session.list_tools()
        init, listed = self.session(self.key(), work)
        self.assertEqual(init.protocolVersion, mcp_http.PROTOCOL_VERSIONS[0], "the newest version the endpoint speaks, which the client asked for first")
        self.assertEqual(init.serverInfo.name, mcp_http.SERVER_NAME)
        self.assertIsNotNone(init.capabilities.tools)
        self.assertIn("Read-only access", init.instructions or "")
        tools = {t.name: t for t in listed.tools}
        self.assertEqual(sorted(tools), sorted(mcp_http.TOOLS), "the same sixteen as the bridge, and no write tool")
        for name, spec in mcp_http.TOOLS.items():
            schema = tools[name].inputSchema
            self.assertEqual(sorted(schema.get("properties") or {}), sorted(spec["inputSchema"].get("properties") or {}), name)
            self.assertEqual(schema.get("required") or [], spec["inputSchema"].get("required") or [], name)
            self.assertTrue(tools[name].annotations.readOnlyHint, name)

    def test_a_tool_answers_with_the_hosts_the_dashboard_shows_the_same_key_for_the_whole_fleet_and_for_a_group(self):
        async def hosts(session, _init):
            res = await session.call_tool("list_devices", {})
            self.assertFalse(res.isError, res)
            self.assertEqual([c.type for c in res.content], ["text"])
            return sorted(h["name"] for h in json.loads(res.content[0].text))
        everything = self.key()
        self.assertEqual(self.session(everything, hosts), self.dashboard_names(everything))
        _status, body = http_call("GET", "/api/devices", token=self.token)
        rows = body if isinstance(body, list) else body.get("devices", [])
        groups = sorted({d.get("group") for d in rows if d.get("group")})
        self.assertGreaterEqual(len(groups), 2, "the seed has groups to confine a key to")
        inside = sorted(d["name"] for d in rows if d.get("group") == groups[0])
        confined = self.key(scope={"type": "groups", "values": [groups[0]]})
        self.assertEqual(self.dashboard_names(confined), inside)
        self.assertEqual(self.session(confined, hosts), inside, "through the client too")
        self.assertGreater(len(self.session(everything, hosts)), len(inside))

    def test_a_missing_host_and_a_missing_argument_are_tool_errors_and_an_unknown_tool_is_a_protocol_error(self):
        from mcp.shared.exceptions import McpError

        async def work(session, _init):
            missing_host = await session.call_tool("get_device", {"name": "no-such-host"})
            missing_arg = await session.call_tool("get_device", {})
            try:
                await session.call_tool("no_such_tool", {})
                unknown = None
            except McpError as exc:
                unknown = exc
            return missing_host, missing_arg, unknown
        missing_host, missing_arg, unknown = self.session(self.key(), work)
        self.assertTrue(missing_host.isError)
        self.assertEqual(missing_host.content[0].text, "No host named 'no-such-host'")
        self.assertTrue(missing_arg.isError)
        self.assertIn("argument required", missing_arg.content[0].text)
        self.assertIsNotNone(unknown, "an unknown tool is a protocol error, which the client raises")
        self.assertIn("Unknown tool: no_such_tool", str(unknown))

    def test_a_tool_that_takes_a_host_returns_what_the_rest_of_the_dashboard_returns_for_it(self):
        status, body = http_call("GET", "/api/devices", token=self.token)
        rows = body if isinstance(body, list) else body.get("devices", [])
        host = sorted(d["name"] for d in rows)[0]
        dev_id = next(d["id"] for d in rows if d["name"] == host)

        async def work(session, _init):
            res = await session.call_tool("get_runbook", {"name": host})
            self.assertFalse(res.isError, res)
            return json.loads(res.content[0].text)
        got = self.session(self.key(), work)
        status, expected = http_call("GET", "/api/devices/%s/runbook" % dev_id, token=self.token)
        self.assertEqual((status, got), (200, expected))

    def test_a_wrong_key_fails_at_the_first_message_with_a_401_and_does_not_hang(self):
        async def work(session, _init):
            return None
        with self.assertRaises(BaseException) as caught:
            self.session("not-a-key", work, seconds=60)
        text = " ".join(repr(x) for x in leaves(caught.exception))
        self.assertIn("401", text)

    def test_a_revoked_key_and_a_module_that_is_switched_off_fail_the_same_way(self):
        async def work(session, _init):
            return None
        key = self.key()
        self.assertEqual(http_call("DELETE", "/api/apikeys/" + self.keys.pop(), token=self.token)[0], 200)
        with self.assertRaises(BaseException) as caught:
            self.session(key, work, seconds=60)
        self.assertIn("401", " ".join(repr(x) for x in leaves(caught.exception)))
        self.switch(False)
        with self.assertRaises(BaseException) as caught:
            self.session(self.key(), work, seconds=60)
        self.assertEqual([repr(x) for x in leaves(caught.exception)], ["McpError('Session terminated')"],
                         "the endpoint answers 404 while the module is off, and the client's own wording for a 404 is Session terminated")


if __name__ == "__main__":
    unittest.main()
