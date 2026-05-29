#!/usr/bin/env python3
"""v3.4.0: the search_fleet MCP tool — the bridge from MCP to the RAG index.

Network-free: the MCP server's _api() HTTP helper is stubbed so the test
asserts the tool calls the right endpoint with the right body and shapes the
result, without standing up the API.
"""
import importlib.util
import unittest
from pathlib import Path

_MCP = Path(__file__).resolve().parent.parent / "mcp" / "remotepower-mcp.py"
_spec = importlib.util.spec_from_file_location("rpmcp", _MCP)
mcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp)


class TestSearchFleetTool(unittest.TestCase):
    def setUp(self):
        self._orig_api = mcp._api
        self.calls = []

        def fake_api(method, path, body=None):
            self.calls.append((method, path, body))
            return {"ok": True, "query": (body or {}).get("query"),
                    "semantic": False,
                    "results": [{"id": "live/_fleet#cves", "title": "Fleet CVE summary",
                                 "source": "live_state", "device": None,
                                 "excerpt": "CVE-2024-3094 critical on web01"}]}
        mcp._api = fake_api

    def tearDown(self):
        mcp._api = self._orig_api

    def test_registered_and_advertised(self):
        self.assertIn("search_fleet", mcp.TOOLS)
        t = mcp.TOOLS["search_fleet"]
        self.assertIs(t["handler"], mcp.tool_search_fleet)
        self.assertEqual(t["inputSchema"]["required"], ["query"])
        names = [x["name"] for x in mcp.handle_tools_list({})["tools"]]
        self.assertIn("search_fleet", names)

    def test_calls_rag_search_endpoint(self):
        out = mcp.tool_search_fleet({"query": "worst cves in the fleet", "top_n": 8})
        self.assertEqual(self.calls, [
            ("POST", "/api/ai/rag/search",
             {"query": "worst cves in the fleet", "top_n": 8})])
        self.assertEqual(out["results"][0]["id"], "live/_fleet#cves")

    def test_default_top_n(self):
        mcp.tool_search_fleet({"query": "x"})
        self.assertEqual(self.calls[0][2]["top_n"], 6)

    def test_empty_query_rejected(self):
        with self.assertRaises(RuntimeError):
            mcp.tool_search_fleet({"query": "  "})
        with self.assertRaises(RuntimeError):
            mcp.tool_search_fleet({})


if __name__ == "__main__":
    unittest.main()
