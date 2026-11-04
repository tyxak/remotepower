#!/usr/bin/env python3
"""The MCP read tools for services, containers and patches answer from data that exists.

Four tools read keys off an item of the `/api/devices` list that the item does not carry: `services_watched_state`,
`services`, `containers`, `upgradable`, `patch_status`, `pkg_manager`. Each answered an empty list or null for every host,
so an AI client asking "is nginx up on web01" or "what is pending" was told there was nothing, with no error to say the
tool did not work. The only test that touched them listed their names.

The responses here come from the real handlers over one stored fleet, and the tools are run against them with the HTTP call
replaced by a lookup of those answers.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-mcp-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("rp_mcp_v750", ROOT / "mcp" / "remotepower-mcp.py")
mcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp)


class _Fleet(_Base):
    STORES = _Base.STORES + ("SERVICES_FILE", "CONTAINERS_FILE", "SERVICE_HIST_FILE", "ROLES_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        now = int(time.time())
        devs = api.load(api.DEVICES_FILE)
        for did, name, upg, sec in (("m1", "web01", 7, 3), ("m2", "db01", 0, 0), ("m3", "nas01", 2, 0)):
            devs[did] = {"name": name, "tenant": "default", "token_hash": "x", "last_seen": now, "monitored": True,
                         "os": "Debian", "sysinfo": {"packages": {"manager": "apt", "upgradable": upg,
                                                                  "security_updates": sec if sec else None}}}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.SERVICES_FILE, {})
        api.save(api.CONTAINERS_FILE, {})
        api.process_service_report("m1", [
            {"unit": "nginx.service", "active": "active", "sub": "running", "since": 5, "restarts": 0},
            {"unit": "app.service", "active": "failed", "sub": "failed", "since": 9, "restarts": 4}])
        api._entity_write_one(api.CONTAINERS_FILE, "m1", {"ts": now, "items": api.containers_mod.normalize_listing([
            {"name": "web", "image": "nginx", "tag": "1", "status": "Up 2 hours", "runtime": "docker", "restart_count": 0},
            {"name": "bad", "image": "app", "tag": "2", "status": "Up 1 hour (unhealthy)", "runtime": "docker",
             "restart_count": 6, "health": "unhealthy"}])})
        api._LOAD_CACHE.clear()
        self._api = mcp._api
        mcp._api = self.fake_api

    def tearDown(self):
        mcp._api = self._api
        super().tearDown()

    def fake_api(self, method, path, body=None, mcp_prompt=None):
        """The real handler's answer for the path, as the HTTP layer would return it."""
        self.assertEqual(method, "GET", path)
        if path == "/api/devices":
            st, d = self.call(api.handle_devices_list, m="GET", who="platform")
        elif path == "/api/patch-report":
            st, d = self.call(api.handle_patch_report, m="GET", who="platform")
        elif path.endswith("/services"):
            st, d = self.call(api.handle_services_device, path.split("/")[3], m="GET", who="platform")
        elif path.endswith("/containers"):
            st, d = self.call(api.handle_device_containers, path.split("/")[3], m="GET", who="platform")
        else:
            self.fail("an endpoint the test does not know: " + path)
        self.assertEqual(st, 200, (path, d))
        return d


class TestServices(_Fleet):

    def test_a_host_with_services_gets_them_with_their_state(self):
        out = mcp.tool_get_services({"name": "web01"})
        by = {s["unit"]: s for s in out["services"]}
        self.assertEqual(by["nginx.service"]["active"], "active")
        self.assertEqual(by["app.service"]["active"], "failed")
        self.assertEqual(by["app.service"]["restarts"], 4)

    def test_the_history_and_log_tail_are_left_out(self):
        out = mcp.tool_get_services({"name": "web01"})
        for s in out["services"]:
            self.assertNotIn("history", s)
            self.assertNotIn("log_tail", s)

    def test_a_host_without_service_data_gets_an_empty_list_not_an_error(self):
        self.assertEqual(mcp.tool_get_services({"name": "db01"})["services"], [])

    def test_an_unknown_host_is_an_error(self):
        with self.assertRaises(RuntimeError):
            mcp.tool_get_services({"name": "nope"})


class TestContainers(_Fleet):

    def test_a_host_with_containers_gets_them_trimmed(self):
        out = mcp.tool_get_containers({"name": "web01"})
        by = {c["name"]: c for c in out["containers"]}
        self.assertEqual(by["web"]["status"], "Up 2 hours")
        self.assertEqual(by["bad"]["health"], "unhealthy")
        self.assertEqual(by["bad"]["restart_count"], 6)
        self.assertNotIn("hist", by["web"])
        self.assertNotIn("audit", by["web"])
        self.assertEqual(out["summary"]["total"], 2)

    def test_a_host_without_containers_gets_an_empty_list(self):
        self.assertEqual(mcp.tool_get_containers({"name": "db01"})["containers"], [])


class TestPatches(_Fleet):

    def test_one_host(self):
        out = mcp.tool_get_patches({"name": "web01"})
        self.assertEqual((out["device"], out["upgradable"], out["security_updates"], out["pkg_manager"]),
                         ("web01", 7, 3, "apt"))
        self.assertEqual(out["patch_status"], "patches_available")

    def test_one_host_with_nothing_pending(self):
        out = mcp.tool_get_patches({"name": "db01"})
        self.assertEqual(out["upgradable"], 0)

    def test_the_fleet_lists_only_hosts_with_updates_pending(self):
        out = mcp.tool_get_patches({})
        self.assertEqual(sorted(r["name"] for r in out["fleet"]), ["nas01", "web01"])
        self.assertEqual(out["summary"]["total_pending_patches"], 9)

    def test_the_security_count_is_carried_for_the_fleet_too(self):
        out = {r["name"]: r for r in mcp.tool_get_patches({})["fleet"]}
        self.assertEqual(out["web01"]["security_updates"], 3)
        self.assertIsNone(out["nas01"]["security_updates"])


class TestTheHostList(_Fleet):

    def test_the_package_manager_is_read_from_the_system_information(self):
        rows = {r["name"]: r for r in mcp.tool_list_devices({})}
        self.assertEqual(rows["web01"]["pkg_manager"], "apt")

    def test_a_host_that_never_reported_one_is_an_empty_string(self):
        devs = api.load(api.DEVICES_FILE)
        devs["m3"]["sysinfo"] = {}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        rows = {r["name"]: r for r in mcp.tool_list_devices({})}
        self.assertEqual(rows["nas01"]["pkg_manager"], "")


if __name__ == "__main__":
    unittest.main()
