#!/usr/bin/env python3
"""8.0.0 (data binding): the apps the agent finds on a host are a fleet question.

The host's drawer lists what the Linux agent found (`sysinfo.discovered`) and the Integrations page lists what a connector could read, but "which hosts run
Jellyfin" had no answer on the two pages built for such questions. The Data Explorer has an `apps` entity now (one row per host and app) and Fleet Query has a
**Runs app** criterion; both read the same finding the drawer does, through `app_discovery_handlers`, so the three cannot disagree.

Driven through the real handle_fleet_query, the real Explorer loader and the real query engine. The rows an agent says are built by the catalog's own `discover`
(the module the agent's copy is written from), and a host with an older agent is left to the server's fallback from the ports and containers it did report.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800-appq-"))

_spec = importlib.util.spec_from_file_location("api_v800_appq", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import app_catalog  # noqa: E402

JELLYFIN_PORT = [{"port": 8096, "proto": "tcp", "process": "jellyfin", "scope": "world"}]
GITEA_BOX = [{"name": "git", "image": "gitea/gitea:1.22", "status": "Up 2 hours", "ports": ["0.0.0.0:3000->3000/tcp"]}]


def _host(name, os_name="Debian 12", **extra):
    h = {"name": name, "last_seen": 1, "monitored": True, "os": os_name, "sysinfo": {}}
    h.update(extra)
    return h


def _fleet():
    """What each kind of host really sends."""
    both = app_catalog.discover(JELLYFIN_PORT, GITEA_BOX, [])
    only_jf = app_catalog.discover(JELLYFIN_PORT, [], [])
    return {
        # an agent that reports the finding itself
        "agent_both": dict(_host("agent_both"), sysinfo={"discovered": both}),
        "agent_jf": dict(_host("agent_jf"), sysinfo={"discovered": only_jf}),
        # an agent that reports an empty list: it looked and found nothing
        "agent_none": dict(_host("agent_none"), sysinfo={"discovered": []}),
        # an older agent: no `discovered`, only the ports it did report
        "old_agent": dict(_host("old_agent"), sysinfo={"listening_ports": JELLYFIN_PORT}),
        # hosts the catalog does not read
        "windows": dict(_host("windows", "Windows Server 2022"), sysinfo={"listening_ports": JELLYFIN_PORT}),
        "agentless": dict(_host("agentless", agentless=True), sysinfo={"discovered": only_jf}),
        "retired": dict(_host("retired", decommissioned=True), sysinfo={"discovered": only_jf}),
    }


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._files = {n: getattr(api, n) for n in ("DEVICES_FILE", "CONTAINERS_FILE")}
        api.DEVICES_FILE = self.d / self._files["DEVICES_FILE"].name
        api.CONTAINERS_FILE = self.d / self._files["CONTAINERS_FILE"].name
        api.save(api.DEVICES_FILE, _fleet())
        api.save(api.CONTAINERS_FILE, {})
        for n in ("DEVICES_FILE", "CONTAINERS_FILE"):
            api._invalidate_load_cache(getattr(api, n))
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in ("respond", "require_auth", "_env", "_scope_filter_devices", "method")}
        api.require_auth = lambda **k: "admin"
        api._scope_filter_devices = lambda d: d
        api.method = lambda: "GET"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)

        api.respond = _resp
        self.addCleanup(self._restore)

    def _restore(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for n, v in self._files.items():
            api._invalidate_load_cache(getattr(api, n))
            setattr(api, n, v)

    def _fq(self, qs):
        self.cap.clear()
        api._env = lambda k, dv="": (qs if k == "QUERY_STRING" else dv)
        try:
            api.handle_fleet_query()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get("s"), 200, self.cap)
        return {r["name"] for r in (self.cap.get("b") or {}).get("devices") or []}


class TestTheExplorerEntity(_Base):

    def rows(self):
        loader, _fields = api._QE_ENTITIES["apps"]
        return loader()

    def test_the_entity_is_registered_with_a_loader_and_fields(self):
        self.assertIn("apps", api._QE_ENTITIES)

    def test_one_row_per_host_and_app_for_the_hosts_the_catalog_reads(self):
        got = sorted((r["device_name"], r["app"]) for r in self.rows())
        self.assertEqual(got, [("agent_both", "gitea"), ("agent_both", "jellyfin"), ("agent_jf", "jellyfin"), ("old_agent", "jellyfin")])

    def test_the_population_is_not_empty(self):
        """Control: every comparison below passes against an empty row set."""
        self.assertGreaterEqual(len(self.rows()), 4)

    def test_an_older_agent_is_read_from_its_ports_and_says_so(self):
        by = {(r["device_name"], r["app"]): r for r in self.rows()}
        self.assertEqual(by[("old_agent", "jellyfin")]["source"], "server")
        self.assertEqual(by[("agent_jf", "jellyfin")]["source"], "agent")

    def test_the_row_says_what_gave_the_app_away(self):
        by = {(r["device_name"], r["app"]): r for r in self.rows()}
        gitea = by[("agent_both", "gitea")]
        self.assertIn("container", gitea["via"])
        self.assertEqual(gitea["container"], "git")
        self.assertEqual(by[("agent_jf", "jellyfin")]["port"], 8096)
        self.assertEqual(by[("agent_jf", "jellyfin")]["scope"], "world")

    def test_a_windows_host_an_agentless_host_and_a_retired_host_have_no_rows(self):
        names = {r["device_name"] for r in self.rows()}
        for gone in ("windows", "agentless", "retired", "agent_none"):
            self.assertNotIn(gone, names)

    def test_the_fields_and_the_rows_agree_both_ways_and_are_scalars(self):
        _loader, fields = api._QE_ENTITIES["apps"]
        row = self.rows()[0]
        self.assertEqual(sorted(fields), sorted(row))
        for r in self.rows():
            for k, v in r.items():
                self.assertNotIsInstance(v, (list, dict), k)

    def test_a_hostile_list_is_not_a_row(self):
        devs = api.load(api.DEVICES_FILE)
        devs["agent_jf"]["sysinfo"]["discovered"] = [{"id": "no-such-app"}, "text", None, {"id": 5}, {"id": "jellyfin", "port": "8096", "via": "process"}]
        api.save(api.DEVICES_FILE, devs)
        api._invalidate_load_cache(api.DEVICES_FILE)
        got = [(r["device_name"], r["app"], r["port"]) for r in self.rows() if r["device_name"] == "agent_jf"]
        self.assertEqual(got, [("agent_jf", "jellyfin", None)])

    def test_a_host_the_caller_may_not_see_has_no_rows(self):
        """The Explorer joins the caller's scope like every device-keyed entity: another tenant's host, or one outside a scoped role, contributes nothing."""
        api._scope_filter_devices = lambda d: {k: v for k, v in d.items() if k != "agent_both"}
        names = {r["device_name"] for r in self.rows()}
        self.assertNotIn("agent_both", names)
        self.assertEqual(names, {"agent_jf", "old_agent"})

    def test_a_question_runs_end_to_end_through_the_query_engine(self):
        st, out = api._query_run_one({"entity": "apps", "where": {"and": [{"field": "app", "op": "eq", "value": "jellyfin"}]}, "sort": "device_name"})
        self.assertEqual(st, 200, out)
        self.assertEqual([r["device_name"] for r in out["rows"]], ["agent_both", "agent_jf", "old_agent"])


class TestTheFleetQueryCriterion(_Base):

    def test_the_unfiltered_query_sees_every_host(self):
        self.assertEqual(len(self._fq("")), len(_fleet()))

    def test_it_matches_the_hosts_that_run_the_app(self):
        self.assertEqual(self._fq("app=jellyfin"), {"agent_both", "agent_jf", "old_agent"})
        self.assertEqual(self._fq("app=gitea"), {"agent_both"})

    def test_it_matches_part_of_the_name_in_any_case(self):
        self.assertEqual(self._fq("app=JELLY"), {"agent_both", "agent_jf", "old_agent"})

    def test_a_host_the_catalog_does_not_read_never_matches(self):
        ids = self._fq("app=jellyfin")
        for gone in ("windows", "agentless", "retired", "agent_none"):
            self.assertNotIn(gone, ids)

    def test_an_app_nobody_runs_matches_nothing(self):
        self.assertEqual(self._fq("app=nosuchapp"), set())

    def test_it_combines_with_the_other_criteria(self):
        self.assertEqual(self._fq("app=jellyfin&os=debian"), {"agent_both", "agent_jf", "old_agent"})
        self.assertEqual(self._fq("app=jellyfin&os=windows"), set())

    def test_a_host_the_caller_may_not_see_never_matches(self):
        api._scope_filter_devices = lambda d: {k: v for k, v in d.items() if k != "agent_both"}
        self.assertEqual(self._fq("app=jellyfin"), {"agent_jf", "old_agent"})

    def test_the_reader_matches_any_case_by_itself(self):
        """The handler lower-cases the parameter, so the reader's own lower-casing is only seen when it is called directly (the MCP and report paths may)."""
        import app_discovery_handlers as ad

        ad.bind(vars(api))
        got = ad.hosts_running(api.load(api.DEVICES_FILE), {}, "JELLY")
        self.assertEqual(got, {"agent_both", "agent_jf", "old_agent"})
        self.assertEqual(ad.hosts_running(api.load(api.DEVICES_FILE), {}, "  "), set())

    def test_a_saved_query_keeps_it(self):
        self.assertIn("app", api._FQ_PARAMS)
        self.assertEqual(api._clean_saved_params("fleet", {"app": "jellyfin", "bogus": "x"}), {"app": "jellyfin"})

    def test_the_page_has_the_input_and_the_field_map_names_it(self):
        html = (ROOT / "server/html/index.html").read_text()
        js = (ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn('id="fq-app"', html)
        self.assertIn("app: 'fq-app'", js)


if __name__ == "__main__":
    unittest.main()
