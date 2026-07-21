"""v6.3.1 — cross-fleet incident outcome memory.

Resolved+triaged alerts are harvested into a durable, tenant-tagged outcome
store that outlives the alert (which is pruned after alerts_retention_days). The
investigate loop gets a new `prior_incidents` evidence tool that surfaces the
most similar priors — the compounding, fleet-wide institutional memory a
single-host tool can't offer. Retrieval is tenant-isolated.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-incmem-"))

_SPEC = importlib.util.spec_from_file_location(
    "api", os.path.join(os.path.dirname(__file__), "..", "server", "cgi-bin", "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


def _triaged_alert(aid, event="service_down", tenant_dev="db", root="pg OOM",
                   rating=None, resolved=True, by="user"):
    tri = {"verdict": {"root_cause": root, "confidence": "high",
                       "recommended_action": "add swap"}, "by": by}
    if rating is not None:
        tri["feedback"] = {"helpful": rating}
    a = {"id": aid, "event": event, "severity": "high", "device_id": tenant_dev,
         "device_name": tenant_dev, "ai_triage": tri}
    if resolved:
        a["resolved_at"] = int(time.time()) - 100
        a["resolved_by"] = "auto"
    return a


class TestCaptureAndHarvest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "db": {"name": "db-03", "tenant": "default", "last_seen": self.now},
            "t2": {"name": "t2-host", "tenant": "acme", "last_seen": self.now},
        })
        api.save(api.INCIDENT_MEMORY_FILE, {})
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 0})

    def _mem(self):
        return api.load(api.INCIDENT_MEMORY_FILE) or {}

    def test_capture_pure_helper(self):
        dev = {"name": "db-03", "tenant": "default"}
        oc = api._capture_incident_outcome(_triaged_alert("a1", rating=True), dev)
        self.assertEqual(oc["root_cause"], "pg OOM")
        self.assertEqual(oc["rating"], "up")
        self.assertEqual(oc["tenant"], "default")

    def test_open_alert_not_captured(self):
        oc = api._capture_incident_outcome(
            _triaged_alert("a1", resolved=False), {"tenant": "default"})
        self.assertIsNone(oc)

    def test_no_verdict_root_not_captured(self):
        a = _triaged_alert("a1")
        a["ai_triage"]["verdict"]["root_cause"] = ""
        self.assertIsNone(api._capture_incident_outcome(a, {"tenant": "default"}))

    def test_harvest_stores_and_dedups(self):
        api.save(api.ALERTS_FILE, {"alerts": [_triaged_alert("a1", rating=True)],
                                   "alert_seq": 1})
        api.run_incident_memory_if_due()
        self.assertEqual(len(self._mem().get("outcomes", [])), 1)
        # bypass the interval gate and re-harvest — seen-ring must dedup
        m = self._mem(); m["last_run"] = self.now - 9999
        api.save(api.INCIDENT_MEMORY_FILE, m)
        api.run_incident_memory_if_due()
        self.assertEqual(len(self._mem().get("outcomes", [])), 1)

    def test_harvest_survives_alert_pruning(self):
        # once harvested, the outcome persists even after the alert is gone
        api.save(api.ALERTS_FILE, {"alerts": [_triaged_alert("a1")], "alert_seq": 1})
        api.run_incident_memory_if_due()
        api.save(api.ALERTS_FILE, {"alerts": [], "alert_seq": 1})   # pruned
        self.assertEqual(len(self._mem().get("outcomes", [])), 1)


class TestRetrieval(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {"db": {"name": "db", "tenant": "default",
                                           "last_seen": self.now}})
        # three priors, same event; one thumbs-up, one thumbs-down, one neutral
        outcomes = [
            {"alert_id": "old", "event": "service_down", "kind": "service",
             "tenant": "default", "device_name": "db", "root_cause": "neutral one",
             "recommended_action": "x", "resolution": "auto", "resolved_at": self.now - 500,
             "rating": None},
            {"alert_id": "up", "event": "service_down", "kind": "service",
             "tenant": "default", "device_name": "db", "root_cause": "confirmed fix",
             "recommended_action": "y", "resolution": "auto", "resolved_at": self.now - 400,
             "rating": "up"},
            {"alert_id": "other", "event": "service_down", "kind": "service",
             "tenant": "acme", "device_name": "z", "root_cause": "other tenant",
             "recommended_action": "z", "resolution": "auto", "resolved_at": self.now - 100,
             "rating": "up"},
        ]
        api.save(api.INCIDENT_MEMORY_FILE, {"outcomes": outcomes, "seen": []})

    def test_tenant_isolation(self):
        # a caller in 'default' must never retrieve 'acme's outcome
        res = api._similar_incidents("service_down", "service", "default")
        self.assertTrue(all(o["tenant"] == "default" for o in res))
        self.assertEqual(len(res), 2)

    def test_thumbs_up_ranks_first(self):
        res = api._similar_incidents("service_down", "service", "default")
        self.assertEqual(res[0]["rating"], "up")

    def test_same_event_beats_kind_only(self):
        m = api.load(api.INCIDENT_MEMORY_FILE)
        m["outcomes"].append({
            "alert_id": "kindonly", "event": "container_stopped", "kind": "service",
            "tenant": "default", "device_name": "db", "root_cause": "kind match only",
            "recommended_action": "", "resolution": "auto",
            "resolved_at": self.now, "rating": "up"})
        api.save(api.INCIDENT_MEMORY_FILE, m)
        res = api._similar_incidents("service_down", "service", "default")
        # the two exact service_down events rank above the newer kind-only one
        self.assertEqual(res[0]["event"], "service_down")

    def test_no_match_returns_empty(self):
        self.assertEqual(
            api._similar_incidents("brute_force_detected", "brute_force", "default"), [])


class TestTriageToolIntegration(unittest.TestCase):
    def test_prior_incidents_tool_present_and_renders(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {"db": {"name": "db", "tenant": "default",
                                           "last_seen": now}})
        api.save(api.INCIDENT_MEMORY_FILE, {"outcomes": [{
            "alert_id": "p1", "event": "service_down", "kind": "service",
            "tenant": "default", "device_name": "db", "root_cause": "was OOM",
            "recommended_action": "add swap", "resolution": "auto-resolved",
            "resolved_at": now - 200, "rating": "up"}], "seen": []})
        dev = api.load(api.DEVICES_FILE)["db"]
        tools = api._triage_tools("db", dev, {"id": "new", "event": "service_down"})
        self.assertIn("prior_incidents", tools)
        out = tools["prior_incidents"]({})
        self.assertIn("was OOM", out)
        self.assertIn("confirmed helpful", out)

    def test_tool_menu_lists_prior_incidents(self):
        # the menu constant lives on the bound module, not re-imported into api
        menu = api.ai_triage_handlers_mod._TRIAGE_TOOL_MENU
        self.assertIn("prior_incidents", menu)


class TestAiStatsScoreboardTenantIsolation(unittest.TestCase):
    """Sweep finding (LOW, fixed): handle_ai_stats' triage scoreboard counted
    over the RAW alert list, leaking other tenants' triaged/feedback aggregates
    to a tenant admin. It must filter through _filter_alerts_for_caller like the
    incident_memory count beside it."""

    def test_scoreboard_counts_only_visible_alerts(self):
        api.save(api.DEVICES_FILE, {
            "a": {"name": "host-a", "tenant": "tenantA", "last_seen": 0},
            "b": {"name": "host-b", "tenant": "tenantB", "last_seen": 0}})
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "x", "device_id": "a", "event": "service_down",
             "ai_triage": {"by": "auto", "feedback": {"helpful": True}}},
            {"id": "y", "device_id": "b", "event": "service_down",
             "ai_triage": {"by": "user", "feedback": {"helpful": False}}},
        ], "alert_seq": 2})
        orig = (api._tenant_gate, api._caller_scope)
        try:
            api._caller_scope = lambda: None
            # tenant-A admin (non-superadmin) sees only host-a's triaged alert
            api._tenant_gate = lambda: "tenantA"
            visible = api._filter_alerts_for_caller(
                (api._load_ro(api.ALERTS_FILE) or {}).get("alerts", []))
            self.assertEqual([a["id"] for a in visible if a.get("ai_triage")], ["x"])
            # superadmin (gate None) sees both
            api._tenant_gate = lambda: None
            allv = api._filter_alerts_for_caller(
                (api._load_ro(api.ALERTS_FILE) or {}).get("alerts", []))
            self.assertEqual(len([a for a in allv if a.get("ai_triage")]), 2)
        finally:
            api._tenant_gate, api._caller_scope = orig

    def test_handler_source_uses_the_filter(self):
        import inspect
        src = inspect.getsource(api.handle_ai_stats)
        self.assertIn("_filter_alerts_for_caller", src)


class TestWiring(unittest.TestCase):
    def test_cadence_in_both_registries(self):
        import inspect
        self.assertIn("run_incident_memory_if_due", inspect.getsource(api.main))
        sched = importlib.util.spec_from_file_location(
            "scheduler", os.path.join(os.path.dirname(__file__), "..",
                                      "server", "cgi-bin", "scheduler.py"))
        mod = importlib.util.module_from_spec(sched)
        sched.loader.exec_module(mod)
        self.assertIn("run_incident_memory_if_due", mod.CADENCE)

    def test_read_endpoint_bound(self):
        self.assertTrue(callable(api.handle_ai_incident_memory))


if __name__ == "__main__":
    unittest.main()
