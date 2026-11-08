#!/usr/bin/env python3
"""8.0.0: four more connectors brought up to what their products' own sources say.

Each fact was read from the vendor's own source on 2026-11-08, not recalled:

  Paperless-ngx  GET /api/status/ is SystemStatusView (src/paperless/urls.py routes ^status/ under ^api/). It answers 403 with the plain text "Insufficient permissions" unless the
                 user is active and a superuser, or staff, or holds paperless.view_system_monitoring. Its keys: database{status OK|ERROR, error, migration_status{unapplied_migrations}},
                 storage{total, available}, tasks{redis_status, celery_status (OK|WARNING|ERROR: WARNING when no worker answers a ping), index_status, classifier_status,
                 sanity_check_status (WARNING means "no task found yet"), llmindex_status (DISABLED too), each with an *_error}. The connector read only /api/statistics/ and was
                 never anything but OK.
  Syncthing      docs.syncthing.net (written for v2.1.0): GET /rest/system/error answers {"errors": [{"when", "message"}]}. /rest/db/status is documented as an expensive call that does
                 not list its state values, so the connector does not ask it.
  ESPHome        the built-in dashboard has been removed from ESPHome ("esphome dashboard" says to install ESPHome Device Builder). Device Builder's docs/API.md keeps two deprecated
                 REST routes for compatibility: GET /devices (the flat legacy shape) and GET /ping ({<config>.yaml: true|false|null}), with Basic or Bearer auth when a password is set.
  Grafana        the alerting spec (pkg/services/ngalert/api/tooling/spec.json): GET /api/alertmanager/grafana/api/v2/alerts takes active, silenced and inhibited and answers a list of
                 {labels, annotations, status{state: unprocessed|active|suppressed, silencedBy, inhibitedBy}, startsAt, ...}.

The connectors are run against fixtures built from those shapes, not against a Paperless, a Syncthing, an ESPHome or a Grafana: none is available here.
"""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import integrations as I  # noqa: E402


class Fake(I.HTTPClient):
    """A client that answers by (method, path) and keeps every call. A route is (status, payload) or an exception to raise; anything else is a 404."""

    def __init__(self, routes, base="http://x"):
        super().__init__(base)
        self.routes, self.calls = routes, []

    def request(self, method, path, headers=None, params=None, body=None):
        key = (method, path.split("?")[0])
        self.calls.append({"method": method, "path": key[1], "headers": dict(headers or {}), "params": dict(params or {}), "body": body})
        v = self.routes.get(key)
        if v is None:
            return I.Resp(404, "")
        if isinstance(v, Exception):
            raise v
        st, payload = v
        return I.Resp(st, payload if isinstance(payload, str) else json.dumps(payload))

    def paths(self):
        return [(c["method"], c["path"]) for c in self.calls]


def run(inst, routes):
    c = Fake(routes)
    return I.poll_instance(inst, c), c


# ── Paperless-ngx ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
HEALTHY = {
    "pngx_version": "2.20.0", "server_os": "Linux", "install_type": "docker", "storage": {"total": 1000, "available": 400},
    "database": {"type": "postgresql", "url": "paperless", "status": "OK", "error": None, "migration_status": {"latest_migration": "documents.0001", "unapplied_migrations": []}},
    "tasks": {
        "redis_url": "redis://broker:6379", "redis_status": "OK", "redis_error": None, "celery_status": "OK", "celery_url": "celery@x", "celery_error": None,
        "index_status": "OK", "index_last_modified": "2026-11-08T05:00:00Z", "index_error": None,
        "classifier_status": "OK", "classifier_last_trained": "2026-11-08T04:00:00Z", "classifier_error": None,
        "sanity_check_status": "OK", "sanity_check_last_run": "2026-11-08T03:00:00Z", "sanity_check_error": None,
        "llmindex_status": "DISABLED", "llmindex_last_modified": None, "llmindex_error": None,
        "summary": {"days": 30, "total_count": 5, "pending_count": 0, "success_count": 5, "failure_count": 0},
    },
}


def status_with(**dotted):
    """The healthy answer with `a.b.c=value` changes ('.' written as '__')."""
    doc = copy.deepcopy(HEALTHY)
    for path, value in dotted.items():
        node = doc
        keys = path.split("__")
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return doc


def paperless(status=None, code=200, stats=None, secret="tok"):
    routes: dict = {("GET", "/api/statistics/"): (200, stats if stats is not None else {"documents_total": 120, "documents_inbox": 3})}
    if status is not None or code != 200:
        routes[("GET", "/api/status/")] = (code, status if status is not None else "")
    return run({"type": "paperless", "secret": secret}, routes)


class TestPaperlessSaysWhenItIsNotWell(unittest.TestCase):

    def test_a_healthy_install_is_ok_and_says_its_counts_and_that_nothing_is_wrong(self):
        r, c = paperless(HEALTHY)
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(r["detail"], "120 documents, 3 in inbox")
        self.assertEqual((r["metrics"]["documents"], r["metrics"]["inbox"], r["metrics"]["problems"]), (120, 3, 0))
        self.assertEqual(c.paths(), [("GET", "/api/statistics/"), ("GET", "/api/status/")])

    def test_each_failure_the_status_names_has_the_severity_of_what_it_stops(self):
        cases = [
            ("database ERROR stops everything", status_with(database__status="ERROR", database__error="Error connecting to database, check logs for more detail."), I.CRIT, "database"),
            ("redis ERROR stops the task queue", status_with(tasks__redis_status="ERROR", tasks__redis_error="Connection refused"), I.CRIT, "redis"),
            ("celery ERROR stops consuming", status_with(tasks__celery_status="ERROR"), I.CRIT, "celery"),
            ("celery WARNING is no worker answering", status_with(tasks__celery_status="WARNING"), I.WARN, "celery"),
            ("index ERROR breaks the search", status_with(tasks__index_status="ERROR", tasks__index_error="index broken"), I.WARN, "index"),
            ("classifier ERROR leaves auto-tagging stale", status_with(tasks__classifier_status="ERROR"), I.WARN, "classifier"),
            ("sanity check ERROR is a check that found something", status_with(tasks__sanity_check_status="ERROR"), I.WARN, "sanity"),
            ("LLM index ERROR", status_with(tasks__llmindex_status="ERROR"), I.WARN, "LLM"),
        ]
        for why, doc, status, word in cases:
            r, _ = paperless(doc)
            self.assertEqual(r["status"], status, why)
            self.assertIn(word, r["detail"], why)
            self.assertEqual(r["metrics"]["problems"], 1, why)
            self.assertTrue(r["detail"].startswith("120 documents, 3 in inbox"), r["detail"])

    def test_a_warning_of_the_classifier_the_sanity_check_or_the_llm_index_is_a_new_install_and_not_a_problem(self):
        doc = status_with(tasks__classifier_status="WARNING", tasks__classifier_error="No classifier training tasks found",
                          tasks__sanity_check_status="WARNING", tasks__sanity_check_error="No sanity check tasks found",
                          tasks__llmindex_status="WARNING", tasks__llmindex_error="No LLM index update tasks found")
        r, _ = paperless(doc)
        self.assertEqual((r["status"], r["metrics"]["problems"]), (I.OK, 0))
        self.assertEqual(r["detail"], "120 documents, 3 in inbox")

    def test_migrations_that_are_not_applied_are_a_warning_with_their_number(self):
        r, _ = paperless(status_with(database__migration_status={"latest_migration": "documents.0001", "unapplied_migrations": ["documents.0002", "documents.0003"]}))
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("2 migrations not applied", r["detail"])

    def test_the_worst_of_several_wins_and_every_problem_is_listed_worst_first(self):
        r, _ = paperless(status_with(database__status="ERROR", tasks__index_status="ERROR", tasks__celery_status="WARNING"))
        self.assertEqual((r["status"], r["metrics"]["problems"]), (I.CRIT, 3))
        text = r["detail"]
        self.assertLess(text.index("database"), text.index("celery"))
        self.assertLess(text.index("celery"), text.index("index"))

    def test_an_error_text_from_the_server_is_kept_but_cut(self):
        r, _ = paperless(status_with(tasks__redis_status="ERROR", tasks__redis_error="x" * 500))
        run_of_x = max(len(part) for part in r["detail"].replace("inbox", " ").split(" ") if set(part) == {"x"})
        self.assertEqual(run_of_x, 80, "the text of the error is cut at 80 characters")

    def test_a_user_who_may_not_read_the_status_gets_the_counts_and_is_told_what_the_status_needs(self):
        r, _ = paperless(code=403, status="Insufficient permissions")
        self.assertEqual(r["status"], I.OK)
        self.assertTrue(r["detail"].startswith("120 documents, 3 in inbox"), r["detail"])
        self.assertIn("staff", r["detail"])
        self.assertIn("view_system_monitoring", r["detail"])
        self.assertNotIn("problems", r["metrics"])

    def test_a_release_without_the_endpoint_gets_the_counts_and_a_short_note(self):
        r, _ = paperless()                      # the route is not there: 404
        self.assertEqual((r["status"], r["metrics"].get("problems")), (I.OK, None))
        self.assertIn("120 documents, 3 in inbox", r["detail"])
        self.assertIn("no status", r["detail"])

    def test_answers_of_the_wrong_shape_are_ignored_and_the_poll_still_succeeds(self):
        for junk in ("<html>", [], {"database": "x", "tasks": []}, {"database": {"status": None}, "tasks": {"celery_status": 7}}, None):
            r, _ = paperless(junk if junk is not None else {})
            self.assertEqual(r["status"], I.OK, junk)

    def test_the_token_goes_out_on_both_calls_and_the_statistics_failing_is_still_a_failure(self):
        _, c = paperless(HEALTHY)
        self.assertTrue(all(call["headers"].get("Authorization") == "Token tok" for call in c.calls), c.calls)
        routes = {("GET", "/api/statistics/"): (500, ""), ("GET", "/api/status/"): (200, HEALTHY)}
        r, _ = run({"type": "paperless", "secret": "tok"}, routes)
        self.assertEqual(r["status"], I.CRIT, "the core call still fails the poll")

    def test_the_label_names_the_new_metric(self):
        self.assertIn(("problems", "Problems", "int"), I._STATS["paperless"])
        self.assertIn("view_system_monitoring", I.CONNECTORS["paperless"]["notes"])


# ── Syncthing ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def syncthing(errors=None, code=200, key="k"):
    routes: dict = {("GET", "/rest/noauth/health"): (200, {"status": "OK"}),
              ("GET", "/rest/system/status"): (200, {"uptime": 7200}),
              ("GET", "/rest/system/connections"): (200, {"connections": {"A": {"connected": True}, "B": {"connected": False}}})}
    if errors is not None or code != 200:
        routes[("GET", "/rest/system/error")] = (code, {"errors": errors} if errors is not None else "")
    return run({"type": "syncthing", "secret": key}, routes)


class TestSyncthingSaysItsOwnErrors(unittest.TestCase):

    def test_no_errors_is_ok_and_reads_as_it_did(self):
        r, c = syncthing([])
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(r["detail"], "1/2 devices connected, up 2h")
        self.assertEqual(r["metrics"]["errors"], 0)
        self.assertIn(("GET", "/rest/system/error"), c.paths())

    def test_errors_are_a_warning_with_their_number_and_the_newest_message(self):
        errs = [{"when": "2026-11-08T01:00:00+01:00", "message": "folder abc: no space left"}, {"when": "2026-11-08T04:00:00+01:00", "message": "listen tcp :22000: address in use"}]
        r, _ = syncthing(errs)
        self.assertEqual(r["status"], I.WARN)
        self.assertEqual(r["metrics"]["errors"], 2)
        self.assertIn("2 errors", r["detail"])
        self.assertIn("address in use", r["detail"], "the newest message")
        self.assertNotIn("no space", r["detail"])

    def test_one_error_reads_in_the_singular_and_a_long_message_is_cut(self):
        r, _ = syncthing([{"when": "2026-11-08T01:00:00+01:00", "message": "m" * 400}])
        self.assertIn("1 error", r["detail"])
        self.assertNotIn("1 errors", r["detail"])
        self.assertEqual(max(len(part) for part in r["detail"].split(" ") if set(part) == {"m"}), 100, "the message is cut at 100 characters")

    def test_the_route_missing_or_refused_leaves_the_answer_it_had(self):
        for code in (403, 404, 500):
            r, _ = syncthing(code=code)
            self.assertEqual((r["status"], r["detail"]), (I.OK, "1/2 devices connected, up 2h"), code)
            self.assertNotIn("errors", r["metrics"], code)

    def test_entries_of_the_wrong_shape_are_ignored(self):
        for junk in ([None, 3, "x", {}, {"when": "w"}], [{"message": ""}]):
            r, _ = syncthing(junk)
            self.assertEqual((r["status"], r["metrics"]["errors"]), (I.OK, 0), junk)

    def test_the_key_goes_out_as_x_api_key_and_the_folder_status_is_never_asked(self):
        _, c = syncthing([])
        self.assertTrue(all(call["headers"].get("X-API-Key") == "k" for call in c.calls if call["path"] != "/rest/noauth/health"), c.calls)
        self.assertFalse([p for m, p in c.paths() if p.startswith("/rest/db/")], "documented as expensive: not asked")

    def test_the_label_names_the_new_metric(self):
        self.assertIn(("errors", "Errors", "int"), I._STATS["syncthing"])


# ── ESPHome ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NODES = {"configured": [
    {"name": "kitchen", "configuration": "kitchen.yaml", "deployed_version": "2026.10.0", "current_version": "2026.10.0"},
    {"name": "garage", "configuration": "garage.yaml", "deployed_version": "2026.9.0", "current_version": "2026.10.0"},
    {"name": "attic", "configuration": "attic.yaml", "deployed_version": "2026.10.0", "current_version": "2026.10.0"}], "importable": []}


def esphome(ping=None, devices=None, inst=None):
    routes: dict = {("GET", "/devices"): (200, devices if devices is not None else NODES)}
    if ping is not None:
        routes[("GET", "/ping")] = (200, ping)
    return run(dict({"type": "esphome"}, **(inst or {})), routes)


class TestEsphomeSaysWhichNodesAnswer(unittest.TestCase):

    def test_the_ping_map_is_counted_and_offline_nodes_are_said_without_changing_the_status(self):
        r, _ = esphome({"kitchen.yaml": True, "attic.yaml": False}, devices={"configured": [NODES["configured"][0], NODES["configured"][2]]})
        self.assertEqual(r["status"], I.OK, "a node in deep sleep is offline most of the time: said, not alerted")
        self.assertIn("2 nodes", r["detail"])
        self.assertIn("1 offline", r["detail"])
        self.assertEqual(r["metrics"]["offline"], 1)

    def test_out_of_date_firmware_is_still_the_warning_and_is_said_beside_the_offline_ones(self):
        r, _ = esphome({"kitchen.yaml": True, "garage.yaml": False, "attic.yaml": True})
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("3 nodes", r["detail"])
        self.assertIn("1 offline", r["detail"])
        self.assertIn("1 out of date", r["detail"])
        self.assertEqual((r["metrics"]["nodes"], r["metrics"]["outdated"], r["metrics"]["offline"]), (3, 1, 1))

    def test_every_node_answering_says_nothing_about_offline(self):
        r, _ = esphome({"kitchen.yaml": True, "garage.yaml": True, "attic.yaml": True}, devices={"configured": [NODES["configured"][0]]})
        self.assertNotIn("offline", r["detail"])
        self.assertEqual(r["metrics"]["offline"], 0)

    def test_a_dashboard_without_the_route_or_with_junk_there_is_read_as_before(self):
        r, _ = esphome()                                              # /ping is a 404
        self.assertEqual(r["status"], I.WARN)
        self.assertNotIn("offline", r["detail"])
        self.assertNotIn("offline", r["metrics"])
        for junk in ([], "x", {"a.yaml": "maybe", "b.yaml": 3}):
            r, _ = esphome(junk)
            self.assertNotIn("offline", r["detail"], junk)
            self.assertNotIn("offline", r["metrics"], junk)

    def test_no_credentials_means_no_authorization_header_and_a_login_is_basic_on_both_calls(self):
        _, c = esphome({"kitchen.yaml": True})
        self.assertTrue(all("Authorization" not in call["headers"] for call in c.calls), c.calls)
        _, c = esphome({"kitchen.yaml": True}, inst={"username": "esp", "secret": "p:ss"})
        want = "Basic " + base64.b64encode(b"esp:p:ss").decode()
        self.assertEqual([call["headers"].get("Authorization") for call in c.calls], [want, want])
        self.assertEqual(c.paths(), [("GET", "/devices"), ("GET", "/ping")])

    def test_a_password_without_a_user_name_is_still_sent_the_way_the_dashboard_reads_it(self):
        _, c = esphome({"kitchen.yaml": True}, inst={"secret": "only"})
        self.assertEqual(c.calls[0]["headers"].get("Authorization"), "Basic " + base64.b64encode(b":only").decode())

    def test_the_connector_takes_an_optional_user_and_password_and_says_what_replaced_the_dashboard(self):
        spec = I.CONNECTORS["esphome"]
        fields = {f["key"]: f for f in spec["fields"]}
        self.assertEqual(sorted(fields), ["secret", "username"])
        self.assertTrue(all(f.get("optional") for f in fields.values()))
        self.assertIn("Device Builder", spec["notes"])
        self.assertIn("keeps both routes", spec["notes"], "the reason /devices and /ping still work against it")
        self.assertIn(("offline", "Offline", "num"), I._STATS["esphome"])


# ── Grafana ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def alert(name, state="active", **labels):
    return {"labels": dict({"alertname": name}, **labels), "annotations": {}, "status": {"state": state, "silencedBy": [], "inhibitedBy": []},
            "startsAt": "2026-11-08T05:00:00Z", "endsAt": "0001-01-01T00:00:00Z", "fingerprint": "f", "receivers": [{"name": "r"}], "updatedAt": "2026-11-08T05:00:00Z"}


def grafana(alerts=None, code=200, secret="tok", db="ok"):
    routes: dict = {("GET", "/api/health"): (200, {"database": db, "version": "12.0.0"})}
    if alerts is not None or code != 200:
        routes[("GET", "/api/alertmanager/grafana/api/v2/alerts")] = (code, alerts if alerts is not None else "")
    inst = {"type": "grafana"}
    if secret:
        inst["secret"] = secret
    return run(inst, routes)


class TestGrafanaSaysWhatIsFiring(unittest.TestCase):

    def test_nothing_firing_is_ok_and_says_so(self):
        r, c = grafana([])
        self.assertEqual(r["status"], I.OK)
        self.assertIn("no alerts firing", r["detail"])
        self.assertEqual(r["metrics"]["alerts_firing"], 0)

    def test_the_call_asks_for_active_alerts_only_with_the_parameters_the_spec_names(self):
        _, c = grafana([])
        call = [x for x in c.calls if x["path"] == "/api/alertmanager/grafana/api/v2/alerts"][0]
        self.assertEqual(call["params"], {"active": "true", "silenced": "false", "inhibited": "false"})
        self.assertEqual(call["headers"].get("Authorization"), "Bearer tok")

    def test_firing_alerts_are_a_warning_with_their_number_and_names(self):
        r, _ = grafana([alert("DiskFull"), alert("HighCPU"), alert("HighCPU", instance="b")])
        self.assertEqual(r["status"], I.WARN)
        self.assertEqual(r["metrics"]["alerts_firing"], 3)
        self.assertIn("3 alerts firing", r["detail"])
        self.assertIn("DiskFull", r["detail"])
        self.assertIn("HighCPU", r["detail"])
        self.assertEqual(r["detail"].count("HighCPU"), 1, "a name once")

    def test_suppressed_and_unprocessed_instances_are_not_firing_even_if_the_server_sends_them(self):
        r, _ = grafana([alert("A", "suppressed"), alert("B", "unprocessed"), alert("C", "active")])
        self.assertEqual(r["metrics"]["alerts_firing"], 1)
        self.assertIn("1 alert firing", r["detail"])
        self.assertNotIn("1 alerts", r["detail"])
        self.assertIn("C", r["detail"])
        self.assertNotIn("B", r["detail"].split("firing")[-1])

    def test_only_three_names_are_listed_and_the_rest_are_counted(self):
        r, _ = grafana([alert("A%d" % i) for i in range(7)])
        self.assertEqual(r["metrics"]["alerts_firing"], 7)
        self.assertIn("7 alerts firing", r["detail"])
        self.assertIn("+4 more", r["detail"])

    def test_without_a_token_the_alerts_are_not_asked_and_the_answer_is_what_it_was(self):
        r, c = grafana(secret="")
        self.assertEqual((r["status"], r["detail"]), (I.OK, "database ok"))
        self.assertNotIn("alerts_firing", r["metrics"])
        self.assertFalse([p for m, p in c.paths() if "alertmanager" in p])

    def test_a_token_that_may_not_read_alert_instances_gets_the_answer_and_a_note(self):
        for code in (401, 403):
            r, _ = grafana(code=code)
            self.assertEqual(r["status"], I.OK, code)
            self.assertTrue(r["detail"].startswith("database ok"), r["detail"])
            self.assertIn("alert", r["detail"][len("database ok"):], code)
            self.assertNotIn("alerts_firing", r["metrics"], code)

    def test_a_grafana_without_the_alerting_route_is_read_as_before(self):
        r, _ = grafana()
        self.assertEqual((r["status"], r["detail"]), (I.OK, "database ok"))

    def test_a_database_that_is_down_is_critical_whatever_is_firing(self):
        r, _ = grafana([alert("A")], db="failing")
        self.assertEqual(r["status"], I.CRIT)

    def test_answers_of_the_wrong_shape_are_ignored(self):
        for junk in ({"a": 1}, "x", [None, 3, "y", {"status": 1}, {"labels": "z", "status": {"state": "active"}}]):
            r, _ = grafana(junk)
            self.assertIn(r["status"], (I.OK, I.WARN), junk)

    def test_the_label_names_the_new_metric(self):
        self.assertIn(("alerts_firing", "Firing", "int"), I._STATS["grafana"])
        self.assertIn("alert instances", I.CONNECTORS["grafana"]["notes"])


if __name__ == "__main__":
    unittest.main()
