#!/usr/bin/env python3
"""8.0.0: three connectors brought up to what their products' own API documents say.

Each fact below was read from the vendor's own source on 2026-11-08, not recalled:

  Pi-hole    docs.pi-hole.net/api/auth: a session is ended with DELETE /api/auth (the SID by header, answered 204); the server holds `webserver.api.max_sessions`
             of them (16 by default) and "may deny" a login when they are all taken; clients are asked to log out when they are done. The connector and the
             DNS-blocker control opened a session on every call and never ended one.
  Immich     the OpenAPI document of the server (immich-app/immich, open-api/immich-openapi-specs.json): GET /server/storage (permission server.storage) answers
             diskUsagePercentage; GET /queues (permission queue.read, since 2.4.0, alpha) answers a list of {name, isPaused, statistics{active, waiting, failed, ...}};
             GET /jobs (permission job.read, deprecated) answers a map of queue name to {jobCounts{...}, queueStatus{...}}.
  PBS        the API schema the documentation is drawn from (pbs.proxmox.com/docs/api-viewer/apidoc.js): GET /status/datastore-usage answers `error`, `avail` (-1 on
             error), `mount-status` (mounted | notmounted | nonremovable), `gc-status.still-bad` and `estimated-full-date` (an estimate in the past means that usage
             is declining or not changing); GET /nodes/{node}/tasks takes `errors`, `since` and `limit`, and a user sees only their own tasks without Sys.Audit.

The connectors are run against fixtures built from those shapes, not against a Pi-hole, an Immich or a PBS: none is available here.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import dns_control as D  # noqa: E402
import integrations as I  # noqa: E402


class Fake(I.HTTPClient):
    """A client that answers by (method, path) and keeps every call. A route is (status, payload), or an exception to raise."""

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

    def paths(self, method=None):
        return [(c["method"], c["path"]) for c in self.calls if method in (None, c["method"])]


SUMMARY = {"queries": {"total": 500, "blocked": 50, "percent_blocked": 10.0}, "gravity": {"domains_being_blocked": 1000}}


def pihole_routes(over=None):
    r = {("POST", "/api/auth"): (200, {"session": {"sid": "s1", "csrf": "c", "validity": 1800, "valid": True}}),
         ("GET", "/api/stats/summary"): (200, SUMMARY),
         ("GET", "/api/info/version"): (200, {"version": {"core": {"local": {"version": "v6.1"}}}}),
         ("DELETE", "/api/auth"): (204, "")}
    r.update(over or {})
    return r


class FakePiHole(I.HTTPClient):
    """A Pi-hole that holds seats the way the documentation says: a login takes one, DELETE /api/auth gives it back, and with all of them taken a login is denied."""

    def __init__(self, seats=16):
        super().__init__("http://x")
        self.seats, self.taken, self.next_id, self.calls = seats, set(), 0, []

    def request(self, method, path, headers=None, params=None, body=None):
        path = path.split("?")[0]
        self.calls.append((method, path))
        sid = (headers or {}).get("X-FTL-SID", "")
        if (method, path) == ("POST", "/api/auth"):
            if len(self.taken) >= self.seats:
                return I.Resp(401, json.dumps({"error": {"key": "api_seats_exceeded", "message": "API seats exceeded"}}))
            self.next_id += 1
            self.taken.add("sid%d" % self.next_id)
            return I.Resp(200, json.dumps({"session": {"sid": "sid%d" % self.next_id, "validity": 1800, "valid": True}}))
        if (method, path) == ("DELETE", "/api/auth"):
            if sid in self.taken:
                self.taken.discard(sid)
                return I.Resp(204, "")
            return I.Resp(401, "")
        if sid not in self.taken:
            return I.Resp(401, "")
        if path == "/api/stats/summary":
            return I.Resp(200, json.dumps(SUMMARY))
        if path == "/api/info/version":
            return I.Resp(200, json.dumps({"version": {"core": {"local": {"version": "v6.1"}}}}))
        if path == "/api/dns/blocking" and method == "GET":
            return I.Resp(200, json.dumps({"blocking": "enabled", "timer": None}))
        if path == "/api/dns/blocking" and method == "POST":
            return I.Resp(200, json.dumps({"blocking": "disabled", "timer": 300}))
        return I.Resp(404, "")


class TestPiHoleGivesTheSessionBack(unittest.TestCase):

    def test_a_poll_ends_the_session_it_opened_with_that_sessions_id(self):
        c = Fake(pihole_routes())
        r = I.poll_instance({"type": "pihole", "secret": "pw"}, c)
        self.assertEqual((r["status"], r["version"]), (I.OK, "v6.1"))
        self.assertEqual(c.paths()[0], ("POST", "/api/auth"))
        self.assertEqual(c.paths()[-1], ("DELETE", "/api/auth"))
        self.assertEqual(c.paths("DELETE"), [("DELETE", "/api/auth")], "once")
        self.assertEqual(c.calls[-1]["headers"], {"X-FTL-SID": "s1"})
        self.assertTrue(all(call["headers"].get("X-FTL-SID") == "s1" for call in c.calls[1:]), "every read carries the session")

    def test_the_session_is_ended_when_a_read_fails_and_the_failure_is_still_the_answer(self):
        c = Fake(pihole_routes({("GET", "/api/stats/summary"): (500, "")}))
        r = I.poll_instance({"type": "pihole", "secret": "pw"}, c)
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("500", r["detail"])
        self.assertEqual(c.paths("DELETE"), [("DELETE", "/api/auth")])

    def test_a_logout_that_fails_or_is_refused_changes_nothing_about_the_answer(self):
        for logout in ((500, ""), (401, ""), I.IntegrationError("the connection was dropped"), RuntimeError("boom")):
            c = Fake(pihole_routes({("DELETE", "/api/auth"): logout}))
            r = I.poll_instance({"type": "pihole", "secret": "pw"}, c)
            self.assertEqual((r["status"], r["metrics"]["queries_today"]), (I.OK, 500), repr(logout))

    def test_a_pihole_without_a_password_has_no_session_and_nothing_is_ended(self):
        c = Fake(pihole_routes({("POST", "/api/auth"): (200, {"session": {"valid": True, "sid": None}})}))
        r = I.poll_instance({"type": "pihole", "secret": ""}, c)
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(c.paths("DELETE"), [])
        self.assertTrue(all("X-FTL-SID" not in call["headers"] for call in c.calls))

    def test_a_hundred_polls_leave_no_seat_taken_and_never_meet_a_full_table(self):
        pihole = FakePiHole(seats=16)
        for n in range(100):
            r = I.poll_instance({"type": "pihole", "secret": "pw"}, pihole)
            self.assertEqual(r["status"], I.OK, "poll %d: %s" % (n, r["detail"]))
        self.assertEqual(pihole.taken, set())

    def test_the_stand_in_can_say_no_so_the_test_above_means_something(self):
        pihole = FakePiHole(seats=16)
        original = I.pihole_logout
        I.pihole_logout = lambda c, sid: False                    # the connector as it was: never ends a session
        try:
            results = [I.poll_instance({"type": "pihole", "secret": "pw"}, pihole)["status"] for _ in range(20)]
        finally:
            I.pihole_logout = original
        self.assertEqual(results[:16], [I.OK] * 16)
        self.assertNotEqual(results[16], I.OK, "the seventeenth login is denied when none is given back")

    def test_the_logout_helper_alone(self):
        c = Fake({("DELETE", "/api/auth"): (204, "")})
        self.assertIs(I.pihole_logout(c, "abc"), True)
        self.assertIs(I.pihole_logout(c, ""), False)
        self.assertIs(I.pihole_logout(c, None), False)
        self.assertEqual(len(c.calls), 1)
        self.assertIs(I.pihole_logout(Fake({("DELETE", "/api/auth"): (500, "")}), "abc"), False)


class TestPiHoleBlockingControlGivesTheSessionBack(unittest.TestCase):

    def test_reading_the_state_uses_one_session_and_ends_it(self):
        pihole = FakePiHole()
        got = D.pihole_status({"secret": "pw"}, pihole)
        self.assertEqual(got, {"blocking": True, "remaining": 0})
        self.assertEqual(pihole.taken, set())
        self.assertEqual([m for m, _ in pihole.calls], ["POST", "GET", "DELETE"])

    def test_changing_it_is_one_session_for_the_change_and_the_answer_and_it_is_ended(self):
        pihole = FakePiHole()
        got = D.pihole_set_blocking({"secret": "pw"}, pihole, False, 300)
        self.assertEqual(pihole.taken, set())
        self.assertEqual(pihole.calls.count(("POST", "/api/auth")), 1, "it used to log in a second time to read the answer")
        self.assertEqual(pihole.calls.count(("DELETE", "/api/auth")), 1)
        self.assertEqual([p for _, p in pihole.calls if p == "/api/dns/blocking"], ["/api/dns/blocking", "/api/dns/blocking"])

    def test_a_change_that_pihole_refuses_still_ends_the_session_and_says_so(self):
        c = Fake({("POST", "/api/auth"): (200, {"session": {"sid": "s9", "valid": True}}), ("POST", "/api/dns/blocking"): (403, ""), ("DELETE", "/api/auth"): (204, "")})
        with self.assertRaises(I.IntegrationError) as caught:
            D.pihole_set_blocking({"secret": "pw"}, c, False, 300)
        self.assertIn("refused the change (HTTP 403)", str(caught.exception))
        self.assertEqual(c.paths("DELETE"), [("DELETE", "/api/auth")])

    def test_a_login_that_gives_no_session_is_still_refused_in_words_and_nothing_is_ended(self):
        c = Fake({("POST", "/api/auth"): (200, {"session": {"valid": False}})})
        with self.assertRaises(I.IntegrationError) as caught:
            D.pihole_status({"secret": "wrong"}, c)
        self.assertIn("did not return a session", str(caught.exception))
        self.assertEqual(c.paths("DELETE"), [])


def immich_routes(over=None):
    r = {("GET", "/api/server/about"): (200, {"version": "v2.5.0"}),
         ("GET", "/api/server/statistics"): (200, {"photos": 3, "videos": 1, "usage": 5 * 1024 * 1024}),
         ("GET", "/api/server/storage"): (200, {"diskSize": "100 GiB", "diskSizeRaw": 100, "diskUse": "62 GiB", "diskUseRaw": 62, "diskAvailable": "38 GiB", "diskAvailableRaw": 38,
                                                "diskUsagePercentage": 62.4}),
         ("GET", "/api/queues"): (200, [{"name": "thumbnailGeneration", "isPaused": False, "statistics": {"active": 2, "completed": 90, "delayed": 0, "failed": 1, "paused": 0, "waiting": 7}},
                                        {"name": "smartSearch", "isPaused": True, "statistics": {"active": 0, "completed": 5, "delayed": 0, "failed": 2, "paused": 3, "waiting": 0}}])}
    r.update(over or {})
    return r


def immich(routes):
    c = Fake(routes)
    return I.poll_instance({"type": "immich", "secret": "key"}, c), c


class TestImmichReadsTheDiskAndTheQueues(unittest.TestCase):

    def test_the_disk_fill_is_in_the_answer_and_sets_the_status(self):
        for pct, status in ((62.4, I.OK), (79.9, I.OK), (80, I.WARN), (89.9, I.WARN), (90, I.CRIT), (100, I.CRIT)):
            r, _ = immich(immich_routes({("GET", "/api/server/storage"): (200, {"diskUsagePercentage": pct})}))
            self.assertEqual(r["status"], status, pct)
            self.assertEqual(r["metrics"]["disk_pct"], round(pct, 1))
        r, _ = immich(immich_routes())
        self.assertIn("disk 62.4% full", r["detail"])
        self.assertTrue(r["detail"].startswith("3 photos, 1 videos, 5 MB used"), r["detail"])

    def test_a_key_without_the_storage_permission_gets_the_answer_it_got_before(self):
        r, _ = immich(immich_routes({("GET", "/api/server/storage"): (403, ""), ("GET", "/api/queues"): (403, ""), ("GET", "/api/jobs"): (403, "")}))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "3 photos, 1 videos, 5 MB used"))
        self.assertEqual(sorted(r["metrics"]), ["photos", "usage_mb", "videos"])

    def test_the_percentage_is_worked_out_from_the_sizes_when_the_server_leaves_it_out_and_not_believed_when_it_is_not_a_number(self):
        r, _ = immich(immich_routes({("GET", "/api/server/storage"): (200, {"diskSizeRaw": 200, "diskUseRaw": 170})}))
        self.assertEqual((r["status"], r["metrics"]["disk_pct"]), (I.WARN, 85.0))
        for junk in ({"diskUsagePercentage": "62"}, {"diskUsagePercentage": True}, {"diskUsagePercentage": None, "diskSizeRaw": 0}, {}, {"diskUsagePercentage": [90]}):
            r, _ = immich(immich_routes({("GET", "/api/server/storage"): (200, junk)}))
            self.assertNotIn("disk_pct", r["metrics"], repr(junk))
            self.assertEqual(r["status"], I.OK)

    def test_the_queues_are_summed_and_the_legacy_jobs_are_not_asked_when_they_answer(self):
        r, c = immich(immich_routes())
        self.assertEqual((r["metrics"]["jobs_failed"], r["metrics"]["jobs_active"], r["metrics"]["jobs_waiting"]), (3, 2, 7))
        self.assertNotIn(("GET", "/api/jobs"), c.paths())
        self.assertIn("3 failed jobs", r["detail"])

    def test_failed_jobs_are_said_and_do_not_change_the_status(self):
        r, _ = immich(immich_routes())
        self.assertEqual(r["status"], I.OK, "a failed job stays counted until somebody clears it, so it is not an alert")
        one = immich_routes({("GET", "/api/queues"): (200, [{"name": "q", "statistics": {"failed": 1}}])})
        r, _ = immich(one)
        self.assertIn("1 failed job", r["detail"])
        self.assertNotIn("1 failed jobs", r["detail"])
        none = immich_routes({("GET", "/api/queues"): (200, [{"name": "q", "statistics": {"failed": 0, "active": 1}}])})
        r, _ = immich(none)
        self.assertNotIn("failed", r["detail"])
        self.assertEqual(r["metrics"]["jobs_failed"], 0)

    def test_an_older_server_is_read_through_the_legacy_jobs_route(self):
        legacy = {"thumbnailGeneration": {"jobCounts": {"active": 1, "completed": 4, "delayed": 0, "failed": 4, "paused": 0, "waiting": 9}, "queueStatus": {"isActive": True, "isPaused": False}},
                  "library": {"jobCounts": {"active": 0, "completed": 0, "delayed": 0, "failed": 0, "paused": 0, "waiting": 1}, "queueStatus": {"isActive": False, "isPaused": False}}}
        routes = immich_routes({("GET", "/api/jobs"): (200, legacy)})
        routes.pop(("GET", "/api/queues"))
        r, c = immich(routes)
        self.assertEqual((r["metrics"]["jobs_failed"], r["metrics"]["jobs_active"], r["metrics"]["jobs_waiting"]), (4, 1, 10))
        self.assertEqual([p for _, p in c.paths() if p in ("/api/queues", "/api/jobs")], ["/api/queues", "/api/jobs"])

    def test_a_key_that_may_read_jobs_but_not_queues_falls_through_to_them(self):
        routes = immich_routes({("GET", "/api/queues"): (403, ""), ("GET", "/api/jobs"): (200, {"q": {"jobCounts": {"failed": 2}}})})
        r, _ = immich(routes)
        self.assertEqual(r["metrics"]["jobs_failed"], 2)

    def test_answers_of_the_wrong_shape_are_ignored_and_the_poll_still_succeeds(self):
        for queues, jobs in (({"error": "x"}, {"also": "junk"}), ([], []), ([1, 2], {"q": 5}), ("text", "text"), ([{"name": "q"}], {"q": {"jobCounts": None}})):
            r, _ = immich(immich_routes({("GET", "/api/queues"): (200, queues), ("GET", "/api/jobs"): (200, jobs)}))
            self.assertEqual(r["status"], I.OK, repr((queues, jobs)))
            self.assertNotIn("jobs_failed", r["metrics"], repr((queues, jobs)))

    def test_the_key_goes_out_as_x_api_key_on_every_call_and_the_status_pages_failure_stays_a_failure(self):
        _, c = immich(immich_routes())
        self.assertTrue(c.calls)
        self.assertTrue(all(call["headers"] == {"x-api-key": "key"} for call in c.calls))
        down = immich_routes({("GET", "/api/server/about"): (500, "")})
        r, _ = immich(down)
        self.assertEqual(r["status"], I.CRIT, "the core calls still fail the poll")

    def test_the_labels_name_the_new_metrics(self):
        labels = {k: (lab, kind) for k, lab, kind in I._STATS["immich"]}
        self.assertEqual(labels["disk_pct"], ("Disk", "pct"))
        self.assertEqual(labels["jobs_failed"], ("Failed jobs", "num"))
        self.assertIn("server.storage", I.CONNECTORS["immich"]["notes"])
        self.assertIn("queue.read", I.CONNECTORS["immich"]["notes"])


NOW = time.time()


def pbs_routes(stores, tasks=None, over=None):
    r = {("GET", "/api2/json/status/datastore-usage"): (200, {"data": stores}), ("GET", "/api2/json/version"): (200, {"data": {"version": "4.0.1", "release": "1", "repoid": "x"}})}
    if tasks is not None:
        r[("GET", "/api2/json/nodes/localhost/tasks")] = (200, {"data": tasks})
    r.update(over or {})
    return r


def store(name="tank", used=100, total=1000, **kw):
    return dict({"store": name, "used": used, "total": total, "avail": total - used, "mount-status": "nonremovable"}, **kw)


def pbs(routes):
    c = Fake(routes)
    return I.poll_instance({"type": "pbs", "username": "u@pbs!t", "secret": "sec"}, c), c


class TestPbsReadsWhatTheSchemaSays(unittest.TestCase):

    def test_a_datastore_with_an_error_is_critical_and_named_and_its_error_is_kept(self):
        r, _ = pbs(pbs_routes([store("tank"), {"store": "bad", "error": "unable to open chunk store", "avail": -1}]))
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("cannot read bad", r["detail"])
        ds = {d["name"]: d for d in r["datastores"]}
        self.assertEqual(ds["bad"]["error"], "unable to open chunk store")
        self.assertNotIn("error", ds["tank"])

    def test_an_avail_of_minus_one_is_an_error_and_a_missing_avail_is_not(self):
        r, _ = pbs(pbs_routes([{"store": "x", "used": 1, "total": 10, "avail": -1}]))
        self.assertEqual((r["status"], r["datastores"][0]["error"]), (I.CRIT, "the datastore could not be read"))
        r, _ = pbs(pbs_routes([{"store": "x", "used": 1, "total": 10}]))
        self.assertEqual(r["status"], I.OK)
        self.assertNotIn("error", r["datastores"][0])
        r, _ = pbs(pbs_routes([store(error="   ")]))
        self.assertNotIn("error", r["datastores"][0], "a blank error is no error")

    def test_a_removable_datastore_that_is_not_mounted_warns_and_the_other_states_do_not(self):
        r, _ = pbs(pbs_routes([store("usb", **{"mount-status": "notmounted"})]))
        self.assertEqual(r["status"], I.WARN)
        self.assertIs(r["datastores"][0]["mounted"], False)
        self.assertIn("not mounted: usb", r["detail"])
        for state in ("mounted", "nonremovable", None):
            r, _ = pbs(pbs_routes([store("usb", **{"mount-status": state})]))
            self.assertEqual(r["status"], I.OK, state)
            self.assertNotIn("mounted", r["datastores"][0])

    def test_chunks_still_bad_after_garbage_collection_warn(self):
        r, _ = pbs(pbs_routes([store(**{"gc-status": {"still-bad": 3, "removed-bad": 1}})]))
        self.assertEqual((r["status"], r["datastores"][0]["bad_chunks"]), (I.WARN, 3))
        self.assertIn("bad chunks in tank", r["detail"])
        for gc in ({"still-bad": 0}, {}, "junk", None, {"still-bad": "x"}):
            r, _ = pbs(pbs_routes([store(**{"gc-status": gc})]))
            self.assertEqual(r["status"], I.OK, repr(gc))
            self.assertNotIn("bad_chunks", r["datastores"][0])

    def test_an_estimate_in_the_past_is_not_a_forecast(self):
        for eta, kept in ((NOW + 86400 * 20, True), (NOW - 1000, False), (0, False), (True, False), ("soon", False), (None, False)):
            r, _ = pbs(pbs_routes([store(**{"estimated-full-date": eta})]))
            self.assertEqual("full_eta" in r["datastores"][0], kept, repr(eta))

    def test_the_failed_tasks_of_the_last_day_are_counted_by_kind_and_make_a_clean_poll_a_warning(self):
        tasks = [{"upid": "u1", "worker_type": "backup", "status": "ERROR: x"}, {"upid": "u2", "worker_type": "backup", "status": "ERROR"}, {"upid": "u3", "worker_type": "verificationjob", "status": "ERROR"}]
        r, c = pbs(pbs_routes([store()], tasks))
        self.assertEqual(r["metrics"]["tasks_failed_24h"], 3)
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("3 failed tasks in 24 h (2 backup, 1 verificationjob)", r["detail"])
        call = [x for x in c.calls if x["path"] == "/api2/json/nodes/localhost/tasks"][0]
        self.assertEqual((call["params"]["errors"], call["params"]["limit"]), (1, 100))
        self.assertAlmostEqual(call["params"]["since"], time.time() - 86400, delta=30, msg="a day back from now (read now: the module may have been loaded a while ago)")
        self.assertEqual(call["headers"], {"Authorization": "PBSAPIToken=u@pbs!t:sec"})

    def test_one_failed_task_reads_in_the_singular_and_none_is_zero_and_ok(self):
        r, _ = pbs(pbs_routes([store()], [{"worker_type": "garbage_collection"}]))
        self.assertIn("1 failed task in 24 h (1 garbage_collection)", r["detail"])
        r, _ = pbs(pbs_routes([store()], []))
        self.assertEqual((r["status"], r["metrics"]["tasks_failed_24h"]), (I.OK, 0))
        self.assertNotIn("failed", r["detail"])

    def test_a_token_that_cannot_list_tasks_gets_the_answer_it_got_before(self):
        routes = pbs_routes([store()])
        routes[("GET", "/api2/json/nodes/localhost/tasks")] = (403, "")
        r, _ = pbs(routes)
        self.assertEqual(r["status"], I.OK)
        self.assertNotIn("tasks_failed_24h", r["metrics"])
        for junk in ({"data": "x"}, {"data": None}, {"data": {"a": 1}}, []):
            routes[("GET", "/api2/json/nodes/localhost/tasks")] = (200, junk)
            r, _ = pbs(routes)
            self.assertNotIn("tasks_failed_24h", r["metrics"], repr(junk))

    def test_failed_tasks_never_soften_a_worse_status(self):
        tasks = [{"worker_type": "backup"}]
        r, _ = pbs(pbs_routes([store(used=950)], tasks))
        self.assertEqual(r["status"], I.CRIT)
        r, _ = pbs(pbs_routes([store(used=850)], tasks))
        self.assertEqual(r["status"], I.WARN)
        r, _ = pbs(pbs_routes([store(error="gone")], tasks))
        self.assertEqual(r["status"], I.CRIT)

    def test_the_old_answer_is_unchanged_for_a_healthy_server(self):
        r, _ = pbs(pbs_routes([store("a", 100, 1000), store("b", 500, 1000)], []))
        self.assertEqual((r["status"], r["version"], r["detail"]), (I.OK, "4.0.1", "2 datastores, fullest b 50.0%"))
        self.assertEqual(sorted(r["metrics"]), ["datastores", "fullest_pct", "tasks_failed_24h"])

    def test_the_label_and_the_notes_name_the_new_reading_and_what_the_token_needs(self):
        labels = {k: lab for k, lab, kind in I._STATS["pbs"]}
        self.assertEqual(labels["tasks_failed_24h"], "Failed 24h")
        self.assertIn("Sys.Audit on /system/tasks", I.CONNECTORS["pbs"]["notes"])


try:
    from py_mini_racer import MiniRacer
except Exception:                                    # pragma: no cover
    MiniRacer = None

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402


@unittest.skipIf(MiniRacer is None, "py_mini_racer not installed")
class TestTheBackupsPageDrawsWhatPbsSays(unittest.TestCase):
    """loadPbsBackups() run in a V8 isolate on the result the connector produces (not a hand-written one)."""

    def page(self, datastores, status="warning"):
        src = (_ROOT / "server" / "html" / "static" / "js" / "app-backups.js").read_text()
        fn = srcpin.js_function(src, "loadPbsBackups")
        if "await " in fn and not fn.lstrip().startswith("async"):
            fn = "async " + fn                       # js_function starts at the keyword `function`, and this one is declared async
        plural = srcpin.js_function((_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(), "plural")
        reply = {"latest": {"i1": {"type": "pbs", "label": "pbs01", "status": status, "version": "4.0.1", "datastores": datastores}}}
        ctx = MiniRacer()
        ctx.eval("""
          var __el = {card: {hidden: true}, body: {innerHTML: ''}};
          var document = {getElementById: function(id){ return id === 'pbs-card' ? __el.card : id === 'pbs-body' ? __el.body : null; }};
          function escHtml(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
          function _fmtAbsDate(t){ return 'DATE(' + t + ')'; }
          async function api(){ return %s; }
        """ % json.dumps(reply))
        ctx.eval(plural + "\n" + fn + "\nloadPbsBackups();")
        return ctx.eval("__el.body.innerHTML")

    def test_an_error_a_removable_store_that_is_out_and_bad_chunks_are_said_under_the_name(self):
        r, _ = pbs(pbs_routes([store("tank", **{"gc-status": {"still-bad": 2}}), store("usb", **{"mount-status": "notmounted"}), {"store": "gone", "error": "unable to open <chunk> store", "avail": -1}]))
        html = self.page(r["datastores"])
        self.assertIn("unable to open &lt;chunk&gt; store", html, "PBS's own words, escaped")
        self.assertIn('<span class="c-red">', html)
        self.assertIn("Not mounted", html)
        self.assertIn("2 bad chunks", html)
        self.assertNotIn("<chunk>", html)

    def test_a_healthy_datastore_has_no_note_and_a_forecast_in_the_past_is_not_drawn(self):
        r, _ = pbs(pbs_routes([store("a", **{"estimated-full-date": NOW - 5000}), store("b", **{"estimated-full-date": NOW + 86400 * 9})]))
        html = self.page(r["datastores"], status="ok")
        self.assertNotIn('<div class="hint">', html, "no issue, no note")
        self.assertEqual(html.count("DATE("), 1, "only the forecast to come")


if __name__ == "__main__":
    unittest.main()
