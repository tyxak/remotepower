#!/usr/bin/env python3
"""v7.4.3, issue #50: CPU and memory thresholds for containers, per container.

"The agent collects CPU and memory per container (via docker stats), but RemotePower can only alert on a
container stopping or restarting. A container that runs away (a media server pegging the CPU, a database
or password manager leaking memory toward its limit) raises nothing."

A line per resource, fleet-wide and per host, with overrides for one container (matched by name, or by
image: as the exclude list is), and a number of reports it has to stay over the line before it alerts, so
a spike does not. The alert opens on the first report that completes the run, once; it closes on the
first report that reads below the line, and also when the container stops, is excluded, or the line is
turned off, so nothing is left open for a condition that no longer exists.

Everything goes through the real heartbeat, the real container diff and the real alert ledger.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, api, ctr  # noqa: E402


def stats(name, cpu=None, mem=None, usage="", limit=0, **kw):
    """A running container with docker-stats numbers."""
    return ctr(name, cpu_percent=cpu, mem_percent=mem, mem_usage=usage, mem_limit_bytes=limit, **kw)


def fleet(**kw):
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg["container_thresholds"] = kw
    api.save(api.CONFIG_FILE, cfg)
    api._LOAD_CACHE.clear()


def host(**kw):
    with api._LockedUpdate(api.DEVICES_FILE) as devs:
        devs[DEV]["container_thresholds"] = kw
    api._LOAD_CACHE.clear()


class _Res(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.FLEET_EVENTS_FILE, {"events": []})
        api.save(api.CONTAINER_STATS_HIST_FILE, {})
        self._gap = api._CTR_HIST_MIN_GAP
        api._CTR_HIST_MIN_GAP = 0
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._CTR_HIST_MIN_GAP = self._gap
        super().tearDown()

    def high(self):
        return [(p.get("container"), p.get("metric")) for e, p in self.events if e == "container_resource_high"]

    def ok(self):
        return [(p.get("container"), p.get("metric")) for e, p in self.events if e == "container_resource_ok"]

    def open_alerts(self):
        return sorted(((a.get("payload") or {}).get("container"), (a.get("payload") or {}).get("metric"))
                      for a in self.alerts("container_resource_high") if not a.get("resolved_at"))

    def beats(self, n, *items):
        for _ in range(n):
            self.beat([dict(i) for i in items])


class TestTheNumbers(unittest.TestCase):

    def test_what_the_normaliser_keeps(self):
        got = api._clean_container_thresholds({"cpu_pct": 150, "mem_pct": "80", "mem_mb": 2048.7, "sustain": 5,
                                               "junk": 1})
        self.assertEqual(got, {"cpu_pct": 150.0, "mem_pct": 80.0, "mem_mb": 2048, "sustain": 5})

    def test_a_key_that_is_not_set_is_not_kept(self):
        self.assertEqual(api._clean_container_thresholds({"cpu_pct": 100}), {"cpu_pct": 100.0})
        self.assertEqual(api._clean_container_thresholds({"cpu_pct": "", "mem_mb": None}), {})

    def test_ranges_are_clamped_and_nonsense_is_dropped(self):
        got = api._clean_container_thresholds({"cpu_pct": 10 ** 9, "mem_pct": 400, "mem_mb": -5, "sustain": 500})
        self.assertEqual(got, {"cpu_pct": 6400.0, "mem_pct": 100.0, "mem_mb": 0, "sustain": 20})
        for bad in (True, False, float("nan"), float("inf"), "x", [], {}, "1e999"):
            with self.subTest(bad=bad):
                self.assertEqual(api._clean_container_thresholds({"cpu_pct": bad, "sustain": bad}), {}, bad)

    def test_anything_but_an_object_is_empty(self):
        for raw in (None, [], "text", 5, True):
            self.assertEqual(api._clean_container_thresholds(raw), {}, raw)

    def test_overrides_need_a_match_and_are_capped(self):
        raw = {"overrides": [{"match": "jellyfin", "cpu_pct": 400}, {"match": "  "}, {"cpu_pct": 1}, "x", None,
                             {"match": "image:ghcr.io/x/job", "mem_mb": 0, "sustain": 2, "extra": 1},
                             {"match": "m" * 500, "cpu_pct": 5}]}
        got = api._clean_container_thresholds(raw)["overrides"]
        self.assertEqual(got[0], {"match": "jellyfin", "cpu_pct": 400.0})
        self.assertEqual(got[1], {"match": "image:ghcr.io/x/job", "mem_mb": 0, "sustain": 2})
        self.assertEqual(len(got[2]["match"]), 128)
        self.assertEqual(len(got), 3)
        many = {"overrides": [{"match": f"c{i}", "cpu_pct": 1} for i in range(200)]}
        self.assertEqual(len(api._clean_container_thresholds(many)["overrides"]), 50)

    def test_the_memory_in_use_is_read_in_mebibytes(self):
        f = api._container_mem_mb
        self.assertAlmostEqual(f("512MiB"), 512.0)
        self.assertAlmostEqual(f("1.5GiB"), 1536.0)
        self.assertAlmostEqual(f("2048KiB"), 2.0)
        self.assertAlmostEqual(f("1TiB"), 1048576.0)
        self.assertAlmostEqual(f("800MB"), 800.0 * 1000 * 1000 / (1024 * 1024), places=3)
        self.assertAlmostEqual(f("1GB"), 1000.0 ** 3 / 1024 ** 2, places=3)
        self.assertAlmostEqual(f("1048576B"), 1.0)
        self.assertAlmostEqual(f(" 64 MiB "), 64.0)
        for bad in ("", None, "garbage", "MiB", "-5MiB", "nanMiB", "infGiB", 5, "12 parsecs"):
            self.assertIsNone(f(bad), bad)


class TestWhichLineApplies(_Base):

    def lim(self, name="web", image="nginx", tag="1", fleet_cfg=None, host_cfg=None):
        return api._container_limits_for(fleet_cfg or {}, host_cfg or {}, name, image, tag)

    def test_nothing_set_is_everything_off(self):
        self.assertEqual(self.lim(), {"cpu_pct": 0, "mem_pct": 0, "mem_mb": 0, "sustain": 3})

    def test_the_fleet_line_then_the_hosts_own(self):
        f = {"cpu_pct": 100.0, "sustain": 4}
        self.assertEqual(self.lim(fleet_cfg=f)["cpu_pct"], 100.0)
        self.assertEqual(self.lim(fleet_cfg=f)["sustain"], 4)
        h = {"cpu_pct": 50.0}
        got = self.lim(fleet_cfg=f, host_cfg=h)
        self.assertEqual((got["cpu_pct"], got["sustain"]), (50.0, 4), "a host overrides what it sets and inherits the rest")

    def test_an_override_for_one_container_beats_both_defaults(self):
        f = {"cpu_pct": 100.0, "overrides": [{"match": "jellyfin", "cpu_pct": 400.0}]}
        h = {"cpu_pct": 50.0}
        self.assertEqual(self.lim("jellyfin-1", fleet_cfg=f, host_cfg=h)["cpu_pct"], 400.0)
        self.assertEqual(self.lim("web", fleet_cfg=f, host_cfg=h)["cpu_pct"], 50.0)

    def test_a_hosts_override_beats_the_fleets_override(self):
        f = {"overrides": [{"match": "jellyfin", "cpu_pct": 400.0, "mem_mb": 4096}]}
        h = {"overrides": [{"match": "jellyfin", "cpu_pct": 800.0}]}
        got = self.lim("jellyfin", fleet_cfg=f, host_cfg=h)
        self.assertEqual((got["cpu_pct"], got["mem_mb"]), (800.0, 4096), "field by field: it says cpu and nothing else")

    def test_the_first_matching_line_of_a_list_applies(self):
        f = {"overrides": [{"match": "jelly", "cpu_pct": 1.0}, {"match": "jellyfin", "cpu_pct": 2.0}]}
        self.assertEqual(self.lim("jellyfin", fleet_cfg=f)["cpu_pct"], 1.0)

    def test_zero_turns_one_resource_off_for_one_container(self):
        f = {"cpu_pct": 100.0, "mem_mb": 1024, "overrides": [{"match": "backup", "cpu_pct": 0}]}
        got = self.lim("backup", fleet_cfg=f)
        self.assertEqual((got["cpu_pct"], got["mem_mb"]), (0, 1024))

    def test_an_image_line_matches_the_image_as_the_exclude_list_does(self):
        f = {"overrides": [{"match": "image:ghcr.io/getarcaneapp/tools", "cpu_pct": 900.0}]}
        self.assertEqual(self.lim("loving_engelbart", "ghcr.io/getarcaneapp/tools", "latest", f)["cpu_pct"], 900.0)
        self.assertEqual(self.lim("tools", "nginx", "1", f)["cpu_pct"], 0, "a name is never read against an image line")
        g = {"overrides": [{"match": "tools", "cpu_pct": 7.0}]}
        self.assertEqual(self.lim("web", "ghcr.io/getarcaneapp/tools", "latest", g)["cpu_pct"], 0,
                         "and an image is never read against a name line")


class TestAlertingThroughTheHeartbeat(_Res):

    def test_nothing_set_nothing_fires(self):
        """The control: an install that never heard of the setting sees no new event."""
        self.beats(6, stats("web", cpu=900.0, mem=99.0, usage="9GiB", limit=10 ** 9))
        self.assertEqual(self.high(), [])
        self.assertEqual(self.open_alerts(), [])

    def test_it_takes_n_reports_over_the_line_and_alerts_once(self):
        fleet(cpu_pct=100, sustain=3)
        self.beats(2, stats("web", cpu=150.0))
        self.assertEqual(self.high(), [], "two reports are not three")
        self.beats(1, stats("web", cpu=150.0))
        self.assertEqual(self.high(), [("web", "cpu")])
        self.beats(4, stats("web", cpu=150.0))
        self.assertEqual(self.high(), [("web", "cpu")], "still over the line: no second alert")
        self.assertEqual(self.open_alerts(), [("web", "cpu")])

    def test_what_the_alert_says(self):
        fleet(cpu_pct=100, sustain=2)
        self.beats(2, stats("web", cpu=412.5))
        p = [p for e, p in self.events if e == "container_resource_high"][0]
        self.assertEqual((p["metric"], p["value"], p["threshold"], p["sustain"]), ("cpu", 412.5, 100.0, 2))
        row = self.alerts("container_resource_high")[0]
        self.assertEqual(row["title"], "Container web on serverbox: CPU 412.5% (alert at 100%)")
        self.assertEqual((row["payload"].get("container"), row["payload"].get("metric"),
                          row["payload"].get("value"), row["payload"].get("threshold")), ("web", "cpu", 412.5, 100.0))

    def test_a_spike_shorter_than_the_run_never_alerts(self):
        fleet(cpu_pct=100, sustain=3)
        for cpu in (150.0, 150.0, 20.0, 150.0, 150.0, 20.0, 150.0):
            self.beats(1, stats("web", cpu=cpu))
        self.assertEqual(self.high(), [])

    def test_it_closes_on_the_first_reading_below_the_line(self):
        fleet(cpu_pct=100, sustain=2)
        self.beats(2, stats("web", cpu=150.0))
        self.assertEqual(self.open_alerts(), [("web", "cpu")])
        self.beats(1, stats("web", cpu=40.0))
        self.assertEqual(self.ok(), [("web", "cpu")])
        self.assertEqual(self.open_alerts(), [])
        self.assertIsNotNone(self.alerts("container_resource_high")[0].get("resolved_at"))

    def test_it_can_alert_again_after_it_closed(self):
        fleet(cpu_pct=100, sustain=2)
        self.beats(2, stats("web", cpu=150.0))
        self.beats(1, stats("web", cpu=10.0))
        self.beats(2, stats("web", cpu=150.0))
        self.assertEqual(len(self.high()), 2)
        self.assertEqual(self.open_alerts(), [("web", "cpu")])

    def test_a_report_without_numbers_neither_counts_nor_clears(self):
        """docker stats can time out; a report with no reading says nothing about the container."""
        fleet(cpu_pct=100, sustain=3)
        self.beats(2, stats("web", cpu=150.0))
        self.beats(1, stats("web", cpu=None))
        self.assertEqual(self.high(), [])
        self.beats(1, stats("web", cpu=150.0))
        self.assertEqual(self.high(), [("web", "cpu")], "the run was two, held through the gap, then three")
        self.beats(1, stats("web", cpu=None))
        self.assertEqual(self.ok(), [], "and an alert is not closed by a missing reading")

    def test_the_line_is_inclusive(self):
        fleet(cpu_pct=100, sustain=1)
        self.beats(1, stats("web", cpu=99.9))
        self.assertEqual(self.high(), [])
        self.beats(1, stats("web", cpu=100.0))
        self.assertEqual(self.high(), [("web", "cpu")])

    def test_memory_as_a_share_of_the_limit_needs_a_limit(self):
        fleet(mem_pct=90, sustain=1)
        self.beats(1, stats("nolimit", mem=99.0, usage="9GiB", limit=0), stats("capped", mem=95.0, usage="950MiB", limit=1000 * 2 ** 20))
        self.assertEqual(self.high(), [("capped", "memory")], "an unlimited container's percentage is of the host's memory")

    def test_memory_in_mebibytes_needs_no_limit(self):
        fleet(mem_mb=1024, sustain=1)
        self.beats(1, stats("big", usage="1.5GiB"), stats("small", usage="512MiB"), stats("odd", usage="garbage"))
        self.assertEqual(self.high(), [("big", "memory_mb")])
        p = [p for e, p in self.events if e == "container_resource_high"][0]
        self.assertEqual((p["value"], p["threshold"]), (1536.0, 1024))
        self.assertEqual(self.alerts("container_resource_high")[0]["title"],
                         "Container big on serverbox: memory 1,536 MB (alert at 1,024 MB)")

    def test_two_resources_and_two_containers_are_separate_alerts(self):
        fleet(cpu_pct=100, mem_mb=1024, sustain=1)
        self.beats(1, stats("web", cpu=150.0, usage="2GiB"), stats("db", cpu=10.0, usage="3GiB"))
        self.assertEqual(self.open_alerts(), [("db", "memory_mb"), ("web", "cpu"), ("web", "memory_mb")])
        self.beats(1, stats("web", cpu=10.0, usage="2GiB"), stats("db", cpu=10.0, usage="3GiB"))
        self.assertEqual(self.open_alerts(), [("db", "memory_mb"), ("web", "memory_mb")],
                         "the CPU recovery closes only the CPU alert of that container")

    def test_an_override_for_one_container(self):
        fleet(cpu_pct=100, sustain=1, overrides=[{"match": "jellyfin", "cpu_pct": 400}])
        self.beats(1, stats("jellyfin", cpu=300.0), stats("web", cpu=300.0))
        self.assertEqual(self.high(), [("web", "cpu")])

    def test_an_override_by_image(self):
        fleet(cpu_pct=100, sustain=1, overrides=[{"match": "image:ghcr.io/acme/job", "cpu_pct": 0}])
        self.beats(1, stats("run-7", cpu=800.0, image="ghcr.io/acme/job"), stats("web", cpu=800.0))
        self.assertEqual(self.high(), [("web", "cpu")])

    def test_a_host_has_its_own_line(self):
        fleet(cpu_pct=100, sustain=1)
        host(cpu_pct=500)
        self.beats(1, stats("web", cpu=300.0))
        self.assertEqual(self.high(), [])
        host(cpu_pct=200)
        self.beats(1, stats("web", cpu=300.0))
        self.assertEqual(self.high(), [("web", "cpu")])

    def test_a_container_the_operator_excluded_never_alerts(self):
        fleet(cpu_pct=100, sustain=1)
        api.save(api.CONFIG_FILE, dict(api.load(api.CONFIG_FILE), container_alert_excludes=["web"]))
        api._LOAD_CACHE.clear()
        self.beats(2, stats("web", cpu=900.0), stats("rp-scan-1", cpu=900.0))
        self.assertEqual(self.high(), [])

    def test_a_container_that_stops_closes_its_alert(self):
        fleet(cpu_pct=100, sustain=1)
        self.beats(1, stats("web", cpu=150.0), stats("db", cpu=150.0))
        self.assertEqual(len(self.open_alerts()), 2)
        self.beats(1, stats("db", cpu=150.0))                    # web is gone
        self.assertEqual(self.open_alerts(), [("db", "cpu")])
        self.assertIn(("web", "cpu"), self.ok())

    def test_excluding_a_container_that_is_alerting_closes_its_alert(self):
        fleet(cpu_pct=100, sustain=1)
        self.beats(1, stats("web", cpu=150.0))
        api.save(api.CONFIG_FILE, dict(api.load(api.CONFIG_FILE), container_alert_excludes=["web"]))
        api._LOAD_CACHE.clear()
        self.beats(1, stats("web", cpu=150.0))
        self.assertEqual(self.open_alerts(), [])

    def test_turning_the_line_off_closes_the_alert(self):
        fleet(cpu_pct=100, sustain=1)
        self.beats(1, stats("web", cpu=150.0))
        fleet(cpu_pct=0, sustain=1)
        self.beats(1, stats("web", cpu=150.0))
        self.assertEqual(self.open_alerts(), [])
        self.assertEqual(self.ok(), [("web", "cpu")])

    def test_the_state_a_host_keeps_is_bounded_and_forgets_what_is_gone(self):
        fleet(cpu_pct=100, sustain=5)
        self.beats(2, *[stats(f"c{i}", cpu=150.0) for i in range(40)])
        entry = self.entry()
        self.assertEqual(len(entry["res_streak"]), 40)
        self.beats(1, stats("c0", cpu=150.0))
        entry = self.entry()
        self.assertEqual(sorted(entry["res_streak"]), ["c0"], "a container that is not reported has no streak to keep")
        self.assertLessEqual(len(entry.get("res_alerted", [])), api._RES_ALERTED_CAP)

    def test_a_malformed_report_cannot_break_the_heartbeat(self):
        fleet(cpu_pct=100, mem_pct=50, mem_mb=10, sustain=1)
        weird = [stats("a", cpu="x"), stats("b", cpu=float("nan")), stats("c", mem=float("inf"), limit=5),
                 stats("d", usage=["1GiB"]), stats("e", cpu=-5.0), ctr("f", cpu_percent=1e30)]
        self.beats(2, *weird)                                     # the point: nothing raised
        self.assertTrue(all(c != "a" for c, _ in self.high()))


class TestTheHistory(_Res):

    def history(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.CONTAINER_STATS_HIST_FILE) or {}).get(DEV, {})

    def test_every_report_with_numbers_adds_a_sample_oldest_first(self):
        for cpu in (10.0, 20.0, 30.0):
            self.beats(1, stats("web", cpu=cpu, mem=40.0, usage="400MiB", limit=1000 * 2 ** 20))
        got = self.history()["web"]
        self.assertEqual([row[1] for row in got], [10.0, 20.0, 30.0])
        self.assertEqual(got[0][2:], [40.0, 400.0])
        self.assertTrue(got[0][0] <= got[1][0] <= got[2][0])

    def test_a_report_without_numbers_adds_none(self):
        self.beats(2, stats("web", cpu=None))
        self.assertEqual(self.history(), {})

    def test_at_most_sixty_samples_a_container(self):
        self.beats(75, stats("web", cpu=5.0))
        self.assertEqual(len(self.history()["web"]), 60)

    def test_a_container_that_is_gone_loses_its_history_with_the_next_report(self):
        self.beats(2, stats("web", cpu=5.0), stats("db", cpu=5.0))
        self.beats(1, stats("db", cpu=5.0))
        self.assertEqual(sorted(self.history()), ["db"])

    def test_samples_are_not_taken_closer_together_than_the_gap(self):
        api._CTR_HIST_MIN_GAP = 3600
        self.beats(5, stats("web", cpu=5.0))
        self.assertEqual(len(self.history()["web"]), 1)

    def test_the_containers_answer_carries_the_history_the_line_and_what_is_alerting(self):
        fleet(cpu_pct=100, sustain=1)
        self.beats(3, stats("web", cpu=150.0, mem=30.0, usage="300MiB"))
        names = ("verify_token", "get_token_from_request", "respond")
        saved = {n: getattr(api, n) for n in names}
        box = {}
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "t"

        def _resp(status, data=None):
            box["status"], box["body"] = status, data
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_device_containers(DEV)
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(box["status"], 200, box)
        row = [c for c in box["body"]["items"] if c["name"] == "web"][0]
        self.assertEqual([p[1] for p in row["hist"]], [150.0, 150.0, 150.0])
        self.assertEqual(row["limits"], {"cpu_pct": 100.0, "mem_pct": 0, "mem_mb": 0, "sustain": 1})
        self.assertEqual(row["res_alerting"], ["cpu"])


def _call(handler, body, *path, role="admin", verb="PUT"):
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
             "audit_log", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.verify_token = lambda t: ("alice", role) if role else (None, None)
    api.get_token_from_request = lambda: "t" if role else ""
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: box.setdefault("audit", []).append((a, k))

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(*path)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class TestTheHostsOwnLine(_Res):

    def put(self, body, **kw):
        return _call(api.handle_device_container_thresholds, body, DEV, **kw)

    def test_a_host_keeps_its_line_on_its_record(self):
        box = self.put({"thresholds": {"cpu_pct": 200, "overrides": [{"match": "db", "mem_mb": 4096}], "junk": 1}})
        self.assertEqual(box["status"], 200, box)
        want = {"cpu_pct": 200.0, "overrides": [{"match": "db", "mem_mb": 4096}]}
        self.assertEqual(box["body"]["thresholds"], want)
        self.assertEqual(api.load(api.DEVICES_FILE)[DEV]["container_thresholds"], want)

    def test_an_empty_line_removes_it(self):
        self.put({"thresholds": {"cpu_pct": 200}})
        self.assertEqual(self.put({"thresholds": {}})["status"], 200)
        self.assertNotIn("container_thresholds", api.load(api.DEVICES_FILE)[DEV])

    def test_get_answers_with_the_hosts_line_and_the_fleets(self):
        fleet(cpu_pct=100, sustain=2)
        self.put({"thresholds": {"cpu_pct": 200}})
        box = _call(api.handle_device_container_thresholds, {}, DEV, verb="GET", role="viewer")
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(box["body"], {"thresholds": {"cpu_pct": 200.0}, "fleet": {"cpu_pct": 100.0, "sustain": 2}})

    def test_the_body_must_carry_an_object(self):
        for body in ({}, {"thresholds": "x"}, {"thresholds": [1]}, {"thresholds": None}, []):
            with self.subTest(body=body):
                self.assertEqual(self.put(body)["status"], 400)

    def test_a_reader_cannot_change_it_and_a_signed_out_caller_is_refused(self):
        for role in ("viewer", "auditor", "finance", "mcp"):
            self.assertEqual(self.put({"thresholds": {"cpu_pct": 1}}, role=role)["status"], 403, role)
        self.assertEqual(self.put({"thresholds": {"cpu_pct": 1}}, role=None)["status"], 401)

    def test_other_verbs_and_unknown_hosts(self):
        for verb in ("POST", "DELETE", "PATCH"):
            self.assertEqual(self.put({"thresholds": {}}, verb=verb)["status"], 405, verb)
        box = _call(api.handle_device_container_thresholds, {"thresholds": {}}, "nope")
        self.assertEqual(box["status"], 404)

    def test_the_change_is_audited_with_the_host_and_not_the_words(self):
        box = self.put({"thresholds": {"cpu_pct": 200, "overrides": [{"match": "very-private-name", "cpu_pct": 5}]}})
        text = json.dumps(box["audit"])
        self.assertIn(DEV, text)
        self.assertNotIn("very-private-name", text)

    def test_route_delete_guard_and_scope(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("PUT", f"/api/devices/{DEV}/container-thresholds")[0],
                         "handle_device_container_thresholds")
        self.assertEqual(resolve_route("GET", f"/api/devices/{DEV}/container-thresholds")[0],
                         "handle_device_container_thresholds")
        self.assertFalse(api._route_code_5(f"/api/devices/{DEV}/container-thresholds", "DELETE"))
        real = (api.path_info, api._tenant_visible, api.respond)
        seen = {}

        def fake(status, data):
            seen["status"] = status
            raise SystemExit()
        api.path_info = lambda: f"/api/devices/{DEV}/container-thresholds"
        api._tenant_visible = lambda dev: False
        api.respond = fake
        try:
            with self.assertRaises(SystemExit):
                api._enforce_device_scope()
        finally:
            api.path_info, api._tenant_visible, api.respond = real
        self.assertEqual(seen["status"], 403)

    def test_a_deleted_host_takes_its_line_with_it(self):
        self.put({"thresholds": {"cpu_pct": 200}})
        self.assertTrue(api._purge_device(DEV))                  # the line lives on the host record


class TestTheFleetLine(_Res):

    def save(self, body, role="admin"):
        return _call(api.handle_config_save, body, role=role, verb="POST")

    def test_the_fleet_line_is_saved_normalised(self):
        box = self.save({"container_thresholds": {"cpu_pct": "150", "sustain": 4, "junk": 1,
                                                  "overrides": [{"match": "jellyfin", "cpu_pct": 400}]}})
        self.assertEqual(box["status"], 200, box)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONFIG_FILE)["container_thresholds"],
                         {"cpu_pct": 150.0, "sustain": 4, "overrides": [{"match": "jellyfin", "cpu_pct": 400.0}]})

    def test_it_must_be_an_object(self):
        for bad in ("x", [1], 5):
            self.assertEqual(self.save({"container_thresholds": bad})["status"], 400, bad)

    def test_an_empty_object_clears_it(self):
        self.save({"container_thresholds": {"cpu_pct": 150}})
        self.save({"container_thresholds": {}})
        api._LOAD_CACHE.clear()
        self.assertNotIn("container_thresholds", api.load(api.CONFIG_FILE) or {})

    def test_saving_something_else_leaves_it_alone(self):
        self.save({"container_thresholds": {"cpu_pct": 150}})
        self.save({"monitor_interval": 120})
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONFIG_FILE)["container_thresholds"], {"cpu_pct": 150.0})


class TestTheEventsAreRegistered(unittest.TestCase):

    def test_both_events_exist_and_pair(self):
        reg = api.EVENT_REGISTRY
        self.assertIn("container_resource_high", reg)
        self.assertEqual(reg["container_resource_ok"].get("resolves"), ("container_resource_high",))
        self.assertIn("severity", reg["container_resource_high"])
        self.assertNotIn("severity", reg["container_resource_ok"], "good news does not go in the paging queue")

    def test_a_window_holds_both(self):
        self.assertIn("container_resource_high", api.SUPPRESSIBLE_EVENTS)
        self.assertIn("container_resource_ok", api.SUPPRESSIBLE_EVENTS)

    def test_the_feed_knows_them(self):
        js = (Path(__file__).resolve().parent.parent / "server/html/static/js/app.js").read_text(encoding="utf-8")
        self.assertIn("'container_resource_high'", js)
        self.assertIn("'container_resource_ok'", js)


if __name__ == "__main__":
    unittest.main()
