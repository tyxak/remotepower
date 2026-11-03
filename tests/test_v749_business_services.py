#!/usr/bin/env python3
"""7.4.9: business services. Hosts, monitors, units, containers and scripts grouped under a name, with a rule for how they add up.

Nothing in the product answered "is Checkout up?". A host list says which machines are, a monitor says whether one URL is, and the
person on call adds them up in their head. A service names the parts and the rule (all of them, any one of them, or at least N), the
sweep keeps its state, and the people are told when it goes down, gets worse or comes back.

Three layers, each driven for real: the pure rules (bizsvc), the handlers over the stores with tenancy on, and the sweep through the
real alert ledger. The state of each kind of part is read from the store the product already keeps for it, so each is tested against
that store's real shape.
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

import bizsvc as bz  # noqa: E402


def host(i):
    return {"kind": "host", "device_id": i}


class TestTheRules(unittest.TestCase):

    def test_all_is_the_worst_part(self):
        ev = lambda *s: bz.evaluate({"type": "all"}, list(s))
        self.assertEqual(ev("ok", "ok"), "ok")
        self.assertEqual(ev("ok", "warning"), "warning")
        self.assertEqual(ev("ok", "unknown"), "unknown")
        self.assertEqual(ev("warning", "critical", "ok"), "critical")

    def test_any_needs_one_part_and_a_lost_spare_is_degraded(self):
        ev = lambda *s: bz.evaluate({"type": "any"}, list(s))
        self.assertEqual(ev("ok", "ok"), "ok")
        self.assertEqual(ev("ok", "critical"), "warning")
        self.assertEqual(ev("critical", "ok", "critical"), "warning")
        self.assertEqual(ev("critical", "critical"), "critical")
        self.assertEqual(ev("critical", "warning"), "critical")
        self.assertEqual(ev("unknown", "unknown"), "unknown")

    def test_min_is_a_quorum(self):
        ev = lambda n, *s: bz.evaluate({"type": "min", "min": n}, list(s))
        self.assertEqual(ev(2, "ok", "ok", "ok"), "ok")
        self.assertEqual(ev(2, "ok", "ok", "critical"), "warning")
        self.assertEqual(ev(2, "ok", "critical", "critical"), "critical")
        self.assertEqual(ev(2, "ok", "unknown", "unknown"), "unknown")
        self.assertEqual(ev(9, "ok", "ok"), "ok")                  # more than the parts: all of them is the most that can be asked
        self.assertEqual(ev(9, "ok", "critical"), "critical")

    def test_no_parts_is_unknown_and_junk_states_are_unknown(self):
        self.assertEqual(bz.evaluate({"type": "all"}, []), "unknown")
        self.assertEqual(bz.evaluate({"type": "all"}, ["ok", "weird", None, ["x"]]), "unknown")

    def test_a_rule_that_cannot_be_read_is_the_strict_one(self):
        for junk in (None, "any", 5, [], {"type": "nonsense"}, {"type": ["any"]}):
            self.assertEqual(bz.clean_rule(junk), {"type": "all"}, junk)
        self.assertEqual(bz.clean_rule({"type": "any", "min": 3}), {"type": "any"})
        for bad in (None, "2", True, float("nan"), float("inf"), [2], -4, 0):
            self.assertEqual(bz.clean_rule({"type": "min", "min": bad}), {"type": "min", "min": 1}, bad)
        self.assertEqual(bz.clean_rule({"type": "min", "min": 3.9}), {"type": "min", "min": 3})
        self.assertEqual(bz.clean_rule({"type": "min", "min": 10 ** 9}), {"type": "min", "min": bz.MAX_MEMBERS})


class TestTheParts(unittest.TestCase):

    def test_each_kind_keeps_only_its_own_fields(self):
        self.assertEqual(bz.clean_member({"kind": "host", "device_id": " d1 ", "junk": 1}), {"kind": "host", "device_id": "d1"})
        self.assertEqual(bz.clean_member({"kind": "unit", "device_id": "d1", "unit": "nginx.service"}),
                         {"kind": "unit", "device_id": "d1", "unit": "nginx.service"})
        self.assertEqual(bz.clean_member({"kind": "monitor", "label": "site"}), {"kind": "monitor", "label": "site"})
        self.assertEqual(bz.clean_member({"kind": "service", "service_id": "bs_1"}), {"kind": "service", "service_id": "bs_1"})

    def test_what_cannot_be_read_is_not_a_part(self):
        for junk in (None, "host", [], {}, {"kind": "disk", "device_id": "d"}, {"kind": "host"}, {"kind": "host", "device_id": ""},
                     {"kind": "host", "device_id": 5}, {"kind": "host", "device_id": ["d"]}, {"kind": "unit", "device_id": "d"},
                     {"kind": "host", "device_id": "x" * 500}, {"kind": "host", "device_id": "  \x00 "}):
            self.assertIsNone(bz.clean_member(junk), junk)

    def test_control_characters_are_removed_from_a_field(self):
        self.assertEqual(bz.clean_member({"kind": "monitor", "label": "a\x00b\nc"})["label"], "abc")

    def test_the_list_has_no_repeats_and_a_cap(self):
        out = bz.clean_members([host("a"), host("a"), host("b"), "junk", None])
        self.assertEqual([m["device_id"] for m in out], ["a", "b"])
        self.assertEqual(len(bz.clean_members([host(f"h{i}") for i in range(500)])), bz.MAX_MEMBERS)
        self.assertEqual(bz.clean_members("not a list"), [])

    def test_the_hosts_a_service_sits_on(self):
        ms = [host("a"), {"kind": "unit", "device_id": "a", "unit": "u"}, {"kind": "monitor", "label": "m"}, host("b")]
        self.assertEqual(bz.device_ids(ms), ["a", "b"])


class TestNesting(unittest.TestCase):

    def svc(self, **kw):
        return {k: [{"kind": "service", "service_id": v} for v in vs] for k, vs in kw.items()}

    def test_a_cycle_is_found(self):
        self.assertEqual(bz.find_cycle(self.svc(a=["b"], b=["a"])), ["a", "b", "a"])
        self.assertEqual(bz.find_cycle(self.svc(a=["a"])), ["a", "a"])
        self.assertEqual(bz.find_cycle(self.svc(a=["b"], b=["c"], c=["a"]))[0], "a")
        self.assertIsNone(bz.find_cycle(self.svc(a=["b", "c"], b=["c"], c=[])))
        self.assertIsNone(bz.find_cycle({}))

    def test_a_part_that_names_nothing_is_not_a_cycle(self):
        self.assertIsNone(bz.find_cycle(self.svc(a=["missing"])))

    def test_depth(self):
        s = self.svc(a=["b"], b=["c"], c=[])
        self.assertEqual((bz.depth(s, "a"), bz.depth(s, "b"), bz.depth(s, "c")), (3, 2, 1))
        self.assertGreater(bz.depth(self.svc(a=["b"], b=["a"]), "a"), bz.MAX_DEPTH)


class TestAvailability(unittest.TestCase):

    def test_a_service_down_for_a_quarter_of_the_window(self):
        tr = [{"ts": 100, "state": "ok"}, {"ts": 150, "state": "critical"}, {"ts": 175, "state": "ok"}]
        self.assertEqual(bz.availability(tr, 200, 100, "ok"), 75.0)

    def test_degraded_is_up_and_unknown_is_left_out(self):
        tr = [{"ts": 0, "state": "ok"}, {"ts": 100, "state": "warning"}, {"ts": 150, "state": "unknown"}, {"ts": 175, "state": "critical"}]
        # 0..100 ok, 100..150 warning (up), 150..175 unknown (left out), 175..200 critical (down): 150 up of 175 known
        self.assertEqual(bz.availability(tr, 200, 200, "critical"), round(100 * 150 / 175, 2))

    def test_no_history_uses_the_state_it_is_in(self):
        self.assertEqual(bz.availability([], 1000, 500, "ok"), 100.0)
        self.assertEqual(bz.availability([], 1000, 500, "critical"), 0.0)
        self.assertIsNone(bz.availability([], 1000, 500, "unknown"))
        self.assertIsNone(bz.availability([], 1000, 500, None))

    def test_transitions_before_the_window_set_its_start(self):
        tr = [{"ts": 10, "state": "critical"}, {"ts": 900, "state": "ok"}]
        self.assertEqual(bz.availability(tr, 1000, 200, "ok"), 50.0)

    def test_junk_transitions_are_ignored(self):
        tr = [None, "x", {"ts": "a", "state": "ok"}, {"ts": 5, "state": "bogus"}, {"ts": 10, "state": "ok"}]
        self.assertEqual(bz.availability(tr, 100, 100, "ok"), 100.0)


DEV_A, DEV_B = "devB", "devB2"      # two hosts of tenant B in the base; the service layer is the operator's, so they are just hosts


class _Svc(_Base):
    STORES = _Base.STORES + ("BUSINESS_SERVICES_FILE", "BUSINESS_SERVICE_STATE_FILE", "BUSINESS_SERVICE_HIST_FILE", "ALERTS_FILE",
                             "FLEET_EVENTS_FILE", "MON_HIST_FILE", "SERVICES_FILE", "CONTAINERS_FILE", "CUSTOM_SCRIPTS_FILE", "ROLES_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        now = int(time.time())
        devs = api.load(api.DEVICES_FILE)
        devs["h1"] = {"name": "web1", "tenant": "default", "token_hash": "x", "last_seen": now, "group": "g1"}
        devs["h2"] = {"name": "db1", "tenant": "default", "token_hash": "x", "last_seen": now, "group": "g1"}
        devs["h3"] = {"name": "db2", "tenant": "default", "token_hash": "x", "last_seen": now - 100000, "group": "g2"}   # offline
        api.save(api.DEVICES_FILE, devs)
        users = api.load(api.USERS_FILE)
        users["dviewer"] = {"role": "viewer", "tenant_id": "default"}
        users["dscoped"] = {"role": "ops-g1", "tenant_id": "default"}
        api.save(api.USERS_FILE, users)
        api.save(api.ROLES_FILE, {"roles": [{"name": "ops-g1", "permissions": [], "scope": {"type": "groups", "values": ["g1"]}}]})
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = [{"label": "site", "type": "http", "target": "https://example.com/"}]
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.MON_HIST_FILE, {"site": [{"ts": now, "up": True}]})
        api.save(api.SERVICES_FILE, {"h1": {"services": [{"unit": "nginx.service", "active": "active", "sub": "running"},
                                                         {"unit": "app.service", "active": "failed", "sub": "failed"}]}})
        api.save(api.CONTAINERS_FILE, {"h1": {"ts": now, "items": [
            {"name": "web", "status": "Up 2 hours", "health": "healthy"}, {"name": "bad", "status": "Up 2 hours (unhealthy)", "health": "unhealthy"},
            {"name": "gone", "status": "Exited (1) 3 hours ago"}]}})
        api.save(api.CUSTOM_SCRIPTS_FILE, {"cs_1": {"id": "cs_1", "name": "disk plugin", "body": "x", "assigned_devices": ["h1"], "mode": "nagios"}})
        devs = api.load(api.DEVICES_FILE)
        devs["h1"]["custom_script_results"] = {"cs_1": {"ok": False, "state": "warning", "mode": "nagios", "rc": 1, "status_text": "DISK WARNING"}}
        api.save(api.DEVICES_FILE, devs)
        for f in (api.BUSINESS_SERVICES_FILE, api.BUSINESS_SERVICE_STATE_FILE, api.BUSINESS_SERVICE_HIST_FILE):
            api.save(f, {})
        api.save(api.ALERTS_FILE, {"alerts": []})
        self.audits = []
        api.audit_log = lambda *a, **k: self.audits.append(a)
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda event, payload: (self.fired.append((event, dict(payload))), self._real_fire(event, payload))[1]
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.fire_webhook = self._real_fire
        super().tearDown()

    def create(self, name="Checkout", members=None, rule=None, who="platform", **extra):
        body = {"name": name, "members": members if members is not None else [host("h1")], "rule": rule or {"type": "all"}}
        body.update(extra)
        return self.call(api.handle_business_services, body=body, who=who)

    def listing(self, who="platform"):
        st, d = self.call(api.handle_business_services, m="GET", who=who)
        self.assertEqual(st, 200, d)
        return {s["name"]: s for s in d["services"]}

    def sweep(self):
        # the sweep is throttled to one read a minute; take the throttle away so a test can read as often as it likes
        doc = api.load(api.BUSINESS_SERVICE_STATE_FILE) or {}
        doc["last_run"] = 0
        api.save(api.BUSINESS_SERVICE_STATE_FILE, doc)
        api._LOAD_CACHE.clear()
        api.run_business_services_if_due()
        api._LOAD_CACHE.clear()

    def events(self, name=None):
        return [(e, p) for e, p in self.fired if e.startswith("business_service") and (name is None or e == name)]

    def set_last_seen(self, dev, ts):
        # save() refuses to move a host's last_seen back (the heartbeat's monotonic guard), so write the file itself
        devs = api.load(api.DEVICES_FILE)
        devs[dev]["last_seen"] = ts
        api.DEVICES_FILE.write_text(json.dumps(devs))
        api._LOAD_CACHE.clear()


class TestEachKindOfPart(_Svc):

    def state_of(self, member):
        st, d = self.create(name="t", members=[member])
        self.assertEqual(st, 201, d)
        row = d["members"][0]
        self.call(api.handle_business_service, d["id"], m="DELETE", who="platform")
        return row["state"], row["reason"]

    def test_a_host_is_ok_online_and_critical_offline(self):
        self.assertEqual(self.state_of(host("h1")), ("ok", "online"))
        self.assertEqual(self.state_of(host("h3")), ("critical", "offline"))

    def test_a_unit_is_what_the_host_last_said(self):
        self.assertEqual(self.state_of({"kind": "unit", "device_id": "h1", "unit": "nginx.service"}), ("ok", "active"))
        self.assertEqual(self.state_of({"kind": "unit", "device_id": "h1", "unit": "app.service"}), ("critical", "failed/failed"))
        self.assertEqual(self.state_of({"kind": "unit", "device_id": "h1", "unit": "never.service"})[0], "unknown")

    def test_a_unit_on_an_offline_host_is_down_not_stale(self):
        api.save(api.SERVICES_FILE, {"h3": {"services": [{"unit": "x.service", "active": "active", "sub": "running"}]}})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.state_of({"kind": "unit", "device_id": "h3", "unit": "x.service"}), ("critical", "host offline"))

    def test_a_container(self):
        self.assertEqual(self.state_of({"kind": "container", "device_id": "h1", "name": "web"}), ("ok", "running"))
        self.assertEqual(self.state_of({"kind": "container", "device_id": "h1", "name": "bad"}), ("warning", "unhealthy"))
        self.assertEqual(self.state_of({"kind": "container", "device_id": "h1", "name": "gone"}), ("critical", "not running"))
        self.assertEqual(self.state_of({"kind": "container", "device_id": "h1", "name": "absent"}), ("critical", "not running"))

    def test_a_host_without_a_container_report_is_unknown(self):
        self.assertEqual(self.state_of({"kind": "container", "device_id": "h2", "name": "web"})[0], "unknown")

    def test_a_monitor(self):
        self.assertEqual(self.state_of({"kind": "monitor", "label": "site"}), ("ok", "up"))
        api.save(api.MON_HIST_FILE, {"site": [{"ts": 1, "up": True}, {"ts": 2, "up": False}]})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.state_of({"kind": "monitor", "label": "site"}), ("critical", "down"))
        api.save(api.MON_HIST_FILE, {"site": [{"ts": 2, "ok": False}]})        # the older key name
        api._LOAD_CACHE.clear()
        self.assertEqual(self.state_of({"kind": "monitor", "label": "site"})[0], "critical")
        api.save(api.MON_HIST_FILE, {})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.state_of({"kind": "monitor", "label": "site"}), ("unknown", "no result yet"))

    def test_a_script_has_the_state_of_its_last_result(self):
        self.assertEqual(self.state_of({"kind": "script", "device_id": "h1", "script_id": "cs_1"}), ("warning", "DISK WARNING"))
        self.assertEqual(self.state_of({"kind": "script", "device_id": "h2", "script_id": "cs_1"})[0], "unknown")

    def test_a_host_that_is_gone_is_unknown(self):
        devs = api.load(api.DEVICES_FILE)
        devs["ghost"] = devs["h1"]
        api.save(api.DEVICES_FILE, devs)
        st, d = self.create(name="g", members=[host("ghost")])
        self.assertEqual(st, 201)
        devs = api.load(api.DEVICES_FILE)
        del devs["ghost"]
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.assertEqual(self.listing()["g"]["members"][0]["state"], "unknown")


class TestTheRulesOverRealParts(_Svc):

    def test_all_any_and_min_over_two_database_hosts(self):
        parts = [host("h2"), host("h3")]          # db1 up, db2 offline
        want = {"all": "critical", "any": "warning", "min": "critical"}
        st, d = self.create(name="all", members=parts, rule={"type": "all"})
        self.assertEqual(d["state"], want["all"])
        st, d = self.create(name="any", members=parts, rule={"type": "any"})
        self.assertEqual(d["state"], want["any"])
        st, d = self.create(name="min2", members=parts, rule={"type": "min", "min": 2})
        self.assertEqual(d["state"], want["min"])
        self.assertEqual(d["parts"], 2)
        self.assertEqual(d["parts_ok"], 1)

    def test_a_service_holds_a_service(self):
        st, inner = self.create(name="Database", members=[host("h2"), host("h3")], rule={"type": "any"})
        st, outer = self.create(name="Shop", members=[host("h1"), {"kind": "service", "service_id": inner["id"]}])
        self.assertEqual(st, 201, outer)
        self.assertEqual(outer["state"], "warning")        # the database is degraded, so the shop is
        row = [m for m in outer["members"] if m["kind"] == "service"][0]
        self.assertEqual((row["label"], row["state"]), ("Database", "warning"))


class TestCreatingAndChanging(_Svc):

    def test_create_returns_the_service_and_audits_it(self):
        st, d = self.create(description="the shop")
        self.assertEqual(st, 201, d)
        self.assertTrue(d["id"].startswith("bs_"))
        self.assertEqual((d["name"], d["description"], d["rule"], d["state"]), ("Checkout", "the shop", {"type": "all"}, "ok"))
        self.assertEqual(self.audits[-1][1], "business_service_create")
        self.assertIn("Checkout", self.listing())

    def test_the_refusals(self):
        cases = [
            (dict(name=""), 400, "name"),
            (dict(members=[]), 400, "at least one part"),
            (dict(members=[host("nobody")]), 400, "unknown host"),
            (dict(members=[{"kind": "monitor", "label": "nope"}]), 400, "unknown monitor"),
            (dict(members=[{"kind": "script", "device_id": "h1", "script_id": "cs_nope"}]), 400, "unknown script"),
            (dict(members=[{"kind": "service", "service_id": "bs_nope"}]), 400, "unknown service"),
            (dict(members=[host("h1")], rule={"type": "min", "min": 2}), 400, "more than the parts"),
            (dict(members=["junk", None, {"kind": "disk"}]), 400, "at least one part"),
        ]
        for kw, status, word in cases:
            st, d = self.create(**kw)
            self.assertEqual((st, word in d.get("error", "")), (status, True), (kw, st, d))
        self.assertEqual(self.listing(), {})

    def test_a_name_is_unique_whatever_its_case(self):
        self.create(name="Checkout")
        st, d = self.create(name="  checkout ")
        self.assertEqual(st, 409, d)

    def test_only_an_administrator_changes_anything(self):
        self.assertEqual(self.create(who="dviewer")[0], 403)
        st, d = self.create()
        sid = d["id"]
        for who in ("dviewer", "dscoped"):
            self.assertEqual(self.call(api.handle_business_service, sid, body={"name": "x", "members": [host("h1")]}, m="PUT", who=who)[0], 403)
            self.assertEqual(self.call(api.handle_business_service, sid, m="DELETE", who=who)[0], 403)
        self.assertEqual(self.call(api.handle_business_service, sid, m="GET", who=None)[0], 401)

    def test_update_replaces_the_fields_and_keeps_the_id(self):
        st, d = self.create()
        st, u = self.call(api.handle_business_service, d["id"], m="PUT", who="platform",
                          body={"name": "Shop", "members": [host("h1"), host("h2")], "rule": {"type": "any"}})
        self.assertEqual((st, u["id"], u["name"], u["rule"], u["parts"]), (200, d["id"], "Shop", {"type": "any"}, 2))
        self.assertEqual(self.audits[-1][1], "business_service_update")
        self.assertEqual(list(self.listing()), ["Shop"])

    def test_a_service_can_keep_its_own_name_on_update(self):
        st, d = self.create(name="Checkout")
        st, _ = self.call(api.handle_business_service, d["id"], m="PUT", who="platform", body={"name": "Checkout", "members": [host("h2")]})
        self.assertEqual(st, 200)

    def test_a_cycle_a_self_reference_and_a_deep_chain_are_refused(self):
        _, a = self.create(name="A")
        _, b = self.create(name="B", members=[{"kind": "service", "service_id": a["id"]}])
        st, d = self.call(api.handle_business_service, a["id"], m="PUT", who="platform",
                          body={"name": "A", "members": [{"kind": "service", "service_id": b["id"]}]})
        self.assertEqual(st, 400, d)
        self.assertIn("each other", d["error"])
        st, d = self.call(api.handle_business_service, a["id"], m="PUT", who="platform",
                          body={"name": "A", "members": [{"kind": "service", "service_id": a["id"]}]})
        self.assertEqual(st, 400, d)
        prev = b["id"]
        for i in range(bz.MAX_DEPTH - 2):         # B is level 2; levels 3 to 5 are fine, 6 is not
            st, nxt = self.create(name=f"L{i}", members=[{"kind": "service", "service_id": prev}])
            self.assertEqual(st, 201, (i, nxt))
            prev = nxt["id"]
        st, d = self.create(name="too deep", members=[{"kind": "service", "service_id": prev}])
        self.assertEqual(st, 400, d)
        self.assertIn("too deep", d["error"])

    def test_the_cap_on_services(self):
        defs = {f"bs_{i}": {"name": f"s{i}", "members": [host("h1")], "rule": {"type": "all"}} for i in range(bz.MAX_SERVICES)}
        api.save(api.BUSINESS_SERVICES_FILE, defs)
        st, d = self.create(name="one too many")
        self.assertEqual(st, 400, d)
        self.assertIn("limit", d["error"])

    def test_delete_removes_state_and_history_and_closes_the_alert(self):
        st, d = self.create(members=[host("h3")])
        sid = d["id"]
        self.sweep()
        self.sweep()
        self.assertEqual(len([e for e in self.events("business_service_down")]), 1)
        self.assertEqual(len([a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]), 1)
        st, r = self.call(api.handle_business_service, sid, m="DELETE", who="platform")
        self.assertEqual((st, r), (200, {"ok": True}))
        self.assertEqual(api.load(api.BUSINESS_SERVICES_FILE), {})
        self.assertNotIn(sid, (api.load(api.BUSINESS_SERVICE_STATE_FILE) or {}).get("services", {}))
        self.assertNotIn(sid, api.load(api.BUSINESS_SERVICE_HIST_FILE) or {})
        alerts = api.load(api.ALERTS_FILE)["alerts"]
        self.assertTrue(alerts and all(a.get("resolved_at") and a.get("resolved_by") == "service-deleted" for a in alerts))
        self.assertEqual(self.call(api.handle_business_service, sid, m="GET", who="platform")[0], 404)

    def test_a_service_another_one_holds_cannot_be_deleted(self):
        _, a = self.create(name="A")
        _, b = self.create(name="B", members=[{"kind": "service", "service_id": a["id"]}])
        st, d = self.call(api.handle_business_service, a["id"], m="DELETE", who="platform")
        self.assertEqual(st, 409, d)
        self.assertIn("B", d["error"])
        self.assertIn("A", self.listing())

    def test_an_unknown_id_is_not_found(self):
        for meth in ("GET", "PUT", "DELETE"):
            self.assertEqual(self.call(api.handle_business_service, "bs_nope", m=meth, who="platform", body={"name": "x"})[0], 404, meth)

    def test_the_wrong_verb(self):
        self.assertEqual(self.call(api.handle_business_services, m="DELETE", who="platform")[0], 405)
        self.assertEqual(self.call(api.handle_business_service, "x", m="PATCH", who="platform")[0], 405)


class TestWhoSeesWhat(_Svc):

    def test_a_scoped_role_sees_only_services_of_hosts_it_can_see(self):
        self.create(name="Mine", members=[host("h1")])
        self.create(name="Theirs", members=[host("h1"), host("h3")])       # h3 is group g2
        self.assertEqual(sorted(self.listing("dscoped")), ["Mine"])
        self.assertEqual(sorted(self.listing("platform")), ["Mine", "Theirs"])

    def test_a_service_that_holds_a_hidden_service_is_hidden_too(self):
        _, inner = self.create(name="Inner", members=[host("h3")])
        self.create(name="Outer", members=[host("h1"), {"kind": "service", "service_id": inner["id"]}])
        self.assertEqual(sorted(self.listing("dscoped")), [])

    def test_a_hidden_service_answers_not_found(self):
        _, d = self.create(name="Theirs", members=[host("h3")])
        self.assertEqual(self.call(api.handle_business_service, d["id"], m="GET", who="dscoped")[0], 404)

    def test_the_operator_sees_a_tenants_host_and_a_user_of_the_default_tenant_does_not(self):
        """The platform operator sees the whole estate, so it may build a service over a customer's host. A viewer of the
        default tenant sees the default tenant's hosts only, so the service is not theirs to see."""
        st, d = self.create(name="Customer app", members=[host("h1"), host("devB")], who="platform")
        self.assertEqual(st, 201, d)
        self.assertIn("Customer app", self.listing("platform"))
        self.assertNotIn("Customer app", self.listing("dviewer"))
        self.assertEqual(self.call(api.handle_business_service, d["id"], m="GET", who="dviewer")[0], 404)

    def test_a_tenant_user_never_reaches_the_handlers(self):
        """The routes are in _OPERATOR_ORG_ROUTES: the dispatcher refuses every user outside the organisation that runs the
        installation before a handler runs."""
        for path in ("/api/business-services", "/api/business-services/bs_1", "/api/business-services/impact"):
            self.assertIsNotNone(api._operator_org_route(path), path)

    def test_the_impact_of_a_host(self):
        _, a = self.create(name="DB", members=[host("h2"), host("h3")], rule={"type": "any"})
        _, b = self.create(name="Shop", members=[{"kind": "service", "service_id": a["id"]}, host("h1")])
        self.create(name="Other", members=[host("h1")])
        os.environ["QUERY_STRING"] = "device_id=h2"
        st, d = self.call(api.handle_business_services_impact, m="GET", who="platform")
        os.environ["QUERY_STRING"] = ""
        self.assertEqual(st, 200, d)
        self.assertEqual({(s["name"], s["direct"]) for s in d["services"]}, {("DB", True), ("Shop", False)})
        os.environ["QUERY_STRING"] = "device_id=nope"
        self.assertEqual(self.call(api.handle_business_services_impact, m="GET", who="platform")[0], 404)
        os.environ["QUERY_STRING"] = "device_id=h3"
        self.assertEqual(self.call(api.handle_business_services_impact, m="GET", who="dscoped")[0], 404)
        os.environ["QUERY_STRING"] = ""


class TestTheSweep(_Svc):

    def test_a_service_that_is_ok_from_the_start_tells_nobody(self):
        self.create(members=[host("h1")])
        self.sweep()
        self.assertEqual(self.events(), [])

    def test_a_service_that_starts_broken_is_told_once_after_the_first_read(self):
        self.create(members=[host("h3")])
        self.sweep()
        down = self.events("business_service_down")
        self.assertEqual(len(down), 1)
        self.assertEqual(down[0][1]["state"], "critical")
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.events("business_service_down")), 1)

    def test_a_change_has_to_hold_for_two_reads(self):
        self.create(members=[host("h1")])
        self.sweep()
        self.set_last_seen("h1", 1)                     # h1 goes quiet
        self.sweep()
        self.assertEqual(self.events(), [], "one read of a change is not enough")
        self.set_last_seen("h1", int(time.time()))      # and is back before the second read
        self.sweep()
        self.assertEqual(self.events(), [])
        self.set_last_seen("h1", 1)
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.events("business_service_down")), 1)

    def test_down_then_up_raises_one_alert_and_closes_it(self):
        _, d = self.create(name="Checkout", members=[host("h1")])
        self.sweep()
        self.set_last_seen("h1", 1)
        self.sweep()
        self.sweep()
        alerts = [a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a["event"], a["severity"], a["title"]), ("business_service_down", "critical", "Business service down: Checkout"))
        self.assertEqual((a["payload"]["service_id"], a["payload"]["service_name"]), (d["id"], "Checkout"))
        self.assertIn("web1 (offline)", a["payload"]["detail"])
        self.set_last_seen("h1", int(time.time()))
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.events("business_service_up")), 1)
        api._LOAD_CACHE.clear()
        self.assertTrue(all(x.get("resolved_at") for x in api.load(api.ALERTS_FILE)["alerts"]))

    def test_degraded_is_medium_and_getting_worse_raises_the_same_alert(self):
        self.create(name="DB", members=[host("h2"), host("h3")], rule={"type": "any"})       # h3 is offline: degraded
        self.sweep()
        alerts = [a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]
        self.assertEqual((len(alerts), alerts[0]["severity"], alerts[0]["title"]), (1, "medium", "Business service degraded: DB"))
        self.set_last_seen("h2", 1)                                                          # now both are offline: down
        self.sweep()
        self.sweep()
        alerts = [a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]
        self.assertEqual(len(alerts), 1, "the second failing state joins the open alert")
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_unknown_changes_nothing_and_does_not_recover_a_service(self):
        self.create(name="Mon", members=[{"kind": "monitor", "label": "site"}])
        self.sweep()
        api.save(api.MON_HIST_FILE, {"site": [{"ts": 1, "up": False}]})
        api._LOAD_CACHE.clear()
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.events("business_service_down")), 1)
        api.save(api.MON_HIST_FILE, {})                         # no result at all: unknown
        api._LOAD_CACHE.clear()
        self.sweep()
        self.sweep()
        self.sweep()
        self.assertEqual(self.events("business_service_up"), [])
        self.assertEqual(len(self.events("business_service_down")), 1, "not knowing is not a second failure")
        self.assertEqual(len([a for a in api.load(api.ALERTS_FILE)["alerts"] if not a.get("resolved_at")]), 1)
        # and when the monitor reports again, up, the service is told as recovered
        api.save(api.MON_HIST_FILE, {"site": [{"ts": 9, "up": True}]})
        api._LOAD_CACHE.clear()
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.events("business_service_up")), 1)

    def test_history_keeps_every_change_and_feeds_availability(self):
        _, d = self.create(members=[host("h1")])
        self.sweep()
        self.set_last_seen("h1", 1)
        self.sweep()
        self.sweep()
        self.set_last_seen("h1", int(time.time()))
        self.sweep()
        self.sweep()
        hist = api.load(api.BUSINESS_SERVICE_HIST_FILE)[d["id"]]
        self.assertEqual([h["state"] for h in hist], ["ok", "critical", "ok"])
        st, one = self.call(api.handle_business_service, d["id"], m="GET", who="platform")
        self.assertEqual([h["state"] for h in one["history"]], ["ok", "critical", "ok"][::-1])
        self.assertIsNotNone(one["availability_30d"])

    def test_the_sweep_runs_about_once_a_minute(self):
        self.create(members=[host("h3")])
        api.run_business_services_if_due()
        first = api.load(api.BUSINESS_SERVICE_STATE_FILE)["last_run"]
        api._LOAD_CACHE.clear()
        api.run_business_services_if_due()          # inside the minute: nothing happens
        self.assertEqual(api.load(api.BUSINESS_SERVICE_STATE_FILE)["last_run"], first)

    def test_nothing_to_do_with_no_services(self):
        api.run_business_services_if_due()
        self.assertEqual(api.load(api.BUSINESS_SERVICE_STATE_FILE), {})

    def test_a_deleted_services_state_is_forgotten(self):
        _, d = self.create(members=[host("h1")])
        self.sweep()
        api.save(api.BUSINESS_SERVICES_FILE, {})
        self.sweep()
        self.assertEqual(api.load(api.BUSINESS_SERVICE_STATE_FILE)["services"], {})

    def test_the_sweep_is_registered_with_main_and_the_scheduler(self):
        import scheduler
        self.assertIn("run_business_services_if_due", scheduler.CADENCE)
        src = open(os.path.join(os.path.dirname(api.__file__), "api.py"), encoding="utf-8").read()
        self.assertIn("_safe(run_business_services_if_due,", src)


class TestHostileStores(_Svc):

    def test_a_definition_of_the_wrong_shape_does_not_break_the_page_or_the_sweep(self):
        api.save(api.BUSINESS_SERVICES_FILE, {
            "bs_ok": {"name": "Fine", "members": [host("h1")], "rule": {"type": "all"}},
            "bs_str": {"name": "S", "members": "host", "rule": "any"},
            "bs_none": {"name": None, "members": None, "rule": None},
            "bs_list": ["x"], "bs_num": 5, 7: {"name": "int key"},
            "bs_junk": {"name": ["l"], "members": [None, 5, {"kind": "host"}, {"kind": "host", "device_id": ["d"]}], "rule": [1]}})
        api._LOAD_CACHE.clear()
        rows = self.listing()
        self.assertIn("Fine", rows)
        self.sweep()
        self.sweep()
        self.assertTrue(api.load(api.BUSINESS_SERVICE_STATE_FILE)["services"])

    def test_a_state_store_of_the_wrong_shape_is_replaced(self):
        self.create(members=[host("h3")])
        api.save(api.BUSINESS_SERVICE_STATE_FILE, {"last_run": "x", "services": ["not", "a", "map"]})
        api._LOAD_CACHE.clear()
        self.sweep()
        self.assertIsInstance(api.load(api.BUSINESS_SERVICE_STATE_FILE)["services"], dict)

    def test_a_history_of_the_wrong_shape_is_survived(self):
        _, d = self.create(members=[host("h1")])
        api.save(api.BUSINESS_SERVICE_HIST_FILE, {d["id"]: "nope"})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.call(api.handle_business_service, d["id"], m="GET", who="platform")[0], 200)
        self.set_last_seen("h1", 1)
        self.sweep()
        self.sweep()


class TestWiring(unittest.TestCase):

    def test_the_events_are_in_the_registry_as_a_pair(self):
        reg = api.EVENT_REGISTRY
        self.assertIsNone(reg["business_service_down"]["severity"])
        self.assertEqual(reg["business_service_up"]["resolves"], ("business_service_down",))
        self.assertEqual(api._ALERT_RECOVER["business_service_up"], "business_service_down")
        self.assertIn("service_id", api._ALERT_IDENTITY_FIELDS)
        self.assertIn(("business_service", "Business service degraded / down", "operational"), api.CHANNEL_KIND_DEFS)

    def test_the_messages(self):
        down = api._webhook_message("business_service_down", {"service_name": "Checkout", "state": "critical", "parts": 3, "parts_ok": 1,
                                                              "detail": "db1 (offline)"})
        self.assertEqual(down, 'Business service "Checkout" is DOWN (1 of 3 parts up) — db1 (offline)')
        self.assertIn("degraded", api._webhook_message("business_service_down", {"service_name": "C", "state": "warning"}))
        self.assertEqual(api._webhook_message("business_service_up", {"service_name": "Checkout"}), 'Business service "Checkout" is up again')

    def test_the_routes(self):
        exact = api._build_exact_routes()
        for key in (("GET", "/api/business-services"), ("POST", "/api/business-services"), ("GET", "/api/business-services/impact")):
            self.assertIn(key, exact)
        pats = [(ms, a, n) for kind, ms, a, b, n, _src in api._PATTERN_ROUTE_DEFS if n == "handle_business_service"]
        self.assertEqual(sorted(m for ms, _a, _n in pats for m in ms), ["DELETE", "GET", "PUT"])


if __name__ == "__main__":
    unittest.main()
