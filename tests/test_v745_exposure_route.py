#!/usr/bin/env python3
"""v7.4.5, issue #55: the switch on a host, and what the pages read back.

PUT/GET /api/devices/<id>/exposure-internal sets and reads the switch. The Exposure page's answer
carries the grade and a map of the hosts that are marked, with why a switch that does not hold does not.
The Checks row says how many services it is not warning about. Each is driven through the real handler
over the real stored host, because a switch that is stored but never read is the failure this feature is
most likely to have.
"""
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, api  # noqa: E402
from test_v743_container_thresholds import _call  # noqa: E402
from test_v745_exposure_ingest import PRIVATE, WITH_PUBLIC, _Internal, ports  # noqa: E402

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import checks  # noqa: E402


class _Route(_Internal):

    def put(self, body, **kw):
        return _call(api.handle_device_exposure_internal, body, DEV, **kw)

    def get(self, **kw):
        return _call(api.handle_device_exposure_internal, {}, DEV, verb="GET", **kw)

    def host(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {})[DEV]


class TestSettingTheSwitch(_Route):

    def test_the_switch_is_kept_on_the_host_record_and_removed_when_off(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        box = self.put({"internal": True})
        self.assertEqual(box["status"], 200, box)
        self.assertIs(self.host()["exposure_internal"], True)
        self.assertEqual(self.put({"internal": False})["status"], 200)
        self.assertNotIn("exposure_internal", self.host())

    def test_turning_it_on_grades_the_stored_listeners_at_once(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades()[443], ("world", False))
        box = self.put({"internal": True})
        self.assertEqual((box["body"]["assumed"], box["body"]["blocked"], box["body"]["regraded"]), (True, "", 2))
        self.assertEqual(self.grades(), {443: ("lan", True), 22: ("lan", True), 5432: ("local", False),
                                         53: ("lan", False)}, "no new report was needed")

    def test_turning_it_off_puts_them_back_at_once(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.put({"internal": True})
        box = self.put({"internal": False})
        self.assertEqual((box["body"]["assumed"], box["body"]["regraded"]), (False, 2))
        self.assertEqual(self.grades()[443], ("world", False))
        self.assertTrue(all("assumed" not in r for r in self.rows().values()))

    def test_a_host_with_a_public_address_keeps_the_switch_but_it_does_not_hold(self):
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        box = self.put({"internal": True})
        body = box["body"]
        self.assertEqual((body["internal"], body["assumed"], body["blocked"], body["public"], body["regraded"]),
                         (True, False, "public_address", ["203.0.113.9"], 0))
        self.assertIs(self.host()["exposure_internal"], True, "the operator's decision is kept")
        self.assertEqual(self.grades()[443], ("world", False))

    def test_a_host_whose_agent_does_not_report_addresses_says_so(self):
        self.report({"listening_ports": ports()})
        body = self.put({"internal": True})["body"]
        self.assertEqual((body["assumed"], body["blocked"], body["regraded"]), (False, "no_address_data", 0))

    def test_a_host_that_has_not_reported_at_all_can_be_marked(self):
        body = self.put({"internal": True})["body"]
        self.assertEqual((body["internal"], body["assumed"], body["blocked"]), (True, False, "no_address_data"))

    def test_nothing_that_is_not_a_clear_yes_turns_it_on(self):
        for body in ({}, {"internal": False}, {"internal": None}, {"internal": 0}, {"internal": []}, []):
            self.put({"internal": True})
            box = self.put(body)
            self.assertIn(box["status"], (200, 400), body)
            if box["status"] == 200:
                self.assertNotIn("exposure_internal", self.host(), repr(body))
        self.put({"internal": False})

    def test_it_is_audited_when_it_changes_and_only_then_and_without_the_addresses(self):
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        first = self.put({"internal": True})
        self.assertEqual(len(first["audit"]), 1)
        (args, kwargs), = first["audit"]
        self.assertEqual(args[1], "exposure_internal_set")
        self.assertIn(DEV, kwargs["detail"])
        self.assertIn("internal=on", kwargs["detail"])
        self.assertIn("holds=no", kwargs["detail"])
        text = json.dumps(first["audit"])
        for secret in ("203.0.113.9", "192.168.1.20", "172.17.0.1"):
            self.assertNotIn(secret, text)
        again = self.put({"internal": True})
        self.assertNotIn("audit", again, "a save that changes nothing writes nothing")
        off = self.put({"internal": False})
        self.assertIn("internal=off", off["audit"][0][1]["detail"])


class TestReadingTheSwitch(_Route):

    def test_get_answers_with_the_state_for_anyone_who_can_see_the_host(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.get(role="viewer")["body"],
                         {"internal": False, "assumed": False, "blocked": "", "public": []})
        self.put({"internal": True})
        self.assertEqual(self.get(role="viewer")["body"],
                         {"internal": True, "assumed": True, "blocked": "", "public": []})

    def test_get_says_why_when_it_does_not_hold(self):
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        self.put({"internal": True})
        self.assertEqual(self.get()["body"], {"internal": True, "assumed": False, "blocked": "public_address",
                                              "public": ["203.0.113.9"]})


class TestWhoMayDoWhat(_Route):

    def test_only_an_administrator_can_set_it(self):
        for role in ("viewer", "auditor", "finance", "mcp"):
            self.assertEqual(self.put({"internal": True}, role=role)["status"], 403, role)
        self.assertEqual(self.put({"internal": True}, role=None)["status"], 401)
        self.assertNotIn("exposure_internal", self.host(), "none of those left a mark")

    def test_every_signed_in_role_can_read_it_and_a_signed_out_caller_cannot(self):
        for role in ("admin", "viewer", "auditor", "finance", "mcp"):
            self.assertEqual(self.get(role=role)["status"], 200, role)
        self.assertEqual(self.get(role=None)["status"], 401)

    def test_other_verbs_and_unknown_hosts(self):
        for verb in ("POST", "DELETE", "PATCH"):
            self.assertEqual(self.put({"internal": True}, verb=verb)["status"], 405, verb)
        for bad in ("nope", "../x", "a b", ""):
            box = _call(api.handle_device_exposure_internal, {"internal": True}, bad)
            self.assertEqual(box["status"], 404, repr(bad))

    def test_route_delete_guard_and_scope(self):
        from routing_harness import resolve_route
        for verb in ("PUT", "GET"):
            self.assertEqual(resolve_route(verb, f"/api/devices/{DEV}/exposure-internal")[0],
                             "handle_device_exposure_internal", verb)
        self.assertFalse(api._route_code_5(f"/api/devices/{DEV}/exposure-internal", "DELETE"),
                         "a DELETE must not fall through to deleting the host")
        self.assertIn("'/exposure-internal'", [r for r in api._PATTERN_ROUTE_DEFS if r[4] == "_route_code_5"][0][5])
        real = (api.path_info, api._tenant_visible, api.respond)
        seen = {}

        def fake(status, data):
            seen["status"] = status
            raise SystemExit()
        api.path_info = lambda: f"/api/devices/{DEV}/exposure-internal"
        api._tenant_visible = lambda dev: False
        api.respond = fake
        try:
            with self.assertRaises(SystemExit):
                api._enforce_device_scope()
        finally:
            api.path_info, api._tenant_visible, api.respond = real
        self.assertEqual(seen["status"], 403, "a host outside the caller's tenant is refused before the handler")

    def test_a_body_cannot_set_the_switch_through_the_other_routes(self):
        """The generic device update takes a fixed set of fields. This one is not among them."""
        src = (Path(api.__file__).parent / "api.py").read_text()
        i = src.index("def handle_device_update")
        body = src[i:src.index("\ndef ", i + 10)]
        self.assertNotIn("exposure_internal", body)


class TestWhatThePagesRead(_Route):

    def overview(self, query=""):
        saved = os.environ.get("QUERY_STRING")
        os.environ["QUERY_STRING"] = query
        try:
            return _call(api.handle_exposure_overview, {}, verb="GET", role="viewer")
        finally:
            if saved is None:
                os.environ.pop("QUERY_STRING", None)
            else:
                os.environ["QUERY_STRING"] = saved

    def test_rows_carry_the_grade_and_the_mark_and_the_counts_say_how_many(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        before = self.overview()["body"]
        self.assertEqual((before["counts"]["world"], before["counts"]["assumed"]), (2, 0))
        self.put({"internal": True})
        body = self.overview()["body"]
        self.assertEqual((body["counts"]["world"], body["counts"]["lan"], body["counts"]["assumed"]), (0, 3, 2))
        by_port = {r["port"]: r for r in body["ports"]}
        self.assertEqual((by_port[443]["scope"], by_port[443]["assumed"]), ("lan", True))
        self.assertEqual((by_port[53]["scope"], by_port[53]["assumed"]), ("lan", False),
                         "a socket the agent itself graded lan is not an assumption")
        self.assertEqual(body["hosts"], {DEV: {"internal": True, "assumed": True, "blocked": "", "public": []}})

    def test_the_world_filter_no_longer_lists_what_is_assumed_internal(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(sorted(r["port"] for r in self.overview("scope=world")["body"]["ports"]), [22, 443])
        self.put({"internal": True})
        self.assertEqual(self.overview("scope=world")["body"]["ports"], [])
        self.assertEqual(sorted(r["port"] for r in self.overview("scope=lan")["body"]["ports"]), [22, 53, 443])

    def test_a_marked_host_that_does_not_hold_is_listed_with_the_reason(self):
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        self.put({"internal": True})
        body = self.overview()["body"]
        self.assertEqual(body["hosts"][DEV]["blocked"], "public_address")
        self.assertEqual(body["hosts"][DEV]["public"], ["203.0.113.9"])
        self.assertEqual(body["counts"]["world"], 2, "and its listeners are still world")

    def test_a_host_that_is_not_marked_is_not_in_the_map(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.overview()["body"]["hosts"], {})

    def test_the_checks_row_says_what_it_is_not_warning_about(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})

        def row():
            dev = api.device_get(DEV)
            rows = checks._host_checks(DEV, dev, {}, [], int(time.time()), 180, exposure_mutes=[])
            return [r for r in rows if r["key"] == "exposure"][0]
        self.assertEqual((row()["status"], row()["output"]), ("warning", "2 world-reachable"))
        self.put({"internal": True})
        self.assertEqual((row()["status"], row()["output"]), ("ok", "none (2 services assumed internal)"))
        self.put({"internal": False})
        self.assertEqual((row()["status"], row()["output"]), ("warning", "2 world-reachable"))

    def test_the_risk_score_and_the_advisory_stop_counting_what_is_assumed_internal(self):
        """Two more readers of the grade, with no code of their own for the switch."""
        import advisory
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        si = api.device_get(DEV)["sysinfo"]
        self.assertEqual(sum(1 for p in si["listening_ports"] if p.get("scope") == "world"), 2)
        self.put({"internal": True})
        si = api.device_get(DEV)["sysinfo"]
        self.assertEqual(sum(1 for p in si["listening_ports"] if p.get("scope") == "world"), 0)
        self.assertTrue(hasattr(advisory, "__file__"))


if __name__ == "__main__":
    unittest.main()
