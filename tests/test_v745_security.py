#!/usr/bin/env python3
"""v7.4.5 security review: what it found, driven for real and watched failing first, and the properties the review
checked and found to hold, so a later change cannot take them away without a test saying so.

Found
  1. PUT /api/devices/<id>/exposure-internal answered 200 and turned the switch OFF for a request that did not say
     what it wanted (an empty body, a broken one, null, a list). It fails closed, but a request that does not say
     what it wants must not change a host's grade, so the route now answers 400 unless `internal` is true or false.
     (test_v745_exposure_route holds the refusals; the cases here are the ones the review ran over HTTP.)

Held (checked, and pinned here)
  * Only an administrator sets the switch, a tenant administrator only on the tenant's own hosts, and a role that
    holds every action permission is refused. The Exposure answer shows a tenant its own hosts and no others, in the
    rows, the counts and the map of marked hosts.
  * A host cannot set its own switch or its own mark, and a hostile report of addresses or ports leaves stored rows
    that are whitelisted, bounded and graded by the one rule.
  * Stored values the code did not write are read without an error by every reader of the new fields.
  * The addresses the corpus carries are redacted for the assistant when the install does not send addresses.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, api  # noqa: E402
from test_v743_container_thresholds import _call  # noqa: E402
from test_v743_security import _Tenancy  # noqa: E402
from test_v745_exposure_ingest import PRIVATE, WITH_PUBLIC, _Internal, ports  # noqa: E402

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import checks  # noqa: E402
import exposure_scope as ex  # noqa: E402
import rag_index  # noqa: E402


class _TwoTenants(_Tenancy):

    def setUp(self):
        super().setUp()
        for h, addrs in (("hostA", ["192.168.1.20"]), ("hostB", ["10.1.1.5", "203.0.113.9"])):
            with api._LockedUpdate(api.DEVICES_FILE) as devs:
                devs[h]["sysinfo"] = {"listening_ports": ports(), "host_addresses": addrs}
                devs[h]["exposure_internal"] = True
                ex.apply(True, devs[h]["sysinfo"])
        api._LOAD_CACHE.clear()

    def gate(self, user, host, verb="PUT"):
        """The pre-dispatch check every /api/devices/<id>/ route runs, with the caller's real tenant."""
        saved = (api.path_info, api.verify_token, api.get_token_from_request, api.respond, api.method)
        seen = {}

        def fake(status, data=None):
            seen["status"] = status
            raise SystemExit(0)
        role = api.load(api.USERS_FILE)[user]["role"]
        api.path_info = lambda: f"/api/devices/{host}/exposure-internal"
        api.verify_token = lambda t: (user, role)
        api.get_token_from_request = lambda: "t"
        api.method = lambda: verb
        api.respond = fake
        try:
            api._enforce_device_scope()
        except SystemExit:
            pass
        finally:
            api.path_info, api.verify_token, api.get_token_from_request, api.respond, api.method = saved
        return seen.get("status", 200)

    def overview(self, user):
        box = self.as_user(user, api.handle_exposure_overview, {}, "GET")
        self.assertEqual(box["status"], 200, box)
        return box["body"]


class TestTheTenantBoundary(_TwoTenants):

    def test_a_tenant_administrator_reaches_the_tenants_own_host_and_no_other(self):
        self.assertEqual(self.gate("tadmin", "hostA"), 200)
        self.assertEqual(self.gate("tadmin", "hostB"), 403)
        self.assertEqual(self.gate("tadmin", "hostB", "GET"), 403)
        self.assertEqual(self.gate("tviewer", "hostB", "GET"), 403)
        self.assertEqual(self.gate("alice", "hostB"), 200, "the platform operator reaches both")

    def test_the_exposure_answer_shows_a_tenant_its_own_hosts_only(self):
        mine = self.overview("tadmin")
        self.assertEqual({r["device_id"] for r in mine["ports"]}, {"hostA"})
        self.assertEqual(set(mine["hosts"]), {"hostA"})
        self.assertEqual(mine["counts"]["assumed"], 2)
        self.assertEqual(mine["counts"]["world"], 0, "hostB's two world sockets are not counted for tenant A")
        viewer = self.overview("tviewer")
        self.assertEqual(set(viewer["hosts"]), {"hostA"})
        every = self.overview("alice")
        self.assertEqual(set(every["hosts"]), {"hostA", "hostB"})
        self.assertEqual(every["hosts"]["hostB"]["blocked"], "public_address")
        self.assertEqual(every["hosts"]["hostB"]["public"], ["203.0.113.9"])
        self.assertNotIn("203.0.113.9", json.dumps(mine), "tenant B's public address is not in tenant A's answer")

    def test_the_other_tenants_host_is_not_changed_by_a_tenant_administrator(self):
        """The gate is what refuses it, and the handler is not reached. A direct call, which skips the gate,
        shows what the gate is for: the handler itself does not look at tenants."""
        before = json.dumps(api.load(api.DEVICES_FILE)["hostB"], sort_keys=True)
        self.assertEqual(self.gate("tadmin", "hostB"), 403)
        self.assertEqual(json.dumps(api.load(api.DEVICES_FILE)["hostB"], sort_keys=True), before)


class TestWhoMaySetIt(_TwoTenants):

    def put_as(self, role, host="hostA", body=None):
        return _call(api.handle_device_exposure_internal, body or {"internal": False}, host, role=role)

    def test_a_role_that_holds_every_action_permission_is_still_refused(self):
        api.save(api.ROLES_FILE, {"roles": [{"name": "ops", "permissions": sorted(api._RBAC_PERMS), "scope": {"type": "all"}}]})
        api._LOAD_CACHE.clear()
        for role in ("viewer", "auditor", "finance", "mcp", "ops", "no-such-role"):
            box = self.put_as(role)
            self.assertEqual(box["status"], 403, role)
        self.assertIs(api.load(api.DEVICES_FILE)["hostA"].get("exposure_internal"), True, "none of them changed it")
        self.assertEqual(self.put_as("admin")["status"], 200)


class TestAHostCannotSetItsOwnGrade(_Internal):

    def test_a_report_that_claims_the_switch_or_the_mark_changes_neither(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE, "exposure_internal": True},
                    exposure_internal=True, internal=True)
        self.assertNotIn("exposure_internal", api.load(api.DEVICES_FILE)[DEV])
        rows = [dict(r, assumed=True) for r in ports()]
        self.report({"listening_ports": rows, "host_addresses": PRIVATE})
        self.assertTrue(all("assumed" not in r for r in self.rows().values()), "the mark is derived, never reported")
        self.assertEqual(self.grades()[443], ("world", False))

    def test_a_marked_host_cannot_make_a_row_look_assumed_that_the_rule_would_not(self):
        self.switch(True)
        rows = [dict(proto="tcp", port=9, process="x", addr="127.0.0.1", scope="local", assumed=True),
                dict(proto="tcp", port=10, process="x", addr="10.0.0.2", scope="lan", assumed=True)]
        self.report({"listening_ports": rows, "host_addresses": PRIVATE})
        self.assertEqual(self.grades(), {9: ("local", False), 10: ("lan", False)})


class TestHostileReports(_Internal):

    JUNK = (["192.168.1.20"], ["192.168.1.20", "203.0.113.9"], ["fd00::1", "fe80::1%eth0"], [], None, "x", 5, True, {"a": 1},
            [None], [1, 2], [["10.0.0.1"]], ["<img src=x onerror=1>"], ["10.0.0.1", "<svg/onload=1>"], ["A" * 100000],
            ["\x00"], ["10.0.0.1/24"], ["::ffff:10.0.0.5"], [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(65)],
            [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(64)], [10 ** 400], [float("nan")], ["0.0.0.0"],
            ["2002:c000:204::1"], ["fe80::1%" + "<b>" * 50])

    def invariants(self, label):
        si = self.stored()
        for r in si.get("listening_ports") or []:
            self.assertLessEqual(set(r), {"proto", "port", "process", "addr", "scope", "assumed"}, label)
            self.assertIn(r.get("scope"), ("local", "lan", "world", ""), label)
            self.assertFalse(r.get("assumed") and r.get("scope") != "lan", label)
        addrs = si.get("host_addresses") or []
        self.assertLessEqual(len(addrs), ex.MAX_ADDRESSES, label)
        for a in addrs:
            self.assertIsNotNone(ex._parse(a), (label, a[:30]))
            self.assertEqual(a, str(ex._parse(a)), "stored in its normal form")
        if any(r.get("assumed") for r in si.get("listening_ports") or []):
            self.assertEqual(ex.assess(addrs)[0], "private", (label, "assumed with an address that is not private"))

    def test_any_list_of_addresses_leaves_stored_rows_the_rule_would_write(self):
        self.switch(True)
        for junk in self.JUNK:
            self.report({"listening_ports": ports(), "host_addresses": junk})
            self.invariants(repr(junk)[:40])
        self.assertGreater(len(self.JUNK), 20, "the population is not empty")

    def test_hostile_rows_are_whitelisted_and_bounded(self):
        self.switch(True)
        rows = [dict(proto="tcp", port=1, process="p", addr="0.0.0.0", scope="world", assumed=True),
                dict(proto="tcp", port=3, process="<img src=x onerror=1>", addr="0.0.0.0", scope="internal"),
                dict(proto="tcp", port=4, process="p", addr="0.0.0.0", scope=["world"]),
                dict(proto="tcp", port=5, process="p", addr="0.0.0.0", scope=None, extra="y"),
                dict(proto="tcp", port=70000, process="p", addr="0.0.0.0", scope="world"),
                dict(proto="tcp", port="80", process="p", addr="0.0.0.0", scope="world")]
        self.report({"listening_ports": rows + [dict(rows[0], port=i) for i in range(100, 600)], "host_addresses": PRIVATE})
        self.invariants("hostile rows")
        self.assertLessEqual(len(self.stored()["listening_ports"]), 80, "the report is capped")

    def test_the_fields_an_agent_may_leave_out_do_not_get_a_stale_grade(self):
        self.switch(True)
        merged = 0
        for omitted in ({"listening_ports": "h"}, {"x" * 5000: 1}, {"listening_ports": {"a": 1}}, "x", ["listening_ports"], None,
                        {"packages": 1, "listening_ports": 1, "network": 1}):
            self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
            self.assertEqual(self.grades()[443], ("lan", True))
            self.report({"host_addresses": WITH_PUBLIC}, sysinfo_omitted=omitted)
            self.invariants("omitted " + repr(omitted)[:30])
            if isinstance(omitted, dict) and "listening_ports" in omitted:
                merged += 1
                self.assertEqual(self.grades()[443], ("world", False),
                                 "the rows came back from the store, and a public address in this report ended the grade")
            else:
                self.assertNotIn(443, self.grades(), "nothing was merged, so the record carries no ports")
        self.assertEqual(merged, 3)


class TestStoredValuesTheCodeDidNotWrite(_Internal):
    """A hand-edited store, an import or an older build can leave anything behind. Every reader of the new fields
    has to read it without an error."""

    ODD_SWITCH = ("yes", 1, [1], {"a": 1}, "false", None)
    ODD_ADDRS = ("10.0.0.5", 5, None, {"a": "10.0.0.5"}, [5, None, "x"], [["10.0.0.5"]], ["<img src=x>"], [10 ** 400], [])
    ODD_ROWS = ([{"scope": "world", "assumed": "yes"}], [{"scope": ["world"], "assumed": [1]}], [{}],
                [{"port": "x", "scope": "lan", "assumed": {"a": 1}}], [{"scope": None, "assumed": 0}])
    NOT_A_LIST_OF_MAPS = ("x", 5, None, [None, 5, "x"], {"a": 1}, True)

    def plant(self, switch, addrs, rows):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["exposure_internal"] = switch
            devs[DEV]["sysinfo"] = {"listening_ports": rows, "host_addresses": addrs}
        api._LOAD_CACHE.clear()

    def read_everything(self):
        dev = api.device_get(DEV)
        self.assertIn(_call(api.handle_exposure_overview, {}, verb="GET", role="admin")["status"], (200,))
        self.assertEqual(_call(api.handle_device_exposure_internal, {}, DEV, verb="GET", role="viewer")["status"], 200)
        checks._host_checks(DEV, dev, {}, [], int(time.time()), 180, exposure_mutes=[])
        api._device_risk(DEV, dev, {}, {}, {}, int(time.time()), 180)
        rag_index.build_live_state_corpus([dev], now=int(time.time()))
        ex.apply(dev.get("exposure_internal"), dev.get("sysinfo"))
        ex.host_state(dev.get("exposure_internal"), (dev.get("sysinfo") or {}).get("host_addresses"))

    def test_no_reader_raises_on_any_shape(self):
        count = 0
        for sw in self.ODD_SWITCH + (True, False):
            for addrs in self.ODD_ADDRS:
                for rows in self.ODD_ROWS + (ports(),):
                    self.plant(sw, addrs, rows)
                    self.read_everything()
                    count += 1
        self.assertGreater(count, 200)

    def test_the_exposure_page_and_the_checks_row_skip_a_port_list_that_is_not_a_list_of_maps(self):
        """Older than this release: the ingest never writes one, a hand-edited or imported store could, and the
        Exposure answer and the Checks row (the two pages this release changed) raised on it."""
        for junk in self.NOT_A_LIST_OF_MAPS:
            self.plant(True, PRIVATE, junk)
            overview = _call(api.handle_exposure_overview, {}, verb="GET", role="admin")
            self.assertEqual(overview["status"], 200, repr(junk))
            self.assertEqual(overview["body"]["ports"], [], repr(junk))
            checks._host_checks(DEV, api.device_get(DEV), {}, [], int(time.time()), 180, exposure_mutes=[])

    def test_a_switch_that_is_not_a_real_true_is_off_everywhere(self):
        for odd in self.ODD_SWITCH:
            self.plant(odd, PRIVATE, ports())
            state = json.loads(json.dumps(_call(api.handle_device_exposure_internal, {}, DEV, verb="GET", role="viewer")["body"]))
            self.assertEqual((state["internal"], state["assumed"]), (False, False), repr(odd))


class TestTheAddressesAreRedactedForTheAssistant(unittest.TestCase):
    """The corpus carries a host's addresses so a question about them can be answered. At chat time the assistant
    sees an address only when the install sends addresses; the redaction has to catch the IPv6 ones this adds."""

    def text(self):
        now = int(time.time())
        dev = {"id": "d1", "name": "web01", "os": "linux", "last_seen": now, "monitored": True, "exposure_internal": True,
               "sysinfo": {"host_addresses": ["192.168.1.20", "203.0.113.9", "2a01:4f8::5", "fd00::1"]}}
        docs = rag_index.build_live_state_corpus([dev], now=now)
        return "\n".join(d.get("text", "") for d in docs)

    def test_with_addresses_off_none_reaches_the_assistant(self):
        import ai_provider
        text = self.text()
        for a in ("192.168.1.20", "203.0.113.9", "2a01:4f8::5", "fd00::1"):
            self.assertIn(a, text, "the control: the corpus does hold the address")
            self.assertNotIn(a, ai_provider.redact(text, {"send_ips": False}), a)

    def test_with_addresses_on_they_pass(self):
        import ai_provider
        out = ai_provider.redact(self.text(), {"send_ips": True})
        self.assertIn("2a01:4f8::5", out)


if __name__ == "__main__":
    unittest.main()
