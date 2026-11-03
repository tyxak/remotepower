#!/usr/bin/env python3
"""7.4.9: an alert can be assigned to a person, who is told, and the inbox filters on it.

The inbox knew who acknowledged an alert and nothing about who was dealing with it, so on a team two people looked at
the same alert or both assumed the other one was. POST /api/alerts/<id>/assign hands it to an account, an empty name takes
it back, GET /api/alerts?assigned=me|none|<name> filters on it.

Everything runs through the real handlers with the tenancy switch on. The assignee is not the caller, so the checks that
matter are the ones on the assignee: an alert of another tenant's host must not be handed to a tenant B account (its title
would reach that tenant), a role scoped to other hosts cannot be given an alert it cannot open, a disabled account is not
an assignee, and the caller still needs the right to act on the alert at all.
"""
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def alert(aid, device_id="devB", **kw):
    a = {"id": aid, "ts": 100, "event": "service_down", "severity": "high", "title": f"title {aid}",
         "device_id": device_id, "device_name": "b1", "payload": {}, "acknowledged_by": None,
         "acknowledged_at": None, "resolved_by": None, "resolved_at": None}
    if not device_id:
        a["device_name"] = ""
    a.update(kw)
    return a


class _Assign(_Base):
    STORES = _Base.STORES + ("ALERTS_FILE", "USER_NOTIFY_FILE", "ROLES_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        users = api.load(api.USERS_FILE)
        users["bviewer"] = {"role": "viewer", "tenant_id": "tenantB"}
        users["badmin2"] = {"role": "admin", "tenant_id": "tenantB"}
        users["bgone"] = {"role": "viewer", "tenant_id": "tenantB", "disabled": True}
        users["bscoped"] = {"role": "ops-group-a", "tenant_id": "tenantB"}
        users["cviewer"] = {"role": "viewer", "tenant_id": "tenantC"}
        users["dviewer"] = {"role": "viewer", "tenant_id": "default"}
        api.save(api.USERS_FILE, users)
        api.save(api.ROLES_FILE, {"roles": [{"name": "ops-group-a", "permissions": [],
                                             "scope": {"type": "groups", "values": ["group-a"]}}]})
        devs = api.load(api.DEVICES_FILE)
        devs["devB"]["group"] = "group-b"
        devs["devB2"] = {"name": "b2", "tenant": "tenantB", "group": "group-a", "token_hash": "x"}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.ALERTS_FILE, {"alerts": [
            alert("a1", "devB"), alert("a2", "devB"), alert("a3", "devC", device_name="c1"),
            alert("a4", "devB2", device_name="b2"), alert("a5", None), alert("a6", "devB", resolved_at=200, resolved_by="x")]})
        api.save(api.USER_NOTIFY_FILE, {})
        self.audits = []
        api.audit_log = lambda *a, **k: self.audits.append(a)
        api._LOAD_CACHE.clear()

    def assign(self, aid, user, who="badmin"):
        return self.call(api.handle_alert_assign, aid, body={"user": user}, who=who)

    def row(self, aid):
        api._LOAD_CACHE.clear()
        return {a["id"]: a for a in api.load(api.ALERTS_FILE)["alerts"]}[aid]

    def listed(self, who, query=""):
        os.environ["QUERY_STRING"] = query
        st, d = self.call(api.handle_alerts_list, m="GET", who=who)
        os.environ["QUERY_STRING"] = ""
        self.assertEqual(st, 200, d)
        return sorted(a["id"] for a in d["alerts"])


class TestAssigning(_Assign):

    def test_it_records_who_to_whom_and_when(self):
        st, d = self.assign("a1", "bviewer")
        self.assertEqual((st, d), (200, {"ok": True, "assigned_to": "bviewer"}))
        r = self.row("a1")
        self.assertEqual((r["assigned_to"], r["assigned_by"]), ("bviewer", "badmin"))
        self.assertGreater(r["assigned_at"], 0)
        self.assertEqual(self.audits[-1][1:3], ("alert_assign", "id=a1 to=bviewer"))

    def test_an_empty_name_takes_it_back(self):
        self.assign("a1", "bviewer")
        st, d = self.assign("a1", "")
        self.assertEqual((st, d["assigned_to"]), (200, None))
        r = self.row("a1")
        self.assertFalse({"assigned_to", "assigned_by", "assigned_at"} & set(r))
        self.assertEqual(self.audits[-1][1], "alert_unassign")

    def test_it_can_be_handed_on(self):
        self.assign("a1", "bviewer")
        self.assign("a1", "badmin2")
        self.assertEqual(self.row("a1")["assigned_to"], "badmin2")

    def test_nothing_else_of_the_alert_changes(self):
        before = self.row("a1")
        self.assign("a1", "bviewer")
        after = {k: v for k, v in self.row("a1").items() if not k.startswith("assigned_")}
        self.assertEqual(after, before)

    def test_a_resolved_alert_keeps_what_it_had(self):
        st, d = self.assign("a6", "bviewer")
        self.assertEqual(st, 409, d)
        self.assertNotIn("assigned_to", self.row("a6"))

    def test_an_unknown_alert_is_not_found(self):
        self.assertEqual(self.assign("nope", "bviewer")[0], 404)

    def test_the_wrong_verb_is_refused(self):
        st, _ = self.call(api.handle_alert_assign, "a1", body={"user": "bviewer"}, m="GET")
        self.assertEqual(st, 405)

    def test_hostile_names_are_refused_not_stored(self):
        for bad in ("nobody", "<script>", "a" * 500, "bviewer\x00", ["bviewer"], {"u": 1}, 7):
            st, d = self.assign("a1", bad)
            self.assertIn(st, (400, 404), (bad, st, d))
            self.assertNotIn("assigned_to", self.row("a1"), bad)

    def test_a_disabled_account_is_not_an_assignee(self):
        st, d = self.assign("a1", "bgone")
        self.assertEqual(st, 404, d)
        self.assertNotIn("assigned_to", self.row("a1"))


class TestTheAssigneeCanSeeTheAlert(_Assign):

    def test_another_tenants_account_is_not_found_for_a_tenant_caller(self):
        st, _ = self.assign("a1", "cviewer")
        self.assertEqual(st, 404)
        self.assertNotIn("assigned_to", self.row("a1"))

    def test_another_tenants_alert_is_not_found(self):
        st, _ = self.assign("a3", "bviewer")
        self.assertEqual(st, 404)
        self.assertNotIn("assigned_to", self.row("a3"))

    def test_the_operator_cannot_hand_a_tenants_alert_to_another_tenant(self):
        """The platform operator sees every alert and every account, so the caller's own gate lets this through. The alert's
        title would reach a tenant that does not own the host."""
        st, d = self.assign("a3", "bviewer", who="platform")
        self.assertEqual(st, 409, d)
        self.assertIn("cannot see", d["error"])
        self.assertNotIn("assigned_to", self.row("a3"))
        # control: the same alert to an account of its own tenant works
        st, _ = self.assign("a3", "cviewer", who="platform")
        self.assertEqual(st, 200)

    def test_an_alert_that_names_no_host_stays_with_the_operator(self):
        st, _ = self.assign("a5", "bviewer", who="platform")
        self.assertEqual(st, 409)
        self.assertEqual(self.assign("a5", "dviewer", who="platform")[0], 200)
        self.assertEqual(self.assign("a5", "platform", who="platform")[0], 200)

    def test_a_role_scoped_to_other_hosts_cannot_be_given_the_alert(self):
        st, d = self.assign("a1", "bscoped")          # devB is group-b; the role sees group-a
        self.assertEqual(st, 409, d)
        self.assertEqual(self.assign("a4", "bscoped")[0], 200)     # devB2 is group-a

    def test_with_tenancy_off_the_tenant_test_is_not_made(self):
        self.tenancy(False)
        self.assertEqual(self.assign("a3", "bviewer", who="platform")[0], 200)


class TestWhoMayDoIt(_Assign):

    def test_a_viewer_may_by_default_as_for_acknowledging(self):
        self.assertEqual(self.assign("a1", "bviewer", who="bviewer")[0], 200)

    def test_the_strict_switch_asks_for_an_administrator(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["viewers_can_ack_alerts"] = False
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        st, _ = self.assign("a1", "bviewer", who="bviewer")
        self.assertEqual(st, 403)
        self.assertNotIn("assigned_to", self.row("a1"))
        self.assertEqual(self.assign("a1", "bviewer", who="badmin")[0], 200)

    def test_a_scoped_caller_cannot_assign_an_alert_outside_its_scope(self):
        st, _ = self.assign("a1", "badmin2", who="bscoped")        # devB is group-b
        self.assertEqual(st, 404)

    def test_nobody_signed_in_is_refused(self):
        st, _ = self.call(api.handle_alert_assign, "a1", body={"user": "bviewer"}, who=None)
        self.assertEqual(st, 401)


class TestTheFilter(_Assign):

    def setUp(self):
        super().setUp()
        self.assign("a1", "bviewer")
        self.assign("a2", "badmin")

    def test_me_none_and_a_name(self):
        self.assertEqual(self.listed("bviewer", "status=all&assigned=me"), ["a1"])
        self.assertEqual(self.listed("badmin", "status=all&assigned=me"), ["a2"])
        self.assertEqual(self.listed("badmin", "status=all&assigned=none"), ["a4", "a6"])
        self.assertEqual(self.listed("badmin", "status=all&assigned=bviewer"), ["a1"])
        self.assertEqual(self.listed("badmin", "status=all&assigned=nobody"), [])

    def test_no_filter_lists_everything_the_caller_sees(self):
        self.assertEqual(self.listed("badmin", "status=all"), ["a1", "a2", "a4", "a6"])

    def test_the_filter_does_not_reach_across_tenants(self):
        # tenant C's admin asks for what bviewer holds: it holds nothing of C's
        self.assertEqual(self.listed("cadmin", "status=all&assigned=bviewer"), [])
        self.assertEqual(self.listed("cadmin", "status=all"), ["a3"])

    def test_the_listing_carries_the_assignment(self):
        os.environ["QUERY_STRING"] = "status=all&assigned=me"
        st, d = self.call(api.handle_alerts_list, m="GET", who="bviewer")
        os.environ["QUERY_STRING"] = ""
        self.assertEqual(d["alerts"][0]["assigned_to"], "bviewer")
        self.assertEqual(d["alerts"][0]["assigned_by"], "badmin")


class TestTheNotice(_Assign):
    """The assignee is told on the channels set up under My Account, and only then."""

    def setUp(self):
        super().setUp()
        self.sent = []
        patcher = mock.patch.object(api, "_dispatch_one_webhook", side_effect=lambda *a, **k: self.sent.append((a, k)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def prefs(self, **kw):
        api.save(api.USER_NOTIFY_FILE, {"bviewer": dict({"enabled": True, "webhook_url": "https://chat.example.com/hook"}, **kw)})
        api._LOAD_CACHE.clear()

    def test_the_assignee_is_told_on_their_personal_webhook(self):
        self.prefs()
        self.assign("a1", "bviewer")
        self.assertEqual(len(self.sent), 1)
        args = self.sent[0][0]
        self.assertEqual(args[0], "alert_assigned")
        self.assertEqual(args[1]["url"], "https://chat.example.com/hook")
        self.assertEqual(args[1]["id"], "user:bviewer")
        self.assertIn("badmin assigned you: title a1", args[3])

    def test_nobody_is_told_who_switched_it_off_or_set_nothing_up(self):
        self.assign("a1", "bviewer")                       # no preferences at all
        self.prefs(enabled=False)
        self.assign("a2", "bviewer")
        self.assertEqual(self.sent, [])

    def test_assigning_to_yourself_tells_nobody(self):
        api.save(api.USER_NOTIFY_FILE, {"badmin": {"enabled": True, "webhook_url": "https://chat.example.com/hook"}})
        api._LOAD_CACHE.clear()
        self.assign("a1", "badmin")
        self.assertEqual(self.sent, [])

    def test_taking_it_back_tells_nobody(self):
        self.prefs()
        self.assign("a1", "")
        self.assertEqual(self.sent, [])

    def test_a_failing_channel_does_not_fail_the_assignment(self):
        self.prefs()
        api._dispatch_one_webhook.side_effect = RuntimeError("down")
        st, _ = self.assign("a1", "bviewer")
        self.assertEqual(st, 200)
        self.assertEqual(self.row("a1")["assigned_to"], "bviewer")


class TestWiring(unittest.TestCase):

    def test_the_route_is_registered_for_post_only(self):
        routes = [(m, p, n) for kind, ms, p, suffix, n, _src in api._PATTERN_ROUTE_DEFS if n == "handle_alert_assign" for m in ms]
        self.assertEqual(routes, [("POST", "/api/alerts/", "handle_alert_assign")])

    def test_a_bad_row_is_repaired_by_the_shape_registry(self):
        import store_shapes
        out = store_shapes.normalize("alerts.json", {"alerts": [
            {"id": "x", "assigned_at": "12", "assigned_to": 5},
            {"id": "y", "assigned_at": [1], "assigned_to": ["x"]}]})
        first, second = out["alerts"]
        self.assertEqual(first["assigned_at"], 12)
        self.assertEqual(first["assigned_to"], "5")
        # a list where a time and a name belong is dropped, so the readers' defaults apply
        self.assertNotIn("assigned_at", second)
        self.assertNotIn("assigned_to", second)

    def test_the_inbox_has_the_filter_the_actions_and_the_words(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app-alerts.js").read_text()
        for name in ("assignAlertToMe", "assignAlertTo", "unassignAlert", "alerts-filter-assignee", "assigned="):
            self.assertIn(name, js)
        for name in ("assignAlertToMe", "assignAlertTo", "unassignAlert"):
            self.assertRegex(js, r"(async )?function %s\(" % name)
        i18n = (ROOT / "server" / "html" / "static" / "js" / "i18n.js").read_text()
        for key in ("Assigned to me", "Unassigned", "Assign to me", "Assign…", "Assignment removed"):
            self.assertRegex(i18n, r'\n\s*["\']%s["\']\s*:' % re.escape(key))


if __name__ == "__main__":
    unittest.main()
