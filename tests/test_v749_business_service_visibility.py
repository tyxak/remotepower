#!/usr/bin/env python3
"""7.4.9: who may read what a business service raises, and who is sent it.

The authorization matrix found it on the final tree: the Business Services page hid a service that holds a host the
reader cannot see, but the alert and the activity entry the same service raises carry the names of its parts in their text,
and the readers of those did not apply the rule. An event that names no host is the installation's, so a tenant's user
should not have read it at all, yet the Home feed kept such an event for everybody, and so did the personal notification
and the browser push (the last of which was sent to every subscriber, tenant or not). A tenant's dashboard showed another
tenant's host names, and a viewer of the installation's own organisation read the names of hosts it cannot see.

The rule, in one place for the request side (business_service_event_visible) and one for stored accounts
(_account_may_see): the platform operator reads everything; under tenancy these rows belong to the organisation that runs
the installation; and every host a row names has to be one the reader can see. Everything runs through the real
recorders and handlers. Each reader is driven as four callers whose answers differ: the platform operator, a viewer of the
installation's own organisation, a viewer scoped to one group, and a tenant's administrator.
"""
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

import webpush  # noqa: E402


class _Vis(_Base):
    STORES = _Base.STORES + ("BUSINESS_SERVICES_FILE", "BUSINESS_SERVICE_STATE_FILE", "BUSINESS_SERVICE_HIST_FILE",
                             "ALERTS_FILE", "FLEET_EVENTS_FILE", "MON_HIST_FILE", "SERVICES_FILE", "CONTAINERS_FILE",
                             "CUSTOM_SCRIPTS_FILE", "ROLES_FILE", "USER_NOTIFY_FILE", "PUSH_SUBS_FILE",
                             "ALERT_MUTES_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        now = int(time.time())
        users = api.load(api.USERS_FILE)
        users["oviewer"] = {"role": "viewer", "tenant_id": "default"}
        users["gviewer"] = {"role": "ops-g1", "tenant_id": "default"}
        users["off"] = {"role": "viewer", "tenant_id": "default", "disabled": True}
        api.save(api.USERS_FILE, users)
        api.save(api.ROLES_FILE, {"roles": [{"name": "ops-g1", "permissions": [],
                                             "scope": {"type": "groups", "values": ["g1"]}}]})
        api.save(api.DEVICES_FILE, {
            "opsA": {"name": "OPS-ALPHA", "tenant": "default", "token_hash": "x", "last_seen": now, "group": "g1"},
            "opsB": {"name": "OPS-BRAVO", "tenant": "default", "token_hash": "x", "last_seen": now, "group": "g2"},
            "devB": {"name": "TENANT-B-HOST", "tenant": "tenantB", "token_hash": "x", "last_seen": now},
            "devC": {"name": "TENANT-C-HOST", "tenant": "tenantC", "token_hash": "x", "last_seen": now}})
        for f in (api.BUSINESS_SERVICES_FILE, api.BUSINESS_SERVICE_STATE_FILE, api.BUSINESS_SERVICE_HIST_FILE):
            api.save(f, {})
        api.save(api.ALERTS_FILE, {"alerts": []})
        api.save(api.FLEET_EVENTS_FILE, {"events": []})
        self._fns2 = {n: getattr(api, n) for n in ("_dispatch_one_webhook", "_webpush_cfg", "_url_targets_local_or_meta")}
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._fns2.items():
            setattr(api, n, v)
        super().tearDown()

    def call_etag(self, fn, who):
        """A conditional GET raises HTTPError itself instead of calling respond(), so read the answer from the exception."""
        self.who, self.body, self.m = who, {}, "GET"
        self.cap.clear()
        api._LOAD_CACHE.clear()
        try:
            fn()
        except api.HTTPError as e:
            return e.status, e.body
        except SystemExit:
            pass
        return self.cap.get("status"), (self.cap.get("data") or {})

    # what the sweep fires, for a service whose detail names these hosts
    def fire_down(self, name, hosts, state="critical"):
        names = [(api.load(api.DEVICES_FILE).get(h) or {}).get("name", h) for h in hosts]
        api.fire_webhook("business_service_down", {
            "service_id": "bs_" + name.replace(" ", "_"), "service_name": name, "name": name, "state": state,
            "detail": "; ".join(f"{n} (offline)" for n in names), "parts_ok": 0, "parts": len(hosts), "host_ids": hosts})
        api._LOAD_CACHE.clear()

    def three_services(self):
        self.fire_down("Ops web", ["opsA"])
        self.fire_down("Both groups", ["opsA", "opsB"])
        self.fire_down("Customer B", ["devB"])

    def alert_names(self, who):
        st, d = self.call(api.handle_alerts_list, m="GET", who=who)
        self.assertEqual(st, 200, d)
        return {(a.get("payload") or {}).get("service_name") for a in d["alerts"]
                if a.get("event") == "business_service_down"}

    def feed_names(self, who):
        st, d = self.call_etag(api.handle_fleet_events, who)
        self.assertEqual(st, 200, d)
        return {(e.get("payload") or {}).get("name") for e in d if e.get("event") == "business_service_down"}

    def home_names(self, who):
        st, d = self.call(api.handle_home, m="GET", who=who)
        self.assertEqual(st, 200, d)
        return {(e.get("payload") or {}).get("name") for e in d["fleet_events"] if e.get("event") == "business_service_down"}

    def problem_names(self, who):
        st, d = self.call(api.handle_problems, m="GET", who=who)
        self.assertEqual(st, 200, d)
        return {p.get("device") for p in d["problems"] if p.get("family") == "alert:business_service_down"}


ALL = {"Ops web", "Both groups", "Customer B"}


class TestTheRowsNameTheirHosts(_Vis):

    def test_the_sweep_records_every_host_a_service_holds_through_the_services_inside_it(self):
        api.save(api.BUSINESS_SERVICES_FILE, {
            "bs_inner": {"name": "Inner", "rule": {"type": "all"}, "members": [
                {"kind": "unit", "device_id": "opsB", "unit": "x.service"}]},
            "bs_outer": {"name": "Outer", "rule": {"type": "all"}, "members": [
                {"kind": "host", "device_id": "opsA"}, {"kind": "service", "service_id": "bs_inner"},
                {"kind": "host", "device_id": "opsA"}]}})
        # both hosts are reported as down by a monitor-less service of units: take the hosts out of the picture
        devs = api.load(api.DEVICES_FILE)
        for h in ("opsA", "opsB"):
            devs[h]["last_seen"] = 1
        api.save(api.DEVICES_FILE, devs, clamp_last_seen=False)
        for _ in range(2):
            doc = api.load(api.BUSINESS_SERVICE_STATE_FILE) or {}
            doc["last_run"] = 0
            api.save(api.BUSINESS_SERVICE_STATE_FILE, doc)
            api._LOAD_CACHE.clear()
            api.run_business_services_if_due()
        api._LOAD_CACHE.clear()
        rows = {(a["payload"] or {}).get("service_name"): a["payload"] for a in api.load(api.ALERTS_FILE)["alerts"]}
        self.assertEqual(rows["Outer"]["host_ids"], ["opsA", "opsB"], rows)
        self.assertEqual(rows["Inner"]["host_ids"], ["opsB"], rows)
        feed = [e["payload"] for e in api.load(api.FLEET_EVENTS_FILE)["events"] if e["event"] == "business_service_down"]
        self.assertTrue(feed and all("host_ids" in p and p.get("service_id") for p in feed), feed)

    def test_a_cycle_in_a_stored_definition_cannot_make_the_closure_run_for_ever(self):
        api.save(api.BUSINESS_SERVICES_FILE, {
            "bs_a": {"name": "A", "rule": {"type": "all"}, "members": [{"kind": "service", "service_id": "bs_b"},
                                                                       {"kind": "host", "device_id": "opsA"}]},
            "bs_b": {"name": "B", "rule": {"type": "all"}, "members": [{"kind": "service", "service_id": "bs_a"},
                                                                       {"kind": "host", "device_id": "opsB"}]}})
        defs = api._definitions() if hasattr(api, "_definitions") else api.business_services_handlers_mod._definitions()
        self.assertEqual(sorted(api.business_services_handlers_mod._host_closure("bs_a", defs)), ["opsA", "opsB"])


class TestWhoReadsWhat(_Vis):

    def test_the_platform_operator_reads_all_of_it_everywhere(self):
        self.three_services()
        self.assertEqual(self.alert_names("platform"), ALL)
        self.assertEqual(self.feed_names("platform"), ALL)
        self.assertEqual(self.home_names("platform"), ALL)
        self.assertEqual(self.problem_names("platform"), ALL)

    def test_a_viewer_of_the_installations_own_organisation_does_not_read_a_tenants_host_names(self):
        self.three_services()
        want = {"Ops web", "Both groups"}
        self.assertEqual(self.alert_names("oviewer"), want)
        self.assertEqual(self.feed_names("oviewer"), want)
        self.assertEqual(self.home_names("oviewer"), want)
        self.assertEqual(self.problem_names("oviewer"), want)

    def test_a_viewer_scoped_to_one_group_reads_only_what_names_hosts_of_that_group(self):
        self.three_services()
        want = {"Ops web"}
        self.assertEqual(self.alert_names("gviewer"), want)
        self.assertEqual(self.feed_names("gviewer"), want)
        self.assertEqual(self.home_names("gviewer"), want)
        self.assertEqual(self.problem_names("gviewer"), want)

    def test_a_tenants_administrator_reads_none_of_it_not_even_a_service_of_its_own_hosts(self):
        self.three_services()
        for who in ("badmin", "cadmin"):
            self.assertEqual(self.alert_names(who), set(), who)
            self.assertEqual(self.feed_names(who), set(), who)
            self.assertEqual(self.home_names(who), set(), who)
            self.assertEqual(self.problem_names(who), set(), who)

    def test_the_predicate_alone_refuses_a_tenants_user_even_for_a_service_of_its_own_hosts(self):
        # the readers above check the organisation first, so each would hide the row without this; the predicate is the
        # one place that answers for every caller that uses it alone, and it must not depend on them
        api._LOAD_CACHE.clear()
        for who, want in (("badmin", False), ("platform", True), ("oviewer", True), ("gviewer", True)):
            self.who = who
            self.assertEqual(api.business_service_event_visible("business_service_down", {"host_ids": ["opsA"]}),
                             want and who != "badmin", who)
        self.who = "badmin"
        self.assertFalse(api.business_service_event_visible("business_service_down", {"host_ids": ["devB"]}))
        self.assertTrue(api.business_service_event_visible("monitor_down", {"label": "not about a service"}))

    def test_the_recovery_entry_follows_the_same_rule(self):
        api.fire_webhook("business_service_up", {"service_id": "bs_x", "service_name": "Customer B", "name": "Customer B",
                                                 "host_ids": ["devB"]})
        api.fire_webhook("business_service_up", {"service_id": "bs_y", "service_name": "Ops web", "name": "Ops web",
                                                 "host_ids": ["opsA"]})
        api._LOAD_CACHE.clear()

        def ups(who):
            st, d = self.call_etag(api.handle_fleet_events, who)
            return {(e.get("payload") or {}).get("name") for e in d if e.get("event") == "business_service_up"}
        self.assertEqual(ups("platform"), {"Customer B", "Ops web"})
        self.assertEqual(ups("oviewer"), {"Ops web"})
        self.assertEqual(ups("badmin"), set())

    def test_a_hidden_alert_cannot_be_acted_on_either(self):
        self.three_services()
        api._LOAD_CACHE.clear()
        ids = {(a["payload"] or {}).get("service_name"): a["id"] for a in api.load(api.ALERTS_FILE)["alerts"]}
        for name, who, want in (("Customer B", "oviewer", 404), ("Both groups", "gviewer", 404),
                                ("Ops web", "gviewer", 200), ("Customer B", "badmin", 404), ("Customer B", "platform", 200)):
            st, d = self.call(api.handle_alert_assign, ids[name], body={"user": "platform"}, who=who)
            self.assertEqual(st, want, (name, who, st, d))
            st, d = self.call(api.handle_alert_ack, ids[name], who=who)
            self.assertIn(st, (200, 404) if want == 404 else (200,), (name, who, st, d))
            if want == 404:
                self.assertEqual(st, 404, (name, who, d))

    def test_on_an_installation_without_tenancy_a_scoped_role_cannot_act_on_a_row_it_cannot_read(self):
        self.three_services()
        self.tenancy(False)
        ids = {(a["payload"] or {}).get("service_name"): a["id"] for a in api.load(api.ALERTS_FILE)["alerts"]}
        st, d = self.call(api.handle_alert_ack, ids["Both groups"], who="gviewer")
        self.assertEqual(st, 404, d)
        st, d = self.call(api.handle_alert_ack, ids["Ops web"], who="gviewer")
        self.assertEqual(st, 200, d)

    def test_a_row_that_records_no_hosts_follows_the_hosts_its_service_holds_now(self):
        api.save(api.BUSINESS_SERVICES_FILE, {
            "bs_ops": {"name": "Ops web", "rule": {"type": "all"}, "members": [{"kind": "host", "device_id": "opsA"}]},
            "bs_cust": {"name": "Customer B", "rule": {"type": "all"}, "members": [{"kind": "host", "device_id": "devB"}]}})
        now = int(time.time())
        rows = [{"id": f"a-{i}", "event": "business_service_down", "device_id": "", "device_name": n, "severity": "critical",
                 "title": "Business service down: " + n, "ts": now, "first_seen": now,
                 "payload": {"service_id": sid, "service_name": n, "name": n, "state": "critical"}}
                for i, (sid, n) in enumerate((("bs_ops", "Ops web"), ("bs_cust", "Customer B"), ("bs_gone", "Gone one")))]
        api.save(api.ALERTS_FILE, {"alerts": rows})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.alert_names("platform"), {"Ops web", "Customer B", "Gone one"})
        self.assertEqual(self.alert_names("oviewer"), {"Ops web"})          # a service that is gone is hidden from a restricted reader
        self.assertEqual(self.alert_names("badmin"), set())

    def test_junk_in_the_host_list_hides_the_row_from_a_restricted_reader_and_breaks_nothing(self):
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": f"a-{i}", "event": "business_service_down", "device_id": "", "device_name": "j", "severity": "critical",
             "title": "t", "ts": 1, "first_seen": 1,
             "payload": {"service_id": "bs_j", "service_name": f"J{i}", "name": "j", "host_ids": junk}}
            for i, junk in enumerate((None, "opsA", {"a": 1}, [5], [None], [["opsA"]], 7))]})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.alert_names("platform"), {f"J{i}" for i in range(7)})
        self.assertEqual(self.alert_names("oviewer"), set())

    def test_an_installation_without_tenancy_and_a_plain_admin_are_as_before(self):
        self.three_services()
        self.tenancy(False)
        self.assertEqual(self.alert_names("badmin"), ALL)       # one organisation: every admin reads everything
        self.assertEqual(self.alert_names("oviewer"), ALL)      # a viewer with no scope is not narrowed
        self.assertEqual(self.alert_names("gviewer"), {"Ops web"})   # a scoped role still is


class TestTheHomeFeedAppliesTheEventsEndpointsRule(_Vis):
    """The Home feed kept an event that names no host for everybody, and an event of a deleted host too."""

    def feed(self, who):
        st, d = self.call(api.handle_home, m="GET", who=who)
        self.assertEqual(st, 200, d)
        return {(e.get("payload") or {}).get("label") or (e.get("payload") or {}).get("device_name") for e in d["fleet_events"]}

    def test_an_event_that_names_no_host_and_one_of_a_deleted_host_are_not_a_tenants(self):
        api._record_fleet_event("monitor_down", {"label": "Operator site", "target": "https://ops.example"})
        api._record_fleet_event("device_offline", {"device_id": "gone", "device_name": "ghost-host"})
        api._record_fleet_event("device_offline", {"device_id": "devB", "device_name": "TENANT-B-HOST"})
        api._record_fleet_event("device_offline", {"device_id": "opsA", "device_name": "OPS-ALPHA"})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.feed("platform"), {"Operator site", "ghost-host", "TENANT-B-HOST", "OPS-ALPHA"})
        self.assertEqual(self.feed("badmin"), {"TENANT-B-HOST"})                  # its own host only
        # a viewer of the installation's own organisation is under the tenant gate too: the events of a deleted host
        # are dropped for it, as the events endpoint drops them (only the platform operator reads them)
        self.assertEqual(self.feed("oviewer"), {"Operator site", "OPS-ALPHA"})
        # and it answers exactly what the events endpoint does
        st, d = self.call_etag(api.handle_fleet_events, "badmin")
        self.assertEqual({(e["payload"] or {}).get("device_name") for e in d}, {"TENANT-B-HOST"})


class TestWhoIsSentIt(_Vis):

    def setUp(self):
        super().setUp()
        api.save(api.USER_NOTIFY_FILE, {u: {"enabled": True, "webhook_url": "https://hooks.example/" + u}
                                        for u in ("platform", "oviewer", "gviewer", "badmin", "off")})
        self.sent = []
        api._dispatch_one_webhook = lambda event, dest, payload, message, title, priority, **k: self.sent.append(dest["name"])
        api._LOAD_CACHE.clear()

    def recipients(self, event, payload):
        self.sent.clear()
        api._deliver_user_notifications(event, dict(payload), "m", api.load(api.CONFIG_FILE) or {})
        return {n.split(" ")[0] for n in self.sent}

    def test_an_event_that_names_no_host_goes_to_the_installations_own_accounts_only(self):
        self.assertEqual(self.recipients("monitor_down", {"label": "Operator site"}), {"platform", "oviewer", "gviewer"})

    def test_a_service_event_goes_to_the_accounts_that_can_see_every_host_it_names(self):
        def payload(hosts):
            return {"service_id": "bs_x", "service_name": "S", "name": "S", "host_ids": hosts}
        self.assertEqual(self.recipients("business_service_down", payload(["opsA"])), {"platform", "oviewer", "gviewer"})
        self.assertEqual(self.recipients("business_service_down", payload(["opsA", "opsB"])), {"platform", "oviewer"})
        self.assertEqual(self.recipients("business_service_down", payload(["devB"])), {"platform"})
        self.assertEqual(self.recipients("business_service_down", payload(["opsA", "gone"])), {"platform"})

    def test_a_host_event_still_goes_to_the_accounts_of_that_host(self):
        self.assertEqual(self.recipients("device_offline", {"device_id": "devB", "name": "TENANT-B-HOST"}),
                         {"platform", "badmin"})
        self.assertEqual(self.recipients("device_offline", {"device_id": "opsB", "name": "OPS-BRAVO"}),
                         {"platform", "oviewer"})

    def test_the_browser_push_follows_the_same_rule(self):
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True, "webpush_enabled": True})
        api.save(api.PUSH_SUBS_FILE, {u: [{"endpoint": "https://push.example/" + u, "keys": {"p256dh": "k", "auth": "a"}}]
                                      for u in ("platform", "oviewer", "gviewer", "badmin")})
        api._webpush_cfg = lambda: (True, "pem", "pub", "mailto:x@example.com")
        api._url_targets_local_or_meta = lambda *a, **k: False
        api._LOAD_CACHE.clear()

        def pushed(event, payload):
            got = []
            with mock.patch.object(webpush, "send", lambda sub, body, pem, subj, opener=None: (got.append(sub["endpoint"]), 201)[1]):
                api._maybe_webpush(event, payload)
            return {e.rsplit("/", 1)[1] for e in got}
        self.assertEqual(pushed("monitor_down", {"label": "Operator site"}), {"platform", "oviewer", "gviewer"})
        self.assertEqual(pushed("business_service_down", {"service_id": "b", "name": "S", "state": "critical", "host_ids": ["devB"]}),
                         {"platform"})
        self.assertEqual(pushed("business_service_down", {"service_id": "b", "name": "S", "state": "critical", "host_ids": ["opsA"]}),
                         {"platform", "oviewer", "gviewer"})
        self.assertEqual(pushed("device_offline", {"device_id": "devB", "name": "TENANT-B-HOST"}), {"platform", "badmin"})


class TestTheAccountRule(_Vis):

    def may(self, who, device_id=None, event="x", payload=None):
        return api._account_may_see(who, api.load(api.USERS_FILE), device_id, event, payload)

    def test_the_cases(self):
        self.assertTrue(self.may("platform", "devB"))
        self.assertTrue(self.may("platform"))
        self.assertFalse(self.may("badmin", "opsA"))
        self.assertTrue(self.may("badmin", "devB"))
        self.assertFalse(self.may("badmin"))                          # an event that names no host: not a tenant's
        self.assertTrue(self.may("oviewer"))
        self.assertFalse(self.may("oviewer", "devB"))
        self.assertFalse(self.may("gviewer", "opsB"))
        self.assertFalse(self.may("off"))                             # a disabled account is nobody
        self.assertFalse(self.may("nobody-here"))
        self.assertFalse(self.may("platform", payload=None, event="business_service_down"))   # no hosts recorded, no service
        self.tenancy(False)
        self.assertTrue(self.may("badmin"))                           # one organisation: as before
        self.assertTrue(self.may("badmin", "opsA"))
        self.assertFalse(self.may("gviewer", "opsB"))                 # a role scope is not a tenancy setting


class TestWiring(unittest.TestCase):

    def test_the_two_whitelists_keep_the_hosts_a_row_names_and_the_inbox_does_not_print_the_list(self):
        root = Path(__file__).resolve().parent.parent
        src = (root / "server" / "cgi-bin" / "api.py").read_text(encoding="utf-8")
        self.assertEqual(src.count("'host_ids'"), 2)        # _record_alert and _record_fleet_event
        js = (root / "server" / "html" / "static" / "js" / "app-alerts.js").read_text(encoding="utf-8")
        self.assertIn("'host_ids'", js)


if __name__ == "__main__":
    unittest.main()
