"""One list of problems (#56): the read model, the maps that join the three views, and the endpoint.

Alerts, Needs attention and Checks each say what is wrong with a host, by their own rules, and closing a problem in
one did not close it in the others. server/cgi-bin/problems.py joins them. Three layers are held here:

  1. the model, on plain data: every state is reached by a scenario, a problem found in all three views is one row,
     and a hand-edited store cannot fail the list;
  2. the maps that join them (check key -> kind, event -> kind) are held to real names, so a typo cannot quietly
     leave a problem unjoined;
  3. the endpoint, run for real on seeded stores, including the story the issue came from: an alert resolved by hand
     while the host still reports a failed unit.
"""
import ast
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-problems-"))

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(CGI))

import problems  # noqa: E402

NOW = 1_800_000_000
DAY = 86400

KIND_OF_EVENT = {
    "failed_unit": "failed_units",
    "cve_found": "cve",
    "mount_issue": "mount",
    "device_offline": "offline",
    "tls_expiry": "tls",
}
CHECK_FAMILY = {"cve": "cve", "mounts": "mount", "reachability": "offline"}
SHOWN = frozenset(KIND_OF_EVENT.values()) | frozenset(CHECK_FAMILY.values()) | {"cpu", "memory", "swap", "disk"}
IDENT = ("unit", "path", "metric", "target", "label", "host", "port")


def alert(event, dev="h1", *, ts=NOW - 600, resolved_at=None, by=None, ack=None, **payload):
    return {
        "id": f"a-{event}-{dev}-{len(payload)}-{ts}",
        "alertid": "alertid_000001",
        "event": event,
        "severity": "high",
        "title": f"{event} on {dev}",
        "device_id": dev,
        "device_name": "web01" if dev == "h1" else dev,
        "payload": payload,
        "ts": ts,
        "first_seen": ts - 60,
        "acknowledged_by": ack,
        "acknowledged_at": (ts + 5) if ack else None,
        "resolved_at": resolved_at,
        "resolved_by": by,
    }


def item(kind, dev="h1", summary="something", severity="warning", **extra):
    return dict({"kind": kind, "device_id": dev, "device": "web01" if dev == "h1" else dev, "summary": summary,
                 "severity": severity}, **extra)


def check(cid, dev="h1", status="warning", key=None):
    return {"device_id": dev, "device": "web01", "id": cid, "key": key or cid, "name": cid.title(), "status": status,
            "output": "x"}


MUTE_MAP = {("failed_units", "warning"): ("failed_unit",), ("disk", "critical"): ("metric_critical", "disk_predict_fail")}


def build(alerts=(), attention=(), checks=(), reports=None, window_days=7, **extra):
    return problems.build(
        alerts=list(alerts), attention=list(attention), checks=list(checks), kind_of_event=KIND_OF_EVENT,
        check_family=CHECK_FAMILY, shown_kinds=SHOWN, identity_fields=IDENT, reports=reports or {}, now=NOW,
        window_s=window_days * DAY, **extra)


def history(alerts, dev="h1", family="failed_units", detail="", window_days=90):
    return problems.history(alerts=list(alerts), device_id=dev, family=family, detail=detail,
                            kind_of_event=KIND_OF_EVENT, identity_fields=IDENT, now=NOW, window_s=window_days * DAY)


def one(rows):
    assert len(rows) == 1, [(r["key"], r["state"]) for r in rows]
    return rows[0]


class TestWhoClosedIt(unittest.TestCase):
    def test_a_person_a_ticket_and_an_emailed_link_are_by_hand(self):
        for by in ("alice", "jakob", "itsm:INC-42", "email-link"):
            a = alert("x", resolved_at=NOW, by=by)
            self.assertTrue(problems.resolved_by_hand(a), by)
            self.assertEqual(problems.resolution_how(a), "hand")

    def test_the_system_is_not_a_person(self):
        for by in problems.SYSTEM_RESOLVERS:
            a = alert("x", resolved_at=NOW, by=by)
            self.assertFalse(problems.resolved_by_hand(a), by)
        self.assertEqual(problems.resolution_how(alert("x", resolved_at=NOW, by="auto")), "auto")
        self.assertEqual(problems.resolution_how(alert("x", resolved_at=NOW, by="muted")), "system")

    def test_an_alert_that_is_not_resolved_has_no_resolver(self):
        a = alert("x", by="alice")                       # resolved_by without resolved_at: not closed
        self.assertFalse(problems.resolved_by_hand(a))
        self.assertEqual(problems.resolution_how(a), "open")

    def test_every_resolver_the_server_writes_is_known(self):
        """Each string api.py stores in resolved_by is either a system value listed here or a person. A new system
        value that is not listed would be taken for a person, and its problem called 'resolved by you'."""
        src = "\n".join(p.read_text() for p in sorted(CGI.glob("*.py")))
        written = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == "resolved_by"
                    for t in node.targets) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                written.add(node.value.value)
        self.assertTrue(written, "found no literal resolved_by assignment: the scan measured nothing")
        unknown = written - problems.SYSTEM_RESOLVERS
        self.assertEqual(sorted(unknown), ["email-link"],
                         "a literal resolved_by the model does not know: add it to SYSTEM_RESOLVERS if no person closed it")


class TestTheKind(unittest.TestCase):
    def test_an_event_belongs_to_the_kind_of_the_map(self):
        self.assertEqual(problems.alert_family(alert("failed_unit"), KIND_OF_EVENT), "failed_units")

    def test_a_metric_alert_belongs_to_the_kind_named_by_its_metric(self):
        for metric, kind in (("memory", "memory"), ("cpu", "cpu"), ("disk", "disk"), ("diskio", "disk")):
            self.assertEqual(problems.alert_family(alert("metric_warning", metric=metric), KIND_OF_EVENT), kind)

    def test_a_metric_alert_without_a_metric_and_an_unknown_event_get_a_kind_of_their_own(self):
        self.assertEqual(problems.alert_family(alert("metric_critical"), KIND_OF_EVENT), "alert:metric_critical")
        self.assertEqual(problems.alert_family(alert("never_heard_of_it"), KIND_OF_EVENT), "alert:never_heard_of_it")

    def test_the_discriminator_is_what_the_alert_store_coalesces_on(self):
        a = alert("mount_issue", path="/mnt/a", port=None, label="")
        self.assertEqual(problems.discriminator(a, IDENT), "path=/mnt/a")
        self.assertEqual(problems.discriminator(alert("x"), IDENT), "")


class TestTheStates(unittest.TestCase):
    """Every state, reached the way an operator reaches it."""

    def state(self, **kw):
        return one(build(**kw))["state"]

    def test_an_open_alert_the_host_still_reports_is_failing(self):
        r = one(build(alerts=[alert("failed_unit", unit="nginx.service")], attention=[item("failed_units")]))
        self.assertEqual(r["state"], problems.FAILING)
        self.assertEqual(r["sources"], ["alert", "attention"])
        self.assertTrue(r["can_resolve"])
        self.assertEqual(r["open_ids"], [r["alerts"][0]["id"]])

    def test_an_open_alert_the_host_no_longer_reports_is_host_clear(self):
        self.assertEqual(self.state(alerts=[alert("failed_unit", unit="nginx.service")]), problems.HOST_CLEAR)

    def test_an_open_alert_of_a_kind_nothing_else_shows_stays_failing(self):
        """Nobody can tell 'the host stopped reporting it' for a kind Needs attention cannot show."""
        self.assertEqual(self.state(alerts=[alert("never_heard_of_it")]), problems.FAILING)

    def test_a_problem_only_the_host_reports_is_failing_with_no_alert(self):
        r = one(build(attention=[item("patches", summary="14 pending package updates")]))
        self.assertEqual((r["state"], r["sources"], r["can_resolve"]), (problems.FAILING, ["attention"], False))

    def test_resolved_by_hand_and_still_reported_is_resolved_but_failing(self):
        """The case #56 came from: a failed unit, an alert closed by hand, and Needs attention still listing it."""
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="alice")
        r = one(build(alerts=[a], attention=[item("failed_units")], reports={"h1": NOW - 10}))
        self.assertEqual(r["state"], problems.RESOLVED_BUT_FAILING)
        self.assertFalse(r["can_resolve"])
        self.assertEqual(r["alerts"][0]["how"], "hand")
        self.assertEqual(r["alerts"][0]["resolved_by"], "alice")

    def test_resolved_by_hand_before_the_host_reported_again_is_waiting(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="alice")
        self.assertEqual(self.state(alerts=[a], attention=[item("failed_units")], reports={"h1": NOW - 500}),
                         problems.WAITING)

    def test_a_host_that_never_said_when_it_reported_is_not_called_waiting(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="alice")
        self.assertEqual(self.state(alerts=[a], attention=[item("failed_units")]), problems.RESOLVED_BUT_FAILING)

    def test_resolved_by_hand_and_not_reported_is_resolved(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="alice")
        self.assertEqual(self.state(alerts=[a]), problems.RESOLVED)

    def test_closed_by_a_recovery_event_is_recovered(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="auto")
        self.assertEqual(self.state(alerts=[a]), problems.RECOVERED)

    def test_closed_by_a_recovery_event_while_the_host_still_reports_it_is_failing(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="auto")
        self.assertEqual(self.state(alerts=[a], attention=[item("failed_units")]), problems.FAILING)

    def test_closed_by_a_mute_is_resolved_not_recovered(self):
        a = alert("failed_unit", unit="nginx.service", resolved_at=NOW - 100, by="muted")
        self.assertEqual(self.state(alerts=[a]), problems.RESOLVED)

    def test_every_state_is_reached_by_the_scenarios_above(self):
        """A control: a state function that never returns a state would pass every other test."""
        reached = set()
        scenarios = [
            dict(alerts=[alert("failed_unit", unit="u")], attention=[item("failed_units")]),
            dict(alerts=[alert("failed_unit", unit="u")]),
            dict(alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 100, by="alice")],
                 attention=[item("failed_units")], reports={"h1": NOW - 10}),
            dict(alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 100, by="alice")],
                 attention=[item("failed_units")], reports={"h1": NOW - 500}),
            dict(alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 100, by="alice")]),
            dict(alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 100, by="auto")]),
        ]
        for s in scenarios:
            reached.add(one(build(**s))["state"])
        self.assertEqual(reached, set(problems.STATES))


class TestEachProblemOnce(unittest.TestCase):
    def test_an_alert_a_needs_attention_item_and_a_failing_check_are_one_row(self):
        rows = build(alerts=[alert("cve_found", cve_id="CVE-1")], attention=[item("cve", severity="critical")],
                     checks=[check("cve", status="critical")])
        r = one(rows)
        self.assertEqual((r["family"], r["sources"]), ("cve", ["alert", "attention", "check"]))
        self.assertEqual(r["severity"], "critical")

    def test_a_check_with_no_kind_in_the_table_is_a_row_of_its_own(self):
        r = one(build(checks=[check("oom")]))
        self.assertEqual((r["family"], r["sources"]), ("check:oom", ["check"]))

    def test_two_alerts_of_one_kind_on_one_host_are_one_problem_with_both_listed(self):
        a1 = alert("failed_unit", unit="a.service", ts=NOW - 900)
        a2 = alert("failed_unit", unit="b.service", ts=NOW - 100)
        r = one(build(alerts=[a1, a2], attention=[item("failed_units")]))
        self.assertEqual(r["alert_total"], 2)
        self.assertEqual([e["detail"] for e in r["alerts"]], ["unit=b.service", "unit=a.service"])

    def test_every_open_alert_of_a_problem_can_be_closed_from_its_row_though_few_are_listed(self):
        many = [alert("failed_unit", unit=f"u{i}.service", ts=NOW - 1000 + i) for i in range(8)]
        r = one(build(alerts=many, attention=[item("failed_units")]))
        self.assertEqual(len(r["alerts"]), problems.HISTORY_PER_PROBLEM)
        self.assertEqual(len(r["open_ids"]), 8)
        self.assertEqual(len(set(r["open_ids"])), 8)

    def test_a_row_with_nothing_open_has_nothing_to_resolve(self):
        a = alert("failed_unit", unit="u", resolved_at=NOW - 10, by="alice")
        self.assertEqual(one(build(alerts=[a]))["open_ids"], [])

    def test_the_same_kind_on_two_hosts_is_two_problems(self):
        rows = build(attention=[item("patches", dev="h1"), item("patches", dev="h2")])
        self.assertEqual(sorted(r["device_id"] for r in rows), ["h1", "h2"])

    def test_a_metric_alert_joins_the_needs_attention_item_of_its_metric(self):
        r = one(build(alerts=[alert("metric_warning", metric="memory", target="")], attention=[item("memory")]))
        self.assertEqual((r["family"], r["state"]), ("memory", problems.FAILING))

    def test_a_fleet_level_item_joins_the_one_alert_of_its_kind(self):
        a = alert("tls_expiry", dev="", host="example.org", port=443)
        r = one(build(alerts=[a], attention=[item("tls", dev="", summary="Certificate EXPIRED")]))
        self.assertEqual(r["sources"], ["alert", "attention"])

    def test_a_fleet_level_item_stands_alone_when_several_alerts_could_be_its_own(self):
        """Two certificates, one Needs attention item: nothing says which is which, so no guess is made."""
        a1 = alert("tls_expiry", dev="", host="a.example", port=443)
        a2 = alert("tls_expiry", dev="", host="b.example", port=443)
        rows = build(alerts=[a1, a2], attention=[item("tls", dev="", summary="Certificate EXPIRED")])
        self.assertEqual(len(rows), 3)
        self.assertEqual(sorted(tuple(r["sources"]) for r in rows), [("alert",), ("alert",), ("attention",)])

    def test_an_open_alert_without_a_host_is_never_called_host_clear(self):
        """There is no host report to say it has gone, so an open fleet-level alert stays failing."""
        rows = build(alerts=[alert("tls_expiry", dev="", host="a.example", port=443),
                             alert("tls_expiry", dev="", host="b.example", port=443)])
        self.assertEqual([r["state"] for r in rows], [problems.FAILING, problems.FAILING])


class TestTheWindow(unittest.TestCase):
    def test_a_resolved_alert_older_than_the_window_is_left_out(self):
        old = alert("failed_unit", unit="u", ts=NOW - 20 * DAY, resolved_at=NOW - 10 * DAY, by="alice")
        self.assertEqual(build(alerts=[old]), [])
        self.assertEqual(len(build(alerts=[old], window_days=30)), 1)

    def test_an_open_alert_is_never_left_out_for_its_age(self):
        r = one(build(alerts=[alert("failed_unit", unit="u", ts=NOW - 90 * DAY)], attention=[item("failed_units")]))
        self.assertEqual(r["state"], problems.FAILING)


class TestHandEditedStores(unittest.TestCase):
    def test_a_row_that_is_not_a_map_or_has_odd_fields_does_not_fail_the_list(self):
        junk = [None, "x", 7, [], {"event": ["list"], "device_id": 5, "ts": "soon", "payload": "text"},
                {"event": "failed_unit", "ts": float("inf"), "resolved_at": True, "payload": {"unit": object()}}]
        rows = problems.build(
            alerts=junk + [alert("failed_unit", unit="u")], attention=junk + [item("failed_units")],
            checks=junk + [check("cve")], kind_of_event=KIND_OF_EVENT, check_family=CHECK_FAMILY, shown_kinds=SHOWN,
            identity_fields=IDENT, reports={"h1": "never", "h2": None}, now=NOW, window_s=7 * DAY)
        self.assertTrue(any(r["device_id"] == "h1" and r["family"] == "failed_units" for r in rows))
        problems.counts(rows)


class TestTheOrderAndTheCounts(unittest.TestCase):
    def rows(self):
        return build(
            alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 50, by="auto")],
            attention=[item("patches", dev="h2", severity="warning"), item("cve", dev="h3", severity="critical")])

    def test_what_needs_you_comes_first_and_the_worst_first_among_it(self):
        rows = self.rows()
        self.assertEqual([r["family"] for r in rows], ["cve", "patches", "failed_units"])
        self.assertEqual([r["active"] for r in rows], [True, True, False])

    def test_counts_cover_every_state_and_every_source(self):
        c = problems.counts(self.rows())
        self.assertEqual(set(c["states"]), set(problems.STATES))
        self.assertEqual(c["states"][problems.FAILING], 2)
        self.assertEqual(c["states"][problems.RECOVERED], 1)
        self.assertEqual((c["active"], c["total"]), (2, 3))
        self.assertEqual(c["sources"], {"alert": 1, "attention": 2, "check": 0})


class TestWhatARowOffers(unittest.TestCase):
    """The page acts on a problem by calling the endpoints the other pages call, so a row says which: the ignore
    key and the Fix of its Needs attention items, the key of its checks, and the events a mute would silence."""

    def test_a_needs_attention_item_keeps_what_ignore_snooze_and_fix_need(self):
        it = item("failed_units", **{"_ignore_key": "failed_units|web01|2 failed", "mitigation_kind": "failed_units",
                                     "mitigation_target": "nginx.service"})
        e = one(build(attention=[it]))["attention"][0]
        self.assertEqual((e["kind"], e["ignore_key"], e["mitigation_kind"], e["mitigation_target"]),
                         ("failed_units", "failed_units|web01|2 failed", "failed_units", "nginx.service"))

    def test_a_check_keeps_the_key_the_toggle_needs_not_only_its_family_id(self):
        r = one(build(checks=[check("disk", key="disk:/var")]))
        self.assertEqual((r["checks"][0]["id"], r["checks"][0]["key"]), ("disk", "disk:/var"))

    def test_muting_silences_the_events_of_its_alerts_and_the_events_its_items_stand_for(self):
        r = one(build(alerts=[alert("failed_unit", unit="a")], attention=[item("failed_units")], mute_map=MUTE_MAP))
        self.assertEqual(r["mute_events"], ["failed_unit"])
        r = one(build(attention=[item("disk", severity="critical")], mute_map=MUTE_MAP))
        self.assertEqual(r["mute_events"], ["metric_critical", "disk_predict_fail"])

    def test_the_events_are_listed_once_whatever_raised_them(self):
        a1, a2 = alert("failed_unit", unit="a", ts=NOW - 50), alert("failed_unit", unit="b", ts=NOW - 60)
        r = one(build(alerts=[a1, a2], attention=[item("failed_units")], mute_map=MUTE_MAP))
        self.assertEqual(r["mute_events"], ["failed_unit"])

    def test_a_problem_with_no_host_offers_no_mute_by_event_and_no_fix(self):
        a = alert("tls_expiry", dev="", host="a.example", port=443)
        r = one(build(alerts=[a], attention=[item("tls", dev="", mitigation_kind="tls")], mute_map=MUTE_MAP,
                      fix_of_alert=lambda al: ("tls", "")))
        self.assertEqual((r["mute_events"], r["fix"]), ([], None))

    def test_the_fix_is_the_one_a_needs_attention_item_names(self):
        it = item("failed_units", mitigation_kind="failed_units", mitigation_target="nginx.service")
        self.assertEqual(one(build(attention=[it]))["fix"],
                         {"kind": "failed_units", "target": "nginx.service", "source": "attention"})

    def test_failing_that_it_is_the_one_the_newest_open_alert_offers(self):
        seen = []

        def fix_of_alert(a):
            seen.append(a["ts"])
            return ("service_down", a["payload"].get("unit", ""))
        old, new = alert("failed_unit", unit="old.service", ts=NOW - 900), alert("failed_unit", unit="new.service", ts=NOW - 10)
        r = one(build(alerts=[old, new], fix_of_alert=fix_of_alert))
        self.assertEqual(r["fix"], {"kind": "service_down", "target": "new.service", "source": "alert"})
        self.assertEqual(seen, [NOW - 10], "the newest open alert is asked first, and the answer is taken")

    def test_a_resolved_alert_offers_no_fix(self):
        a = alert("failed_unit", unit="u", resolved_at=NOW - 10, by="alice")
        self.assertIsNone(one(build(alerts=[a], fix_of_alert=lambda al: ("service_down", "u")))["fix"])

    def test_no_fix_is_offered_when_nothing_names_one(self):
        self.assertIsNone(one(build(alerts=[alert("failed_unit", unit="u")], attention=[item("failed_units")]))["fix"])

    def test_counts_say_how_many_active_problems_each_source_has(self):
        rows = build(alerts=[alert("failed_unit", unit="u", resolved_at=NOW - 10, by="auto")],
                     attention=[item("patches", dev="h2"), item("cve", dev="h3")], checks=[check("cve", dev="h3")])
        c = problems.counts(rows)
        self.assertEqual(c["sources"], {"alert": 1, "attention": 2, "check": 1})
        self.assertEqual(c["active_sources"], {"alert": 0, "attention": 2, "check": 1})


class TestTheHistoryOfAProblem(unittest.TestCase):
    A1 = dict(alert("failed_unit", unit="nginx.service", ts=NOW - 5000, ack="bob", resolved_at=NOW - 3000, by="alice"),
              count=4, first_seen=NOW - 9000, resolve_note="restarted it")

    def test_each_alert_reads_back_as_raised_acknowledged_and_resolved_newest_first(self):
        h = history([self.A1])
        self.assertEqual([e["kind"] for e in h["events"]], ["resolved", "acknowledged", "raised"])
        resolved, acked, raised = h["events"]
        self.assertEqual((resolved["by"], resolved["how"], resolved["note"], resolved["at"]),
                         ("alice", "hand", "restarted it", NOW - 3000))
        self.assertEqual((acked["by"], acked["at"]), ("bob", NOW - 5000 + 5))
        self.assertEqual((raised["at"], raised["count"], raised["last"], raised["detail"]),
                         (NOW - 9000, 4, NOW - 5000, "unit=nginx.service"))

    def test_resolving_an_alert_nobody_acknowledged_reads_back_resolved_then_acknowledged(self):
        """The server records both at the same second; the later step comes first in a newest-first list."""
        a = dict(alert("failed_unit", unit="u", ts=NOW - 900, resolved_at=NOW - 60, by="alice"),
                 acknowledged_by="alice", acknowledged_at=NOW - 60)
        self.assertEqual([e["kind"] for e in history([a])["events"]], ["resolved", "acknowledged", "raised"])

    def test_a_recovery_event_and_a_mute_are_told_apart_from_a_person(self):
        auto = alert("failed_unit", unit="a", ts=NOW - 400, resolved_at=NOW - 300, by="auto")
        muted = alert("failed_unit", unit="b", ts=NOW - 200, resolved_at=NOW - 100, by="muted")
        hows = [e["how"] for e in history([auto, muted])["events"] if e["kind"] == "resolved"]
        self.assertEqual(hows, ["system", "auto"])

    def test_an_open_alert_has_only_been_raised(self):
        h = history([alert("failed_unit", unit="u")])
        self.assertEqual([e["kind"] for e in h["events"]], ["raised"])

    def test_only_this_host_and_this_kind(self):
        mine, other_host, other_kind = alert("failed_unit", unit="u"), alert("failed_unit", dev="h2", unit="u"), alert("mount_issue", path="/")
        self.assertEqual(history([mine, other_host, other_kind])["alerts"], 1)
        self.assertEqual(history([other_kind], family="mount")["alerts"], 1)

    def test_a_problem_with_no_host_is_told_by_its_detail(self):
        a = alert("tls_expiry", dev="", host="a.example", port=443)
        b = alert("tls_expiry", dev="", host="b.example", port=443)
        self.assertEqual(history([a, b], dev="", family="tls", detail="host=a.example;port=443")["alerts"], 1)
        self.assertEqual(history([a, b], dev="", family="tls", detail="")["alerts"], 0)

    def test_the_window_and_the_limits(self):
        old = alert("failed_unit", unit="u", ts=NOW - 100 * DAY, resolved_at=NOW - 99 * DAY, by="alice")
        self.assertEqual(history([old])["alerts"], 0)
        self.assertEqual(history([old], window_days=365)["alerts"], 1)
        many = [alert("failed_unit", unit=f"u{i}", ts=NOW - i) for i in range(problems.HISTORY_ALERT_LIMIT + 30)]
        self.assertEqual(history(many)["alerts"], problems.HISTORY_ALERT_LIMIT)

    def test_a_hand_edited_store_does_not_fail_it(self):
        junk = [None, "x", 7, [], {"event": ["l"], "device_id": "h1", "ts": "soon", "payload": "text"}]
        h = history(junk + [self.A1])
        self.assertEqual(h["alerts"], 1)

    def test_an_unknown_family_or_host_has_an_empty_history(self):
        self.assertEqual(history([self.A1], family="nothing")["events"], [])
        self.assertEqual(history([self.A1], dev="nobody")["events"], [])


class TestTheJoinTablesNameRealThings(unittest.TestCase):
    """A typo in a map leaves a problem unjoined and nothing fails. These tests make it fail."""

    @classmethod
    def setUpClass(cls):
        src = (CGI / "api.py").read_text()
        fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "_compute_attention")
        cls.na_kinds = {
            v.value
            for node in ast.walk(fn) if isinstance(node, ast.Dict)
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and k.value == "kind" and isinstance(v, ast.Constant)
        }
        cls.checks_src = (CGI / "checks.py").read_text()
        cls.handlers_src = (CGI / "problems_handlers.py").read_text()
        cls.table = cls._table(cls.handlers_src, "CHECK_FAMILY")
        cls.metric_kinds = {"cpu", "memory", "swap", "disk"}

    @staticmethod
    def _table(src, name):
        for node in ast.parse(src).body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == name for t in node.targets):
                return ast.literal_eval(node.value)
        raise AssertionError(f"{name} not found")

    def test_the_census_of_kinds_is_not_empty(self):
        self.assertGreaterEqual(len(self.na_kinds), 30, "the scan of _compute_attention found too few kinds")
        self.assertIn("failed_units", self.na_kinds)

    def test_every_value_of_check_family_is_a_kind_needs_attention_emits_or_a_registered_event(self):
        api = _fresh_api()
        for key, kind in self.table.items():
            if kind.startswith("alert:"):
                self.assertIn(kind[len("alert:"):], api.EVENT_REGISTRY, f"CHECK_FAMILY[{key!r}] names no such event")
            else:
                self.assertIn(kind, self.na_kinds | self.metric_kinds, f"CHECK_FAMILY[{key!r}] = {kind!r} is no such kind")

    def test_every_key_of_check_family_is_a_check_that_exists(self):
        for key in self.table:
            self.assertTrue(f'"{key}"' in self.checks_src or f'"{key}:' in self.checks_src or f"'{key}:" in self.checks_src
                            or f"f\"{key}:" in self.checks_src or f"f'{key}:" in self.checks_src,
                            f"CHECK_FAMILY has {key!r} and checks.py has no such check")

    def test_every_event_of_the_mute_map_is_a_registered_event(self):
        api = _fresh_api()
        events = {e for evs in api._NA_MUTE_EVENTS.values() for e in evs}
        self.assertEqual(sorted(events - set(api.EVENT_REGISTRY)), [])

    def test_every_kind_of_the_mute_map_is_a_kind_needs_attention_emits(self):
        api = _fresh_api()
        kinds = {k for (k, _sev) in api._NA_MUTE_EVENTS}
        self.assertEqual(sorted(kinds - self.na_kinds - self.metric_kinds), [])

    def test_the_event_map_is_the_mute_map_without_the_metric_events(self):
        """A metric alert is placed by its metric. If the mute map placed it, one that lost its `metric` would be
        taken for a disk problem."""
        api = _fresh_api()
        kinds = api.problems_handlers_mod._kind_of_event()
        for ev in problems.METRIC_EVENTS:
            self.assertNotIn(ev, kinds)
        self.assertEqual((kinds["failed_unit"], kinds["cve_found"], kinds["mount_issue"]),
                         ("failed_units", "cve", "mount"))
        self.assertGreaterEqual(len(kinds), 30)

    def test_the_route_is_registered(self):
        api = _fresh_api()
        self.assertEqual(api._build_exact_routes()[("GET", "/api/problems")].__name__, "handle_problems")
        self.assertIn("/api/problems", api._GZIP_SAFE_GET_PATHS)


# ── the endpoint, for real ────────────────────────────────────────────────────────────────────────────────────

def _fresh_api(auth=True):
    d = tempfile.mkdtemp(prefix="rp-problems-")
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_problems", CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if auth:
        mod.require_auth = lambda *a, **k: "admin"
    return mod


class _Endpoint(unittest.TestCase):
    def setUp(self):
        self.api = api = _fresh_api()
        self.query = ""
        api._env = lambda k, d="": self.query if k == "QUERY_STRING" else d
        self.now = int(time.time())
        host = {"monitored": True, "last_seen": self.now, "sysinfo": {}}
        api.save(api.DEVICES_FILE, {
            "h1": dict(host, name="web01", group="lab", metrics_ts=self.now - 600,
                       sysinfo={"failed_units": ["nginx.service"]}),
            "h2": dict(host, name="db01", group="prod", metrics_ts=self.now - 600, sysinfo={"reboot_required": True}),
        })

    def bust(self):
        """Needs attention and Checks are cached for seconds; the scenarios change a host in between."""
        api = self.api
        api._LOAD_CACHE.clear()
        api.save(api._attention_cache_file(), {})
        api.save(api._fleet_checks_cache_file(), {})

    def fire(self, event, **payload):
        self.api._record_alert(event, payload)

    def alert_id(self, event):
        return next(a["id"] for a in self.api.load(self.api.ALERTS_FILE)["alerts"] if a["event"] == event)

    def resolve_by_hand(self, event, who="alice", at=None):
        with self.api._LockedUpdate(self.api.ALERTS_FILE) as store:
            for a in store["alerts"]:
                if a["event"] == event:
                    a["resolved_by"], a["resolved_at"] = who, at or self.now - 60
                    a["acknowledged_by"], a["acknowledged_at"] = who, at or self.now - 60

    def set_host(self, dev, **fields):
        with self.api._LockedUpdate(self.api.DEVICES_FILE) as devs:
            devs[dev].update(fields)

    def get(self, query=""):
        self.query = query
        self.bust()
        try:
            self.api.handle_problems()
        except self.api.HTTPError as e:
            self.status, body = e.status, e.body
            return body
        raise AssertionError("handle_problems did not respond")

    def row(self, body, dev, family):
        return next(r for r in body["problems"] if r["device_id"] == dev and r["family"] == family)


class TestTheIssueStory(_Endpoint):
    """Alerts, Needs attention and Checks, for a reset failed unit. The alert is resolved by hand; the host's
    next report is what clears Needs attention."""

    UNIT = dict(device_id="h1", name="web01", unit="nginx.service", units=["nginx.service"], new_count=1)

    def test_a_failed_unit_in_all_three_views_is_one_problem(self):
        self.fire("failed_unit", **self.UNIT)
        body = self.get()
        r = self.row(body, "h1", "failed_units")
        self.assertEqual((r["state"], r["sources"]), ("failing", ["alert", "attention", "check"]))
        self.assertEqual(sum(1 for p in body["problems"] if p["device_id"] == "h1"), 1)

    def test_resolved_by_hand_before_the_host_reports_again_waits_for_its_report(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)         # the host last reported 600 s ago
        r = self.row(self.get(), "h1", "failed_units")
        self.assertEqual(r["state"], "waiting_for_report")
        self.assertEqual((r["alerts"][0]["how"], r["alerts"][0]["resolved_by"]), ("hand", "alice"))

    def test_resolved_by_hand_and_still_reported_after_the_next_report_is_resolved_but_failing(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)
        self.set_host("h1", metrics_ts=self.now - 5)                  # the host reported again, unit still failed
        self.assertEqual(self.row(self.get(), "h1", "failed_units")["state"], "resolved_but_failing")

    def test_resolved_by_hand_and_cleared_on_the_host_is_resolved(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)
        self.set_host("h1", metrics_ts=self.now - 5, sysinfo={"failed_units": []})
        self.assertEqual(self.row(self.get("state=all"), "h1", "failed_units")["state"], "resolved")

    def test_an_open_alert_for_a_unit_the_host_stopped_reporting_is_host_clear(self):
        self.fire("failed_unit", **self.UNIT)
        self.set_host("h1", sysinfo={"failed_units": []})
        self.assertEqual(self.row(self.get(), "h1", "failed_units")["state"], "host_clear")

    def test_resolving_through_the_real_handler_gives_the_same_answer(self):
        """The resolve handler, not a hand-edited store: who closed it is what it records."""
        api = self.api
        self.fire("failed_unit", **self.UNIT)
        api._check_alert_mutation_perm = lambda: "alice"
        api.method = lambda: "POST"
        api._read_valid = lambda model: {}
        api._request_host_refresh = lambda ids: None
        try:
            api.handle_alert_resolve(self.alert_id("failed_unit"))
        except api.HTTPError as e:
            self.assertEqual(e.status, 200)
        r = self.row(self.get(), "h1", "failed_units")
        self.assertIn(r["state"], ("waiting_for_report", "resolved_but_failing"))
        self.assertEqual(r["alerts"][0]["resolved_by"], "alice")


class TestTheAlertsListSaysWhenTheHostDisagrees(_Endpoint):
    """The Alerts page, resolved view: "resolved by alice" must not read as "fixed" while the host still reports
    the problem. The inbox the operators open first (status=open) must not pay for this."""

    UNIT = dict(device_id="h1", name="web01", unit="nginx.service", units=["nginx.service"], new_count=1)

    def listing(self, status):
        self.query = f"status={status}"
        self.bust()
        try:
            self.api.handle_alerts_list()
        except self.api.HTTPError as e:
            self.assertEqual(e.status, 200)
            return e.body["alerts"]
        raise AssertionError("handle_alerts_list did not respond")

    def watch_rows(self):
        """Count the times the read model is built, and let it answer nothing."""
        calls = []
        mod = self.api.problems_handlers_mod
        original = mod._rows
        mod._rows = lambda days: (calls.append(days) or ([], 0))
        self.addCleanup(setattr, mod, "_rows", original)
        return calls

    def test_resolved_by_hand_while_the_host_still_reports_it(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)
        self.set_host("h1", metrics_ts=self.now - 5)
        self.assertEqual(self.listing("resolved")[0]["still_failing"], "resolved_but_failing")
        self.assertEqual(self.listing("all")[0]["still_failing"], "resolved_but_failing")

    def test_resolved_by_hand_before_the_host_reported_again(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)
        self.assertEqual(self.listing("resolved")[0]["still_failing"], "waiting_for_report")

    def test_nothing_is_said_when_the_host_has_cleared_it(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)
        self.set_host("h1", metrics_ts=self.now - 5, sysinfo={"failed_units": []})
        self.assertNotIn("still_failing", self.listing("resolved")[0])

    def test_an_alert_a_recovery_event_closed_is_not_called_still_failing(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", who="auto", at=self.now - 60)
        self.set_host("h1", metrics_ts=self.now - 5)
        self.assertNotIn("still_failing", self.listing("resolved")[0])

    def test_the_open_view_never_builds_the_read_model(self):
        self.fire("failed_unit", **self.UNIT)
        calls = self.watch_rows()
        self.assertEqual(len(self.listing("open")), 1)
        self.assertEqual(calls, [])

    def test_a_resolved_view_with_nothing_resolved_by_hand_does_not_build_it_either(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", who="auto", at=self.now - 60)
        calls = self.watch_rows()
        self.assertEqual(len(self.listing("resolved")), 1)
        self.assertEqual(calls, [])

    def test_a_failure_of_the_read_model_does_not_fail_the_list(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", at=self.now - 60)

        def boom(days):
            raise RuntimeError("the read model broke")
        mod = self.api.problems_handlers_mod
        original = mod._rows
        mod._rows = boom
        self.addCleanup(setattr, mod, "_rows", original)
        alerts = self.listing("resolved")
        self.assertEqual(len(alerts), 1)
        self.assertNotIn("still_failing", alerts[0])

    def test_every_alert_of_a_problem_is_named_on_its_row(self):
        self.fire("failed_unit", **self.UNIT)
        self.fire("failed_unit", device_id="h1", name="web01", unit="b.service", units=["b.service"], new_count=1)
        body = self.get()
        r = self.row(body, "h1", "failed_units")
        self.assertEqual(len(r["alert_ids"]), 2)
        self.assertEqual(set(r["open_ids"]), set(r["alert_ids"]))


class TestTheEndpointOffersTheActions(_Endpoint):
    def test_a_failed_unit_offers_mute_ignore_and_fix_from_the_real_stores(self):
        self.fire("failed_unit", device_id="h1", name="web01", unit="nginx.service", units=["nginx.service"], new_count=1)
        r = self.row(self.get(), "h1", "failed_units")
        self.assertEqual(r["mute_events"], ["failed_unit"])
        self.assertTrue(r["attention"][0]["ignore_key"], "Needs attention gave the item no ignore key")
        self.assertEqual(r["fix"]["kind"], "failed_units")
        self.assertIn(r["fix"]["source"], ("attention", "alert"))
        self.assertEqual(r["checks"][0]["key"], "services")
        self.assertEqual(r["open_ids"], [r["alerts"][0]["id"]])

    def test_a_problem_only_the_host_reports_still_offers_the_mute_its_item_stands_for(self):
        """No alert exists for it, so the only source of the event is the map from Needs attention kinds."""
        r = self.row(self.get(), "h2", "reboot")
        self.assertEqual(r["sources"], ["attention", "check"])
        self.assertEqual(r["mute_events"], ["reboot_required"])

    def test_an_alert_with_a_playbook_offers_the_fix_though_no_item_does(self):
        """No Needs attention item names a mitigation here, so only the alert's own rule can supply it."""
        self.fire("service_down", device_id="h2", name="db01", unit="postgres.service", active="failed")
        r = self.row(self.get(), "h2", "service_down")
        self.assertEqual(r["sources"], ["alert"])
        self.assertEqual((r["fix"] or {}).get("source"), "alert")
        self.assertEqual(r["fix"]["target"], "postgres.service")

    def test_the_fix_of_an_alert_is_asked_of_a_probe_and_never_written_onto_the_stored_alert(self):
        self.fire("service_down", device_id="h2", name="db01", unit="postgres.service", active="failed")
        self.get()
        stored = [a for a in self.api.load(self.api.ALERTS_FILE)["alerts"] if a["event"] == "service_down"]
        self.assertTrue(stored)
        for a in stored:
            self.assertNotIn("mitigation_kind", a)


class TestTheHistoryEndpoint(_Endpoint):
    UNIT = dict(device_id="h1", name="web01", unit="nginx.service", units=["nginx.service"], new_count=1)

    def history(self, query):
        self.query = query
        try:
            self.api.handle_problems_history()
        except self.api.HTTPError as e:
            self.status = e.status
            return e.body
        raise AssertionError("handle_problems_history did not respond")

    def test_it_reads_back_what_happened_to_the_issues_own_story(self):
        self.fire("failed_unit", **self.UNIT)
        self.resolve_by_hand("failed_unit", who="alice", at=int(time.time()) + 30)   # after it was raised
        h = self.history("device_id=h1&family=failed_units")
        self.assertEqual(self.status, 200)
        self.assertEqual([e["kind"] for e in h["events"]], ["resolved", "acknowledged", "raised"])
        self.assertEqual((h["events"][0]["by"], h["events"][0]["how"]), ("alice", "hand"))

    def test_a_host_outside_the_callers_scope_has_an_empty_history(self):
        self.fire("failed_unit", **self.UNIT)
        self.api._caller_scope = lambda: {"type": "groups", "values": ["prod"]}
        self.assertEqual(self.history("device_id=h1&family=failed_units")["events"], [])

    def test_bad_parameters_fall_back_and_an_unknown_family_is_empty(self):
        for q in ("", "family=", "device_id=h1&family=failed_units&days=zzz", "family=failed_units&days=99999&device_id=%00"):
            body = self.history(q)
            self.assertEqual(self.status, 200, q)
            self.assertEqual(body["events"], [])

    def test_it_needs_a_signed_in_caller(self):
        api = _fresh_api(auth=False)
        api._env = lambda k, d="": d
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_problems_history()
        self.assertEqual(cm.exception.status, 401)

    def test_the_route_is_registered(self):
        self.assertEqual(self.api._build_exact_routes()[("GET", "/api/problems/history")].__name__, "handle_problems_history")


class TestTheEndpoint(_Endpoint):
    def test_a_problem_only_the_host_reports_is_one_row_without_an_alert(self):
        """Needs attention and the reboot check both show it: one row, with both, and nothing to resolve."""
        body = self.get()
        r = self.row(body, "h2", "reboot")
        self.assertEqual((r["state"], r["sources"], r["can_resolve"]), ("failing", ["attention", "check"], False))
        self.assertEqual(sum(1 for p in body["problems"] if p["device_id"] == "h2"), 1)

    def test_the_default_is_what_needs_you_and_all_shows_the_rest(self):
        self.fire("failed_unit", device_id="h1", name="web01", unit="nginx.service")
        self.resolve_by_hand("failed_unit")
        self.set_host("h1", sysinfo={"failed_units": []}, metrics_ts=self.now - 5)
        self.assertNotIn("failed_units", [r["family"] for r in self.get()["problems"]])
        self.assertIn("failed_units", [r["family"] for r in self.get("state=all")["problems"]])
        self.assertEqual([r["family"] for r in self.get("state=resolved")["problems"]], ["failed_units"])

    def test_the_filters(self):
        self.fire("failed_unit", device_id="h1", name="web01", unit="nginx.service")
        both = self.get()
        self.assertEqual(sorted(r["device_id"] for r in both["problems"]), ["h1", "h2"])
        self.assertEqual([r["device_id"] for r in self.get("device_id=h2")["problems"]], ["h2"])
        self.assertEqual([r["family"] for r in self.get("source=alert")["problems"]], ["failed_units"])
        self.assertEqual([r["device_id"] for r in self.get("q=DB01")["problems"]], ["h2"])
        self.assertEqual(self.get("limit=1")["total"], 2)
        self.assertEqual(len(self.get("limit=1")["problems"]), 1)
        self.assertEqual(len(self.get("limit=1&offset=1")["problems"]), 1)

    def test_a_bad_parameter_falls_back_instead_of_failing(self):
        for q in ("limit=x&offset=-4&days=zzz&state=%00&source=&device_id=", "limit=0", "days=9999&limit=99999"):
            body = self.get(q)
            self.assertEqual(self.status, 200, q)
            self.assertLessEqual(body["limit"], 1000)
            self.assertLessEqual(body["days"], 30)

    def test_counts_cover_everything_the_caller_sees_whatever_the_filters(self):
        self.fire("failed_unit", device_id="h1", name="web01", unit="nginx.service")
        everything = self.get()["counts"]
        self.assertEqual(self.get("device_id=h2&source=attention")["counts"], everything)
        self.assertEqual(everything["total"], 2)

    def test_a_scoped_caller_sees_only_the_hosts_in_scope(self):
        """Alerts, Needs attention and Checks are all filtered through the caller's scope, not just the hosts."""
        api = self.api
        self.fire("failed_unit", device_id="h1", name="web01", unit="nginx.service")
        self.fire("reboot_required", device_id="h2", name="db01")
        api._caller_scope = lambda: {"type": "groups", "values": ["lab"]}
        body = self.get("state=all")
        self.assertEqual({r["device_id"] for r in body["problems"]}, {"h1"})
        self.assertEqual(body["counts"]["total"], 1)

    def test_the_endpoint_needs_a_signed_in_caller(self):
        api = _fresh_api(auth=False)
        api._env = lambda k, d="": d
        with self.assertRaises(api.HTTPError) as cm:
            api.handle_problems()
        self.assertEqual(cm.exception.status, 401)

    def test_an_unmonitored_host_is_not_a_problem(self):
        self.set_host("h2", monitored=False)
        self.assertNotIn("h2", {r["device_id"] for r in self.get("state=all")["problems"]})

    def test_a_check_switched_off_on_a_host_is_not_a_problem(self):
        api = self.api
        with api._LockedUpdate(api.CONFIG_FILE) as cfg:
            cfg["host_checks_disabled"] = {"h1": ["services"]}
        r = self.row(self.get(), "h1", "failed_units")
        self.assertEqual(r["sources"], ["attention"])

    def test_a_hand_edited_alert_store_does_not_fail_the_endpoint(self):
        api = self.api
        api.save(api.ALERTS_FILE, {"alerts": [None, "x", {"event": 3, "ts": "soon"}, 7], "alert_seq": 0})
        body = self.get()
        self.assertEqual(self.status, 200)
        self.assertIn("reboot", [r["family"] for r in body["problems"]])


if __name__ == "__main__":
    unittest.main()
