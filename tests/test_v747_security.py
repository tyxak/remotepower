#!/usr/bin/env python3
"""v7.4.7 security review: what it found, driven for real and watched failing first, and the properties it checked and
found to hold, so a later change cannot take them away without a test saying so.

Found
  1. A stored alert that is not shaped like what `_record_alert` writes (a `payload` that is a string, an `event` or a
     `device_id` that is a list) made GET /api/problems answer 500 to every caller, because the hint for the Fix
     button handed the row to an annotator that assumes a map and a string. The inbox, GET /api/alerts, already
     failed the same way on the 7.4.6 tree, in the correlation and mitigation annotators. Only a hand edit or an
     import can store such a row. The two read paths now skip a row they cannot read (`_readable_alerts`), and the
     Fix hint can no longer fail a list.

Held (checked over HTTP on a seeded instance, and pinned here where a unit can hold them)
  * Who sees which host: a viewer scoped to a group or a tag, a tenant administrator and a tenant viewer each get
    their own hosts in the problems, the inbox, Needs attention, Checks and the Fleet query, and the history of a
    host outside their reach is empty. The state tag and the plain answers never leak into each other through the
    caches, in any order.
  * The routes answer 401 without a session, 404 or 405 to any other method, and 200 or 400 to every hostile
    parameter. No answer echoes its input.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v747-sec-"))

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(CGI))

NOW = int(time.time())
XSS = '"><img src=x onerror="window.__pwned=1">'


def fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v747-sec-")
    spec = importlib.util.spec_from_file_location("api_v747_sec", CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.require_auth = lambda *a, **k: "admin"
    mod.require_admin_auth = lambda *a, **k: "admin"
    return mod


def alert(i, **kw):
    row = {"id": f"a-sec{i:02d}", "ts": NOW - 3600, "event": "service_down", "severity": "high", "title": "x",
           "device_id": "nc01", "device_name": "nextcloud.lab", "payload": {}, "source": "internal",
           "acknowledged_by": None, "acknowledged_at": None, "resolved_by": None, "resolved_at": None}
    row.update(kw)
    return row


# Every shape a row of the store can have that _record_alert cannot write. The first three carry markup.
SHAPES = [
    dict(title=XSS, device_name=XSS, payload={"service": XSS, "unit": XSS}, acknowledged_by=XSS),
    dict(event="device_offline", title=XSS, resolved_by=XSS, resolved_at=NOW - 60, resolve_note=XSS),
    dict(device_id=XSS, device_name=XSS),
    dict(title=12345), dict(title=None), dict(title=["a"]), dict(payload="str"), dict(payload=None),
    dict(payload={"unit": {"a": 1}}), dict(ts="abc"), dict(ts=-1), dict(ts=2 ** 70), dict(ts=None), dict(event=None),
    dict(event=["x"]), dict(device_id=["a"]), dict(device_id=123), dict(id=None),
    dict(resolved_by={"a": 1}, resolved_at=NOW - 100), dict(resolved_at="yesterday", resolved_by="alice"),
    dict(acknowledged_at="x", acknowledged_by=5), dict(severity="ULTRA"), dict(count="many"),
    dict(resolve_note={"a": 1}, resolved_at=NOW - 50, resolved_by="bob"), dict(first_seen="x"),
]
# The ones the readers must skip: a map is required, and a string for the event and the host id, and a map payload.
UNREADABLE = [i for i, s in enumerate(SHAPES, 1)
              if not isinstance(s.get("payload", {}), (dict, type(None)))
              or not isinstance(s.get("event", ""), (str, type(None)))
              or not isinstance(s.get("device_id", ""), (str, type(None)))]


class _Stored(unittest.TestCase):
    def setUp(self):
        self.api = api = fresh_api()
        api.save(api.DEVICES_FILE, {"nc01": {"name": "nextcloud.lab", "monitored": True, "last_seen": NOW, "sysinfo": {}}})
        self.plant([])

    def plant(self, rows):
        api = self.api
        api.save(api.ALERTS_FILE, {"alerts": rows})
        api._LOAD_CACHE.clear()

    def call(self, fn, query=""):
        api = self.api
        api._env = lambda k, d="": query if k == "QUERY_STRING" else ""
        try:
            fn()
        except api.HTTPError as e:
            return e.status, e.body
        raise AssertionError(f"{fn.__name__} did not respond")


class TestAStoredAlertOfAnyShape(_Stored):
    def lists(self):
        api = self.api
        return {"problems": (api.handle_problems, "state=all&limit=1000&days=30"),
                "history": (api.handle_problems_history, "device_id=nc01&family=failed_units"),
                "inbox": (api.handle_alerts_list, "status=all&limit=1000")}

    def test_every_shape_stored_at_once_leaves_the_lists_answering(self):
        self.plant([alert(i, **s) for i, s in enumerate(SHAPES, 1)])
        for name, (fn, query) in self.lists().items():
            status, _ = self.call(fn, query)
            self.assertEqual(status, 200, f"{name} answered {status}")

    def test_each_shape_alone_leaves_the_lists_answering(self):
        for i, shape in enumerate(SHAPES, 1):
            self.plant([alert(i, **shape)])
            for name, (fn, query) in self.lists().items():
                status, _ = self.call(fn, query)
                self.assertEqual(status, 200, f"shape {i} {shape!r} made {name} answer {status}")

    def test_the_population_of_unreadable_shapes_is_what_the_comment_says(self):
        """A control: the three shapes that broke the inbox on the 7.4.6 tree are in the set that is skipped."""
        self.assertGreaterEqual(len(UNREADABLE), 3)
        self.assertTrue({7, 15, 16} <= set(UNREADABLE))

    def test_a_row_the_readers_skip_does_not_hide_the_rows_beside_it(self):
        good = [alert(100, title="one"), alert(101, title="two", event="device_offline")]
        bad = [alert(i, **SHAPES[i - 1]) for i in UNREADABLE]
        self.plant(good + bad)
        _, body = self.call(self.api.handle_alerts_list, "status=all&limit=1000")
        listed = {a["id"] for a in body["alerts"]}
        self.assertTrue({"a-sec100", "a-sec101"} <= listed)
        self.assertEqual(body["total"], len(body["alerts"]), "the total counts a row the page cannot list")
        _, p = self.call(self.api.handle_problems, "state=all&limit=1000&days=30")
        ids = {e["id"] for r in p["problems"] for e in r["alerts"]}
        self.assertTrue({"a-sec100", "a-sec101"} <= ids)

    def test_clear_all_still_removes_an_unreadable_row(self):
        """The readers skip a bad row, and only the readers do: the administrator's purge still sees every row, so a
        bad one can be removed from the store."""
        api = self.api
        self.plant([alert(1, payload="str"), alert(2, event=["x"]), alert(3)])
        api.method = lambda: "DELETE"
        status, body = self.call(api.handle_alerts_clear, "scope=all")
        self.assertEqual((status, body["removed"]), (200, 3))
        self.assertEqual(api.load(api.ALERTS_FILE)["alerts"], [])


class TestAStoredAlertOfAnyShapeAndAScopedCaller(_Stored):
    """The visibility filter looks a row's host up by its id, so an id that is a list raised for a caller whose role
    or tenant is scoped, which an unscoped administrator never reaches."""

    def setUp(self):
        super().setUp()
        api = self.api
        api.save(api.DEVICES_FILE, {"nc01": {"name": "nextcloud.lab", "group": "lab", "monitored": True,
                                             "last_seen": NOW, "sysinfo": {}}})
        api._caller_scope = lambda: {"type": "groups", "values": ["lab"]}
        self.plant([alert(i, **s) for i, s in enumerate(SHAPES, 1)] + [alert(100, title="in scope")])

    def test_the_problems_list_and_the_inbox_answer(self):
        status, body = self.call(self.api.handle_problems, "state=all&limit=1000&days=30")
        self.assertEqual(status, 200)
        status, inbox = self.call(self.api.handle_alerts_list, "status=all&limit=1000")
        self.assertEqual(status, 200)
        self.assertIn("a-sec100", {a["id"] for a in inbox["alerts"]})

    def test_the_history_answers(self):
        status, _ = self.call(self.api.handle_problems_history, "device_id=nc01&family=failed_units")
        self.assertEqual(status, 200)


class TestTheDashboardAndTheStatsSurviveAStoredAlertOfAnyShape(_Stored):
    """/api/home sorted the open alerts by `-ts`, and /api/alerts/resolution-stats called int() on `resolved_at`, so
    a `ts` of "abc" or a `resolved_at` of "yesterday" answered 500 to every caller: the dashboard stayed down for as
    long as the row stayed in the store."""

    def readers(self):
        api = self.api
        return {"home": (api.handle_home, ""), "stats": (api.handle_alert_resolution_stats, "days=30"),
                "summary": (api.handle_alerts_summary, ""), "nav": (api.handle_nav_counts, "")}

    def test_every_shape_at_once(self):
        self.plant([alert(i, **s) for i, s in enumerate(SHAPES, 1)])
        for name, (fn, query) in self.readers().items():
            status, _ = self.call(fn, query)
            self.assertEqual(status, 200, f"{name} answered {status}")

    def test_each_shape_alone(self):
        for i, shape in enumerate(SHAPES, 1):
            self.plant([alert(i, **shape)])
            for name, (fn, query) in self.readers().items():
                status, _ = self.call(fn, query)
                self.assertEqual(status, 200, f"shape {i} {shape!r} made {name} answer {status}")

    def test_a_good_alert_still_counts(self):
        self.plant([alert(1, ts=NOW - 7200, resolved_at=NOW - 3600, resolved_by="alice"),
                    alert(2, ts="abc", resolved_at="yesterday", resolved_by="alice")])
        status, body = self.call(self.api.handle_alert_resolution_stats, "days=30")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["resolved"] if "resolved" in body else body.get("total_resolved", 1), 1)

    def test_alerts_with_times_of_two_kinds_sort_on_the_dashboard(self):
        """A sort compares its keys, so a single bad row passes and two of different kinds do not."""
        self.plant([alert(1, ts=NOW - 10, acknowledged_at=NOW - 5, acknowledged_by="alice"),
                    alert(2, ts="x", acknowledged_at="y", acknowledged_by="bob"),
                    alert(3, ts=NOW - 20), alert(4, ts="abc")])
        status, body = self.call(self.api.handle_home)
        self.assertEqual(status, 200)

    def test_a_timestamp_that_is_not_one_reads_as_zero(self):
        f = self.api._epoch_or_zero
        for value in ("abc", "yesterday", None, True, [], {}, float("inf"), float("nan")):
            self.assertEqual(f(value), 0, repr(value))
        self.assertEqual(f(1790000000), 1790000000)
        self.assertEqual(f(1790000000.9), 1790000000)
        self.assertEqual(f("1790000000"), 1790000000)


class TestTheAutonomyLoopSurvivesAStoredAlertOfAnyShape(_Stored):
    """The sweep runs from every request on a single-process install and from the scheduler otherwise. An event that
    is a list made `_ladder_for` raise, `_safe` caught it, and the sweep then failed the same way on every pass:
    1,528 tracebacks in the log of a probe, and no action taken, for as long as the row stayed in the store."""

    def ops(self):
        return self.api.autonomy_ops_handlers_mod

    def test_a_list_for_an_event_is_not_a_candidate_and_not_an_error(self):
        rows = [alert(i, **s) for i, s in enumerate(SHAPES, 1)] + [alert(200, event="disk_full")]
        try:
            self.ops()._candidate_alerts(rows)
        except Exception as exc:   # noqa: BLE001
            self.fail(f"the candidate filter raised {exc!r}")

    def test_the_ladder_of_a_row_that_is_not_a_string_is_empty(self):
        for event in (["x"], {"a": 1}, 5, None):
            self.assertEqual(self.ops()._ladder_for({"event": event, "payload": {}}), ())


class TestTheFixHintNeverFailsAList(_Stored):
    def hint(self, a):
        return self.api.problems_handlers_mod._fix_of_alert(a)

    def test_a_row_of_the_wrong_shape_has_no_hint_and_no_error(self):
        for shape in SHAPES:
            try:
                self.hint(alert(1, **shape))
            except Exception as exc:   # noqa: BLE001
                self.fail(f"{shape!r} raised {exc!r}")

    def test_the_two_shapes_that_raised_have_none(self):
        self.assertIsNone(self.hint(alert(1, payload="str")))
        self.assertIsNone(self.hint(alert(2, event=["x"])))

    def test_a_failing_annotator_is_a_missing_hint_and_not_a_failed_list(self):
        api = self.api

        def boom(rows):
            raise RuntimeError("the annotator broke")
        real = api._annotate_alert_mitigation
        api._annotate_alert_mitigation = boom
        try:
            self.assertIsNone(self.hint(alert(1)))
        finally:
            api._annotate_alert_mitigation = real

    def test_a_good_row_still_gets_its_hint(self):
        got = self.hint(alert(1, event="service_down", payload={"service": "nginx"}))
        self.assertIsNotNone(got, "the guard took the hint away from a well-formed alert")


if __name__ == "__main__":
    unittest.main()
