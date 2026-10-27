#!/usr/bin/env python3
"""v7.4.2, issue #44, the longer trend: seven days of hourly averages behind the last 100 checks.

The host card draws a trend from the numbers the last 100 polls kept, about eight hours at the
default five-minute cycle. For anything slower than that (a hub's free memory, a NAS volume)
eight hours says little, so a bound instance also folds each poll into a row per clock hour and
keeps the newest 168 of them. It is inside the file the polls already write (no new store), only
for an instance bound to a host, and only averages: a sum and a count per metric, so the average
is exact however many polls the hour held.

Three layers, like test_v742_host_integrations: the fold on its own, what the poll persists
(and drops again when the instance is unbound or removed), and what the host's answer carries.
The drawn line is in test_v742_host_integrations_e2e.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_host_integrations import HUB, OTHER, _Base, _Call, api, inst, result  # noqa: E402

H = 3600
# A clock hour well in the past, so "the next hour" is never in the future of a real poll.
T0 = (int(time.time()) // H) * H - 400 * H


class TestTheFold(unittest.TestCase):
    """api._integ_hourly_fold(rows, ts, nums): a pure function over the stored rows."""

    def test_the_first_poll_starts_an_hour(self):
        self.assertEqual(api._integ_hourly_fold([], T0 + 125, {"cpu": 10}),
                         [{"h": T0, "m": {"cpu": [10, 1]}}])

    def test_a_second_poll_in_the_same_hour_joins_it(self):
        rows = api._integ_hourly_fold([], T0 + 125, {"cpu": 10})
        rows = api._integ_hourly_fold(rows, T0 + 3599, {"cpu": 30})
        self.assertEqual(rows, [{"h": T0, "m": {"cpu": [40, 2]}}])

    def test_a_poll_in_the_next_hour_starts_a_new_row_after_it(self):
        rows = api._integ_hourly_fold([], T0 + 5, {"cpu": 10})
        rows = api._integ_hourly_fold(rows, T0 + H, {"cpu": 20})
        self.assertEqual([r["h"] for r in rows], [T0, T0 + H])
        self.assertEqual(rows[1]["m"], {"cpu": [20, 1]})

    def test_the_hour_boundary_is_the_clock_hour(self):
        a = api._integ_hourly_fold([], T0 + H - 1, {"x": 1})
        b = api._integ_hourly_fold(a, T0 + H, {"x": 1})
        self.assertEqual(len(b), 2, "the last second of an hour and the first of the next are two hours")

    def test_a_metric_one_poll_lacks_is_averaged_over_the_polls_that_had_it(self):
        rows = api._integ_hourly_fold([], T0 + 1, {"a": 10, "b": 100})
        rows = api._integ_hourly_fold(rows, T0 + 2, {"a": 20})
        self.assertEqual(rows[0]["m"], {"a": [30, 2], "b": [100, 1]})

    def test_a_poll_with_no_numbers_adds_nothing(self):
        self.assertEqual(api._integ_hourly_fold([], T0, {}), [])
        rows = [{"h": T0, "m": {"a": [1, 1]}}]
        self.assertEqual(api._integ_hourly_fold(rows, T0 + 5, {}), rows)

    def test_it_keeps_the_newest_168_hours(self):
        rows = []
        for i in range(200):
            rows = api._integ_hourly_fold(rows, T0 + i * H + 7, {"x": i})
        self.assertEqual(len(rows), 168)
        self.assertEqual(rows[0]["h"], T0 + 32 * H)
        self.assertEqual(rows[-1]["h"], T0 + 199 * H)
        self.assertEqual(rows[-1]["m"], {"x": [199, 1]})

    def test_a_late_poll_joins_its_own_hour_and_never_reorders_the_rows(self):
        rows = api._integ_hourly_fold([], T0 + 5, {"x": 1})
        rows = api._integ_hourly_fold(rows, T0 + H + 5, {"x": 2})
        rows = api._integ_hourly_fold(rows, T0 + 9, {"x": 3})          # the clock stepped back an hour
        self.assertEqual([r["h"] for r in rows], [T0, T0 + H])
        self.assertEqual(rows[0]["m"], {"x": [4, 2]})

    def test_a_poll_older_than_every_row_is_dropped_not_inserted_out_of_order(self):
        rows = api._integ_hourly_fold([], T0 + 5 * H, {"x": 1})
        rows = api._integ_hourly_fold(rows, T0 + 2 * H, {"x": 9})
        self.assertEqual([r["h"] for r in rows], [T0 + 5 * H])
        self.assertEqual(rows[0]["m"], {"x": [1, 1]})

    def test_what_it_is_given_is_not_changed_in_place(self):
        given = [{"h": T0, "m": {"a": [1, 1]}}]
        snapshot = json.dumps(given)
        api._integ_hourly_fold(given, T0 + 5, {"a": 2})
        self.assertEqual(json.dumps(given), snapshot)

    def test_damaged_rows_in_the_store_are_dropped_not_raised_on(self):
        """The file can be hand-edited, restored from a backup or written by a later version."""
        damaged = ["junk", None, 5, {"h": "x", "m": {}}, {"h": T0}, {"h": T0, "m": "no"},
                   {"h": T0, "m": {"a": "bad", "b": [1], "c": [1, 0], "d": [float("nan"), 1], "e": [2, 1]}}]
        rows = api._integ_hourly_fold(damaged, T0 + 5, {"z": 1})
        self.assertEqual(rows, [{"h": T0, "m": {"e": [2, 1], "z": [1, 1]}}])

    def test_not_a_list_reads_as_empty(self):
        for raw in (None, "x", 5, {"h": T0}):
            with self.subTest(raw=raw):
                self.assertEqual(api._integ_hourly_fold(raw, T0 + 1, {"a": 1}),
                                 [{"h": T0, "m": {"a": [1, 1]}}])

    def test_a_timestamp_that_is_not_a_time_uses_now(self):
        for bad in (None, "later", float("nan"), -5, 0, True):
            with self.subTest(ts=bad):
                rows = api._integ_hourly_fold([], bad, {"a": 1})
                self.assertEqual(len(rows), 1)
                self.assertLess(abs(rows[0]["h"] - (int(time.time()) // H) * H), 2 * H)

    def test_a_number_that_is_not_a_finite_number_is_left_out(self):
        rows = api._integ_hourly_fold([], T0, {"nan": float("nan"), "inf": float("inf"), "t": True, "ok": 1.5})
        self.assertEqual(rows[0]["m"], {"ok": [1.5, 1]})

    def test_at_most_twelve_metrics_a_row_like_the_short_trend(self):
        rows = api._integ_hourly_fold([], T0, {f"m{i}": i for i in range(30)})
        self.assertEqual(len(rows[0]["m"]), api._INTEG_NUMERIC_MAX)

    def test_metrics_that_change_name_between_polls_cannot_grow_a_row_past_the_cap(self):
        """One poll is cut to twelve numbers, but a service whose keys change from poll to poll
        would otherwise add twelve new names an hour for ever."""
        rows = []
        for i in range(10):
            rows = api._integ_hourly_fold(rows, T0 + i, {f"k{i}_{j}": j for j in range(12)})
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["m"]), api._INTEG_NUMERIC_MAX)
        self.assertEqual(sorted(rows[0]["m"])[:2], ["k0_0", "k0_1"], "the names that came first stay")


class TestWhatThePollPersists(_Base):

    def test_a_bound_instance_gets_a_row_per_hour(self):
        self.configure(inst(1, "free memory"))
        self.poll(result(1, "free memory", metrics={"freeMemory": 100}, ts=T0 + 5))
        self.poll(result(1, "free memory", metrics={"freeMemory": 300}, ts=T0 + 305))
        self.poll(result(1, "free memory", metrics={"freeMemory": 50}, ts=T0 + H + 5))
        self.assertEqual(self.state()["hourly"]["i1"],
                         [{"h": T0, "m": {"freeMemory": [400, 2]}},
                          {"h": T0 + H, "m": {"freeMemory": [50, 1]}}])

    def test_an_instance_bound_to_nothing_keeps_none(self):
        self.configure(inst(1, "x", device_id=""))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0))
        self.assertNotIn("i1", self.state().get("hourly", {}))

    def test_a_site_binding_alone_is_not_a_host_binding(self):
        self.configure(inst(1, "x", device_id="", site="hq"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0))
        self.assertNotIn("i1", self.state().get("hourly", {}))

    def test_unbinding_drops_the_rollup_and_the_numbers_of_the_short_history(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0 + 5))
        self.poll(result(1, "x", metrics={"n": 2}, ts=T0 + 305))
        self.assertIn("i1", self.state()["hourly"])
        self.assertIn("m", self.state()["history"]["i1"][-1])
        self.configure(inst(1, "x", device_id=""))
        self.poll(result(1, "x", metrics={"n": 3}, ts=T0 + 605))
        st = self.state()
        self.assertNotIn("i1", st.get("hourly", {}))
        self.assertTrue(all("m" not in e for e in st["history"]["i1"]),
                        "numbers are kept only for an instance bound to a host")

    def test_removing_the_instance_drops_its_rollup_and_keeps_the_others(self):
        self.configure(inst(1, "a"), inst(2, "b", device_id=OTHER))
        self.poll(result(1, "a", metrics={"n": 1}, ts=T0), result(2, "b", metrics={"n": 2}, ts=T0))
        self.assertEqual(set(self.state()["hourly"]), {"i1", "i2"})
        self.configure(inst(2, "b", device_id=OTHER))
        self.poll(result(2, "b", metrics={"n": 3}, ts=T0 + 300))
        self.assertEqual(set(self.state()["hourly"]), {"i2"})

    def test_a_transient_empty_config_does_not_wipe_the_rollups(self):
        """The same guard the history has: during an upgrade restart the configured set can read
        empty for a moment, and that must not cost a week of trend."""
        self.configure(inst(1, "a"))
        self.poll(result(1, "a", metrics={"n": 1}, ts=T0))
        self.configure()            # no instances at all
        self.poll(result(1, "a", metrics={"n": 2}, ts=T0 + 300))
        self.assertIn("i1", self.state().get("hourly", {}))

    def test_booleans_and_non_finite_numbers_never_reach_it(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"up": True, "bad": float("nan"), "inf": float("inf"), "n": 3}, ts=T0))
        self.assertEqual(self.state()["hourly"]["i1"][0]["m"], {"n": [3, 1]})

    def test_a_poll_with_no_numbers_adds_no_row(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"state": "ok"}, ts=T0))
        self.assertNotIn("i1", self.state().get("hourly", {}))

    def test_a_checked_time_that_is_not_a_time_still_counts_the_poll(self):
        self.configure(inst(1, "x"))
        r = result(1, "x", metrics={"n": 1})
        r["checked"] = "garbage"
        self.poll(r)
        rows = self.state()["hourly"]["i1"]
        self.assertEqual(len(rows), 1)
        self.assertLess(abs(rows[0]["h"] - (int(time.time()) // H) * H), 2 * H)

    def test_a_week_of_twelve_metrics_stays_small(self):
        self.configure(inst(1, "x"))
        metrics = {f"metric_number_{i}": 123456.789 + i for i in range(12)}
        for i in range(200):
            api._LOAD_CACHE.clear()
            api._persist_integration_results([result(1, "x", metrics=metrics, ts=T0 + i * H + 11)])
        rows = self.state()["hourly"]["i1"]
        self.assertEqual(len(rows), 168)
        self.assertLess(len(json.dumps(rows)), 90_000, "the file every poll rewrites must stay small")

    def test_the_status_endpoint_does_not_carry_it(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0))

        class Cap(SystemExit):
            pass
        out = {}

        def fake(status, data):
            out["body"] = data
            raise Cap()
        saved = (api.respond, api.require_auth)
        api.respond, api.require_auth = fake, (lambda *a, **k: None)
        try:
            api.handle_integrations_status()
        except Cap:
            pass
        finally:
            api.respond, api.require_auth = saved
        self.assertEqual(set(out["body"]), {"latest", "history"})


class TestTheAnswer(_Base, _Call):

    def get(self, dev=HUB):
        status, body = self.run_handler(api.handle_device_integrations, dev)
        self.assertEqual(status, 200, body)
        return body

    def test_the_trend_is_the_hourly_average(self):
        self.configure(inst(1, "free memory"))
        self.poll(result(1, "free memory", metrics={"freeMemory": 100}, ts=T0 + 5))
        self.poll(result(1, "free memory", metrics={"freeMemory": 300}, ts=T0 + 305))
        self.poll(result(1, "free memory", metrics={"freeMemory": 50}, ts=T0 + H + 5))
        row = self.get()["integrations"][0]
        self.assertEqual(row["series_long"], {"freeMemory": [{"ts": T0, "val": 200}, {"ts": T0 + H, "val": 50}]})

    def test_an_average_is_rounded_to_a_value_a_chart_can_use(self):
        self.configure(inst(1, "x"))
        for i, v in enumerate((1, 1, 2)):
            self.poll(result(1, "x", metrics={"n": v}, ts=T0 + i * 60))
        val = self.get()["integrations"][0]["series_long"]["n"][0]["val"]
        self.assertEqual(val, round(4 / 3, 3))

    def test_the_short_trend_is_still_there_and_unchanged(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0 + 5))
        self.poll(result(1, "x", metrics={"n": 2}, ts=T0 + 305))
        row = self.get()["integrations"][0]
        self.assertEqual(row["series"], {"n": [{"ts": T0 + 5, "val": 1}, {"ts": T0 + 305, "val": 2}]})

    def test_an_instance_with_no_rollup_has_an_empty_one(self):
        self.configure(inst(1, "x"))
        self.assertEqual(self.get()["integrations"][0]["series_long"], {})

    def test_a_disabled_instance_has_no_trend(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0 + 5))
        self.configure(inst(1, "x", enabled=False))
        self.assertEqual(self.get()["integrations"][0]["series_long"], {})

    def test_another_hosts_trend_is_not_in_this_hosts_answer(self):
        self.configure(inst(1, "a"), inst(2, "b", device_id=OTHER))
        self.poll(result(1, "a", metrics={"n": 1}, ts=T0), result(2, "b", metrics={"n": 99}, ts=T0))
        rows = self.get(HUB)["integrations"]
        self.assertEqual([r["label"] for r in rows], ["a"])
        self.assertEqual(rows[0]["series_long"]["n"], [{"ts": T0, "val": 1}])
        self.assertNotIn("99", json.dumps(rows))

    def test_damaged_rollup_in_the_store_cannot_break_the_answer(self):
        self.configure(inst(1, "x"))
        self.poll(result(1, "x", metrics={"n": 1}, ts=T0))
        st = self.state()
        st["hourly"]["i1"] = ["junk", {"h": T0, "m": {"n": "bad"}}, {"h": "x"}, {"h": T0 + H, "m": {"n": [4, 2]}}]
        api.save(api.INTEG_STATE_FILE, st)
        api._LOAD_CACHE.clear()
        self.assertEqual(self.get()["integrations"][0]["series_long"], {"n": [{"ts": T0 + H, "val": 2}]})

    def test_the_hourly_key_being_something_else_cannot_break_the_answer(self):
        self.configure(inst(1, "x"))
        api.save(api.INTEG_STATE_FILE, {"latest": {}, "history": {}, "hourly": "no"})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.get()["integrations"][0]["series_long"], {})


if __name__ == "__main__":
    unittest.main()
