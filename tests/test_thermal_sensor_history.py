"""A temperature history for every sensor a host reports, not only the hottest.

The Thermal page charted one series per host: its hottest reading. Every other row of the sensor table had no
history at all. thermal_sensors.py keeps one for each row, in rows that already exist: a ring of points in
thermal_history.json (about every 14 minutes for a day) and hourly buckets in thermal_rollup.json (30 days).

The pure rules are held by the first classes. The classes after them drive the real hardware ingest, the real
roll-up sweep and the real endpoint, because what the page draws is what those three leave in the store.
"""

import math
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sensorhist-"))

import api  # noqa: E402
import thermal_sensors as ts  # noqa: E402

NOW = 1_790_000_000
SENSOR = "sensor|coretemp Core 0"
DISK = "disk|/dev/sda"
GPU = "gpu|RTX 4070"


def board(label, value):
    return {"label": label, "current_c": value}


class TestKeys(unittest.TestCase):

    def test_a_key_is_the_kind_and_the_label(self):
        self.assertEqual(ts.key_for("sensor", "coretemp Core 0"), SENSOR)
        self.assertEqual(ts.split_key(SENSOR), ("sensor", "coretemp Core 0"))

    def test_a_label_may_hold_the_separator(self):
        key = ts.key_for("disk", "a|b|c")
        self.assertEqual(ts.split_key(key), ("disk", "a|b|c"))

    def test_an_empty_label_reads_as_the_row_prints_it(self):
        """The Thermal page prints 'sensor', 'disk' and 'GPU' for a row with no name; a key built from the
        report has to be the key the page asks for."""
        self.assertEqual(ts.key_for("sensor", ""), "sensor|sensor")
        self.assertEqual(ts.key_for("disk", None), "disk|disk")
        self.assertEqual(ts.key_for("gpu", ""), "gpu|GPU")

    def test_only_the_three_kinds_have_keys(self):
        for kind in ("", "SENSOR", "host", None, 5, "sensor|x"):
            with self.subTest(kind=kind):
                self.assertIsNone(ts.key_for(kind, "x"))

    def test_a_label_is_cut_at_the_limit_and_the_cut_key_reads_back(self):
        key = ts.key_for("gpu", "x" * 500)
        self.assertEqual(len(key), len("gpu|") + ts.MAX_LABEL)
        self.assertEqual(ts.split_key(key), ("gpu", "x" * ts.MAX_LABEL))

    def test_a_malformed_key_is_refused(self):
        for key in (None, 5, "", "sensor", "sensor|", "|x", "host|x", "sensor|" + "x" * (ts.MAX_LABEL + 1), ["sensor|x"]):
            with self.subTest(key=key):
                self.assertIsNone(ts.split_key(key))


class TestReadings(unittest.TestCase):

    def test_every_kind_of_row_the_page_lists_gets_a_reading(self):
        got = ts.readings(
            [board("coretemp Core 0", 51.0)],
            [{"device": "/dev/sda", "temperature_c": 38}],
            [{"name": "RTX 4070", "temp_c": 62}],
        )
        self.assertEqual(got, [(SENSOR, 51.0), (DISK, 38.0), (GPU, 62.0)])

    def test_a_list_the_report_did_not_carry_gives_nothing(self):
        """None is "not in this report". A reading kept from an older report is not sampled again under a new
        time, which is why the ingest passes None and not the stored list."""
        self.assertEqual(ts.readings(None, None, None), [])
        self.assertEqual(ts.readings([board("a", 40)], None, None), [("sensor|a", 40.0)])

    def test_a_reading_no_sensor_could_have_produced_is_dropped(self):
        rows = [board("rail", 127.0), board("rail2", -128), board("hot", 151), board("cold", -41),
                board("nan", float("nan")), board("inf", float("inf")), board("flag", True),
                board("text", "50"), board("none", None), board("ok", 150.0), board("ok2", -40)]
        self.assertEqual(ts.readings(rows, None, None), [("sensor|ok", 150.0), ("sensor|ok2", -40.0)])

    def test_a_name_that_appears_twice_keeps_its_first_reading(self):
        self.assertEqual(ts.readings([board("Core 0", 40), board("Core 0", 70)], None, None), [("sensor|Core 0", 40.0)])

    def test_the_same_label_on_two_kinds_is_two_series(self):
        got = dict(ts.readings([board("x", 40)], [{"device": "x", "temperature_c": 41}], [{"name": "x", "temp_c": 42}]))
        self.assertEqual(got, {"sensor|x": 40.0, "disk|x": 41.0, "gpu|x": 42.0})

    def test_a_row_that_is_not_a_map_is_skipped(self):
        self.assertEqual(ts.readings(["a", 5, None, board("ok", 40)], "text", {"name": "x"}), [("sensor|ok", 40.0)])


class TestRing(unittest.TestCase):

    def test_a_point_is_added_for_each_reading(self):
        ring = ts.ring_add({}, [(SENSOR, 50.0), (DISK, 38.0)], NOW)
        self.assertEqual(ring, {SENSOR: [[NOW, 50.0]], DISK: [[NOW, 38.0]]})

    def test_a_report_inside_the_gap_adds_nothing(self):
        ring = ts.ring_add({}, [(SENSOR, 50.0)], NOW)
        again = ts.ring_add(ring, [(SENSOR, 55.0)], NOW + ts.RING_GAP_S - 1)
        self.assertEqual(again, ring)

    def test_a_report_at_the_gap_adds_a_point(self):
        ring = ts.ring_add({}, [(SENSOR, 50.0)], NOW)
        again = ts.ring_add(ring, [(SENSOR, 55.0)], NOW + ts.RING_GAP_S)
        self.assertEqual(again[SENSOR], [[NOW, 50.0], [NOW + ts.RING_GAP_S, 55.0]])

    def test_a_clock_that_went_backwards_adds_nothing(self):
        ring = ts.ring_add({}, [(SENSOR, 50.0)], NOW)
        self.assertEqual(ts.ring_add(ring, [(SENSOR, 55.0)], NOW - 5000), ring)

    def test_the_stored_ring_is_not_changed(self):
        stored = {SENSOR: [[NOW, 50.0]]}
        ts.ring_add(stored, [(SENSOR, 55.0)], NOW + 5000)
        self.assertEqual(stored, {SENSOR: [[NOW, 50.0]]})

    def test_points_older_than_a_day_go_and_so_does_an_empty_series(self):
        ring = {SENSOR: [[NOW - ts.RING_KEEP_S - 1, 40.0], [NOW - 3600, 41.0]], DISK: [[NOW - ts.RING_KEEP_S - 5, 30.0]]}
        out = ts.ring_add(ring, [], NOW)
        self.assertEqual(out, {SENSOR: [[NOW - 3600, 41.0]]})

    def test_a_series_holds_at_most_its_point_cap(self):
        """The gap and the age already keep a series near a hundred points, so the cap is the guard for a ring
        that was written some other way: 500 points inside the last hour come back as the newest hundred and
        twenty."""
        crowded = {SENSOR: [[NOW - 3600 + i, 40.0 + i % 5] for i in range(500)]}
        out = ts.ring_add(crowded, [], NOW)
        self.assertEqual(len(out[SENSOR]), ts.RING_MAX_POINTS)
        self.assertEqual(out[SENSOR][-1], crowded[SENSOR][-1])

    def test_a_long_run_of_reports_stays_inside_a_day(self):
        ring = {}
        for i in range(ts.RING_MAX_POINTS + 30):
            ring = ts.ring_add(ring, [(SENSOR, 40.0 + i % 5)], NOW + i * ts.RING_GAP_S)
        last = NOW + (ts.RING_MAX_POINTS + 29) * ts.RING_GAP_S
        self.assertLessEqual(len(ring[SENSOR]), ts.RING_MAX_POINTS)
        self.assertEqual(ring[SENSOR][-1][0], last)
        self.assertGreaterEqual(ring[SENSOR][0][0], last - ts.RING_KEEP_S)

    def test_a_host_never_holds_more_than_the_series_cap(self):
        readings = [(f"sensor|s{i}", 40.0) for i in range(ts.MAX_SERIES + 10)]
        ring = ts.ring_add({}, readings, NOW)
        self.assertEqual(len(ring), ts.MAX_SERIES)
        self.assertIn("sensor|s0", ring)
        self.assertNotIn(f"sensor|s{ts.MAX_SERIES}", ring)

    def test_a_series_that_is_already_kept_is_not_refused_at_the_cap(self):
        ring = ts.ring_add({}, [(f"sensor|s{i}", 40.0) for i in range(ts.MAX_SERIES)], NOW)
        ring = ts.ring_add(ring, [("sensor|s3", 41.0), ("sensor|new", 42.0)], NOW + 5000)
        self.assertEqual(ring["sensor|s3"][-1], [NOW + 5000, 41.0])
        self.assertNotIn("sensor|new", ring)

    def test_a_slot_comes_free_when_a_series_has_been_silent_for_a_day(self):
        ring = ts.ring_add({}, [(f"sensor|s{i}", 40.0) for i in range(ts.MAX_SERIES)], NOW)
        later = NOW + ts.RING_KEEP_S + 10
        ring = ts.ring_add(ring, [("sensor|new", 42.0)], later)
        self.assertEqual(list(ring), ["sensor|new"])

    def test_a_reading_that_is_not_usable_or_not_named_is_left_out(self):
        ring = ts.ring_add({}, [(SENSOR, 999.0), ("nope", 40.0), (DISK, 38.0), (GPU, "hot")], NOW)
        self.assertEqual(ring, {DISK: [[NOW, 38.0]]})

    def test_raw_points_come_in_the_shape_of_the_rollup_endpoint(self):
        ring = ts.ring_add({}, [(SENSOR, 50.5)], NOW)
        self.assertEqual(ts.raw_points(ring, SENSOR), [{"ts": NOW, "temp": {"min": 50.5, "avg": 50.5, "max": 50.5}}])
        self.assertEqual(ts.raw_points(ring, DISK), [])


class TestFold(unittest.TestCase):

    def ring(self, series, step=900, start=NOW):
        """{key: [[ts, v], ...]} with `step` seconds between points."""
        return {key: [[start + i * step, v] for i, v in enumerate(values)] for key, values in series.items()}

    def test_points_fold_into_the_hour_they_belong_to(self):
        start = NOW - NOW % 3600
        rec, changed = ts.fold_hourly({}, self.ring({SENSOR: [40, 42, 44, 46, 50]}, start=start), start + 5 * 900)
        self.assertTrue(changed)
        rows = rec["hourly"][SENSOR]
        self.assertEqual(rows, [[start, 40.0, 46.0, 172.0, 4], [start + 3600, 50.0, 50.0, 50.0, 1]])
        self.assertEqual(rec["last_ts"], start + 4 * 900)

    def test_a_bucket_reads_as_min_avg_max(self):
        start = NOW - NOW % 3600
        rec, _ = ts.fold_hourly({}, self.ring({SENSOR: [40, 42, 44, 46]}, start=start), start + 3600)
        self.assertEqual(ts.hourly_points(rec, SENSOR), [{"ts": start, "temp": {"min": 40.0, "avg": 43.0, "max": 46.0}}])

    def test_folding_the_same_ring_twice_changes_nothing(self):
        ring = self.ring({SENSOR: [40, 42, 44, 46, 50]})
        once, _ = ts.fold_hourly({}, ring, NOW + 7200)
        twice, changed = ts.fold_hourly(once, ring, NOW + 7200)
        self.assertEqual(twice, once)
        self.assertFalse(changed)

    def test_a_bucket_of_the_current_hour_grows_as_new_points_arrive(self):
        start = NOW - NOW % 3600
        first, _ = ts.fold_hourly({}, self.ring({SENSOR: [40, 42]}, start=start), start + 1800)
        grown, changed = ts.fold_hourly(first, self.ring({SENSOR: [40, 42, 44, 60]}, start=start), start + 3500)
        self.assertTrue(changed)
        self.assertEqual(grown["hourly"][SENSOR], [[start, 40.0, 60.0, 186.0, 4]])

    def test_buckets_older_than_thirty_days_are_pruned(self):
        old = NOW - ts.HOURLY_KEEP_S - 7200
        rec, changed = ts.fold_hourly({}, self.ring({SENSOR: [40], DISK: [30]}, start=old), old + 7200)
        self.assertEqual(rec["hourly"], {SENSOR: [[old - old % 3600, 40.0, 40.0, 40.0, 1]], DISK: [[old - old % 3600, 30.0, 30.0, 30.0, 1]]})
        pruned, changed = ts.fold_hourly(rec, {}, NOW)
        self.assertTrue(changed)
        self.assertEqual(pruned["hourly"], {})

    def test_a_hold_keeps_what_is_already_there(self):
        old = NOW - ts.HOURLY_KEEP_S - 7200
        rec, _ = ts.fold_hourly({}, self.ring({SENSOR: [40]}, start=old), old + 7200)
        kept, _ = ts.fold_hourly(rec, self.ring({SENSOR: [41]}, start=NOW), NOW + 10, hold=True)
        self.assertEqual(len(kept["hourly"][SENSOR]), 2)

    def test_a_series_beyond_the_cap_is_dropped_and_the_rest_are_folded(self):
        ring = self.ring({f"sensor|s{i}": [40] for i in range(ts.MAX_SERIES + 5)})
        rec, _ = ts.fold_hourly({}, ring, NOW + 900)
        self.assertEqual(len(rec["hourly"]), ts.MAX_SERIES)

    def test_a_series_silent_for_a_week_gives_its_slot_to_a_new_one(self):
        quiet = NOW - ts.STALE_S - 7200
        rec, _ = ts.fold_hourly({}, self.ring({f"sensor|s{i}": [40] for i in range(ts.MAX_SERIES)}, start=quiet), quiet + 900)
        rec, _ = ts.fold_hourly(rec, self.ring({"sensor|new": [41]}, start=NOW), NOW + 900, hold=True)
        self.assertIn("sensor|new", rec["hourly"])
        self.assertEqual(len(rec["hourly"]), ts.MAX_SERIES)

    def test_a_series_that_is_recent_does_not_give_its_slot_away(self):
        rec, _ = ts.fold_hourly({}, self.ring({f"sensor|s{i}": [40] for i in range(ts.MAX_SERIES)}), NOW + 900)
        rec, _ = ts.fold_hourly(rec, self.ring({"sensor|new": [41]}, start=NOW + 3600), NOW + 4000)
        self.assertNotIn("sensor|new", rec["hourly"])


class TestAStoreThatWasEditedByHand(unittest.TestCase):
    """The ring and the roll-up sit in rows that people and migrations can write. Whatever is there, a reader
    gives fewer series and never raises: one bad row must not stop the hourly sweep for the whole fleet."""

    JUNK = [None, 5, "text", [], {}, [[1, 2]], {"sensor|a": "x"}, {"sensor|a": [[1]]}, {"sensor|a": [["a", "b"]]},
            {"sensor|a": [[1, float("nan")]]}, {"sensor|a": [[1, 2, 3]]}, {"sensor|a": 7}, {"nope": [[1, 2]]},
            {1: [[1, 2]]}, {"sensor|a": [[10 ** 400, 5]]}, {"sensor|a": [[-5, 5]]}, {"sensor|a": [[True, 5]]},
            {"hourly": "x"}, {"hourly": {"sensor|a": [[1, 2, 3, 4]]}}, {"hourly": {"sensor|a": [[1, 2, 3, 4, 0]]}},
            {"hourly": {"sensor|a": [["a", 2, 3, 4, 5]]}}, {"hourly": {"sensor|a": "x"}}, {"last_ts": "x", "hourly": {}},
            {"last_ts": [], "hourly": None}, {"hourly": {5: [[1, 2, 3, 4, 5]]}}]

    def test_every_reader_survives_every_shape(self):
        for junk in self.JUNK:
            with self.subTest(junk=repr(junk)[:60]):
                ring = ts.ring_add(junk, [(SENSOR, 50.0)], NOW)
                self.assertIsInstance(ring, dict)
                rec, _ = ts.fold_hourly(junk, ring, NOW + 3600)
                self.assertEqual(set(rec), {"last_ts", "hourly"})
                ts.fold_hourly(rec, junk, NOW + 7200)
                ts.raw_points(junk, SENSOR)
                ts.hourly_points(junk, SENSOR)

    def test_the_series_that_can_be_read_are_kept(self):
        mixed = {"sensor|good": [[NOW, 40.0], ["x", 1], [NOW + 1]], "bad key": [[NOW, 1.0]], "disk|also": [[NOW, 33.0]]}
        self.assertEqual(ts.ring_add(mixed, [], NOW), {"sensor|good": [[NOW, 40.0]], "disk|also": [[NOW, 33.0]]})

    def test_a_store_with_a_thousand_series_is_read_in_a_bounded_way(self):
        huge = {f"sensor|s{i}": [[NOW, 40.0]] for i in range(1000)}
        self.assertLessEqual(len(ts.ring_add(huge, [], NOW)), 2 * ts.MAX_SERIES)


# ─── the real path: ingest, sweep, endpoint ──────────────────────────────────

class _Base(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-sensorhist-run-"))
        self._files = {}
        for attr in ("DEVICES_FILE", "THERMAL_HIST_FILE", "THERMAL_ROLLUP_FILE", "HARDWARE_FILE", "CONFIG_FILE", "SMART_HIST_FILE",
                     "GPU_HIST_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.dir / Path(str(getattr(api, attr))).name)
        self.now = int(time.time())
        api.save(api.DEVICES_FILE, {"d1": {"name": "host-one", "last_seen": self.now}})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for attr, value in self._files.items():
            setattr(api, attr, value)

    def report(self, at, temps=None, smart=None, gpus=None, dev=None):
        body = {}
        if temps is not None:
            body["hardware"] = {"temps": temps}
        if smart is not None:
            body["smart"] = smart
        if gpus is not None:
            body["gpus"] = gpus
        api._ingest_hardware("d1", "host-one", body, at, dev=dev)

    def ring(self):
        return (api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {}) or {}).get("sensors") or {}

    def call(self, qs, dev_id="d1"):
        cap = {}

        def _resp(status, body=None):
            cap["s"], cap["b"] = status, body
            raise api.HTTPError(status, body)

        saved = (api.respond, api.require_auth, api._caller_scope)
        api.respond, api.require_auth, api._caller_scope = _resp, (lambda: "jakob"), (lambda: None)
        os.environ["QUERY_STRING"] = qs
        try:
            api.handle_device_thermal_rollup(dev_id)
        except api.HTTPError:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope = saved
            os.environ.pop("QUERY_STRING", None)
        return cap


class TestTheIngestFeedsTheRing(_Base):

    def test_a_report_leaves_a_point_for_every_row_the_page_lists(self):
        self.report(self.now - 3600, temps=[board("coretemp Core 0", 51)], smart=[{"device": "/dev/sda", "temperature_c": 38}],
                    gpus=[{"vendor": "nvidia", "name": "RTX 4070", "temp_c": 62}])
        ring = self.ring()
        self.assertEqual(ring[SENSOR], [[self.now - 3600, 51.0]])
        self.assertEqual(ring[DISK], [[self.now - 3600, 38.0]])
        self.assertEqual(ring[GPU], [[self.now - 3600, 62.0]])

    def test_the_hottest_reading_is_sampled_as_it_always_was(self):
        self.report(self.now - 3600, temps=[board("a", 51)], smart=[{"device": "/dev/sda", "temperature_c": 38}])
        samples = (api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {}) or {}).get("samples")
        self.assertEqual(samples, [{"ts": self.now - 3600, "temp": 51.0}])

    def test_a_report_five_minutes_later_adds_no_point_and_one_a_quarter_hour_later_does(self):
        self.report(self.now - 3600, temps=[board("a", 51)])
        self.report(self.now - 3600 + 300, temps=[board("a", 52)])
        self.assertEqual(len(self.ring()["sensor|a"]), 1)
        self.report(self.now - 3600 + 900, temps=[board("a", 53)])
        self.assertEqual([p[1] for p in self.ring()["sensor|a"]], [51.0, 53.0])
        samples = (api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {}) or {}).get("samples")
        self.assertEqual(len(samples), 3, "the hottest reading is still sampled on every report")

    def test_a_list_the_report_left_out_is_not_sampled_from_the_old_record(self):
        """The GPU was in the first report. The second carries only sensors; the stored record still lists the
        GPU, and sampling that would put a stale temperature on the chart under a new time."""
        self.report(self.now - 3600, temps=[board("a", 51)], gpus=[{"vendor": "nvidia", "name": "RTX 4070", "temp_c": 62}])
        self.report(self.now - 3600 + 1000, temps=[board("a", 52)])
        ring = self.ring()
        self.assertEqual(len(ring["sensor|a"]), 2)
        self.assertEqual(len(ring[GPU]), 1)

    def test_an_ignored_sensor_still_has_a_chart(self):
        """Ignoring a sensor keeps it out of the host's temperature. The operator can still look at it."""
        self.report(self.now - 3600, temps=[board("AUXTIN2", 60), board("Core 0", 50)], dev={"sensor_ignores": ["AUXTIN2"]})
        self.assertIn("sensor|AUXTIN2", self.ring())
        samples = (api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {}) or {}).get("samples")
        self.assertEqual(samples[-1]["temp"], 50.0, "the ignored sensor is still not the hottest")

    def test_a_dead_pin_is_not_charted(self):
        self.report(self.now - 3600, temps=[board("AUXTIN2", 127), board("Core 0", 50)])
        self.assertEqual(list(self.ring()), ["sensor|Core 0"])

    def test_a_report_with_only_ignored_sensors_still_feeds_the_ring(self):
        self.report(self.now - 3600, temps=[board("AUXTIN2", 60)], dev={"sensor_ignores": ["AUXTIN2"]})
        self.assertIn("sensor|AUXTIN2", self.ring())

    def test_a_host_with_no_temperatures_leaves_no_row(self):
        self.report(self.now - 3600, temps=[])
        self.assertIsNone(api._entity_read_one(api.THERMAL_HIST_FILE, "d1", None))


class TestTheSweepAndTheEndpoint(_Base):

    def feed(self, hours, label="Core 0", start_value=40):
        """A report every 15 minutes for `hours` hours, ending now."""
        n = hours * 4
        for i in range(n + 1):
            at = self.now - (n - i) * 900
            self.report(at, temps=[board(label, start_value + i % 7), board("Package", 60 + i % 5)])
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)

    def test_the_sweep_folds_every_series_into_hourly_buckets(self):
        self.feed(6)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        self.assertEqual(set(rec["sensors"]["hourly"]), {"sensor|Core 0", "sensor|Package"})
        self.assertTrue(rec.get("hourly"), "the hottest reading's roll-up is still built")
        self.assertTrue(rec.get("fivemin") and rec.get("daily"))

    def test_the_sweep_folds_a_series_when_the_hottest_reading_has_nothing_new(self):
        """A host whose only sensors are ignored has no hottest reading at all, and still has series."""
        for i in range(8):
            self.report(self.now - (7 - i) * 900, temps=[board("AUXTIN2", 60 + i)], dev={"sensor_ignores": ["AUXTIN2"]})
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        api.run_thermal_rollup_if_due()
        rec = api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {}
        self.assertIn("sensor|AUXTIN2", rec["sensors"]["hourly"])

    def test_a_second_sweep_does_not_count_a_point_twice(self):
        self.feed(3)
        api.run_thermal_rollup_if_due()
        first = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]
        with api._LockedUpdate(api.THERMAL_ROLLUP_FILE) as state:
            state["_meta"] = {"last_run": 0}
        api.run_thermal_rollup_if_due()
        again = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]
        self.assertEqual(again, first)

    def test_a_series_added_later_does_not_disturb_the_ones_already_folded(self):
        self.feed(3)
        api.run_thermal_rollup_if_due()
        before = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]["hourly"]["sensor|Core 0"]
        self.report(self.now + 1000, temps=[board("Core 0", 45), board("New", 33)])
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        with api._LockedUpdate(api.THERMAL_ROLLUP_FILE) as state:
            state["_meta"] = {"last_run": 0}
        api.run_thermal_rollup_if_due()
        rec = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]["hourly"]
        self.assertIn("sensor|New", rec)
        self.assertEqual(rec["sensor|Core 0"][:len(before) - 1], before[:-1])

    def test_a_hold_keeps_the_old_buckets(self):
        old = self.now - 40 * 86400
        api.save(api.THERMAL_ROLLUP_FILE, {"d1": {"sensors": {"last_ts": old, "hourly": {SENSOR: [[old - old % 3600, 40.0, 41.0, 81.0, 2]]}}}})
        saved = api._litigation_hold_active
        api._litigation_hold_active = lambda: True
        try:
            self.feed(2)
            api.run_thermal_rollup_if_due()
        finally:
            api._litigation_hold_active = saved
        rows = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]["hourly"][SENSOR]
        self.assertEqual(rows[0][0], old - old % 3600)

    def test_without_a_hold_the_old_buckets_go(self):
        old = self.now - 40 * 86400
        api.save(api.THERMAL_ROLLUP_FILE, {"d1": {"sensors": {"last_ts": old, "hourly": {SENSOR: [[old - old % 3600, 40.0, 41.0, 81.0, 2]]}}}})
        self.feed(2, label="coretemp Core 0")
        api.run_thermal_rollup_if_due()
        rows = (api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", {}) or {})["sensors"]["hourly"][SENSOR]
        self.assertGreater(rows[0][0], old)

    def test_a_host_that_is_gone_loses_its_series_with_its_row(self):
        self.feed(2)
        api.run_thermal_rollup_if_due()
        api.save(api.DEVICES_FILE, {})
        with api._LockedUpdate(api.THERMAL_ROLLUP_FILE) as state:
            state["_meta"] = {"last_run": 0}
        api.run_thermal_rollup_if_due()
        self.assertIsNone(api._entity_read_one(api.THERMAL_ROLLUP_FILE, "d1", None))

    def test_the_endpoint_answers_the_raw_series_from_the_ring(self):
        self.feed(3)
        cap = self.call("tier=raw&sensor=" + "sensor%7CCore%200")
        self.assertEqual(cap["s"], 200)
        body = cap["b"]
        self.assertEqual((body["device_id"], body["tier"], body["sensor"]), ("d1", "raw", "sensor|Core 0"))
        self.assertEqual(len(body["points"]), 13)
        self.assertEqual(set(body["points"][0]), {"ts", "temp"})
        self.assertEqual(set(body["points"][0]["temp"]), {"min", "avg", "max"})
        stamps = [p["ts"] for p in body["points"]]
        self.assertEqual(stamps, sorted(stamps))

    def test_the_endpoint_answers_the_hourly_series_from_the_rollup(self):
        self.feed(5)
        api.run_thermal_rollup_if_due()
        cap = self.call("tier=hourly&sensor=sensor%7CPackage")
        self.assertEqual(cap["s"], 200)
        self.assertEqual(cap["b"]["tier"], "hourly")
        self.assertTrue(cap["b"]["points"])
        for point in cap["b"]["points"]:
            self.assertLessEqual(point["temp"]["min"], point["temp"]["avg"])
            self.assertLessEqual(point["temp"]["avg"], point["temp"]["max"])

    def test_any_other_tier_of_a_sensor_answers_hourly(self):
        self.feed(5)
        api.run_thermal_rollup_if_due()
        for tier in ("daily", "fivemin", "", "wat"):
            with self.subTest(tier=tier):
                cap = self.call(f"tier={tier}&sensor=sensor%7CPackage")
                self.assertEqual((cap["s"], cap["b"]["tier"]), (200, "hourly"))

    def test_a_sensor_with_no_history_answers_an_empty_list(self):
        self.feed(2)
        cap = self.call("tier=raw&sensor=sensor%7CNo%20such%20sensor")
        self.assertEqual((cap["s"], cap["b"]["points"]), (200, []))

    def test_a_host_that_has_never_reported_answers_an_empty_list(self):
        cap = self.call("tier=raw&sensor=sensor%7CCore%200")
        self.assertEqual((cap["s"], cap["b"]["points"]), (200, []))

    def test_a_malformed_sensor_is_refused(self):
        for sensor in ("Core%200", "host%7Cx", "sensor%7C", "%7Cx", "sensor%7C" + "x" * 200):
            with self.subTest(sensor=sensor):
                self.assertEqual(self.call("tier=raw&sensor=" + sensor)["s"], 400)

    def test_without_a_sensor_the_endpoint_answers_as_it_always_did(self):
        self.feed(5)
        api.run_thermal_rollup_if_due()
        cap = self.call("tier=hourly")
        self.assertEqual(cap["s"], 200)
        self.assertNotIn("sensor", cap["b"])
        self.assertEqual(set(cap["b"]["points"][0]), {"ts", "temp"})
        self.assertEqual(self.call("")["b"]["tier"], "daily")

    def test_a_device_outside_the_callers_scope_is_not_readable(self):
        self.feed(2)
        cap = {}

        def _resp(status, body=None):
            cap["s"] = status
            raise api.HTTPError(status, body)

        saved = (api.respond, api.require_auth, api._caller_scope, api._device_in_scope)
        api.respond, api.require_auth = _resp, (lambda: "viewer")
        api._caller_scope = lambda: {"type": "group", "value": "other"}
        api._device_in_scope = lambda scope, dev: False
        os.environ["QUERY_STRING"] = "tier=raw&sensor=sensor%7CCore%200"
        try:
            api.handle_device_thermal_rollup("d1")
        except api.HTTPError:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope, api._device_in_scope = saved
            os.environ.pop("QUERY_STRING", None)
        self.assertEqual(cap.get("s"), 403)

    def test_an_id_that_is_not_a_host_id_is_not_found(self):
        self.assertEqual(self.call("tier=raw&sensor=sensor%7Ca", dev_id="../etc/passwd")["s"], 404)

    def test_a_row_that_is_not_a_map_answers_an_empty_list(self):
        api._entity_write_one(api.THERMAL_HIST_FILE, "d1", {"samples": [], "sensors": "junk"})
        api._entity_write_one(api.THERMAL_ROLLUP_FILE, "d1", {"sensors": ["junk"]})
        for tier in ("raw", "hourly"):
            with self.subTest(tier=tier):
                cap = self.call(f"tier={tier}&sensor=sensor%7CCore%200")
                self.assertEqual((cap["s"], cap["b"]["points"]), (200, []))

    def test_the_sweep_survives_a_row_that_is_not_a_map(self):
        api._entity_write_one(api.THERMAL_HIST_FILE, "d1", {"samples": [], "sensors": "junk"})
        api._entity_write_one(api.THERMAL_ROLLUP_FILE, "d1", {"sensors": ["junk"], "last_ts": "x"})
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        api.run_thermal_rollup_if_due()


class TestWhatTheFleetPageStillReads(_Base):
    """The Thermal table reads the same hardware record and the same ring row it always read."""

    def test_the_row_still_carries_the_samples_the_sparkline_reads(self):
        self.report(self.now - 3600, temps=[board("a", 51)])
        row = api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {})
        self.assertEqual(set(row), {"samples", "sensors"})
        self.assertTrue(all(isinstance(s.get("temp"), float) for s in row["samples"]))

    def test_the_hottest_series_ignores_the_new_key(self):
        for i in range(6):
            self.report(self.now - (5 - i) * 900, temps=[board("a", 50 + i)])
        api._invalidate_load_cache(api.THERMAL_HIST_FILE)
        self.assertEqual(len(api._raw_temp_samples(api._entity_read_one(api.THERMAL_HIST_FILE, "d1", {}), 0)), 6)

    def test_the_ring_is_small_enough_to_write_on_every_report(self):
        """24 series at the point cap, as JSON: the row is rewritten on every hardware report."""
        import json
        ring = {f"sensor|sensor number {i}": [[NOW + j * 900, 40.5 + j % 9] for j in range(ts.RING_MAX_POINTS)] for i in range(ts.MAX_SERIES)}
        size = len(json.dumps({"samples": [], "sensors": ring}))
        self.assertLess(size, 120_000, size)

    def test_the_rollup_row_stays_bounded_at_the_cap(self):
        import json
        hours = 30 * 24
        hourly = {f"sensor|sensor number {i}": [[NOW + h * 3600, 40.5, 44.5, 170.25, 4] for h in range(hours)] for i in range(ts.MAX_SERIES)}
        size = len(json.dumps({"sensors": {"last_ts": NOW, "hourly": hourly}}))
        self.assertLess(size, 900_000, size)


class TestTheDemoDataKeepsTheContract(unittest.TestCase):
    """The demo seeder is a producer under contract. The rendered gates measure the seeded instance, so a
    seeder that wrote the wrong shape would leave every Thermal chart of a sensor empty and nothing would say
    so. It is held to the module's own readers: what it writes is what a real report and the real sweep leave."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("seed_sensorhist", ROOT / "packaging" / "seed-demo-data.py")
        cls.seed = importlib.util.module_from_spec(spec)
        sys.modules["seed_sensorhist"] = cls.seed
        spec.loader.exec_module(cls.seed)
        cls.hardware = cls.seed.build_hardware()
        cls.history = cls.seed.build_thermal_history()
        cls.rollup = cls.seed.build_thermal_rollup()
        cls.hosts = [h for h, row in cls.history.items() if row.get("sensors")]

    def readings(self, host):
        rec = self.hardware[host]
        return ts.readings((rec.get("hardware") or {}).get("temps"), rec.get("smart"), rec.get("gpus"))

    def test_there_are_hosts_to_check(self):
        self.assertGreaterEqual(len(self.hosts), 5, "a gate over nothing passes for any seeder")
        self.assertGreater(sum(len(self.history[h]["sensors"]) for h in self.hosts), 15)

    def test_the_seeder_names_the_series_as_the_server_does(self):
        for host in self.hosts:
            with self.subTest(host=host):
                names = [key for key, _ in self.readings(host)][:ts.MAX_SERIES]
                self.assertEqual(sorted(self.history[host]["sensors"]), sorted(names))
                self.assertEqual(sorted(self.rollup[host]["sensors"]["hourly"]), sorted(names))

    def test_the_ring_is_one_the_server_would_have_written(self):
        for host in self.hosts:
            with self.subTest(host=host):
                ring = self.history[host]["sensors"]
                self.assertEqual(ts.ring_add(ring, [], self.seed.now()), ring, "the reader changed what the seeder wrote")
                for key, points in ring.items():
                    self.assertEqual(len(points), 96)
                    self.assertEqual({b[0] - a[0] for a, b in zip(points, points[1:])}, {900})
                    self.assertGreaterEqual(900, ts.RING_GAP_S)

    def test_the_rollup_is_one_the_sweep_would_have_left(self):
        for host in self.hosts:
            with self.subTest(host=host):
                rec = self.rollup[host]["sensors"]
                again, changed = ts.fold_hourly(rec, {}, self.seed.now())
                self.assertEqual(again["hourly"], rec["hourly"], "the reader changed what the seeder wrote")
                self.assertFalse(changed)
                for key in rec["hourly"]:
                    points = ts.hourly_points(rec, key)
                    self.assertGreater(len(points), 700)
                    for p in points:
                        self.assertLessEqual(p["temp"]["min"], p["temp"]["avg"])
                        self.assertLessEqual(p["temp"]["avg"], p["temp"]["max"])

    def test_every_series_ends_on_the_reading_the_table_shows(self):
        for host in self.hosts:
            with self.subTest(host=host):
                for key, value in self.readings(host)[:ts.MAX_SERIES]:
                    self.assertEqual(self.history[host]["sensors"][key][-1][1], value, key)
                    # The newest bucket is the hour that is still going on: it holds the reading, among earlier ones.
                    last = ts.hourly_points(self.rollup[host]["sensors"], key)[-1]["temp"]
                    self.assertLessEqual(last["min"], value, key)
                    self.assertGreaterEqual(last["max"], value, key)

    def test_the_hottest_sensor_is_charted_the_way_the_hottest_reading_is(self):
        """The series of the sensor that is the host's hottest follows the host's own hottest-reading curve,
        so charting it and charting the hottest reading show the same line."""
        for host in self.hosts:
            with self.subTest(host=host):
                hottest = self.history[host]["samples"][-1]["temp"]
                key = next(k for k, v in self.readings(host) if v == hottest)
                ring = self.history[host]["sensors"][key]
                self.assertEqual(ring[-1][1], hottest)

    def test_a_series_of_a_cooler_sensor_stays_below_the_hottest_one(self):
        for host in self.hosts:
            with self.subTest(host=host):
                readings = dict(self.readings(host))
                hot_key = max(readings, key=readings.get)
                hot = {p[0]: p[1] for p in self.history[host]["sensors"][hot_key]}
                for key, points in self.history[host]["sensors"].items():
                    if key == hot_key or readings[key] >= readings[hot_key] - 1:
                        continue
                    below = sum(1 for ts_, v in points if v <= hot[ts_] + 1.7)
                    self.assertGreaterEqual(below, 0.95 * len(points), key)


class TestTheModuleIsWiredIn(unittest.TestCase):

    def test_the_lint_lists_carry_it(self):
        make = (ROOT / "Makefile").read_text()
        self.assertEqual(make.count("server/cgi-bin/thermal_sensors.py"), 2, "both the lint and the type-check list")

    def test_it_stays_stdlib_only(self):
        import ast
        tree = ast.parse((_CGI / "thermal_sensors.py").read_text())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                 for a in (n.names if isinstance(n, ast.Import) else [ast.alias(name=n.module or "")])}
        self.assertEqual(names, {"math"})

    def test_a_float_that_is_not_a_number_is_never_stored(self):
        self.assertFalse(ts.usable(math.nan))
        self.assertEqual(ts.ring_add({}, [(SENSOR, math.inf)], NOW), {})


if __name__ == "__main__":
    unittest.main()
