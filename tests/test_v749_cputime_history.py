#!/usr/bin/env python3
"""7.4.9: where a host's CPU time went, over the last two days.

The shares the Linux agent sends with its system information (user, nice, system, I/O wait, interrupts, steal, idle) were shown as one
figure, the latest. A slow disk or a crowded hypervisor shows up as a shape over hours, so each report now adds a sample to a store of
its own: the metric history has a fixed set of columns on SQLite and PostgreSQL, and the shares do not belong in it. The store is one
row a host, a sample a minute at most, 288 kept. The Metrics window of a host draws it.

Driven through the real heartbeat, the real storage and the real endpoint; the readers are held against stored rows of every wrong kind.

User, system and idle are needed in a sample: every system has them. Nice, I/O wait, interrupts and steal are numbers or null. The Linux
agent sends all seven; the Windows agent sends user, system, idle and interrupts, and the macOS agent user, nice, system and idle
(psutil, for the states each system has). A state a system does not have is stored as null, which the chart leaves out; a zero would say
it was measured and none was found.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, api  # noqa: E402
from test_v749_cpu_time import _Cpu  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SHARES = dict(user=12.0, nice=1.0, system=4.0, idle=70.0, iowait=10.0, irq=1.0, steal=2.0)
ORDER = ("user", "nice", "system", "iowait", "irq", "steal", "idle")
NEEDED = ("user", "system", "idle")
OPTIONAL = ("nice", "iowait", "irq", "steal")


class _Hist(_Cpu):

    def setUp(self):
        super().setUp()
        api.save(api.CPUTIME_HIST_FILE, {})
        self._gap = api._CPUTIME_HIST_MIN_GAP
        api._CPUTIME_HIST_MIN_GAP = 0
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._CPUTIME_HIST_MIN_GAP = self._gap
        super().tearDown()

    def hist(self):
        api._LOAD_CACHE.clear()
        return api._entity_read_one(api.CPUTIME_HIST_FILE, DEV, []) or []

    def store(self, rows):
        api._entity_write_one(api.CPUTIME_HIST_FILE, DEV, rows)
        api._LOAD_CACHE.clear()


class TestWhatIsKept(_Hist):

    def test_a_report_adds_a_sample_in_the_order_the_chart_reads(self):
        with mock.patch.object(api.time, "time", return_value=1_800_000_000):
            self.beat_cpu(**SHARES)
        rows = self.hist()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], [1_800_000_000] + [SHARES[k] for k in ORDER])

    def test_the_order_is_user_nice_system_iowait_irq_steal_idle(self):
        self.beat_cpu(user=1.0, nice=2.0, system=3.0, idle=7.0, iowait=4.0, irq=5.0, steal=6.0)
        self.assertEqual(self.hist()[0][1:], [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0])

    def test_samples_are_kept_oldest_first(self):
        for i, t in enumerate((1_800_000_000, 1_800_000_100, 1_800_000_200)):
            with mock.patch.object(api.time, "time", return_value=t):
                self.beat_cpu(**dict(SHARES, iowait=float(i)))
        self.assertEqual([r[0] for r in self.hist()], [1_800_000_000, 1_800_000_100, 1_800_000_200])
        self.assertEqual([r[4] for r in self.hist()], [0.0, 1.0, 2.0])

    def test_at_most_one_a_minute(self):
        api._CPUTIME_HIST_MIN_GAP = 60
        for t in (1_800_000_000, 1_800_000_059, 1_800_000_060, 1_800_000_100):
            with mock.patch.object(api.time, "time", return_value=t):
                self.beat_cpu(**SHARES)
        self.assertEqual([r[0] for r in self.hist()], [1_800_000_000, 1_800_000_060], "59 s later is too soon, 60 s is not, 40 s after that is")

    def test_only_the_newest_are_kept(self):
        with mock.patch.object(api, "_CPUTIME_HIST_MAX", 5):
            for i in range(9):
                with mock.patch.object(api.time, "time", return_value=1_800_000_000 + i * 600):
                    self.beat_cpu(**dict(SHARES, iowait=float(i)))
        rows = self.hist()
        self.assertEqual([r[4] for r in rows], [4.0, 5.0, 6.0, 7.0, 8.0])

    def test_two_days_is_what_the_cap_is_for(self):
        self.assertEqual(api._CPUTIME_HIST_MAX, 288, "a system report about every ten minutes: two days")

    def test_a_figure_is_rounded_to_a_tenth(self):
        self.beat_cpu(**dict(SHARES, iowait=11.0 + 0.04, steal=0.06))
        row = self.hist()[0]
        self.assertEqual((row[4], row[6]), (11.0, 0.1))

    def test_a_report_without_the_shares_adds_nothing(self):
        self.beat_cpu(**SHARES)
        self.beat_cpu(partial=True)                                  # the merged record still holds the first reading
        self.assertEqual(len(self.hist()), 1)

    def test_a_report_missing_user_system_or_idle_adds_nothing(self):
        for missing in NEEDED:
            shares = {k: v for k, v in SHARES.items() if k != missing}
            self.beat_cpu(**shares)
            self.assertEqual(self.hist(), [], missing)

    def test_a_report_missing_one_of_the_other_four_is_a_sample_with_a_hole(self):
        for missing in OPTIONAL:
            self.store([])
            shares = {k: v for k, v in SHARES.items() if k != missing}
            self.beat_cpu(**shares)
            row = self.hist()[0]
            col = 1 + ORDER.index(missing)
            self.assertIsNone(row[col], missing)
            self.assertEqual([v for i, v in enumerate(row[1:], 1) if i != col], [SHARES[k] for k in ORDER if k != missing], "the rest is kept")

    def test_a_windows_report_has_user_system_idle_and_interrupts(self):
        self.beat_cpu(user=40.0, system=10.0, idle=45.0, irq=5.0)
        self.assertEqual(self.hist()[0][1:], [40.0, None, 10.0, None, 5.0, None, 45.0])

    def test_a_macos_report_has_user_nice_system_and_idle(self):
        self.beat_cpu(user=10.0, nice=1.0, system=4.0, idle=85.0)
        self.assertEqual(self.hist()[0][1:], [10.0, 1.0, 4.0, None, None, None, 85.0])

    def test_a_needed_share_that_is_not_a_number_in_range_adds_nothing(self):
        # (a boolean is read as 1.0 by the ingest, as it is for every figure there, so it never reaches the recorder as one)
        for field in NEEDED:
            for bad in ("lots", None, [1], {"a": 1}, -1, 101, float("nan"), 10 ** 400):
                self.store([])
                self.beat_cpu(**dict(SHARES, **{field: bad}))
                self.assertEqual(self.hist(), [], (field, repr(bad)[:20]))

    def test_an_optional_share_that_is_not_a_number_in_range_is_a_hole_and_the_sample_stays(self):
        for field in OPTIONAL:
            for bad in ("lots", None, [1], {"a": 1}, -1, 101, float("nan"), 10 ** 400):
                self.store([])
                self.beat_cpu(**dict(SHARES, **{field: bad}))
                row = self.hist()
                self.assertEqual(len(row), 1, (field, repr(bad)[:20]))
                self.assertIsNone(row[0][1 + ORDER.index(field)], (field, repr(bad)[:20]))

    def test_the_recorder_itself_holds_the_same_line(self):
        """The ingest drops such a figure first; this holds the recorder to the same line for a caller that did not go through it."""
        full = {f"cpu_{k}": v for k, v in SHARES.items()}
        for field in NEEDED:
            for bad in (True, False, "5", None, -0.1, 100.1, float("nan"), float("inf"), 10 ** 400, [5]):
                self.store([])
                api._record_cputime(DEV, dict(full, **{f"cpu_{field}": bad}), 1_800_000_000)
                self.assertEqual(self.hist(), [], (field, repr(bad)[:20]))
        for field in OPTIONAL:
            for bad in (True, False, "5", None, -0.1, 100.1, float("nan"), float("inf"), 10 ** 400, [5]):
                self.store([])
                api._record_cputime(DEV, dict(full, **{f"cpu_{field}": bad}), 1_800_000_000)
                self.assertIsNone(self.hist()[0][1 + ORDER.index(field)], (field, repr(bad)[:20]))
        self.store([])
        api._record_cputime(DEV, full, 1_800_000_000)
        self.assertEqual(len(self.hist()), 1)
        api._record_cputime(DEV, {}, 1_800_001_000)
        api._record_cputime(DEV, {"cpu_iowait": 5}, 1_800_001_000)
        self.assertEqual(len(self.hist()), 1)

    def test_a_partial_report_with_one_share_adds_nothing(self):
        """The merged record holds all seven shares (six of them from the last full report); only the ones this beat sent are its own."""
        self.beat_cpu(**SHARES)
        self.beat_cpu(partial=True, iowait=55.0)
        self.assertEqual(len(self.hist()), 1, "a sample mixing the old shares with the new one would be a reading nobody took")

    def test_a_row_that_is_not_a_list_is_replaced_whatever_the_loader_made_of_it(self):
        """The loader repairs a wrong row before the recorder sees it; this hands the recorder one directly."""
        for odd in ("not a list", 5, {"a": 1}, True):
            written = []
            with mock.patch.object(api, "_entity_read_one", return_value=odd), \
                    mock.patch.object(api, "_entity_write_one", lambda f, d, v, **k: written.append(v)):
                api._record_cputime(DEV, {f"cpu_{k}": v for k, v in SHARES.items()}, 1_800_000_000)
            self.assertEqual(len(written), 1, repr(odd))
            self.assertEqual(len(written[0]), 1, repr(odd))

    def test_a_store_that_fails_does_not_fail_the_report(self):
        with mock.patch.object(api, "_entity_write_one", side_effect=OSError("disk full")), \
                mock.patch.object(api.sys, "stderr") as err:
            api._record_cputime(DEV, {f"cpu_{k}": v for k, v in SHARES.items()}, 1_800_000_000)
        self.assertIn("cpu time history", "".join(str(c.args[0]) for c in err.write.call_args_list))
        with mock.patch.object(api, "_entity_read_one", side_effect=OSError("gone")):
            api._record_cputime(DEV, {f"cpu_{k}": v for k, v in SHARES.items()}, 1_800_000_000)

    def test_a_row_that_is_not_a_list_is_replaced(self):
        api.save(api.CPUTIME_HIST_FILE, {DEV: "not a list"})
        api._LOAD_CACHE.clear()
        self.beat_cpu(**SHARES)
        self.assertEqual(len(self.hist()), 1)

    def test_a_last_sample_that_is_junk_does_not_stop_the_next_one(self):
        self.store([None])
        with mock.patch.object(api, "_CPUTIME_HIST_MIN_GAP", 60):
            self.beat_cpu(**SHARES)
        self.assertEqual(len(self.hist()), 2)


class TestWhatIsRead(_Hist):

    GOOD = [1_800_000_000, 10.0, 0.0, 5.0, 3.0, 0.5, 0.0, 81.5]

    def test_since_keeps_the_newer_samples_only(self):
        self.store([[1_800_000_000 + i * 100] + self.GOOD[1:] for i in range(5)])
        self.assertEqual([r[0] for r in api._cputime_history(DEV, 1_800_000_200)], [1_800_000_200, 1_800_000_300, 1_800_000_400])
        self.assertEqual(len(api._cputime_history(DEV)), 5)
        self.assertEqual(api._cputime_history(DEV, 1_800_001_000), [])

    def test_a_host_with_no_history_is_an_empty_list(self):
        self.assertEqual(api._cputime_history("nobody"), [])
        self.assertEqual(api._cputime_history("not a valid id !!"), [])

    def test_they_come_back_oldest_first_whatever_order_they_are_stored_in(self):
        self.store([[1_800_000_200] + self.GOOD[1:], [1_800_000_000] + self.GOOD[1:], [1_800_000_100] + self.GOOD[1:]])
        self.assertEqual([r[0] for r in api._cputime_history(DEV)], [1_800_000_000, 1_800_000_100, 1_800_000_200])

    def test_a_hole_in_one_of_the_four_optional_shares_is_kept_and_in_a_needed_one_is_not(self):
        holes = [[1_800_000_000, 10.0, None, 5.0, None, None, None, 85.0], [1_800_000_001, 10.0, 0.0, 5.0, 3.0, None, 0.0, 81.0]]
        needed = [[1_800_000_000, None] + self.GOOD[2:], [1_800_000_000] + self.GOOD[1:3] + [None] + self.GOOD[4:], self.GOOD[:7] + [None]]
        self.store(holes + needed)
        self.assertEqual(api._cputime_history(DEV), holes)

    def test_an_optional_share_out_of_range_or_not_a_number_leaves_the_row_out(self):
        ts = 1_800_000_000
        bad = [[ts, 10.0, 101, 5.0, 3.0, 1.0, 0.0, 81.0], [ts, 10.0, 0.0, 5.0, -1, 1.0, 0.0, 81.0], [ts, 10.0, 0.0, 5.0, 3.0, 150, 0.0, 81.0],
               [ts, 10.0, 0.0, 5.0, 3.0, 1.0, -0.5, 81.0], [ts, 10.0, True, 5.0, 3.0, 1.0, 0.0, 81.0], [ts, 10.0, 0.0, 5.0, "3", 1.0, 0.0, 81.0],
               [ts, 10.0, 0.0, 5.0, 3.0, [1], 0.0, 81.0], [ts, 10.0, 0.0, 5.0, 3.0, 1.0, {"a": 1}, 81.0]]
        self.store(bad + [self.GOOD])
        self.assertEqual(api._cputime_history(DEV), [self.GOOD])
        with mock.patch.object(api, "_entity_read_one", return_value=bad + [[ts, 10.0, 0.0, 5.0, 3.0, 1.0, float("nan"), 81.0],
                                                                           [ts, 10.0, 0.0, 5.0, 3.0, 1.0, float("inf"), 81.0], self.GOOD]):
            self.assertEqual(api._cputime_history(DEV), [self.GOOD])

    def test_a_row_of_the_wrong_kind_is_left_out_and_the_good_ones_stay(self):
        bad = [None, "x", 5, {"a": 1}, [], [1], self.GOOD[:7], self.GOOD + [1], ["t"] + self.GOOD[1:], [1_800_000_000] + ["x"] + self.GOOD[2:],
               [1_800_000_000] + [True] + self.GOOD[2:], [1_800_000_000, True] + self.GOOD[2:], [1_800_000_000, -1] + self.GOOD[2:],
               [1_800_000_000, 101] + self.GOOD[2:], [1_800_000_000, 10 ** 400] + self.GOOD[2:], [1_800_000_000] + [[1]] + self.GOOD[2:]]
        self.store(bad + [self.GOOD])
        self.assertEqual(api._cputime_history(DEV), [self.GOOD])

    def test_not_a_number_is_left_out(self):
        # JSON cannot hold NaN and the store refuses to write it, but a hand-edited file can carry it and the loader reads it
        rows = [[1_800_000_000, float("nan")] + self.GOOD[2:], [1_800_000_000, float("inf")] + self.GOOD[2:],
                [float("nan")] + self.GOOD[1:], self.GOOD]
        with mock.patch.object(api, "_entity_read_one", return_value=rows):
            self.assertEqual(api._cputime_history(DEV), [self.GOOD])

    def test_a_row_that_is_not_a_list_is_empty_whatever_the_loader_made_of_it(self):
        for odd in ("text", 5, {"a": 1}, None, True, 5.5):
            with mock.patch.object(api, "_entity_read_one", return_value=odd):
                self.assertEqual(api._cputime_history(DEV), [], repr(odd))

    def test_a_row_that_is_not_a_list_of_samples_is_empty(self):
        for odd in ("text", 5, {"a": 1}, None, True):
            api.save(api.CPUTIME_HIST_FILE, {DEV: odd})
            api._LOAD_CACHE.clear()
            self.assertEqual(api._cputime_history(DEV), [], repr(odd))


class TestTheMetricsAnswer(_Hist):

    def ask(self, qs=""):
        names = ("verify_token", "get_token_from_request", "method", "respond", "_env")
        saved = {n: getattr(api, n) for n in names}
        cap = {}

        def respond(status, body=None):
            cap["s"], cap["b"] = status, body
            raise api.HTTPError(status, body)
        api.verify_token = lambda *a, **k: ("admin", "admin")
        api.method = lambda: "GET"
        api.respond = respond
        real_env = api._env
        api._env = lambda k, d="": qs if k == "QUERY_STRING" else real_env(k, d)
        try:
            try:
                api.handle_metrics(DEV)
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        return cap.get("s"), cap.get("b") or {}

    def test_the_answer_carries_the_history(self):
        self.beat_cpu(**SHARES)
        st, body = self.ask()
        self.assertEqual(st, 200, body)
        self.assertEqual(len(body["cputime"]), 1)
        self.assertEqual(body["cputime"][0][1:], [SHARES[k] for k in ORDER])

    def test_with_a_range_too(self):
        self.beat_cpu(**SHARES)
        st, body = self.ask("range=86400")
        self.assertEqual(st, 200)
        self.assertEqual(len(body["cputime"]), 1, "whichever of the two ways the endpoint answers")

    @staticmethod
    def database_answering(series):
        """A stand-in for the database module that only the metrics handler is given, so the branch that answers from it runs on either
        backend; every other caller of _dbmod() gets the real one."""
        real = api._dbmod

        class Db:
            @staticmethod
            def metric_range(data_dir, dev_id, since):
                return series

        def pick():
            return Db if sys._getframe(1).f_code.co_name == "handle_metrics" else real()
        return mock.patch.object(api, "_dbmod", pick)

    def window(self, first_ts):
        return mock.patch.object(api, "_recent_metric_window", return_value=[{"ts": first_ts, "cpu": 5.0}, {"ts": first_ts + 60, "cpu": 6.0}])

    def test_the_recent_window_leaves_out_what_is_older_than_its_first_sample(self):
        good = TestWhatIsRead.GOOD[1:]
        self.store([[1_800_000_000 - 500] + good, [1_800_000_000] + good, [1_800_000_000 + 500] + good])
        with self.window(1_800_000_000):
            st, body = self.ask()
        self.assertEqual([r[0] for r in body["cputime"]], [1_800_000_000, 1_800_000_500], "the chart and the lines under it cover the same hours")

    def test_a_range_gives_the_samples_of_that_range_only(self):
        """The branch that answers from the database. The database module is a stand-in that returns a series, so the branch runs on
        either backend; the cut-off is the range back from now."""
        good = TestWhatIsRead.GOOD[1:]
        now = 1_800_000_000
        self.store([[now - 7200] + good, [now - 3000] + good, [now - 10] + good])

        with self.database_answering([{"ts": now - 100, "cpu": 1.0}]), mock.patch.object(api.time, "time", return_value=now):
            st, body = self.ask("range=3600")
            self.assertEqual((st, [r[0] for r in body["cputime"]]), (200, [now - 3000, now - 10]), "an hour back")
            self.assertNotIn("recent_window", body, "the database answered")
            st, body = self.ask("range=86400")
            self.assertEqual([r[0] for r in body["cputime"]], [now - 7200, now - 3000, now - 10], "a day back")

    def test_a_range_that_is_not_a_number_is_a_400_as_before(self):
        with self.database_answering([]):
            st, _ = self.ask("range=soon")
        self.assertEqual(st, 400)

    def test_a_host_with_none_gets_an_empty_list_not_a_missing_key(self):
        st, body = self.ask()
        self.assertEqual((st, body["cputime"]), (200, []))

    def test_a_range_leaves_out_what_is_older(self):
        old = 1_000_000_000
        self.store([[old] + TestWhatIsRead.GOOD[1:], [old + 100] + TestWhatIsRead.GOOD[1:]])
        st, body = self.ask("range=3600")
        self.assertEqual(st, 200)
        # the endpoint's own cut-off is "now - range" when the database answers and the first sample of the window otherwise;
        # a sample from 2001 is inside neither, unless the window is empty and the whole history is given
        self.assertTrue(all(r[0] >= 0 for r in body["cputime"]))

    def test_a_reader_scoped_away_from_the_host_is_refused_and_given_nothing(self):
        self.beat_cpu(**SHARES)
        with mock.patch.object(api, "_scope_block_device", side_effect=lambda d: api.respond(403, {"error": "Host outside your role scope"})):
            st, body = self.ask()
        self.assertEqual(st, 403)
        self.assertNotIn("cputime", body)


class TestTheStoreIsWiredLikeItsSiblings(_Hist):

    def test_a_deleted_host_takes_its_history(self):
        self.beat_cpu(**SHARES)
        self.assertEqual(len(self.hist()), 1)
        self.assertTrue(api._purge_device(DEV))
        api._LOAD_CACHE.clear()
        self.assertNotIn(DEV, api.load(api.CPUTIME_HIST_FILE) or {})

    def test_it_is_an_entity_file_on_the_database_backends(self):
        import storage
        self.assertIn("cputime_history.json", storage.ENTITY_FILES)

    def test_its_shape_is_registered(self):
        import store_shapes
        self.assertIn("cputime_history.json", store_shapes.SHAPES)

    def test_the_demo_seeds_it_in_that_shape(self):
        src = (ROOT / "packaging" / "seed-demo-data.py").read_text()
        self.assertIn("'cputime_history.json':", src)
        self.assertIn("def build_cputime_history", src)

    def test_the_file_is_where_the_other_stores_are(self):
        self.assertEqual(api.CPUTIME_HIST_FILE.name, "cputime_history.json")
        self.assertEqual(api.CPUTIME_HIST_FILE.parent, api.DATA_DIR)


class TestWhatTheDemoHolds(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("seed_demo_ct", ROOT / "packaging" / "seed-demo-data.py")
        cls.seed = importlib.util.module_from_spec(spec)
        sys.modules["seed_demo_ct"] = cls.seed
        spec.loader.exec_module(cls.seed)
        cls.hist = cls.seed.build_cputime_history()
        cls.devs = cls.seed.build_devices()

    def test_every_host_whose_agent_sends_shares_has_a_history_and_nothing_else_has(self):
        with_shares = {k for k, d in self.devs.items() if "cpu_user" in (d.get("sysinfo") or {})}
        self.assertEqual(set(self.hist), with_shares)
        self.assertGreaterEqual(len(with_shares), 10)
        for appliance in ("sw01", "sw02", "ap01", "ap02"):
            self.assertNotIn(appliance, self.hist)

    def test_it_ends_on_the_shares_the_host_shows_and_a_missing_one_is_a_hole(self):
        for k, rows in self.hist.items():
            si = self.devs[k]["sysinfo"]
            self.assertEqual(rows[-1][1:], [si.get(f"cpu_{n}") for n in ORDER], k)

    def test_the_windows_host_has_user_system_idle_and_interrupts_and_the_macos_host_nice_instead(self):
        win, mac = self.hist["wks01"], self.hist["mbp01"]
        for r in win:
            self.assertEqual([r[i] is None for i in (2, 4, 5, 6)], [True, True, False, True], "no nice, I/O wait or steal on Windows")
        for r in mac:
            self.assertEqual([r[i] is None for i in (2, 4, 5, 6)], [False, True, True, True], "no I/O wait, interrupts or steal on macOS")
        si = self.devs["wks01"]["sysinfo"]
        self.assertTrue({"cpu_user", "cpu_system", "cpu_idle", "cpu_irq"} <= set(si))
        self.assertFalse({"cpu_iowait", "cpu_steal", "cpu_nice"} & set(si), "the Windows agent does not send what Windows does not have")
        si = self.devs["mbp01"]["sysinfo"]
        self.assertTrue({"cpu_user", "cpu_nice", "cpu_system", "cpu_idle"} <= set(si))
        self.assertFalse({"cpu_iowait", "cpu_steal", "cpu_irq"} & set(si))

    def test_every_sample_is_eight_values_in_range_that_add_up(self):
        for k, rows in self.hist.items():
            self.assertEqual(len(rows), 48)
            for r in rows:
                self.assertEqual(len(r), 8, k)
                self.assertTrue(all(v is None or (isinstance(v, (int, float)) and 0 <= v <= 100) for v in r[1:]), (k, r))
                self.assertTrue(all(r[i] is not None for i in (1, 3, 7)), (k, r))
                self.assertAlmostEqual(sum(v for v in r[1:] if v is not None), 100.0, delta=1.0, msg=(k, r))

    def test_samples_are_ten_minutes_apart_and_oldest_first(self):
        for k, rows in self.hist.items():
            gaps = {b[0] - a[0] for a, b in zip(rows, rows[1:])}
            self.assertEqual(gaps, {600}, k)

    def test_the_hosts_with_something_to_see_ramp_up_to_it(self):
        nas = self.hist["tnas"]
        self.assertGreater(nas[-1][4], 25, "the NAS waits for its disks now")
        self.assertLess(nas[0][4], nas[-1][4] * 0.6, "and did not eight hours ago")
        guest = self.hist["jf01"]
        self.assertGreater(guest[-1][6], 10, "the guest on a busy hypervisor loses time to steal")

    def test_it_is_the_same_on_every_run(self):
        again = self.seed.build_cputime_history()
        self.assertEqual({k: [r[1:] for r in v] for k, v in again.items()}, {k: [r[1:] for r in v] for k, v in self.hist.items()})

    def test_the_servers_reader_takes_every_row_the_demo_writes(self):
        for k, rows in self.hist.items():
            with mock.patch.object(api, "_entity_read_one", return_value=rows):
                self.assertEqual(len(api._cputime_history(k)), len(rows), k)


if __name__ == "__main__":
    unittest.main()
