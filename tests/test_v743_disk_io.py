#!/usr/bin/env python3
"""v7.4.3, issue #49: how busy each disk is, how much it moves and how long it takes, with a line on %busy.

"The agent reports network I/O per interface but nothing about disk I/O. On a host with eleven drives behind
an HBA plus an md mirror, the question 'which drive is saturated, or slow?' can't be answered from
RemotePower, and there's no alert for a drive pinned at 100% busy for minutes (a failing disk, a stuck scrub
or a runaway job often shows up there before SMART changes)."

Three layers, each driven for real: the Linux agent's reading of /proc/diskstats (against a small fake
root), the server's ingest and metric engine through the real heartbeat and the real alert ledger, and the
pages' data (the Hardware answer, the digest line, the alert words).
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402
from test_v741_drift_globs import load_agent  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"


def stat_line(name, reads=0, rsect=0, rms=0, writes=0, wsect=0, wms=0, busy_ms=0, major=8, minor=0):
    """One /proc/diskstats line (the 14 fields every kernel since 2.6 has)."""
    return f"{major:4d} {minor:7d} {name} {reads} 0 {rsect} {rms} {writes} 0 {wsect} {wms} 0 {busy_ms} {busy_ms}\n"


class _FakeHost(unittest.TestCase):
    """A host root with /proc/diskstats and the /sys/block entries of whole devices only."""

    WHOLE = ("sda", "nvme0n1", "md0", "loop0", "ram0", "dm-0", "sr0", "zram0")

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rp-diskio-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.root), True)
        (self.root / "proc").mkdir()
        for name in self.WHOLE:
            (self.root / "sys" / "block" / name).mkdir(parents=True)
        self.agent = load_agent("rp_agent_diskio", AGENT, host_root=str(self.root))
        self.clock = 1000.0

    def write(self, *lines):
        (self.root / "proc" / "diskstats").write_text("".join(lines))

    def read(self, at):
        with mock.patch.object(self.agent.time, "monotonic", return_value=at):
            return self.agent.collect_disk_io()


class TestTheAgentReading(_FakeHost):

    def base(self, **kw):
        return [stat_line("sda", **kw), stat_line("sda1", minor=1, **kw), stat_line("nvme0n1", major=259, **kw),
                stat_line("nvme0n1p1", major=259, minor=1, **kw), stat_line("md0", major=9, **kw),
                stat_line("loop0", major=7, **kw), stat_line("ram0", major=1, **kw), stat_line("dm-0", major=253, **kw),
                stat_line("sr0", major=11, **kw), stat_line("zram0", major=251, **kw)]

    def test_the_first_reading_has_nothing_to_subtract(self):
        self.write(*self.base(reads=100, busy_ms=500))
        self.assertEqual(self.read(1000.0), [])

    def test_two_readings_give_the_rates(self):
        self.write(stat_line("sda", reads=100, rsect=2000, rms=50, writes=200, wsect=4000, wms=100, busy_ms=1000))
        self.read(1000.0)
        # ten seconds later: 500 reads of 10 MiB, 1000 writes of 20 MiB, busy for 5 of the 10 seconds
        self.write(stat_line("sda", reads=600, rsect=2000 + 20480, rms=300, writes=1200, wsect=4000 + 40960,
                             wms=1100, busy_ms=6000))
        rows = self.read(1010.0)
        self.assertEqual(rows, [{"dev": "sda", "busy_pct": 50.0, "read_mbs": 1.0, "write_mbs": 2.0,
                                 "riops": 50.0, "wiops": 100.0, "await_ms": 0.8}])

    def test_only_whole_disks_and_arrays_are_reported(self):
        self.write(*self.base(reads=1))
        self.read(1000.0)
        self.write(*self.base(reads=2, busy_ms=10))
        self.assertEqual(sorted(r["dev"] for r in self.read(1010.0)), ["md0", "nvme0n1", "sda"])

    def test_busy_never_reads_above_100(self):
        self.write(stat_line("sda"))
        self.read(1000.0)
        self.write(stat_line("sda", busy_ms=12000))             # 12 s busy in a 10 s window: timer skew
        self.assertEqual(self.read(1010.0)[0]["busy_pct"], 100.0)

    def test_an_idle_disk_is_zero_not_an_error(self):
        self.write(stat_line("sda", reads=5, busy_ms=5))
        self.read(1000.0)
        self.write(stat_line("sda", reads=5, busy_ms=5))
        row = self.read(1010.0)[0]
        self.assertEqual((row["busy_pct"], row["riops"], row["wiops"], row["await_ms"]), (0.0, 0.0, 0.0, 0.0))

    def test_a_counter_that_goes_backwards_starts_again(self):
        self.write(stat_line("sda", reads=1000, rsect=99999, busy_ms=9000))
        self.read(1000.0)
        self.write(stat_line("sda", reads=3, rsect=10, busy_ms=4))      # the driver reloaded
        self.assertEqual(self.read(1010.0), [])
        self.write(stat_line("sda", reads=13, rsect=2058, busy_ms=1004))
        self.assertEqual(self.read(1020.0)[0]["busy_pct"], 10.0)

    def test_a_long_gap_is_not_a_rate(self):
        self.write(stat_line("sda", reads=1))
        self.read(1000.0)
        self.write(stat_line("sda", reads=100000, busy_ms=3000000))
        self.assertEqual(self.read(1000.0 + 7200), [], "two hours apart says nothing about the last minute")

    def test_two_readings_in_the_same_instant_wait_for_the_next(self):
        self.write(stat_line("sda", reads=1))
        self.read(1000.0)
        self.write(stat_line("sda", reads=2, busy_ms=1))
        self.assertEqual(self.read(1000.1), [])
        self.write(stat_line("sda", reads=3, busy_ms=1000))
        self.assertEqual(self.read(1010.0)[0]["busy_pct"], 10.0, "the baseline stayed at the first reading")

    def test_a_disk_that_goes_away_is_forgotten(self):
        self.write(stat_line("sda"), stat_line("md0", major=9))
        self.read(1000.0)
        self.write(stat_line("sda"))
        self.read(1010.0)
        self.assertEqual(sorted(self.agent._prev_disk_io), ["sda"])

    def test_a_missing_or_garbled_file_is_an_empty_answer(self):
        self.assertEqual(self.read(1000.0), [])
        self.write("not a diskstats line\n", "8 0 sda 1 2\n", stat_line("sda", reads=1))
        self.assertEqual(self.read(1010.0), [])
        self.write("8 0 sda x 0 x x x 0 x x 0 x x\n")
        self.assertEqual(self.read(1020.0), [])

    def test_at_most_thirty_two_disks_the_busiest_first(self):
        for i in range(40):
            (self.root / "sys" / "block" / f"sdz{i}").mkdir()
        self.write(*[stat_line(f"sdz{i}") for i in range(40)])
        self.read(1000.0)
        self.write(*[stat_line(f"sdz{i}", busy_ms=i * 100) for i in range(40)])
        rows = self.read(1010.0)
        self.assertEqual(len(rows), 32)
        self.assertEqual(rows[0]["dev"], "sdz39")
        self.assertEqual([r["busy_pct"] for r in rows], sorted((r["busy_pct"] for r in rows), reverse=True))

    def test_the_heartbeat_carries_it(self):
        src = AGENT.read_text(encoding="utf-8")
        i = src.index("sysinfo = {\n                'uptime':")
        block = src[i:src.index("# Merge metrics if psutil available", i)]
        self.assertIn("'disk_io': collect_disk_io()", block, "it has to be inside the dict the heartbeat sends")
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), AGENT.read_bytes())


class _Hb(_Base):
    """The real heartbeat with a sysinfo in it, and the real metric engine and alert ledger behind it."""

    def setUp(self):
        super().setUp()
        api.save(api.FLEET_EVENTS_FILE, {"events": []})
        api.save(api.DISKIO_HIST_FILE, {})
        self._gap = api._DISKIO_HIST_MIN_GAP
        api._DISKIO_HIST_MIN_GAP = 0
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._DISKIO_HIST_MIN_GAP = self._gap
        super().tearDown()

    def lines(self, warn=0, crit=0, sustain=None, **more):
        cfg = {"diskio_warn_percent": warn, "diskio_crit_percent": crit}
        if sustain is not None:
            cfg["diskio_sustain"] = sustain
        cfg.update(more)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def beat_si(self, rows, partial=False, **more):
        """One heartbeat with this disk_io in its sysinfo; rows=None leaves the key out altogether."""
        si = {"hostname": "serverbox"}
        if rows is not None:
            si["disk_io"] = rows
        si.update(more)
        body = {"device_id": DEV, "token": "tok", "sysinfo": si}
        if partial:
            body["sysinfo_partial"] = True
        raw = json.dumps(body).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return
        self.fail("heartbeat did not answer")

    def busy(self, **by_dev):
        """Rows for the named disks: busy(sda=95, sdb=3)."""
        return [{"dev": d, "busy_pct": float(v), "read_mbs": 1.5, "write_mbs": 2.5, "riops": 10.0,
                 "wiops": 20.0, "await_ms": 4.2} for d, v in by_dev.items()]

    def stored(self):
        api._LOAD_CACHE.clear()
        return ((api.load(api.DEVICES_FILE) or {}).get(DEV) or {}).get("sysinfo", {}).get("disk_io")

    def metric_events(self, kind="diskio"):
        return [(e, p.get("target"), p.get("value"), p.get("threshold")) for e, p in self.events
                if e.startswith("metric_") and p.get("kind") == kind]

    def open_alerts(self):
        api._LOAD_CACHE.clear()
        return sorted((a.get("payload") or {}).get("target") for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                      if a.get("event") in ("metric_warning", "metric_critical") and not a.get("resolved_at")
                      and (a.get("payload") or {}).get("metric") == "diskio")


class TestTheIngest(_Hb):

    def test_the_rows_are_kept_as_numbers_in_range(self):
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.stored(), [{"dev": "sda", "busy_pct": 95.0, "read_mbs": 1.5, "write_mbs": 2.5,
                                          "riops": 10.0, "wiops": 20.0, "await_ms": 4.2}])

    def test_garbage_is_dropped_row_by_row(self):
        rows = [{"dev": "ok", "busy_pct": 10.0}, {"dev": "", "busy_pct": 5}, {"busy_pct": 5}, "x", None, 5,
                {"dev": "nan", "busy_pct": float("nan")}, {"dev": "neg", "busy_pct": -4},
                {"dev": "big", "busy_pct": 4000, "read_mbs": 1e30, "await_ms": "slow"},
                {"dev": "d" * 100, "busy_pct": 1}]
        self.beat_si(rows)
        got = {r["dev"]: r for r in self.stored()}
        self.assertEqual(got["ok"]["busy_pct"], 10.0)
        self.assertNotIn("", got)
        self.assertNotIn("nan", got)
        self.assertEqual(got["neg"]["busy_pct"], 0.0)
        self.assertEqual(got["big"]["busy_pct"], 100.0)
        self.assertNotIn("read_mbs", got["big"])
        self.assertNotIn("await_ms", got["big"])
        self.assertEqual(len(next(r for r in got if r.startswith("d" * 32))), 32)

    def test_a_number_too_big_for_a_float_is_dropped_not_an_error(self):
        """10**400 compares fine and raises OverflowError the moment float() is called on it; a report that
        carried one in busy_pct took the heartbeat down with a 500 (found by the 7.4.3 review)."""
        huge = 10 ** 400
        rows = [{"dev": "big", "busy_pct": huge}, {"dev": "neg", "busy_pct": -huge},
                {"dev": "ok", "busy_pct": 10.0, "read_mbs": huge, "write_mbs": -huge, "riops": huge, "wiops": 5,
                 "await_ms": huge}]
        self.beat_si(rows)                                         # beat_si fails the test on anything but a 200
        got = {r["dev"]: r for r in self.stored()}
        self.assertNotIn("big", got)
        self.assertNotIn("neg", got)
        self.assertEqual(got["ok"], {"dev": "ok", "busy_pct": 10.0, "wiops": 5.0})

    def test_the_finite_number_rule_itself(self):
        for good in (0, 1, -1, 0.5, 10 ** 300, -10 ** 300):
            self.assertTrue(api._finite_number(good), good)
        for bad in (True, False, None, "5", [], {}, float("nan"), float("inf"), float("-inf"), 10 ** 400, -10 ** 400):
            self.assertFalse(api._finite_number(bad), repr(bad)[:20])

    def test_at_most_thirty_two_rows_and_only_a_list(self):
        self.beat_si([{"dev": f"d{i}", "busy_pct": 1.0} for i in range(80)])
        self.assertEqual(len(self.stored()), 32)
        self.beat_si("sda")
        self.assertIsNone(self.stored(), "a value that is not a list is not a report")

    def test_a_value_that_is_not_a_list_is_not_a_calm_disk(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        for junk in ("sda", {"sda": 1}, 5, True):
            self.beat_si(junk)
            self.assertEqual(self.open_alerts(), ["sda"], junk)

    def test_the_device_list_does_not_carry_it(self):
        self.assertIn("disk_io", api._ROSTER_SYSINFO_OMIT)


class TestTheLine(_Hb):

    def test_nothing_set_nothing_fires(self):
        for _ in range(6):
            self.beat_si(self.busy(sda=100))
        self.assertEqual(self.metric_events(), [])

    def test_it_takes_n_reports_and_warns_once(self):
        self.lines(warn=90, crit=99, sustain=3)
        for _ in range(2):
            self.beat_si(self.busy(sda=95))
        self.assertEqual(self.metric_events(), [])
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.metric_events(), [("metric_warning", "sda", 95.0, 90.0)])
        for _ in range(3):
            self.beat_si(self.busy(sda=95))
        self.assertEqual(len(self.metric_events()), 1)
        self.assertEqual(self.open_alerts(), ["sda"])

    def test_critical_after_the_same_run(self):
        self.lines(warn=90, crit=99, sustain=2)
        for _ in range(2):
            self.beat_si(self.busy(sda=100))
        self.assertEqual(self.metric_events(), [("metric_critical", "sda", 100.0, 99.0)])

    def test_a_spike_shorter_than_the_run_never_alerts(self):
        self.lines(warn=90, crit=99, sustain=3)
        for v in (95, 95, 10, 95, 95, 10, 95):
            self.beat_si(self.busy(sda=v))
        self.assertEqual(self.metric_events(), [])

    def test_it_closes_when_the_disk_calms_down(self):
        self.lines(warn=90, crit=99, sustain=2)
        for _ in range(2):
            self.beat_si(self.busy(sda=95))
        self.beat_si(self.busy(sda=10))
        self.assertEqual([e for e, *_ in self.metric_events()], ["metric_warning", "metric_recovered"])
        self.assertEqual(self.open_alerts(), [])

    def test_the_disks_are_separate(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95, sdb=96, sdc=5))
        self.assertEqual(self.open_alerts(), ["sda", "sdb"])
        self.beat_si(self.busy(sda=5, sdb=96, sdc=5))
        self.assertEqual(self.open_alerts(), ["sdb"])

    def test_a_host_has_its_own_line(self):
        self.lines(warn=90, crit=99, sustain=1)
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["metric_thresholds"] = {"diskio_warn_percent": 50.0, "diskio_crit_percent": 80.0}
        api._LOAD_CACHE.clear()
        self.beat_si(self.busy(sda=60))
        self.assertEqual(self.metric_events(), [("metric_warning", "sda", 60.0, 50.0)])

    def test_turning_the_line_off_closes_what_is_open(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.open_alerts(), ["sda"])
        self.lines(warn=0, crit=0, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.open_alerts(), [])

    def test_a_disk_that_leaves_the_list_closes_its_alert(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95, sdb=95))
        self.beat_si(self.busy(sdb=95))
        self.assertEqual(self.open_alerts(), ["sdb"])

    def test_only_a_warning_line_makes_the_critical_one_unreachable(self):
        self.lines(warn=90, crit=0, sustain=1)
        self.beat_si(self.busy(sda=100))
        self.assertEqual(self.metric_events(), [("metric_warning", "sda", 100.0, 90.0)])

    def test_only_a_critical_line_is_the_warning_one_too(self):
        self.lines(warn=0, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.metric_events(), [])
        self.beat_si(self.busy(sda=100))
        self.assertEqual(self.metric_events(), [("metric_critical", "sda", 100.0, 99.0)])

    def test_without_a_setting_it_takes_five_reports(self):
        self.lines(warn=90, crit=99)
        for _ in range(4):
            self.beat_si(self.busy(sda=95))
        self.assertEqual(self.metric_events(), [])
        self.beat_si(self.busy(sda=95))
        self.assertEqual([e for e, *_ in self.metric_events()], ["metric_warning"])

    def test_a_hand_edited_run_is_held_to_sixty(self):
        self.lines(warn=90, crit=99, sustain=9999)
        for _ in range(59):
            self.beat_si(self.busy(sda=95))
        self.assertEqual(self.metric_events(), [])
        self.beat_si(self.busy(sda=95))
        self.assertEqual([e for e, *_ in self.metric_events()], ["metric_warning"])

    def test_turning_the_line_back_on_alerts_again(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.lines(warn=0, crit=0, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.open_alerts(), [])
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.open_alerts(), ["sda"])

    def test_a_disk_that_comes_back_busy_alerts_again(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95, sdb=5))
        self.beat_si(self.busy(sdb=5))
        self.assertEqual(self.open_alerts(), [])
        self.beat_si(self.busy(sda=95, sdb=5))
        self.assertEqual(self.open_alerts(), ["sda"])

    def test_a_report_without_the_figures_says_nothing(self):
        """An agent that does not send disk_io, or a beat that left it out, is not a calm disk."""
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=95))
        self.assertEqual(self.open_alerts(), ["sda"])
        before = list(self.events)
        self.beat_si(None)
        self.beat_si(None, partial=True, mem_percent=5.0)
        self.assertEqual(self.open_alerts(), ["sda"])
        self.assertEqual([e for e, _ in self.events if e == "metric_recovered"],
                         [e for e, _ in before if e == "metric_recovered"])

    def test_a_partial_report_does_not_run_the_old_run_again(self):
        """The merged record still holds the last disk_io; only a beat that carries it counts."""
        self.lines(warn=90, crit=99, sustain=3)
        self.beat_si(self.busy(sda=95))
        for _ in range(4):
            self.beat_si(None, partial=True, mem_percent=5.0)
        self.assertEqual(self.metric_events(), [])

    def test_the_other_metrics_keep_their_own_dampening(self):
        """diskio_sustain is the disk's own run; a memory breach is still held by the global setting."""
        self.lines(warn=90, crit=99, sustain=5, metric_failures_before_alert=1)
        raw = {"hostname": "serverbox", "mem_percent": 99.0}
        body = json.dumps({"device_id": DEV, "token": "tok", "sysinfo": raw}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(body))})
        api.sys.stdin = _Stdin(body)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured:
            pass
        self.assertTrue(any(e.startswith("metric_") and p.get("kind") == "memory" for e, p in self.events))


class TestTheHistory(_Hb):

    def hist(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DISKIO_HIST_FILE) or {}).get(DEV, {})

    def test_every_report_adds_a_sample_oldest_first(self):
        for v in (10, 20, 30):
            self.beat_si(self.busy(sda=v))
        rows = self.hist()["sda"]
        self.assertEqual([r[1] for r in rows], [10.0, 20.0, 30.0])
        self.assertEqual(rows[0][2:], [1.5, 2.5, 30.0, 4.2])          # read, write, iops, await
        self.assertTrue(rows[0][0] <= rows[1][0] <= rows[2][0])

    def test_at_most_a_hundred_and_twenty_a_disk(self):
        for _ in range(130):
            self.beat_si(self.busy(sda=5))
        self.assertEqual(len(self.hist()["sda"]), 120)

    def test_samples_are_not_taken_closer_together_than_the_gap(self):
        api._DISKIO_HIST_MIN_GAP = 3600
        for _ in range(5):
            self.beat_si(self.busy(sda=5))
        self.assertEqual(len(self.hist()["sda"]), 1)

    def test_a_report_without_the_figures_adds_no_sample(self):
        self.beat_si(self.busy(sda=5))
        self.beat_si(None, partial=True, mem_percent=5.0)      # the merged record still holds the first reading
        self.assertEqual(len(self.hist()["sda"]), 1)
        self.beat_si(None)
        self.assertEqual(len(self.hist()["sda"]), 1)

    def test_a_disk_that_is_gone_loses_its_history(self):
        self.beat_si(self.busy(sda=5, sdb=5))
        self.beat_si(self.busy(sda=5))
        self.assertEqual(sorted(self.hist()), ["sda"])

    def test_a_deleted_host_takes_its_history(self):
        self.beat_si(self.busy(sda=5))
        self.assertTrue(api._purge_device(DEV))
        api._LOAD_CACHE.clear()
        self.assertNotIn(DEV, api.load(api.DISKIO_HIST_FILE) or {})


class TestWhatThePagesAreGiven(_Hb):

    def hardware(self):
        names = ("verify_token", "get_token_from_request", "method", "respond")
        saved = {n: getattr(api, n) for n in names}
        box = {}
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "t"
        api.method = lambda: "GET"

        def _resp(status, data=None):
            box["status"], box["body"] = status, data
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_device_hardware(DEV)
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(box.get("status"), 200, box)
        return box["body"]

    def test_the_hardware_answer_has_the_latest_the_history_and_the_line(self):
        self.lines(warn=90, crit=99, sustain=1)
        for v in (10, 50, 95):
            self.beat_si(self.busy(sda=v))
        row = self.hardware()["diskio"][0]
        self.assertEqual((row["dev"], row["busy_pct"], row["read_mbs"], row["await_ms"]), ("sda", 95.0, 1.5, 4.2))
        self.assertEqual([p[1] for p in row["hist"]], [10.0, 50.0, 95.0])
        self.assertEqual((row["warn"], row["crit"]), (90.0, 99.0))

    def test_the_answer_carries_the_last_sixty_samples(self):
        for _ in range(70):
            self.beat_si(self.busy(sda=5))
        self.assertEqual(len(self.hardware()["diskio"][0]["hist"]), 60)

    def test_a_warning_line_alone_leaves_the_critical_one_empty(self):
        self.lines(warn=90, crit=0, sustain=1)
        self.beat_si(self.busy(sda=10))
        row = self.hardware()["diskio"][0]
        self.assertEqual((row["warn"], row["crit"]), (90.0, None))
        json.dumps(self.hardware(), allow_nan=False)             # no Infinity on the wire

    def test_a_named_disk_carries_its_name(self):
        api.save(api.HARDWARE_FILE, {DEV: {"smart": [{"device": "/dev/sda", "serial": "S1", "health": "PASSED"},
                                                      {"device": "/dev/sdb", "serial": "S2", "health": "PASSED"}]}})
        api.save(api.DISK_NAMES_FILE, {DEV: {"S1": "Backup pool"}})
        api._LOAD_CACHE.clear()
        self.beat_si(self.busy(sda=10, sdb=10, sdc=10))
        rows = {r["dev"]: r for r in self.hardware()["diskio"]}
        self.assertEqual(rows["sda"].get("name"), "Backup pool")
        self.assertNotIn("name", rows["sdb"])
        self.assertNotIn("name", rows["sdc"])

    def test_with_no_line_the_answer_says_so(self):
        self.beat_si(self.busy(sda=10))
        row = self.hardware()["diskio"][0]
        self.assertIsNone(row["warn"])
        self.assertIsNone(row["crit"])

    def test_a_host_that_reports_none_gets_an_empty_list(self):
        self.assertEqual(self.hardware()["diskio"], [])

    def test_the_alert_says_which_disk_and_how_busy(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=97))
        api._LOAD_CACHE.clear()
        row = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == "metric_warning"][0]
        self.assertEqual(row["title"], "Disk sda busy WARNING on serverbox: 97%")

    def test_the_webhook_text(self):
        import notify
        p = {"kind": "diskio", "target": "sda", "value": 97.0, "threshold": 90.0}
        self.assertEqual(notify._webhook_message("metric_warning", dict(p, name="serverbox")),
                         "serverbox: WARNING — disk sda busy 97% of the time (threshold: 90%)")
        self.assertEqual(notify._webhook_message("metric_recovered", dict(p, name="serverbox", value=12.0)),
                         "serverbox: disk sda busy share back to 12%")

    def test_needs_attention_names_the_disk(self):
        self.lines(warn=90, crit=99, sustain=1)
        self.beat_si(self.busy(sda=97))
        self.assertEqual(self.na_lines(), [("disk", "disk sda busy: 97% (warning ≥ 90%)")])

    def test_needs_attention_gives_the_critical_line_when_it_is_critical(self):
        self.lines(warn=90, crit=95, sustain=1)
        self.beat_si(self.busy(sda=97))
        self.assertEqual(self.na_lines(), [("disk", "disk sda busy: 97% (critical ≥ 95%)")])

    def na_lines(self):
        import attention_isolation
        tmp = tempfile.mkdtemp(prefix="rp-v743-dio-")
        keep = {n: getattr(api, n) for n in ("DEVICES_FILE", "CONFIG_FILE", "ALERTS_FILE")}
        live = {"devices": dict(api.load(api.DEVICES_FILE)), "config": dict(api.load(api.CONFIG_FILE))}
        saved = attention_isolation.isolate(api, tmp)
        try:
            api.save(api.DEVICES_FILE, live["devices"])
            api.save(api.CONFIG_FILE, live["config"])
            api._LOAD_CACHE.clear()
            lines = [(i["kind"], i["summary"]) for i in api._compute_attention() if "busy" in (i.get("summary") or "")]
        finally:
            attention_isolation.restore(api, saved)
            for n, v in keep.items():
                setattr(api, n, v)
        return lines


def _call(handler, body, *path, role="admin", verb="POST"):
    """Run one handler for real with the caller's role and body; whatever it answers is returned."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log",
             "respond", "require_admin_auth")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.require_admin_auth = lambda: "alice"
    api.verify_token = lambda t: ("alice", role)
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(*path)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class TestTheSettings(_Hb):
    """The fleet's lines are Settings -> Alert parameters, saved the way every other one is."""

    def save(self, body):
        box = _call(api.handle_config_save, body)
        return box["status"], (api.load(api.CONFIG_FILE) or {})

    def test_the_three_keys_are_saved(self):
        status, cfg = self.save({"diskio_warn_percent": "90", "diskio_crit_percent": 99, "diskio_sustain": 4})
        self.assertEqual(status, 200)
        self.assertEqual((cfg["diskio_warn_percent"], cfg["diskio_crit_percent"], cfg["diskio_sustain"]), (90, 99, 4))

    def test_out_of_range_is_refused_as_every_other_alert_parameter_is(self):
        for body in ({"diskio_warn_percent": 500}, {"diskio_crit_percent": -3}, {"diskio_sustain": 9999},
                     {"diskio_sustain": 0}):
            with self.subTest(body=body):
                status, _cfg = self.save(body)
                self.assertEqual(status, 400)

    def test_blank_puts_the_default_back(self):
        self.save({"diskio_warn_percent": 90, "diskio_sustain": 4})
        _s, cfg = self.save({"diskio_warn_percent": "", "diskio_sustain": ""})
        self.assertNotIn("diskio_warn_percent", cfg)
        self.assertNotIn("diskio_sustain", cfg)

    def test_a_word_is_refused(self):
        status, _cfg = self.save({"diskio_warn_percent": "busy"})
        self.assertEqual(status, 400)

    def test_the_defaults_are_off_and_five_reports(self):
        box = _call(api.handle_config_get, {}, verb="GET")
        self.assertEqual(box["status"], 200, box)
        body = box["body"]
        self.assertEqual((body["diskio_warn_percent"], body["diskio_crit_percent"], body["diskio_sustain"]), (0, 0, 5))

    def test_a_saved_value_is_what_the_page_gets_back(self):
        self.save({"diskio_warn_percent": 80, "diskio_crit_percent": 95, "diskio_sustain": 3})
        body = _call(api.handle_config_get, {}, verb="GET")["body"]
        self.assertEqual((body["diskio_warn_percent"], body["diskio_crit_percent"], body["diskio_sustain"]), (80, 95, 3))


class TestTheHostsOwnLine(_Hb):

    def patch(self, body):
        return _call(api.handle_device_metric_thresholds, body, DEV, verb="PATCH")

    def test_the_two_numbers_are_kept_and_a_null_removes_one(self):
        box = self.patch({"diskio_warn_percent": 60, "diskio_crit_percent": 85})
        self.assertEqual(box["status"], 200, box)
        mt = api.load(api.DEVICES_FILE)[DEV]["metric_thresholds"]
        self.assertEqual((mt["diskio_warn_percent"], mt["diskio_crit_percent"]), (60.0, 85.0))
        self.patch({"diskio_warn_percent": None})
        mt = api.load(api.DEVICES_FILE)[DEV]["metric_thresholds"]
        self.assertNotIn("diskio_warn_percent", mt)
        self.assertIn("diskio_crit_percent", mt)

    def test_the_editor_is_told_the_fleets_line_and_its_own(self):
        self.lines(warn=90, crit=99, sustain=1)
        got = _call(api.handle_device_metric_thresholds, {}, DEV, verb="GET")["body"]
        self.assertEqual((got["effective"]["diskio_warn_percent"], got["effective"]["diskio_crit_percent"]), (90, 99))
        self.assertEqual((got["defaults"]["diskio_warn_percent"], got["defaults"]["diskio_crit_percent"]), (90, 99))
        self.assertEqual(got["overrides"], {})
        self.patch({"diskio_warn_percent": 60})
        got = _call(api.handle_device_metric_thresholds, {}, DEV, verb="GET")["body"]
        self.assertEqual((got["effective"]["diskio_warn_percent"], got["effective"]["diskio_crit_percent"]), (60.0, 99))
        self.assertEqual(got["defaults"]["diskio_warn_percent"], 90)

    def test_with_no_line_anywhere_the_editor_is_told_zero(self):
        got = _call(api.handle_device_metric_thresholds, {}, DEV, verb="GET")["body"]
        self.assertEqual((got["effective"]["diskio_warn_percent"], got["effective"]["diskio_crit_percent"]), (0, 0))

    def test_out_of_range_is_refused(self):
        for bad in (0, 100, -1, "x", True):
            self.assertEqual(self.patch({"diskio_warn_percent": bad})["status"], 400, bad)


if __name__ == "__main__":
    unittest.main()
