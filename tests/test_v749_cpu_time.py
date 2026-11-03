#!/usr/bin/env python3
"""7.4.9: where the CPUs spend their time: I/O wait, steal, interrupts, nice, with a line on the first two.

The load average and the CPU percentage say a host is busy and not with what. A slow disk and a crowded hypervisor both look like load.
Three layers, each driven for real: the Linux agent's reading of /proc/stat (against a small fake root), the server's ingest and metric
engine through the real heartbeat and the real alert ledger, and the words the alerts and the pages use. Written beside the disk busy
tests (test_v743_disk_io), whose shape this feature copies, so the two are held to the same rules.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Captured, _Stdin, api  # noqa: E402
from test_v743_disk_io import _call, _Hb  # noqa: E402
from test_v741_drift_globs import load_agent  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"
NAMES = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def stat_cpu(*counters, extra=True):
    """The first lines of /proc/stat. `counters` are the first values of the aggregate line."""
    line = "cpu  " + " ".join(str(c) for c in counters) + "\n"
    return line + ("cpu0 1 2 3 4 5 6 7 8\nintr 12345\nctxt 999\n" if extra else "")


class _FakeHost(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rp-cpu-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.root), True)
        (self.root / "proc").mkdir()
        self.agent = load_agent("rp_agent_cpu", AGENT, host_root=str(self.root))
        self.agent._prev_cpu_times = None

    def write(self, text):
        (self.root / "proc" / "stat").write_text(text)

    def read(self, at):
        with mock.patch.object(self.agent.time, "monotonic", return_value=at):
            return self.agent.collect_cpu_time()


class TestTheAgentReading(_FakeHost):

    def first(self, *c, at=1000.0):
        self.write(stat_cpu(*c))
        self.assertEqual(self.read(at), {}, "the first reading has nothing to subtract")

    def test_the_shares_of_the_interval(self):
        self.first(1000, 100, 400, 8000, 300, 50, 50, 100)
        self.write(stat_cpu(1100, 110, 450, 8500, 400, 60, 90, 190))      # +100 +10 +50 +500 +100 +10 +40 +90 = 900
        got = self.read(1060.0)
        self.assertEqual(got, {"cpu_user": 11.1, "cpu_nice": 1.1, "cpu_system": 5.6, "cpu_idle": 55.6, "cpu_iowait": 11.1,
                               "cpu_irq": 5.6, "cpu_steal": 10.0})
        self.assertAlmostEqual(sum(got.values()), 100.0, delta=0.3)

    def test_irq_and_softirq_are_one_figure(self):
        self.first(0, 0, 0, 0, 0, 0, 0, 0)
        self.write(stat_cpu(0, 0, 0, 90, 0, 4, 6, 0))
        self.assertEqual(self.read(1060.0)["cpu_irq"], 10.0)

    def test_an_old_kernel_with_five_counters_reads_the_rest_as_zero(self):
        self.write(stat_cpu(100, 0, 50, 850, 0, extra=False))
        self.assertEqual(self.read(1000.0), {})
        self.write(stat_cpu(200, 0, 100, 1700, 0, extra=False))
        got = self.read(1060.0)
        self.assertEqual((got["cpu_iowait"], got["cpu_steal"], got["cpu_irq"]), (0.0, 0.0, 0.0))
        self.assertEqual(got["cpu_idle"], 85.0)

    def test_the_guest_columns_are_not_added_again(self):
        # user already includes guest time: only the first eight counters are read
        self.first(100, 0, 100, 800, 0, 0, 0, 0)
        self.write("cpu  200 0 200 1600 0 0 0 0 100 50\n")
        self.assertEqual(self.read(1060.0)["cpu_user"], 10.0)

    def test_two_readings_in_the_same_moment_wait_for_the_next(self):
        self.first(1000, 0, 0, 1000, 0, 0, 0, 0)
        self.write(stat_cpu(2000, 0, 0, 1500, 0, 0, 0, 0))
        self.assertEqual(self.read(1002.0), {}, "two seconds is too soon")
        self.write(stat_cpu(2000, 0, 0, 2000, 0, 0, 0, 0))
        got = self.read(1060.0)
        self.assertEqual(got["cpu_user"], 50.0, "the older baseline was kept, so the interval is the whole minute")

    def test_a_long_gap_is_not_an_interval(self):
        self.first(1000, 0, 0, 1000, 0, 0, 0, 0)
        self.write(stat_cpu(2000, 0, 0, 1000, 0, 0, 0, 0))
        self.assertEqual(self.read(1000.0 + 7200.0), {})
        self.write(stat_cpu(2100, 0, 0, 1100, 0, 0, 0, 0))
        self.assertEqual(self.read(1000.0 + 7260.0)["cpu_user"], 50.0, "and the next reading starts from there")

    def test_a_counter_that_goes_backwards_starts_again(self):
        self.first(1000, 0, 0, 1000, 0, 0, 0, 0)
        self.write(stat_cpu(10, 0, 0, 10, 0, 0, 0, 0))
        self.assertEqual(self.read(1060.0), {})
        self.write(stat_cpu(60, 0, 0, 20, 0, 0, 0, 0))
        got = self.read(1120.0)
        self.assertEqual((got["cpu_user"], got["cpu_idle"]), (83.3, 16.7))

    def test_an_idle_machine_that_did_not_tick_is_not_a_division_by_zero(self):
        self.first(100, 0, 0, 100, 0, 0, 0, 0)
        self.write(stat_cpu(100, 0, 0, 100, 0, 0, 0, 0))
        self.assertEqual(self.read(1060.0), {})

    def test_a_missing_or_garbled_file_is_an_empty_answer(self):
        self.assertEqual(self.read(1000.0), {}, "no file")
        for text in ("", "\n", "cpu\n", "cpu  a b c d e\n", "intr 1 2 3\n", "cpu0 1 2 3 4 5\n", "cpu  1 2 3\n", "\x00\x01"):
            self.write(text)
            self.assertEqual(self.read(2000.0), {}, repr(text))
            self.agent._prev_cpu_times = None

    def test_the_figures_are_percentages_in_range(self):
        self.first(1, 2, 3, 4, 5, 6, 7, 8)
        self.write(stat_cpu(10 ** 6, 5, 10 ** 5, 7, 3, 2, 1, 10 ** 4))
        got = self.read(1060.0)
        for k, v in got.items():
            self.assertTrue(0.0 <= v <= 100.0, (k, v))

    def test_the_real_proc_stat_reads(self):
        real = load_agent("rp_agent_cpu_real", AGENT)
        if not Path("/proc/stat").exists():
            self.skipTest("no /proc/stat here")
        counters = real._read_cpu_times()
        self.assertEqual(len(counters), 8)
        self.assertTrue(all(isinstance(c, int) and c >= 0 for c in counters))

    def test_the_heartbeat_carries_it(self):
        src = AGENT.read_text()
        self.assertIn("sysinfo.update(collect_cpu_time())", src)
        i = src.index("sysinfo.update(collect_cpu_time())")
        self.assertLess(src.rfind("sysinfo = {", 0, i), i, "after sysinfo exists")
        self.assertGreater(src.rfind("if send_sysinfo:", 0, i), src.rfind("sysinfo = {", 0, i) - 5000)
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), AGENT.read_bytes())

    def test_the_windows_and_macos_agents_do_not_send_it(self):
        for name in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            self.assertNotIn("cpu_iowait", (ROOT / "client" / name).read_text(), name)


class _Cpu(_Hb):
    """The real heartbeat with CPU time in its sysinfo, and the real metric engine and alert ledger behind it."""

    def lines(self, iowait=(0, 0), steal=(0, 0), sustain=None, **more):  # type: ignore[override]
        cfg = {"iowait_warn_percent": iowait[0], "iowait_crit_percent": iowait[1], "steal_warn_percent": steal[0], "steal_crit_percent": steal[1]}
        if sustain is not None:
            cfg["cpu_time_sustain"] = sustain
        cfg.update(more)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def beat_cpu(self, partial=False, **shares):
        """One heartbeat whose sysinfo carries these shares (iowait=40, steal=2 ...)."""
        si = {"hostname": "serverbox"}
        si.update({f"cpu_{k}": v for k, v in shares.items()})
        body = {"device_id": DEV, "token": "tok", "sysinfo": si}
        if partial:
            body["sysinfo_partial"] = True
        raw = json.dumps(body).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
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

    def cpu_events(self, kind):
        return [(e, p.get("value"), p.get("threshold")) for e, p in self.events if e.startswith("metric_") and p.get("kind") == kind]

    def open_cpu_alerts(self, kind):
        api._LOAD_CACHE.clear()
        return len([a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                    if a.get("event") in ("metric_warning", "metric_critical") and not a.get("resolved_at")
                    and (a.get("payload") or {}).get("metric") == kind])

    def stored_si(self):
        api._LOAD_CACHE.clear()
        return ((api.load(api.DEVICES_FILE) or {}).get(DEV) or {}).get("sysinfo", {})


class TestTheIngest(_Cpu):

    def test_the_shares_are_kept_as_numbers_in_range(self):
        self.beat_cpu(user=12.34, nice=0.0, system=3.2, idle=70.0, iowait=11.5, irq=0.9, steal=2.0)
        si = self.stored_si()
        self.assertEqual((si["cpu_iowait"], si["cpu_steal"], si["cpu_user"], si["cpu_irq"]), (11.5, 2.0, 12.34, 0.9))

    def test_garbage_is_dropped_one_figure_at_a_time(self):
        self.beat_cpu(iowait="lots", steal=float("nan"), user=101, idle=-1, nice=None, system=[1], irq={"a": 1})
        si = self.stored_si()
        for k in ("cpu_iowait", "cpu_steal", "cpu_user", "cpu_idle", "cpu_nice", "cpu_system", "cpu_irq"):
            self.assertNotIn(k, si, k)

    def test_a_number_too_big_for_a_float_is_dropped_not_an_error(self):
        self.beat_cpu(iowait=10 ** 400, steal=-(10 ** 400))
        self.assertNotIn("cpu_iowait", self.stored_si())

    def test_an_unknown_share_is_not_kept(self):
        self.beat_cpu(guest=5.0)
        self.assertNotIn("cpu_guest", self.stored_si())


class TestTheLine(_Cpu):

    def test_nothing_set_nothing_fires(self):
        for _ in range(6):
            self.beat_cpu(iowait=99.0, steal=99.0)
        self.assertEqual(self.cpu_events("iowait") + self.cpu_events("steal"), [])

    def test_it_takes_n_reports_and_warns_once(self):
        self.lines(iowait=(25, 50), sustain=3)
        for _ in range(2):
            self.beat_cpu(iowait=30.0)
        self.assertEqual(self.cpu_events("iowait"), [])
        self.beat_cpu(iowait=30.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_warning", 30.0, 25.0)])
        for _ in range(3):
            self.beat_cpu(iowait=30.0)
        self.assertEqual(len(self.cpu_events("iowait")), 1)
        self.assertEqual(self.open_cpu_alerts("iowait"), 1)

    def test_critical_after_the_same_run(self):
        self.lines(iowait=(25, 50), sustain=2)
        for _ in range(2):
            self.beat_cpu(iowait=60.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_critical", 60.0, 50.0)])

    def test_a_spike_shorter_than_the_run_never_alerts(self):
        self.lines(steal=(10, 25), sustain=3)
        for share in (40.0, 40.0, 1.0, 40.0, 40.0, 1.0):
            self.beat_cpu(steal=share)
        self.assertEqual(self.cpu_events("steal"), [])

    def test_it_closes_when_the_share_falls(self):
        self.lines(iowait=(25, 50), sustain=1)
        self.beat_cpu(iowait=40.0)
        self.assertEqual(self.open_cpu_alerts("iowait"), 1)
        self.beat_cpu(iowait=10.0)
        self.assertEqual(self.open_cpu_alerts("iowait"), 0)
        self.assertEqual([e for e, _v, _t in self.cpu_events("iowait")], ["metric_warning", "metric_recovered"])

    def test_the_two_kinds_are_separate(self):
        self.lines(iowait=(25, 50), steal=(10, 25), sustain=1)
        self.beat_cpu(iowait=30.0, steal=2.0)
        self.assertEqual((self.open_cpu_alerts("iowait"), self.open_cpu_alerts("steal")), (1, 0))
        self.beat_cpu(iowait=30.0, steal=12.0)
        self.assertEqual((self.open_cpu_alerts("iowait"), self.open_cpu_alerts("steal")), (1, 1))

    def test_a_host_has_its_own_line(self):
        self.lines(iowait=(25, 50), sustain=1)
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["metric_thresholds"] = {"iowait_warn_percent": 60.0}
        self.beat_cpu(iowait=40.0)
        self.assertEqual(self.cpu_events("iowait"), [], "the host's 60 replaces the fleet's 25")
        self.beat_cpu(iowait=65.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_critical", 65.0, 50.0)], "the fleet's critical line is still there for the host")

    def test_turning_the_line_off_closes_what_is_open_even_when_the_report_has_no_figure(self):
        self.lines(iowait=(25, 50), sustain=1)
        self.beat_cpu(iowait=40.0)
        self.assertEqual(self.open_cpu_alerts("iowait"), 1)
        self.lines(iowait=(0, 0), sustain=1)
        self.beat_cpu(user=1.0)                       # a report with other shares and no iowait
        self.assertEqual(self.open_cpu_alerts("iowait"), 0)

    def test_only_a_warning_line_makes_the_critical_one_unreachable(self):
        self.lines(iowait=(25, 0), sustain=1)
        self.beat_cpu(iowait=99.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_warning", 99.0, 25.0)])

    def test_only_a_critical_line_is_the_warning_one_too(self):
        self.lines(iowait=(0, 50), sustain=1)
        self.beat_cpu(iowait=30.0)
        self.assertEqual(self.cpu_events("iowait"), [], "under the only line there is nothing to say: it is not a warning line of zero")
        self.beat_cpu(iowait=55.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_critical", 55.0, 50.0)])

    def test_without_a_setting_it_takes_three_reports(self):
        self.lines(iowait=(25, 50))
        for _ in range(2):
            self.beat_cpu(iowait=30.0)
        self.assertEqual(self.cpu_events("iowait"), [])
        self.beat_cpu(iowait=30.0)
        self.assertEqual(len(self.cpu_events("iowait")), 1)

    def test_a_hand_edited_run_is_held_to_sixty(self):
        for odd, want in ((0, 1), (-5, 1), (10 ** 6, 60), ("x", 3), (None, 3), (True, 3), ("7", 7)):
            self.lines(iowait=(25, 50), sustain=odd)
            api._LOAD_CACHE.clear()
            self.assertEqual(api._cpu_time_sustain(), want, odd)

    def test_a_report_without_the_figure_says_nothing(self):
        self.lines(iowait=(25, 50), sustain=1)
        self.beat_cpu(iowait=40.0)
        before = list(self.events)
        self.beat_cpu(user=3.0)
        self.beat_cpu(partial=True, user=3.0)
        self.assertEqual(self.open_cpu_alerts("iowait"), 1)
        self.assertEqual(len(self.events), len(before))

    def test_a_partial_report_does_not_run_the_old_run_again(self):
        self.lines(iowait=(25, 50), sustain=3)
        self.beat_cpu(iowait=40.0)
        for _ in range(4):
            self.beat_cpu(partial=True, user=3.0)
        self.assertEqual(self.cpu_events("iowait"), [])

    def test_a_line_that_is_junk_is_off(self):
        for junk in (True, "abc", -5, None, [], 10 ** 400 * -1):          # NaN can not be stored at all: the writer refuses it
            self.lines(iowait=(junk, junk), sustain=1)
            self.beat_cpu(iowait=99.0)
            self.assertEqual(self.cpu_events("iowait"), [], repr(junk)[:20])
        self.lines(iowait=("50", "50"), sustain=1)
        self.beat_cpu(iowait=99.0)
        self.assertEqual(self.cpu_events("iowait"), [("metric_critical", 99.0, 50.0)], "text that holds a number is that number, as for every setting")

    def test_a_hand_edited_line_of_a_host_that_is_not_a_usable_number_is_off(self):
        """Asked of the host record directly: the store reader repairs most of these before the engine sees them, so the engine's own
        reading of a line (a number, finite, above zero, not a bool) is only reached this way."""
        self.lines()
        for junk in (True, False, "abc", -5, 0, None, [], float("inf"), float("-inf"), float("nan"), 10 ** 400, -(10 ** 400)):
            dev = {"metric_thresholds": {"iowait_warn_percent": junk, "iowait_crit_percent": junk, "steal_warn_percent": junk}}
            for kind in ("iowait", "steal"):
                self.assertEqual(api._resolve_metric_thresholds(dev, kind, ""), (None, None), (kind, repr(junk)[:20]))
        dev = {"metric_thresholds": {"iowait_warn_percent": 30.0}}
        self.assertEqual(api._resolve_metric_thresholds(dev, "iowait", ""), (30.0, float("inf")))
        self.assertEqual(api._resolve_metric_thresholds(dev, "steal", ""), (None, None), "steal does not take the line of iowait")

    def test_the_run_of_reports_is_three_when_the_setting_is_unreadable(self):
        keep = api._config_ro
        try:
            for odd in ("abc", None, [], float("inf"), {}):
                api._config_ro = lambda odd=odd: {"cpu_time_sustain": odd}
                self.assertEqual(api._cpu_time_sustain(), 3, repr(odd))
            api._config_ro = lambda: {}
            self.assertEqual(api._cpu_time_sustain(), 3)
            api._config_ro = lambda: {"cpu_time_sustain": 7}
            self.assertEqual(api._cpu_time_sustain(), 7)
        finally:
            api._config_ro = keep

    def test_turning_the_line_off_leaves_nothing_behind(self):
        """The state of the kind and its run of breaching reports go with the line. Left behind, the closed alert is closed again by
        every report that follows."""
        self.lines(iowait=(25, 50), sustain=3)
        for _ in range(3):
            self.beat_cpu(iowait=40.0)
        self.assertEqual(self.open_cpu_alerts("iowait"), 1)
        self.lines(iowait=(0, 0), sustain=3)
        for _ in range(3):
            self.beat_cpu(iowait=40.0)
        self.assertEqual([e for e, _v, _t in self.cpu_events("iowait")], ["metric_warning", "metric_recovered"], "closed once, not by every report")
        dev = (api.load(api.DEVICES_FILE) or {})[DEV]
        self.assertNotIn("iowait:", dev.get("metric_state") or {})
        self.assertNotIn("iowait:", dev.get("metric_breach_streak") or {})

    def test_a_run_cut_short_by_turning_the_line_off_does_not_count_when_it_is_turned_on_again(self):
        self.lines(iowait=(25, 50), sustain=3)
        for _ in range(2):
            self.beat_cpu(iowait=40.0)                 # two reports of the three it takes
        self.lines(iowait=(0, 0), sustain=3)
        self.beat_cpu(iowait=40.0)                     # the line is off: the run is dropped
        self.lines(iowait=(25, 50), sustain=3)
        for _ in range(2):
            self.beat_cpu(iowait=40.0)
        self.assertEqual(self.cpu_events("iowait"), [], "two reports are not three")
        self.beat_cpu(iowait=40.0)
        self.assertEqual(len(self.cpu_events("iowait")), 1)


class TestTheWords(_Cpu):

    def test_the_alert_title(self):
        self.lines(iowait=(25, 50), steal=(10, 25), sustain=1)
        self.beat_cpu(iowait=40.0, steal=30.0)
        api._LOAD_CACHE.clear()
        titles = sorted(a["title"] for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") in ("metric_warning", "metric_critical"))
        self.assertIn("CPU time waiting for storage WARNING on serverbox: 40%", titles)
        self.assertIn("CPU time taken by the hypervisor CRITICAL on serverbox: 30%", titles)

    def test_the_webhook_text(self):
        import notify
        p = {"kind": "iowait", "target": "", "value": 40.0, "threshold": 25.0, "name": "serverbox"}
        self.assertEqual(notify._webhook_message("metric_warning", p), "serverbox: WARNING — 40% of the CPU time went to waiting for storage (threshold: 25%)")
        self.assertEqual(notify._webhook_message("metric_critical", dict(p, kind="steal", value=30.0, threshold=25.0)),
                         "serverbox: CRITICAL — 30% of the CPU time was taken by the hypervisor (threshold: 25%)")
        self.assertEqual(notify._webhook_message("metric_recovered", dict(p, value=3.0)), "serverbox: the share of the CPU time that went to waiting for storage is back to 3%")
        self.assertEqual(notify._webhook_message("metric_recovered", dict(p, kind="steal", value=2.0)), "serverbox: the share of the CPU time that was taken by the hypervisor is back to 2%")

    def na_lines(self, mutes=()):
        """The Needs-Attention items about the CPU time, with these events muted for the host."""
        import attention_isolation
        tmp = tempfile.mkdtemp(prefix="rp-v749-cpu-")
        keep = {n: getattr(api, n) for n in ("DEVICES_FILE", "CONFIG_FILE", "ALERTS_FILE")}
        live = {"devices": dict(api.load(api.DEVICES_FILE)), "config": dict(api.load(api.CONFIG_FILE))}
        saved = attention_isolation.isolate(api, tmp)
        try:
            api.save(api.DEVICES_FILE, live["devices"])
            api.save(api.CONFIG_FILE, live["config"])
            if mutes:
                api.save(api.ALERT_MUTES_FILE, {"mutes": [{"id": f"m{n}", "device_id": DEV, "event": ev} for n, ev in enumerate(mutes)]})
            api._LOAD_CACHE.clear()
            api._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)      # the set is kept by the store's mtime, which two files can share
            lines = [(i["kind"], i["summary"]) for i in api._compute_attention() if "CPU time" in (i.get("summary") or "")]
        finally:
            attention_isolation.restore(api, saved)
            for n, v in keep.items():
                setattr(api, n, v)
            api._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)      # and what a test muted is not left for the next one
        return lines

    def test_needs_attention_names_the_share_and_is_a_cpu_item(self):
        self.lines(iowait=(25, 50), sustain=1)
        self.beat_cpu(iowait=40.0)
        self.assertEqual(self.na_lines(), [("cpu", "CPU time waiting for storage: 40% (warning ≥ 25%)")])

    def test_the_critical_line_is_given_when_it_is_critical(self):
        self.lines(steal=(10, 25), sustain=1)
        self.beat_cpu(steal=30.0)
        self.assertEqual(self.na_lines(), [("cpu", "CPU time taken by the hypervisor: 30% (critical ≥ 25%)")])

    def test_muting_the_metric_alert_of_the_host_takes_the_item_off_the_list(self):
        """A cpu item is muted with the host's metric_warning or metric_critical, as a disk item is. Without that row the alert was
        silent and the item stayed, so the host's health score never recovered."""
        self.lines(iowait=(25, 50), steal=(10, 25), sustain=1)
        self.beat_cpu(iowait=40.0, steal=30.0)
        self.assertEqual(len(self.na_lines()), 2)
        self.assertEqual([k for k, _ in self.na_lines(mutes=("metric_warning",))], ["cpu"], "only the warning is gone")
        self.assertEqual([s for _, s in self.na_lines(mutes=("metric_warning",))], ["CPU time taken by the hypervisor: 30% (critical ≥ 25%)"])
        self.assertEqual(self.na_lines(mutes=("metric_critical",)), [("cpu", "CPU time waiting for storage: 40% (warning ≥ 25%)")])
        self.assertEqual(self.na_lines(mutes=("metric_warning", "metric_critical")), [])

    def test_a_mute_of_another_host_or_another_event_hides_nothing(self):
        self.lines(iowait=(25, 50), sustain=1)
        self.beat_cpu(iowait=40.0)
        self.assertEqual(len(self.na_lines(mutes=("device_offline", "disk_predict_fail"))), 1)

    def test_every_item_of_the_metric_loop_has_a_mute_row(self):
        """The metric loop emits one item for each of cpu, memory and swap; the disk items of the same loop had their rows and
        these did not. Pinned for the three kinds and both severities, to the events a metric alert is raised as."""
        for kind in ("cpu", "memory", "swap", "disk"):
            self.assertEqual(api._NA_MUTE_EVENTS[(kind, "warning")][0], "metric_warning", kind)
            self.assertEqual(api._NA_MUTE_EVENTS[(kind, "critical")][0], "metric_critical", kind)

    def test_the_problems_page_knows_the_kinds(self):
        import problems_handlers
        self.assertTrue({"iowait", "steal"} <= problems_handlers.METRIC_KINDS)


class TestTheSettings(_Cpu):
    """The fleet's lines are Settings -> Alert parameters, saved the way every other one is."""

    def save(self, body):
        box = _call(api.handle_config_save, body)
        return box["status"], (api.load(api.CONFIG_FILE) or {})

    def test_the_five_keys_are_saved(self):
        st, cfg = self.save({"iowait_warn_percent": "25", "iowait_crit_percent": "50", "steal_warn_percent": "10", "steal_crit_percent": "25", "cpu_time_sustain": "4"})
        self.assertEqual(st, 200)
        self.assertEqual([cfg[k] for k in ("iowait_warn_percent", "iowait_crit_percent", "steal_warn_percent", "steal_crit_percent", "cpu_time_sustain")], [25, 50, 10, 25, 4])

    def test_out_of_range_is_refused_as_every_other_alert_parameter_is(self):
        for body in ({"iowait_warn_percent": "101"}, {"steal_crit_percent": "-1"}, {"cpu_time_sustain": "0"}, {"cpu_time_sustain": "61"}, {"steal_warn_percent": "x"}):
            st, _ = self.save(body)
            self.assertEqual(st, 400, body)

    def test_every_line_is_held_to_zero_and_a_hundred(self):
        for key in ("iowait_warn_percent", "iowait_crit_percent", "steal_warn_percent", "steal_crit_percent"):
            for bad in ("101", "-1", "1000"):
                self.assertEqual(self.save({key: bad})[0], 400, (key, bad))
            for good, want in (("0", 0), ("100", 100), ("37", 37)):
                st, cfg = self.save({key: good})
                self.assertEqual((st, cfg[key]), (200, want), (key, good))

    def test_blank_puts_the_default_back(self):
        self.save({"iowait_warn_percent": "25", "cpu_time_sustain": "9"})
        self.save({"iowait_warn_percent": "", "cpu_time_sustain": ""})
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotIn("iowait_warn_percent", cfg)
        self.assertNotIn("cpu_time_sustain", cfg)

    def test_blank_puts_the_default_back_for_every_key(self):
        keys = ("iowait_warn_percent", "iowait_crit_percent", "steal_warn_percent", "steal_crit_percent", "cpu_time_sustain")
        self.assertEqual(self.save({k: "7" for k in keys})[0], 200)
        self.assertEqual(self.save({k: "" for k in keys})[0], 200)
        cfg = api.load(api.CONFIG_FILE)
        for k in keys:
            self.assertNotIn(k, cfg, k)

    def test_the_defaults_are_off_and_three_reports(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        box = _call(api.handle_config_get, {}, verb="GET")
        body = box["body"]
        self.assertEqual([body[k] for k in ("iowait_warn_percent", "iowait_crit_percent", "steal_warn_percent", "steal_crit_percent")], [0, 0, 0, 0])
        self.assertEqual(body["cpu_time_sustain"], 3)

    def test_a_saved_value_is_what_the_page_gets_back(self):
        self.save({"steal_warn_percent": "12"})
        self.assertEqual(_call(api.handle_config_get, {}, verb="GET")["body"]["steal_warn_percent"], 12)


class TestTheHostsOwnLine(_Cpu):

    def patch(self, body):
        return _call(api.handle_device_metric_thresholds, body, DEV, verb="PATCH")

    def get(self):
        return _call(api.handle_device_metric_thresholds, {}, DEV, verb="GET")["body"]

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(DEV, {}).get("metric_thresholds", {})

    def test_the_lines_are_kept_and_a_null_removes_one(self):
        self.assertEqual(self.patch({"iowait_warn_percent": 30, "iowait_crit_percent": 60, "steal_warn_percent": 5})["status"], 200)
        self.assertEqual({k: v for k, v in self.stored().items() if "percent" in k and ("iowait" in k or "steal" in k)},
                         {"iowait_warn_percent": 30.0, "iowait_crit_percent": 60.0, "steal_warn_percent": 5.0})
        self.patch({"iowait_warn_percent": None})
        self.assertNotIn("iowait_warn_percent", self.stored())
        self.assertEqual(self.stored()["iowait_crit_percent"], 60.0)

    def test_the_editor_is_told_the_fleets_line_and_its_own(self):
        self.lines(iowait=(25, 50), steal=(10, 25))
        self.patch({"steal_warn_percent": 8})
        got = self.get()
        self.assertEqual((got["defaults"]["iowait_warn_percent"], got["defaults"]["steal_warn_percent"]), (25, 10))
        self.assertEqual((got["effective"]["iowait_warn_percent"], got["effective"]["steal_warn_percent"]), (25, 8.0))
        self.assertEqual(got["overrides"], {"steal_warn_percent": 8.0})

    def test_with_no_line_anywhere_the_editor_is_told_zero(self):
        self.lines()
        got = self.get()
        for k in ("iowait_warn_percent", "iowait_crit_percent", "steal_warn_percent", "steal_crit_percent"):
            self.assertEqual((got["defaults"][k], got["effective"][k]), (0, 0), k)

    def test_out_of_range_is_refused_with_a_sentence_the_page_can_translate(self):
        for bad in (0, -1, 100, 1000, 10 ** 400, True, "hot", "50", "", [], {}, float("nan")):
            box = self.patch({"steal_warn_percent": bad})
            self.assertEqual(box["status"], 400, repr(bad)[:20])
            self.assertEqual(box["body"]["error"], "The CPU time lines must be a number from 1 to 99")
            self.assertEqual(box["body"]["field"], "steal_warn_percent")
        self.assertNotIn("steal_warn_percent", self.stored())

    def test_a_reset_removes_them_with_the_rest(self):
        self.patch({"iowait_warn_percent": 30})
        _call(api.handle_device_metric_thresholds, {}, DEV, verb="DELETE")
        self.assertEqual(self.stored(), {})


class TestTheExporter(_Cpu):

    def test_the_two_shares_are_gauges(self):
        import prometheus_export
        src = (ROOT / "server" / "cgi-bin" / "prometheus_export.py").read_text()
        for name, key in (("remotepower_device_cpu_iowait_percent", "cpu_iowait"), ("remotepower_device_cpu_steal_percent", "cpu_steal")):
            self.assertIn(name, src)
            self.assertIn(f"'{key}'", src)
        self.assertTrue(hasattr(prometheus_export, "generate_metrics"))

    def test_a_host_that_reports_them_is_exported(self):
        import prometheus_export
        now = int(__import__("time").time())
        devs = {DEV: {"name": "serverbox", "last_seen": now, "sysinfo": {"cpu_iowait": 12.5, "cpu_steal": 1.5}}}
        text = prometheus_export.generate_metrics({"now": now, "devices": devs, "online_ttl": 300, "server_version": "x"})
        self.assertRegex(text, r'remotepower_device_cpu_iowait_percent\{[^}]*\} 12\.5')
        self.assertRegex(text, r'remotepower_device_cpu_steal_percent\{[^}]*\} 1\.5')

    def test_a_host_that_does_not_has_no_line_not_a_zero(self):
        import prometheus_export
        now = int(__import__("time").time())
        devs = {DEV: {"name": "serverbox", "last_seen": now, "sysinfo": {"cpu_percent": 3.0}}}
        text = prometheus_export.generate_metrics({"now": now, "devices": devs, "online_ttl": 300, "server_version": "x"})
        self.assertNotRegex(text, r"remotepower_device_cpu_iowait_percent\{")


class TestNothingWasLeftOut(unittest.TestCase):
    """The disk busy lines were added to a dozen places in 7.4.3. These are the same places, counted: a place that has one and not the other is
    the half-applied rule this codebase keeps finding."""

    FILES = ("server/cgi-bin/api.py", "server/cgi-bin/request_models.py", "server/cgi-bin/store_shapes.py", "server/html/static/js/app.js")

    def test_every_file_that_names_the_disk_busy_lines_names_the_cpu_time_lines(self):
        seen = {}
        for rel in self.FILES:
            text = (ROOT / rel).read_text()
            disk = text.count("diskio_warn_percent")
            cpu = text.count("iowait_warn_percent") + text.count("_CPU_TIME_LINE_KEYS")        # the constant stands for all four lines
            seen[rel] = (disk, cpu)
            self.assertGreater(disk, 0, f"{rel}: the baseline is empty, so the comparison would pass over nothing")
            self.assertEqual(text.count("iowait_crit_percent"), text.count("steal_crit_percent") + 0 if rel.endswith("store_shapes.py") else text.count("iowait_crit_percent"))
        # api.py and the page name the pair in a few places that are not the disk's (the generic kind branch, the fleet defaults), so the ratio is
        # printed with the failure rather than demanded to be one to one
        for rel, (disk, cpu) in seen.items():
            self.assertGreaterEqual(cpu, 1, f"{rel}: disk {disk} / cpu {cpu}")
        self.assertGreaterEqual(seen["server/cgi-bin/api.py"][1], seen["server/cgi-bin/api.py"][0] - 3, seen)
        self.assertGreaterEqual(seen["server/html/static/js/app.js"][1], seen["server/html/static/js/app.js"][0], seen)


if __name__ == "__main__":
    unittest.main()
