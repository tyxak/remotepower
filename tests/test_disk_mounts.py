"""The disk figures stopped saying the same thing in every row.

A Linux host with btrfs reports each subvolume (/, /home, /var/log, ...) as a mount of its own, and every one of
them has the size and the use of the volume. Monitor -> Host metrics listed all of them with the same percentage,
and the Trends chart drew the same line over itself seven times, so the disk figures looked as if they never
moved. disk_mounts.py says which mounts are one filesystem. The Trends chart and the Host metrics table both use
it (the table through the page's own copy of the rule, which these tests hold to the module).

The mount lists below are what the real agent reported on a btrfs machine (get_metrics() of
client/remotepower-agent.py), not a shape made up for the test.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-diskmounts-"))

import api  # noqa: E402
import disk_mounts as dm  # noqa: E402
import srcpin  # noqa: E402

APP = (ROOT / "server/html/static/js/app.js").read_text()
NODE = shutil.which("node")


def mount(path, percent, used, total, fstype="btrfs", **extra):
    return dict({"path": path, "percent": percent, "used_gb": used, "total_gb": total, "fstype": fstype}, **extra)


# What the agent reported: one btrfs volume under seven mount points, a network share, the boot partition, a
# portal with no size at all and two profile overlays that are the same volume.
REAL = [
    mount("/", 49.7, 454.35, 927.4),
    mount("/data", 67.6, 12079.89, 17871.35, "cifs", network=True, server="10.0.0.5:/data"),
    mount("/boot", 23.5, 0.96, 4.09, "vfat"),
    mount("/home", 49.7, 454.35, 927.4),
    mount("/root", 49.7, 454.35, 927.4),
    mount("/run/user/1000/doc", 0.0, 0.0, 0.0, "fuse.portal"),
    mount("/run/user/1000/psd/jaove-firefox-snkiqd2t.default-release", 4.1, 0.26, 6.26, "fuse.fuse-overlayfs"),
    mount("/run/user/1000/psd/jaove-google-chrome", 4.1, 0.26, 6.26, "fuse.fuse-overlayfs"),
    mount("/srv", 49.7, 454.35, 927.4),
    mount("/var/cache", 49.7, 454.35, 927.4),
    mount("/var/log", 49.7, 454.35, 927.4),
    mount("/var/tmp", 49.7, 454.35, 927.4),
]
BTRFS = ["/home", "/root", "/srv", "/var/cache", "/var/log", "/var/tmp"]


class TestWhichMountsAreOneFilesystem(unittest.TestCase):

    def test_the_subvolumes_of_one_volume_are_one_filesystem(self):
        got = dm.groups(REAL)
        by = {g["path"]: g["also"] for g in got}
        self.assertEqual(by["/"], sorted(BTRFS, key=lambda p: (len(p), p)), "shortest first")
        self.assertEqual(by["/data"], [])
        self.assertEqual(by["/boot"], [])
        self.assertEqual(len(got), 5, got)

    def test_the_two_profile_overlays_are_one_filesystem(self):
        by = {g["path"]: g["also"] for g in dm.groups(REAL)}
        self.assertEqual(by["/run/user/1000/psd/jaove-google-chrome"],
                         ["/run/user/1000/psd/jaove-firefox-snkiqd2t.default-release"],
                         "the shortest path names the filesystem")

    def test_the_filesystems_come_in_the_order_they_first_appear(self):
        self.assertEqual([g["path"] for g in dm.groups(REAL)],
                         ["/", "/data", "/boot", "/run/user/1000/doc", "/run/user/1000/psd/jaove-google-chrome"])

    def test_the_shortest_path_names_it_whatever_the_order(self):
        a, b = mount("/var/log", 49.7, 454.35, 927.4), mount("/", 49.7, 454.35, 927.4)
        for mounts in ([a, b], [b, a]):
            self.assertEqual(dm.groups(mounts), [{"path": "/", "also": ["/var/log"]}])

    def test_the_use_may_move_a_little_between_two_reads(self):
        a, b = mount("/", 49.7, 454.35, 927.4), mount("/home", 49.7, 454.40, 927.4)
        self.assertEqual(len(dm.groups([a, b])), 1)
        c = mount("/home", 49.7, 454.41, 927.4)
        self.assertEqual(len(dm.groups([a, c])), 2, "0.06 GB apart is past the tolerance")

    def test_different_sizes_are_different_filesystems(self):
        a, b = mount("/a", 50.0, 100.0, 200.0), mount("/b", 50.0, 100.0, 200.05)
        self.assertEqual(len(dm.groups([a, b])), 2)

    def test_two_new_empty_disks_are_not_taken_for_one(self):
        a, b = mount("/mnt/a", 0.0, 0.02, 931.5, "ext4"), mount("/mnt/b", 0.0, 0.02, 931.5, "ext4")
        self.assertEqual(len(dm.groups([a, b])), 2, "a mount with no use to speak of says nothing about which disk it is")

    def test_a_share_and_a_local_filesystem_of_the_same_size_are_two(self):
        a = mount("/a", 50.0, 100.0, 200.0)
        b = mount("/b", 50.0, 100.0, 200.0, "nfs", network=True)
        self.assertEqual(len(dm.groups([a, b])), 2)

    def test_a_mount_that_reports_no_size_is_never_merged(self):
        a = {"path": "/a", "percent": 50.0}
        b = {"path": "/b", "percent": 50.0}
        self.assertEqual(len(dm.groups([a, b])), 2)
        stalled = {"path": "/nas", "stalled": True, "network": True}
        self.assertEqual(len(dm.groups([stalled, dict(stalled, path="/nas2")])), 2)

    def test_the_same_path_twice_is_one_mount(self):
        """psutil can list a bind mount twice."""
        a = mount("/srv", 49.7, 454.35, 927.4)
        self.assertEqual(dm.groups([a, dict(a)]), [{"path": "/srv", "also": []}])

    def test_a_filesystem_names_at_most_twenty_other_mount_points(self):
        many = [mount(f"/m/{i:02d}", 49.7, 454.35, 927.4) for i in range(60)]
        (only,) = dm.groups(many)
        self.assertEqual(len(only["also"]), dm.MAX_ALSO)

    def test_what_is_not_a_mount_is_skipped(self):
        junk = [None, 5, "text", [], {}, {"path": ""}, {"path": 5}, {"path": None}, mount("/ok", 1.0, 5.0, 10.0)]
        self.assertEqual(dm.groups(junk), [{"path": "/ok", "also": []}])
        for bad in (None, 5, "text", {}, ()):
            self.assertEqual(dm.groups(bad), [])

    def test_sizes_that_are_not_numbers_are_not_a_match(self):
        for bad in (None, "100", True, float("nan"), float("inf"), [], {}):
            with self.subTest(bad=repr(bad)):
                a = mount("/a", 50.0, 100.0, 200.0)
                b = dict(mount("/b", 50.0, 100.0, 200.0), used_gb=bad)
                self.assertEqual(len(dm.groups([a, b])), 2)


class TestWhichLinesAreOneLine(unittest.TestCase):

    @staticmethod
    def line(*values, start=1_000):
        return [{"ts": start + i * 86400, "v": v} for i, v in enumerate(values)]

    def test_a_line_that_agrees_everywhere_is_the_same_line(self):
        self.assertTrue(dm.same_line(self.line(40.0, 41.0, 42.0), self.line(40.0, 41.03, 42.0)))

    def test_one_point_apart_is_a_different_line(self):
        self.assertFalse(dm.same_line(self.line(40.0, 41.0, 42.0), self.line(40.0, 41.2, 42.0)))

    def test_lines_that_share_no_time_say_nothing(self):
        self.assertFalse(dm.same_line(self.line(40.0, start=1_000), self.line(40.0, start=9_000_000)))
        self.assertFalse(dm.same_line([], self.line(40.0)))

    def test_only_the_times_both_have_count(self):
        self.assertTrue(dm.same_line(self.line(40.0, 41.0), self.line(40.0, 41.0, 90.0)))

    def test_points_that_are_not_numbers_are_a_different_line(self):
        for bad in (None, "40", True, float("nan")):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(dm.same_line(self.line(40.0), self.line(bad)))

    def test_history_decides_when_it_is_given(self):
        """/home was a volume of its own for a while and has the size and the use of / now: the history keeps it
        a separate line, because the two did not always say the same thing."""
        mounts = [mount("/", 49.7, 454.35, 927.4), mount("/home", 49.7, 454.35, 927.4)]
        points = {"/": self.line(40.0, 45.0, 49.7), "/home": self.line(10.0, 20.0, 49.7)}
        self.assertEqual(len(dm.groups(mounts, points=points)), 2)
        points["/home"] = self.line(40.0, 45.0, 49.7)
        self.assertEqual(len(dm.groups(mounts, points=points)), 1)

    def test_a_mount_with_no_history_is_not_merged_when_history_is_asked_for(self):
        mounts = [mount("/", 49.7, 454.35, 927.4), mount("/home", 49.7, 454.35, 927.4)]
        self.assertEqual(len(dm.groups(mounts, points={"/": self.line(40.0)})), 2)


class TestALegendPath(unittest.TestCase):

    def test_a_short_path_is_kept_and_a_long_one_keeps_its_end(self):
        self.assertEqual(dm.short_path("/var/log"), "/var/log")
        long = "/run/user/1000/psd/jaove-firefox-snkiqd2t.default-release"
        out = dm.short_path(long)
        self.assertEqual(len(out), dm.MAX_PATH)
        self.assertTrue(out.startswith("…") and long.endswith(out[1:]))


# ─── the Trends chart, through the real handler ─────────────────────────────

class _Trends(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-diskmounts-run-"))
        self._files = {}
        for attr in ("DEVICES_FILE", "METRICS_HIST_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.dir / Path(str(getattr(api, attr))).name)
        api.save(api.DEVICES_FILE, {"d1": {"name": "host-one", "last_seen": int(time.time())}})
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        for attr, value in self._files.items():
            setattr(api, attr, value)

    def history(self, mounts_for_day, days=12):
        now = int(time.time())
        samples = []
        for i in range(days):
            ts = now - (days - 1 - i) * 86400
            samples.append({"date": time.strftime("%Y-%m-%d", time.gmtime(ts)), "ts": ts, "mem_percent": 30.0,
                            "swap_percent": 0.0, "mounts": mounts_for_day(i)})
        api.save(api.METRICS_HIST_FILE, {"d1": {"samples": samples}})
        api._invalidate_load_cache(api.METRICS_HIST_FILE)

    def series(self):
        cap = {}

        def _resp(status, body=None):
            cap["s"], cap["b"] = status, body
            raise api.HTTPError(status, body)

        saved = (api.respond, api.require_auth, api._caller_scope)
        api.respond, api.require_auth, api._caller_scope = _resp, (lambda: "jakob"), (lambda: None)
        try:
            api.handle_device_metrics_history("d1")
        except api.HTTPError:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope = saved
        self.assertEqual(cap["s"], 200)
        return {s["name"]: s["points"] for s in cap["b"]["series"]}

    @staticmethod
    def names(series):
        return [n for n in series if n.startswith("disk ") and n != "disk % (busiest)"]


class TestTheTrendsChartDrawsEachFilesystemOnce(_Trends):

    def test_seven_mounts_of_one_volume_are_one_line_that_says_so(self):
        self.history(lambda i: [dict(m, percent=round(m["percent"] + (i * 0.1 if m["fstype"] == "btrfs" else 0), 1),
                                     used_gb=round(m["used_gb"] + (i * 0.9 if m["fstype"] == "btrfs" else 0), 2))
                                for m in REAL])
        names = self.names(self.series())
        self.assertIn("disk / (+6)", names)
        for other in BTRFS:
            self.assertNotIn(f"disk {other}", names, "a mount of the same volume was drawn again")
        self.assertEqual(len(names), 4, names)

    def test_the_mounts_that_are_different_are_all_drawn(self):
        self.history(lambda i: REAL)
        names = self.names(self.series())
        self.assertIn("disk /data (net)", names)
        self.assertIn("disk /boot", names)

    def test_the_pseudo_filesystem_with_no_size_has_no_line(self):
        self.history(lambda i: REAL)
        self.assertFalse([n for n in self.series() if "doc" in n], "a mount of size 0 was drawn")

    def test_a_long_path_is_cut_to_its_end_in_the_legend(self):
        self.history(lambda i: REAL)
        names = [n for n in self.names(self.series()) if "psd" in n or "chrome" in n]
        self.assertTrue(names)
        for name in names:
            self.assertLessEqual(len(name), len("disk ") + dm.MAX_PATH + len(" (+1)"), name)

    def test_the_points_of_the_line_are_those_of_the_shortest_path(self):
        self.history(lambda i: REAL, days=5)
        series = self.series()
        self.assertEqual([p["v"] for p in series["disk / (+6)"]], [49.7] * 5)

    def test_the_busiest_line_and_the_other_series_are_as_they_were(self):
        self.history(lambda i: REAL)
        series = self.series()
        self.assertEqual({p["v"] for p in series["disk % (busiest)"]}, {67.6})
        self.assertIn("memory %", series)

    def test_a_mount_that_was_once_its_own_volume_stays_its_own_line(self):
        def mounts(i):
            home = mount("/home", 49.7, 454.35, 927.4) if i >= 8 else mount("/home", 10.0 + i, 120.0, 927.4)
            return [mount("/", 49.7, 454.35, 927.4), home]
        self.history(mounts, days=12)
        names = self.names(self.series())
        self.assertEqual(sorted(names), ["disk /", "disk /home"], "the two did not always say the same thing")

    def test_at_most_eight_different_filesystems_are_drawn(self):
        self.history(lambda i: [mount(f"/m{k}", 10.0 + k, 50.0 + k * 7, 400.0 + k * 11) for k in range(12)])
        self.assertEqual(len(self.names(self.series())), 8)

    def test_more_real_filesystems_fit_now_that_the_copies_are_gone(self):
        """Eight slots, and the old chart spent seven of them on one volume."""
        real = [mount(f"/mnt/d{k}", 20.0 + k, 100.0 + k * 9, 500.0 + k * 13, "ext4") for k in range(5)]
        self.history(lambda i: [mount("/", 49.7, 454.35, 927.4)] + [mount(p, 49.7, 454.35, 927.4) for p in BTRFS] + real)
        names = self.names(self.series())
        self.assertEqual(len(names), 6, names)
        for k in range(5):
            self.assertIn(f"disk /mnt/d{k}", names)

    def test_a_sample_with_a_mount_that_is_not_a_map_does_not_stop_the_chart(self):
        """A stored row can be imported or edited by hand. The chart used to fail for the whole host on one."""
        self.history(lambda i: REAL + ["junk", None, 5, [], {"path": "/x", "percent": "high"}])
        names = self.names(self.series())
        self.assertIn("disk / (+6)", names)

    def test_a_sample_whose_mounts_is_not_a_list_still_gives_the_other_series(self):
        self.history(lambda i: "not a list")
        series = self.series()
        self.assertIn("memory %", series)
        self.assertEqual(self.names(series), [])


# ─── the page's copy of the rule ────────────────────────────────────────────

def run_js(script):
    if NODE is None:
        raise unittest.SkipTest("node is not installed")
    done = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise AssertionError(done.stderr)
    return json.loads(done.stdout)


def page_groups(cases):
    script = (srcpin.js_function(APP, "_groupMounts")
              + "\nconst cases = JSON.parse(process.argv[1]);\n"
              + "console.log(JSON.stringify(cases.map(c => _groupMounts(c).map(g => ({path: g.m.path, also: g.also})))));\n")
    done = subprocess.run([NODE, "-e", script, json.dumps(cases)], capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise AssertionError(done.stderr)
    return json.loads(done.stdout)


class TestThePageAndTheServerAgree(unittest.TestCase):

    CASES = [
        REAL[:5] + REAL[6:],
        [mount("/", 49.7, 454.35, 927.4), mount("/home", 49.7, 454.40, 927.4)],
        [mount("/", 49.7, 454.35, 927.4), mount("/home", 49.7, 454.41, 927.4)],
        [mount("/a", 50.0, 100.0, 200.0), mount("/b", 50.0, 100.0, 200.05)],
        [mount("/mnt/a", 0.0, 0.02, 931.5, "ext4"), mount("/mnt/b", 0.0, 0.02, 931.5, "ext4")],
        [mount("/a", 50.0, 100.0, 200.0), mount("/b", 50.0, 100.0, 200.0, "nfs", network=True)],
        [{"path": "/a", "percent": 50.0}, {"path": "/b", "percent": 50.0}],
        [mount("/var/log", 49.7, 454.35, 927.4), mount("/", 49.7, 454.35, 927.4)],
        [mount("/srv", 49.7, 454.35, 927.4), mount("/srv", 49.7, 454.35, 927.4)],
        [mount(f"/m/{i:02d}", 49.7, 454.35, 927.4) for i in range(60)],
        [None, 5, "text", [], {}, {"path": ""}, {"path": 5}, mount("/ok", 1.0, 5.0, 10.0)],
        [mount("/z/b", 49.7, 454.35, 927.4), mount("/z/a", 49.7, 454.35, 927.4), mount("/y", 49.7, 454.35, 927.4)],
        [],
    ]

    def test_every_case_is_grouped_the_same_way_by_the_page_and_the_server(self):
        if NODE is None:
            self.skipTest("node is not installed")
        got = page_groups(self.CASES)
        for case, page in zip(self.CASES, got):
            with self.subTest(case=json.dumps(case)[:70]):
                self.assertEqual(page, dm.groups(case))

    def test_the_check_can_fail(self):
        """The control: the table must hold a pair the rule merges, or agreement would prove nothing."""
        got = page_groups([self.CASES[0]])[0]
        self.assertTrue(any(g["also"] for g in got))

    def test_the_page_leaves_a_mount_of_size_zero_out(self):
        got = page_groups([REAL])[0]
        self.assertNotIn("/run/user/1000/doc", [g["path"] for g in got])
        self.assertEqual(len(got), 4)

    def test_the_page_keeps_a_stalled_share_which_has_no_percentage(self):
        stalled = {"path": "/nas", "stalled": True, "network": True, "server": "nas:/x"}
        self.assertEqual(page_groups([[stalled]])[0], [{"path": "/nas", "also": []}])


class TestTheHostMetricsTable(unittest.TestCase):

    def test_the_disks_column_lists_filesystems_and_not_mount_points(self):
        body = APP[APP.index("function _registerDeviceMetricsTable()"):]
        body = body[:body.index("// v3.2.0 follow-up: SNMP devices table")]
        self.assertIn("const filesystems = _groupMounts(mounts);", body)
        self.assertIn("filesystems.map(({ m, also }) =>", body)
        self.assertNotIn("const items = mounts.map(", body, "the column went back to one entry for each mount point")

    def test_an_alert_on_any_mount_point_of_the_filesystem_colours_its_entry(self):
        body = APP[APP.index("function _registerDeviceMetricsTable()"):]
        self.assertIn("for (const mp of [m.path, ...also])", body)

    def test_the_other_mount_points_are_named_on_hover_and_counted(self):
        body = APP[APP.index("function _registerDeviceMetricsTable()"):]
        self.assertIn("also mounted at ${escHtml(also.join(', '))}", body)
        self.assertIn("+${also.length}", body)

    def test_searching_by_a_mount_point_still_finds_a_host_for_every_mount_point(self):
        body = APP[APP.index("function _registerDeviceMetricsTable()"):]
        self.assertIn("(d.sysinfo?.mounts || []).map(m => (m.path || '').toLowerCase()).join(' ')", body)


class TestTheDiskIoWindow(unittest.TestCase):

    @staticmethod
    def window(rows):
        script = (srcpin.js_function(APP, "_diskIoWindow")
                  + "\nconsole.log(JSON.stringify(_diskIoWindow(JSON.parse(process.argv[1]))));\n")
        if NODE is None:
            raise unittest.SkipTest("node is not installed")
        done = subprocess.run([NODE, "-e", script, json.dumps(rows)], capture_output=True, text=True, timeout=30)
        if done.returncode != 0:
            raise AssertionError(done.stderr)
        return json.loads(done.stdout)

    def test_the_gap_is_the_spacing_of_the_last_two_samples(self):
        rows = [{"dev": "sda", "hist": [[1000, 1, 0, 0, 0, 0], [1600, 1, 0, 0, 0, 0], [2200, 2, 0, 0, 0, 0]]}]
        self.assertEqual(self.window(rows), {"ts": 2200, "secs": 600})

    def test_the_newest_disk_decides(self):
        rows = [{"hist": [[1000, 1], [1060, 1]]}, {"hist": [[5000, 1], [5600, 1]]}]
        self.assertEqual(self.window(rows), {"ts": 5600, "secs": 600})

    def test_one_sample_or_none_says_nothing(self):
        self.assertIsNone(self.window([{"hist": [[1000, 1]]}, {"hist": []}, {}]))
        self.assertIsNone(self.window([]))
        self.assertIsNone(self.window(None))

    def test_a_sample_that_is_not_a_list_and_a_gap_that_is_not_positive_are_skipped(self):
        rows = [{"hist": ["x", 5, None, [1000, 1], [1000, 1]]}, {"hist": [[2000, 1], [1900, 1]]}]
        self.assertIsNone(self.window(rows))

    def test_the_table_says_what_the_figures_cover(self):
        body = APP[APP.index("function _renderHardwareSection("):]
        body = body[:body.index("// ── v3.14.0: GPUs")]
        self.assertIn("const ioWindow = _diskIoWindow(dio);", body)
        self.assertIn("Each figure is an average over the last", body)
        self.assertIn("timeAgoHtml(ioWindow.ts, { clamp: true })", body, "a time in markup goes through the one rule")


class TestTheTrendsRangeIsHonest(unittest.TestCase):

    def test_the_first_option_says_what_it_is(self):
        html = (ROOT / "server/html/index.html").read_text()
        i = html.index('id="trend-range"')
        select = html[i:html.index("</select>", i)]
        self.assertIn('<option value="raw">Daily samples (per mount)</option>', select)
        self.assertNotIn("raw, 24h", select)

    def test_the_label_is_translated_into_the_six_languages(self):
        import re
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        m = re.search(r'^    "Daily samples \(per mount\)": \{(.*)\},$', i18n, re.M)
        self.assertIsNotNone(m)
        for lang in ("fr", "de", "zh", "hi", "es", "ar"):
            self.assertIn(f'"{lang}": "', m.group(1))

    def test_a_narrow_recent_window_is_never_answered_with_the_daily_samples(self):
        script = (srcpin.js_function(APP, "_trendTierFor")
                  + "\nconst now = Date.now() / 1000;\nconsole.log(JSON.stringify([\n"
                  + "  _trendTierFor(now - 3 * 3600, now - 3600), _trendTierFor(now - 2 * 86400, now - 86400),\n"
                  + "  _trendTierFor(now - 20 * 86400, now - 10 * 86400), _trendTierFor(now - 400 * 86400, now - 300 * 86400)]));\n")
        self.assertEqual(run_js(script), ["fivemin", "fivemin", "hourly", "daily"])


class TestTheModuleIsWiredIn(unittest.TestCase):

    def test_the_lint_lists_carry_it(self):
        make = (ROOT / "Makefile").read_text()
        self.assertEqual(make.count("server/cgi-bin/disk_mounts.py"), 2, "both the lint and the type-check list")

    def test_it_stays_stdlib_only(self):
        import ast
        tree = ast.parse((_CGI / "disk_mounts.py").read_text())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual(names, {"math"})


if __name__ == "__main__":
    unittest.main()
