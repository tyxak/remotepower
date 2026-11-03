#!/usr/bin/env python3
"""7.4.9: the ZFS cache (ARC) and the datasets that hold the most space.

The agent has reported a pool's health, its last scrub and its newest snapshot since 3.11.0, and nothing about what the pool's
memory does or which dataset holds the space. The Linux agent now reads the kernel's arcstats and `zfs list`; the server keeps
only numbers that are numbers and names that are ZFS names (zfs_stats.py), works out the hit ratio and the share of a quota that
is used once, and the Storage page and the host drawer show them.

What is real and what is not: this machine has no ZFS, so the arcstats and `zfs list` text below is written to the layout the
kernel module and the zfs command document (the arcstats file has two header lines and then `name type data` rows; `zfs list -H
-p` prints tab-separated, exact numbers with `0` for no quota). The reader is exercised on that text and nothing here proves
anything about a live pool. The agent code is run for real, with the two sources replaced.
"""
import importlib.machinery
import importlib.util
import json
import math
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-zfs-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import store_shapes  # noqa: E402
import zfs_stats as Z  # noqa: E402

ARCSTATS = """13 1 0x01 147 39984 8236450091 7249364092031
name                            type data
hits                            4    3000000000
misses                          4    250000000
demand_data_hits                4    2000000000
mru_size                        4    4294967296
mfu_size                        4    6442450944
size                            4    12884901888
c_min                           4    1073741824
c_max                           4    17179869184
l2_hits                         4    0
l2_misses                       4    0
l2_size                         4    0
memory_throttle_count           4    0
"""

TAB = "\t"
ZFS_LIST = "\n".join(TAB.join(r) for r in [
    ("tank", "4398046511104", "2199023255552", "98304", "0", "0", "1.00x"),
    ("tank/media", "3298534883328", "2199023255552", "3298534883328", "0", "107374182400", "1.02x"),
    ("tank/backups", "2020000000000", "180000000000", "1900000000000", "2199023255552", "687194767360", "1.61x"),
    ("tank/vol1", "107374182400", "2199023255552", "107374182400", "-", "0", "-"),
    ("tank/small", "1048576", "2199023255552", "1048576", "none", "0", "1.50x"),
]) + "\n"


def load_agent():
    loader = importlib.machinery.SourceFileLoader("agent_zfs_under_test", str(ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("agent_zfs_under_test", loader)
    agent = importlib.util.module_from_spec(spec)           # type: ignore[arg-type]
    loader.exec_module(agent)                                # type: ignore[union-attr]
    return agent


# ── the agent ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheAgentReadsIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()

    def test_arcstats(self):
        with mock.patch.object(self.agent, "_safe_read", lambda path, n=0: ARCSTATS):
            arc = self.agent.get_zfs_arc()
        self.assertEqual(arc["size"], 12884901888)
        self.assertEqual((arc["c_min"], arc["c_max"]), (1073741824, 17179869184))
        self.assertEqual((arc["hits"], arc["misses"]), (3000000000, 250000000))
        self.assertEqual((arc["mru_size"], arc["mfu_size"], arc["l2_size"]), (4294967296, 6442450944, 0))
        self.assertNotIn("memory_throttle_count", arc, "only the counters the server uses are sent")
        self.assertNotIn("demand_data_hits", arc)

    def test_no_zfs_is_none_not_an_empty_cache(self):
        for text in ("", None):
            with mock.patch.object(self.agent, "_safe_read", lambda path, n=0, t=text: t):
                self.assertIsNone(self.agent.get_zfs_arc())
        with mock.patch.object(self.agent, "_safe_read", lambda path, n=0: "13 1 0x01\nname type data\nhits 4 5\n"):
            self.assertIsNone(self.agent.get_zfs_arc(), "no size, no cache")

    def test_garbage_in_arcstats_is_skipped(self):
        junk = "13 1 0x01\nname type data\nsize 4 abc\nhits 4 -5\nmisses 4 7 8\nc_max 4 100\nsize 4 50\n"
        with mock.patch.object(self.agent, "_safe_read", lambda path, n=0: junk):
            arc = self.agent.get_zfs_arc()
        self.assertEqual(arc, {"c_max": 100, "size": 50})

    def test_the_file_is_read_through_host_path(self):
        # a containerized agent reads the host's /proc through the bind mount: _safe_read does that, so it is the one used
        src = (ROOT / "client" / "remotepower-agent.py").read_text()
        body = src[src.index("def get_zfs_arc"):src.index("def get_zfs_datasets")]
        self.assertIn("_safe_read('/proc/spl/kstat/zfs/arcstats'", body)
        self.assertNotIn("open(", body)

    def test_datasets(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(returncode=0, stdout=ZFS_LIST, stderr="")
        with mock.patch.object(self.agent, "_which", lambda p: "/usr/sbin/zfs"), mock.patch.object(self.agent.subprocess, "run", fake_run):
            ds = self.agent.get_zfs_datasets()
        self.assertEqual(calls[0][:5], ["zfs", "list", "-H", "-p", "-t"])
        self.assertEqual(ds["count"], 5)
        self.assertEqual([r["name"] for r in ds["rows"]], ["tank", "tank/media", "tank/backups", "tank/vol1", "tank/small"],
                         "sorted by used, biggest first")
        by = {r["name"]: r for r in ds["rows"]}
        self.assertEqual(by["tank/backups"]["quota"], 2199023255552)
        self.assertEqual(by["tank/media"]["quota"], 0, "no quota is 0")
        self.assertEqual(by["tank/vol1"]["quota"], 0, "a volume prints - for a quota")
        self.assertEqual(by["tank/small"]["quota"], 0, "none")
        self.assertEqual(by["tank/media"]["snap"], 107374182400)
        self.assertEqual((by["tank/media"]["ratio"], by["tank/vol1"]["ratio"]), (1.02, 1.0))

    def test_the_biggest_are_kept(self):
        many = "\n".join(TAB.join((f"p/d{i}", str(i * 1000), "5", "5", "0", "0", "1.00x")) for i in range(1, 80)) + "\n"
        with mock.patch.object(self.agent, "_which", lambda p: "zfs"), \
                mock.patch.object(self.agent.subprocess, "run", lambda *a, **k: mock.Mock(returncode=0, stdout=many)):
            ds = self.agent.get_zfs_datasets(limit=10)
        self.assertEqual(ds["count"], 79)
        self.assertEqual([r["used"] for r in ds["rows"]], [i * 1000 for i in range(79, 69, -1)])

    def test_no_zfs_command_or_a_failure_is_none(self):
        with mock.patch.object(self.agent, "_which", lambda p: None):
            self.assertIsNone(self.agent.get_zfs_datasets())
        with mock.patch.object(self.agent, "_which", lambda p: "zfs"), \
                mock.patch.object(self.agent.subprocess, "run", lambda *a, **k: mock.Mock(returncode=1, stdout=ZFS_LIST)):
            self.assertIsNone(self.agent.get_zfs_datasets())
        with mock.patch.object(self.agent, "_which", lambda p: "zfs"), \
                mock.patch.object(self.agent.subprocess, "run", lambda *a, **k: mock.Mock(returncode=0, stdout="short\tline\n")):
            self.assertIsNone(self.agent.get_zfs_datasets())

    def test_the_host_health_report_carries_both_on_a_zfs_host(self):
        def fake_run(cmd, **kw):
            out = ""
            if cmd[:2] == ["zpool", "list"]:
                out = "tank\tONLINE\t42%\n"
            elif cmd[:2] == ["zfs", "list"] and "snapshot" not in cmd:
                out = ZFS_LIST
            return mock.Mock(returncode=0 if out else 1, stdout=out, stderr="")
        real_which = self.agent._which
        with mock.patch.object(self.agent, "_which", lambda p: ("/x/" + p) if p in ("zpool", "zfs") else real_which(p)), \
                mock.patch.object(self.agent.subprocess, "run", fake_run), \
                mock.patch.object(self.agent, "_safe_read", lambda path, n=0: ARCSTATS if "arcstats" in path else ""):
            out = self.agent.get_host_health()
        self.assertEqual(out["zfs_arc"]["size"], 12884901888)
        self.assertEqual(out["zfs_datasets"]["count"], 5)
        self.assertEqual([p["name"] for p in out["storage_health"] if p["kind"] == "zfs"], ["tank"])

    def test_a_host_without_zfs_reports_neither(self):
        real_which = self.agent._which
        with mock.patch.object(self.agent, "_which", lambda p: None if p in ("zpool", "zfs") else real_which(p)), \
                mock.patch.object(self.agent, "_safe_read", lambda path, n=0: ""):
            out = self.agent.get_host_health()
        self.assertNotIn("zfs_arc", out)
        self.assertNotIn("zfs_datasets", out)

    def test_extensionless_agent_is_the_same_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


# ── the validator ─────────────────────────────────────────────────────────────────────────────────────────────────────
class TestArcValidation(unittest.TestCase):

    def test_numbers_and_the_two_derived_figures(self):
        a = Z.clean_arc({"size": 8, "c_min": 1, "c_max": 16, "hits": 90, "misses": 10, "l2_size": 0, "mru_size": 3, "mfu_size": 4})
        self.assertEqual(a["hit_ratio"], 0.9)
        self.assertEqual(a["fill_pct"], 50.0)
        self.assertEqual(a["size"], 8)

    def test_no_traffic_has_no_ratio_and_no_limit_has_no_fill(self):
        a = Z.clean_arc({"size": 8, "hits": 0, "misses": 0})
        self.assertNotIn("hit_ratio", a)
        self.assertNotIn("fill_pct", a)

    def test_fill_cannot_exceed_a_hundred(self):
        self.assertEqual(Z.clean_arc({"size": 20, "c_max": 10})["fill_pct"], 100.0)

    def test_only_numbers_that_are_numbers(self):
        bad = [True, False, "5", "abc", None, [], {}, float("nan"), float("inf"), -1, 10 ** 400, 2 ** 62, -(10 ** 400)]
        for v in bad:
            a = Z.clean_arc({"size": 1, "hits": v, "misses": v, "c_max": v, "l2_size": v})
            for k in ("hits", "misses", "c_max", "l2_size"):
                self.assertNotIn(k, a, (k, v))
            self.assertNotIn("hit_ratio", a)
            self.assertNotIn("fill_pct", a)
            json.dumps(a)

    def test_a_cache_without_a_size_is_nothing(self):
        for raw in ({}, {"hits": 5}, {"size": "9"}, {"size": True}, None, [], "x", 5, {"size": -1}):
            self.assertEqual(Z.clean_arc(raw), {}, repr(raw))

    def test_unknown_keys_are_dropped(self):
        a = Z.clean_arc({"size": 1, "evil": 5, "__proto__": 1, "hit_ratio": 99, "fill_pct": 99})
        self.assertEqual(set(a), {"size"}, "the two derived figures are never taken from the host")


class TestDatasetValidation(unittest.TestCase):

    def row(self, name="tank/a", used=100, **kw):
        return dict({"name": name, "used": used, "avail": 5, "refer": 5, "quota": 0, "snap": 0, "ratio": 1.5}, **kw)

    def test_sorted_by_used_and_counted(self):
        d = Z.clean_datasets({"count": 12, "rows": [self.row("a", 1), self.row("b", 9), self.row("c", 5)]})
        self.assertEqual([r["name"] for r in d["rows"]], ["b", "c", "a"])
        self.assertEqual(d["count"], 12)

    def test_the_count_is_never_below_what_is_listed(self):
        d = Z.clean_datasets({"count": 1, "rows": [self.row("a", 1), self.row("b", 2)]})
        self.assertEqual(d["count"], 2)
        self.assertEqual(Z.clean_datasets({"rows": [self.row()]})["count"], 1)

    def test_the_quota_share(self):
        d = Z.clean_datasets({"rows": [self.row("q", 94, quota=100), self.row("n", 50, quota=0)]})
        by = {r["name"]: r for r in d["rows"]}
        self.assertEqual(by["q"]["quota_pct"], 94.0)
        self.assertIsNone(by["n"]["quota_pct"])

    def test_the_list_is_capped_and_keeps_the_biggest(self):
        d = Z.clean_datasets({"count": 500, "rows": [self.row(f"p/d{i}", i) for i in range(1, 200)]})
        self.assertEqual(len(d["rows"]), Z.MAX_DATASETS)
        # the agent sends its biggest 30; a report with more is looked at only up to four times what is kept, so the work is bounded
        self.assertEqual(d["rows"][0]["used"], Z.MAX_DATASETS * 4)

    def test_names_must_be_zfs_names(self):
        bad = ["", "/x", "tank/", "tank//x", "<img src=x>", "a" * 300, "tank@snap", "tank#bm", "tank/ev'il", "tank\n", "tank;rm",
               ".hidden", "-x", 5, None, ["a"], {"a": 1}, "tank/" + "x/" * 20]
        good = ["tank", "tank/media", "rpool/ROOT/ubuntu_a1b2c3", "pool-1/data.set", "tank/with space", "a:b/c_d"]
        d = Z.clean_datasets({"rows": [self.row(n, 10) for n in bad] + [self.row(n, 5) for n in good]})
        self.assertEqual(sorted(r["name"] for r in d["rows"]), sorted(good))

    def test_numbers_are_numbers(self):
        for v in (True, "5", None, [], float("nan"), float("inf"), -1, 10 ** 400):
            d = Z.clean_datasets({"rows": [self.row("x", 5, avail=v, refer=v, quota=v, snap=v, ratio=v)]})
            r = d["rows"][0]
            self.assertEqual((r["avail"], r["refer"], r["quota"], r["snap"]), (0, 0, 0, 0), repr(v))
            self.assertEqual(r["ratio"], 1.0, repr(v))
            self.assertIsNone(r["quota_pct"])
        self.assertEqual(Z.clean_datasets({"rows": [self.row("x", "5")]}), {}, "used that is not a number drops the row")
        self.assertEqual(Z.clean_datasets({"rows": [self.row("x", True)]}), {})

    def test_nothing_usable_is_nothing(self):
        for raw in (None, [], "x", 5, {}, {"rows": None}, {"rows": []}, {"rows": ["a", 5, None]}, {"count": 5}):
            self.assertEqual(Z.clean_datasets(raw), {}, repr(raw))

    def test_random_input_never_raises(self):
        rnd = random.Random(11)
        vals = [None, True, 0, -1, 1.5, float("nan"), "x", "tank", "tank/a", [], {}, [1], {"a": 1}, 10 ** 30, "\x00", "é"]
        for _ in range(500):
            raw = {"count": rnd.choice(vals), "rows": [{k: rnd.choice(vals) for k in ("name", "used", "avail", "refer", "quota", "snap", "ratio")}
                                                        for _ in range(rnd.randint(0, 5))] if rnd.random() < 0.9 else rnd.choice(vals)}
            out = Z.clean_datasets(raw)
            json.dumps(out)
            for r in out.get("rows", []):
                self.assertTrue(all(math.isfinite(r[k]) for k in ("used", "avail", "refer", "quota", "snap", "ratio")))


# ── the server ────────────────────────────────────────────────────────────────────────────────────────────────────────
class _Hb(_Base):
    STORES = _Base.STORES + ("CMD_OUTPUT_FILE", "CONTAINERS_FILE", "ALERTS_FILE", "POSTURE_STATE_FILE", "HARDWARE_FILE")

    def zfs_host(self, dev_id, tenant, arc=True, ds=True):
        devs = api.load(api.DEVICES_FILE)
        si = {"storage_health": [{"name": "tank", "kind": "zfs", "state": "ONLINE", "capacity": 40}]}
        if arc:
            si["zfs_arc"] = Z.clean_arc({"size": 8, "c_max": 16, "hits": 90, "misses": 10})
        if ds:
            si["zfs_datasets"] = Z.clean_datasets({"count": 3, "rows": [
                {"name": f"{dev_id}/data", "used": 50, "avail": 5, "refer": 5, "quota": 100, "snap": 2, "ratio": 1.4},
                {"name": f"{dev_id}/small", "used": 5, "avail": 5, "refer": 5, "quota": 0, "snap": 0, "ratio": 1.0}]})
        devs[dev_id] = {"name": dev_id + "-host", "tenant": tenant, "token_hash": "x", "last_seen": int(time.time()), "sysinfo": si}
        api.save(api.DEVICES_FILE, devs)

    def overview(self, who):
        return self.call(api.handle_storage_overview, m="GET", who=who)


class TestTheStoragePage(_Hb):

    def setUp(self):
        super().setUp()
        self.zfs_host("zb", "tenantB")
        self.zfs_host("zc", "tenantC")
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE), bviewer={"role": "viewer", "tenant_id": "tenantB"}))
        api._LOAD_CACHE.clear()

    def test_it_answers_with_the_cache_and_the_datasets(self):
        st, d = self.overview("badmin")
        self.assertEqual(st, 200)
        self.assertEqual([r["device_id"] for r in d["arc"]], ["zb"])
        arc = d["arc"][0]
        self.assertEqual((arc["hit_ratio"], arc["fill_pct"], arc["size"]), (0.9, 50.0, 8))
        self.assertEqual([r["name"] for r in d["datasets"]], ["zb/data", "zb/small"])
        self.assertEqual(d["datasets"][0]["quota_pct"], 50.0)
        self.assertEqual(d["count"], 1, "the pools list is as before")

    def test_a_tenant_sees_only_its_own_hosts(self):
        for who in ("badmin", "bviewer"):
            st, d = self.overview(who)
            self.assertEqual({r["device_id"] for r in d["arc"]}, {"zb"}, who)
            self.assertEqual({r["device_id"] for r in d["datasets"]}, {"zb"}, who)
            self.assertNotIn("zc", json.dumps(d), who)
        st, d = self.overview("cadmin")
        self.assertEqual({r["device_id"] for r in d["arc"]}, {"zc"})
        self.assertNotIn("zb", json.dumps(d))

    def test_the_platform_operator_sees_every_host(self):
        st, d = self.overview("platform")
        self.assertEqual({r["device_id"] for r in d["arc"]}, {"zb", "zc"})

    def test_a_host_without_zfs_adds_nothing(self):
        devs = api.load(api.DEVICES_FILE)
        devs["plain"] = {"name": "plain", "tenant": "tenantB", "token_hash": "x", "sysinfo": {"storage_health": [
            {"name": "md0", "kind": "mdraid", "state": "active"}]}}
        api.save(api.DEVICES_FILE, devs)
        st, d = self.overview("badmin")
        self.assertEqual({r["device_id"] for r in d["arc"]}, {"zb"})
        self.assertEqual(d["count"], 2)

    def test_datasets_are_capped_at_eight_a_host(self):
        devs = api.load(api.DEVICES_FILE)
        devs["zb"]["sysinfo"]["zfs_datasets"] = Z.clean_datasets({"rows": [
            {"name": f"zb/d{i}", "used": i, "avail": 1, "refer": 1, "quota": 0, "snap": 0, "ratio": 1.0} for i in range(1, 30)]})
        api.save(api.DEVICES_FILE, devs)
        st, d = self.overview("badmin")
        self.assertEqual(len(d["datasets"]), 8)
        self.assertEqual(d["datasets"][0]["used"], 29)

    def test_a_hand_edited_store_does_not_break_the_page(self):
        devs = api.load(api.DEVICES_FILE)
        devs["zb"]["sysinfo"]["zfs_arc"] = "garbage"
        devs["zb"]["sysinfo"]["zfs_datasets"] = {"rows": ["x", 5, None, {"name": "ok", "used": "12"}, {"name": 7, "used": 1}]}
        api.save(api.DEVICES_FILE, devs)
        st, d = self.overview("badmin")
        self.assertEqual(st, 200, d)
        self.assertTrue(all(isinstance(r["name"], str) for r in d["datasets"]), "a number where text goes is read as its text")
        self.assertIn("ok", [r["name"] for r in d["datasets"]])

    def test_the_viewer_may_read_it(self):
        self.assertEqual(self.overview("bviewer")[0], 200)
        self.assertEqual(self.overview(None)[0], 401)


class TestWhatTheHeartbeatKeeps(unittest.TestCase):
    """The whitelist in handle_heartbeat, through the real handler with the agent's own request body."""

    DEV = "z1"

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond",)}
        self._env = dict(os.environ)
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.CONFIG_FILE, {}),
                         (api.MAINT_FILE, {"windows": []}), (api.MAINT_SUPPRESS_LOG, {"entries": []}),
                         (api.CMD_OUTPUT_FILE, {})):
            api.save(f, empty)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "zbox", "hostname": "zbox", "token": "tok", "last_seen": now,
                                                "enrolled": now, "tags": [], "group": "", "sysinfo": {}, "monitored": True}})
        api._LOAD_CACHE.clear()

        class _Captured(SystemExit):
            def __init__(self, status, body):
                super().__init__(0)
                self.status, self.body = status, body
        self.Captured = _Captured

        def fake(status, data):
            raise _Captured(status, data)
        api.respond = fake

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def beat(self, sysinfo):
        import io
        raw = json.dumps({"device_id": self.DEV, "token": "tok", "sysinfo": sysinfo}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)

        class _Stdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except self.Captured:
            pass
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(self.DEV, {}).get("sysinfo") or {}

    def test_both_are_kept_and_the_derived_figures_are_the_servers(self):
        si = self.beat({"storage_health": [{"name": "tank", "kind": "zfs", "state": "ONLINE", "capacity": 5}],
                        "zfs_arc": {"size": 8, "c_max": 16, "hits": 90, "misses": 10, "hit_ratio": 5.0, "fill_pct": 999},
                        "zfs_datasets": {"count": 2, "rows": [{"name": "tank/a", "used": 50, "avail": 5, "refer": 5, "quota": 100,
                                                               "snap": 1, "ratio": 1.5}]}})
        self.assertEqual((si["zfs_arc"]["hit_ratio"], si["zfs_arc"]["fill_pct"]), (0.9, 50.0), "never taken from the host")
        self.assertEqual(si["zfs_datasets"]["rows"][0]["quota_pct"], 50.0)

    def test_it_is_kept_on_a_host_that_reports_no_pool(self):
        si = self.beat({"zfs_arc": {"size": 8, "c_max": 16}})
        self.assertEqual(si["zfs_arc"]["size"], 8)

    def test_hostile_values_do_not_reach_the_store(self):
        si = self.beat({"zfs_arc": {"size": 8, "hits": "9", "misses": True, "c_max": 10 ** 400, "l2_size": float("inf")},
                        "zfs_datasets": {"count": 10 ** 400, "rows": [
                            {"name": "<img src=x onerror=alert(1)>", "used": 5},
                            {"name": "tank/ok", "used": 5, "avail": "x", "quota": -3, "ratio": float("nan")}]}})
        self.assertEqual(si["zfs_arc"], {"size": 8})
        rows = si["zfs_datasets"]["rows"]
        self.assertEqual([r["name"] for r in rows], ["tank/ok"])
        self.assertEqual((rows[0]["avail"], rows[0]["quota"], rows[0]["ratio"]), (0, 0, 1.0))
        self.assertNotIn("<", json.dumps(si))

    def test_a_report_that_stops_sending_it_does_not_keep_the_old_one(self):
        self.beat({"zfs_arc": {"size": 8}})
        si = self.beat({"storage_health": [{"name": "tank", "kind": "zfs", "state": "ONLINE"}]})
        self.assertNotIn("zfs_arc", si, "a pool that left, or a host that no longer has ZFS, does not show a stale cache")


class TestRegistration(unittest.TestCase):

    def test_the_shape_registry_knows_the_new_fields(self):
        si = {"zfs_arc": 5, "zfs_datasets": {"count": "3", "rows": [{"name": "a", "used": "12", "quota": None}, {"used": 5}, "x"]}}
        fixed = store_shapes.normalize("devices.json", {"h": {"name": "h", "sysinfo": si}})
        got = fixed["h"]["sysinfo"]
        self.assertNotEqual(got.get("zfs_arc"), 5, "a cache that is not a map is repaired")
        self.assertEqual([r["name"] for r in got["zfs_datasets"]["rows"]], ["a"], "a row without a name is not a row")
        self.assertEqual(got["zfs_datasets"]["rows"][0]["used"], 12, "text that holds a number is read as the number")

    def test_the_module_is_in_the_lint_and_type_baselines(self):
        self.assertEqual((ROOT / "Makefile").read_text().count("server/cgi-bin/zfs_stats.py"), 2)


if __name__ == "__main__":
    unittest.main()
