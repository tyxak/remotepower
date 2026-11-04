#!/usr/bin/env python3
"""v7.5.0 (signals matrix G22): the AI index knows a host's ZFS cache and datasets, and its Docker disk use.

The Storage page shows the ZFS cache and the datasets that hold the most space, and the Containers page shows `docker system df`.
The AI index had neither, so "which dataset is nearly at its quota?" and "which host is filling up with images?" had nothing to
answer from. They are chunks of the host's storage and Docker facets now, built for the index and not for a reader: sizes in two
significant figures, the hit ratio in whole percent, a quota share in steps of five and the date of the newest snapshot instead of its
epoch, so a chunk is not rewritten (and, with an embedding provider, paid for again) by a few megabytes or by an hourly snapshot.

Two controls on the way: what the index must NOT do (a hostile figure is left out, a dataset's growth by a megabyte changes nothing),
and the real path, which builds the corpus from the stores the ingest writes (`_rag_build_corpus`) and not from a dict a test made up.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-rag-"))
sys.path.insert(0, str(_CGI))
import rag_index  # noqa: E402

GIB = 1024 ** 3
TIB = 1024 ** 4

ARC = {"size": 14 * GIB, "c_min": GIB, "c_max": 16 * GIB, "hits": 900, "misses": 100, "hit_ratio": 0.9, "fill_pct": 87.5}


def dataset(name, used, quota=0, snap=0, pct=None):
    return {"name": name, "used": int(used), "avail": 2 * TIB, "refer": int(used * 0.9), "quota": int(quota), "snap": int(snap),
            "ratio": 1.1, "quota_pct": pct}


def storage_chunk(si, devs=None):
    dev = {"id": "d1", "name": "nas", "last_seen": 1, "sysinfo": si}
    docs = rag_index.build_live_state_corpus([dev], facets=devs or {}, now=1)
    got = [d for d in docs if d["id"] == "live/d1#storage"]
    return got[0]["text"] if got else None


class TestZfsInTheStorageChunk(unittest.TestCase):

    def si(self, **kw):
        base = {"storage_health": [{"name": "tank", "kind": "zfs", "state": "ONLINE", "capacity": 80, "last_snapshot": 1_800_000_000}],
                "zfs_arc": dict(ARC),
                "zfs_datasets": {"count": 2, "rows": [dataset("tank/backups", 1.88 * TIB, 2 * TIB, 640 * GIB, 94.0),
                                                      dataset("tank/media", 5.4 * TIB)]}}
        base.update(kw)
        return base

    def test_the_cache_and_the_datasets_are_in_it(self):
        text = storage_chunk(self.si())
        self.assertIn("ZFS cache (ARC): 90% hit ratio, limit 16 GiB", text)
        self.assertIn("dataset tank/backups: 1.9 TiB used — of a 2.0 TiB quota (95% of it) — snapshots hold 640 GiB", text)
        self.assertIn("dataset tank/media: 5.4 TiB used — no quota", text)
        self.assertIn("ZFS cache and datasets", text, "the chunk says what it holds, so a question about them retrieves it")

    def test_a_host_with_datasets_and_no_pool_rows_still_gets_the_chunk(self):
        si = self.si()
        del si["storage_health"]
        self.assertIn("dataset tank/media", storage_chunk(si))

    def test_a_host_without_zfs_is_unchanged(self):
        text = storage_chunk({"storage_health": [{"name": "md0", "kind": "mdadm", "state": "active", "capacity": 40}]})
        self.assertIn("md0 — mdadm", text)
        self.assertNotIn("ZFS cache (ARC)", text)
        self.assertNotIn("dataset ", text)
        self.assertIsNone(storage_chunk({}))

    def test_the_newest_snapshot_is_a_date(self):
        text = storage_chunk(self.si())
        self.assertIn("last snapshot 2027-01-15", text)
        self.assertNotIn("1800000000", text)
        none = storage_chunk(self.si(storage_health=[{"name": "tank", "kind": "zfs", "state": "ONLINE", "last_snapshot": 0}]))
        self.assertIn("no snapshots", none)

    def test_twelve_datasets_at_most(self):
        rows = [dataset(f"tank/d{i:02d}", GIB * (i + 1)) for i in range(30)]
        text = storage_chunk(self.si(zfs_datasets={"count": 30, "rows": rows}))
        self.assertEqual(text.count("dataset tank/"), 12)

    def test_a_dataset_growing_by_a_megabyte_does_not_rewrite_the_chunk(self):
        a = storage_chunk(self.si())
        grown = self.si(zfs_datasets={"count": 2, "rows": [dataset("tank/backups", 1.88 * TIB + 1024 ** 2, 2 * TIB, 640 * GIB, 94.0001),
                                                          dataset("tank/media", 5.4 * TIB + 3 * 1024 ** 2)]})
        self.assertEqual(a, storage_chunk(grown))
        # control: the same dataset growing by a tenth of its size does
        big = self.si(zfs_datasets={"count": 2, "rows": [dataset("tank/backups", 1.88 * TIB * 1.1, 2 * TIB, 640 * GIB, 94.0),
                                                        dataset("tank/media", 5.4 * TIB)]})
        self.assertNotEqual(a, storage_chunk(big))

    def test_an_hourly_snapshot_does_not_rewrite_the_chunk_within_a_day(self):
        a = storage_chunk(self.si(storage_health=[{"name": "tank", "kind": "zfs", "state": "ONLINE", "last_snapshot": 1_800_000_000}]))
        b = storage_chunk(self.si(storage_health=[{"name": "tank", "kind": "zfs", "state": "ONLINE", "last_snapshot": 1_800_003_600}]))
        c = storage_chunk(self.si(storage_health=[{"name": "tank", "kind": "zfs", "state": "ONLINE", "last_snapshot": 1_800_000_000 + 2 * 86400}]))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_a_hostile_figure_is_left_out_and_nothing_is_raised(self):
        bad = float("nan"), float("inf"), -5, True, "9", None, [], {}, 10 ** 400
        for v in bad:
            with self.subTest(v=repr(v)[:30]):
                si = self.si(zfs_arc=dict(ARC, hit_ratio=v, c_max=v),
                             zfs_datasets={"count": 1, "rows": [dataset("tank/x", GIB, 0, 0, None) | {"used": v, "quota": v, "snap": v, "quota_pct": v}]})
                text = storage_chunk(si)
                self.assertIsNotNone(text)
                self.assertNotIn("nan", text.lower().replace("snapshots", "").replace("unknown", ""))
                self.assertNotIn("inf ", text.lower())
                self.assertNotIn("dataset tank/x", text, "a dataset with no usable size is left out")
                self.assertNotIn("ZFS cache (ARC)", text, "a hit ratio that is not a ratio is left out")

    def test_a_store_of_the_wrong_kind_is_ignored(self):
        for arc, ds in (("x", "y"), ([1], [2]), (None, {"rows": "no"}), (0, {"rows": [None, 7, "a", {"name": ""}]}), (True, {"rows": None})):
            with self.subTest(arc=arc, ds=ds):
                text = storage_chunk(self.si(zfs_arc=arc, zfs_datasets=ds))
                self.assertIsNotNone(text)
                self.assertNotIn("ZFS cache (ARC)", text)
                self.assertNotIn("dataset ", text)


class TestDockerDiskUse(unittest.TestCase):

    DF = {"images": {"size": "12.3GB", "reclaimable": "4.1GB (33%)", "total": "31", "active": "9"},
          "containers": {"size": "210MB", "reclaimable": "0B", "total": "12", "active": "9"},
          "build_cache": {"size": "", "reclaimable": "", "total": "", "active": ""},
          "volumes": [{"name": f"vol{i}", "size": f"{9 - i}GB", "links": 1} for i in range(8)]}

    def test_one_line_per_kind_and_the_biggest_volumes(self):
        got = rag_index.docker_df_facet(self.DF)
        self.assertEqual(got["images"], "12.3GB in use, 4.1GB (33%) reclaimable, 31 in all, 9 active")
        self.assertEqual(got["containers"], "210MB in use, 0B reclaimable, 12 in all, 9 active")
        self.assertNotIn("build_cache", got, "a kind with no size says nothing")
        self.assertEqual(got["largest volumes"], "vol0 9GB, vol1 8GB, vol2 7GB, vol3 6GB, vol4 5GB and 3 more")

    def test_junk_is_nothing(self):
        for v in (None, "x", [], {}, {"images": "no"}, {"volumes": "no"}, {"volumes": [None, 3, {"name": ""}]}):
            with self.subTest(v=v):
                self.assertIsNone(rag_index.docker_df_facet(v))


class TestThroughTheRealPath(unittest.TestCase):
    """_rag_build_corpus reads the stores the ingest writes; a facet nobody passes it is not in the index."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("api_v750_rag", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        self.d = Path(tempfile.mkdtemp(prefix="rp-v750-rag-d-"))
        self._saved = {n: getattr(api, n) for n in ("DEVICES_FILE", "CONTAINERS_FILE", "HARDWARE_FILE", "CVE_FINDINGS_FILE", "SNMP_DATA_FILE",
                                                    "ALERTS_FILE", "SERVICES_FILE")}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)    # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        for n in ("CVE_FINDINGS_FILE", "SNMP_DATA_FILE", "ALERTS_FILE", "SERVICES_FILE", "HARDWARE_FILE"):
            api.save(getattr(api, n), {})

    def _restore(self):
        for n, v in self._saved.items():
            setattr(self.api, n, v)
        self.api._LOAD_CACHE.clear()

    def corpus(self, device, containers=None):
        api = self.api
        api.save(api.DEVICES_FILE, {"d1": device})
        api.save(api.CONTAINERS_FILE, containers or {})
        api._LOAD_CACHE.clear()
        return {d["id"]: d["text"] for d in api._rag_build_corpus({"rag": {"sources": {"live_state": True}}})}

    def test_docker_disk_use_reaches_the_index(self):
        dev = {"id": "d1", "name": "dock", "last_seen": int(time.time()), "sysinfo": {}}
        docs = self.corpus(dev, {"d1": {"ts": int(time.time()), "items": [{"name": "web", "image": "nginx", "status": "Up", "health": "healthy"}],
                                        "df": TestDockerDiskUse.DF}})
        self.assertIn("live/d1#docker_disk", docs)
        self.assertIn("images: 12.3GB in use, 4.1GB (33%) reclaimable", docs["live/d1#docker_disk"])
        self.assertIn("live/d1#containers", docs)

    def test_a_host_that_reported_no_df_has_no_such_chunk(self):
        dev = {"id": "d1", "name": "dock", "last_seen": int(time.time()), "sysinfo": {}}
        docs = self.corpus(dev, {"d1": {"ts": int(time.time()), "items": [{"name": "web", "image": "nginx", "status": "Up"}]}})
        self.assertNotIn("live/d1#docker_disk", docs)
        self.assertIn("live/d1#containers", docs)

    def test_zfs_reaches_the_index_from_the_device_record(self):
        si = {"storage_health": [{"name": "tank", "kind": "zfs", "state": "DEGRADED", "capacity": 91}], "zfs_arc": dict(ARC),
              "zfs_datasets": {"count": 1, "rows": [dataset("tank/vm", 1.1 * TIB, 0, 310 * GIB)]}}
        docs = self.corpus({"id": "d1", "name": "nas", "last_seen": int(time.time()), "sysinfo": si})
        self.assertIn("(DEGRADED)", docs["live/d1#storage"])
        self.assertIn("dataset tank/vm: 1.1 TiB used — no quota — snapshots hold 310 GiB", docs["live/d1#storage"])


if __name__ == "__main__":
    unittest.main()
