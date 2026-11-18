#!/usr/bin/env python3
"""What the review of the Windows host items found (the update search, the build, the shares and the TPM), closed at the cause.

Each class below is one finding of that review. Every guard in it was watched failing against the old code: the mutations that were
applied one at a time (with the anchor checked first, and a green control before) are listed in the commit that added the class.

  * A host read on its own by a SQL backend skipped the shape registry that every other read of the store goes through.
  * (later commits add the stored build, the multi-session edition, the count a failed search leaves, the corpus and the time cell.)

The Windows agent cannot run here; its parsing is driven through the stand-ins of win_host_support.py.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="rp-winreview-")
os.environ.setdefault("RP_DATA_DIR", _TMP)

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_CGI = _ROOT / "server" / "cgi-bin"
for _p in (str(_CGI), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import win_host_support as S  # noqa: E402

import api  # noqa: E402
import storage  # noqa: E402


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


# ── a host read on its own ───────────────────────────────────────────────────────────────────────────────────────────────
class _OnSqlite(unittest.TestCase):
    """Runs against the SQLite backend whatever backend the gate runs: the marker of a scratch directory selects it, the way
    test_storage_backend.py does, and the environment variable that would override the marker is put back afterwards."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-winreview-sql-"))
        storage.close_connection()
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        self._files = {}
        for attr in ("DEVICES_FILE", "STORAGE_MARKER_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.dir / Path(getattr(api, attr)).name)
        storage.write_marker(self.dir, "sqlite")
        self._env_backend = os.environ.pop("RP_STORAGE_BACKEND", None)
        self.assertEqual(api._storage_backend(), "sqlite", "control: this class runs the SQL path, not the JSON one")

    def tearDown(self):
        for attr, value in self._files.items():
            setattr(api, attr, value)
        if self._env_backend is not None:
            os.environ["RP_STORAGE_BACKEND"] = self._env_backend
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        storage.close_connection()
        shutil.rmtree(self.dir, ignore_errors=True)

    def host(self, **over):
        now = int(time.time())
        return dict({"name": "h1", "hostname": "h1", "os": "Windows 11", "token": "t", "last_seen": now, "enrolled": now, "tags": [],
                     "group": "", "agentless": False, "sysinfo": {"uptime": "1d"}}, **over)

    def raw_row(self, dev_id, doc):
        """A row written the way a hand edit or a restore from a mixed-up backup would leave it: straight into the table."""
        import json
        conn = storage._connect(self.dir)
        conn.execute("INSERT OR REPLACE INTO devices(id, doc, last_seen) VALUES(?,?,?)", (dev_id, json.dumps(doc), 1))
        conn.commit()
        api._LOAD_CACHE.clear()


class TestAHostReadOnItsOwnIsRepairedLikeTheWholeStore(_OnSqlite):
    """The whole store is repaired where it is read (api._load_uncached, and the locked read of the SQL backends). A host read on its own
    (device_get, and the transaction of _DeviceUpdate) was not: a text where `sysinfo.packages` is a map answered 500 on the Checks page of
    the host on SQLite and PostgreSQL, and 200 on JSON."""

    HOSTILE = {
        "packages as text": {"sysinfo": {"packages": "x", "uptime": "1d"}},
        "the search as a list": {"sysinfo": {"wu_search": [1, 2], "uptime": "1d"}},
        "tags as text and a stamp as text": {"tags": "oops", "last_seen": "17", "sysinfo": {"uptime": "1d"}},
        "the name as a list": {"name": ["x"], "sysinfo": {"uptime": "1d"}},
    }

    def test_every_way_to_read_one_host_gives_the_row_the_whole_store_gives(self):
        for label, over in self.HOSTILE.items():
            with self.subTest(row=label):
                api.save(api.DEVICES_FILE, {"h1": self.host(**over)})
                api._LOAD_CACHE.clear()
                whole = api.load(api.DEVICES_FILE)["h1"]
                api._LOAD_CACHE.clear()
                single = api.device_get("h1")
                self.assertEqual(single, whole, "the single-row read left a field as it was stored")
                api._LOAD_CACHE.clear()
                with api._DeviceUpdate("h1") as devices:
                    in_transaction = devices["h1"]
                self.assertEqual(in_transaction, whole, "the transaction of one host yielded the stored row")

    def test_the_repair_is_real_and_not_a_comparison_of_two_unrepaired_rows(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        stored = storage.device_get(api.DEVICES_FILE, "h1")
        self.assertEqual(stored["sysinfo"]["packages"], "x", "control: the stored row really holds the text")
        self.assertEqual(api.device_get("h1")["sysinfo"]["packages"], {})

    def test_the_checks_page_of_the_host_answers(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        status, body = S.call(api, api.handle_device_checks, "h1")
        self.assertEqual(status, 200, body)

    def test_the_transaction_stores_the_repaired_row_when_it_ends_cleanly(self):
        api.save(api.DEVICES_FILE, {"h1": self.host(tags="oops", sysinfo={"packages": "x", "uptime": "1d"})})
        api._LOAD_CACHE.clear()
        with api._DeviceUpdate("h1") as devices:
            devices["h1"]["group"] = "edited"
        stored = storage.device_get(api.DEVICES_FILE, "h1")
        self.assertEqual((stored["tags"], stored["sysinfo"]["packages"], stored["group"]), ([], {}, "edited"))

    def test_a_row_the_registry_leaves_out_is_a_host_that_is_not_there(self):
        self.raw_row("h2", "not a map")
        self.assertIsNone(api.device_get("h2"))
        self.assertEqual(api.device_get("h2", {"fallback": 1}), {"fallback": 1})
        with api._DeviceUpdate("h2") as devices:
            self.assertEqual(devices, {}, "the transaction yielded a row that is not a map")
        self.assertEqual(storage.device_get(api.DEVICES_FILE, "h2"), "not a map", "nothing was written for a row the registry left out")

    def test_a_host_that_is_not_stored_is_still_the_default(self):
        self.assertIsNone(api.device_get("nobody"))
        self.assertEqual(api.device_get("nobody", {"d": 1}), {"d": 1})
        with api._DeviceUpdate("nobody") as devices:
            self.assertEqual(devices, {})

    def test_a_clean_row_comes_back_unchanged(self):
        row = self.host(tags=["a", "b"], sysinfo={"uptime": "1d", "packages": {"manager": "apt", "upgradable": 2}})
        api.save(api.DEVICES_FILE, {"h1": row})
        api._LOAD_CACHE.clear()
        self.assertEqual(api.device_get("h1"), api.load(api.DEVICES_FILE)["h1"])
        self.assertEqual(api.device_get("h1")["sysinfo"]["packages"], {"manager": "apt", "upgradable": 2})


class TestTheRepairIsTheSameOnJson(unittest.TestCase):
    """The page walk of test_windows_shares_tpm.py runs on whichever backend the gate runs. This is the JSON side of the same property, so
    a plain `make test` holds both directions."""

    def test_the_json_backend_gives_the_same_repaired_row(self):
        saved_cache = api._BACKEND_CACHE
        saved_env = os.environ.pop("RP_STORAGE_BACKEND", None)
        saved_file = api.DEVICES_FILE
        scratch = Path(tempfile.mkdtemp(prefix="rp-winreview-json-"))
        try:
            api._BACKEND_CACHE = "json"
            api.DEVICES_FILE = scratch / "devices.json"
            api._LOAD_CACHE.clear()
            self.assertIsNone(api._dbmod(), "control: this is the JSON path")
            now = int(time.time())
            api.save(api.DEVICES_FILE, {"h1": {"name": "h1", "os": "Windows 11", "token": "t", "last_seen": now, "tags": "oops",
                                               "sysinfo": {"packages": "x"}}})
            api._LOAD_CACHE.clear()
            row = api.device_get("h1")
            self.assertEqual((row["tags"], row["sysinfo"]["packages"]), ([], {}))
        finally:
            api._BACKEND_CACHE = saved_cache
            if saved_env is not None:
                os.environ["RP_STORAGE_BACKEND"] = saved_env
            api.DEVICES_FILE = saved_file
            api._LOAD_CACHE.clear()
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
