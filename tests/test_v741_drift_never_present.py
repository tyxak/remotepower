#!/usr/bin/env python3
"""v7.4.1, issue #38: a default watched file the host never had alerts as "removed".

`/etc/apt/sources.list` is in the default watch list. On a system that keeps its apt
sources only in `sources.list.d` the file has never existed, the agent reports it as
missing from the first heartbeat, and three reports later the file went dormant and
raised `Config drift on <host>: /etc/apt/sources.list removed`. Nothing was removed.

A file that goes missing after it was there is still a removal and still says so.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v741-drift-"))
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_spec = importlib.util.spec_from_file_location("api_v741_drift_never", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

PATH = "/etc/apt/sources.list"
GONE = {"hash": None, "size": None, "mtime": None, "exists": False}


def present(h="sha256:aaa", size=10):
    return {"hash": h, "size": size, "mtime": 1, "exists": True}


class _Base(unittest.TestCase):
    _NAMES = ("DATA_DIR", "DEVICES_FILE", "CONFIG_FILE", "DRIFT_STATE_FILE",
              "AUDIT_LOG_FILE", "WEBHOOK_LOG_FILE", "fire_webhook")

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in self._NAMES}
        t = Path(tempfile.mkdtemp(prefix="rp-v741-drift-t-"))
        api.DATA_DIR = t
        # a storage file's NAME is the key on the SQLite/Postgres backends
        for n in self._NAMES[1:6]:
            setattr(api, n, t / self._saved[n].name)
        self.calls = []
        api.fire_webhook = lambda ev, payload: self.calls.append((ev, payload))
        api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "vaultbox"}})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def report(self, info, path=PATH, times=1):
        for _ in range(times):
            api._ingest_drift_report("d1", {path: info})

    def rec(self, path=PATH):
        api._invalidate_load_cache(api.DRIFT_STATE_FILE)
        return api.load(api.DRIFT_STATE_FILE)["d1"]["files"][path]


class TestAFileThatWasNeverThere(_Base):

    def test_it_goes_dormant_and_says_nothing(self):
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER + 3)
        # the control: it DID reach dormancy, so the silence below is not "never got there"
        self.assertTrue(self.rec()["dormant"])
        self.assertEqual(self.calls, [], "a file the host never had raised a drift event")

    def test_the_alert_the_reporter_saw_is_the_one_that_is_gone(self):
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER + 1)
        titles = [api._alert_title(ev, dict(p, device_name="vaultbox")) for ev, p in self.calls]
        self.assertNotIn(f"Config drift on vaultbox: {PATH} removed", titles)

    def test_the_record_remembers_it_never_was(self):
        self.report(GONE)
        self.assertFalse(self.rec()["ever_present"])


class TestAFileThatWentAway(_Base):

    def test_a_removed_file_says_so_once(self):
        self.report(present())
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER + 3)
        self.assertEqual(len(self.calls), 1, self.calls)
        ev, payload = self.calls[0]
        self.assertEqual(ev, "drift_detected")
        self.assertIs(payload["exists"], False)
        self.assertEqual(api._alert_title(ev, dict(payload, device_name="vaultbox")),
                         f"Config drift on vaultbox: {PATH} removed")

    def test_a_file_that_appeared_later_and_then_went_away_says_so(self):
        self.report(GONE)                       # the baseline: not there
        self.report(present("sha256:new"))      # it appears
        self.calls.clear()
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER)
        self.assertEqual(len(self.calls), 1, "a file that was there and left is a removal")

    def test_a_file_too_big_to_hash_still_counts_as_having_been_there(self):
        self.report({"hash": None, "size": 9_999_999, "mtime": 1, "exists": True, "note": "too_large"})
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER)
        self.assertEqual(len(self.calls), 1)

    def test_a_file_reported_present_with_nothing_else_still_counts(self):
        # An agent that could neither hash nor size the file says only that it exists.
        self.report({"hash": None, "size": None, "mtime": None, "exists": True})
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER)
        self.assertEqual(len(self.calls), 1)

    def test_present_again_clears_dormancy_and_the_next_removal_is_reported(self):
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER + 1)   # dormant, silent
        self.report(present("sha256:back"))                            # revived
        self.assertFalse(self.rec()["dormant"])
        self.calls.clear()
        self.report(GONE, times=api.DRIFT_MISSING_DORMANT_AFTER)
        self.assertEqual(len(self.calls), 1)


class TestRecordsFromBeforeTheKeyExisted(_Base):
    """A state file written by an earlier release has no `ever_present`."""

    def seed(self, **fields):
        rec = {"current_hash": None, "current_size": None, "current_mtime": None,
               "baseline_hash": None, "baseline_size": None, "baseline_set_at": 1,
               "baseline_set_by": "agent", "first_seen": 1, "last_check": 1,
               "drift_count": 0, "exists": False, "history": [],
               "missing_streak": api.DRIFT_MISSING_DORMANT_AFTER - 1}
        rec.update(fields)
        api.save(api.DRIFT_STATE_FILE, {"d1": {"files": {PATH: rec}}})
        api._invalidate_load_cache(api.DRIFT_STATE_FILE)

    def test_no_hash_and_no_size_means_it_never_was(self):
        self.seed()
        self.report(GONE)
        self.assertTrue(self.rec()["dormant"])
        self.assertEqual(self.calls, [])

    def test_a_baseline_hash_means_it_was(self):
        self.seed(baseline_hash="sha256:old", current_hash="sha256:old")
        self.report(GONE)
        self.assertEqual(len(self.calls), 1)

    def test_a_baseline_size_alone_means_it_was(self):
        self.seed(baseline_size=4096)
        self.report(GONE)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
