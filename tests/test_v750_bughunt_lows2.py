#!/usr/bin/env python3
"""The rest of the Low findings of the 7.5.0 bug hunt (the first batch is test_v750_bughunt_lows).

BH-7   Two hosts reporting probe results in the same moment each read the whole results document and wrote it back; the second
       write took the first host's result with it. Held with threads against the real ingest, because a forced interleaving
       cannot be written against code that now holds a lock.
BH-10  A recovery notice said a container "passes its health check again" when it had stopped, and "back under its CPU line" when
       the line was switched off. The payload carries why it closed now, and the message says it.
BH-11  The activity-feed copy of an event dropped the state of a business service, its parts, an unhealthy container's output.
BH-12  A request that names no user took an alert's assignment back, a viewer's included.
BH-14  numeric text of 4,301+ digits made the store repair give up on the whole store; two stores of 7.4.3 were not registered.
BH-15  notify._num raised on an infinite or huge value.
BH-16  a time period name was not stable under a second clean, overlapping ranges counted their minutes twice, a ZFS ratio of
       0.0039 became 0.0, and two business-service parts could share a key.
BH-19  the business service cadence gate copied two stores before it looked at the time.
"""
import ast
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-bhl2-"))
from test_v749_alert_assignment import _Assign, api as tapi  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import bizsvc  # noqa: E402
import notify  # noqa: E402
import store_shapes  # noqa: E402
import time_periods as tp  # noqa: E402
import zfs_stats  # noqa: E402


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-bhl2-api-")
    spec = importlib.util.spec_from_file_location("api_v750_bhl2", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── BH-7 ─────────────────────────────────────────────────────────────────────

class TestProbeResultsAreNotLost(unittest.TestCase):

    HOSTS, ROUNDS = 12, 15

    def test_twelve_hosts_reporting_at_once_keep_every_result(self):
        a = _fresh_api()
        monitors = [{"label": f"m{h}_{r}", "via_host": f"h{h}", "type": "ping", "target": "10.0.0.1"}
                    for h in range(self.HOSTS) for r in range(self.ROUNDS)]
        a.save(a.CONFIG_FILE, {"monitors": monitors})
        a._invalidate_load_cache(a.CONFIG_FILE)
        a._persist_monitor_results = lambda results: None          # the history and the transitions have their own locks
        start = threading.Barrier(self.HOSTS)
        errors = []

        def host(h):
            try:
                start.wait()
                for r in range(self.ROUNDS):
                    got = a.host_probe_ingest(f"h{h}", [{"label": f"m{h}_{r}", "type": "ping", "target": "10.0.0.1", "ok": True,
                                                         "detail": "", "latency_ms": 1.5}])
                    if got != 1:
                        errors.append((h, r, got))
            except Exception as e:                                   # noqa: BLE001
                errors.append((h, repr(e)))

        threads = [threading.Thread(target=host, args=(h,)) for h in range(self.HOSTS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(errors, [])
        a._LOAD_CACHE.clear()
        stored = a.load(a.SATELLITE_MON_FILE) or {}
        self.assertEqual(len(stored), self.HOSTS * self.ROUNDS, "a result was lost to a concurrent report")

    def test_no_writer_of_the_results_document_is_a_bare_save(self):
        """The class, not the instance: every writer takes the store's lock."""
        for p in _CGI.glob("*.py"):
            src = p.read_text()
            self.assertNotIn("save(A.SATELLITE_MON_FILE", src, p.name)
            self.assertNotIn("save(SATELLITE_MON_FILE", src, p.name)
        users = [p.name for p in _CGI.glob("*.py") if "_LockedUpdate(A.SATELLITE_MON_FILE)" in p.read_text()
                 or "_LockedUpdate(SATELLITE_MON_FILE)" in p.read_text()]
        self.assertEqual(sorted(users), ["api.py", "host_probe_handlers.py"])


# ── BH-12 ────────────────────────────────────────────────────────────────────

class TestAnAssignmentIsOnlyTakenBackOnPurpose(_Assign):

    def test_a_request_that_says_nothing_changes_nothing(self):
        self.assign("a1", "bviewer")
        for body in ({}, {"usr": "bviewer"}, {"user": None}, {"user": 5}, {"user": ["bviewer"]}, {"user": {"n": 1}}):
            st, d = self.call(tapi.handle_alert_assign, "a1", body=body)
            self.assertEqual(st, 400, (body, st, d))
            self.assertEqual(self.row("a1").get("assigned_to"), "bviewer", body)
        self.assertNotIn("alert_unassign", [a[1] for a in self.audits])

    def test_a_viewer_cannot_take_it_back_by_asking_for_nothing(self):
        self.assign("a1", "bviewer")
        st, _d = self.call(tapi.handle_alert_assign, "a1", body={}, who="bviewer")
        self.assertIn(st, (400, 403, 404))
        self.assertEqual(self.row("a1").get("assigned_to"), "bviewer")

    def test_an_empty_name_still_takes_it_back_and_a_name_still_assigns(self):
        self.assign("a1", "bviewer")
        st, d = self.assign("a1", "")
        self.assertEqual((st, d["assigned_to"]), (200, None))
        st, d = self.assign("a1", "badmin2")
        self.assertEqual((st, d["assigned_to"]), (200, "badmin2"))


# ── BH-10 ────────────────────────────────────────────────────────────────────

class TestRecoveryNoticesAreTrue(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.a = _fresh_api()

    def closes(self, running_now, excluded=lambda n, i, t: False):
        a = self.a
        sent = []
        real = a._fire_container_webhook
        a._fire_container_webhook = lambda ev, dev, name, extra=None: sent.append((ev, name, dict(extra or {})))
        try:
            a._evaluate_container_health("d1", running_now, {"unhealthy_alerted": ["web"]}, excluded, {})
        finally:
            a._fire_container_webhook = real
        return [(ev, extra.get("reason")) for ev, _n, extra in sent]

    def test_the_reason_a_health_alert_closed(self):
        self.assertEqual(self.closes({}), [("container_healthy", "gone")])
        self.assertEqual(self.closes({"web": {"health": "healthy", "image": "i", "tag": "t"}}), [("container_healthy", "healthy")])
        self.assertEqual(self.closes({"web": {"health": "unhealthy", "image": "i", "tag": "t"}}, lambda n, i, t: True),
                         [("container_healthy", "excluded")])
        self.assertEqual(self.closes({"web": {"health": None, "image": "i", "tag": "t"}}), [("container_healthy", "unchecked")])

    def test_a_container_that_is_still_starting_keeps_its_alert(self):
        self.assertEqual(self.closes({"web": {"health": "starting", "image": "i", "tag": "t"}}), [])
        self.assertEqual(self.closes({"web": {"health": "unhealthy", "image": "i", "tag": "t"}}), [])

    def say(self, event, **payload):
        return notify._webhook_message(event, {"name": "web01", "container": "web", **payload})

    def test_the_health_message_says_what_happened(self):
        self.assertIn("passes its health check again", self.say("container_healthy", reason="healthy"))
        self.assertIn("passes its health check again", self.say("container_healthy"))               # an older payload
        self.assertIn("no longer running", self.say("container_healthy", reason="gone"))
        self.assertNotIn("passes", self.say("container_healthy", reason="gone"))
        self.assertIn("excluded from monitoring", self.say("container_healthy", reason="excluded"))
        self.assertIn("no longer reports a health check", self.say("container_healthy", reason="unchecked"))

    def test_the_resource_message_says_what_happened(self):
        self.assertIn("back under its CPU line", self.say("container_resource_ok", metric="cpu", reason="below"))
        self.assertIn("back under its CPU line", self.say("container_resource_ok", metric="cpu"))
        gone = self.say("container_resource_ok", metric="cpu", reason="gone")
        self.assertIn("no longer running", gone)
        self.assertNotIn("back under", gone)
        off = self.say("container_resource_ok", metric="memory", reason="off")
        self.assertIn("switched off", off)
        self.assertNotIn("back under", off)


# ── BH-11 ────────────────────────────────────────────────────────────────────

def _whitelist(src, function):
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == function:
            for m in ast.walk(n):
                if isinstance(m, ast.For) and isinstance(m.iter, ast.Tuple) and len(m.iter.elts) > 30:
                    return {e.value for e in m.iter.elts if isinstance(e, ast.Constant)}
    raise AssertionError(function)


class TestTheFeedKeepsWhatTheNewEventsCarry(unittest.TestCase):

    def test_both_copies_carry_the_keys(self):
        src = (_CGI / "api.py").read_text()
        feed, inbox = _whitelist(src, "_record_fleet_event"), _whitelist(src, "_record_alert")
        for k in ("state", "parts_ok", "parts", "output", "health_streak", "runtime"):
            self.assertIn(k, feed, f"feed: {k}")
        for k in ("health_streak", "runtime", "parts_ok", "parts"):
            self.assertIn(k, inbox, f"inbox: {k}")

    def test_a_degraded_service_is_stored_as_degraded(self):
        a = _fresh_api()
        a._record_fleet_event("business_service_down", {"service_id": "bs1", "name": "Shop", "state": "degraded",
                                                         "parts_ok": 2, "parts": 3, "detail": "1 of 3 parts down"})
        a._LOAD_CACHE.clear()
        store = a.load(a.FLEET_EVENTS_FILE)
        rows = store if isinstance(store, list) else (store.get("events") or [])
        row = rows[-1]
        blob = json.dumps(row)
        for want in ('"state": "degraded"', '"parts_ok": 2', '"parts": 3'):
            self.assertIn(want, blob)


# ── BH-14 / BH-15 ────────────────────────────────────────────────────────────

class TestStoreShapesAndNumbers(unittest.TestCase):

    def test_numeric_text_of_five_thousand_digits_does_not_stop_the_repair(self):
        doc = {"h1": {"ts": "9" * 5000, "ok": 1}, "h2": 7}
        out = store_shapes.normalize("repo_inventory.json", doc)           # used to raise ValueError
        self.assertIsInstance(out, dict)
        self.assertNotIn("h2", out, "the repair ran: a row that is not a map is left out")

    def test_the_two_stores_of_7_4_3_are_registered_and_repaired(self):
        names = store_shapes.normalize("disk_names.json", {"h1": {"S1": "boot", "S2": 5, "S3": None}, "h2": "x", "h3": ["y"]})
        self.assertEqual(names, {"h1": {"S1": "boot", "S2": "5"}})
        hist = store_shapes.normalize("container_stats_hist.json",
                                      {"h1": {"web": [[1, 2.0, 3.0, 4.0], "x", None, [5, 1, 1, 1]]}, "h2": 3, "h3": {"db": "x"}})
        self.assertEqual(hist, {"h1": {"web": [[1, 2.0, 3.0, 4.0], [5, 1, 1, 1]]}, "h3": {}})     # h2 is not a map; h3 lost its bad row

    def test_a_bad_row_in_the_sample_history_does_not_stop_recording(self):
        a = _fresh_api()
        now = int(time.time())
        a._entity_write_one(a.CONTAINER_STATS_HIST_FILE, "d1", {"web": [["x"], None, [now - 600, 1.0, 2.0, 3.0]]})
        a._record_container_stats("d1", {"web": [now, 5.0, 6.0, 7.0]}, ["web"], now)
        a._LOAD_CACHE.clear()
        rows = (a._entity_read_one(a.CONTAINER_STATS_HIST_FILE, "d1", {}) or {}).get("web")
        self.assertEqual([r[0] for r in rows], [now - 600, now])

    def test_num_survives_what_a_float_cannot_hold(self):
        for v in (float("inf"), float("-inf"), float("nan"), 10 ** 400, "1e999", "x", None):
            self.assertIsInstance(notify._num(v), str, v)
        self.assertEqual(notify._num(100.0), "100")
        self.assertEqual(notify._num(412.5), "412.5")
        self.assertEqual(notify._num(1536.0), "1,536")
        self.assertEqual(notify._num("12"), "12")


# ── BH-16 ────────────────────────────────────────────────────────────────────

class TestTheSmallerOnes(unittest.TestCase):

    def test_a_period_name_is_stable_under_a_second_clean(self):
        raw = {"name": "A" * 63 + " tail", "tz": "UTC", "weekly": {"0": [[0, 60]]}}
        once = tp.clean_period(raw, new_id="tp-0123abcd")
        twice = tp.clean_period(dict(once))
        self.assertEqual(once["name"], twice["name"])
        self.assertFalse(once["name"].endswith(" "))

    def test_overlapping_ranges_are_merged_when_read(self):
        self.assertEqual(tp._ranges({"weekly": {"0": [[0, 2], [0, 9], [0, 1]]}}, 0), [(0, 9)])
        self.assertEqual(tp._ranges({"weekly": {"0": [[0, 60], [60, 120]]}}, 0), [(0, 120)])
        self.assertEqual(tp._ranges({"weekly": {"0": [[600, 700], [0, 60]]}}, 0), [(0, 60), (600, 700)])
        self.assertEqual(tp._ranges({"weekly": {"0": [[0, 100], [50, 80]]}}, 0), [(0, 100)])

    def test_more_time_never_moves_the_deadline_earlier(self):
        period = {"tz": "UTC", "weekly": {str(d): [[0, 2], [0, 9], [0, 1]] for d in range(7)}}
        start = 1_700_000_000
        last = 0
        for seconds in (60, 120, 300, 500, 600, 1200):
            d = tp.business_deadline(start, seconds, period)
            self.assertGreaterEqual(d, last, seconds)
            last = d

    def test_a_zfs_ratio_that_rounds_to_nothing_is_unknown_and_stays_so(self):
        self.assertEqual(zfs_stats._ratio(0.0039), 1.0)
        self.assertEqual(zfs_stats._ratio(zfs_stats._ratio(0.0039)), zfs_stats._ratio(0.0039))
        self.assertEqual(zfs_stats._ratio(0.5), 0.5)
        self.assertEqual(zfs_stats._ratio(1.234), 1.23)
        self.assertEqual(zfs_stats._ratio(0.0), 1.0)
        self.assertEqual(zfs_stats._ratio(1000), 1.0)

    def test_two_parts_never_share_a_key(self):
        a = {"kind": bizsvc.KIND_UNIT, "device_id": "a", "unit": "x|y"}
        b = {"kind": bizsvc.KIND_UNIT, "device_id": "a|x", "unit": "y"}
        self.assertNotEqual(bizsvc.member_key(a), bizsvc.member_key(b))

    def test_no_two_pairs_of_fields_share_a_key(self):
        """Every pair of fields over a small alphabet, the separator and the escape character included: the key is injective."""
        import itertools
        words = ["".join(w) for n in range(0, 4) for w in itertools.product("a|\\", repeat=n)]
        seen = {}
        for f1, f2 in itertools.product(words, words):
            key = bizsvc.member_key({"kind": bizsvc.KIND_UNIT, "device_id": f1, "unit": f2})
            self.assertNotIn(key, seen, f"{(f1, f2)} and {seen.get(key)} share {key!r}")
            seen[key] = (f1, f2)
        self.assertGreater(len(seen), 1500)

    def test_an_ordinary_key_is_what_it_always_was(self):
        """Stored state is keyed by this text; a key with neither character must not change."""
        self.assertEqual(bizsvc.member_key({"kind": bizsvc.KIND_UNIT, "device_id": "h1", "unit": "nginx.service"}),
                         f"{bizsvc.KIND_UNIT}|h1|nginx.service")
        self.assertEqual(bizsvc.member_key({"kind": bizsvc.KIND_HOST, "device_id": "h1"}), f"{bizsvc.KIND_HOST}|h1")


# ── BH-19 ────────────────────────────────────────────────────────────────────

class TestTheCadenceGateLooksAtTheClockFirst(unittest.TestCase):

    def test_a_service_sweep_that_is_not_due_loads_nothing_else(self):
        a = _fresh_api()
        g = a.run_business_services_if_due.__globals__
        now = int(time.time())
        a.save(a.BUSINESS_SERVICE_STATE_FILE, {"last_run": now, "services": {}})
        a._LOAD_CACHE.clear()
        calls = []
        real_defs, real_load = g["_definitions"], a.load
        g["_definitions"] = lambda: calls.append("definitions") or {}
        a.load = lambda path, *x, **k: calls.append(str(path)) or real_load(path, *x, **k)
        try:
            a.run_business_services_if_due()
        finally:
            g["_definitions"] = real_defs
            a.load = real_load
        self.assertEqual(calls, [], "a sweep that is not due must not copy a store")

    def test_a_due_sweep_still_runs(self):
        a = _fresh_api()
        g = a.run_business_services_if_due.__globals__
        a.save(a.BUSINESS_SERVICE_STATE_FILE, {"last_run": int(time.time()) - 10_000, "services": {"gone": {}}})
        a._LOAD_CACHE.clear()
        seen = []
        real_defs = g["_definitions"]
        g["_definitions"] = lambda: seen.append(1) or {}
        try:
            a.run_business_services_if_due()
        finally:
            g["_definitions"] = real_defs
        self.assertEqual(seen, [1])
        a._LOAD_CACHE.clear()
        self.assertEqual((a.load(a.BUSINESS_SERVICE_STATE_FILE) or {}).get("services"), {}, "the stale service was dropped")


if __name__ == "__main__":
    unittest.main()
