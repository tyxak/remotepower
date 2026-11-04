#!/usr/bin/env python3
"""Two Medium findings of the 7.5.0 bug hunt, and the small ones in the same code.

BH-2 (Medium). `POST /api/config/declarative?apply=1` wrote the `time_periods`
collection exactly as it came, without the cleaner the Settings save uses. A period
with `weekly: {"0": 5}` was then stored, and the ticket SLA walk raised on it, so
`GET /api/tickets` answered 500 for everyone. Two fixes: the import runs the cleaner,
and the reader no longer trusts the shape of a day (a store written by 7.4.9 can
already hold one).

BH-3 (Medium). The nesting limit judged only the service being saved, downwards, so
editing a service at the bottom of a chain made every holder deeper without a check,
and `bizsvc.depth()` walked every path (a graph where each service holds the next two
costs F(n) calls: about 70 s at 40 services, hours at 50, with 100 allowed). It needed
an administrator of the operator's organisation, hence Medium, not High. Now memoised,
and every service of the trial graph is judged.

BH-5. `members[i].kind` as a list or a dict was an unhashable key: a 500 on save, and
on every read of a stored definition.

BH-13. Six ranges on a day plus a range crossing midnight from the day before made
seven; the seventh was lost on the next save.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-bh-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v749_business_services import _Svc, api, host  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import bizsvc as bz  # noqa: E402
import time_periods as tp  # noqa: E402

GOOD = {"name": "Office", "tz": "UTC", "weekly": {"0": [[540, 1020]], "1": [[540, 1020]]}}


def svc(**kw):
    return {k: [{"kind": "service", "service_id": v} for v in vs] for k, vs in kw.items()}


class TestADayThatIsNotAListDoesNotRaise(unittest.TestCase):

    BAD_DAYS = (5, 1.5, True, "x", {"a": 1}, None, 0)

    def test_ranges_reads_junk_as_no_ranges(self):
        for day in self.BAD_DAYS:
            for wd in range(7):
                self.assertEqual(tp._ranges({"weekly": {str(wd): day}}, wd), [], (day, wd))

    def test_the_readers_that_walk_a_period_survive_every_weekday(self):
        poisoned = {"id": "tp-abcd1234", "name": "Bad", "tz": "UTC",
                    "weekly": {str(d): 5 for d in range(7)}}
        now = int(time.time())
        for fn in (lambda: tp.is_active(poisoned, now),
                   lambda: tp.next_change(poisoned, now),
                   lambda: tp.business_deadline(now, 120, poisoned)):
            try:
                fn()
            except Exception as e:                 # noqa: BLE001
                self.fail(f"{type(e).__name__}: {e}")

    def test_a_good_period_still_works(self):
        """Control: the guard did not turn every day into nothing."""
        self.assertEqual(tp._ranges({"weekly": {"0": [[540, 1020]]}}, 0), [(540, 1020)])


class TestTheImportCleansTimePeriods(unittest.TestCase):

    def setUp(self):
        self._saved = api.CONFIG_FILE
        d = Path(tempfile.mkdtemp())
        api.CONFIG_FILE = d / Path(self._saved).name
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        api.CONFIG_FILE = self._saved
        api._LOAD_CACHE.clear()

    def _apply(self, periods):
        doc = {"schema": api.DECLARATIVE_SCHEMA, "resources": {"time_periods": periods}}
        r = api._declarative_apply(doc, "jakob", dry_run=False)
        api._LOAD_CACHE.clear()
        return r, (api.load(api.CONFIG_FILE) or {}).get("time_periods")

    def test_a_bad_day_is_cleaned_away_before_it_is_stored(self):
        r, stored = self._apply([{"id": "tp-deadbeef", "name": "Bad", "tz": "UTC",
                                  "weekly": {"0": 5, "1": [[540, 1020]], "2": "x"}}])
        self.assertNotIn("skipped", r["report"]["time_periods"])
        self.assertEqual(stored[0]["weekly"], {"1": [[540, 1020]]})

    def test_so_the_ticket_walk_no_longer_meets_it(self):
        _r, stored = self._apply([{"id": "tp-deadbeef", "name": "Bad", "tz": "UTC",
                                   "weekly": {str(d): 5 for d in range(7)}}])
        now = int(time.time())
        self.assertEqual(tp.business_deadline(now, 3600, stored[0]) >= now, True)

    def test_a_period_with_an_id_that_is_not_ours_is_refused(self):
        r, stored = self._apply([{"id": "../../x", "name": "Bad", "tz": "UTC", "weekly": {}}])
        self.assertIn("skipped", r["report"]["time_periods"])
        self.assertIsNone(stored)

    def test_two_periods_with_one_name_are_refused(self):
        r, stored = self._apply([dict(GOOD, id="tp-aaaa1111"), dict(GOOD, id="tp-bbbb2222")])
        self.assertIn("skipped", r["report"]["time_periods"])
        self.assertIsNone(stored)

    def test_a_good_period_is_stored_cleaned(self):
        r, stored = self._apply([dict(GOOD, id="tp-aaaa1111", name="  Office  ")])
        self.assertNotIn("skipped", r["report"]["time_periods"])
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["name"], "Office")
        self.assertEqual(stored[0]["id"], "tp-aaaa1111")

    def test_a_period_without_an_id_gets_one(self):
        r, stored = self._apply([dict(GOOD)])
        self.assertTrue(stored[0]["id"].startswith("tp-"))

    def test_an_export_comes_back_the_same(self):
        """The round trip: what Settings stored is what the import accepts."""
        api.save(api.CONFIG_FILE, {"time_periods": tp.clean_periods([dict(GOOD)],
                                                                    lambda: "tp-01020304")})
        api._LOAD_CACHE.clear()
        doc = api._build_declarative_config()
        before = (api.load(api.CONFIG_FILE) or {})["time_periods"]
        r = api._declarative_apply(doc, "jakob", dry_run=False)
        api._LOAD_CACHE.clear()
        self.assertNotIn("skipped", r["report"].get("time_periods", {}))
        self.assertEqual((api.load(api.CONFIG_FILE) or {})["time_periods"], before)

    def test_a_dry_run_changes_nothing_and_still_reports_the_refusal(self):
        doc = {"schema": api.DECLARATIVE_SCHEMA,
               "resources": {"time_periods": [{"id": "../x", "name": "Bad", "weekly": {}}]}}
        r = api._declarative_apply(doc, "jakob", dry_run=True)
        self.assertIn("skipped", r["report"]["time_periods"])
        api._LOAD_CACHE.clear()
        self.assertIsNone((api.load(api.CONFIG_FILE) or {}).get("time_periods"))

    def test_the_other_collections_are_not_touched_by_the_cleaner(self):
        r = api._declarative_apply(
            {"schema": api.DECLARATIVE_SCHEMA, "resources": {"monitors": []}},
            "jakob", dry_run=True)
        self.assertTrue(r["ok"])


class TestTheSixRangeLimit(unittest.TestCase):

    def test_seven_pieces_on_a_day_are_cut_to_six_and_stay_cut(self):
        # six ranges that start at 01:00, and Sunday's range that crosses midnight: a piece at 00:00 that touches none of them
        weekly = {"0": [[60 + i * 120, 120 + i * 120] for i in range(6)], "6": [[1320, 30]]}
        once = tp.clean_weekly(weekly)
        self.assertEqual(len(once["0"]), tp.MAX_RANGES_PER_DAY)
        self.assertEqual(tp.clean_weekly(once), once, "idempotent")

    def test_a_day_with_fewer_ranges_keeps_all_of_them(self):
        weekly = {"0": [[60, 120], [180, 240]], "6": [[1320, 30]]}
        self.assertEqual(len(tp.clean_weekly(weekly)["0"]), 3, "two of its own and the piece from Sunday")


class TestNestingIsJudgedForTheWholeGraph(unittest.TestCase):

    def test_depth_counts_levels_as_before(self):
        s = svc(a=["b"], b=["c"], c=[])
        self.assertEqual((bz.depth(s, "a"), bz.depth(s, "b"), bz.depth(s, "c")), (3, 2, 1))
        self.assertGreater(bz.depth(svc(a=["b"], b=["a"]), "a"), bz.MAX_DEPTH)
        self.assertEqual(bz.depth(svc(a=["missing"]), "a"), 1)

    def test_a_diamond_is_counted_once_per_level(self):
        s = svc(top=["l", "r"], l=["bottom"], r=["bottom"], bottom=[])
        self.assertEqual(bz.depth(s, "top"), 3)

    def test_the_cost_follows_the_size_not_the_number_of_paths(self):
        """Each service holds the next two: F(n) paths. At 45 services the old
        walk took the better part of an hour; the memoised one takes milliseconds."""
        n = 45
        g = {f"s{i}": ([f"s{i + 1}", f"s{i + 2}"] if i + 2 < n else
                       ([f"s{i + 1}"] if i + 1 < n else [])) for i in range(n)}
        trial = svc(**g)
        t = time.time()
        d = bz.depth(trial, "s0")
        took = time.time() - t
        self.assertEqual(d, n, "a chain of n services is n levels")
        self.assertLess(took, 1.0, f"depth took {took:.1f} s on {n} services")

    def test_a_shared_memo_is_not_confused_by_a_cycle(self):
        s = svc(a=["b"], b=["c"], c=["a"], z=[])
        memo = {}
        self.assertGreater(bz.depth(s, "a", None, memo), bz.MAX_DEPTH)
        self.assertEqual(bz.depth(s, "z", None, memo), 1)


class TestEditingTheBottomOfAChain(_Svc):

    def _chain(self, n):
        """n services, each holding the next; returns the ids from the top."""
        ids = []
        prev = None
        for i in range(n):
            members = [host("h1")] + ([{"kind": "service", "service_id": prev}] if prev else [])
            st, d = self.create(name=f"chain{i}", members=members)
            self.assertEqual(st, 201, (i, d))
            ids.append(d["id"])
            prev = d["id"]
        return list(reversed(ids))        # top first

    def test_the_limit_holds_for_a_new_service(self):
        self._chain(bz.MAX_DEPTH)
        # one more on top of the deepest is the sixth level
        top = self._chain_top()
        st, d = self.create(name="too-deep", members=[{"kind": "service", "service_id": top}])
        self.assertEqual(st, 400, d)
        self.assertIn("nested too deep", d["error"])

    def _chain_top(self):
        defs = api.load(api.BUSINESS_SERVICES_FILE)
        for sid, d in defs.items():
            if d["name"] == f"chain{bz.MAX_DEPTH - 1}":
                return sid
        self.fail("no top of the chain")

    def test_editing_the_bottom_to_hold_another_service_is_refused(self):
        """The bypass: the bottom service gains a part that is itself a service,
        which makes every holder above it one level deeper."""
        ids = self._chain(bz.MAX_DEPTH)
        bottom = ids[-1]
        st, extra = self.create(name="extra", members=[host("h2")])
        self.assertEqual(st, 201, extra)
        st, d = self.call(api.handle_business_service, bottom,
                          body={"name": "chain0",
                                "members": [host("h1"), {"kind": "service", "service_id": extra["id"]}]},
                          m="PUT", who="platform")
        self.assertEqual(st, 400, d)
        self.assertIn("nested too deep", d["error"])

    def test_an_edit_that_stays_within_the_limit_is_accepted(self):
        ids = self._chain(3)
        st, extra = self.create(name="extra", members=[host("h2")])
        st, d = self.call(api.handle_business_service, ids[-1],
                          body={"name": "chain0",
                                "members": [host("h1"), {"kind": "service", "service_id": extra["id"]}]},
                          m="PUT", who="platform")
        self.assertEqual(st, 200, d)

    def test_the_refused_edit_leaves_the_store_as_it_was(self):
        ids = self._chain(bz.MAX_DEPTH)
        before = json.dumps(api.load(api.BUSINESS_SERVICES_FILE), sort_keys=True)
        st, extra = self.create(name="extra", members=[host("h2")])
        before = json.dumps(api.load(api.BUSINESS_SERVICES_FILE), sort_keys=True)
        self.call(api.handle_business_service, ids[-1],
                  body={"name": "chain0",
                        "members": [host("h1"), {"kind": "service", "service_id": extra["id"]}]},
                  m="PUT", who="platform")
        api._LOAD_CACHE.clear()
        self.assertEqual(json.dumps(api.load(api.BUSINESS_SERVICES_FILE), sort_keys=True), before)


class TestAnUnhashableKind(_Svc):

    def test_clean_member_refuses_any_kind_that_is_not_a_known_string(self):
        for kind in ([], [None], [[]], {}, {"a": 1}, 5, None, True, ""):
            self.assertIsNone(bz.clean_member({"kind": kind}), kind)

    def test_the_save_answers_400_not_500(self):
        for kind in ([], [None], {"a": 1}):
            st, d = self.create(members=[{"kind": kind}])
            self.assertEqual(st, 400, (kind, st, d))

    def test_a_good_kind_still_works(self):
        self.assertIsNotNone(bz.clean_member(host("h1")))


if __name__ == "__main__":
    unittest.main()
