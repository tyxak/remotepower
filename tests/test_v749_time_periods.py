#!/usr/bin/env python3
"""7.4.9: named time periods, the one reading of "is this moment inside that window".

The module is pure, so these tests need no server. The part that matters most is what did not change: the older settings (quiet
hours, after-hours, the ticket calendar) now run through this module, and each is compared here with the rule it replaced, written
out again as it was and tried on every minute of a week.
"""
import os
import random
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import time_periods as tp  # noqa: E402


class ServerClock(unittest.TestCase):
    """A test case that can set the time zone of the process and puts it back."""

    def set_tz(self, name):
        real = os.environ.get("TZ")

        def restore():
            if real is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = real
            time.tzset()
        self.addCleanup(restore)
        os.environ["TZ"] = name
        time.tzset()


def ts_of(y, mo, d, h=0, mi=0, tz=timezone.utc):
    return int(datetime(y, mo, d, h, mi, tzinfo=tz).timestamp())


def weekdays(spec):
    """{0: [[s, e]], ...} from a short form."""
    return {str(d): [list(r) for r in rs] for d, rs in spec.items()}


OFFICE = {"id": "tp-00000001", "name": "Office", "tz": "", "tz_offset_min": 0, "holidays": [],
          "weekly": weekdays({d: [(540, 1020)] for d in range(5)})}     # Monday to Friday, 09:00-17:00 UTC


class TestIsActive(ServerClock):

    def test_inside_and_outside_the_hours(self):
        monday = lambda h, m: ts_of(2026, 11, 2, h, m)       # 2026-11-02 is a Monday
        self.assertTrue(tp.is_active(OFFICE, monday(9, 0)), "the start minute is in")
        self.assertTrue(tp.is_active(OFFICE, monday(16, 59)))
        self.assertFalse(tp.is_active(OFFICE, monday(17, 0)), "the end minute is out")
        self.assertFalse(tp.is_active(OFFICE, monday(8, 59)))
        self.assertFalse(tp.is_active(OFFICE, ts_of(2026, 11, 7, 12)), "Saturday")
        self.assertFalse(tp.is_active(OFFICE, ts_of(2026, 11, 8, 12)), "Sunday")

    def test_a_holiday_closes_the_whole_day(self):
        per = dict(OFFICE, holidays=["2026-11-02"])
        self.assertFalse(tp.is_active(per, ts_of(2026, 11, 2, 12)))
        self.assertTrue(tp.is_active(per, ts_of(2026, 11, 3, 12)))

    def test_a_time_zone_by_name_follows_summer_time(self):
        cph = dict(OFFICE, tz="Europe/Copenhagen", tz_offset_min=None)
        # 09:00 in Copenhagen is 08:00 UTC in November (CET) and 07:00 UTC in July (CEST)
        self.assertTrue(tp.is_active(cph, ts_of(2026, 11, 2, 8, 0)))
        self.assertFalse(tp.is_active(cph, ts_of(2026, 11, 2, 7, 59)))
        self.assertTrue(tp.is_active(cph, ts_of(2026, 7, 6, 7, 0)))
        self.assertFalse(tp.is_active(cph, ts_of(2026, 7, 6, 6, 59)))
        self.assertFalse(tp.is_active(cph, ts_of(2026, 7, 6, 15, 0)), "17:00 CEST")
        self.assertTrue(tp.is_active(cph, ts_of(2026, 7, 6, 14, 59)))

    def test_a_fixed_offset(self):
        plus2 = dict(OFFICE, tz_offset_min=120)
        self.assertTrue(tp.is_active(plus2, ts_of(2026, 11, 2, 7, 0)))       # 09:00 at +02:00
        self.assertFalse(tp.is_active(plus2, ts_of(2026, 11, 2, 6, 59)))
        self.assertFalse(tp.is_active(dict(OFFICE, tz_offset_min=99999), 0) is None)

    def test_the_name_wins_over_the_offset_and_an_unknown_name_falls_back(self):
        both = dict(OFFICE, tz="Europe/Copenhagen", tz_offset_min=-300)
        self.assertTrue(tp.is_active(both, ts_of(2026, 11, 2, 8, 0)))
        broken = dict(OFFICE, tz="Nowhere/Land", tz_offset_min=120)
        self.assertEqual(tp.zone_of(broken).utcoffset(None), timedelta(minutes=120))
        self.assertIsNone(tp.zone_of(dict(OFFICE, tz="Nowhere/Land", tz_offset_min=None)))

    def test_the_clock_of_the_server(self):
        self.set_tz("Asia/Tokyo")
        local = dict(OFFICE, tz="", tz_offset_min=None)
        self.assertTrue(tp.is_active(local, ts_of(2026, 11, 2, 0, 0)), "00:00 UTC is 09:00 in Tokyo")
        self.assertFalse(tp.is_active(local, ts_of(2026, 11, 2, 9, 0)))
        self.set_tz("UTC")
        self.assertTrue(tp.is_active(local, ts_of(2026, 11, 2, 9, 0)))

    def test_a_fixed_offset_that_is_not_a_whole_number_of_minutes_within_the_range_is_not_one(self):
        for odd in (True, False, 5000, -5000, 841, -721, "60", 1.5, None):
            self.assertIsNone(tp.zone_of({"tz": "", "tz_offset_min": odd}), repr(odd))
        self.assertEqual(tp.zone_of({"tz_offset_min": 840}).utcoffset(None), timedelta(minutes=840))
        self.assertEqual(tp.zone_of({"tz_offset_min": -720}).utcoffset(None), timedelta(minutes=-720))
        self.assertEqual(tp.zone_of({"tz_offset_min": 0}).utcoffset(None), timedelta(0), "zero is UTC, not the clock of the server")

    def test_a_range_that_begins_before_the_day_is_not_a_range(self):
        per = {"tz_offset_min": 0, "weekly": {"0": [[-60, 600]]}}
        self.assertFalse(tp.is_active(per, ts_of(2026, 11, 2, 2, 0)))

    def test_what_is_not_a_period(self):
        for junk in (None, "x", 5, [], [1], {}, {"weekly": "x"}, {"weekly": {"0": "x"}}, {"weekly": {"0": [[1]]}}, {"weekly": {"x": [[0, 60]]}},
                     {"weekly": {"0": [[60, 30]]}}, {"weekly": {"0": [["a", "b"]]}}, {"weekly": {"0": [[0, 99999]]}}):
            self.assertFalse(tp.is_active(junk, ts_of(2026, 11, 2, 0, 30)), repr(junk))

    def test_a_huge_or_odd_timestamp_does_not_raise(self):
        for odd in (0, 1, 2 ** 31, 2 ** 40, -5):
            try:
                tp.is_active(OFFICE, odd)
            except (OverflowError, OSError, ValueError):
                pass       # a time stamp the platform can not represent is a refusal, never another kind of error


class TestOlderSettingsAreTheSameRule(ServerClock):
    """quiet hours and after-hours as they were, tried on every minute of a week."""

    @staticmethod
    def legacy_in_window(hhmm, start, end):
        if start <= end:
            return start <= hhmm < end
        return hhmm >= start or hhmm < end

    def minutes_of_a_week(self):
        base = ts_of(2026, 11, 2, 0, 0)              # a Monday, UTC
        for i in range(7 * 24 * 60):
            yield base + i * 60

    def test_quiet_hours_on_the_clock_of_the_server(self):
        self.set_tz("UTC")
        for start, end in (("22:00", "07:00"), ("09:00", "17:00"), ("00:00", "23:59"), ("23:30", "00:30"), ("06:15", "06:16"), ("12:00", "12:00")):
            per = tp.from_clock_range(start, end)
            for t in self.minutes_of_a_week():
                hhmm = time.strftime("%H:%M", time.localtime(t))
                want = self.legacy_in_window(hhmm, start, end)
                self.assertEqual(tp.is_active(per, t), want, (start, end, hhmm))

    def test_after_hours_with_its_working_days(self):
        self.set_tz("UTC")
        for start, end, days in (("09:00", "17:00", [0, 1, 2, 3, 4]), ("08:30", "16:45", [0, 2, 4]), ("22:00", "06:00", [0, 1, 2, 3, 4]), ("00:00", "12:00", [5, 6])):
            per = tp.from_clock_range(start, end, days)
            for t in self.minutes_of_a_week():
                lt = datetime.fromtimestamp(t)
                want = lt.weekday() in days and self.legacy_in_window(lt.strftime("%H:%M"), start, end)
                self.assertEqual(tp.is_active(per, t), want, (start, end, days, lt))

    def test_a_range_of_hours_is_read_on_the_clock_of_the_server_not_in_utc(self):
        self.set_tz("Asia/Tokyo")
        per = tp.from_clock_range("09:00", "17:00")
        self.assertTrue(tp.is_active(per, ts_of(2026, 11, 2, 0, 0)), "00:00 UTC is 09:00 in Tokyo")
        self.assertFalse(tp.is_active(per, ts_of(2026, 11, 2, 9, 0)), "09:00 UTC is 18:00 in Tokyo")

    def test_a_range_that_is_not_one(self):
        for start, end in (("", ""), ("9:00", "17:00"), ("25:00", "26:00"), ("24:00", "07:00"), ("09:00", "24:00"), ("09:00", "09:60"), ("09:00", "09:00"), (None, None), ("09:00", "")):
            self.assertIsNone(tp.from_clock_range(start, end), (start, end))
        self.assertIsNotNone(tp.from_clock_range(" 09:00 ", "17:00\n"), "spaces round the times do not matter")
        self.assertEqual(tp.from_clock_range("09:00", "17:00", [])["weekly"], {}, "no working days: never in")
        self.assertEqual(sorted(tp.from_clock_range("09:00", "17:00", [9, "x", True, 2, 2, 7, -1])["weekly"]), ["2"])
        self.assertEqual(len(tp.from_clock_range("09:00", "17:00", "junk")["weekly"]), 7)


class TestTheSlaClock(unittest.TestCase):
    """business_deadline against the walk it replaced, written out again as it was."""

    @staticmethod
    def old_deadline(start_ts, seconds, spec):
        try:
            offset = int(spec.get("tz_offset_min", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            offset = 0
        tz = timezone(timedelta(minutes=offset))
        weekly = spec.get("weekly") or {}
        holidays = set(spec.get("holidays") or [])
        remaining = float(seconds)
        cur = datetime.fromtimestamp(int(start_ts), tz)
        for _ in range(3700):
            if remaining <= 0:
                return int(cur.timestamp())
            day_key = str(cur.weekday())
            if cur.strftime("%Y-%m-%d") not in holidays:
                midnight = cur.replace(hour=0, minute=0, second=0, microsecond=0)
                for win in weekly.get(day_key) or []:
                    try:
                        s_min, e_min = int(win[0]), int(win[1])
                    except (TypeError, ValueError, IndexError, OverflowError):
                        continue
                    if e_min <= s_min:
                        continue
                    w_start = max(cur, midnight + timedelta(minutes=s_min))
                    w_end = midnight + timedelta(minutes=e_min)
                    if w_start >= w_end:
                        continue
                    avail = (w_end - w_start).total_seconds()
                    if avail >= remaining:
                        return int((w_start + timedelta(seconds=remaining)).timestamp())
                    remaining -= avail
            cur = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return int(start_ts) + int(seconds)

    def test_it_matches_the_old_walk_on_a_few_thousand_random_cases(self):
        rng = random.Random(749)
        for _ in range(3000):
            weekly = {}
            for d in range(7):
                if rng.random() < 0.7:
                    s = rng.randrange(0, 1300)
                    e = rng.randrange(s + 1, 1441)
                    weekly[str(d)] = [[s, e]]
                    if rng.random() < 0.3 and e < 1380:
                        s2 = rng.randrange(e + 5, 1400)
                        weekly[str(d)].append([s2, rng.randrange(s2 + 1, 1441)])
            spec = {"tz_offset_min": rng.choice([0, 60, -300, 330, 540]), "weekly": weekly,
                    "holidays": [f"2026-11-{rng.randrange(1, 30):02d}" for _ in range(rng.randrange(0, 4))]}
            start = ts_of(2026, 11, 1) + rng.randrange(0, 20 * 86400)
            secs = rng.choice([60, 3600, 4 * 3600, 8 * 3600, 3 * 86400, rng.randrange(1, 10 * 86400)])
            self.assertEqual(tp.business_deadline(start, secs, spec), self.old_deadline(start, secs, spec), (spec, start, secs))

    def test_a_calendar_with_no_ranges_is_plain_elapsed_time(self):
        self.assertEqual(tp.business_deadline(1000, 500, {"weekly": {}}), 1500)
        self.assertEqual(tp.business_deadline(1000, 500, None), 1500)
        self.assertEqual(tp.business_deadline(1000, 500, "x"), 1500)

    def test_zero_seconds_is_now(self):
        self.assertEqual(tp.business_deadline(ts_of(2026, 11, 2, 12), 0, OFFICE), ts_of(2026, 11, 2, 12))

    def test_zero_seconds_is_now_outside_the_hours_too(self):
        sunday = ts_of(2026, 11, 8, 12)
        self.assertEqual(tp.business_deadline(sunday, 0, OFFICE), sunday, "no work to wait for, so no wait for the office to open")
        self.assertEqual(tp.business_deadline(sunday, -5, OFFICE), sunday)

    def test_the_clock_stops_over_the_weekend(self):
        friday_4pm = ts_of(2026, 11, 6, 16, 0)
        self.assertEqual(tp.business_deadline(friday_4pm, 2 * 3600, OFFICE), ts_of(2026, 11, 9, 10, 0), "1h Friday, 1h Monday")

    def test_a_named_zone_moves_with_summer_time(self):
        cph = dict(OFFICE, tz="Europe/Copenhagen", tz_offset_min=None)
        # the Friday before the clocks go back (2026-10-25): 16:00 local, two hours of work, ends Monday 10:00 local (CET, 09:00 UTC)
        start = ts_of(2026, 10, 23, 14, 0)           # 16:00 CEST
        self.assertEqual(tp.business_deadline(start, 2 * 3600, cph), ts_of(2026, 10, 26, 9, 0))


class TestCleaning(unittest.TestCase):

    def test_ranges_are_checked_sorted_and_joined(self):
        got = tp.clean_weekly({"0": [[600, 700], [540, 610], [900, 960], [0, 0], [5, 5], ["a", "b"], [10]], "9": [[0, 60]], "x": [[0, 60]], "1": "x", "2": [[-50, 99999]]})
        self.assertEqual(got, {"0": [[540, 700], [900, 960]], "2": [[0, 1440]]})

    def test_a_range_across_midnight_becomes_two(self):
        self.assertEqual(tp.clean_weekly({"0": [[1320, 420]]}), {"0": [[1320, 1440]], "1": [[0, 420]]})
        self.assertEqual(tp.clean_weekly({"6": [[1320, 420]]}), {"6": [[1320, 1440]], "0": [[0, 420]]}, "Sunday night into Monday")
        self.assertEqual(tp.clean_weekly({"3": [[0, 0]]}), {})
        self.assertEqual(tp.clean_weekly({"3": [[1440, 100]]}), {"4": [[0, 100]]})

    def test_no_more_ranges_than_the_limit(self):
        got = tp.clean_weekly({"0": [[i * 100, i * 100 + 50] for i in range(14)]})
        self.assertLessEqual(len(got["0"]), tp.MAX_RANGES_PER_DAY * 2)

    def test_a_day_keeps_the_first_six_ranges_it_is_given(self):
        got = tp.clean_weekly({"0": [[i * 100, i * 100 + 50] for i in range(10)]})
        self.assertEqual(got["0"], [[i * 100, i * 100 + 50] for i in range(tp.MAX_RANGES_PER_DAY)])

    def test_ranges_that_touch_or_lie_inside_another_are_joined(self):
        self.assertEqual(tp.clean_weekly({"0": [[540, 600], [600, 660]]}), {"0": [[540, 660]]}, "touching")
        self.assertEqual(tp.clean_weekly({"0": [[540, 1020], [600, 700]]}), {"0": [[540, 1020]]}, "inside the first")
        self.assertEqual(tp.clean_weekly({"0": [[540, 600], [601, 660]]}), {"0": [[540, 600], [601, 660]]}, "a minute apart stays two")

    def test_a_day_that_does_not_exist_is_left_out(self):
        self.assertEqual(tp.clean_weekly({"7": [[540, 1020]], "-1": [[540, 1020]], "0": [[540, 600]]}), {"0": [[540, 600]]})

    def test_junk_in_gives_an_empty_calendar(self):
        for junk in (None, "x", 5, [], [[0, 60]]):
            self.assertEqual(tp.clean_weekly(junk), {})

    def test_a_period(self):
        per = tp.clean_period({"name": "  Night\x00 shift ", "tz": "Europe/Copenhagen", "weekly": {"0": [[1320, 420]]}, "holidays": ["2026-12-25", "2026-12-25", "junk", "2026-02-30", 5, "2026-01-01"]},
                              new_id="tp-0a0b0c0d")
        self.assertEqual(per["id"], "tp-0a0b0c0d")
        self.assertEqual(per["name"], "Night  shift")
        self.assertEqual(per["holidays"], ["2026-01-01", "2026-12-25"])
        self.assertIsNone(per["tz_offset_min"])
        self.assertEqual(sorted(per["weekly"]), ["0", "1"])

    def test_a_name_is_cut_to_sixty_four_characters(self):
        self.assertEqual(len(tp.clean_period({"name": "n" * 100}, new_id="tp-0a0b0c0d")["name"]), 64)

    def test_a_server_with_no_time_zone_database_asks_for_an_offset(self):
        from unittest import mock
        with mock.patch.object(tp, "ZoneInfo", None):
            with self.assertRaises(ValueError) as cm:
                tp.clean_period({"name": "x", "tz": "Europe/Copenhagen"}, new_id="tp-0a0b0c0d")
            self.assertIn("no time zone database", str(cm.exception))
            self.assertEqual(tp.zone_of({"tz": "Europe/Copenhagen", "tz_offset_min": 60}).utcoffset(None), timedelta(minutes=60))
            self.assertIsNone(tp.zone_of({"tz": "Europe/Copenhagen"}))

    def test_holidays_are_capped_and_a_date_is_its_first_ten_characters(self):
        dates = [f"2026-{m:02d}-{d:02d}" for m in range(1, 13) for d in range(1, 21)]          # 240 different days
        self.assertEqual(len(tp.clean_period({"name": "x", "holidays": dates}, new_id="tp-0a0b0c0d")["holidays"]), tp.MAX_HOLIDAYS)
        per = tp.clean_period({"name": "x", "holidays": ["2026-12-25 (Christmas)", "2026-1-5", "2026-12-24T10:00", " 2026-12-31 ", "26-12-25"]}, new_id="tp-0a0b0c0d")
        self.assertEqual(per["holidays"], ["2026-12-24", "2026-12-25", "2026-12-31"], "a day that is not written yyyy-mm-dd is not a day")

    def test_what_is_refused_and_why(self):
        cases = ((None, "object"), ({"name": ""}, "name"), ({"name": "x" * 5, "id": "bad"}, "id"), ({"name": "x", "tz": "No/Such_Zone"}, "time zone"),
                 ({"name": "x", "tz": "../../etc/passwd"}, "IANA"), ({"name": "x", "tz": "Europe/Copenhagen", "tz_offset_min": "abc"}, "offset"),
                 ({"name": "x", "tz_offset_min": 5000}, "between"), ({"name": "x", "tz_offset_min": True}, "offset"))
        for raw, word in cases:
            with self.assertRaises(ValueError, msg=repr(raw)) as cm:
                tp.clean_period(raw, new_id="tp-0a0b0c0d")
            self.assertIn(word, str(cm.exception), raw)

    def test_a_list(self):
        made = iter(f"tp-{i:08x}" for i in range(1, 50))
        out = tp.clean_periods([{"name": "A", "weekly": {"0": [[0, 60]]}}, {"name": "B"}, {"id": "tp-deadbeef", "name": "C"}], lambda: next(made))
        self.assertEqual([p["id"] for p in out], ["tp-00000001", "tp-00000002", "tp-deadbeef"])
        ids = iter(f"tp-{i:08x}" for i in range(100, 200))
        for bad, word in (("x", "list"), ([{"name": "A"}, {"name": "a"}], "same name"), ([{"id": "tp-deadbeef", "name": "A"}, {"id": "tp-deadbeef", "name": "B"}], "same id"),
                          ([{"name": str(i)} for i in range(tp.MAX_PERIODS + 1)], "at most 50")):
            with self.assertRaises(ValueError) as cm:
                tp.clean_periods(bad, lambda: next(ids))
            self.assertIn(word, str(cm.exception))

    def test_a_given_id_is_kept_and_a_missing_one_is_made(self):
        made = []
        out = tp.clean_periods([{"id": "tp-0000abcd", "name": "A"}, {"name": "B"}], lambda: made.append(1) or "tp-11111111")
        self.assertEqual([p["id"] for p in out], ["tp-0000abcd", "tp-11111111"])
        self.assertEqual(len(made), 1, "an id is made for a period that has none, and for no other")

    def test_an_id_that_keeps_colliding_is_a_refusal_not_a_hang(self):
        with self.assertRaises(ValueError) as cm:
            tp.clean_periods([{"id": "tp-00000001", "name": "A"}, {"name": "B"}], lambda: "tp-00000001")
        self.assertIn("could not make an id", str(cm.exception))

    def test_a_made_id_that_collides_is_made_again(self):
        ids = iter(["tp-00000001", "tp-00000001", "tp-00000002"])
        out = tp.clean_periods([{"id": "tp-00000001", "name": "A"}, {"name": "B"}], lambda: next(ids))
        self.assertEqual([p["id"] for p in out], ["tp-00000001", "tp-00000002"])

    def test_find(self):
        periods = [{"id": "tp-00000001", "name": "A"}, "junk", {"id": "tp-00000002"}, {"id": "", "name": "blank"}]
        self.assertEqual(tp.find(periods, "tp-00000002"), {"id": "tp-00000002"})
        for pid in ("", None, 5, "tp-nope", ["tp-00000001"]):
            self.assertIsNone(tp.find(periods, pid))
        for lst in (None, "x", {}, 5):
            self.assertIsNone(tp.find(lst, "tp-00000001"))


class TestNextChange(unittest.TestCase):

    def test_the_next_edge(self):
        monday_noon = ts_of(2026, 11, 2, 12)
        self.assertEqual(tp.next_change(OFFICE, monday_noon), (ts_of(2026, 11, 2, 17, 0), False))
        monday_evening = ts_of(2026, 11, 2, 18)
        self.assertEqual(tp.next_change(OFFICE, monday_evening), (ts_of(2026, 11, 3, 9, 0), True))
        friday_evening = ts_of(2026, 11, 6, 18)
        self.assertEqual(tp.next_change(OFFICE, friday_evening), (ts_of(2026, 11, 9, 9, 0), True), "over the weekend")

    def test_the_last_day_asked_about_counts(self):
        tuesdays = {"tz_offset_min": 0, "weekly": weekdays({1: [(540, 600)]})}        # Tuesdays, 09:00-10:00
        monday_noon = ts_of(2026, 11, 2, 12)
        self.assertEqual(tp.next_change(tuesdays, monday_noon, days=1), (ts_of(2026, 11, 3, 9, 0), True))
        self.assertIsNone(tp.next_change(tuesdays, monday_noon, days=0), "today alone has no edge")

    def test_the_answer_is_a_whole_minute(self):
        t = ts_of(2026, 11, 2, 12, 0) + 37
        self.assertEqual(tp.next_change(OFFICE, t), (ts_of(2026, 11, 2, 17, 0), False))
        cph = dict(OFFICE, tz="Europe/Copenhagen", tz_offset_min=None)
        self.assertEqual(tp.next_change(cph, t)[0] % 60, 0)

    def test_a_holiday_moves_the_edge(self):
        per = dict(OFFICE, holidays=["2026-11-03"])
        self.assertEqual(tp.next_change(per, ts_of(2026, 11, 2, 18)), (ts_of(2026, 11, 4, 9, 0), True))
        inside = ts_of(2026, 11, 2, 12)
        self.assertEqual(tp.next_change(per, inside), (ts_of(2026, 11, 2, 17, 0), False))

    def test_never_changing(self):
        self.assertIsNone(tp.next_change({"weekly": {}}, ts_of(2026, 11, 2)))
        always = {"weekly": weekdays({d: [(0, 1440)] for d in range(7)})}
        self.assertIsNone(tp.next_change(always, ts_of(2026, 11, 2)), "on all week, no holidays: no edge in two weeks")
        self.assertIsNone(tp.next_change("x", 0))
        self.assertIsNone(tp.next_change(None, 0))

    def test_a_day_that_ends_at_midnight_joins_the_next(self):
        night = {"tz_offset_min": 0, "weekly": weekdays({0: [(1320, 1440)], 1: [(0, 420)]})}
        self.assertEqual(tp.next_change(night, ts_of(2026, 11, 2, 23, 0)), (ts_of(2026, 11, 3, 7, 0), False), "no gap at midnight")

    def test_in_a_named_zone(self):
        cph = dict(OFFICE, tz="Europe/Copenhagen", tz_offset_min=None)
        self.assertEqual(tp.next_change(cph, ts_of(2026, 11, 2, 9, 0)), (ts_of(2026, 11, 2, 16, 0), False), "17:00 CET")


if __name__ == "__main__":
    unittest.main()
