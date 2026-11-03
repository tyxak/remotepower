#!/usr/bin/env python3
"""7.4.9: named time periods on the server: where they are saved, and the four places that read them.

Quiet hours, after-hours detection, the ticket SLA clock and maintenance windows each used to hold their own idea of "when". They
now read one thing (time_periods.py, tested on its own in test_v749_time_periods), and each can point at a named period. These tests
drive the real handlers: the settings save with its checks, the reads, and a period that something still uses.
"""
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import api  # noqa: E402
from test_v743_disk_io import _call  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def at(y, mo, d, h=0, mi=0):
    return int(datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp())


OFFICE = {"name": "Office hours", "tz": "", "tz_offset_min": 0, "weekly": {str(d): [[540, 1020]] for d in range(5)}, "holidays": []}
MON_NOON, MON_NIGHT, SAT_NOON = at(2026, 11, 2, 12), at(2026, 11, 2, 23), at(2026, 11, 7, 12)
SAT_NIGHT, SUN_EARLY = at(2026, 11, 7, 23), at(2026, 11, 8, 3)


class _Base(unittest.TestCase):

    def setUp(self):
        self._keep = {n: getattr(api, n) for n in ("respond", "audit_log", "verify_token", "get_token_from_request")}
        api.save(api.CONFIG_FILE, {})
        api.save(api.MAINT_FILE, {"windows": []})
        api.save(api.AFTER_HOURS_FILE, {"hits": []})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._keep.items():
            setattr(api, n, v)
        api.save(api.CONFIG_FILE, {})
        api.save(api.MAINT_FILE, {"windows": []})
        api.save(api.AFTER_HOURS_FILE, {"hits": []})
        api._LOAD_CACHE.clear()

    def server_zone(self, name):
        """The time zone of the process for this test, put back afterwards."""
        import os
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

    def save(self, body):
        box = _call(api.handle_config_save, body)
        api._LOAD_CACHE.clear()
        return box["status"], box.get("body") or {}

    def cfg(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CONFIG_FILE) or {}

    def make(self, **extra):
        """Save one period and return its stored form (with the id the server made)."""
        st, body = self.save({"time_periods": [dict(OFFICE, **extra)]})
        self.assertEqual(st, 200, body)
        return self.cfg()["time_periods"][0]


class TestSavingPeriods(_Base):

    def test_a_period_is_saved_and_given_an_id(self):
        per = self.make()
        self.assertRegex(per["id"], r"^tp-[0-9a-f]{8}$")
        self.assertEqual((per["name"], per["weekly"]["0"], per["tz"], per["holidays"]), ("Office hours", [[540, 1020]], "", []))

    def test_an_edit_keeps_the_id_and_a_new_one_gets_its_own(self):
        first = self.make()
        st, _ = self.save({"time_periods": [dict(first, name="Day shift"), dict(OFFICE, name="Night shift")]})
        self.assertEqual(st, 200)
        got = self.cfg()["time_periods"]
        self.assertEqual((got[0]["id"], got[0]["name"]), (first["id"], "Day shift"))
        self.assertNotIn(got[1]["id"], (first["id"], ""))

    def test_what_cannot_be_used_is_refused_with_the_reason(self):
        for body, word in (({"time_periods": "x"}, "list"), ({"time_periods": [{"name": ""}]}, "name"), ({"time_periods": [dict(OFFICE, tz="No/Such_Place")]}, "time zone"),
                           ({"time_periods": [dict(OFFICE), dict(OFFICE)]}, "same name"), ({"time_periods": [dict(OFFICE, id="mine")]}, "id"),
                           ({"time_periods": [dict(OFFICE, tz_offset_min=99999)]}, "between"), ({"time_periods": [dict(OFFICE, name=str(i)) for i in range(60)]}, "at most 50")):
            st, resp = self.save(body)
            self.assertEqual(st, 400, body)
            self.assertEqual(resp["field"], "time_periods", resp)
            self.assertIn(word, resp["error"], body)
        self.assertEqual(self.cfg().get("time_periods", []), [])

    def test_a_refused_save_changes_nothing_else(self):
        st, _ = self.save({"time_periods": [dict(OFFICE, name="")], "server_name": "changed"})
        self.assertEqual(st, 400)
        self.assertNotEqual(self.cfg().get("server_name"), "changed")

    def test_the_read_has_the_list_and_an_empty_one_by_default(self):
        box = _call(api.handle_config_get, {}, verb="GET")
        self.assertEqual(box["body"]["time_periods"], [])
        per = self.make()
        box = _call(api.handle_config_get, {}, verb="GET")
        self.assertEqual([p["id"] for p in box["body"]["time_periods"]], [per["id"]])

    def test_hostile_values_do_not_get_in(self):
        per = self.make(name="<img src=x onerror=1>\x00", weekly={"0": [[0, 99999], ["x"], "junk"], "9": [[1, 2]]}, holidays=["2026-02-30", "x", "2026-12-25"], tz="")
        self.assertEqual(per["name"], "<img src=x onerror=1>")        # text; the page escapes it
        self.assertEqual(per["weekly"], {"0": [[0, 1440]]})
        self.assertEqual(per["holidays"], ["2026-12-25"])

    def test_config_as_code_carries_them(self):
        self.make()
        box = _call(api.handle_config_declarative, {}, verb="GET")
        self.assertEqual([p["name"] for p in box["body"]["resources"]["time_periods"]], ["Office hours"])
        self.assertIn("time_periods", api._declarative_meta())


class TestWhatUsesAPeriod(_Base):

    def point(self, per, key):
        body = {"quiet_hours": {"enabled": True, "period": per["id"], "min_severity": "critical"},
                "after_hours": {"enabled": True, "period": per["id"], "events": []},
                "ticket_business_hours": {"enabled": True, "period": per["id"]}}[key]
        st, resp = self.save({key: body})
        self.assertEqual(st, 200, resp)

    def test_each_of_the_four_stops_the_removal(self):
        per = self.make()
        for key, phrase in (("quiet_hours", "quiet hours"), ("after_hours", "after-hours detection"), ("ticket_business_hours", "the ticket SLA calendar")):
            self.point(per, key)
            st, resp = self.save({"time_periods": []})
            self.assertEqual(st, 400, key)
            self.assertIn(phrase, resp["error"])
            self.assertEqual(len(self.cfg()["time_periods"]), 1, "and it is still there")
            self.save({key: {"enabled": False, "period": ""}})
        st, _ = self.save({"time_periods": []})
        self.assertEqual(st, 200)

    def test_a_maintenance_window_stops_the_removal(self):
        per = self.make()
        box = _call(api.handle_maintenance_add, {"reason": "weekly", "scope": "global", "period": per["id"]})
        self.assertEqual(box["status"], 200, box)
        st, resp = self.save({"time_periods": []})
        self.assertEqual(st, 400)
        self.assertIn("1 maintenance window", resp["error"])

    def test_a_window_that_follows_another_period_does_not_stop_the_removal(self):
        a = self.make(name="A")
        st, resp = self.save({"time_periods": [dict(OFFICE, name="A", id=a["id"]), dict(OFFICE, name="B", id="tp-0b0b0b0b")]})
        self.assertEqual(st, 200, resp)
        box = _call(api.handle_maintenance_add, {"reason": "weekly", "scope": "global", "period": "tp-0b0b0b0b"})
        self.assertEqual(box["status"], 200, box)
        st, resp = self.save({"time_periods": [dict(OFFICE, name="B", id="tp-0b0b0b0b")]})
        self.assertEqual(st, 200, resp)                  # A goes: the window follows B

    def test_one_save_can_stop_using_a_period_and_remove_it(self):
        per = self.make()
        self.point(per, "quiet_hours")
        st, resp = self.save({"time_periods": [], "quiet_hours": {"enabled": False, "period": "", "start": "22:00", "end": "07:00"}})
        self.assertEqual(st, 200, resp)
        self.assertEqual(self.cfg()["time_periods"], [])

    def test_one_save_can_add_a_period_and_use_it(self):
        st, resp = self.save({"time_periods": [dict(OFFICE, id="tp-0a0b0c0d")], "quiet_hours": {"enabled": True, "period": "tp-0a0b0c0d"}})
        self.assertEqual(st, 200, resp)
        self.assertEqual(self.cfg()["quiet_hours"]["period"], "tp-0a0b0c0d")

    def test_a_period_that_does_not_exist_can_not_be_chosen(self):
        for key, body in (("quiet_hours", {"enabled": True, "period": "tp-deadbeef"}), ("after_hours", {"enabled": True, "period": "tp-deadbeef"}),
                          ("ticket_business_hours", {"enabled": True, "period": "tp-deadbeef"})):
            st, resp = self.save({key: body})
            self.assertEqual(st, 400, key)
            self.assertEqual((resp["error"], resp["field"]), ("that time period does not exist", key))

    def test_the_times_are_not_needed_when_a_period_is_chosen(self):
        per = self.make()
        st, _ = self.save({"quiet_hours": {"enabled": True, "period": per["id"], "start": "", "end": ""}})
        self.assertEqual(st, 200)
        st, _ = self.save({"quiet_hours": {"enabled": True, "period": "", "start": "", "end": ""}})
        self.assertEqual(st, 400, "and they are when none is")


class TestQuietHours(_Base):

    def held(self, ts, **qh):
        api.save(api.CONFIG_FILE, dict(self.cfg(), quiet_hours=dict({"enabled": True, "min_severity": "critical"}, **qh)))
        api._LOAD_CACHE.clear()
        return api._quiet_hours_active("config_drift", {"device_id": "x"}, self.cfg(), now=ts)

    def test_the_hours_of_a_period(self):
        night = self.make(name="Night", weekly={str(d): [[1320, 1440], [0, 420]] for d in range(7)})
        self.assertEqual(self.held(MON_NIGHT, period=night["id"]), "Night")
        self.assertIsNone(self.held(MON_NOON, period=night["id"]))

    def test_a_period_that_is_gone_holds_nothing(self):
        self.make()
        self.assertIsNone(self.held(MON_NIGHT, period="tp-deadbeef"))

    def test_the_period_wins_over_the_times(self):
        per = self.make()        # office hours: quiet during the day
        self.assertEqual(self.held(MON_NOON, period=per["id"], start="22:00", end="07:00"), "Office hours")
        self.assertIsNone(self.held(MON_NIGHT, period=per["id"], start="22:00", end="07:00"))

    def test_the_times_still_work_with_no_period(self):
        import os
        real = os.environ.get("TZ")
        self.addCleanup(lambda: (os.environ.__setitem__("TZ", real) if real is not None else os.environ.pop("TZ", None), time.tzset()))
        os.environ["TZ"] = "UTC"
        time.tzset()
        self.assertEqual(self.held(MON_NIGHT, start="22:00", end="07:00"), "22:00-07:00")
        self.assertIsNone(self.held(MON_NOON, start="22:00", end="07:00"))
        self.assertEqual(self.held(SAT_NIGHT, start="22:00", end="07:00"), "22:00-07:00", "every day of the week, as quiet hours always were")
        self.assertEqual(self.held(SUN_EARLY, start="22:00", end="07:00"), "22:00-07:00")
        self.assertIsNone(self.held(MON_NIGHT, start="22:00", end="22:00"), "equal times are an empty range")
        self.assertIsNone(self.held(MON_NIGHT, start="22", end="07"))

    def test_a_severe_event_is_never_held(self):
        per = self.make(weekly={str(d): [[0, 1440]] for d in range(7)})
        api.save(api.CONFIG_FILE, dict(self.cfg(), quiet_hours={"enabled": True, "period": per["id"], "min_severity": "high"}))
        api._LOAD_CACHE.clear()
        self.assertIsNone(api._quiet_hours_active("ssh_key_added", {"device_id": "x"}, self.cfg(), now=MON_NOON), "an event at the high line passes through")
        self.assertEqual(api._quiet_hours_active("config_drift", {"device_id": "x"}, self.cfg(), now=MON_NOON), "Office hours", "and a medium one is held")

    def test_switched_off_holds_nothing(self):
        per = self.make(weekly={str(d): [[0, 1440]] for d in range(7)})
        self.assertIsNone(self.held(MON_NOON, enabled=False, period=per["id"]))


class TestAfterHours(_Base):

    def record(self, ts, **ah):
        api.save(api.CONFIG_FILE, dict(self.cfg(), after_hours=dict({"enabled": True, "events": ["ssh_key_added"]}, **ah)))
        api._LOAD_CACHE.clear()
        api.save(api.AFTER_HOURS_FILE, {"hits": []})
        with mock.patch.object(api.time, "time", return_value=ts):
            api._record_after_hours("ssh_key_added", {"device_name": "web1"}, self.cfg())
        api._LOAD_CACHE.clear()
        return len((api.load(api.AFTER_HOURS_FILE) or {}).get("hits") or [])

    def test_outside_the_period_is_recorded_and_inside_is_not(self):
        per = self.make()
        self.assertEqual(self.record(MON_NOON, period=per["id"]), 0)
        self.assertEqual(self.record(MON_NIGHT, period=per["id"]), 1)
        self.assertEqual(self.record(SAT_NOON, period=per["id"]), 1, "a Saturday is outside Monday to Friday")

    def test_a_period_that_is_gone_records_nothing(self):
        self.make()
        self.assertEqual(self.record(MON_NIGHT, period="tp-deadbeef"), 0)

    def test_the_times_and_the_working_days_still_work(self):
        import os
        real = os.environ.get("TZ")
        self.addCleanup(lambda: (os.environ.__setitem__("TZ", real) if real is not None else os.environ.pop("TZ", None), time.tzset()))
        os.environ["TZ"] = "UTC"
        time.tzset()
        ah = {"start": "09:00", "end": "17:00", "workdays": [0, 1, 2, 3, 4]}
        self.assertEqual(self.record(MON_NOON, **ah), 0)
        self.assertEqual(self.record(MON_NIGHT, **ah), 1)
        self.assertEqual(self.record(SAT_NOON, **ah), 1)
        self.assertEqual(self.record(MON_NOON, start="09:00", end="09:00", workdays=[0, 1, 2, 3, 4]), 1, "equal times: never in business hours, as before")

    def test_an_event_that_is_not_watched_is_not_recorded(self):
        per = self.make()
        api.save(api.CONFIG_FILE, dict(self.cfg(), after_hours={"enabled": True, "events": ["other_event"], "period": per["id"]}))
        api._LOAD_CACHE.clear()
        with mock.patch.object(api.time, "time", return_value=MON_NIGHT):
            api._record_after_hours("ssh_key_added", {}, self.cfg())
        self.assertEqual((api.load(api.AFTER_HOURS_FILE) or {}).get("hits"), [])


class TestTicketClock(_Base):

    def due(self, created, hours):
        api._LOAD_CACHE.clear()
        return api._ticket_sla({"created_at": created, "priority": 3, "status": "ongoing", "type": "incident"}, {3: hours})[0]

    def test_the_clock_follows_the_period(self):
        per = self.make()
        api.save(api.CONFIG_FILE, dict(self.cfg(), ticket_business_hours={"enabled": True, "period": per["id"]}))
        # Friday 16:00, two hours of work: one on Friday, one on Monday morning
        self.assertEqual(self.due(at(2026, 11, 6, 16), 2), at(2026, 11, 9, 10))

    def test_a_period_in_a_named_zone_follows_summer_time(self):
        per = self.make(tz="Europe/Copenhagen", tz_offset_min=None)
        api.save(api.CONFIG_FILE, dict(self.cfg(), ticket_business_hours={"enabled": True, "period": per["id"]}))
        self.assertEqual(self.due(at(2026, 10, 23, 14), 2), at(2026, 10, 26, 9), "16:00 CEST on the Friday before the clocks go back, 10:00 CET on the Monday")

    def test_a_period_that_is_gone_falls_back_to_the_calendar_typed_here(self):
        api.save(api.CONFIG_FILE, {"ticket_business_hours": {"enabled": True, "period": "tp-deadbeef", "tz_offset_min": 0,
                                                              "weekly": {str(d): [[540, 1020]] for d in range(5)}, "holidays": []}})
        self.assertEqual(self.due(at(2026, 11, 6, 16), 2), at(2026, 11, 9, 10))

    def test_switched_off_is_plain_elapsed_time(self):
        per = self.make()
        api.save(api.CONFIG_FILE, dict(self.cfg(), ticket_business_hours={"enabled": False, "period": per["id"]}))
        self.assertEqual(self.due(at(2026, 11, 6, 16), 2), at(2026, 11, 6, 18))

    def test_a_calendar_typed_here_with_no_offset_is_read_in_utc_whatever_the_server_clock_says(self):
        self.server_zone("Asia/Tokyo")
        api.save(api.CONFIG_FILE, {"ticket_business_hours": {"enabled": True, "weekly": {str(d): [[540, 1020]] for d in range(5)}, "holidays": []}})
        # Wednesday 08:30 UTC is before the hours in UTC (09:00) and after them in Tokyo (17:30): the hour of work starts at 09:00 UTC
        self.assertEqual(self.due(at(2026, 11, 4, 8, 30), 1), at(2026, 11, 4, 10))

    def test_the_old_calendar_with_no_offset_is_read_in_utc(self):
        api.save(api.CONFIG_FILE, {"ticket_business_hours": {"enabled": True, "weekly": {str(d): [[540, 1020]] for d in range(5)}, "holidays": []}})
        self.assertEqual(self.due(at(2026, 11, 6, 16), 2), at(2026, 11, 9, 10))


class TestTheCalendarTypedHere(_Base):
    """The hours typed under Settings -> Tickets are saved by the same settings call, and read with the cleaner a time period uses:
    up to six ranges a day, a range across midnight split over the two days, ranges that touch joined. Until 7.4.9 the call had a
    loop of its own that dropped a range across midnight without a word, and the page showed and saved only the first range of a
    day, so a calendar with a lunch break lost the rest the next time anyone pressed Save."""

    def hours(self, weekly, **extra):
        st, body = self.save({"ticket_business_hours": dict({"enabled": True, "tz_offset_min": 0, "weekly": weekly, "holidays": []}, **extra)})
        self.assertEqual(st, 200, body)
        return self.cfg()["ticket_business_hours"]["weekly"]

    def due(self, created, hours):
        api._LOAD_CACHE.clear()
        return api._ticket_sla({"created_at": created, "priority": 3, "status": "ongoing", "type": "incident"}, {3: hours})[0]

    def test_a_day_with_a_lunch_break_keeps_both_ranges(self):
        self.assertEqual(self.hours({"0": [[540, 720], [780, 1020]]})["0"], [[540, 720], [780, 1020]])

    def test_the_clock_pauses_for_the_break(self):
        self.hours({str(d): [[540, 720], [780, 1020]] for d in range(5)})
        # Monday 2026-11-02, created 11:00, two hours of work: one until noon, then none until 13:00, then one more
        self.assertEqual(self.due(at(2026, 11, 2, 11), 2), at(2026, 11, 2, 14))
        # the same calendar with one range 09:00-17:00 would be due at 13:00
        self.hours({str(d): [[540, 1020]] for d in range(5)})
        self.assertEqual(self.due(at(2026, 11, 2, 11), 2), at(2026, 11, 2, 13))

    def test_six_ranges_a_day_are_kept_and_a_seventh_is_cut(self):
        six = [[60 * h, 60 * h + 30] for h in range(8, 20, 2)]
        self.assertEqual(len(six), 6)
        self.assertEqual(self.hours({"1": six})["1"], six)
        seven = six + [[1300, 1320]]
        self.assertEqual(self.hours({"1": seven})["1"], six, "the seventh is the one that goes")

    def test_a_range_across_midnight_is_split_over_the_two_days(self):
        w = self.hours({"4": [[1320, 360]]})           # Friday 22:00 to 06:00
        self.assertEqual(w, {"4": [[1320, 1440]], "5": [[0, 360]]})
        w = self.hours({"6": [[1320, 360]]})           # Sunday night runs into Monday
        self.assertEqual(w, {"6": [[1320, 1440]], "0": [[0, 360]]})

    def test_the_clock_runs_through_the_night_shift(self):
        self.hours({"0": [[1320, 360]]})
        # Monday 22:00 created, 3 hours of work: Monday 22:00 -> 24:00 is two, then Tuesday 00:00 -> 01:00 is the third... on a calendar
        # that is open Monday night and Tuesday early (the split puts 0-360 on TUESDAY, which is not in this calendar)
        self.assertEqual(self.due(at(2026, 11, 2, 22), 2), at(2026, 11, 3, 0))

    def test_ranges_that_touch_or_overlap_are_joined(self):
        self.assertEqual(self.hours({"2": [[540, 720], [720, 1020]]})["2"], [[540, 1020]])
        self.assertEqual(self.hours({"2": [[540, 800], [700, 1020]]})["2"], [[540, 1020]])
        self.assertEqual(self.hours({"2": [[780, 1020], [540, 720]]})["2"], [[540, 720], [780, 1020]], "and they are sorted")

    def test_what_is_not_a_range_is_left_out_without_failing_the_save(self):
        w = self.hours({"0": [[-5, 30], [540, 1020], [1500, 1600], [600, 600], [], [5]], "x": [[1, 2]], "9": [[1, 2]], "3": "no"})
        self.assertEqual(w, {"0": [[0, 30], [540, 1020]]},
                         "-5 reads as the start of the day, 1500 to 1600 as an empty range at its end, 600 to 600 as an empty one")
        self.assertEqual(self.hours({"1": [["a", "b"], None, 7, "x", {"a": 1}, [540, 600]]}), {"1": [[540, 600]]})
        for junk in (None, [], "text", 5, True, [[540, 1020]]):
            self.assertEqual(self.hours(junk), {}, repr(junk))

    def test_a_calendar_with_one_range_a_day_is_unchanged(self):
        self.assertEqual(self.hours({str(d): [[540, 1020]] for d in range(5)}), {str(d): [[540, 1020]] for d in range(5)})

    def test_a_day_with_no_range_is_closed(self):
        w = self.hours({"0": [[540, 1020]], "1": []})
        self.assertEqual(w, {"0": [[540, 1020]]})


class TestMaintenanceWindows(_Base):

    def add(self, **body):
        return _call(api.handle_maintenance_add, dict({"reason": "weekly change", "scope": "global"}, **body))

    def test_a_window_that_follows_a_period(self):
        per = self.make(name="Sunday change window", weekly={"6": [[120, 300]]})        # Sunday 02:00 to 05:00 UTC
        box = self.add(period=per["id"])
        self.assertEqual(box["status"], 200, box)
        w = box["body"]["window"]
        self.assertEqual((w["period"], w["cron"], w["start"]), (per["id"], "", ""))
        self.assertTrue(api._window_active(w, at(2026, 11, 8, 3)))
        self.assertFalse(api._window_active(w, at(2026, 11, 8, 6)))
        self.assertFalse(api._window_active(w, at(2026, 11, 9, 3)), "Monday")

    def test_a_window_whose_period_is_gone_is_never_open(self):
        per = self.make(weekly={str(d): [[0, 1440]] for d in range(7)})
        w = self.add(period=per["id"])["body"]["window"]
        self.save({"time_periods": []})            # refused while the window uses it
        self.assertEqual(len(self.cfg()["time_periods"]), 1)
        api.save(api.CONFIG_FILE, dict(self.cfg(), time_periods=[]))     # removed behind the check, as a hand edit would
        api._LOAD_CACHE.clear()
        self.assertFalse(api._window_active(w, MON_NOON))

    def test_the_ways_to_say_when_are_exclusive(self):
        per = self.make()
        cases = ((dict(period=per["id"], cron="0 3 * * SUN", duration=60), "not both"), (dict(period=per["id"], start="2026-11-08T02:00:00Z", end="2026-11-08T05:00:00Z"), "not both"),
                 (dict(period="tp-deadbeef"), "does not exist"), (dict(), "specify exactly one"), (dict(start="2026-11-08T02:00:00Z", end="2026-11-08T05:00:00Z", cron="0 3 * * *", duration=60), "specify exactly one"))
        for body, word in cases:
            box = self.add(**body)
            self.assertEqual(box["status"], 400, body)
            self.assertIn(word, box["body"]["error"], body)

    def test_the_old_kinds_are_unchanged(self):
        box = self.add(cron="0 3 * * SUN", duration=60)
        self.assertEqual((box["status"], box["body"]["window"]["period"]), (200, ""))
        box = self.add(start="2026-11-08T02:00:00Z", end="2026-11-08T05:00:00Z")
        self.assertEqual(box["status"], 200)

    def test_an_edit_keeps_or_changes_the_period(self):
        st, _ = self.save({"time_periods": [dict(OFFICE), dict(OFFICE, name="Other")]})
        self.assertEqual(st, 200)
        per, other = self.cfg()["time_periods"]
        wid = self.add(period=per["id"])["body"]["window"]["id"]
        box = _call(api.handle_maintenance_update, {"reason": "weekly change", "scope": "global", "period": per["id"]}, wid, verb="PUT")
        self.assertEqual(box["status"], 200, box)
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.MAINT_FILE)["windows"][0]["period"]), per["id"])
        box = _call(api.handle_maintenance_update, {"reason": "weekly change", "scope": "global", "period": other["id"]}, wid, verb="PUT")
        self.assertEqual(box["status"], 200, box)
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.MAINT_FILE)["windows"][0]["period"]), other["id"])

    def test_the_list_names_the_period(self):
        per = self.make(name="Sunday change window", weekly={"6": [[120, 300]]})
        self.add(period=per["id"])
        box = _call(api.handle_maintenance_list, {}, verb="GET")
        w = box["body"]["windows"][0]
        self.assertEqual((w["period"], w["period_name"]), (per["id"], "Sunday change window"))

    def test_the_calendar_shows_when_it_next_opens(self):
        per = self.make(name="Sunday change window", weekly={"6": [[120, 300]]})
        self.add(period=per["id"])
        now = at(2026, 11, 3, 12)       # a Tuesday
        windows = (api.load(api.MAINT_FILE) or {}).get("windows") or []
        self.assertTrue(windows)
        nxt = api.time_periods_mod.next_change(api._period_by_id(per["id"]), now, 14)
        self.assertEqual(nxt, (at(2026, 11, 8, 2), True))

    def test_the_period_is_in_the_request_model(self):
        import request_models
        if getattr(request_models, "MaintenanceAddRequest", None) is None:
            self.skipTest("pydantic is not installed")
        self.assertIn("period", request_models.MaintenanceAddRequest.model_fields)


class TestNothingIsLeftOut(unittest.TestCase):
    """Every place that read a window's times by itself is on the one reading now."""

    def test_the_older_checks_do_not_compare_clock_strings_any_more(self):
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        for fn in ("_quiet_hours_active", "_record_after_hours"):
            i = src.index(f"def {fn}(")
            body = src[i:src.index("\ndef ", i + 10)]
            self.assertNotIn("_in_time_window(", body, fn)
            self.assertIn("time_periods_mod.is_active(", body, fn)
        t = (ROOT / "server" / "cgi-bin" / "tickets_handlers.py").read_text()
        self.assertIn("time_periods_mod.business_deadline(", t)
        self.assertNotIn("timedelta(", t)


if __name__ == "__main__":
    unittest.main()
