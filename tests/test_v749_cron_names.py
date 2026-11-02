#!/usr/bin/env python3
"""A maintenance window written with a day name opens (7.4.9), and one the matcher cannot read is refused.

The New maintenance window dialog's own placeholder was `0 3 * * SUN`. `_cron_matches` read numbers only, so a window saved that
way never opened, and with "Gate command/upgrade execution" ticked it held every command and upgrade for its hosts until someone
edited it. The validator did not notice: it checked the number of fields and nothing else. crontab accepts three-letter day and
month names, so the matcher now does too, and the validator refuses a field the matcher cannot evaluate, instead of saving a
schedule that never runs. Found by the documentation cross-check (docs3).
"""
import datetime
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-cron-"))
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v749_cron", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]


def at(y, mo, d, h=3, mi=0):
    return datetime.datetime(y, mo, d, h, mi).timestamp()


SUNDAY = at(2026, 11, 1)         # 2026-11-01 is a Sunday
MONDAY = at(2026, 11, 2)
JULY_SUNDAY = at(2026, 7, 5)     # 2026-07-05 is a Sunday


class TestNamesAreRead(unittest.TestCase):

    def test_sun_opens_on_sunday_and_not_on_monday(self):
        self.assertTrue(api._cron_matches("0 3 * * SUN", SUNDAY))
        self.assertFalse(api._cron_matches("0 3 * * SUN", MONDAY))

    def test_case_does_not_matter(self):
        for spec in ("0 3 * * sun", "0 3 * * Sun", "0 3 * * SUN"):
            with self.subTest(spec=spec):
                self.assertTrue(api._cron_matches(spec, SUNDAY))

    def test_ranges_and_lists_of_names(self):
        self.assertTrue(api._cron_matches("0 3 * * MON-FRI", MONDAY))
        self.assertFalse(api._cron_matches("0 3 * * MON-FRI", SUNDAY))
        self.assertTrue(api._cron_matches("0 3 * * SAT,SUN", SUNDAY))
        self.assertFalse(api._cron_matches("0 3 * * SAT,SUN", MONDAY))

    def test_month_names(self):
        self.assertTrue(api._cron_matches("0 3 * JUL SUN", JULY_SUNDAY))
        self.assertFalse(api._cron_matches("0 3 * JUL SUN", SUNDAY))
        self.assertTrue(api._cron_matches("0 3 * jan,jul sun", JULY_SUNDAY))

    def test_numbers_behave_as_they_did(self):
        self.assertTrue(api._cron_matches("0 3 * * 0", SUNDAY))
        self.assertTrue(api._cron_matches("0 3 * * 7", SUNDAY), "7 is Sunday in every crontab")
        self.assertTrue(api._cron_matches("0 3 * * 1-5", MONDAY))
        self.assertFalse(api._cron_matches("0 3 * * 1-5", SUNDAY))
        self.assertTrue(api._cron_matches("*/15 * * * *", at(2026, 11, 2, 9, 30)))
        self.assertFalse(api._cron_matches("*/15 * * * *", at(2026, 11, 2, 9, 31)))

    def test_a_word_that_is_not_a_name_matches_nothing(self):
        self.assertFalse(api._cron_matches("0 3 * * SUNDAY", SUNDAY))
        self.assertFalse(api._cron_matches("0 3 * * FOO", SUNDAY))


class TestTheValidatorRefusesWhatCannotRun(unittest.TestCase):

    def unreadable(self, cron):
        return api._cron_unreadable_field(cron)

    def test_readable_expressions(self):
        for cron in ("0 3 * * SUN", "0 3 * * 0", "*/15 * * * *", "0 22 * * 1-5", "0 3 1 */3 *", "0 9 * * mon-fri",
                     "5,35 * * * *", "0 0 * JAN,JUL *", "30 2 * * 7", "0-30/10 * * * *"):
            with self.subTest(cron=cron):
                self.assertIsNone(self.unreadable(cron))

    def test_unreadable_expressions_name_the_field(self):
        cases = {"0 3 * * FOO": "FOO", "0 3 * * SUNDAY": "SUNDAY", "61 * * * *": "61", "0 24 * * *": "24",
                 "0 3 32 * *": "32", "0 3 * 13 *": "13", "0 3 * * 8": "8", "*/0 * * * *": "*/0", "0 3 * * 5-1": "5-1",
                 "0 3 * * ,": ",", "0 3 * * /5": "/5", "a * * * *": "a"}
        for cron, bad in cases.items():
            with self.subTest(cron=cron):
                self.assertEqual(self.unreadable(cron), bad)

    def test_every_expression_the_validator_reads_the_matcher_can_evaluate(self):
        # the pair must agree: a readable expression matches on some minute of a year, an unreadable one never can.
        # Candidates: minute 0 and minute 7 of every hour of 2026.
        base = datetime.datetime(2026, 1, 1)
        minutes = [(base + datetime.timedelta(hours=h, minutes=m)).timestamp() for h in range(366 * 24) for m in (0, 7)]
        for cron in ("0 3 * * SUN", "0 3 * * 0", "7 4 1 */3 *", "0 9 * * mon-fri"):
            with self.subTest(cron=cron):
                self.assertIsNone(self.unreadable(cron))
                self.assertTrue(any(api._cron_matches(cron, m) for m in minutes))
        for cron in ("0 3 * * FOO", "0 3 * * SUNDAY"):
            with self.subTest(cron=cron):
                self.assertIsNotNone(self.unreadable(cron))
                self.assertFalse(any(api._cron_matches(cron, m) for m in minutes))


class TestTheMaintenanceEndpointsRefuseIt(unittest.TestCase):

    def respond_of(self, body):
        class Captured(SystemExit):
            def __init__(self, status, data):
                super().__init__(0)
                self.status, self.data = status, data

        def fake(status, data):
            raise Captured(status, data)
        real = api.respond
        setattr(api, "respond", fake)
        try:
            api._validate_maintenance_body(body)
        except Captured as c:
            return c.status, c.data
        finally:
            setattr(api, "respond", real)
        return 200, None

    def test_a_window_that_could_never_open_is_refused_with_a_reason(self):
        status, data = self.respond_of({"scope": "global", "cron": "0 3 * * FOO", "duration": 3600})
        self.assertEqual(status, 400)
        self.assertEqual(data["field"], "FOO", "the field that is not understood rides in its own key; the sentence is fixed so it can be translated")
        self.assertIn("MON", data["error"], "the message says what is understood")

    def test_the_dialogs_own_placeholder_is_accepted(self):
        status, _ = self.respond_of({"scope": "global", "cron": "0 3 * * SUN", "duration": 3600})
        self.assertEqual(status, 200)

    def test_the_field_count_is_still_checked(self):
        status, data = self.respond_of({"scope": "global", "cron": "0 3 * *", "duration": 3600})
        self.assertEqual(status, 400)
        self.assertIn("5 space-separated fields", data["error"])


if __name__ == "__main__":
    unittest.main()
