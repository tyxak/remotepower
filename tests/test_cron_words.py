#!/usr/bin/env python3
"""A cron expression in words (cronWords / cronHtml in app.js, run under node).

Four tables showed the raw expression (`0 3 * * 0`) and left the reading to the operator: Auto-patch, Schedule, Maintenance and
Backups. They show words now ("Sundays at 03:00") with the expression under them. Wrong words are worse than none, so the helper
words the common shapes and returns '' for the rest, and the caller then shows the expression alone.

Three kinds of test:

* a table of hand-written cases, both directions (the words, and the shapes that must stay unworded);
* a property test over 63,360 expressions: the words are a function of the schedule and the schedule is a function of the words. The
  schedule is worked out by a second, plain implementation of cron's matching rules in this file (a year of days, the minutes of a
  day), not by reading the words. Two expressions that fire at the same times must read the same, and two that fire at different
  times must not: that is what catches Monday called Sunday, a list squashed into a range, or the day-of-month / weekday "either"
  rule worded as "both";
* the cell markup, and the four sites that use it.

The rendered half (the four pages of the seeded demo) is in test_sidebar_page_fixes_e2e.py.
"""
import functools
import itertools
import json
import math
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which('node')
_APP = (_JS / 'app.js').read_text(encoding='utf-8')
_BACKUPS = (_JS / 'app-backups.js').read_text(encoding='utf-8')


def _run_node(script, driver):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / 'run.js'
        p.write_text(script + '\n' + driver)
        r = subprocess.run([str(_NODE), str(p)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def words_of(exprs, fn_name='cronWords', extra=''):
    script = srcpin.js_function(_APP, 'cronWords') + '\n' + extra
    return _run_node(script, f'console.log(JSON.stringify({json.dumps(list(exprs))}.map(e => {fn_name}(e))));')


# ── a second implementation of cron's matching rules, for the property test ────────────────────────────────────────
_MON = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
_DOW = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
_DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]          # a year that is not a leap year


def _values(text, lo, hi, names=None):
    """The values a cron field matches, and whether it starts with `*` (Vixie cron's "star" flag)."""
    def num(t):
        if t.isdigit():
            return int(t)
        return names.index(t) + (1 if names is _MON else 0)
    out = set()
    for item in text.split(','):
        step = 1
        if '/' in item:
            item, s = item.split('/')
            step = int(s)
        if item == '*':
            a, b = lo, hi
        elif '-' in item:
            x, y = item.split('-')
            a, b = num(x), num(y)
        else:
            a = b = num(item)
        out.update(range(a, b + 1, step))
    return out, text.startswith('*')


@functools.lru_cache(maxsize=None)
def _times(m, h):
    ms, _ = _values(m, 0, 59)
    hs, _ = _values(h, 0, 23)
    return frozenset(hh * 60 + mm for hh in hs for mm in ms)


@functools.lru_cache(maxsize=None)
def _days(dom, mon, dow):
    doms, dom_star = _values(dom, 1, 31)
    mons, _ = _values(mon, 1, 12, _MON)
    dows, dow_star = _values(dow, 0, 7, _DOW)
    dows = {0 if d == 7 else d for d in dows}
    days = set()
    n = 0
    for month, length in enumerate(_DAYS_IN_MONTH, start=1):
        for day in range(1, length + 1):
            weekday = (n + 4) % 7                                         # 1 January 2026 is a Thursday
            ok_dom, ok_dow = day in doms, weekday in dows
            # either field, unless one of them starts with `*`: then both
            day_ok = (ok_dom and ok_dow) if (dom_star or dow_star) else (ok_dom or ok_dow)
            if month in mons and day_ok:
                days.add(n)
            n += 1
    return frozenset(days)


def schedule_of(expr):
    """(minutes of the day it fires at, days of a year it fires on) for a five-field expression."""
    m, h, dom, mon, dow = expr.split()
    return _times(m, h), _days(dom, mon, dow)


_POOL = {
    'm': ['*', '*/5', '*/15', '*/30', '0', '15', '30', '0,30', '5,35', '*/7'],
    'h': ['*', '*/2', '*/6', '*/5', '0', '3', '22', '2,14', '9-17', '0-23', '1,13-15', '1-5'],
    'dom': ['*', '1', '15', '1,15', '25', '1-31', '*/2', '31'],
    'mon': ['*', '6', '12', '1,7', 'jun-aug', '1-12'],
    'dow': ['*', '0', '7', '1', '1-5', '6,0', '1,3,5', '0-6', 'mon-fri', 'sun', '*/2'],
}


def _all_expressions():
    return [' '.join(parts) for parts in itertools.product(_POOL['m'], _POOL['h'], _POOL['dom'], _POOL['mon'], _POOL['dow'])]


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheTable(unittest.TestCase):

    CASES = [
        # intervals
        ('* * * * *', 'Every minute'), ('*/1 * * * *', 'Every minute'), ('*/5 * * * *', 'Every 5 minutes'), ('*/15 * * * *', 'Every 15 minutes'),
        ('0 * * * *', 'Every hour'), ('15 * * * *', 'Every hour at :15'), ('5,35 * * * *', 'Every hour at :05 and :35'),
        ('0 */6 * * *', 'Every 6 hours'), ('30 */6 * * *', 'Every 6 hours at :30'), ('0 */1 * * *', 'Every hour'),
        ('*/15 9-17 * * 1-5', 'Every 15 minutes from 09:00 to 17:59, weekdays'), ('0 1-5 * * *', 'Every hour from 01:00 to 05:00'),
        ('30 1-5 * * *', 'Every hour from 01:30 to 05:30'), ('* 3 * * *', 'Every minute from 03:00 to 03:59'),
        ('*/10 3 * * *', 'Every 10 minutes from 03:00 to 03:59'), ('*/10 3 * * 0', 'Every 10 minutes from 03:00 to 03:59, on Sundays'),
        ('0 1-5 * * 6,0', 'Every hour from 01:00 to 05:00, weekends'), ('0 1-5 * * 1,3', 'Every hour from 01:00 to 05:00, on Mon and Wed'),
        ('*/5 * * * 1', 'Every 5 minutes, on Mondays'),
        # a time of day
        ('0 3 * * *', 'Daily at 03:00'), ('30 22 * * *', 'Daily at 22:30'), ('0 2,14 * * *', 'Daily at 02:00 and 14:00'),
('5,35 3 * * *', 'Daily at 03:05 and 03:35'), ('0 1,13-15 * * *', 'Daily at 01:00, 13:00, 14:00 and 15:00'),
        ('0 9 * * 0-6', 'Daily at 09:00'),
        # a list that is a step written out reads as the step
        ('0,30 * * * *', 'Every 30 minutes'), ('0,15,30,45 * * * *', 'Every 15 minutes'), ('0,30 3 * * *', 'Every 30 minutes from 03:00 to 03:59'), ('0,30 1-5 * * *', 'Every 30 minutes from 01:00 to 05:59'),
        ('0,30 2,14 * * *', 'Daily at 02:00, 02:30, 14:00 and 14:30'), ('*/30 2,14 * * *', 'Daily at 02:00, 02:30, 14:00 and 14:30'),
        ('0 0,12 * * *', 'Every 12 hours'), ('0 0,6,12,18 * * *', 'Every 6 hours'), ('30 0,8,16 * * *', 'Every 8 hours at :30'),
        # weekdays
        ('0 3 * * 0', 'Sundays at 03:00'), ('0 3 * * 7', 'Sundays at 03:00'), ('30 2 * * 1', 'Mondays at 02:30'),
        ('0 6 * * 1-5', 'Weekdays at 06:00'), ('0 6 * * mon-fri', 'Weekdays at 06:00'), ('0 9 * * 6,0', 'Weekends at 09:00'),
        ('0 9 * * 6,7', 'Weekends at 09:00'), ('0 9 * * 1,3,5', 'Mon, Wed and Fri at 09:00'), ('0 3 * * MON', 'Mondays at 03:00'),
        # the days of the month and the year
        ('0 4 1 * *', 'Monthly on day 1 at 04:00'), ('0 4 1,15 * *', 'Days 1 and 15 of the month at 04:00'),
        ('0 4 25 12 *', 'Yearly on 25 Dec at 04:00'), ('0 3 1 1,7 *', 'On 1 Jan and 1 Jul at 03:00'),
        ('0 3 * 6 *', 'Daily in Jun at 03:00'), ('0 3 * jun-aug *', 'Daily in Jun, Jul and Aug at 03:00'),
        ('0 3 * 6 1', 'Mondays in Jun at 03:00'),
        # the macros
        ('@hourly', 'Every hour'), ('@daily', 'Daily at 00:00'), ('@midnight', 'Daily at 00:00'), ('@weekly', 'Sundays at 00:00'),
        ('@monthly', 'Monthly on day 1 at 00:00'), ('@yearly', 'Yearly on 1 Jan at 00:00'), ('@annually', 'Yearly on 1 Jan at 00:00'),
        ('@reboot', 'At boot'),
        # spacing and case
        ('  0   3 * * *  ', 'Daily at 03:00'),
    ]
    UNWORDED = [
        '', None, '0 3 * *', '0 0 3 * * *', '0 3 * * * *',                                 # not five fields
        '60 3 * * *', '0 24 * * *', '0 3 32 * *', '0 3 0 * *', '0 3 * 13 *', '0 3 * 0 *', '0 3 * * 8',   # out of range
        '0 3 * * 5-1', '0 3 ? * *', '0 3 * * 1/2', '0 3 L * *', '0 3 * * 1#2', '0 0-30/10 * * *',      # shapes it does not read
        '*/7 * * * *', '*/60 * * * *', '0 */5 * * *', '0 */7 * * *', '*/10 */2 * * *',                  # a step that does not divide its field
        '0 3 15 * 1', '0 3 1,15 * 1-5',                                                                 # a day of the month AND a weekday: either
        '0 3 31 * *', '0 3 29 * *', '0 3 29 2 *', '0 3 1,30 * *',                                       # a day that short months skip
        '0,15,30,45 1,2 * * *',                                                                          # more than six times
        '0 1-5 1 * *', '0 1-5 * 6 *', '*/5 * 1 * *', '5,35 1-5 * * *', '0 3 1,15 6 *',
        'every day', 'abc', '@sometimes',
    ]

    def test_the_words_for_each_shape(self):
        got = words_of([c[0] for c in self.CASES])
        self.assertEqual([(c[0], g) for c, g in zip(self.CASES, got)], list(self.CASES))

    def test_the_shapes_it_does_not_read_stay_unworded(self):
        got = words_of(self.UNWORDED)
        self.assertEqual([(e, g) for e, g in zip(self.UNWORDED, got) if g != ''], [])
        self.assertGreater(len(self.UNWORDED), 30, 'control: the negative table is not empty')


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheWordsFollowTheSchedule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.exprs = _all_expressions()
        cls.words = words_of(cls.exprs)

    def test_the_population(self):
        self.assertEqual(len(self.exprs), math.prod(len(pool) for pool in _POOL.values()))
        self.assertGreater(len(self.exprs), 60000, 'control: the grammar is not trimmed')
        worded = [w for w in self.words if w]
        self.assertGreater(len(worded), 2500, 'control: a good share of the grammar is worded')
        self.assertLess(len(worded), len(self.words), 'control: and a share is left alone')

    def test_no_words_are_broken_text(self):
        bad = [(e, w) for e, w in zip(self.exprs, self.words) if w and re.search(r'undefined|NaN|\[object|null|Infinity', w)]
        self.assertEqual(bad[:5], [])

    def _check(self, words):
        by_words, by_schedule = {}, {}
        for expr, w in zip(self.exprs, words):
            if not w:
                continue
            sig = schedule_of(expr)
            by_words.setdefault(w, set()).add(sig)
            by_schedule.setdefault(sig, set()).add(w)
        return ({w: len(s) for w, s in by_words.items() if len(s) > 1}, [sorted(ws) for ws in by_schedule.values() if len(ws) > 1])

    def test_the_same_words_never_mean_two_schedules_and_one_schedule_has_one_reading(self):
        same_words_two_schedules, one_schedule_two_readings = self._check(self.words)
        self.assertEqual(same_words_two_schedules, {}, 'the words are ambiguous')
        self.assertEqual(one_schedule_two_readings, [], 'the same schedule is read two ways')

    def test_the_check_sees_a_wording_that_confuses_two_schedules(self):
        # a helper that calls every weekday set "Weekdays" must fail the property: this is the control that the check can fail
        broken = [re.sub(r'^(Mon, Wed and Fri|Mondays|Sundays)', 'Weekdays', w) if w else w for w in self.words]
        same_words_two_schedules, _ = self._check(broken)
        self.assertTrue(same_words_two_schedules)

    def test_the_check_sees_one_schedule_read_two_ways(self):
        broken = [w.replace('Daily at', 'Every day at') if (w and e.startswith('0 3 * * *')) else w for e, w in zip(self.exprs, self.words)]
        # only the spelling `0 3 * * *` changes: `0 3 * * 0-6` has the same schedule and keeps the old words
        _, one_schedule_two_readings = self._check(broken)
        self.assertTrue(one_schedule_two_readings)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheCell(unittest.TestCase):

    def _cells(self, calls):
        script = srcpin.js_function(_APP, 'cronWords') + '\n' + srcpin.js_function(_APP, 'cronHtml') + \
            '\nfunction escHtml(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }\nconst escAttr = escHtml;'
        return _run_node(script, 'console.log(JSON.stringify([' + ','.join(calls) + ']));')

    def test_words_over_the_expression_and_the_expression_alone_when_there_are_none(self):
        got = self._cells(["cronHtml('0 3 * * 0')", "cronHtml('0 3 * * 0', 'c-accent')", "cronHtml('0 3 15 * 1')", "cronHtml('')", "cronHtml(null)"])
        self.assertEqual(got, [
            '<span>Sundays at 03:00</span><div class="hint mono-12">0 3 * * 0</div>',
            '<span class="c-accent">Sundays at 03:00</span><div class="hint mono-12">0 3 * * 0</div>',
            '<span class="mono-12">0 3 15 * 1</span>', '', ''])

    def test_the_suffix_follows_the_first_line(self):
        got = self._cells(["cronHtml('0 1 1 * *', '', ' for 180min')", "cronHtml('0 3 15 * 1', '', ' for 60min')"])
        self.assertEqual(got, ['<span>Monthly on day 1 at 01:00</span> for 180min<div class="hint mono-12">0 1 1 * *</div>',
                               '<span class="mono-12">0 3 15 * 1</span> for 60min'])

    def test_the_expression_is_escaped(self):
        got = self._cells(["cronHtml('<img src=x onerror=1>')", "cronHtml('0 3 * * 0 <b>')"])
        self.assertEqual(got, ['<span class="mono-12">&lt;img src=x onerror=1&gt;</span>', '<span class="mono-12">0 3 * * 0 &lt;b&gt;</span>'])


class TestTheFourSitesUseTheHelper(unittest.TestCase):

    def test_each_table_that_shows_a_schedule_goes_through_cronhtml(self):
        self.assertIn("cronHtml(j.cron, 'c-accent')", _APP)                         # Schedule
        self.assertIn('cronHtml(p.cron)', _APP)                                     # Auto-patch
        self.assertIn("cronHtml(w.cron, '', ` for ${Math.round((w.duration||0)/60)}min`)", _APP)   # Maintenance
        self.assertIn('cronHtml(j.cron)', _BACKUPS)                                 # Backups

    def test_none_of_them_prints_the_raw_expression_on_its_own_any_more(self):
        self.assertNotIn('escHtml(p.cron)', _APP)
        self.assertNotIn('escHtml(w.cron)', _APP)
        self.assertNotIn('escHtml(j.cron)', _APP)
        self.assertNotIn('escHtml(j.cron)', _BACKUPS)


if __name__ == '__main__':
    unittest.main()
