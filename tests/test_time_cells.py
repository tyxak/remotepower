#!/usr/bin/env python3
"""A time in a table cell follows the Time display setting, unless the cell is a log row, a future date or a file's own time.

My Account -> Appearance has a Time display setting: relative in place ("3h ago") with the exact time on hover, or the other way
round. The rule for that is timeAgoHtml() (see test_v740_time_display.py, which holds the relative-time call sites to it). It could
not hold the cells that printed an exact stamp straight from `_fmtAbsTs()`: 32 of them ignored the setting, so one page
showed "3h ago" in one column and `11/5/2026, 4:08:25 PM` in the next. The "last run", "created", "last seen", "checked" and "since"
cells go through the rule now.

What stays exact on purpose, and is listed below with its reason:
  log     a row is an event, read by its exact time (audit trail, webhook log, sudo log, traps, client errors, monitor history)
  future  an expiry, an ETA or a scheduled run: the relative form counts from the past
  file    a file's own modified time, as `ls -l` shows it, and an archive picked by its time

This test lists every call of `_fmtAbsTs`, `_fmtAbsDate`, `_fmtAbsTime` or a Date's `toLocale*String` on a line that carries a table
cell, outside an attribute value, and compares it with the list: a new one fails, and so does a listed one that is gone, so the list
only shrinks. The rendered half (the setting flips the converted cells of twelve pages) is in test_sidebar_page_fixes_e2e.py.
"""
import collections
import pathlib
import re
import unittest

_JS = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js'

_CALL = re.compile(r'(?<![\w.])(?:_fmtAbsTs|_fmtAbsDate|_fmtAbsTime)\([^()]*(?:\([^()]*\)[^()]*)*\)|\.(?:toLocaleDateString|toLocaleTimeString|toLocaleString)\(')
_CELL = re.compile(r'<(?:td|th)\b')


def _in_attribute(line, pos):
    lt = line.rfind('<', 0, pos)
    seg = line[lt:pos] if lt >= 0 else line[:pos]
    m = list(re.finditer(r'=\s*"', seg))
    return bool(m) and seg[m[-1].end():].count('"') % 2 == 0


def cell_sites(text, name='<src>'):
    """(file, call) for each absolute-time call on a line that carries a table cell, outside an attribute value."""
    out = collections.Counter()
    for line in text.split('\n'):
        if 'function _fmtAbs' in line or not _CELL.search(line):
            continue
        for m in _CALL.finditer(line):
            call = m.group(0)
            # `.toLocaleString(` also formats numbers: it is a time only on a Date
            if call == '.toLocaleString(' and 'new Date(' not in line:
                continue
            if _in_attribute(line, m.start()):
                continue
            out[(name, call[:60])] += 1
    return out


ALLOWED = {
    ('app-backups.js', '_fmtAbsDate(s.full_eta)'): (1, 'future: when the disk is forecast to fill'),
    ('app-kmip.js', '.toLocaleString('): (1, 'log: the KMIP operations'),
    ('app-network.js', '_fmtAbsDate(c.expires_at)'): (1, 'future: a certificate expires on a date'),
    ('app-remote.js', '_fmtAbsTs(e.mtime)'): (1, "file: the remote file's own modified time"),
    ('app-s3restore.js', '_fmtAbsTs(a.mtime)'): (1, 'file: an archive is picked by its exact time'),
    ('app-self.js', '_fmtAbsTs(e.ts)'): (1, 'log: client errors'),
    ('app.js', '_fmtAbsTs((a.ts || 0))'): (1, 'log: remediation'),
    ('app.js', '_fmtAbsTs((e.ts||0))'): (1, 'log: sudo'),
    ('app.js', '_fmtAbsTs((t.ts||0))'): (1, 'log: SNMP traps'),
    ('app.js', '_fmtAbsTs(e.ts || 0)'): (1, 'log: sudo, by user'),
    ('app.js', '_fmtAbsTs(e.ts)'): (5, 'log: webhook log, dead letters, schedule history, maintenance suppressions, audit trail'),
    ('app.js', '_fmtAbsTs(h.ts)'): (1, 'log: monitor history'),
    ('app.js', '_fmtAbsTs(j.run_at)'): (1, 'future: a one-shot job runs at that time'),
}


class TestTheScanner(unittest.TestCase):

    def test_it_sees_a_cell_and_spares_an_attribute_a_number_and_a_sentence(self):
        self.assertEqual(cell_sites('x = `<td>${_fmtAbsTs(t.ts)}</td>`;'), {('<src>', '_fmtAbsTs(t.ts)'): 1})
        self.assertEqual(cell_sites('x = `<td>${_fmtAbsDate(t.created)}</td>`;'), {('<src>', '_fmtAbsDate(t.created)'): 1})
        self.assertEqual(cell_sites('x = `<td>${new Date(t * 1000).toLocaleString(loc)}</td>`;'), {('<src>', '.toLocaleString('): 1})
        self.assertEqual(cell_sites('x = `<td title="${_fmtAbsTs(t.ts)}">a</td>`;'), {})
        self.assertEqual(cell_sites('x = `<td>${Number(n).toLocaleString(loc)}</td>`;'), {})
        self.assertEqual(cell_sites('x = `Last run ${_fmtAbsTs(t.ts)}`;'), {})
        self.assertEqual(cell_sites('x = `<td>${_fmtAbsTs(fn(t.ts))}</td>`;'), {('<src>', '_fmtAbsTs(fn(t.ts))'): 1})

    def test_a_converted_cell_is_not_a_site(self):
        self.assertEqual(cell_sites("x = `<td>${timeAgoHtml(t.ts, {empty: '—'})}</td>`;"), {})


class TestTheCellsFollowTheSetting(unittest.TestCase):

    def test_every_cell_that_still_prints_an_exact_time_is_listed_with_its_reason(self):
        files = sorted(_JS.glob('app*.js'))
        self.assertGreater(len(files), 40, 'control: the scripts were found')
        found = collections.Counter()
        cells = 0
        for p in files:
            text = p.read_text(encoding='utf-8')
            cells += len(_CELL.findall(text))
            found.update(cell_sites(text, p.name))
        self.assertGreater(cells, 1000, 'control: the table cells were counted')
        want = {k: v[0] for k, v in ALLOWED.items()}
        new = {k: n for k, n in found.items() if n > want.get(k, 0)}
        gone = {k: n for k, n in want.items() if found.get(k, 0) < n}
        self.assertEqual(new, {}, 'a table cell prints an exact time: use timeAgoHtml() (relative in place, exact on hover, and the Time '
                                  'display setting flips them), or list the cell in ALLOWED with the reason it stays exact')
        self.assertEqual(gone, {}, 'a listed cell no longer prints an exact time: take it off ALLOWED, so the list only shrinks')

    def test_the_converted_cells_are_a_large_share_of_the_time_cells(self):
        uses = 0
        for p in sorted(_JS.glob('app*.js')):
            for line in p.read_text(encoding='utf-8').split('\n'):
                if _CELL.search(line):
                    uses += line.count('timeAgoHtml(')
        self.assertGreater(uses, 25, 'control: the cells were converted, not deleted')


if __name__ == '__main__':
    unittest.main()
