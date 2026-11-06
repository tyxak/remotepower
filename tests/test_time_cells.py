#!/usr/bin/env python3
"""A time on a page follows the Time display setting, unless it is one of the kinds below, each of which is read by its exact time.

My Account -> Appearance has a Time display setting: relative in place ("3h ago") with the exact time on hover, or the other way
round. The rule for that is timeAgoHtml() for markup and timeAgo() for a sentence in textContent (see test_v740_time_display.py,
which holds the relative-time call sites to it). It could not hold the places that printed an exact stamp straight from `_fmtAbsTs()`:
before the sidebar sweep 126 calls did, so one page showed "3h ago" in one column and `11/5/2026, 4:08:25 PM` in the next. The "last
run", "created", "last seen", "checked" and "since" cells and sentences go through the rule now.

What stays exact is listed below, one line for each call, with its kind:
  funnel  the formatter itself and the two time helpers that call it
  hover   the title of a relative time: the exact time is what the hover is for
  chart   an axis, a label or a tooltip of a chart
  log     a row of a log, a history or an audit trail: the row is the event, read by its exact time
  future  an expiry, a due date, an ETA or a scheduled time: the relative form counts from the past
  record  a date that belongs to a document or a record (invoice, ticket, legal hold, report period, baseline, key lifecycle, a measurement window)
  fact    an inventory fact in a detail view (last boot, a file's own modified time) or a value beside an Age column
  rule    when a suppression rule or an acknowledgement was made: audit data
  toast   a transient message

This test lists every call of `_fmtAbsTs`, `_fmtAbsDate`, `_fmtAbsTime`, `fmtDate` or a Date's `toLocale*String` in the scripts, outside
comments and attribute values, and compares it with the list: a new call fails, and so does a listed one that is gone, so the list only
shrinks. test_sidebar_page_fixes_e2e.py flips the setting on fourteen pages of the demo and reads the converted cells.
"""
import collections
import pathlib
import re
import unittest

_JS = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'html' / 'static' / 'js'

_CALL = re.compile(
    r'(?<![\w.])(?:_fmtAbsTs|_fmtAbsDate|_fmtAbsTime|fmtDate)\([^()]*(?:\([^()]*\)[^()]*)*\)'
    r'|\.(?:toLocaleDateString|toLocaleTimeString)\('
    r'|new Date\([^()]*(?:\([^()]*\)[^()]*)*\)\.toLocaleString\(')
_DEFINITION = re.compile(r'(?:async\s+)?function\s+(?:_fmtAbs\w+|fmtDate|_absTs)\b')


def _in_attribute(line, pos):
    lt = line.rfind('<', 0, pos)
    seg = line[lt:pos] if lt >= 0 else line[:pos]
    m = list(re.finditer(r'=\s*"', seg))
    return bool(m) and seg[m[-1].end():].count('"') % 2 == 0


def time_sites(text, name='<src>'):
    """(file, call) for each exact-time call outside comments, function headers and attribute values."""
    out = collections.Counter()
    for line in text.split('\n'):
        stripped = line.lstrip()
        if stripped.startswith('//') or _DEFINITION.match(stripped):
            continue
        for m in _CALL.finditer(line):
            if _in_attribute(line, m.start()):
                continue
            out[(name, m.group(0)[:70])] += 1
    return out


KINDS = {'funnel', 'hover', 'chart', 'log', 'future', 'record', 'fact', 'rule', 'toast'}

# (file, call) -> (how many, kind, which)
ALLOWED = {
    ('app-ai.js', '_fmtAbsTs(ts)'): (1, 'future', 'the next runs of a cron the AI wrote'),
    ('app-alerts.js', '_fmtAbsTs(t.resolved_at)'): (1, 'log', 'the alert resolution timeline'),
    ('app-backups.js', '_fmtAbsDate(s.full_eta)'): (1, 'future', 'when the disk is forecast to fill'),
    ('app-backups.js', '_fmtAbsTs(g.last_backup)'): (1, 'fact', 'Proxmox guests: the exact time sits beside the Age column'),
    ('app-billing.js', '_fmtAbsDate(inv.issued_at)'): (1, 'record', 'the date an invoice was issued'),
    ('app-billing.js', '_fmtAbsDate(q.valid_until)'): (1, 'future', 'until when a quote holds'),
    ('app-business-services.js', '_fmtAbsTs(h.ts)'): (1, 'log', 'state changes of a business service'),
    ('app-dmarc.js', '.toLocaleDateString('): (1, 'record', 'the end of the period a DMARC report covers'),
    ('app-dmarc.js', '_fmtAbsDate(r.date_begin)'): (1, 'record', 'the start of the period a DMARC report covers'),
    ('app-dns.js', '_fmtAbsDate(r.next_renew_ts)'): (1, 'future', 'the next renewal of a certificate'),
    ('app-dns.js', '_fmtAbsTs(e.ts)'): (1, 'log', 'the ACME timeline'),
    ('app-dns.js', '_fmtAbsTs(l.ts)'): (1, 'log', 'the ACME command logs'),
    ('app-drift.js', '_fmtAbsTs(c.ts)'): (1, 'log', 'a version of a watched file, in the diff picker'),
    ('app-drift.js', '_fmtAbsTs(h.ts)'): (1, 'log', 'the hash history of a watched file'),
    ('app-drift.js', '_fmtAbsTs(newer.ts)'): (1, 'log', 'the newer version in a diff'),
    ('app-drift.js', '_fmtAbsTs(older.ts)'): (1, 'log', 'the older version in a diff'),
    ('app-hostconfig.js', '_fmtAbsTime(data.current_collected_at)'): (1, 'toast', 'loading the current host config'),
    ('app-kmip.js', '_fmtAbsDate(ts)'): (1, 'record', 'the lifecycle dates of a key'),
    ('app-kmip.js', 'new Date((r.ts || 0) * 1000).toLocaleString('): (1, 'log', 'the KMIP operations log'),
    ('app-logs.js', '_fmtAbsTime(l.ts)'): (1, 'log', 'a log line'),
    ('app-logs.js', '_fmtAbsTs(l.ts)'): (1, 'log', 'a log search hit'),
    ('app-network.js', '_fmtAbsDate(c.expires_at)'): (1, 'future', 'a certificate expires on a date'),
    ('app-network.js', '_fmtAbsDate(t.expires_at)'): (1, 'future', 'a TLS monitor: the certificate expires on a date'),
    ('app-network.js', '_fmtAbsTs(t.expires_at)'): (1, 'future', 'the certificate chain view'),
    ('app-problems.js', '_fmtAbsTs(e.at)'): (1, 'hover', 'the title of the relative time in the problem history'),
    ('app-remote.js', '_fmtAbsTs(e.mtime)'): (1, 'fact', "a remote file's own modified time"),
    ('app-s3restore.js', '_fmtAbsTs(a.mtime)'): (1, 'fact', 'an archive is picked by its exact time'),
    ('app-scans.js', '_fmtAbsTs(s.next_run)'): (1, 'future', 'the next run of a scheduled scan'),
    ('app-self.js', '_fmtAbsTs(e.at)'): (1, 'log', 'the upgrade history of the server'),
    ('app-self.js', '_fmtAbsTs(e.ts)'): (1, 'log', 'client errors'),
    ('app-tickets.js', '_fmtAbsTs(m.ts)'): (2, 'record', 'the messages and the timeline of a ticket'),
    ('app-tickets.js', '_fmtAbsTs(t.sla_due)'): (1, 'future', 'when a ticket is due'),
    ('app-vpn.js', '_fmtAbsDate(ts)'): (1, 'future', 'a VPN key expires on a date'),
    ('app.js', '.toLocaleDateString('): (2, 'funnel', 'the chart axis helper and _fmtAbsDate'),
    ('app.js', '.toLocaleTimeString('): (3, 'funnel', 'the chart axis helper, _fmtAbsTime, and the fetched-at of the container log viewer'),
    ('app.js', '_fmtAbsDate(a.until)'): (1, 'future', 'when a log alert mute lapses'),
    ('app.js', '_fmtAbsDate(k.expires_at)'): (1, 'future', 'an API key expires on a date'),
    ('app.js', "_fmtAbsDate(ts, { month: 'short', day: 'numeric' })"): (1, 'chart', 'the date axis of a chart'),
    ('app.js', '_fmtAbsTime(e.finished_at)'): (1, 'log', 'a batch job'),
    ('app.js', '_fmtAbsTs((a.ts || 0))'): (1, 'log', 'the remediation log'),
    ('app.js', '_fmtAbsTs((e.ts||0))'): (1, 'log', 'the sudo log'),
    ('app.js', '_fmtAbsTs((it.ts || 0))'): (1, 'hover', 'the title of the relative time in the timeline'),
    ('app.js', '_fmtAbsTs((t.ts||0))'): (1, 'log', 'SNMP traps'),
    ('app.js', '_fmtAbsTs((v.ts || 0))'): (1, 'record', 'the configuration revisions'),
    ('app.js', '_fmtAbsTs(_n)'): (1, 'funnel', 'timeAgo, with the absolute setting'),
    ('app.js', '_fmtAbsTs(a.ts)'): (2, 'chart', 'the title of a chart annotation; and when an alert mute was made (rule)'),
    ('app.js', '_fmtAbsTs(c.ts)'): (1, 'rule', 'when a CVE ignore was made'),
    ('app.js', '_fmtAbsTs(data.started_at)'): (1, 'record', 'when a legal hold began'),
    ('app.js', '_fmtAbsTs(e.ts || 0)'): (1, 'log', 'the sudo log, by user'),
    ('app.js', '_fmtAbsTs(e.ts)'): (6, 'log', 'the webhook log, the dead letters, the schedule history, the maintenance suppressions, the audit trail; and an ignore (rule)'),
    ('app.js', '_fmtAbsTs(entry.finished_at)'): (1, 'log', 'the update logs'),
    ('app.js', '_fmtAbsTs(h.ts)'): (2, 'log', 'the monitor history and the transitions of a service'),
    ('app.js', '_fmtAbsTs(j.run_at)'): (1, 'future', 'a one-shot scheduled job'),
    ('app.js', '_fmtAbsTs(l.ts)'): (1, 'log', 'WordPress logins'),
    ('app.js', '_fmtAbsTs(latest.ts)'): (1, 'record', 'the window a flow sample covers'),
    ('app.js', '_fmtAbsTs(n)'): (1, 'funnel', 'timeAgoHtml'),
    ('app.js', '_fmtAbsTs(o.ts)'): (2, 'log', 'the commands of a patch report and of the audit section'),
    ('app.js', '_fmtAbsTs(r.baseline_at)'): (1, 'record', 'the SBOM baseline'),
    ('app.js', '_fmtAbsTs(si.last_boot)'): (1, 'fact', 'the host drawer'),
    ('app.js', '_fmtAbsTs(si.last_oom_ts)'): (1, 'fact', 'the host drawer'),
    ('app.js', '_fmtAbsTs(ts)'): (3, 'chart', 'a chart tooltip; the expiry of a session (future); and _formatTs, which the alert inbox uses (record)'),
    ('app.js', "_fmtAbsTs(ts, { month: 'short', day: 'numeric', hour: '2-digit', minut"): (1, 'chart', 'the time axis of a chart'),
    ('app.js', 'fmtDate(m.fill_date_ts)'): (2, 'chart', 'the forecast chart'),
    ('app.js', 'fmtDate(p[0])'): (1, 'chart', 'the forecast chart'),
    ('app.js', 'fmtDate(tMax)'): (1, 'chart', 'the forecast chart'),
    ('app.js', 'fmtDate(tMin)'): (1, 'chart', 'the forecast chart'),
    ('app.js', 'new Date().toLocaleString('): (1, 'record', 'the printed patch report is stamped with the time it was made'),
    ('app.js', 'new Date(Number(ts || 0) * 1000).toLocaleString('): (1, 'funnel', '_fmtAbsTs'),
}


class TestTheScanner(unittest.TestCase):

    def test_it_sees_a_call_and_spares_a_comment_a_header_an_attribute_and_a_number(self):
        self.assertEqual(time_sites('x = `<td>${_fmtAbsTs(t.ts)}</td>`;'), {('<src>', '_fmtAbsTs(t.ts)'): 1})
        self.assertEqual(time_sites('x = `Last run ${_fmtAbsDate(t.created)}`;'), {('<src>', '_fmtAbsDate(t.created)'): 1})
        self.assertEqual(time_sites('x = `${fmtDate(t.created)}`;'), {('<src>', 'fmtDate(t.created)'): 1})
        self.assertEqual(time_sites('x = new Date(t * 1000).toLocaleString(loc);'), {('<src>', 'new Date(t * 1000).toLocaleString('): 1})
        self.assertEqual(time_sites('x = d.toLocaleTimeString(loc);'), {('<src>', '.toLocaleTimeString('): 1})
        self.assertEqual(time_sites('x = `<td title="${_fmtAbsTs(t.ts)}">a</td>`;'), {})
        self.assertEqual(time_sites('// the old `_fmtAbsTs(t.ts)` form'), {})
        self.assertEqual(time_sites('function _fmtAbsTs(ts, opts) {'), {})
        self.assertEqual(time_sites('x = `<td>${Number(n).toLocaleString(loc)}</td>`;'), {})
        self.assertEqual(time_sites('x = `<td>${_fmtAbsTs(fn(t.ts))}</td>`;'), {('<src>', '_fmtAbsTs(fn(t.ts))'): 1})

    def test_a_converted_call_is_not_a_site(self):
        self.assertEqual(time_sites("x = `<td>${timeAgoHtml(t.ts, {empty: '—'})}</td>`;"), {})
        self.assertEqual(time_sites("x = `last scan ${timeAgo(t.ts)}`;"), {})


class TestEveryExactTimeIsListedWithItsKind(unittest.TestCase):

    def test_the_kinds_are_the_ones_the_docstring_names(self):
        self.assertEqual({v[1] for v in ALLOWED.values()}, KINDS, 'a kind is unused, or a call has a kind nobody defined')

    def test_every_exact_time_is_listed_and_every_listed_one_is_still_there(self):
        files = sorted(_JS.glob('app*.js'))
        self.assertGreater(len(files), 40, 'control: the scripts were found')
        found = collections.Counter()
        for p in files:
            found.update(time_sites(p.read_text(encoding='utf-8'), p.name))
        self.assertGreater(sum(found.values()), 70, 'control: the calls were counted')
        want = {k: v[0] for k, v in ALLOWED.items()}
        new = {k: n for k, n in found.items() if n > want.get(k, 0)}
        gone = {k: n for k, n in want.items() if found.get(k, 0) < n}
        self.assertEqual(new, {}, 'a call prints an exact time: use timeAgoHtml() in markup or timeAgo() in a sentence (relative in place, '
                                  'exact on hover, and the Time display setting flips them), or list it in ALLOWED with the kind that '
                                  'makes it exact')
        self.assertEqual(gone, {}, 'a listed call is gone (converted, or moved): take it off ALLOWED, so the list only shrinks')

    def test_the_converted_places_are_a_large_share_of_the_time_sites(self):
        uses = 0
        for p in sorted(_JS.glob('app*.js')):
            text = p.read_text(encoding='utf-8')
            uses += text.count('timeAgoHtml(') + text.count('timeAgo(')
        self.assertGreater(uses, 120, 'control: the calls were converted, not deleted')


if __name__ == '__main__':
    unittest.main()
