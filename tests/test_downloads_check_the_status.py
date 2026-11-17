#!/usr/bin/env python3
"""A download that saves the answer without looking at its status saves the error.

fetch() resolves on a 403 as it does on a 200, so `fetch(url).then(r => r.blob())` hands over the refusal's JSON as if it were the file.
Two buttons did that: the redacted export of Settings > Backups and the calendar export. When this branch made GET /api/export the platform
operator's, a tenant administrator who pressed Export got a .zip holding {"error": "..."} and a green "Backup downloaded" toast.

The rule held here: every place a script reads a response as a Blob has looked at `.ok` or `.status` between the fetch and the read. The
shared helper `_downloadAuthed` does, so a call to it needs no check of its own. The population is every `.blob()` in every client script,
found by reading them, and the scanner is shown to flag the old text of both buttons (a scan that cannot see the defect would pass
whatever the tree held).
"""
import re
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import srcpin  # noqa: E402

# what the two buttons read before the fix (kept here as the control: the scanner has to flag both)
_OLD_EXPORT_BACKUP = ("function exportBackup() { const token = getToken(); fetch('/api/export', {headers: {'X-Token': token}})"
                      ".then(r => r.blob()).then(blob => { const url = URL.createObjectURL(blob); a.click(); "
                      "toast('Backup downloaded', 'success'); }).catch(() => toast('Export failed', 'error')); }")
_OLD_EXPORT_CALENDAR = ("function exportCalendarIcs() {\n  fetch('/api/calendar.ics', { headers: { 'X-Token': getToken() } })\n"
                        "    .then(r => r.blob())\n    .then(b => { toast('Calendar exported', 'success'); })\n"
                        "    .catch(() => toast('Export failed', 'error'));\n}")


def _without_comments(src):
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'(?m)(^|[^:\w"\'`])//.*$', r'\1', src)


def blob_sites(src):
    """Every `.blob()` of a script as (line, checked): checked when `.ok` or `.status` is read between the nearest fetch( before it and the
    `.blob()` itself. A read with no fetch( before it at all counts as unchecked."""
    src = _without_comments(src)
    out = []
    for m in re.finditer(r'\.blob\(\)', src):
        start = src.rfind('fetch(', 0, m.start())
        between = src[start:m.start()] if start >= 0 else ''
        out.append((src.count('\n', 0, m.start()) + 1, bool(re.search(r'\.ok\b|\.status\b', between))))
    return out


def _population():
    sites = []
    for p in sorted(_JS.glob('app*.js')):
        for line, checked in blob_sites(p.read_text()):
            sites.append((p.name, line, checked))
    return sites


class TestEveryBlobReadLooksAtTheStatus(unittest.TestCase):

    def test_the_population_is_found(self):
        sites = _population()
        # 16 when this was written: a derivation that finds a handful has stopped reading the scripts
        self.assertGreaterEqual(len(sites), 12, sites)
        self.assertTrue(any(n == 'app.js' for n, _l, _c in sites), 'app.js holds the shared helper and several downloads')

    def test_the_scanner_flags_the_old_text_of_both_buttons(self):
        for label, old in (('exportBackup', _OLD_EXPORT_BACKUP), ('exportCalendarIcs', _OLD_EXPORT_CALENDAR)):
            sites = blob_sites(old)
            self.assertEqual([c for _l, c in sites], [False], '%s as it was is not flagged: %s' % (label, sites))

    def test_the_scanner_passes_a_read_that_checks_the_status(self):
        good = "fetch(u).then(r => { if (!r.ok) throw new Error('failed'); return r.blob(); })"
        self.assertEqual([c for _l, c in blob_sites(good)], [True])
        self.assertEqual([c for _l, c in blob_sites("const r = await fetch(u); if (r.status !== 200) return; const b = await r.blob();")], [True])

    def test_no_download_reads_a_blob_without_looking_at_the_status(self):
        unchecked = ['%s:%d' % (n, line) for n, line, checked in _population() if not checked]
        self.assertEqual(unchecked, [], 'a download that saves a refusal as the file: route it through _downloadAuthed, or read .ok first')

    def test_the_two_buttons_use_the_helper_that_checks(self):
        backups = (_JS / 'app-backups.js').read_text()
        calendar = (_JS / 'app-calendar.js').read_text()
        self.assertTrue(re.search(r"function exportBackup\(\)\s*\{\s*_downloadAuthed\('/api/export'", backups),
                        'the redacted export does not go through _downloadAuthed')
        self.assertTrue(re.search(r"function exportCalendarIcs\(\)\s*\{\s*_downloadAuthed\('/api/calendar\.ics'", calendar),
                        'the calendar export does not go through _downloadAuthed')
        body = srcpin.js_function((_JS / 'app.js').read_text(), '_downloadAuthed')
        self.assertIn('if (!r.ok) throw', body, 'the helper the buttons rely on no longer refuses a failed answer')


if __name__ == '__main__':
    unittest.main()
