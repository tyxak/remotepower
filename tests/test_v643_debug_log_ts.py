#!/usr/bin/env python3
"""A client-supplied timestamp could forge entries in the debug log.

`POST /api/debug-log` accepts batches of browser-side log lines so the UI and
server timelines can be read together during an incident. Each line is written
as::

    [{ts}] {tag} {msg}

`tag` and `msg` were both sanitised and length-capped. `ts` — sitting between
them on the same line — was written raw and unbounded. A newline in it therefore
forges whole entries in the one file whose entire value is that you can trust
its sequence, and any authenticated user can post to it on an install with debug
logging enabled.

Validating the SHAPE beats escaping here, and the difference is worth stating:
escaping would stop the forgery and still allow a 10,000-character "timestamp"
that leaves the file unreadable to anything splitting on the leading bracket. A
timestamp field has exactly one legitimate form, so anything else becomes server
time — which bounds the length and removes every newline by construction.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-dbgts-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class TestClientTimestampIsValidated(unittest.TestCase):

    def test_a_real_timestamp_is_kept(self):
        """POSITIVE CONTROL. Replacing everything with server time would satisfy
        every assertion below while destroying the feature — the whole point is
        to keep the BROWSER's clock so the two timelines line up."""
        for good in ('2026-08-13T14:05:09',
                     '2026-08-13T14:05:09Z',
                     '2026-08-13T14:05:09.123Z',
                     '2026-08-13 14:05:09',
                     '2026-08-13T14:05:09+02:00'):
            self.assertEqual(api._clean_client_ts(good), good, good)

    def test_a_newline_cannot_forge_a_line(self):
        forged = ('2026-08-13T14:05:09]\n[2026-08-13T14:05:10] audit '
                  'admin deleted nothing, honest')
        out = api._clean_client_ts(forged)
        self.assertNotIn('\n', out)
        self.assertNotIn('audit', out)

    def test_carriage_return_is_also_refused(self):
        self.assertNotIn('\r', api._clean_client_ts('2026-08-13T14:05:09\r[x]'))

    def test_length_is_bounded(self):
        self.assertLessEqual(len(api._clean_client_ts('9' * 100000)), 40)

    def test_non_strings_do_not_raise(self):
        for bad in (None, 12345, {'a': 1}, ['x'], b'2026-08-13T00:00:00'):
            out = api._clean_client_ts(bad)
            self.assertIsInstance(out, str)
            self.assertNotIn('\n', out)

    def test_the_fallback_is_itself_a_valid_timestamp(self):
        """The replacement must satisfy the same rule it enforces, or the log
        gains a second unparseable shape instead of losing one."""
        out = api._clean_client_ts('nonsense')
        self.assertEqual(api._clean_client_ts(out), out)


class TestTheWriterUsesIt(unittest.TestCase):
    """Source-level, and deliberately narrow: it pins that the raw value no
    longer reaches the format string. The behaviour above is the real check."""

    def test_the_log_line_formats_the_cleaned_value(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        i = src.index('def handle_debug_log_post')
        body = src[i:i + 3000]
        self.assertIn('_clean_client_ts(entry.get(', body)
        self.assertNotIn("ts  = entry.get('ts')", body,
                         'the raw client timestamp is being used again')


if __name__ == '__main__':
    unittest.main()
