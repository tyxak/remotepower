#!/usr/bin/env python3
"""Notification HEADER text must be ASCII-safe.

An HTTP header is latin-1 at best, and ntfy/Gotify substitute "?" for anything
they cannot represent. Our notification titles are full of typographic
characters — the em dash alone appears ~103 times across the message builders —
so a correct title arrived on the operator's phone as:

    SIEM audit forwarding recovered ? 12 spooled entries

The body was never affected (JSON, or text/plain;charset=utf-8), which is why
email, Slack and the web UI all looked right and only push looked broken.

Seven of the characters in use cannot be represented in latin-1 AT ALL, so they
are guaranteed to mangle rather than merely risk it: — – … → ↔ ≥ ≠.
"""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTIFY = ROOT / 'server' / 'cgi-bin' / 'notify.py'


def _load():
    spec = importlib.util.spec_from_file_location('notify_hdr', NOTIFY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAsciiHeader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not NOTIFY.exists():
            raise unittest.SkipTest('notify.py not in this tree')
        cls.n = _load()

    def test_the_real_regression(self):
        """The exact string from the report."""
        out = self.n._ascii_header(
            'SIEM audit forwarding recovered — 12 spooled entries')
        self.assertEqual(out, 'SIEM audit forwarding recovered - 12 spooled entries')
        self.assertNotIn('?', out)

    def test_every_character_actually_used_survives_readably(self):
        """Not just 'is ASCII' — the transliteration must preserve MEANING.
        Dropping the arrow out of 'agent -> server' or the >= out of a
        threshold would be a quieter bug than the '?' it replaces."""
        cases = {
            'a — b': 'a - b',
            'a – b': 'a - b',
            'more…': 'more...',
            'agent → server': 'agent -> server',
            'a ↔ b': 'a <-> b',
            'disk ≥ 90%': 'disk >= 90%',
            'disk ≤ 10%': 'disk <= 10%',
            'a ≠ b': 'a != b',
            'nas01 · /mnt': 'nas01 - /mnt',
            '3 × retry': '3 x retry',
            '82°': '82 deg',
            '“quoted”': '"quoted"',
            "it’s": "it's",
        }
        for src, want in cases.items():
            with self.subTest(src=src):
                self.assertEqual(self.n._ascii_header(src), want)

    def test_output_is_always_header_safe(self):
        """Every output must be encodable as ASCII — that is the property that
        stops the substitution happening at all.

        The no-"?" check applies only to the plain path: RFC 2047 uses "?" as a
        STRUCTURAL delimiter (=?utf-8?b?...?=), so asserting its absence there
        would be asserting the encoding is broken. The encoded path is checked
        by round-tripping it instead, below."""
        for src in ('plain', 'a — b', 'CPU 82° on 主機-01', 'مرحبا', ''):
            with self.subTest(src=src):
                out = self.n._ascii_header(src)
                out.encode('ascii')          # raises if not header-safe
                if not out.startswith('=?'):
                    self.assertNotIn('?', out)

    def test_non_latin_is_encoded_not_destroyed(self):
        """A device named in Chinese must survive as RFC 2047 (which ntfy
        documents support for), not become a row of question marks. Losing the
        text is the same defect wearing a different mask."""
        out = self.n._ascii_header('主機-01')
        self.assertTrue(out.startswith('=?utf-8?'), out)
        from email.header import decode_header
        decoded = ''.join(
            (b.decode(enc or 'ascii') if isinstance(b, bytes) else b)
            for b, enc in decode_header(out))
        self.assertIn('主機-01', decoded)

    def test_it_is_not_a_no_op(self):
        """Guard the guard: if _HEADER_TRANSLIT were emptied this file would
        still pass everything above except this."""
        self.assertGreaterEqual(len(self.n._HEADER_TRANSLIT), 10)


class TestEveryHeaderValueGoesThroughIt(unittest.TestCase):
    """Source-pin: a future sender that drops a raw title into a header
    reintroduces the bug, and push is the one channel where nobody notices
    until an operator squints at their phone."""

    def setUp(self):
        if not NOTIFY.exists():
            self.skipTest('notify.py not in this tree')
        self.src = NOTIFY.read_text()

    def test_no_raw_title_in_a_header_dict(self):
        bad = re.findall(r'"(?:X-)?Title":\s*(?!_ascii_header)([A-Za-z_][\w.]*)',
                         self.src)
        self.assertEqual(
            bad, [],
            'these Title headers are set from a raw value — wrap them in '
            '_ascii_header(): %s' % bad)

    def test_the_helper_is_still_there(self):
        self.assertIn('def _ascii_header(', self.src)
        self.assertIn('_HEADER_TRANSLIT', self.src)


if __name__ == '__main__':
    unittest.main()
