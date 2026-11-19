#!/usr/bin/env python3
"""8.0.2 review (UI-06): the cleaners of text a host or a tenant administrator chose take out the characters that reorder or hide text.

Two cleaners written for the inventories already did; four others did not: a share's name, path and description, the OS text of the Hosts list, a log path from the capability
report, and `_sanitize_str` (the label of an enrolment token and every name and note stored through it). A right-to-left override makes one name read as another on a page,
and a zero-width space makes two names that look the same. The joiner and non-joiner and the variation selectors stay: Persian, Hindi and emoji sequences are spelled with them.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-hidden-text-'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import agent_capabilities  # noqa: E402
import persistence  # noqa: E402
import sanitize  # noqa: E402
import software_inventory  # noqa: E402
import windows_host  # noqa: E402

HIDDEN = {'U+202E (right-to-left override)': '\u202e', 'U+200B (zero-width space)': '\u200b', 'U+2066 (isolate)': '\u2066',
          'U+200F (right-to-left mark)': '\u200f', 'U+FEFF (byte order mark)': '\ufeff', 'U+2028 (line separator)': '\u2028'}


def flat(o):
    if isinstance(o, dict):
        return ''.join(flat(v) for v in o.values())
    if isinstance(o, (list, tuple)):
        return ''.join(flat(v) for v in o)
    return o if isinstance(o, str) else ''


class TestTheSixCleaners(unittest.TestCase):

    def cleaned(self, mark):
        t = 'x' + mark + 'y'
        share = windows_host.clean_shares({'count': 1, 'items': [{'name': t, 'path': 'C:\\' + t, 'description': t}]})
        os_text = windows_host.os_label({'build': '22631', 'ubr': 1, 'edition': t, 'product': 'Windows 11 ' + t})
        caps = agent_capabilities.clean({'logs': [{'kind': 'web', 'path': '/var/log/' + t, 'readable': True}]})
        return {'clean_shares': flat(share), 'os_label': os_text, 'log path': flat(caps), '_sanitize_str': sanitize._sanitize_str(t, 80),
                'persistence.clean_text': persistence.clean_text(t, 80), 'software_inventory.clean_text': software_inventory.clean_text(t, 80)}

    def test_each_cleaner_takes_each_character_out(self):
        for label, mark in HIDDEN.items():
            for who, out in self.cleaned(mark).items():
                with self.subTest(character=label, cleaner=who):
                    self.assertNotIn(mark, out)

    def test_control_the_text_around_the_character_is_kept(self):
        got = self.cleaned('\u202e')
        self.assertEqual(sanitize._sanitize_str('x\u202ey', 80), 'xy')
        self.assertIn('xy', got['clean_shares'])
        self.assertIn('/var/log/xy', got['log path'])

    def test_the_joiner_the_non_joiner_and_the_variation_selector_stay(self):
        keep = 'a\u200db\u200cc\ufe0fd'
        self.assertEqual(sanitize._sanitize_str(keep, 80), keep)

    def test_every_character_the_pattern_takes_out_is_one_the_stricter_rule_of_the_inventories_hides(self):
        taken = [c for c in range(0x110000) if sanitize._HIDDEN_FROM_THE_READER.fullmatch(chr(c))]
        self.assertGreater(len(taken), 15, 'the pattern is not empty')
        self.assertEqual([hex(c) for c in taken if not persistence.hidden(chr(c))], [], 'a person\'s text keeps less hidden than text a machine supplied, never more')


if __name__ == '__main__':
    unittest.main()
