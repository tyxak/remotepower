#!/usr/bin/env python3
"""8.0.2 review (ST-12): a stored value of the wrong kind in a field the shape registry did not list answered HTTP 500 for every caller.

A restored backup, an import or an older release can leave one: the ledger of an address in the Threat Intel store (`src` as text, `ban` as a boolean), an account's `last_login`
or `ui_prefs`, a row of the enrollment tokens that is null, a host's package manager as a number. A host cannot produce them through the real ingest (1,862 hostile ingests were
tried), which is why this is a repair on read and not a check on write. Each damage is repaired by `store_shapes.normalize` and the sound value next to it is kept.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import store_shapes as S  # noqa: E402


class TestTheSixDamages(unittest.TestCase):

    def test_a_ledger_of_the_wrong_kinds_is_repaired_and_the_sound_part_stays(self):
        doc = {'attackers': {'203.0.113.9': {'ev': {'src': 'x', 'ban': True, 'tok': {'web': {'req:sqli': 2}}, 'blk': 3, 'cve': 'CVE-1', 'smp': 5}}}}
        ev = S.normalize('ip_intel.json', doc)['attackers']['203.0.113.9']['ev']
        self.assertEqual((ev['src'], ev['ban'], ev['cve'], ev['smp']), ({}, [], [], []))
        self.assertEqual((ev['tok'], ev['blk']), ({'web': {'req:sqli': 2}}, 3), 'the parts that were sound are as they were')

    def test_an_account_with_a_wrong_last_login_or_ui_prefs(self):
        got = S.normalize('users.json', {'pw': {'role': 'viewer', 'last_login': 'x', 'ui_prefs': 'x'}, 'ok': {'last_login': 1790000000, 'ui_prefs': {'a': 1}}})
        self.assertNotIsInstance(got['pw'].get('last_login'), str)
        self.assertIn(got['pw'].get('ui_prefs'), (None, {}))
        self.assertEqual(got['ok'], {'last_login': 1790000000, 'ui_prefs': {'a': 1}})

    def test_a_null_row_of_the_enrollment_tokens_is_left_out(self):
        got = S.normalize('enrollment_tokens.json', {'a': None, 'b': {'max_uses': 3, 'uses': 1}})
        self.assertEqual(got, {'b': {'max_uses': 3, 'uses': 1}})

    def test_a_package_manager_that_is_a_number_reads_as_its_text(self):
        got = S.normalize('devices.json', {'h': {'name': 'h', 'group': 'g', 'sysinfo': {'packages': {'manager': 7}}}})
        self.assertEqual(got['h']['sysinfo']['packages']['manager'], '7')


if __name__ == '__main__':
    unittest.main()
