#!/usr/bin/env python3
"""8.0.2 review (cve-flow F2): an advisory in an OSV answer with no usable name makes the scan say it could not read the answer, not "nothing found".

An advisory whose `id` was missing or not text was skipped, and a host whose only advisory was such a record read as clean with no error. It needs a broken or hostile answer
from the advisory database, which makes it an integrity matter and not a way in; a scan that cannot read an answer has to say so, because a clean host announces its findings cleared.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import cve_scanner as C  # noqa: E402

Q = [{'package': {'name': 'openssl', 'ecosystem': 'Debian:12'}, 'version': '3.0.11-1'}]


class TestAnAnswerWithoutNames(unittest.TestCase):

    def ask(self, answer):
        real = C._osv_querybatch
        C._osv_querybatch = lambda queries: [answer]
        try:
            return C._osv_query_all(Q)
        finally:
            C._osv_querybatch = real

    def test_a_record_with_no_name_is_refused(self):
        for bad in (None, 5, True, [], {}, ['a'], 10 ** 30, float('nan'), ''):
            with self.subTest(id=repr(bad)[:30]):
                with self.assertRaises(ValueError):
                    self.ask({'vulns': [{'id': bad, 'modified': 'x'}]})

    def test_a_record_with_the_id_missing_is_refused(self):
        with self.assertRaises(ValueError):
            self.ask({'vulns': [{'modified': 'x'}]})

    def test_control_a_named_advisory_and_no_advisories_are_read(self):
        self.assertEqual(self.ask({'vulns': [{'id': 'DEBIAN-CVE-2024-0001', 'modified': 'x'}]})[0]['vulns'][0]['id'], 'DEBIAN-CVE-2024-0001')
        self.assertEqual(self.ask({'vulns': []})[0]['vulns'], [])
        self.assertEqual(self.ask({})[0]['vulns'], [])


if __name__ == '__main__':
    unittest.main()
