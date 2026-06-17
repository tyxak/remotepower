#!/usr/bin/env python3
"""Unit tests for the IP-reputation (DNSBL) checker — fake resolver, no real DNS."""
import os
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import dns.resolver  # noqa: E402
import ip_reputation as ipr  # noqa: E402


class _Rdata:
    def __init__(self, s, strings=None):
        self._s = s
        self.strings = strings or []

    def __str__(self):
        return self._s


class FakeResolver:
    """Resolves names present in ``listed`` (an A answer + optional TXT); every
    other name raises NXDOMAIN — exactly the DNSBL 'not listed' signal."""
    def __init__(self, listed):
        self.listed = listed
        self.lifetime = 5
        self.timeout = 5

    def resolve(self, name, rtype):
        if name in self.listed:
            codes, txt = self.listed[name]
            if rtype == 'A':
                return [_Rdata(c) for c in codes]
            return [_Rdata('', [t.encode()]) for t in txt]
        raise dns.resolver.NXDOMAIN()


ZONES = [{'name': 'TestBL', 'zone': 'bl.test'},
         {'name': 'OtherBL', 'zone': 'other.test'}]


class TestHelpers(unittest.TestCase):
    def test_reverse_ip(self):
        self.assertEqual(ipr.reverse_ip('1.2.3.4'), '4.3.2.1')

    def test_parse_ip_valid_invalid(self):
        self.assertEqual(ipr.parse_ip(' 8.8.8.8 '), '8.8.8.8')
        self.assertIsNone(ipr.parse_ip('not-an-ip'))
        self.assertIsNone(ipr.parse_ip('2001:db8::1'))  # IPv6 rejected (v4 zones)

    def test_parse_target(self):
        self.assertEqual(ipr.parse_target({'ip': '1.2.3.4', 'label': 'mx'}),
                         {'ip': '1.2.3.4', 'label': 'mx'})
        self.assertIsNone(ipr.parse_target({'ip': 'bad'}))
        self.assertIsNone(ipr.parse_target('nope'))


class TestZoneValidation(unittest.TestCase):
    def test_valid_and_invalid_zones(self):
        self.assertTrue(ipr.valid_zone('zen.spamhaus.org'))
        self.assertTrue(ipr.valid_zone('bl.test'))
        for bad in ('', 'nodot', 'has space.org', 'bad;zone.org', 'a..b', '.leading'):
            self.assertFalse(ipr.valid_zone(bad), bad)

    def test_invalid_zone_is_skipped(self):
        # A malformed zone is ignored rather than queried with a bad name.
        out = ipr.check_ip('1.2.3.4', [{'name': 'Bad', 'zone': 'no good'}],
                           FakeResolver({}))
        self.assertEqual(out['listed_count'], 0)
        self.assertEqual(out['errors'], {})


class TestCheckIp(unittest.TestCase):
    def test_listed_on_one_zone(self):
        res = FakeResolver({'4.3.2.1.bl.test': (['127.0.0.2'], ['spam source'])})
        out = ipr.check_ip('1.2.3.4', ZONES, res)
        self.assertEqual(out['listed_count'], 1)
        self.assertEqual(out['listed_on'][0]['name'], 'TestBL')
        self.assertEqual(out['listed_on'][0]['reason'], 'spam source')
        self.assertTrue(out['ok'])

    def test_clean_everywhere(self):
        out = ipr.check_ip('8.8.8.8', ZONES, FakeResolver({}))
        self.assertEqual(out['listed_count'], 0)
        self.assertEqual(out['listed_on'], [])
        self.assertTrue(out['ok'])

    def test_invalid_ip(self):
        out = ipr.check_ip('999.1.1.1', ZONES, FakeResolver({}))
        self.assertIn('error', out)
        self.assertNotIn('listed_on', out)

    def test_zone_error_marks_not_ok(self):
        class Boom(FakeResolver):
            def resolve(self, name, rtype):
                raise TimeoutError('dns timeout')
        out = ipr.check_ip('1.2.3.4', ZONES, Boom({}))
        self.assertFalse(out['ok'])
        self.assertEqual(out['listed_count'], 0)
        self.assertEqual(len(out['errors']), 2)


if __name__ == '__main__':
    unittest.main()
