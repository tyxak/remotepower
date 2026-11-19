#!/usr/bin/env python3
"""8.0.2 review (threat-flow R4 and R5): two ways the never-block rules answered a question they should not have.

R5: `in_any` compared address families, so the IPv4-mapped spelling of a protected IPv4 address (`::ffff:a.b.c.d`, which Apache on a dual-stack socket writes for a visitor
who came in over IPv4, and which the heartbeat's brute-force counter keeps as written) was not protected: an office address on the never-block list was blocked and reported
under its other spelling. R4: `POST /api/ip-intel/ban` answered "Not banning <ip>: on the never-block list" before it asked whether the caller may ban anything, and that list
holds every tenant's hosts and where every user signed in from, so a viewer could ask about any address and read one bit about it.
"""
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(ROOT / 'tests'))
import ip_intel  # noqa: E402
import srcpin  # noqa: E402

NETS = [ipaddress.ip_network('185.15.56.0/24'), ipaddress.ip_network('2001:db8::/32')]


class TestTheSpellingsOfOneAddress(unittest.TestCase):

    def test_the_mapped_spelling_is_protected_like_the_plain_one(self):
        self.assertTrue(ip_intel.in_any('185.15.56.1', NETS))
        self.assertTrue(ip_intel.in_any('::ffff:185.15.56.1', NETS))
        self.assertEqual(ip_intel.never_block_reason('::ffff:185.15.56.1', NETS), 'on the never-block list')

    def test_control_an_address_outside_is_not_protected_in_either_spelling(self):
        self.assertFalse(ip_intel.in_any('185.15.57.1', NETS))
        self.assertFalse(ip_intel.in_any('::ffff:185.15.57.1', NETS))

    def test_a_real_ipv6_address_is_still_matched_by_an_ipv6_network(self):
        self.assertTrue(ip_intel.in_any('2001:db8::5', NETS))
        self.assertFalse(ip_intel.in_any('2001:db9::5', NETS))

    def test_an_unparseable_address_is_not_in_any_network(self):
        self.assertFalse(ip_intel.in_any('not an address', NETS))


class TestThePermissionComesFirst(unittest.TestCase):

    def test_the_ban_route_asks_for_the_permission_before_it_applies_the_never_block_rules(self):
        body = srcpin.py_function((ROOT / 'server' / 'cgi-bin' / 'edge_blocklist_handlers.py').read_text(), 'handle_ip_intel_ban')
        ask = body.index("A.require_perm('command', None)")
        rule = body.index('never_block_reason(')
        self.assertLess(ask, rule)

    def test_the_block_route_already_did(self):
        body = srcpin.py_function((ROOT / 'server' / 'cgi-bin' / 'ip_intel_handlers.py').read_text(), 'handle_ip_intel_block')
        self.assertIn('require_perm', body.split('never_block_reason')[0])


if __name__ == '__main__':
    unittest.main()
