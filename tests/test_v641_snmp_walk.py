"""v6.4.1: the SNMP OID browser.

The deep poll answers "what does RemotePower already know how to read"; the
walk answers "what does this device actually expose", which is the question an
operator has when a vendor counter is in none of our parsers.

It reads ARBITRARY OIDs using the device's stored SNMP credentials, which is a
broader read than the fixed poll set — so it is admin-only, audited, and
bounded. The OID goes into a packet we build, never a shell, but an unbounded
arc count or a huge sub-identifier still lets a caller inflate the request, and
`int()` on junk would surface as a 500 rather than a 400. The validator, not
the encoder, is the boundary; most of these tests are about it.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api   # noqa: E402
import snmp  # noqa: E402


class TestOidValidator(unittest.TestCase):
    def test_accepts_real_oids(self):
        for oid in ('1.3.6.1.2.1.1', '1.3.6.1.2.1.2.2.1.2', '0.0',
                    '1.3.6.1.4.1.14988.1.1.3.100.1.3.1'):
            self.assertEqual(api._validate_walk_oid(oid), oid, oid)

    def test_strips_a_leading_dot(self):
        self.assertEqual(api._validate_walk_oid('.1.3.6.1.2.1.1'), '1.3.6.1.2.1.1')
        self.assertEqual(api._validate_walk_oid('  1.3.6.1  '), '1.3.6.1')

    def test_rejects_non_numeric(self):
        for junk in ('1.3.6.1.2.1.1; rm -rf /', 'sysDescr', '1.3.6.$(id)',
                     '1.3.6.1.2.1.-1', '1..3', '1.3.6.1 2', '1.3.6.1\n1.2'):
            self.assertIsNone(api._validate_walk_oid(junk), junk)

    def test_rejects_empty_and_single_arc(self):
        for junk in ('', None, '.', '1', '   '):
            self.assertIsNone(api._validate_walk_oid(junk), junk)

    def test_rejects_absurd_arc_counts(self):
        self.assertIsNone(api._validate_walk_oid('.'.join(['1'] * 200)))

    def test_rejects_oversized_sub_identifiers(self):
        # BER sub-identifiers are unsigned 32-bit; a 40-digit arc is a way to
        # make us build a very large packet.
        self.assertIsNone(api._validate_walk_oid('1.3.' + '9' * 40))
        self.assertIsNone(api._validate_walk_oid('1.3.4294967296'))
        self.assertEqual(api._validate_walk_oid('1.3.4294967295'), '1.3.4294967295')

    def test_rejects_illegal_first_arcs(self):
        # BER packs the first two arcs into one byte: arc1 <= 2, and arc2 <= 39
        # unless arc1 is 2.
        self.assertIsNone(api._validate_walk_oid('3.1.1'))
        self.assertIsNone(api._validate_walk_oid('1.40.1'))
        self.assertEqual(api._validate_walk_oid('2.100.3'), '2.100.3')

    def test_every_accepted_oid_actually_encodes(self):
        # The validator's contract is "if this passes, the encoder won't blow
        # up" — assert it rather than trusting the two agree.
        for oid in ('0.0', '1.3.6.1.2.1.1', '2.100.3', '1.3.4294967295'):
            snmp._encode_oid(api._validate_walk_oid(oid))


class TestOidLabels(unittest.TestCase):
    def test_longest_prefix_wins(self):
        self.assertEqual(snmp.oid_label('1.3.6.1.2.1.1.5.0'), 'sysName')
        self.assertEqual(snmp.oid_label('1.3.6.1.2.1.1.9.1'), 'system')

    def test_unknown_returns_empty_not_a_guess(self):
        # A vendor OID needs its vendor MIB, which we do not ship. Better blank
        # than a plausible-looking wrong name.
        self.assertEqual(snmp.oid_label('1.3.6.1.5.99.7.1'), '')

    def test_unknown_vendor_oid_resolves_only_as_far_as_enterprises(self):
        # Naming the subtree is genuinely useful ("this is vendor-private");
        # naming the leaf would be a guess.
        self.assertEqual(snmp.oid_label('1.3.6.1.4.1.99999.7.1'), 'enterprises')

    def test_a_prefix_is_not_matched_mid_arc(self):
        # '1.3.6.1.2.1.11' must not resolve as a child of '1.3.6.1.2.1.1'.
        self.assertNotEqual(snmp.oid_label('1.3.6.1.2.1.11.1'), 'system')


class TestHandlerContract(unittest.TestCase):
    """Auth, method and route wiring — the parts that turn a bounded admin
    tool into an unbounded one if they slip."""

    def setUp(self):
        self.src = (ROOT / 'server' / 'cgi-bin' / 'snmp_device_handlers.py').read_text()
        self.fn = self.src[self.src.index('def handle_device_snmp_walk('):]

    def test_admin_only(self):
        self.assertIn('A.require_admin_auth()', self.fn)
        # …and before anything reads the body or touches the device.
        self.assertLess(self.fn.index('A.require_admin_auth()'),
                        self.fn.index('A.get_json_obj()'))

    def test_audited(self):
        self.assertIn("A.audit_log(actor, 'device_snmp_walk'", self.fn)

    def test_post_only(self):
        self.assertIn("A.method() != 'POST'", self.fn)

    def test_result_count_is_capped(self):
        self.assertIn('min(2000,', self.fn)
        self.assertIn('max_results=limit', self.fn)

    def test_values_are_sanitized_before_returning(self):
        # They land in innerHTML on the client (escaped there too) and come
        # from an unauthenticated UDP protocol.
        self.assertIn('A._sanitize_str(str(v), 512)', self.fn)

    def test_route_registered_and_bound(self):
        api_src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'/snmp/walk', 'handle_device_snmp_walk'", api_src)
        self.assertIn("'handle_device_snmp_walk'", api_src)
        self.assertTrue(callable(getattr(api, 'handle_device_snmp_walk', None)))

    def test_delete_route_guard_lists_the_new_suffix(self):
        # /api/devices/<id>/... DELETE falls through to device-delete unless the
        # suffix is excluded — the sibling snmp routes are all listed.
        api_src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'/snmp', '/snmp/poll', '/snmp/deep', '/snmp/walk',", api_src)

    def test_presets_have_one_definition(self):
        self.assertTrue(len(api.SNMP_WALK_PRESETS) >= 5)
        for oid, label in api.SNMP_WALK_PRESETS:
            self.assertEqual(api._validate_walk_oid(oid), oid, oid)
            self.assertTrue(label)
        # The frontend must not carry its own copy.
        import clientjs
        self.assertNotIn('SNMP_WALK_FALLBACK_PRESETS', clientjs.client_js())

    def test_deep_poll_carries_the_presets(self):
        deep = self.src[self.src.index('def handle_device_snmp_deep('):
                        self.src.index('def _validate_walk_oid(')]
        self.assertIn('SNMP_WALK_PRESETS', deep)


class TestFrontend(unittest.TestCase):
    def setUp(self):
        import clientjs
        self.js = clientjs.client_js()

    def test_action_is_dispatched(self):
        self.assertIn('data-action="snmpWalk"', self.js)
        self.assertIn('async function snmpWalk(', self.js)

    def test_device_id_does_not_travel_through_data_arg(self):
        # The dispatcher runs Number() on a numeric-looking data-arg, so a hex
        # device id like '1e5' would arrive as Infinity.
        fn = self.js[self.js.index('async function snmpWalk('):]
        fn = fn[:fn.index('\nfunction switchDrawerTab(')]
        self.assertIn('_drawerDeviceId', fn)

    def test_values_are_escaped_into_innerhtml(self):
        fn = self.js[self.js.index('async function snmpWalk('):]
        fn = fn[:fn.index('\nfunction switchDrawerTab(')]
        self.assertIn('escHtml(row.value)', fn)
        self.assertIn('escHtml(row.oid)', fn)

    def test_results_table_is_height_capped(self):
        fn = self.js[self.js.index('async function snmpWalk('):]
        fn = fn[:fn.index('\nfunction switchDrawerTab(')]
        self.assertIn('scrollable-table-wrap audit-scroll', fn)

    def test_truncation_is_reported_not_hidden(self):
        fn = self.js[self.js.index('async function snmpWalk('):]
        fn = fn[:fn.index('\nfunction switchDrawerTab(')]
        self.assertIn('r.truncated', fn)


if __name__ == '__main__':
    unittest.main()
