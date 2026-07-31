"""Behaviour lock for the extracted sanitize.py leaf module (v3.4.0 refactor).

These pure helpers moved out of api.py; api.py imports them back by name. The
test pins the behaviour and that api re-exports the same objects (so the 268
call sites resolve to the moved functions).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import sanitize  # noqa: E402
import api  # noqa: E402


class TestSanitizeModule(unittest.TestCase):
    def test_str(self):
        self.assertEqual(sanitize._sanitize_str('  hi  ', 10), 'hi')
        self.assertEqual(sanitize._sanitize_str(None, 10), '')
        self.assertEqual(sanitize._sanitize_str('abcdef', 3), 'abc')
        self.assertEqual(sanitize._sanitize_str('   ', 5, allow_empty=False), '')

    def test_hostname(self):
        self.assertEqual(sanitize._sanitize_hostname('host.example.com'), 'host.example.com')
        self.assertEqual(sanitize._sanitize_hostname('bad/;name'), 'badname')
        self.assertEqual(sanitize._sanitize_hostname(''), 'unknown')

    def test_ip(self):
        self.assertEqual(sanitize._sanitize_ip('10.0.0.1'), '10.0.0.1')
        self.assertEqual(sanitize._sanitize_ip('999.1.1.1'), '')
        self.assertEqual(sanitize._sanitize_ip(''), '')

    def test_ip_rejects_trailing_garbage(self):
        # Regression: the IPv4 branch of _IP_RE lacked its closing anchor, so a
        # valid-IP prefix matched and _sanitize_ip returned the whole string
        # verbatim (trailing garbage and all) instead of rejecting it.
        self.assertEqual(sanitize._sanitize_ip('1.2.3.4 anything-here'), '')
        self.assertEqual(sanitize._sanitize_ip('1.2.3.4; rm -rf /'), '')
        self.assertEqual(sanitize._sanitize_ip('1.2.3.4.5'), '')
        self.assertEqual(sanitize._sanitize_ip('10.0.0.1xyz'), '')
        # A clean simplified IPv6 still validates (both branches stay anchored).
        self.assertEqual(
            sanitize._sanitize_ip('2001:0db8:0000:0000:0000:0000:0000:0001'),
            '2001:0db8:0000:0000:0000:0000:0000:0001')

    def test_ipv6_is_accepted_in_the_form_people_actually_write(self):
        # Regression: the IPv6 branch matched ONLY the fully-expanded eight-group
        # form, so every real address silently became ''. It reached the audit
        # log's source_ip, device create/update, the interface inventory, the
        # gateway and the WordPress login table — nothing logged, the field was
        # just empty on any IPv6 network.
        for ip in ('2001:db8::1', '::1', '2a02:1810:1234:5678::1f',
                   '::ffff:192.0.2.1', 'fd00::abcd'):
            self.assertEqual(sanitize._sanitize_ip(ip), ip, ip)
        # A zone id is interface-local metadata, not part of the address.
        self.assertEqual(sanitize._sanitize_ip('fe80::1%eth0'), 'fe80::1')
        # And nothing previously accepted may now be rejected — the old regex is
        # kept as a fallback for forms `ipaddress` considers ambiguous.
        self.assertEqual(sanitize._sanitize_ip('192.168.001.1'), '192.168.001.1')
        for bad in ('not-an-ip', '1.2.3.4.5', '999.1.1.1', '203.0.113.7, 10.0.0.1'):
            self.assertEqual(sanitize._sanitize_ip(bad), '', bad)

    def test_hostname_keeps_underscores_instead_of_rewriting_the_host(self):
        # Regression: this function does not REJECT what it dislikes, it silently
        # REWRITES it — `db_primary` was enrolled as `dbprimary`. Underscores are
        # forbidden by RFC-1123 and ubiquitous in practice (Windows/AD,
        # docker-compose, homelabs), so every later join on the hostname failed
        # against the machine's real name. The one that bites is the EDR coverage
        # cross-reference, which compares our stored name to the name the EDR
        # itself reports: the host read `covered: false` while it was protected,
        # and a false "unprotected" is what teaches an operator to ignore the list.
        for h in ('db_primary', 'SQL_NODE_1', 'my_server.lan', 'host_01.corp.local'):
            self.assertEqual(sanitize._sanitize_hostname(h), h, h)
        # Genuinely unsafe characters are still removed.
        for bad, want in (('a b', 'ab'), ('host<script>', 'hostscript'),
                          ('bad/;name', 'badname'), ('host\x00x', 'hostx')):
            self.assertEqual(sanitize._sanitize_hostname(bad), want, bad)

    def test_edr_coverage_join_survives_an_underscore_hostname(self):
        # The end of the chain above, driven rather than asserted about: an EDR
        # agent reporting the host's real name must match our stored record.
        stored = sanitize._sanitize_hostname('db_primary')
        norm = api._edr_norm_host
        self.assertEqual(norm(stored), norm('db_primary'),
                         'EDR coverage would report a protected host as uncovered')

    def test_mac(self):
        self.assertEqual(sanitize._sanitize_mac('AA:BB:CC:DD:EE:FF'), 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(sanitize._sanitize_mac('nope'), '')

    def test_version(self):
        self.assertEqual(sanitize._sanitize_version('1.2.3'), '1.2.3')
        self.assertEqual(sanitize._sanitize_version('garbage!'), '')

    def test_api_reexports_same_objects(self):
        # api.py must import the moved functions, not keep stale copies.
        for name in ('_sanitize_str', '_sanitize_hostname', '_sanitize_ip',
                     '_sanitize_mac', '_sanitize_version'):
            self.assertIs(getattr(api, name), getattr(sanitize, name), name)
        self.assertEqual(api.MAX_HOSTNAME_LEN, 253)


if __name__ == '__main__':
    unittest.main()
