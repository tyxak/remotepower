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
