"""An IPv6 zone id is not part of an address, and its text must never be trusted.

`ipaddress.ip_address()` accepts anything after a `%` ("2606:4700::1111%$(id)"
parses), keeps it in `str()`, and the address still counts as global. The ones
that mattered were the sanitisers whose output is interpolated into a shell
command the agent runs as root (the firewall block the threat-intel sweep queues,
the fail2ban action), or into a WireGuard config. Each now refuses a `%`.

Every case below is shown red by removing the refusal in the function it names.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-zoneid-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import edge_blocklist  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402
import wg_access  # noqa: E402

PUBLIC6 = '2606:4700:4700::1111'
# Text a hostile log writer or a compromised agent could put after the "%".
ZONES = ['eth0', '$(id)', ';reboot;', '`id`', 'a b', 'a|b', "a'b", 'a\nPostUp=id', 'x&y']


def _scoped():
    return [f'{PUBLIC6}%{z}' for z in ZONES]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSanitisers(unittest.TestCase):
    def test_the_premise_holds(self):
        # If the standard library ever refuses these itself, the tests below
        # still pass and this one says the guards are now belt and braces.
        import ipaddress
        a = ipaddress.ip_address(f'{PUBLIC6}%$(id)')
        self.assertTrue(a.is_global)
        self.assertIn('$(id)', str(a))

    def test_parse_ip_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertIsNone(ip_intel.parse_ip(v), v)
        self.assertEqual(ip_intel.parse_ip(PUBLIC6), PUBLIC6)
        self.assertEqual(ip_intel.parse_ip('185.220.101.7'), '185.220.101.7')

    def test_is_public_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertFalse(ip_intel.is_public(v), v)
        self.assertTrue(ip_intel.is_public(PUBLIC6))

    def test_firewall_commands_are_never_built_from_one(self):
        for v in _scoped():
            with self.assertRaises(ValueError):
                ip_intel.block_command(v)
            with self.assertRaises(ValueError):
                ip_intel.unblock_command(v)
        self.assertIn(PUBLIC6, ip_intel.block_command(PUBLIC6))

    def test_evidence_public_ip_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertIsNone(threat_evidence.public_ip(v), v)
        self.assertEqual(threat_evidence.public_ip(PUBLIC6), PUBLIC6)

    def test_blocklist_spelling_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertIsNone(edge_blocklist.canonical(v), v)
            self.assertIsNone(edge_blocklist.canonical(v + '/128'), v)
        self.assertEqual(edge_blocklist.canonical(PUBLIC6), PUBLIC6)
        self.assertEqual(edge_blocklist.canonical('185.220.101.0/24'), '185.220.101.0/24')

    def test_wireguard_validators_refuse_a_zone_id(self):
        for v in _scoped():
            self.assertFalse(wg_access.valid_host_ip(v), v)
            self.assertFalse(wg_access.valid_cidr(v + '/128'), v)
        self.assertTrue(wg_access.valid_host_ip('10.8.0.2'))
        self.assertTrue(wg_access.valid_cidr('10.8.0.0/24'))


class TestApiPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-zoneid-api-')
        cls.api = _load(_CGI / 'api.py', 'api_zoneid')

    def test_brute_force_source_keeps_the_address_only(self):
        for z in ZONES:
            got = self.api._brute_src_ip(f'{PUBLIC6}%{z}')
            self.assertEqual(got, PUBLIC6, z)
        self.assertEqual(self.api._brute_src_ip('fe80::1%eth0'), 'fe80::1')

    def test_scan_target_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertEqual(self.api._classify_scan_target(v), (None, ''), v)

    def test_tls_host_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertFalse(self.api._valid_tls_host(v), v)
        self.assertTrue(self.api._valid_tls_host(PUBLIC6))


class TestAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = _load(_ROOT / 'client' / 'remotepower-agent.py', 'agent_zoneid')

    def test_sensor_address_refuses_a_zone_id(self):
        for v in _scoped():
            self.assertIsNone(self.agent._ts_ip(v), v)
            self.assertIsNone(self.agent._ts_ip(f'[{v}]'), v)
        self.assertEqual(self.agent._ts_ip(PUBLIC6), PUBLIC6)

    def test_generic_access_log_does_not_take_a_zone_id_as_the_visitor(self):
        line = (f'{PUBLIC6}%$(id) - - [05/Oct/2026:12:00:01 +0000] '
                '"GET /wp-login.php HTTP/1.1" 403 12 "-" "curl/8"')
        got = self.agent._ts_generic_access(line)
        self.assertIsNone(got)


if __name__ == '__main__':
    unittest.main()
