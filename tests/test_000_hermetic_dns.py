#!/usr/bin/env python3
"""Name resolution is off for the test process.

A logger on `socket` during a full serial run (7.4.0) showed unit tests resolving real names:
`api.github.com`, `www.cisa.gov`, `epss.empiricalsecurity.com`, `discord.com`, `api.pushover.net`. They are
not asking on purpose. A test earlier in the process saved a webhook destination into the shared data
directory and never took it out, so every later test that fires an alert delivered to it: four tests in
`test_v642_sweep_fixes` waited 16 to 24 seconds each for the resolver to answer for a host called `x`, and
a version check, a CVE feed fetch and an agent self-update test talked to the internet.

This file is first in discovery order and patches `socket.getaddrinfo` when it is imported, before any
other test module runs: an address literal and `localhost` resolve as before; any other name fails at once
with the error an unreachable resolver gives. Tests of failure paths ("this name does not resolve") see
the same exception they always did. A test that needs a name to resolve stubs the lookup, as it should.

`RP_TEST_REAL_DNS=1` turns it off, to see what a test does on a real network.
"""
import os
import socket
import time
import unittest

_REAL = socket.getaddrinfo
_OPTED_OUT = os.environ.get('RP_TEST_REAL_DNS', '') in ('1', 'true', 'yes')
_ON = not _OPTED_OUT
_LOCAL = {'localhost', 'localhost.localdomain', 'ip6-localhost', ''}


def _numeric(host):
    """True when the resolver reads `host` as an address and needs no lookup: 127.0.0.1, ::1, fe80::1%lo,
    and the older forms a test of the SSRF guard sends on purpose (2130706433, 0x7f.1, 127.1). Asking the
    real resolver with AI_NUMERICHOST is the exact definition. A name it cannot even encode (an empty
    label, 64 characters) raises UnicodeError here, as it does before any lookup in the real call."""
    try:
        _REAL(host, None, flags=socket.AI_NUMERICHOST)
    except socket.gaierror:
        return False
    return True


def _offline_getaddrinfo(host, *args, **kwargs):
    if host is None or (isinstance(host, str) and host.lower() in _LOCAL) or _numeric(host):
        return _REAL(host, *args, **kwargs)
    raise socket.gaierror(socket.EAI_NONAME, 'name resolution is off in the test suite (tests/test_000_hermetic_dns.py)')


_offline_getaddrinfo._rp_offline = True
if _ON:
    socket.getaddrinfo = _offline_getaddrinfo


# skipped only by the person's own switch, never by the guard's own state: a guard that turned itself off
# would otherwise skip its tests and read as a pass
@unittest.skipIf(_OPTED_OUT, 'RP_TEST_REAL_DNS is set')
class TestResolutionIsOff(unittest.TestCase):
    def test_the_patch_is_installed_where_the_other_modules_see_it(self):
        self.assertTrue(getattr(socket.getaddrinfo, '_rp_offline', False),
                        'something replaced the guard; a later test restored the wrong function')

    def test_a_name_fails_at_once_with_the_resolver_error(self):
        t0 = time.monotonic()
        for name in ('api.github.com', 'x', 'discord.com', 'no-such-host.invalid'):
            with self.subTest(name=name):
                with self.assertRaises(socket.gaierror):
                    socket.getaddrinfo(name, 443)
        self.assertLess(time.monotonic() - t0, 1.0, 'name resolution was attempted for real')

    def test_create_connection_goes_through_it(self):
        with self.assertRaises(OSError):
            socket.create_connection(('api.github.com', 443), timeout=2)

    def test_address_literals_and_localhost_still_resolve(self):
        for name in ('127.0.0.1', '::1', 'localhost', '192.0.2.7', 'fe80::1%lo'):
            with self.subTest(name=name):
                self.assertTrue(_numeric(name) or name == 'localhost', name)
                socket.getaddrinfo(name, None)                                 # a literal needs no network

    def test_the_older_numeric_forms_are_addresses_too(self):
        # the SSRF guard's tests send these on purpose; a name check would call them names and let them through
        for name in ('2130706433', '0x7f000001', '127.1', '0177.0.0.1'):
            with self.subTest(name=name):
                self.assertTrue(_numeric(name), name)
                self.assertEqual(socket.getaddrinfo(name, None)[0][4][0], '127.0.0.1')

    def test_a_name_the_resolver_cannot_encode_raises_what_it_raised_before(self):
        # test_v710_agentless_ping_concurrent pins that this is NOT an OSError: a probe swallows OSError, so
        # a bad name would vanish instead of being seen
        for name in ('a..b', 'x' * 70 + '.example'):
            with self.subTest(name=name[:12]):
                with self.assertRaises(UnicodeError):
                    socket.getaddrinfo(name, 80)

    def test_the_wrapper_refuses_what_it_should(self):
        for name in ('example.com', 'x', 'api.github.com', '1.2.3.4.5', 'no-such-host.invalid'):
            with self.subTest(name=name):
                self.assertFalse(_numeric(name), name)


if __name__ == '__main__':
    unittest.main()
