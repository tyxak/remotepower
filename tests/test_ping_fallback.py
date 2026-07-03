"""Agentless ICMP reachability fallback chain (v5.8.0, issue #20).

The stock Docker image and minimal Debian installs ship no `ping` binary, so
every ICMP-mode agentless device flipped offline forever ~2 sweeps after being
added (the netscan that discovered them worked fine — different mechanism).
_ping_host is now tiered: system ping → unprivileged ICMP datagram socket →
TCP connect probe (success OR refused = up). These tests pin the tier logic
(with the binary and socket layers faked), the TCP-probe semantics against a
real loopback socket, and the packaging fixes (iputils shipped everywhere).
"""
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_pingfb', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _FakeRun:
    """subprocess.run stand-in: returncode, or an exception to raise."""

    def __init__(self, returncode=None, exc=None):
        self.returncode_, self.exc = returncode, exc
        self.calls = 0

    def __call__(self, *a, **k):
        self.calls += 1
        if self.exc:
            raise self.exc
        class R:  # noqa: N801
            returncode = self.returncode_
        return R()


class TestPingHostTiers(unittest.TestCase):
    def setUp(self):
        self._run = api.subprocess.run
        self._icmp = api._icmp_socket_ping
        self._tcp = api._tcp_reach_ping
        api._PING_FALLBACK_LOGGED = True   # keep test stderr quiet

    def tearDown(self):
        api.subprocess.run = self._run
        api._icmp_socket_ping = self._icmp
        api._tcp_reach_ping = self._tcp

    def test_binary_up_short_circuits(self):
        api.subprocess.run = _FakeRun(returncode=0)
        api._icmp_socket_ping = lambda *a, **k: self.fail('must not be called')
        self.assertTrue(api._ping_host('192.0.2.1'))

    def test_binary_down_is_authoritative_no_tcp_softening(self):
        # ping ran (rc 1 = no reply): host is down; the TCP tier must NOT run.
        api.subprocess.run = _FakeRun(returncode=1)
        api._icmp_socket_ping = lambda *a, **k: None
        api._tcp_reach_ping = lambda *a, **k: self.fail('TCP tier must not run')
        self.assertFalse(api._ping_host('192.0.2.1'))

    def test_missing_binary_falls_to_icmp_socket(self):
        api.subprocess.run = _FakeRun(exc=FileNotFoundError('ping'))
        api._icmp_socket_ping = lambda *a, **k: True
        self.assertTrue(api._ping_host('192.0.2.1'))

    def test_socket_down_is_authoritative_no_tcp_softening(self):
        api.subprocess.run = _FakeRun(exc=FileNotFoundError('ping'))
        api._icmp_socket_ping = lambda *a, **k: False
        api._tcp_reach_ping = lambda *a, **k: self.fail('TCP tier must not run')
        self.assertFalse(api._ping_host('192.0.2.1'))

    def test_no_icmp_mechanism_falls_to_tcp(self):
        api.subprocess.run = _FakeRun(exc=FileNotFoundError('ping'))
        api._icmp_socket_ping = lambda *a, **k: None
        api._tcp_reach_ping = lambda *a, **k: True
        self.assertTrue(api._ping_host('192.0.2.1'))

    def test_ping_error_rc2_falls_through(self):
        # rc 2 = ping errored (no caps, bad env) — NOT "host down".
        api.subprocess.run = _FakeRun(returncode=2)
        api._icmp_socket_ping = lambda *a, **k: True
        self.assertTrue(api._ping_host('192.0.2.1'))

    def test_empty_host_false(self):
        self.assertFalse(api._ping_host(''))


class TestTcpReachPing(unittest.TestCase):
    def test_refused_proves_up(self):
        # A definitely-closed loopback port: bind → learn the port → close.
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        self.assertTrue(api._tcp_reach_ping('127.0.0.1', ports=(port,)))

    def test_open_port_proves_up(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(api._tcp_reach_ping('127.0.0.1', ports=(port,)))
        finally:
            srv.close()

    def test_unresolvable_is_down(self):
        self.assertFalse(api._tcp_reach_ping('nope.invalid', ports=(80,)))


class TestIcmpSocketPing(unittest.TestCase):
    def test_loopback_or_unavailable(self):
        # In a permissive environment (systemd default ping_group_range) the
        # loopback answers; a sandbox may forbid the socket → None. Both are
        # valid; only False (loopback "down") would be a bug.
        res = api._icmp_socket_ping('127.0.0.1', timeout=2)
        if res is None:
            self.skipTest('unprivileged ICMP sockets forbidden here')
        self.assertTrue(res)

    def test_unresolvable_is_false_not_none(self):
        self.assertFalse(api._icmp_socket_ping('nope.invalid') is not False)


class TestIcmpReachableFallback(unittest.TestCase):
    def test_source_uses_socket_fallback(self):
        src = (_CGI / 'api.py').read_text()
        # _icmp_reachable ("definitely up?" pre-offline guard) must consult the
        # unprivileged socket when the binary is missing — True-only contract.
        self.assertIn('return _icmp_socket_ping(host, to) is True', src)
        # The ping monitor type falls back for its single up/down check.
        self.assertIn("ok = _icmp_socket_ping(target, 2) is True", src)


class TestPackagingShipsPing(unittest.TestCase):
    def test_dockerfile(self):
        self.assertIn('iputils-ping', (_ROOT / 'Dockerfile').read_text())

    def test_install_server(self):
        src = (_ROOT / 'install-server.sh').read_text()
        self.assertIn('iputils-ping', src)          # apt
        self.assertEqual(src.count('iputils'), 3)   # apt + dnf + pacman

    def test_aur_server_depends(self):
        self.assertIn("'iputils'",
                      (_ROOT / 'packaging/aur/remotepower-server/PKGBUILD').read_text())


if __name__ == '__main__':
    unittest.main()
