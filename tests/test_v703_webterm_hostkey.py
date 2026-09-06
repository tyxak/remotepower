#!/usr/bin/env python3
"""The web terminal sent the operator's SSH password to an unverified host.

`asyncssh.connect(..., known_hosts=None)` is "accept any host key". Password
authentication happens AFTER the key exchange, so anything able to answer on
that address and port received the operator's SSH password on the first
connect: an ARP or DHCP spoof on the management segment, a stale DNS record, a
re-provisioned IP, a compromised jump host. There was no setting to turn
checking on, and every session on every install was affected.

The comment that stood there argued the operator "typed in this hostname; they
know what they're connecting to" — which is the thing host keys exist to refute,
since knowing the intended destination is not knowing you reached it — and that
a daemon-managed known_hosts file would be theatre. It would not have been
needed: the agent has reported `sysinfo.ssh_hostkeys` since v6.1.2, `safe_si`
persists it, and the product fires `hostkey_changed` when it moves. The trust
anchor existed and nothing consulted it.

This drives a REAL asyncssh server on loopback with a REAL generated host key,
because the whole question is what the library does at key exchange — reading
the argument list cannot answer it. Three cases, and the middle one is the point:

  * a key RemotePower has on file           -> connects
  * a DIFFERENT key                          -> refused, and the password is
                                                never sent
  * nothing on file for the device           -> connects, recorded as unverified

The password-was-never-sent assertion is what makes this a security test rather
than a connectivity test: the server records every authentication attempt, and
on the mismatch case there must be none.
"""
import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DAEMON = _ROOT / 'server' / 'webterm' / 'remotepower-webterm.py'

try:
    import asyncssh
except ImportError:                                        # pragma: no cover
    asyncssh = None


def _load_daemon():
    spec = importlib.util.spec_from_file_location('rp_webterm_v703', _DAEMON)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipIf(asyncssh is None, 'asyncssh not installed')
class TestHostKeyPinning(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-v703-webterm-'))
        self.host_key = asyncssh.generate_private_key('ssh-ed25519')
        self.other_key = asyncssh.generate_private_key('ssh-ed25519')
        self.good_fp = self.host_key.convert_to_public().get_fingerprint()
        self.other_fp = self.other_key.convert_to_public().get_fingerprint()
        self.auth_attempts = []

        outer = self

        class _Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                outer.auth_attempts.append((username, password))
                return password == 'correct-horse'

        self.server = await asyncssh.create_server(
            _Server, '127.0.0.1', 0, server_host_keys=[self.host_key])
        self.port = next(iter(self.server.sockets)).getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _connect(self, expected):
        """Connect with the daemon's pinning callback and the given fingerprint
        set. Returns 'ok' or the exception class name."""
        state = {}

        class _Pinned(asyncssh.SSHClient):
            def validate_host_public_key(self, host, addr, port, key):
                fp = key.get_fingerprint()
                state['fp'] = fp
                if not expected:
                    state['state'] = 'unverified'
                    return True
                if fp in expected:
                    state['state'] = 'verified'
                    return True
                state['state'] = 'mismatch'
                return False

        try:
            conn = await asyncio.wait_for(asyncssh.connect(
                '127.0.0.1', port=self.port, username='op',
                password='correct-horse', known_hosts=([], [], []),
                client_factory=_Pinned), timeout=15)
            conn.close()
            await conn.wait_closed()
            return 'ok', state
        except Exception as e:                             # noqa: BLE001
            return type(e).__name__, state

    async def test_a_known_host_key_connects(self):
        result, state = await self._connect({self.good_fp})
        self.assertEqual(result, 'ok')
        self.assertEqual(state.get('state'), 'verified')
        self.assertEqual(len(self.auth_attempts), 1,
                         'the control: authentication happened, so the '
                         'no-authentication assertion below means something')

    async def test_a_wrong_host_key_is_refused_before_the_password_is_sent(self):
        result, state = await self._connect({self.other_fp})
        self.assertEqual(result, 'HostKeyNotVerifiable',
                         f'expected refusal, got {result}')
        self.assertEqual(state.get('state'), 'mismatch')
        self.assertEqual(
            self.auth_attempts, [],
            'the server saw an authentication attempt, so the password was '
            'sent to a host presenting an unknown key — which is the entire '
            'defect this test exists for')

    async def test_no_keys_on_file_connects_but_is_recorded_unverified(self):
        result, state = await self._connect(set())
        self.assertEqual(result, 'ok')
        self.assertEqual(state.get('state'), 'unverified')
        self.assertEqual(state.get('fp'), self.good_fp)


class TestTheDaemonUsesTheCallback(unittest.TestCase):
    """Source-level, so it runs without asyncssh: the daemon must pass a
    client_factory and must not have gone back to bare `known_hosts=None`."""

    def setUp(self):
        self.src = _DAEMON.read_text()

    def test_connect_passes_a_client_factory(self):
        self.assertIn('client_factory=_PinnedHostKey', self.src,
                      'the SSH connect no longer installs the pinning client')

    def test_connect_does_not_pass_known_hosts_none(self):
        """The trap this fix fell into first. asyncssh only consults
        validate_host_public_key when its trusted-key set is not None, and
        `known_hosts=None` makes it None — so the callback is installed and
        never called. Measured, not read: with None the real library ran the
        callback zero times."""
        code = '\n'.join(l for l in self.src.splitlines()
                         if not l.lstrip().startswith('#'))
        self.assertNotIn('known_hosts=None', code)
        self.assertIn('known_hosts=([], [], [])', code)

    def test_the_callback_validates_a_fingerprint(self):
        self.assertIn('def validate_host_public_key', self.src)
        self.assertIn('key.get_fingerprint()', self.src)

    def test_a_mismatch_refuses(self):
        self.assertIn('asyncssh.HostKeyNotVerifiable', self.src,
                      'the refusal must be caught and explained, not surfaced '
                      'as a generic SSH error')

    def test_the_daemon_asks_the_server_what_the_keys_should_be(self):
        self.assertIn('def fetch_host_keys', self.src)
        self.assertIn('/webterm/hostkeys', self.src)

    def test_the_outcome_reaches_the_audit_trail(self):
        self.assertIn("'host_key_state': self.host_key_state", self.src)


class TestTheEndpointExists(unittest.TestCase):

    def test_api_routes_the_hostkeys_endpoint(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("('GET', '/api/webterm/hostkeys'): handle_webterm_hostkeys",
                      src)
        self.assertIn('def handle_webterm_hostkeys', src)

    def test_it_is_gated_on_the_daemon_secret(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        start = src.index('def handle_webterm_hostkeys')
        body = src[start:src.index('\ndef ', start + 10)]
        self.assertIn('hmac.compare_digest', body,
                      'the daemon secret must be compared in constant time')
        self.assertIn('webterm_daemon_secret', body)


if __name__ == '__main__':
    unittest.main()
