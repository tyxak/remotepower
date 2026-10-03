"""SSH gateway daemon, driven end to end with the real libraries.

    asyncssh client ──ProxyJump──> remotepower-sshgw ──WebSocket──> agent's
    _sshgw_serve ──TCP──> an asyncssh server standing in for the host's sshd

Nothing here is mocked except the RemotePower API (the daemon's policy oracle),
which is a small in-memory fake: the API side has its own tests in
test_sshgw.py. What this file proves is that a stock SSH client can actually
reach a host through the gateway and the agent, that bytes survive the framing
in both directions at volume, and that each refusal reaches the client as a
refusal rather than a hang.
"""
import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sshgw-d-'))

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

try:
    import asyncssh
    import websockets
    _DEPS = True
except ImportError:
    _DEPS = False


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeApi:
    def __init__(self):
        self.keys = {}            # username -> fingerprint
        self.allowed = {}         # (username, target) -> device_id
        self.devices = {'d1': 'tok-1'}
        self.opted_in = {'d1'}
        self.audits = []
        self.calls = []

    async def authorize(self, username, fp, target, ip):
        self.calls.append((username, fp, target))
        if self.keys.get(username) != fp:
            return {'ok': False, 'error': 'key not authorized'}
        if not target:
            return {'ok': True}
        did = self.allowed.get((username, target))
        if not did:
            return {'ok': False, 'error': f'no device named "{target}"'}
        return {'ok': True, 'device_id': did, 'device_name': target,
                'session_id': 'sess-' + str(len(self.audits))}

    async def agent_check(self, device_id, token):
        ok = self.devices.get(device_id) == token and device_id in self.opted_in
        return ok, '' if ok else 'device authentication failed'

    async def audit(self, payload):
        self.audits.append(payload)


class _HostSSHServer(asyncssh.SSHServer if _DEPS else object):
    """The managed host's sshd. Accepts one key; `echo` prints, `cat` echoes."""
    def __init__(self, key):
        self.key = key

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == 'root' and key.public_data == self.key.public_data


async def _host_process(process):
    if process.command == 'cat':
        while True:
            data = await process.stdin.read(65536)
            if not data:
                break
            process.stdout.write(data)
        process.exit(0)
    else:
        process.stdout.write(b'hello from the host\n')
        process.exit(0)


@unittest.skipUnless(_DEPS, 'asyncssh / websockets not installed')
class TestGatewayEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.gwmod = _load('rp_sshgw_daemon', ROOT / 'server' / 'sshgw' / 'remotepower-sshgw.py')
        self.agent = _load('rp_agent_for_sshgw', ROOT / 'client' / 'remotepower-agent.py')
        self.api = FakeApi()
        self.user_key = asyncssh.generate_private_key('ssh-ed25519')
        self.root_key = asyncssh.generate_private_key('ssh-ed25519')
        self.api.keys['alice'] = self.user_key.get_fingerprint('sha256')
        self.api.allowed[('alice', 'web01.rp')] = 'd1'
        self.api.allowed[('alice', 'ghost.rp')] = 'd9'   # authorized, no tunnel

        # the host's sshd
        self.host = await asyncssh.create_server(
            lambda: _HostSSHServer(self.root_key.convert_to_public()),
            '127.0.0.1', 0,
            server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
            process_factory=_host_process, encoding=None)
        self.host_port = self.host.sockets[0].getsockname()[1]

        # the gateway
        self.gw = self.gwmod.Gateway(self.api, 'gw.test', 2222)
        self.gw_ssh, self.gw_ws = await self.gwmod.start(
            self.gw, asyncssh.generate_private_key('ssh-ed25519'),
            '127.0.0.1', 0, '127.0.0.1', 0)
        self.gw_port = self.gw_ssh.sockets[0].getsockname()[1]
        self.ws_port = list(self.gw_ws.sockets)[0].getsockname()[1]
        self.agent_tasks = []

    async def asyncTearDown(self):
        for stop, task in self.agent_tasks:
            stop.set()
            try:
                await asyncio.wait_for(task, 5)
            except Exception:
                task.cancel()
        self.gw_ssh.close()
        self.gw_ws.close()
        self.host.close()

    async def start_agent(self, dev_id='d1', token='tok-1'):
        import threading
        stop = threading.Event()
        url = f'ws://127.0.0.1:{self.ws_port}/api/sshgw/tunnel?device_id={dev_id}'
        connected = asyncio.Event()

        async def run():
            kw = {self.agent._WS_HEADER_KW: {'X-RP-Sshgw-Token': token}}
            async with websockets.connect(url, **kw) as ws:
                connected.set()
                await self.agent._sshgw_serve(ws, stop, self.host_port)

        task = asyncio.ensure_future(run())
        self.agent_tasks.append((stop, task))
        await asyncio.wait_for(connected.wait(), 5)
        for _ in range(50):
            if dev_id in self.gw.tunnels:
                break
            await asyncio.sleep(0.05)
        return task

    async def jump(self, key=None, username='alice'):
        return await asyncssh.connect(
            '127.0.0.1', self.gw_port, username=username,
            client_keys=[key or self.user_key], known_hosts=None,
            agent_path=None)

    async def host_conn(self, gw, target='web01.rp'):
        return await asyncssh.connect(
            target, 22, tunnel=gw, username='root',
            client_keys=[self.root_key], known_hosts=None, agent_path=None)

    async def wait_audits(self, n):
        for _ in range(100):
            if len(self.api.audits) >= n:
                return
            await asyncio.sleep(0.05)
        self.fail(f'expected {n} audit records, got {self.api.audits}')

    async def test_command_runs_on_the_host_through_the_gateway(self):
        await self.start_agent()
        async with await self.jump() as gw:
            async with await self.host_conn(gw) as conn:
                r = await conn.run('echo', check=True, encoding=None)
        self.assertEqual(r.stdout, b'hello from the host\n')
        await self.wait_audits(1)
        a = self.api.audits[0]
        self.assertEqual((a['username'], a['device_id']), ('alice', 'd1'))
        self.assertEqual(a['fingerprint'], self.user_key.get_fingerprint('sha256'))
        self.assertGreater(a['bytes_in'], 0)
        self.assertGreater(a['bytes_out'], 0)

    async def test_volume_survives_framing_and_backpressure(self):
        """3 MiB each way: more than the high-water mark, the frame payload cap
        and the agent's read size, so chunking and pause/resume all run."""
        await self.start_agent()
        blob = os.urandom(3 * 1024 * 1024)
        async with await self.jump() as gw:
            async with await self.host_conn(gw) as conn:
                r = await conn.run('cat', input=blob, encoding=None, check=True)
        self.assertEqual(len(r.stdout), len(blob))
        self.assertEqual(r.stdout, blob)

    async def test_two_streams_share_one_tunnel(self):
        await self.start_agent()
        async with await self.jump() as gw:
            c1 = await self.host_conn(gw)
            c2 = await self.host_conn(gw)
            r1, r2 = await asyncio.gather(c1.run('echo'), c2.run('echo'))
            c1.close()
            c2.close()
        self.assertEqual(r1.stdout, r2.stdout)

    async def test_refused_target_reaches_the_client_as_a_refusal(self):
        await self.start_agent()
        async with await self.jump() as gw:
            with self.assertRaises(asyncssh.ChannelOpenError) as cm:
                await self.host_conn(gw, 'db01.rp')
        self.assertIn('no device named', cm.exception.reason)
        self.assertEqual(cm.exception.code, asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED)

    async def test_repeated_refusals_close_the_connection(self):
        self.gwmod.MAX_DENIED_PER_CONN = 3
        gw = await self.jump()
        for _ in range(3):
            with self.assertRaises(asyncssh.ChannelOpenError):
                await self.host_conn(gw, 'db01.rp')
        await asyncio.wait_for(gw.wait_closed(), 5)
        with self.assertRaises((asyncssh.ChannelOpenError, asyncssh.ConnectionLost,
                                asyncssh.DisconnectError, OSError)):
            await self.host_conn(gw, 'web01.rp')

    async def test_authorized_but_no_tunnel_says_so(self):
        async with await self.jump() as gw:
            with self.assertRaises(asyncssh.ChannelOpenError) as cm:
                await self.host_conn(gw, 'ghost.rp')
        self.assertIn('not connected', cm.exception.reason)

    async def test_unregistered_key_cannot_log_in(self):
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.jump(key=asyncssh.generate_private_key('ssh-ed25519'))
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.jump(username='bob')

    async def test_a_login_asks_the_api_once_per_key(self):
        """asyncssh validates the accepted key twice (offer, then signature).
        The second answer comes from the connection's own record."""
        async with await self.jump():
            pass
        logins = [c for c in self.api.calls if not c[2]]
        self.assertEqual(len(logins), 1, logins)

    async def test_key_offers_per_connection_are_capped(self):
        """asyncssh has no MaxAuthTries. Without a cap one unauthenticated
        connection could make an API request per key it offers, for the whole
        login timeout."""
        self.gwmod.MAX_AUTH_ATTEMPTS = 4
        keys = [asyncssh.generate_private_key('ssh-ed25519') for _ in range(12)]
        with self.assertRaises((asyncssh.PermissionDenied, asyncssh.ConnectionLost,
                                asyncssh.DisconnectError, OSError)):
            await asyncssh.connect('127.0.0.1', self.gw_port, username='alice',
                                   client_keys=keys, known_hosts=None, agent_path=None)
        self.assertLessEqual(len(self.api.calls), 4, self.api.calls)

    async def test_unauthenticated_connections_per_address_are_capped(self):
        self.gwmod.MAX_UNAUTH_PER_IP = 2
        idle = [await asyncio.open_connection('127.0.0.1', self.gw_port) for _ in range(2)]
        await asyncio.sleep(0.2)
        with self.assertRaises((asyncssh.ConnectionLost, asyncssh.DisconnectError,
                                asyncssh.PermissionDenied, OSError)):
            await asyncio.wait_for(self.jump(), 10)
        for _r, w in idle:
            w.close()
        for _ in range(50):
            if not self.gw._logging_in:
                break
            await asyncio.sleep(0.05)
        self.assertFalse(self.gw._logging_in, 'closed connections still counted')
        async with await self.jump():
            pass
        self.assertFalse(self.gw._logging_in, 'an authenticated connection is still counted')

    async def test_no_shell_on_the_gateway_just_instructions(self):
        async with await self.jump() as gw:
            r = await gw.run('id')
        self.assertEqual(r.exit_status, 1)
        self.assertIn('ProxyJump alice@gw.test:2222', r.stdout)

    async def test_agent_with_a_bad_token_gets_no_tunnel(self):
        url = f'ws://127.0.0.1:{self.ws_port}/api/sshgw/tunnel?device_id=d1'
        kw = {self.agent._WS_HEADER_KW: {'X-RP-Sshgw-Token': 'wrong'}}
        async with websockets.connect(url, **kw) as ws:
            with self.assertRaises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 5)
            self.assertEqual(ws.close_code, 4403)
        self.assertNotIn('d1', self.gw.tunnels)

    async def test_tunnel_closes_when_the_device_is_opted_out(self):
        self.gwmod.TUNNEL_RECHECK_S = 0.2
        await self.start_agent()
        self.assertIn('d1', self.gw.tunnels)
        self.api.opted_in.discard('d1')
        for _ in range(60):
            if 'd1' not in self.gw.tunnels:
                break
            await asyncio.sleep(0.05)
        self.assertNotIn('d1', self.gw.tunnels)

    async def test_host_sshd_down_is_reported(self):
        self.host.close()
        await self.host.wait_closed()
        await self.start_agent()
        async with await self.jump() as gw:
            with self.assertRaises(asyncssh.ChannelOpenError) as cm:
                await self.host_conn(gw)
        self.assertIn('not reachable on local port', cm.exception.reason)


@unittest.skipUnless(_DEPS, 'asyncssh / websockets not installed')
class TestAgentLocalPolicy(unittest.TestCase):
    def setUp(self):
        self.agent = _load('rp_agent_for_sshgw2', ROOT / 'client' / 'remotepower-agent.py')

    def test_port_comes_from_the_host(self):
        old = os.environ.get('RP_SSHGW_PORT')
        try:
            for raw, want in (('', 22), ('2200', 2200), ('0', 22), ('99999', 22), ('x', 22)):
                os.environ['RP_SSHGW_PORT'] = raw
                self.assertEqual(self.agent._sshgw_local_port(), want, raw)
        finally:
            if old is None:
                os.environ.pop('RP_SSHGW_PORT', None)
            else:
                os.environ['RP_SSHGW_PORT'] = old

    def test_host_kill_switch_and_audit_mode(self):
        # The host owner's kill switch is a real file on the host, not a store
        # key, so it is written through a plain path.
        kill_switch = Path(tempfile.mkdtemp()) / 'sshgw-disabled'
        self.agent.SSHGW_DISABLED_FILE = kill_switch
        self.agent.IN_CONTAINER = False
        self.agent._audit_mode = lambda: False
        self.assertEqual(self.agent._sshgw_blocked_locally(), '')
        kill_switch.write_text('')
        self.assertIn('sshgw-disabled', self.agent._sshgw_blocked_locally())
        kill_switch.unlink()
        self.agent._audit_mode = lambda: True
        self.assertIn('audit', self.agent._sshgw_blocked_locally())


if __name__ == '__main__':
    unittest.main()
