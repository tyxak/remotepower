"""The agent's WebSocket channels must not carry the device token across a
redirect.

The push listener and the SSH-gateway tunnel both authenticate with a custom
header (X-RP-Push-Token, X-RP-Sshgw-Token). `websockets.connect` follows
redirects, and on a cross-origin one it strips only Authorization, Cookie and
Proxy-Authorization — so a custom token header is replayed to whatever host the
3xx names. Driven for real: server A answers the upgrade with a 302 to server
B, and B records every request line and header it receives.

The control case runs the stock `websockets.connect` against the same pair and
must see the token arrive at B. Without it, a B that never got a connection for
some unrelated reason would read as "no leak".
"""
import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-wsredir-'))

ROOT = Path(__file__).resolve().parent.parent

try:
    import websockets
    _DEPS = True
except ImportError:
    _DEPS = False

TOKEN = 'device-token-must-stay-home'


def _load_agent():
    spec = importlib.util.spec_from_file_location(
        'rp_agent_wsredir', ROOT / 'client' / 'remotepower-agent.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _pair():
    """(redirector_port, sink_port, sink_received: list[bytes], close())."""
    received = []

    async def sink(reader, writer):
        try:
            received.append(await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5))
        except Exception:
            pass
        writer.close()

    sink_srv = await asyncio.start_server(sink, '127.0.0.1', 0)
    sink_port = sink_srv.sockets[0].getsockname()[1]

    async def redirector(reader, writer):
        try:
            await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            writer.write(('HTTP/1.1 302 Found\r\n'
                          f'Location: ws://127.0.0.1:{sink_port}/stolen\r\n'
                          'Content-Length: 0\r\nConnection: close\r\n\r\n').encode())
            await writer.drain()
        except Exception:
            pass
        writer.close()

    red_srv = await asyncio.start_server(redirector, '127.0.0.1', 0)
    red_port = red_srv.sockets[0].getsockname()[1]

    def close():
        sink_srv.close()
        red_srv.close()

    return red_port, sink_port, received, close


@unittest.skipUnless(_DEPS, 'needs the websockets package (the agent push/tunnel dependency)')
class TestWebSocketRedirect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = _load_agent()

    def _attempt(self, connect, header):
        async def go():
            red, _sink, received, close = await _pair()
            kw = {self.agent._WS_HEADER_KW: {header: TOKEN}, 'open_timeout': 5}
            try:
                async with connect(f'ws://127.0.0.1:{red}/api/push/connect?device_id=d1', **kw):
                    pass
            except Exception:
                pass
            await asyncio.sleep(0.2)
            close()
            return b''.join(received)
        return asyncio.run(go())

    def test_control_the_stock_client_leaks_the_header(self):
        got = self._attempt(websockets.connect, 'X-RP-Push-Token')
        self.assertIn(TOKEN.encode(), got,
                      'control failed: the stock client did not reach the redirect '
                      'target, so the assertions below would prove nothing')

    def test_push_token_does_not_follow_a_redirect(self):
        got = self._attempt(self.agent._WS_CONNECT, 'X-RP-Push-Token')
        self.assertEqual(got, b'', 'the redirect target received a request')

    def test_sshgw_token_does_not_follow_a_redirect(self):
        got = self._attempt(self.agent._WS_CONNECT, 'X-RP-Sshgw-Token')
        self.assertEqual(got, b'', 'the redirect target received a request')

    def test_both_channels_use_the_guarded_connect(self):
        src = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertNotIn('websockets.connect(url', src,
                         'a WebSocket channel connects with the redirect-following default')
        self.assertEqual(src.count('async with _WS_CONNECT(url'), 2)


if __name__ == '__main__':
    unittest.main()
