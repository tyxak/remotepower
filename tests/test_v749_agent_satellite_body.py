#!/usr/bin/env python3
"""7.4.9 agent security pass: the relay satellite must not read a body of any size a stranger names.

`client/remotepower-satellite.py` relays `/api/*` for the agents of a segment that cannot reach the server. It listens on every
address by default and takes no credentials, because the agents' own tokens travel inside what it relays. It read
`int(Content-Length)` bytes from the socket with no ceiling, no check that the header was a number, and no read timeout on the
connection: `Content-Length: 99999999999` made it wait for (and buffer) that much, `-1` made it read until the client hung up, and a
header that was not a number killed the handler thread without an answer. Anybody who could reach the port could hold a thread, and
memory, for as long as they liked. The server refuses bodies over 50 MB, so the relay now refuses them too, with a 413, and answers
a bad header with a 400, without reading the body.

The relay runs in this process on an ephemeral port, in front of a stand-in for the server.
"""
import importlib.machinery
import importlib.util
import os
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SATELLITE = Path(os.environ.get('RP_TEST_SATELLITE') or ROOT / 'client' / 'remotepower-satellite.py')

os.environ['RP_UPSTREAM'] = 'http://127.0.0.1:1'          # replaced below, before the first request
os.environ['RP_SATELLITE_TOKEN'] = 'sat-token-for-the-test'
_loader = importlib.machinery.SourceFileLoader('satellite_under_test', str(SATELLITE))
_spec = importlib.util.spec_from_loader('satellite_under_test', _loader)
sat = importlib.util.module_from_spec(_spec)
_loader.exec_module(sat)


class _Upstream(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n)
        _Upstream.seen.append((self.path, len(body), self.headers.get('X-RP-Satellite')))
        out = b'{"ok": true}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestTheRelayAndItsBodyLimit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.up = _serve(_Upstream)
        sat.UPSTREAM = f'http://127.0.0.1:{cls.up.server_address[1]}'
        cls.relay = _serve(sat.Relay)
        cls.port = cls.relay.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.relay.shutdown()
        cls.up.shutdown()

    def setUp(self):
        _Upstream.seen.clear()

    def raw(self, header_lines, body=b'', wait=5.0):
        """Send a request by hand and return what comes back (b'' when nothing does within `wait` seconds)."""
        s = socket.create_connection(('127.0.0.1', self.port), timeout=wait)
        self.addCleanup(s.close)
        s.sendall(('POST /api/heartbeat HTTP/1.1\r\nHost: relay\r\n' + ''.join(h + '\r\n' for h in header_lines) + '\r\n').encode() + body)
        try:
            return s.recv(4096)
        except (socket.timeout, ConnectionError):
            return b''

    def test_an_ordinary_request_is_relayed_with_the_satellite_token(self):
        out = self.raw(['Content-Length: 5', 'Content-Type: application/json'], b'hello')
        self.assertTrue(out.startswith(b'HTTP/1.1 200'), out)
        # assertIn, not assertEqual: a relay that reads a bogus length until the client leaves forwards the half request after
        # it has gone, which lands in the list during a later test.
        self.assertIn(('/api/heartbeat', 5, 'sat-token-for-the-test'), _Upstream.seen)

    def test_a_body_larger_than_the_server_would_take_is_refused_at_once(self):
        out = self.raw(['Content-Length: 99999999999'])           # promises 100 GB, sends nothing
        self.assertTrue(out.startswith(b'HTTP/1.1 413'), f'no 413 for an absurd Content-Length: {out!r}')
        self.assertIn(b'Connection: close', out)
        self.assertEqual(_Upstream.seen, [])

    def test_the_limit_is_the_servers(self):
        self.assertEqual(sat.MAX_BODY, 50 * 1024 * 1024)
        self.assertTrue(self.raw([f'Content-Length: {sat.MAX_BODY + 1}']).startswith(b'HTTP/1.1 413'))

    def test_a_negative_length_is_refused_not_read_until_the_client_hangs_up(self):
        out = self.raw(['Content-Length: -1'])
        self.assertTrue(out.startswith(b'HTTP/1.1 400'), f'no 400 for Content-Length: -1: {out!r}')
        self.assertEqual(_Upstream.seen, [])

    def test_a_length_that_is_not_a_number_is_answered(self):
        out = self.raw(['Content-Length: lots'])
        self.assertTrue(out.startswith(b'HTTP/1.1 400'), f'no 400 for a non-numeric Content-Length: {out!r}')

    def test_a_connection_that_says_nothing_is_dropped(self):
        self.assertGreaterEqual(sat.Relay.timeout, 1)
        self.assertLessEqual(sat.Relay.timeout, 300)


if __name__ == '__main__':
    unittest.main()
