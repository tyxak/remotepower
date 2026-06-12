#!/usr/bin/env python3
"""v4.3.0: persistent SCGI prefork API worker (server/cgi-bin/api_worker.py).

Two layers:
  * protocol unit tests — netstring + SCGI header parsing (no fork, no api.py)
  * an end-to-end smoke test — boot the real worker on a temp unix socket,
    send a raw SCGI request, and assert a CGI-style response comes back.
    This is the test that proves the fork-per-request plumbing (env setup,
    stdin/stdout rebinding, HTTPError unwinding) actually works; the protocol
    tests alone would pass with a broken child.
"""

import io
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import api_worker  # noqa: E402


def _netstring(headers: dict) -> bytes:
    blob = b"".join(k.encode() + b"\x00" + v.encode() + b"\x00" for k, v in headers.items())
    return str(len(blob)).encode() + b":" + blob + b","


class TestSCGIParsing(unittest.TestCase):
    def test_read_netstring_roundtrip(self):
        payload = b"CONTENT_LENGTH\x000\x00SCGI\x001\x00"
        buf = io.BytesIO(str(len(payload)).encode() + b":" + payload + b",rest")
        self.assertEqual(api_worker.read_netstring(buf), payload)
        self.assertEqual(buf.read(), b"rest")  # body bytes stay on the stream

    def test_read_netstring_rejects_garbage(self):
        for raw in (b"", b"abc:x,", b"5:ab,", b"3:abcX"):
            with self.assertRaises(api_worker.SCGIProtocolError):
                api_worker.read_netstring(io.BytesIO(raw))

    def test_parse_headers(self):
        env = api_worker.parse_scgi_headers(b"REQUEST_METHOD\x00GET\x00PATH_INFO\x00/api/home\x00")
        self.assertEqual(env["REQUEST_METHOD"], "GET")
        self.assertEqual(env["PATH_INFO"], "/api/home")

    def test_oversized_header_block_refused(self):
        # v4.3.0 security review: a fabricated netstring length must not make
        # the worker allocate unbounded memory (local socket-access DoS).
        big = str(api_worker.MAX_HEADER_BYTES + 1).encode() + b":x"
        with self.assertRaises(api_worker.SCGIProtocolError):
            api_worker.read_netstring(io.BytesIO(big))

    def test_parse_headers_rejects_odd_parts(self):
        with self.assertRaises(api_worker.SCGIProtocolError):
            api_worker.parse_scgi_headers(b"KEY_WITHOUT_VALUE\x00")


class TestWorkerEndToEnd(unittest.TestCase):
    """Boot the real worker once for the class; each test is one request."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp()
        cls.sock_dir = tempfile.mkdtemp()
        cls.sock_path = os.path.join(cls.sock_dir, "api.sock")
        env = dict(
            os.environ, RP_DATA_DIR=cls.data_dir, RP_SCGI_SOCKET=cls.sock_path, RP_WORKER_MAX="4"
        )
        cls.proc = subprocess.Popen(
            [sys.executable, str(_CGI / "api_worker.py")], env=env, stderr=subprocess.PIPE
        )
        # api.py import takes a moment; wait for the socket to appear.
        deadline = time.time() + 60
        while not os.path.exists(cls.sock_path):
            if cls.proc.poll() is not None:
                raise RuntimeError(
                    "worker died at startup:\n" + cls.proc.stderr.read().decode(errors="replace")
                )
            if time.time() > deadline:
                cls.proc.kill()
                raise RuntimeError("worker socket never appeared")
            time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def _request(self, method, path, body=b"", extra=None):
        headers = {
            "CONTENT_LENGTH": str(len(body)),
            "SCGI": "1",
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "RP_DATA_DIR": self.data_dir,
        }
        if extra:
            headers.update(extra)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(60)
        s.connect(self.sock_path)
        s.sendall(_netstring(headers) + body)
        chunks = []
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
        s.close()
        return b"".join(chunks).decode(errors="replace")

    def test_unknown_route_returns_cgi_style_404(self):
        resp = self._request("GET", "/api/__no_such_route__")
        self.assertTrue(resp.startswith("Status: 404"), resp[:200])
        self.assertIn("Content-Type: application/json", resp)

    def test_auth_required_route_returns_401_not_500(self):
        resp = self._request("GET", "/api/devices")
        self.assertTrue(resp.startswith("Status: 401"), resp[:200])
        self.assertIn("Unauthorized", resp)

    def test_requests_are_isolated(self):
        """Two sequential requests must not bleed state — same answers twice
        (the fork-per-request contract that makes the worker safe)."""
        a = self._request("GET", "/api/devices")
        b = self._request("GET", "/api/devices")
        self.assertEqual(a.splitlines()[0], b.splitlines()[0])

    def test_post_body_reaches_handler(self):
        body = b'{"username": "x", "password": "y"}'
        resp = self._request(
            "POST", "/api/login", body=body, extra={"CONTENT_TYPE": "application/json"}
        )
        # Wrong creds → 401/403/429, never a body-parse 400/500: proves the
        # SCGI body made it through the rebound stdin to the handler.
        status = resp.splitlines()[0]
        self.assertNotIn("500", status, resp[:300])
        self.assertNotIn("400", status, resp[:300])


if __name__ == "__main__":
    unittest.main()
