"""v6.2.2 "Pu1seMatters" — agent HTTP keep-alive.

http_post now rides a per-thread persistent connection (one TLS handshake per
agent lifetime instead of one per heartbeat). Driven FUNCTIONALLY against a
real HTTP/1.1 server: connection reuse, the stale-socket single retry, and the
preserved error semantics (any >=300 raises error.HTTPError — http.client
never follows redirects, so the _NoRedirect guarantee holds by construction).
The test swaps the agent's HTTPSConnection for a plain HTTPConnection; TLS
context wiring is pinned separately below.
"""

import http.client
import http.server
import importlib.util
import json
import os
import threading
import types
import unittest
from pathlib import Path
from urllib import error

_ROOT = Path(__file__).parent.parent

_spec = importlib.util.spec_from_file_location(
    "rp_agent_ka", _ROOT / "client" / "remotepower-agent.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    connections = []
    close_next = False
    status_next = 200

    def setup(self):
        super().setup()
        _Handler.connections.append(self.connection)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = json.dumps({"ok": True, "path": self.path}).encode()
        status = _Handler.status_next
        _Handler.status_next = 200
        self.send_response(status)
        if status in (301, 302, 307, 308):
            self.send_header("Location", "http://127.0.0.1:1/nowhere")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if _Handler.close_next:
            _Handler.close_next = False
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestKeepAlive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        # Swap TLS for plain TCP so no cert fixture is needed; everything else
        # (retry, reuse, error mapping) is the real code path.
        cls._real_http_client = agent._http_client
        agent._http_client = types.SimpleNamespace(
            HTTPSConnection=lambda host, timeout=None, context=None:
                http.client.HTTPConnection(host, timeout=timeout),
            HTTPException=http.client.HTTPException,
        )
        for var in ("HTTPS_PROXY", "https_proxy", "RP_NO_KEEPALIVE"):
            os.environ.pop(var, None)

    @classmethod
    def tearDownClass(cls):
        agent._http_client = cls._real_http_client
        cls.srv.shutdown()

    def setUp(self):
        _Handler.connections.clear()
        _Handler.close_next = False
        _Handler.status_next = 200
        agent._ka_drop()

    def _url(self, path="/api/heartbeat"):
        return f"https://127.0.0.1:{self.port}{path}"

    def test_two_posts_reuse_one_connection(self):
        r1 = agent.http_post(self._url(), {"a": 1})
        r2 = agent.http_post(self._url(), {"a": 2})
        self.assertTrue(r1["ok"] and r2["ok"])
        self.assertEqual(len(_Handler.connections), 1,
                         "second POST must ride the same connection")

    def test_stale_socket_gets_one_fresh_retry(self):
        agent.http_post(self._url(), {"a": 1})
        _Handler.close_next = True
        agent.http_post(self._url(), {"a": 2})   # server closes after this one
        r = agent.http_post(self._url(), {"a": 3})   # stale socket → retry
        self.assertTrue(r["ok"])
        self.assertEqual(len(_Handler.connections), 2,
                         "exactly one reconnect after the server dropped it")

    def test_server_error_raises_httperror(self):
        _Handler.status_next = 500
        with self.assertRaises(error.HTTPError) as ctx:
            agent.http_post(self._url(), {"a": 1})
        self.assertEqual(ctx.exception.code, 500)

    def test_redirect_is_refused_not_followed(self):
        """The token-bearing POST body must never be replayed to a redirect
        host — same guarantee _NoRedirect gave the legacy opener."""
        _Handler.status_next = 307
        with self.assertRaises(error.HTTPError) as ctx:
            agent.http_post(self._url(), {"token": "secret"})
        self.assertEqual(ctx.exception.code, 307)
        # And nothing ever connected elsewhere: only our one server connection.
        self.assertEqual(len(_Handler.connections), 1)

    def test_http_url_still_refused(self):
        with self.assertRaises(ValueError):
            agent.http_post(f"http://127.0.0.1:{self.port}/x", {})

    def test_no_keepalive_env_uses_legacy_opener(self):
        os.environ["RP_NO_KEEPALIVE"] = "1"
        try:
            calls = []
            real = agent._ka_request
            agent._ka_request = lambda *a, **k: calls.append(1) or b"{}"
            try:
                # The legacy opener will fail TLS against our plain server —
                # that failure itself proves the keep-alive path was bypassed.
                with self.assertRaises(Exception):
                    agent.http_post(self._url(), {"a": 1})
                self.assertEqual(calls, [], "keep-alive path must be bypassed")
            finally:
                agent._ka_request = real
        finally:
            os.environ.pop("RP_NO_KEEPALIVE", None)


class TestTLSWiring(unittest.TestCase):
    def test_persistent_connection_uses_the_shared_ssl_context(self):
        """The keep-alive transport must carry the SAME _SSL_CTX (CA bundle +
        mTLS client cert) as the legacy opener — a default context would break
        every self-signed-CA fleet on upgrade."""
        src = (_ROOT / "client" / "remotepower-agent.py").read_text()
        i = src.index("_http_client.HTTPSConnection(")
        self.assertIn("context=_SSL_CTX", src[i:i + 200])

    def test_gunicorn_keepalive_flag_shipped(self):
        for rel in ("server/conf/remotepower-wsgi.service",
                    "docker/entrypoint.sh"):
            p = _ROOT / rel
            if not p.exists():
                continue
            self.assertIn("--keep-alive 75", p.read_text(), rel)


if __name__ == "__main__":
    unittest.main()
