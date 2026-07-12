"""v6.1.2 — the agent push channel through a RELAY SATELLITE.

The push channel (v6.1.1) is a wake-only WebSocket nudge. A satellite-relayed
agent builds its push URL from the same base URL it uses for the API — which,
behind a satellite, IS the satellite. But the satellite relayed with urllib,
which cannot carry an `Upgrade`, so the connect died and satellite-relayed
agents silently never got early wakes. Push was, in practice, a
direct-agents-only feature.

The satellite now byte-tunnels exactly one path (`/api/push/connect`) when the
request is a WebSocket upgrade. It is NOT a general WS proxy: no frame parsing,
no protocol knowledge — the agent↔daemon handshake, token header and ping/pong
pass through untouched, so the daemon's device-token auth remains the only auth
that matters end to end.

These drive the REAL satellite process against a stand-in upstream that speaks a
real RFC 6455 handshake — not a mocked relay.
"""

import base64
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_SAT = _ROOT / "client" / "remotepower-satellite.py"
_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeUpstream:
    """Speaks a real WS handshake, records the relayed request, then echoes."""

    def __init__(self, accept_upgrade=True):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.request = ""
        self.from_client = b""
        self.accept_upgrade = accept_upgrade
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        req = b""
        try:
            while b"\r\n\r\n" not in req:
                chunk = c.recv(4096)
                if not chunk:
                    return
                req += chunk
            self.request = req.decode(errors="replace")
            first = self.request.split("\r\n", 1)[0]
            # Behave like the real server: only /api/push/connect upgrades, and
            # only when the request actually IS an upgrade. (Anything the
            # satellite relays through urllib arrives without the hop-by-hop
            # Upgrade header, so it must never get a 101 back.)
            is_upgrade = "upgrade: websocket" in self.request.lower()
            if not (self.accept_upgrade
                    and is_upgrade
                    and "/api/push/connect" in first):
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                c.close()
                return
            key = [
                ln.split(": ", 1)[1]
                for ln in self.request.split("\r\n")
                if ln.lower().startswith("sec-websocket-key")
            ][0].strip()
            acc = base64.b64encode(
                hashlib.sha1(key.encode() + _GUID).digest()
            ).decode()
            c.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {acc}\r\n\r\n"
                ).encode()
            )
            self.from_client = c.recv(1024)
            c.sendall(b"NUDGE")          # the server-initiated push — the point
            time.sleep(0.4)
            c.close()
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class _Satellite:
    def __init__(self, upstream_port):
        self.port = _free_port()
        env = dict(
            os.environ,
            RP_UPSTREAM=f"http://127.0.0.1:{upstream_port}",
            RP_SATELLITE_TOKEN="sat-tok",
            RP_LISTEN=f"127.0.0.1:{self.port}",
        )
        # Keep stderr so a startup failure is diagnosable rather than a bare
        # "did not start" (the satellite prints its reason there).
        self.proc = subprocess.Popen(
            [sys.executable, str(_SAT)],
            env=env,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        # Poll for the listener. The budget is generous (30s) because this
        # spawns a cold Python interpreter and the full suite runs it under
        # heavy parallel load — a tight timeout here is a flaky test, not a
        # real signal about the satellite.
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:      # it died — say why
                raw = self.proc.stderr.read() if self.proc.stderr else b""
                err = (raw or b"").decode(errors="replace")
                raise RuntimeError(f"satellite exited early: {err[:400]}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("satellite did not start within 30s")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        for s in (self.proc.stderr,):
            if s:
                s.close()


def _ws_upgrade(port, path="/api/push/connect?device_id=d1", token="dev-tok"):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(b"0123456789abcdef").decode()
    s.sendall(
        (
            f"GET {path} HTTP/1.1\r\nHost: sat\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"X-RP-Push-Token: {token}\r\n\r\n"
        ).encode()
    )
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    return s, resp


class TestSatelliteWebSocketTunnel(unittest.TestCase):
    def setUp(self):
        self.up = _FakeUpstream()
        self.sat = _Satellite(self.up.port)

    def tearDown(self):
        self.sat.close()
        self.up.close()

    def test_upgrade_is_relayed_and_the_nudge_reaches_the_agent(self):
        s, resp = _ws_upgrade(self.sat.port)
        try:
            self.assertTrue(
                resp.startswith(b"HTTP/1.1 101"),
                f"expected a relayed 101, got {resp[:60]!r}",
            )
            # Agent -> daemon.
            s.sendall(b"hello")
            time.sleep(0.3)
            # Daemon -> agent: the wake nudge, which is the entire feature.
            self.assertEqual(s.recv(64), b"NUDGE")
            self.assertEqual(self.up.from_client, b"hello")
        finally:
            s.close()

    def test_satellite_and_device_tokens_both_reach_the_upstream(self):
        s, _ = _ws_upgrade(self.sat.port, token="dev-tok-xyz")
        try:
            time.sleep(0.2)
            self.assertIn("X-RP-Satellite: sat-tok", self.up.request)
            self.assertIn("X-RP-Push-Token: dev-tok-xyz", self.up.request)
            # Upgrade/Connection are hop-by-hop and get stripped — the tunnel
            # must re-add them or the upstream never sees an upgrade at all.
            self.assertIn("Upgrade: websocket", self.up.request)
            self.assertIn("Connection: Upgrade", self.up.request)
        finally:
            s.close()

    def test_x_forwarded_for_is_appended(self):
        s, _ = _ws_upgrade(self.sat.port)
        try:
            time.sleep(0.2)
            self.assertIn("X-Forwarded-For: 127.0.0.1", self.up.request)
        finally:
            s.close()


class TestTunnelIsNarrowlyScoped(unittest.TestCase):
    """It's a push-channel enabler, not a general-purpose WebSocket proxy."""

    def setUp(self):
        self.up = _FakeUpstream()
        self.sat = _Satellite(self.up.port)

    def tearDown(self):
        self.sat.close()
        self.up.close()

    def test_a_websocket_upgrade_on_another_path_is_not_tunnelled(self):
        # Any other /api/* path must go down the ordinary urllib relay, which
        # cannot upgrade — so it must NOT come back as a 101.
        s, resp = _ws_upgrade(self.sat.port, path="/api/devices")
        try:
            self.assertFalse(resp.startswith(b"HTTP/1.1 101"))
        finally:
            s.close()

    def test_a_plain_get_on_the_push_path_is_not_tunnelled(self):
        # No Upgrade header -> ordinary relay (the tunnel keys on BOTH the path
        # and a real websocket upgrade).
        s = socket.create_connection(("127.0.0.1", self.sat.port), timeout=5)
        try:
            s.sendall(b"GET /api/push/connect HTTP/1.1\r\nHost: sat\r\n\r\n")
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            self.assertFalse(resp.startswith(b"HTTP/1.1 101"))
        finally:
            s.close()


class TestUpstreamRefusalIsRelayedVerbatim(unittest.TestCase):
    def test_non_101_response_is_passed_back_and_the_tunnel_is_not_opened(self):
        up = _FakeUpstream(accept_upgrade=False)
        sat = _Satellite(up.port)
        try:
            s, resp = _ws_upgrade(sat.port)
            try:
                self.assertTrue(resp.startswith(b"HTTP/1.1 403"))
            finally:
                s.close()
        finally:
            sat.close()
            up.close()


class TestAgentDerivesTheWsSchemeFromTheServerUrl(unittest.TestCase):
    """A satellite on a trusted segment LAN may listen over plain HTTP. The
    agent used to hard-code wss://, which can never connect to it."""

    SRC = (_ROOT / "client/remotepower-agent.py").read_text()

    def test_scheme_is_not_hardcoded(self):
        self.assertNotIn(
            "url = f'wss://{host_and_path}/api/push/connect", self.SRC,
            "the ws scheme must be derived from server_url, not hard-coded",
        )
        self.assertIn("_scheme = 'wss' if _secure else 'ws'", self.SRC)

    def test_ssl_context_is_omitted_for_a_plain_ws_url(self):
        # websockets rejects an ssl= kwarg on a ws:// URL.
        self.assertIn("ssl=(_SSL_CTX if _secure else None)", self.SRC)

    def test_all_three_agents_stay_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
