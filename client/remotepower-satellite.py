#!/usr/bin/env python3
"""
RemotePower satellite — a minimal authenticated relay (v3.12.0).

Agents in a segmented network often can't reach the central RemotePower server
directly. Point them at a satellite instead; it forwards every /api/* request
to the upstream server, adding its own authentication header so the server
knows which relay the traffic came through (and can revoke it).

    agent ──(http|https)──▶ satellite ──https──▶ RemotePower server

The agent's own device token still authenticates the device end-to-end; the
satellite token is a second, independent layer identifying the relay.

Configure via environment:
    RP_UPSTREAM           upstream base URL, e.g. https://remote.example.com   [required]
    RP_SATELLITE_TOKEN    token minted at Settings → Integrations → Satellites [required]
    RP_LISTEN             listen address (default 0.0.0.0:8800)
    RP_UPSTREAM_INSECURE  set to 1 to skip TLS verification (self-signed upstream)
    RP_TLS_CERT           PEM cert chain → the satellite listens over HTTPS
    RP_TLS_KEY            PEM private key for RP_TLS_CERT

With RP_TLS_CERT + RP_TLS_KEY the agent→satellite hop is encrypted too: point
the segment's agents at https://<satellite-host>:8800 (use a cert the agents
trust — an internal CA or Let's Encrypt). Without them the relay listens over
plain HTTP and warns; only do that on a trusted segment LAN. The upstream hop
(satellite→server) is HTTPS whenever RP_UPSTREAM is https. Standard library
only — no dependencies.
"""
import os
import selectors
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get('RP_UPSTREAM', '').rstrip('/')
TOKEN = os.environ.get('RP_SATELLITE_TOKEN', '')
LISTEN = os.environ.get('RP_LISTEN', '0.0.0.0:8800')
INSECURE = os.environ.get('RP_UPSTREAM_INSECURE') == '1'
TLS_CERT = os.environ.get('RP_TLS_CERT', '')
TLS_KEY = os.environ.get('RP_TLS_KEY', '')

# Hop-by-hop headers (RFC 7230 §6.1) + length/host that we recompute.
_HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host', 'content-length'}


def _ssl_ctx():
    if not UPSTREAM.startswith('https'):
        return None
    ctx = ssl.create_default_context()
    # v4.1.0: never negotiate down to legacy TLS on the satellite→server hop.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# v6.1.1 (broad sweep, adversarial self-review): every relayed request carries
# the satellite's own X-RP-Satellite token plus whatever the forwarding agent
# sent (its device token / telemetry body). A 3xx from UPSTREAM must NOT be
# followed -- an open-redirect, misconfig, or MITM'd hop would silently
# replay both credentials to the redirect target, and an https→http hop
# would leak them in cleartext. Mirrors the agents' own _NoRedirect opener
# (remotepower-agent.py / -win.py / -mac.py), which this separate,
# not-auto-synced file never got.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=_ssl_ctx()))


class Relay(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _forward(self):
        path = self.path
        if path == '/satellite/health':
            self._send(200, b'{"ok":true}', {'Content-Type': 'application/json'})
            return
        if not path.startswith('/api/'):
            self._send(404, b'not found (satellite only relays /api/*)',
                       {'Content-Type': 'text/plain'})
            return
        # v6.1.2: the agent push channel through a satellite. An agent's push
        # listener builds its WebSocket URL from the SAME base URL it uses for
        # the API — which, behind a satellite, is the satellite. urllib can't
        # carry an Upgrade, so this used to fail silently and satellite-relayed
        # agents simply never got the wake nudge (harmless — the channel is
        # wake-only by design — but it made push a direct-agents-only feature).
        # Tunnel the upgrade as raw bytes instead of proxying it as HTTP.
        if (path.split('?', 1)[0] == '/api/push/connect'
                and 'websocket' in (self.headers.get('Upgrade') or '').lower()):
            self._tunnel_websocket(path)
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        headers['X-RP-Satellite'] = TOKEN
        xff = self.headers.get('X-Forwarded-For')
        headers['X-Forwarded-For'] = (xff + ', ' if xff else '') + self.client_address[0]
        req = urllib.request.Request(UPSTREAM + path, data=body,
                                     headers=headers, method=self.command)
        try:
            resp = _OPENER.open(req, timeout=30)
            self._send(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), dict(e.headers))
        except Exception as e:
            self._send(502, ('upstream error: ' + str(e))[:500].encode(),
                       {'Content-Type': 'text/plain'})

    # ── v6.1.2: WebSocket tunnel for the agent push channel ────────────────
    # Scope is deliberately exactly ONE path (= /api/push/connect): this is a
    # push-channel enabler, not a general WS proxy. The tunnel is byte-level —
    # no frame parsing, no protocol knowledge — so the agent↔daemon handshake,
    # token header, and ping/pong pass through untouched, and the daemon's own
    # device-token auth stays the only auth that matters end to end. If the
    # tunnel can't be established the agent just doesn't get early wakes,
    # identical to push never being installed (the channel is wake-only).

    TUNNEL_IDLE_TIMEOUT_S = 90    # agent pings every 20s; 90s silent = dead peer

    def _upstream_ws_socket(self):
        """Raw (optionally TLS) socket to the upstream server's WS port."""
        u = urllib.parse.urlsplit(UPSTREAM)
        port = u.port or (443 if u.scheme == 'https' else 80)
        raw = socket.create_connection((u.hostname, port), timeout=15)
        ctx = _ssl_ctx()
        if u.scheme == 'https' and ctx is not None:
            raw = ctx.wrap_socket(raw, server_hostname=u.hostname)
        return raw, (u.hostname or '')

    def _tunnel_websocket(self, path):
        try:
            up, host = self._upstream_ws_socket()
        except Exception as e:
            self._send(502, ('upstream connect failed: ' + str(e))[:300].encode(),
                       {'Content-Type': 'text/plain'})
            return
        try:
            # Replay the client's handshake upstream. Upgrade/Connection are
            # hop-by-hop so _HOP drops them — re-add them explicitly, plus the
            # satellite's own identifying token (same as every relayed request).
            lines = [f'GET {path} HTTP/1.1', f'Host: {host}',
                     'Connection: Upgrade', 'Upgrade: websocket']
            for k, v in self.headers.items():
                if k.lower() in _HOP:
                    continue
                lines.append(f'{k}: {v}')
            lines.append(f'X-RP-Satellite: {TOKEN}')
            xff = self.headers.get('X-Forwarded-For')
            lines.append('X-Forwarded-For: '
                         + ((xff + ', ' if xff else '') + self.client_address[0]))
            up.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())

            # Read upstream's handshake response (headers only — a 101 has no
            # body, and anything else we just relay and drop the connection).
            resp = b''
            while b'\r\n\r\n' not in resp and len(resp) < 65536:
                chunk = up.recv(4096)
                if not chunk:
                    break
                resp += chunk
            try:
                self.connection.sendall(resp)
            except (BrokenPipeError, ConnectionResetError):
                return
            if not resp.startswith(b'HTTP/1.1 101'):
                return   # upstream refused the upgrade — relayed verbatim, done

            # 101 established: pump raw bytes both ways until either side
            # closes or the link goes silent past the idle timeout (the agent
            # pings every 20s, so a healthy tunnel is never quiet that long).
            self.close_connection = True
            client = self.connection
            client.setblocking(False)
            up.setblocking(False)
            sel = selectors.DefaultSelector()
            sel.register(client, selectors.EVENT_READ, up)
            sel.register(up, selectors.EVENT_READ, client)
            try:
                while True:
                    events = sel.select(timeout=self.TUNNEL_IDLE_TIMEOUT_S)
                    if not events:
                        return   # idle too long — dead peer
                    for key, _mask in events:
                        try:
                            data = key.fileobj.recv(65536)
                        except ssl.SSLWantReadError:
                            continue
                        except OSError:
                            return
                        if not data:
                            return   # clean close on one side ends the tunnel
                        try:
                            key.data.sendall(data)
                        except OSError:
                            return
            finally:
                sel.close()
        finally:
            try:
                up.close()
            except OSError:
                pass

    def _send(self, status, body, headers):
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() in _HOP:
                continue
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward

    def log_message(self, *args):
        pass


def main():
    if not UPSTREAM or not TOKEN:
        sys.stderr.write('error: RP_UPSTREAM and RP_SATELLITE_TOKEN are required\n')
        return 1
    host, _, port = LISTEN.partition(':')
    srv = ThreadingHTTPServer((host or '0.0.0.0', int(port or 8800)), Relay)
    scheme = 'http'
    # v3.14.0: encrypt the agent→satellite hop when a cert/key is provided.
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # v4.1.0: require TLS 1.2+ on the agent→satellite hop — refuse the
        # obsolete TLS 1.0/1.1 protocols even if the platform still offers them.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = 'https'
    elif TLS_CERT or TLS_KEY:
        sys.stderr.write('error: set BOTH RP_TLS_CERT and RP_TLS_KEY for HTTPS\n')
        return 1
    else:
        sys.stderr.write('WARNING: satellite is listening over plain HTTP — set '
                         'RP_TLS_CERT + RP_TLS_KEY to encrypt the agent→satellite '
                         'hop (only run plaintext on a trusted segment LAN)\n')
    sys.stderr.write(f'RemotePower satellite: relaying {scheme}://{LISTEN} -> {UPSTREAM}\n')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
