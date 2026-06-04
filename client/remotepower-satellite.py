#!/usr/bin/env python3
"""
RemotePower satellite — a minimal authenticated relay (v3.12.0).

Agents in a segmented network often can't reach the central RemotePower server
directly. Point them at a satellite instead; it forwards every /api/* request
to the upstream server, adding its own authentication header so the server
knows which relay the traffic came through (and can revoke it).

    agent ──http──▶ satellite ──https──▶ RemotePower server

The agent's own device token still authenticates the device end-to-end; the
satellite token is a second, independent layer identifying the relay.

Configure via environment:
    RP_UPSTREAM           upstream base URL, e.g. https://remote.example.com   [required]
    RP_SATELLITE_TOKEN    token minted at Settings → Integrations → Satellites [required]
    RP_LISTEN             listen address (default 0.0.0.0:8800)
    RP_UPSTREAM_INSECURE  set to 1 to skip TLS verification (self-signed upstream)

Then on each agent in the segment set the server URL to
http://<satellite-host>:8800. Standard library only — no dependencies.
"""
import os
import ssl
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get('RP_UPSTREAM', '').rstrip('/')
TOKEN = os.environ.get('RP_SATELLITE_TOKEN', '')
LISTEN = os.environ.get('RP_LISTEN', '0.0.0.0:8800')
INSECURE = os.environ.get('RP_UPSTREAM_INSECURE') == '1'

# Hop-by-hop headers (RFC 7230 §6.1) + length/host that we recompute.
_HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host', 'content-length'}


def _ssl_ctx():
    if not UPSTREAM.startswith('https'):
        return None
    ctx = ssl.create_default_context()
    if INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


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
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        headers['X-RP-Satellite'] = TOKEN
        xff = self.headers.get('X-Forwarded-For')
        headers['X-Forwarded-For'] = (xff + ', ' if xff else '') + self.client_address[0]
        req = urllib.request.Request(UPSTREAM + path, data=body,
                                     headers=headers, method=self.command)
        try:
            resp = urllib.request.urlopen(req, timeout=30, context=_ssl_ctx())
            self._send(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), dict(e.headers))
        except Exception as e:
            self._send(502, ('upstream error: ' + str(e))[:500].encode(),
                       {'Content-Type': 'text/plain'})

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
    sys.stderr.write(f'RemotePower satellite: relaying {LISTEN} -> {UPSTREAM}\n')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
