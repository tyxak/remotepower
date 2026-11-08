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
    RP_SATELLITE_PROBES   set to 0 to stop this satellite running the monitors assigned to it

The satellite also runs the monitors that are assigned to it (Settings → Monitors → "Probe from"): it asks the server for them,
checks tcp ports, http(s) addresses, ping targets and the smtp, imap, ssh and ntp handshakes from its own side of the network, and reports
the results. That is how a
service in a segment the server cannot reach is watched. It needs no extra setting; RP_SATELLITE_PROBES=0 turns it off.

With RP_TLS_CERT + RP_TLS_KEY the agent→satellite hop is encrypted too: point
the segment's agents at https://<satellite-host>:8800 (use a cert the agents
trust — an internal CA or Let's Encrypt). Without them the relay listens over
plain HTTP and warns; only do that on a trusted segment LAN. The upstream hop
(satellite→server) is HTTPS whenever RP_UPSTREAM is https. Standard library
only — no dependencies.
"""
import http.client as _http_client
import ipaddress
import json
import os
import selectors
import shutil
import socket
import re
import ssl
import subprocess  # nosec B404 - the ping probe runs the system ping with a fixed argument list, never a shell
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get('RP_UPSTREAM', '').rstrip('/')
TOKEN = os.environ.get('RP_SATELLITE_TOKEN', '')
LISTEN = os.environ.get('RP_LISTEN', '0.0.0.0:8800')
INSECURE = os.environ.get('RP_UPSTREAM_INSECURE') == '1'
TLS_CERT = os.environ.get('RP_TLS_CERT', '')
TLS_KEY = os.environ.get('RP_TLS_KEY', '')
PROBES = os.environ.get('RP_SATELLITE_PROBES', '1') != '0'

# Hop-by-hop headers (RFC 7230 §6.1) + length/host that we recompute.
_HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host', 'content-length'}


def _ssl_ctx():
    if not UPSTREAM.startswith('https'):
        return None
    ctx = ssl.create_default_context()
    # v4.1.0: never negotiate down to legacy TLS on the satellite→server hop.
    # Raise the floor, never lower it.
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
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


# The largest request body the relay will read. The server refuses anything over 50 MB (MAX_BODY_BYTES), so a larger one could
# never succeed upstream. Before 7.4.9 the relay read whatever Content-Length said, with no ceiling and no check that it was a
# number: the port is open to the whole segment and takes no credentials, so a `Content-Length: 99999999999`, or `-1` (read until
# the client hangs up), held a thread and memory for as long as the client liked.
MAX_BODY = 50 * 1024 * 1024


# 7.4.9: the paths an agent calls, and nothing else. The relay used to forward every /api/* request, so any machine on the segment
# could reach the sign-in and the whole administration API from the relay's address, which an IP allowlist on the server treats as
# trusted. An agent needs heartbeats, enrolment, the package and log submissions, the scan and threat reports, the compose fetch,
# the push and SSH-gateway channels, the update check and the two per-host uploads. tests/test_v749_agent_satellite_paths.py reads
# every /api/ path out of the three agents and the installers and fails if one is not listed here.
_AGENT_PATHS = frozenset((
    '/api/heartbeat', '/api/enroll/register', '/api/packages', '/api/logs', '/api/threat-events', '/api/scap/report',
    '/api/compose/fetch', '/api/push/connect', '/api/sshgw/tunnel',
    '/api/agent/version', '/api/agent/signature',
    '/api/agent/mac/version', '/api/agent/mac/signature', '/api/agent/mac/download',
    '/api/agent/win/version', '/api/agent/win/signature', '/api/agent/win/download',
))
_AGENT_HOST_PATH = re.compile(r'^/api/devices/[A-Za-z0-9_-]{1,64}/(?:live-sample|files/archive-chunk)$')


def relayed(path):
    """True when `path` (with its query string) is one an agent calls. A path that is not in its plain form (`..`, a doubled slash, an
    escape) is not relayed, since the server may read it differently from a table of literal names."""
    bare = path.split('?', 1)[0]
    if '%' in bare or '//' in bare or '/./' in bare or '..' in bare:
        return False
    return bare in _AGENT_PATHS or bool(_AGENT_HOST_PATH.match(bare))


class Relay(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    # A client that opens a connection and says nothing is dropped after a minute instead of holding a thread for ever.
    timeout = 60

    def _forward(self):
        path = self.path
        if path == '/satellite/health':
            self._send(200, b'{"ok":true}', {'Content-Type': 'application/json'})
            return
        if not path.startswith('/api/') or not relayed(path):
            self._send(404, b'not found (the satellite relays the paths an agent calls)',
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
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            # The body is not read, so what follows on this connection is not a request: close it after answering.
            self.close_connection = True
            self._send(413 if length > MAX_BODY else 400,
                       b'request body too large' if length > MAX_BODY else b'bad Content-Length',
                       {'Content-Type': 'text/plain'})
            return
        chunks, remaining = [], length
        while remaining:
            part = self.rfile.read(min(remaining, 1 << 20))
            if not part:                     # the client went away before sending what it promised
                self.close_connection = True
                return
            chunks.append(part)
            remaining -= len(part)
        body = b''.join(chunks) if length else None
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
    # Scope is exactly ONE path (= /api/push/connect): this is a
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
                return   # upstream refused the upgrade — relayed unchanged, done

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
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward

    def log_message(self, *args):
        pass



# ── 7.5.0: the monitors that run from this satellite ────────────────────────────────────────────────────────────────────────
# A monitor can be assigned to a satellite (`via_satellite`): the satellite probes it from its own side of the network, which is
# the only way to watch a service in a segment the server cannot reach. The server held the assignment, the list of monitors
# (GET /api/satellite/monitor-work) and the place to report the results (POST /api/satellite/monitor-results), and the satellite
# never asked, so no such monitor was ever probed. This is the other half. The engine is the agent's own host-probe engine
# (client/remotepower-agent.py, `_probe_*`): the same checks of a spec, the same refusal of cloud metadata and link-local
# addresses with the loopback and the private ranges allowed, the same no-redirect opener. tests/test_v750_satellite_probes.py
# runs both over the same specs and addresses and fails if they disagree.
_PROBE_MAX_SPECS = 200          # what the server's results endpoint takes in one report
_PROBE_WORKERS = 8
_PROBE_HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$')
_PROBE_V6_RE = re.compile(r'^\[[0-9A-Fa-f:.]{2,45}\]$')
_PROBE_CTRL_RE = re.compile(r'[\x00-\x1f\x7f]')


def _probe_host_ok(h):
    return bool(_PROBE_HOST_RE.match(h or '') or _PROBE_V6_RE.match(h or ''))


def _probe_spec(raw):
    """A monitor spec from the server as this satellite will run it, or None when it is not one it runs."""
    if not isinstance(raw, dict):
        return None
    label = _PROBE_CTRL_RE.sub(' ', str(raw.get('label') or '')).strip()[:128]
    mtype = raw.get('type')
    target = _PROBE_CTRL_RE.sub('', str(raw.get('target') or '')).strip()[:512]
    if not label or mtype not in _probe_types() or not target:
        return None
    spec = {'label': label, 'type': mtype, 'target': target}
    if mtype in _pp_TYPES:
        # 8.0.0: smtp, imap, ssh and ntp. host or host:port, the protocol's own port when none is given
        host, _, port_s = target.partition(':')
        try:
            port = int(port_s) if port_s.strip() else _pp_DEFAULT_PORTS[mtype]
        except ValueError:
            return None
        if not _probe_host_ok(host) or not 0 < port < 65536:
            return None
        spec['host'], spec['port'] = host, port
        if raw.get('tls') in _pp_TLS_MODES:
            spec['tls'] = raw['tls']
        mo = raw.get('max_offset_ms')
        if isinstance(mo, (int, float)) and not isinstance(mo, bool) and 0 < mo <= _pp_MAX_OFFSET_MS:
            spec['max_offset_ms'] = mo
        if raw.get('verify_tls') is False:
            spec['verify_tls'] = False
    elif mtype == 'ping':
        if not _probe_host_ok(target.strip('[]')) or target.startswith('-'):
            return None
    elif mtype == 'tcp':
        host, _, port_s = target.rpartition(':')
        try:
            port = int(port_s)
        except ValueError:
            return None
        if not _probe_host_ok(host) or not 0 < port < 65536:
            return None
        spec['host'], spec['port'] = host.strip('[]'), port
    else:
        u = urllib.parse.urlsplit(target)
        if u.scheme not in ('http', 'https') or not u.hostname or not _probe_host_ok(u.hostname if ':' not in u.hostname else '[' + u.hostname + ']'):
            return None
        es = raw.get('expect_status')
        if isinstance(es, int) and not isinstance(es, bool) and 100 <= es <= 599:
            spec['expect_status'] = es
        ec = raw.get('expect_contains')
        if isinstance(ec, str) and ec:
            spec['expect_contains'] = _PROBE_CTRL_RE.sub(' ', ec)[:200]
        if raw.get('method') in ('head', 'get'):
            spec['method'] = raw['method']
        if raw.get('verify_tls') is False:
            spec['verify_tls'] = False
    return spec


# The addresses a probe never connects to, even when a monitor names a host that resolves to one: the link-local range, where a
# cloud keeps its instance metadata, the metadata addresses that are not link-local, and the unspecified, multicast and reserved
# ranges. The loopback and the private ranges are the point of probing from here.
_PROBE_METADATA_IPS = frozenset({'fd00:ec2::254', '100.100.100.200', '192.0.0.192'})
_PROBE_NAT64 = 0x0064ff9b << 64


class _ProbeBlocked(Exception):
    """The name resolved to an address a probe does not connect to."""


def _probe_addr_blocked(ip_str):
    try:
        ip = ipaddress.ip_address(str(ip_str))
    except ValueError:
        return True                     # an address that cannot be read is not one to connect to
    if isinstance(ip, ipaddress.IPv6Address):
        inner = ip.ipv4_mapped or ip.sixtofour      # an IPv4 address wrapped in an IPv6 one is judged as the IPv4 address
        if inner is None and (int(ip) >> 32) == _PROBE_NAT64:
            inner = ipaddress.IPv4Address(int(ip) & 0xffffffff)
        if inner is not None:
            ip = inner
    if str(ip) in _PROBE_METADATA_IPS:
        return True
    if ip.is_loopback:
        return False
    return bool(ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


def _probe_connect(address, timeout=None, source_address=None):
    """socket.create_connection that resolves the name once, refuses it when any of its addresses is one a probe does not reach,
    and connects to an address it has checked. A name cannot answer one thing to the check and another to the connection."""
    host, port = address[0], address[1]
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        if _probe_addr_blocked(info[4][0]):
            raise _ProbeBlocked(host)
    err = None
    for info in infos:
        try:
            return socket.create_connection((info[4][0], info[4][1]), timeout, source_address)
        except OSError as e:
            err = e
    raise err or OSError('no address to connect to')


class _ProbeHTTPConnection(_http_client.HTTPConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _probe_connect


class _ProbeHTTPSConnection(_http_client.HTTPSConnection):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._create_connection = _probe_connect


class _ProbeHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_ProbeHTTPConnection, req)


class _ProbeHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_ProbeHTTPSConnection, req, context=self._context)


def _probe_tcp(spec):
    with _probe_connect((spec['host'], spec['port']), 3):
        return True, 'open'


def _probe_ping(spec):
    target = spec['target'].strip('[]')
    try:
        literal = ipaddress.ip_address(target)
    except ValueError:
        literal = None                  # a name: ping resolves it, and only an address can be judged here
    if literal is not None and _probe_addr_blocked(literal):
        raise _ProbeBlocked(target)
    if not shutil.which('ping'):
        return False, 'ping is not installed on this satellite'
    r = subprocess.run(['ping', '-c', '1', '-W', '2', '--', target], capture_output=True, text=True, timeout=6)  # nosec B603 B607 - fixed argv, no shell; the target passed _probe_spec and follows `--`, so it is never an option
    if r.returncode == 2:
        # ping exits 1 when nothing answered and 2 when it could not run (an unprivileged account that may not send ICMP, a name
        # that does not resolve). Calling the second "unreachable" would raise an alert for a satellite that cannot ping.
        return False, 'ping could not run here (no permission to send ICMP, or the name did not resolve)'
    return r.returncode == 0, ('reachable' if r.returncode == 0 else 'unreachable')


def _probe_opener(verify):
    """http and https only (no file: or ftp:), the system's certificate authorities, and no redirect."""
    ctx = ssl.create_default_context()
    if not verify:                      # the operator switched Verify TLS off for this check
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.OpenerDirector()
    for h in (urllib.request.UnknownHandler(), _ProbeHTTPHandler(), _ProbeHTTPSHandler(context=ctx),
              urllib.request.HTTPDefaultErrorHandler(), _NoRedirect(), urllib.request.HTTPErrorProcessor()):
        op.add_handler(h)
    return op


def _probe_http(spec):
    op = _probe_opener(spec.get('verify_tls') is not False)
    want = spec.get('expect_status')
    needs_body = bool(spec.get('expect_contains'))
    verbs = ['GET'] if needs_body or spec.get('method') == 'get' else ['HEAD', 'GET'] if spec.get('method') != 'head' else ['HEAD']
    status, body = 0, ''
    for i, verb in enumerate(verbs):
        req = urllib.request.Request(spec['target'], method=verb, headers={'User-Agent': 'RemotePower-satellite'})
        try:
            resp = op.open(req, timeout=5)
        except urllib.error.HTTPError as e:
            resp = e
        with resp:
            status = resp.status
            if needs_body and verb == 'GET':
                body = resp.read(512 * 1024).decode('utf-8', 'replace')
        if i + 1 < len(verbs) and status in (404, 405, 501):
            continue            # a server that answers HEAD with 405 answers GET
        break
    ok = (status == want) if want is not None else status < 400
    detail = f'{status}' + (f' (expected {want})' if want is not None and not ok else '')
    if ok and needs_body and spec['expect_contains'] not in body:
        ok, detail = False, f'{status} · "{spec["expect_contains"][:40]}" not found'
    return ok, detail


# BEGIN protocol_probes: generated from server/cgi-bin/protocol_probes.py by tools/sync-protocol-probes.py, do not edit by hand
# the probes run from this client: tcp, http and ping above, and the four below
import socket as _pp_socket
import ssl as _pp_ssl
import struct as _pp_struct
import time as _pp_time
_pp_DEFAULT_PORTS = {"smtp": 25, "imap": 143, "ssh": 22, "ntp": 123}
_pp_TYPES = tuple(_pp_DEFAULT_PORTS)
_pp_TLS_MODES = ("none", "starttls", "tls")
_pp_MAX_OFFSET_MS = 3_600_000  # an hour: past that the clock is not "a little off"
_pp_NTP_EPOCH = 2208988800  # seconds from 1900-01-01 to 1970-01-01
_pp_LINE_MAX = 1024
_pp_REPLY_LINES_MAX = 40


class _pp_ProbeError(Exception):
    """A probe that failed in a way worth saying in words."""


def _pp_clean(text, limit=60):
    """One printable line, cut: what a server said, safe to show in a table and to put in a message."""
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in str(text))
    return " ".join(s.split())[:limit]


def _pp_connect(host, port, timeout, peer_ok):
    """Resolve the name once, refuse it when any address it resolves to is one the check will not allow, and connect to an address that
    was checked, so a name cannot answer one thing to the check and another to the connection and nothing is connected to that should not
    be. The peer is checked again once connected, which costs nothing."""
    infos = _pp_socket.getaddrinfo(host, port, type=_pp_socket.SOCK_STREAM)
    if peer_ok is not None:
        for info in infos:
            if not peer_ok(info[4][0]):
                raise _pp_ProbeError("blocked")
    err = None
    for info in infos:
        try:
            s = _pp_socket.create_connection((info[4][0], info[4][1]), timeout=timeout)
        except OSError as e:
            err = e
            continue
        try:
            peer = s.getpeername()[0]
        except (OSError, IndexError):
            peer = None
        if peer_ok is not None and peer and not peer_ok(peer):
            s.close()
            raise _pp_ProbeError("blocked")
        s.settimeout(timeout)
        return s
    raise err or OSError("no address to connect to")


def _pp_wrap(sock, host, ctx):
    ctx = ctx or _pp_ssl.create_default_context()
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except _pp_ssl.SSLCertVerificationError:
        sock.close()
        raise _pp_ProbeError("TLS: the certificate was not accepted") from None
    except _pp_ssl.SSLError as e:
        sock.close()
        raise _pp_ProbeError(
            "TLS: " + _pp_clean(getattr(e, "reason", None) or "handshake failed", 40)
        ) from None


class _pp_Conn:
    """A socket and the bytes read from it but not yet used, so a line is read whole whatever way the segments fall."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def readline(self, limit=_pp_LINE_MAX):
        while b"\n" not in self.buf:
            if len(self.buf) >= limit:
                break
            chunk = self.sock.recv(512)
            if not chunk:
                if not self.buf:
                    raise _pp_ProbeError("the connection closed with no answer")
                break
            self.buf += chunk
        line, sep, rest = self.buf.partition(b"\n")
        if not sep and len(line) > limit:
            line, rest = line[:limit], line[limit:]
        self.buf = rest
        return line.rstrip(b"\r").decode("latin-1")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _pp_smtp_reply(c):
    """(code, lines) of one SMTP reply. A line 'ddd-text' continues it, 'ddd text' or 'ddd' ends it."""
    lines = []
    for _ in range(_pp_REPLY_LINES_MAX):
        line = c.readline()
        lines.append(line)
        if len(line) < 3 or not (line[:3].isascii() and line[:3].isdigit()):
            raise _pp_ProbeError("not SMTP: " + _pp_clean(line, 40))
        if len(line) == 3 or line[3] == " ":
            return int(line[:3]), lines
    raise _pp_ProbeError("an SMTP reply that does not end")


def _pp_smtp_probe(host, port, tls="none", ctx=None, timeout=5, peer_ok=None):
    t0 = _pp_time.monotonic()
    sock = _pp_connect(host, port, timeout, peer_ok)
    if tls == "tls":
        sock = _pp_wrap(sock, host, ctx)
    c = _pp_Conn(sock)
    try:
        code, lines = _pp_smtp_reply(c)
        if code != 220:
            return False, "greeting %d %s" % (code, _pp_clean(lines[0][4:], 40))
        greeting = _pp_clean(lines[0][4:], 50)
        c.send(b"EHLO remotepower\r\n")
        code, ehlo = _pp_smtp_reply(c)
        if code != 250:
            return False, "EHLO refused (%d)" % code
        used = "TLS" if tls == "tls" else ""
        if tls == "starttls":
            if not any(ln[4:].strip().upper().startswith("STARTTLS") for ln in ehlo[1:]):
                return False, "STARTTLS is not offered"
            c.send(b"STARTTLS\r\n")
            code, _ = _pp_smtp_reply(c)
            if code != 220:
                return False, "STARTTLS refused (%d)" % code
            c.sock = _pp_wrap(c.sock, host, ctx)
            c.buf = b""
            # the server forgets everything said before the upgrade: a second EHLO is what shows the encrypted session works
            c.send(b"EHLO remotepower\r\n")
            code, _ = _pp_smtp_reply(c)
            if code != 250:
                return False, "no answer inside STARTTLS (%d)" % code
            used = "STARTTLS"
        try:
            c.send(b"QUIT\r\n")
        except OSError:
            pass
        return True, " · ".join(
            x for x in (greeting, used, "%dms" % int((_pp_time.monotonic() - t0) * 1000)) if x
        )
    finally:
        c.close()


def _pp_imap_until(c, tag):
    """Lines of an IMAP answer up to and including the tagged completion; returns (ok, untagged_lines)."""
    untagged = []
    for _ in range(_pp_REPLY_LINES_MAX):
        line = c.readline()
        if line.startswith(tag + " "):
            return line[len(tag) + 1 :].upper().startswith("OK"), untagged
        untagged.append(line)
    raise _pp_ProbeError("an IMAP answer that does not end")


def _pp_imap_probe(host, port, tls="none", ctx=None, timeout=5, peer_ok=None):
    t0 = _pp_time.monotonic()
    sock = _pp_connect(host, port, timeout, peer_ok)
    if tls == "tls":
        sock = _pp_wrap(sock, host, ctx)
    c = _pp_Conn(sock)
    try:
        greeting = c.readline()
        if greeting.upper().startswith("* BYE"):
            return False, "refused: " + _pp_clean(greeting[5:], 40)
        if not greeting.upper().startswith("* OK"):
            return False, "not IMAP: " + _pp_clean(greeting, 40)
        c.send(b"a1 CAPABILITY\r\n")
        ok, untagged = _pp_imap_until(c, "a1")
        caps = []
        for ln in untagged:
            if ln.upper().startswith("* CAPABILITY"):
                caps = ln.split()[2:]
        if not ok:
            return False, "CAPABILITY refused"
        used = "TLS" if tls == "tls" else ""
        if tls == "starttls":
            if not any(x.upper() == "STARTTLS" for x in caps):
                return False, "STARTTLS is not offered"
            c.send(b"a2 STARTTLS\r\n")
            ok, _ = _pp_imap_until(c, "a2")
            if not ok:
                return False, "STARTTLS refused"
            c.sock = _pp_wrap(c.sock, host, ctx)
            c.buf = b""
            c.send(b"a3 CAPABILITY\r\n")
            ok, _ = _pp_imap_until(c, "a3")
            if not ok:
                return False, "no answer inside STARTTLS"
            used = "STARTTLS"
        try:
            c.send(b"a9 LOGOUT\r\n")
        except OSError:
            pass
        proto = next((_pp_clean(x, 12) for x in caps if x.upper().startswith("IMAP4")), "IMAP")
        return True, " · ".join(
            x for x in (proto, used, "%dms" % int((_pp_time.monotonic() - t0) * 1000)) if x
        )
    finally:
        c.close()


def _pp_ssh_banner_probe(host, port, timeout=5, peer_ok=None):
    t0 = _pp_time.monotonic()
    c = _pp_Conn(_pp_connect(host, port, timeout, peer_ok))
    try:
        for _ in range(8):  # a server may send other lines before its identification
            line = c.readline(255)
            if line.startswith("SSH-"):
                banner = _pp_clean(line, 80)
                if not (banner.startswith("SSH-2.0-") or banner.startswith("SSH-1.99-")):
                    return False, "not SSH 2: " + banner
                return True, "%s · %dms" % (banner, int((_pp_time.monotonic() - t0) * 1000))
        return False, "no SSH banner"
    finally:
        c.close()


def _pp_to_ntp(ts):
    secs = int(ts)
    # the seconds field is 32 bits and wraps in February 2036 (and every 136 years after): the wrapped value is what goes on the wire
    return _pp_struct.pack(
        ">II", (secs + _pp_NTP_EPOCH) & 0xFFFFFFFF, int((ts - secs) * (1 << 32)) & 0xFFFFFFFF
    )


def _pp_from_ntp(b, ref=None):
    """Seconds since 1970 for an NTP timestamp. The field wraps every 136 years, so with `ref` (a time known to be near, which is this
    machine's own clock) the era is the one that puts the result closest to it; without it the first era is assumed.
    """
    secs, frac = _pp_struct.unpack(">II", b)
    unix = secs - _pp_NTP_EPOCH + frac / float(1 << 32)
    if ref is not None:
        unix += round((ref - unix) / float(1 << 32)) * float(1 << 32)
    return unix


def _pp_ntp_probe(
    host, port, max_offset_ms=None, timeout=5, peer_ok=None, now=_pp_time.time, sock_factory=None
):
    infos = _pp_socket.getaddrinfo(host, port, 0, _pp_socket.SOCK_DGRAM)
    chosen = None
    for family, _t, _p, _c, sa in infos:
        if peer_ok is None or peer_ok(sa[0]):
            chosen = (family, sa)
            break
    if chosen is None:
        return False, "blocked"
    family, sa = chosen
    sock = sock_factory(family) if sock_factory else _pp_socket.socket(family, _pp_socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        t1 = now()
        req = bytearray(48)
        req[0] = 0x23  # leap indicator 0, version 4, mode 3 (client)
        req[40:48] = _pp_to_ntp(t1)
        sock.sendto(bytes(req), sa)
        data = None
        for _ in range(4):  # a stray datagram from somewhere else is not the answer
            d, addr = sock.recvfrom(1024)
            if addr[0] == sa[0] and len(d) >= 48:
                data = d
                break
        t4 = now()
    finally:
        sock.close()
    if data is None:
        return False, "no answer"
    if data[24:32] != bytes(req[40:48]):
        return False, "the reply does not match the request"
    mode, li, stratum = data[0] & 7, data[0] >> 6, data[1]
    if mode != 4:
        return False, "not a server reply (mode %d)" % mode
    if stratum == 0:
        return False, "kiss-of-death %s" % (
            _pp_clean(data[12:16].decode("ascii", "replace"), 8) or "?"
        )
    if li == 3 or stratum >= 16:
        return False, "not synchronised (stratum %d)" % stratum
    if data[40:48] == b"\0" * 8:
        return False, "the reply carries no time"
    t2, t3 = _pp_from_ntp(data[32:40], t1), _pp_from_ntp(data[40:48], t1)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay = (t4 - t1) - (t3 - t2)
    detail = "stratum %d · offset %+.1f ms · delay %.0f ms" % (
        stratum,
        offset * 1000,
        max(delay, 0.0) * 1000,
    )
    if max_offset_ms is not None and abs(offset * 1000) > max_offset_ms:
        return False, "%s (limit %d ms)" % (detail, int(max_offset_ms))
    return True, detail


def _pp_why(e):
    """A network failure in words an operator can act on."""
    if isinstance(e, _pp_socket.gaierror):
        return "the host name does not resolve"
    if isinstance(e, ConnectionRefusedError):
        return "the connection was refused"
    if isinstance(e, (_pp_socket.timeout, TimeoutError)):
        return "it did not answer in time"
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "the connection was dropped"
    text = str(e).lower()
    if "unreachable" in text or "no route" in text:
        return "the network is unreachable"
    return "the connection failed"


def _pp_run(mtype, host, port, m, peer_ok=None, ssl_ctx=None, timeout=5):
    """``(ok, detail)`` for a monitor `m` of one of TYPES. Never raises: every failure is a result."""
    tls = m.get("tls") if m.get("tls") in _pp_TLS_MODES else "none"
    try:
        if mtype == "smtp":
            return _pp_smtp_probe(host, port, tls, ssl_ctx, timeout, peer_ok)
        if mtype == "imap":
            return _pp_imap_probe(host, port, tls, ssl_ctx, timeout, peer_ok)
        if mtype == "ssh":
            return _pp_ssh_banner_probe(host, port, timeout, peer_ok)
        if mtype == "ntp":
            limit = m.get("max_offset_ms")
            limit = (
                limit
                if isinstance(limit, (int, float))
                and not isinstance(limit, bool)
                and 0 < limit <= _pp_MAX_OFFSET_MS
                else None
            )
            return _pp_ntp_probe(host, port, limit, timeout, peer_ok)
        return False, "unknown protocol check"
    except _pp_ProbeError as e:
        return False, str(e)
    except _pp_ssl.SSLError as e:
        return False, "TLS: " + _pp_clean(getattr(e, "reason", None) or "handshake failed", 40)
    except OSError as e:
        return False, _pp_why(e)
    except Exception:
        return False, "error"
# END protocol_probes


def _probe_types():
    """The monitor types this satellite runs. Every call to the server says so (the X-RP-Probes header), and the server hands it no other type: a
    satellite from before a type existed would drop the monitor without a word, and its row would wait for a first result for ever."""
    return ['tcp', 'http', 'ping'] + list(_pp_TYPES)


def _probe_protocol(spec):
    """An smtp, imap, ssh or ntp monitor: the server's own handshake (the block above), with this satellite's address rule, the loopback allowed."""
    ctx = ssl.create_default_context()
    if spec.get('verify_tls') is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ok, detail = _pp_run(spec['type'], spec['host'], spec['port'], spec, peer_ok=lambda ip: not _probe_addr_blocked(ip), ssl_ctx=ctx, timeout=5)
    if detail == 'blocked':
        raise _ProbeBlocked(spec['host'])
    return ok, detail


def _probe_run_one(spec):
    t0 = time.monotonic()
    try:
        ok, detail = dict({'tcp': _probe_tcp, 'ping': _probe_ping, 'http': _probe_http}, **{k: _probe_protocol for k in _pp_TYPES})[spec['type']](spec)
    except _ProbeBlocked:
        ok, detail = False, 'that address is not allowed (link-local or cloud metadata)'
    except Exception as e:
        ok, detail = False, ('closed' if spec['type'] == 'tcp' else 'error: ' + type(e).__name__)
    return {'label': spec['label'], 'type': spec['type'], 'target': spec['target'][:256], 'ok': bool(ok),
            'detail': str(detail)[:200], 'latency_ms': round((time.monotonic() - t0) * 1000, 1)}


def _upstream_json(method, path, payload=None):
    """One authenticated call to the server (the same token and no-redirect opener the relay uses), answered as parsed JSON."""
    data = None if payload is None else json.dumps(payload).encode()
    headers = {'X-RP-Satellite': TOKEN, 'X-RP-Probes': ','.join(_probe_types())}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(UPSTREAM + path, data=data, headers=headers, method=method)
    with _OPENER.open(req, timeout=30) as resp:
        out = json.loads(resp.read(1 << 20).decode('utf-8', 'replace') or '{}')
    return out if isinstance(out, dict) else {}


def _monitor_cycle():
    """One round: ask the server for the monitors assigned to this satellite, run them side by side, report the results. Returns the
    seconds to wait before the next round (the server's monitor interval, one to sixty minutes)."""
    work = _upstream_json('GET', '/api/satellite/monitor-work')
    raw = work.get('monitors')
    specs = [s for s in (_probe_spec(r) for r in (raw if isinstance(raw, list) else [])[:_PROBE_MAX_SPECS]) if s]
    if specs:
        with ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as pool:
            results = list(pool.map(_probe_run_one, specs))
        _upstream_json('POST', '/api/satellite/monitor-results', {'results': results})
    try:
        interval = int(work.get('interval') or 300)
    except (TypeError, ValueError, OverflowError):
        interval = 300
    return max(60, min(3600, interval))


def _monitor_loop():
    """Run the assigned monitors for as long as the satellite runs. A failed round (the server unreachable, a bad answer) is tried
    again after a pause that grows to five minutes, and says so on stderr once in a while."""
    wait, failures = 5, 0
    while True:
        time.sleep(wait)
        try:
            wait, failures = _monitor_cycle(), 0
        except Exception as e:
            failures += 1
            if failures in (1, 10) or failures % 60 == 0:
                sys.stderr.write(f'monitor round failed ({failures}): {type(e).__name__}: {str(e)[:120]}\n')
            wait = min(60 * failures, 300)


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
        # Raise the floor, never lower it: an operator who pinned this host
        # above 1.2 keeps their setting.
        if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
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
    if PROBES:
        threading.Thread(target=_monitor_loop, name='monitor-probes', daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
