#!/usr/bin/env python3
"""
remotepower-sshgw — the RemotePower SSH gateway sidecar
=======================================================

Reach any opted-in host with a normal SSH client, without opening a port on
the host, a VPN, or a firewall rule:

    # ~/.ssh/config
    Host *.rp
        ProxyJump alice@gw.example.com:2222

    ssh root@web01.rp
    scp backup.tar root@web01.rp:/srv/
    rsync -a ./site/ deploy@web01.rp:/var/www/

How it works
------------

Two listeners in one asyncio process:

  * an SSH server (default 0.0.0.0:2222) for operators. It accepts public-key
    logins only and serves exactly one thing: direct-tcpip channels, which is
    what `ssh -J` / ProxyJump / `ssh -W` ask for. No shell, no remote forwards.
  * a WebSocket server (default 127.0.0.1:8767, behind nginx at
    /api/sshgw/tunnel) for AGENTS. An opted-in Linux agent dials out to it
    and keeps one connection open. Many SSH streams share it, framed as
    described in server/cgi-bin/sshgw.py.

When a channel is requested for `web01.rp`, the gateway asks the RemotePower
API whether this account may reach that host, finds web01's tunnel, and asks
the agent to open a stream to its own local sshd. Bytes then flow:

    ssh client ──(SSH, end-to-end)── gateway ──(WebSocket)── agent ── 127.0.0.1:22

The operator's session is encrypted end to end with the HOST's sshd: the
gateway relays ciphertext and never holds a credential for any host. The
host's own sshd still decides who may log in and as which user.

Policy lives in the API, not here
---------------------------------

Every login and every channel is decided by POST /api/sshgw/authorize, and
every agent tunnel by POST /api/sshgw/agent-check, both over loopback with the
shared secret. Revoking a key, removing a role's 'ssh' permission, opting a
device out or switching the module off therefore takes effect on the next
channel, and a tunnel is re-checked every few minutes and closed if its device
was opted out.

What is audited
---------------

One record per stream: who (account + key fingerprint), from where, which
device, when, how long and how many bytes, posted to /api/sshgw/audit. The
gateway sees only ciphertext, so there is no keystroke recording; use the web
terminal for recorded sessions.

Dependencies: Python 3.9+, asyncssh >= 2.14.2, websockets >= 10.
"""

import argparse
import asyncio
import collections
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
    _WS_AVAILABLE = True
except ImportError:
    websockets = None
    ConnectionClosed = Exception
    _WS_AVAILABLE = False

import warnings as _warnings
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CryptoDeprecation
    _warnings.filterwarnings('ignore', category=_CryptoDeprecation)
except Exception:  # nosec B110
    # optional; only silences a noisy warning
    pass

try:
    import asyncssh
    _SSH_AVAILABLE = True
except ImportError:
    asyncssh = None
    _SSH_AVAILABLE = False

# Below 2.14.2 asyncssh has the Terrapin prefix-truncation and "rogue session"
# flaws (CVE-2023-48795, CVE-2023-46445/46446). This daemon is an SSH SERVER
# facing the internet, so unlike the web terminal it refuses to start on one.
MIN_ASYNCSSH = (2, 14, 2)

VERSION = '1.0.0'

# The gateway's public listener, so all interfaces by default.
DEFAULT_SSH_HOST = '0.0.0.0'  # nosec B104
DEFAULT_SSH_PORT = 2222
DEFAULT_WS_HOST = '127.0.0.1'
DEFAULT_WS_PORT = 8767
DEFAULT_API_BASE = 'http://127.0.0.1:8090/api'
# A path to the secret, not the secret.
DEFAULT_SECRET_FILE = '/etc/remotepower/sshgw-secret'  # nosec B105
DEFAULT_HOST_KEY = '/var/lib/remotepower-sshgw/ssh_host_ed25519_key'

OPEN_TIMEOUT_S = 10            # agent must answer OPEN within this
TUNNEL_RECHECK_S = 300         # re-ask agent-check for every open tunnel
MAX_STREAMS_PER_TUNNEL = 64
MAX_STREAMS_PER_CONN = 16
# A logged-in client that keeps asking for hosts it may not reach is probing
# names (and filling the audit log); drop the connection after this many.
MAX_DENIED_PER_CONN = 20
LOGIN_TIMEOUT_S = 30
# Back-pressure on the client → agent direction: pause reading the SSH channel
# when this much is queued for the tunnel, resume below the low mark.
HIGH_WATER = 512 * 1024
LOW_WATER = 128 * 1024
CHUNK = 32 * 1024
# Failed-login throttle per source address.
FAIL_WINDOW_S = 600
FAIL_LIMIT = 20
BAN_S = 600
# asyncssh has no MaxAuthTries: left alone, one unauthenticated connection may
# offer keys for the whole login timeout, and every offer is a request to the
# API. Distinct (user, key) offers per connection, as OpenSSH counts them; an
# ssh-agent holding a handful of keys stays well inside it.
MAX_AUTH_ATTEMPTS = 10
# Connections from one address that have not finished logging in yet, the
# per-address half of OpenSSH's MaxStartups.
MAX_UNAUTH_PER_IP = 10

log = logging.getLogger('sshgw')


def _find_cgi_bin():
    """Locate the server's cgi-bin (for sshgw.py) across dev and installed
    layouts. Mirrors the push and webterm daemons."""
    candidates = []
    env = os.environ.get('RP_CGI_BIN', '').strip()
    if env:
        candidates.append(Path(env))
    candidates += [
        Path(__file__).resolve().parent.parent / 'cgi-bin',
        Path('/var/www/remotepower/cgi-bin'),
        Path('/usr/share/webapps/remotepower/cgi-bin'),
        Path('/opt/remotepower/cgi-bin'),
    ]
    for c in candidates:
        try:
            if (c / 'sshgw.py').is_file():
                return c
        except OSError:
            continue
    return None


_cgi = _find_cgi_bin()
if _cgi is not None and str(_cgi) not in sys.path:
    sys.path.insert(0, str(_cgi))
import sshgw  # noqa: E402


# ─── API client ──────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """This client sends the shared secret; a 3xx must never replay it."""
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class ApiClient:
    """The three questions the gateway asks RemotePower. Blocking urllib in a
    worker thread: the calls are short, loopback, and once per login/channel."""

    def __init__(self, api_base, secret):
        if not str(api_base).startswith(('http://', 'https://')):
            raise ValueError('api_base must be an http(s) URL')
        self.api_base = api_base.rstrip('/')
        self.secret = secret

    def _post(self, path, body):
        req = urllib.request.Request(
            f'{self.api_base}{path}', data=json.dumps(body).encode(), method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Sshgw-Secret', self.secret)
        try:
            # The scheme is enforced in __init__ and the path is a literal.
            with _OPENER.open(req, timeout=8) as resp:  # nosec B310  # nosemgrep: dynamic-urllib-use-detected -- http(s) scheme enforced; fixed loopback base
                return resp.status, json.loads(resp.read(65536) or b'{}')
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read(65536) or b'{}')
            except ValueError:
                data = {}
            return e.code, data if isinstance(data, dict) else {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning('API %s unreachable: %s', path, e)
            return 0, {'error': 'gateway could not reach RemotePower'}

    async def authorize(self, username, fingerprint, target, client_ip):
        st, data = await asyncio.to_thread(self._post, '/sshgw/authorize', {
            'username': username, 'fingerprint': fingerprint,
            'target': target, 'client_ip': client_ip})
        if st == 200 and data.get('ok'):
            return data
        if st == 404:
            data = {'error': 'the SSH gateway is turned off in RemotePower'}
        return {'ok': False, 'error': str(data.get('error') or 'not authorized')[:200]}

    async def agent_check(self, device_id, token):
        st, data = await asyncio.to_thread(self._post, '/sshgw/agent-check', {
            'device_id': device_id, 'token': token})
        return st == 200 and bool(data.get('ok')), str(data.get('error') or '')[:200]

    async def audit(self, payload):
        st, _ = await asyncio.to_thread(self._post, '/sshgw/audit', payload)
        if st != 200:
            log.warning('audit POST for session %s returned %s',
                        payload.get('session_id'), st)


# ─── Agent tunnels ───────────────────────────────────────────────────────────

class StreamOpenError(Exception):
    pass


class Tunnel:
    """One agent's WebSocket, carrying many SSH streams."""

    def __init__(self, device_id, ws):
        self.device_id = device_id
        self.ws = ws
        self.streams = {}          # sid -> GatewaySession
        self.pending = {}          # sid -> Future (awaiting OPEN_OK / OPEN_FAIL)
        self._next_sid = 1
        self._outq = asyncio.Queue()
        self.closed = False
        self._writer = asyncio.ensure_future(self._write_loop())

    def _alloc_sid(self):
        for _ in range(sshgw.MAX_STREAM_ID):
            sid = self._next_sid
            self._next_sid = 1 if sid >= sshgw.MAX_STREAM_ID else sid + 1
            if sid not in self.streams and sid not in self.pending:
                return sid
        raise StreamOpenError('no free stream ids')

    def send(self, kind, sid, payload=b'', session=None):
        """Queue a frame. Never blocks; ordering is preserved by the single
        writer task."""
        if self.closed:
            return
        self._outq.put_nowait((sshgw.encode_frame(kind, sid, payload), session, len(payload)))

    async def _write_loop(self):
        try:
            while True:
                frame, session, n = await self._outq.get()
                await self.ws.send(frame)
                if session is not None and n:
                    session.sent_to_agent(n)
        except (ConnectionClosed, asyncio.CancelledError):
            pass
        except Exception as e:
            log.warning('tunnel %s writer stopped: %s', self.device_id, e)
        finally:
            self.closed = True

    async def open_stream(self, session):
        if len(self.streams) >= MAX_STREAMS_PER_TUNNEL:
            raise StreamOpenError('too many open sessions to this device')
        sid = self._alloc_sid()
        fut = asyncio.get_running_loop().create_future()
        self.pending[sid] = fut
        session.attach(self, sid)
        # Registered BEFORE the OPEN goes out: the agent sends the sshd banner
        # right behind OPEN_OK, and that DATA frame can be read before this
        # coroutine resumes. The session buffers it until its channel exists.
        self.streams[sid] = session
        self.send(sshgw.FRAME_OPEN, sid)
        try:
            await asyncio.wait_for(fut, OPEN_TIMEOUT_S)
        except asyncio.TimeoutError:
            self.streams.pop(sid, None)
            self.send(sshgw.FRAME_CLOSE, sid)
            raise StreamOpenError('the agent did not answer in time') from None
        except BaseException:
            self.streams.pop(sid, None)
            raise
        finally:
            self.pending.pop(sid, None)
        return sid

    def handle_frame(self, raw):
        try:
            kind, sid, payload = sshgw.decode_frame(raw)
        except ValueError as e:
            log.warning('tunnel %s: bad frame (%s); closing', self.device_id, e)
            return False
        if kind in (sshgw.FRAME_OPEN_OK, sshgw.FRAME_OPEN_FAIL):
            fut = self.pending.get(sid)
            if fut is not None and not fut.done():
                if kind == sshgw.FRAME_OPEN_OK:
                    fut.set_result(True)
                else:
                    fut.set_exception(StreamOpenError(
                        payload.decode('utf-8', 'replace')[:200] or 'agent refused'))
            return True
        session = self.streams.get(sid)
        if session is None:
            if kind == sshgw.FRAME_DATA:
                self.send(sshgw.FRAME_CLOSE, sid)
            return True
        if kind == sshgw.FRAME_DATA:
            session.from_agent(payload)
        elif kind == sshgw.FRAME_CLOSE:
            self.streams.pop(sid, None)
            session.remote_closed()
        elif kind == sshgw.FRAME_PAUSE:
            session.pause_from_agent()
        elif kind == sshgw.FRAME_RESUME:
            session.resume_from_agent()
        # FRAME_OPEN from an agent is not a thing; ignore it.
        return True

    def stream_done(self, sid):
        if self.streams.pop(sid, None) is not None:
            self.send(sshgw.FRAME_CLOSE, sid)

    def close(self, reason='tunnel closed'):
        if self.closed and not self.streams and not self.pending:
            return
        self.closed = True
        for fut in list(self.pending.values()):
            if not fut.done():
                fut.set_exception(StreamOpenError(reason))
        for session in list(self.streams.values()):
            session.remote_closed(reason)
        self.streams.clear()
        self._writer.cancel()


# ─── SSH side ────────────────────────────────────────────────────────────────

_SSHTCPSession = asyncssh.SSHTCPSession if _SSH_AVAILABLE else object
_SSHServer = asyncssh.SSHServer if _SSH_AVAILABLE else object
_SSHServerSession = asyncssh.SSHServerSession if _SSH_AVAILABLE else object


class GatewaySession(_SSHTCPSession):
    """One direct-tcpip channel, relayed to one agent stream."""

    def __init__(self, gw, meta):
        self.gw = gw
        self.meta = meta
        self.chan = None
        self.tunnel = None
        self.sid = None
        self.started = int(time.time())
        self._t0 = time.monotonic()
        self.bytes_in = 0          # client → host
        self.bytes_out = 0         # host → client
        self._queued = 0
        self._paused = False
        self._early = []           # host bytes that arrived before the channel
        self._done = False
        self.reason = 'closed'

    # wiring
    def attach(self, tunnel, sid):
        self.tunnel, self.sid = tunnel, sid

    def connection_made(self, chan):
        self.chan = chan
        for chunk in self._early:
            chan.write(chunk)
        self._early = []

    # client → agent
    def data_received(self, data, datatype):
        if not data or self.tunnel is None:
            return
        self.bytes_in += len(data)
        for i in range(0, len(data), CHUNK):
            part = data[i:i + CHUNK]
            self._queued += len(part)
            self.tunnel.send(sshgw.FRAME_DATA, self.sid, part, session=self)
        if self._queued > HIGH_WATER and not self._paused and self.chan:
            self._paused = True
            self.chan.pause_reading()

    def sent_to_agent(self, n):
        self._queued -= n
        if self._paused and self._queued < LOW_WATER and self.chan:
            self._paused = False
            self.chan.resume_reading()

    def eof_received(self):
        # The SSH protocol inside the stream does not use half-close; the
        # client's EOF is the end of the stream.
        self.reason = 'client closed'
        self._finish(close_tunnel_side=True)
        return False

    def connection_lost(self, exc):
        if exc is not None and self.reason == 'closed':
            self.reason = f'client lost: {type(exc).__name__}'
        self._finish(close_tunnel_side=True)

    # pause/resume of the host → client direction (asyncssh calls these when
    # the client stops keeping up)
    def pause_writing(self):
        if self.tunnel is not None and not self._done:
            self.tunnel.send(sshgw.FRAME_PAUSE, self.sid)

    def resume_writing(self):
        if self.tunnel is not None and not self._done:
            self.tunnel.send(sshgw.FRAME_RESUME, self.sid)

    # agent → client
    def from_agent(self, data):
        self.bytes_out += len(data)
        if self.chan is None:
            self._early.append(data)
        else:
            self.chan.write(data)

    def pause_from_agent(self):
        if self.chan is not None:
            self.chan.pause_reading()

    def resume_from_agent(self):
        if self.chan is not None and not self._paused:
            self.chan.resume_reading()

    def remote_closed(self, reason='host closed'):
        if self._done:
            return
        self.reason = reason
        if self.chan is not None:
            try:
                self.chan.write_eof()
            except Exception:  # nosec B110
                # channel may already be closing
                pass
            self.chan.close()
        self._finish(close_tunnel_side=False)

    def _finish(self, close_tunnel_side):
        if self._done:
            return
        self._done = True
        if close_tunnel_side and self.tunnel is not None and self.sid is not None:
            self.tunnel.stream_done(self.sid)
        self.gw.session_finished(self)


class _UsageSession(_SSHServerSession):
    """`ssh alice@gw` with no jump: explain how to use the gateway, then exit.
    The gateway never runs a shell."""

    def __init__(self, text):
        self.text = text
        self.chan = None

    def connection_made(self, chan):
        self.chan = chan

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        return True

    def subsystem_requested(self, subsystem):
        return False

    def session_started(self):
        self.chan.write(self.text)
        self.chan.exit(1)


class GatewaySSHServer(_SSHServer):
    def __init__(self, gw):
        self.gw = gw
        self.conn = None
        self.username = ''
        self.fingerprint = ''
        self.client_ip = ''
        self.authed = False
        self.streams = 0
        self.denied = 0
        self._answers = {}         # (username, fingerprint) -> bool, this connection
        self._pending = False      # counted in the gateway's unauthenticated total

    def connection_made(self, conn):
        self.conn = conn
        peer = conn.get_extra_info('peername') or ('', 0)
        self.client_ip = str(peer[0])
        if self.gw.banned(self.client_ip):
            log.info('refusing %s: too many failed logins', self.client_ip)
            conn.close()
            return
        if not self.gw.login_started(self.client_ip):
            log.info('refusing %s: %d connections already logging in',
                     self.client_ip, MAX_UNAUTH_PER_IP)
            conn.close()
            return
        self._pending = True

    def connection_lost(self, exc):
        if self._pending:
            self._pending = False
            self.gw.login_finished(self.client_ip)
        if not self.authed and self.client_ip:
            self.gw.note_failure(self.client_ip)

    def begin_auth(self, username):
        self.username = username
        return True

    def password_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return False

    def public_key_auth_supported(self):
        return True

    async def validate_public_key(self, username, key):
        fp = key.get_fingerprint('sha256')
        pair = (username, fp)
        if pair not in self._answers:
            if len(self._answers) >= MAX_AUTH_ATTEMPTS:
                log.info('closing %s: more than %d keys offered',
                         self.client_ip, MAX_AUTH_ATTEMPTS)
                if self.conn is not None:
                    self.conn.close()
                return False
            res = await self.gw.api.authorize(username, fp, '', self.client_ip)
            self._answers[pair] = bool(res.get('ok'))
            if not self._answers[pair]:
                # The fingerprint is what the SSH gateway page lists for each key,
                # so an operator can tell "wrong account name" from "key not added".
                log.info('refused key %s for %s from %s: %s', fp, username,
                         self.client_ip, res.get('error') or 'not authorized')
        if self._answers[pair]:
            # asyncssh asks once without a signature and once with; the last
            # key accepted before auth completes is the one that signed. The
            # second ask is answered from this connection's own record, so a
            # client re-offering one key costs the API nothing.
            self.fingerprint = fp
            return True
        return False

    def auth_completed(self):
        self.authed = True
        if self._pending:
            self._pending = False
            self.gw.login_finished(self.client_ip)
        log.info('login %s from %s key %s', self.username, self.client_ip, self.fingerprint)

    def session_requested(self):
        return _UsageSession(self.gw.usage_text(self.username))

    def server_requested(self, listen_host, listen_port):
        return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return self._open(dest_host)

    async def _open(self, dest_host):
        if self.streams >= MAX_STREAMS_PER_CONN:
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_RESOURCE_SHORTAGE, 'too many channels on this connection')
        res = await self.gw.api.authorize(self.username, self.fingerprint,
                                          dest_host, self.client_ip)
        if not res.get('ok'):
            log.info('denied %s → %s: %s', self.username, dest_host, res.get('error'))
            self.denied += 1
            if self.denied >= MAX_DENIED_PER_CONN and self.conn is not None:
                log.warning('closing %s from %s after %d refused channels',
                            self.username, self.client_ip, self.denied)
                self.conn.close()
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED,
                res.get('error') or 'not authorized')
        device_id = res['device_id']
        tunnel = self.gw.tunnels.get(device_id)
        if tunnel is None or tunnel.closed:
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_CONNECT_FAILED,
                f'{res.get("device_name") or device_id} is not connected to the '
                'gateway (agent offline, or its tunnel has not opened yet)')
        meta = {'session_id': res.get('session_id') or '',
                'username': self.username, 'fingerprint': self.fingerprint,
                'device_id': device_id, 'target': dest_host[:128],
                'client_ip': self.client_ip}
        session = GatewaySession(self.gw, meta)
        try:
            await tunnel.open_stream(session)
        except StreamOpenError as e:
            session.reason = f'open failed: {e}'
            self.gw.session_finished(session)
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, str(e)) from None
        self.streams += 1
        session.on_close = self._stream_closed
        log.info('stream %s: %s → %s (%s)', meta['session_id'], self.username,
                 device_id, dest_host)
        return session

    def _stream_closed(self):
        self.streams = max(0, self.streams - 1)


# ─── The gateway ─────────────────────────────────────────────────────────────

class Gateway:
    def __init__(self, api, public_host='', public_port=DEFAULT_SSH_PORT):
        self.api = api
        self.tunnels = {}                       # device_id -> Tunnel
        self.public_host = public_host
        self.public_port = public_port
        self._fails = collections.defaultdict(collections.deque)
        self._banned = {}
        self._logging_in = collections.Counter()   # ip -> connections not yet authenticated
        self._audit_tasks = set()

    # concurrent unauthenticated connections per address
    def login_started(self, ip):
        if self._logging_in[ip] >= MAX_UNAUTH_PER_IP:
            return False
        self._logging_in[ip] += 1
        return True

    def login_finished(self, ip):
        n = self._logging_in.get(ip, 0) - 1
        if n > 0:
            self._logging_in[ip] = n
        else:
            self._logging_in.pop(ip, None)

    # failed-login throttle
    def note_failure(self, ip):
        now = time.monotonic()
        q = self._fails[ip]
        q.append(now)
        while q and now - q[0] > FAIL_WINDOW_S:
            q.popleft()
        if len(q) >= FAIL_LIMIT:
            self._banned[ip] = now + BAN_S
            q.clear()
            log.warning('throttling %s for %ds after %d failed logins', ip, BAN_S, FAIL_LIMIT)
        if len(self._fails) > 10000:
            self._fails.clear()

    def banned(self, ip):
        until = self._banned.get(ip)
        if until is None:
            return False
        if time.monotonic() >= until:
            self._banned.pop(ip, None)
            return False
        return True

    def usage_text(self, username):
        host = self.public_host or 'this-gateway'
        port = '' if self.public_port == 22 else f':{self.public_port}'
        return ('This is the RemotePower SSH gateway. It does not run a shell.\r\n'
                'Jump through it to reach a host:\r\n\r\n'
                f'  ssh -J {username}@{host}{port} root@web01{sshgw.TARGET_SUFFIX}\r\n\r\n'
                'or add to ~/.ssh/config:\r\n\r\n'
                '  Host rp-gateway\r\n'
                f'      HostName {host}\r\n'
                + (f'      Port {port[1:]}\r\n' if port else '') +
                f'      User {username}\r\n'
                '      # with several keys, add: IdentityFile <the key you registered>\r\n\r\n'
                f'  Host *{sshgw.TARGET_SUFFIX}\r\n'
                '      ProxyJump rp-gateway\r\n')

    def session_finished(self, session):
        cb = getattr(session, 'on_close', None)
        if cb:
            session.on_close = None
            cb()
        meta = session.meta
        payload = dict(meta, started=session.started,
                       duration_s=int(time.monotonic() - session._t0),
                       bytes_in=session.bytes_in, bytes_out=session.bytes_out,
                       reason=session.reason[:128])
        log.info('stream %s closed: %s (%d in / %d out)', meta.get('session_id'),
                 session.reason, session.bytes_in, session.bytes_out)
        t = asyncio.ensure_future(self.api.audit(payload))
        self._audit_tasks.add(t)
        t.add_done_callback(self._audit_tasks.discard)

    # agent side
    @staticmethod
    def _credentials(websocket):
        try:
            path = websocket.request.path
        except AttributeError:
            path = getattr(websocket, 'path', '')
        qs = urllib.parse.urlparse(path).query
        dev_id = (urllib.parse.parse_qs(qs).get('device_id', [''])[0] or '').strip()
        try:
            headers = websocket.request.headers
        except AttributeError:
            headers = getattr(websocket, 'request_headers', {})
        token = (headers.get('X-RP-Sshgw-Token', '') or '').strip()
        return dev_id, token

    async def agent_handler(self, websocket, *_ignored):
        dev_id, token = self._credentials(websocket)
        ok, why = (False, 'missing credentials')
        if dev_id and token and len(dev_id) <= 64:
            ok, why = await self.api.agent_check(dev_id, token)
        if not ok:
            log.warning('tunnel refused for %r: %s', dev_id[:64], why)
            await websocket.close(code=4403, reason='not authorized')
            return
        old = self.tunnels.get(dev_id)
        if old is not None:
            old.close('superseded by a new tunnel')
            try:
                await old.ws.close(code=4409, reason='superseded')
            except Exception:  # nosec B110
                # the old peer may be gone already
                pass
        tunnel = Tunnel(dev_id, websocket)
        self.tunnels[dev_id] = tunnel
        log.info('tunnel up: %s (%d connected)', dev_id, len(self.tunnels))
        recheck = asyncio.ensure_future(self._recheck(tunnel, token))
        try:
            async for msg in websocket:
                if isinstance(msg, str) or not tunnel.handle_frame(msg):
                    break
        except ConnectionClosed:
            pass
        finally:
            recheck.cancel()
            tunnel.close()
            if self.tunnels.get(dev_id) is tunnel:
                del self.tunnels[dev_id]
            try:
                await websocket.close()
            except Exception:  # nosec B110
                pass
            log.info('tunnel down: %s (%d connected)', dev_id, len(self.tunnels))

    async def _recheck(self, tunnel, token):
        """Close a tunnel whose device has since been opted out, or whose token
        was rotated, without waiting for the agent to notice."""
        while True:
            await asyncio.sleep(TUNNEL_RECHECK_S)
            ok, why = await self.api.agent_check(tunnel.device_id, token)
            if not ok:
                log.info('closing tunnel %s: %s', tunnel.device_id, why)
                tunnel.close(why or 'no longer authorized')
                try:
                    await tunnel.ws.close(code=4403, reason='no longer authorized')
                except Exception:  # nosec B110
                    pass
                return


def load_or_create_host_key(path):
    p = Path(path)
    if p.exists():
        return asyncssh.read_private_key(str(p))
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = asyncssh.generate_private_key('ssh-ed25519')
    old = os.umask(0o077)
    try:
        key.write_private_key(str(p))
    finally:
        os.umask(old)
    log.warning('generated a new gateway host key at %s', p)
    return key


async def start(gw, host_key, ssh_host, ssh_port, ws_host, ws_port):
    """Start both listeners; returns (ssh_server, ws_server). Split out so the
    test suite can run the real gateway on ephemeral ports."""
    ssh_server = await asyncssh.create_server(
        lambda: GatewaySSHServer(gw), ssh_host, ssh_port,
        server_host_keys=[host_key],
        login_timeout=LOGIN_TIMEOUT_S,
        keepalive_interval=30,
        allow_scp=False,
        agent_forwarding=False,
        x11_forwarding=False,
        server_version='RemotePower-sshgw')
    ws_server = await websockets.serve(
        gw.agent_handler, ws_host, ws_port,
        ping_interval=20, ping_timeout=20,
        max_size=sshgw.FRAME_HEADER.size + sshgw.MAX_FRAME_PAYLOAD,
        max_queue=64)
    return ssh_server, ws_server


async def main_async(args):
    api = ApiClient(args.api_base, args.secret)
    gw = Gateway(api, args.public_host, args.public_port or args.ssh_port)
    key = load_or_create_host_key(args.host_key)
    ssh_server, ws_server = await start(gw, key, args.ssh_host, args.ssh_port,
                                        args.ws_host, args.ws_port)
    log.info('remotepower-sshgw v%s: ssh on %s:%d, agent tunnels on %s:%d',
             VERSION, args.ssh_host, args.ssh_port, args.ws_host, args.ws_port)
    log.info('host key fingerprint %s', key.get_fingerprint('sha256'))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    log.info('shutting down')
    ssh_server.close()
    for t in list(gw.tunnels.values()):
        t.close('gateway shutting down')
    ws_server.close()
    try:
        await asyncio.wait_for(ws_server.wait_closed(), timeout=3)
    except asyncio.TimeoutError:
        pass


def _asyncssh_version_ok():
    try:
        v = tuple(int(x) for x in str(asyncssh.__version__).split('.')[:3])
    except Exception:
        return False
    return v >= MIN_ASYNCSSH


def main():
    if not _SSH_AVAILABLE or not _WS_AVAILABLE:
        print('ERROR: remotepower-sshgw needs asyncssh (>= 2.14.2) and websockets (>= 10).',
              file=sys.stderr)
        print('  Debian/Ubuntu: apt install python3-asyncssh python3-websockets', file=sys.stderr)
        print("  pip:           pip install 'asyncssh>=2.14.2' 'websockets>=10'", file=sys.stderr)
        sys.exit(2)
    if not _asyncssh_version_ok():
        print(f'ERROR: asyncssh {asyncssh.__version__} is older than '
              f'{".".join(map(str, MIN_ASYNCSSH))}, which fixes the Terrapin and '
              'rogue-session flaws. This daemon faces the internet; upgrade asyncssh.',
              file=sys.stderr)
        sys.exit(2)

    env = os.environ.get
    p = argparse.ArgumentParser(description='RemotePower SSH gateway')
    p.add_argument('--ssh-host', default=env('SSHGW_SSH_HOST', DEFAULT_SSH_HOST))
    p.add_argument('--ssh-port', type=int, default=int(env('SSHGW_SSH_PORT', DEFAULT_SSH_PORT)))
    p.add_argument('--ws-host', default=env('SSHGW_WS_HOST', DEFAULT_WS_HOST))
    p.add_argument('--ws-port', type=int, default=int(env('SSHGW_WS_PORT', DEFAULT_WS_PORT)))
    p.add_argument('--api-base', default=env('SSHGW_API_BASE', DEFAULT_API_BASE))
    p.add_argument('--secret-file', default=env('SSHGW_SECRET_FILE', DEFAULT_SECRET_FILE))
    p.add_argument('--host-key', default=env('SSHGW_HOST_KEY', DEFAULT_HOST_KEY))
    p.add_argument('--public-host', default=env('SSHGW_PUBLIC_HOST', ''),
                   help='hostname shown in the usage message')
    p.add_argument('--public-port', type=int, default=int(env('SSHGW_PUBLIC_PORT', 0)),
                   help='port shown in the usage message (default: --ssh-port)')
    p.add_argument('--verbose', '-v', action='count', default=0)
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose >= 2 else logging.INFO if args.verbose else logging.WARNING,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', stream=sys.stderr)
    if args.verbose < 2:
        logging.getLogger('asyncssh').setLevel(logging.WARNING)

    if not str(args.api_base).startswith(('http://', 'https://')):
        raise SystemExit(f'--api-base must be an http(s) URL, got {args.api_base!r}')
    try:
        args.secret = Path(args.secret_file).read_text().strip()
    except OSError as e:
        log.error('could not read secret file %s: %s', args.secret_file, e)
        log.error('create one with: openssl rand -hex 32 > %s && chmod 600 %s',
                  args.secret_file, args.secret_file)
        sys.exit(2)
    if len(args.secret) < 32:
        log.error('secret in %s is shorter than 32 characters', args.secret_file)
        sys.exit(2)
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
