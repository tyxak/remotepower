#!/usr/bin/env python3
"""
remotepower-webterm — companion daemon for browser-based SSH terminals
=======================================================================

Why a separate daemon?
----------------------

RemotePower's main API runs over CGI (fcgiwrap), which is request/response.
WebSockets need persistent connections — incompatible with CGI. Rather than
refactor the whole stack onto an asyncio server, this lightweight daemon
handles just the WebSocket+SSH proxy and runs as its own systemd unit.

What it does:
  1. Accepts WebSocket connections on 127.0.0.1:8765 (nginx proxies
     /api/webterm/connect → here over loopback).
  2. Reads a ticket from the WS URL, validates against the shared
     ticket store written by the CGI's /api/webterm/auth endpoint.
  3. After ticket validation, expects the first WS message to be a JSON
     blob with SSH host/user/password (the user typed those into the
     dashboard). Connects via asyncssh.
  4. Pumps bytes between the WS and the SSH channel. Records the session
     to /var/lib/remotepower/webterm-sessions/<session_id>.cast in
     asciinema v2 format (replayable in any asciinema player; also
     readable as plain text JSON for grep/audit).
  5. POSTs session metadata back to the CGI's /api/webterm/audit
     endpoint when the session ends (duration, byte counts, reason).

Security model
--------------

- The ticket is the *only* trust anchor between CGI and daemon. Tickets
  are 32-byte URL-safe random strings (~256 bits of entropy), single-use,
  and expire 60 seconds after issue. The daemon deletes each ticket
  immediately after validating it.

- SSH credentials are never persisted. The user types them into the
  dashboard each session; they live in memory inside this daemon for the
  duration of the SSH connection only. They're never logged.

- The daemon binds to 127.0.0.1 only. nginx is the only thing that should
  reach it, and nginx terminates TLS so the WS hop from browser to nginx
  is over wss. The hop from nginx to daemon is plaintext over loopback,
  which is fine for this threat model.

- The daemon authenticates back to the CGI via a shared secret in
  /etc/remotepower/webterm-secret (mode 600, owned by the daemon's user).
  CGI reads the same secret from config.json. Mismatch → audit POST
  rejected.

Dependencies
------------

- Python 3.8+ (3.9+ recommended for asyncio.to_thread)
- websockets >= 10
- asyncssh >= 2.10

On Debian/Ubuntu: apt install python3-websockets python3-asyncssh
On Fedora/RHEL:   dnf install python3-websockets python3-asyncssh

Both are widely packaged. The daemon refuses to start if either is missing
and prints a useful error message.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import signal
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

# Defer the optional-dep imports so we can give a useful error message
# if they're missing instead of crashing with ModuleNotFoundError.
try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:
    print("ERROR: websockets library not installed.", file=sys.stderr)
    print("  Debian/Ubuntu: apt install python3-websockets", file=sys.stderr)
    print("  Fedora/RHEL:   dnf install python3-websockets", file=sys.stderr)
    print("  pip:           pip install 'websockets>=10'", file=sys.stderr)
    sys.exit(2)

try:
    import asyncssh
except ImportError:
    print("ERROR: asyncssh library not installed.", file=sys.stderr)
    print("  Debian/Ubuntu: apt install python3-asyncssh", file=sys.stderr)
    print("  Fedora/RHEL:   dnf install python3-asyncssh", file=sys.stderr)
    print("  pip:           pip install 'asyncssh>=2.10'", file=sys.stderr)
    sys.exit(2)

VERSION = '1.12.1'

# ─── Defaults — overridable via CLI ──────────────────────────────────────────

DEFAULT_BIND_HOST = '127.0.0.1'
DEFAULT_BIND_PORT = 8765
DEFAULT_DATA_DIR = Path('/var/lib/remotepower')
DEFAULT_SECRET_FILE = Path('/etc/remotepower/webterm-secret')
DEFAULT_API_BASE = 'http://127.0.0.1/api'   # CGI accessed via nginx loopback

SSH_CONNECT_TIMEOUT = 10
SSH_KEEPALIVE_INTERVAL = 30
MAX_RECORDING_BYTES = 10 * 1024 * 1024  # 10 MiB cap per session — matches CGI

log = logging.getLogger('webterm')


# ─── Ticket store (shared with CGI via JSON file) ────────────────────────────


class TicketStore:
    """Reads/writes the ticket file the CGI's /api/webterm/auth populates.

    The file is owned by the CGI user (rp-www) but readable by the daemon
    (rp-webterm) — the deploy script puts both in the same group and
    gives the file mode 640. The daemon never *creates* tickets, only
    consumes them.

    File format (JSON dict):
        { "<ticket>": {actor, device_id, created, expires, used, source_ip} }
    """

    def __init__(self, path: Path):
        self.path = path

    def consume(self, ticket: str):
        """Validate-and-delete a ticket. Returns the metadata dict or None."""
        if not ticket or len(ticket) > 256:
            return None
        try:
            with self.path.open('r') as f:
                tickets = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        meta = tickets.get(ticket)
        if not meta:
            return None
        now = int(time.time())
        if meta.get('expires', 0) < now or meta.get('used'):
            return None
        # Mark used + persist. We delete entirely rather than just flagging
        # because file growth would be unbounded otherwise.
        del tickets[ticket]
        # Best-effort write — if we can't persist, the ticket has still
        # been consumed in our return, but a concurrent daemon process
        # (shouldn't happen) might re-validate. Acceptable.
        try:
            tmp = self.path.with_suffix('.tmp')
            with tmp.open('w') as f:
                json.dump(tickets, f)
            os.replace(tmp, self.path)
        except OSError as e:
            log.warning("ticket_store: persist failed: %s", e)
        return meta


# ─── Session recording (asciinema v2) ────────────────────────────────────────


class SessionRecorder:
    """Writes asciinema v2 cast files. Append-only, line-buffered.

    Format (https://docs.asciinema.org/manual/asciicast/v2/):
        First line: header JSON with {version: 2, width, height, timestamp, ...}
        Subsequent lines: [delta_seconds, "o", "output text"]

    We only record output ('o' events) — the user's keystrokes are
    sensitive (could include `sudo SECRET_VALUE`) and recording them
    creates a higher liability surface. If you need keystroke recording
    for compliance, set RECORD_INPUT=1 in the daemon env, but think
    carefully about who can read /var/lib/remotepower/webterm-sessions
    first.
    """

    def __init__(self, path: Path, width=80, height=24, title='', record_input=False):
        self.path = path
        self.start = time.time()
        self.bytes_written = 0
        self.fd = None
        self.record_input = record_input
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = open(path, 'w', buffering=1)  # line-buffered
        header = {
            'version':   2,
            'width':     width,
            'height':    height,
            'timestamp': int(self.start),
            'title':     title[:128],
            'env': {'TERM': 'xterm-256color', 'SHELL': '/bin/sh'},
        }
        self._write_line(json.dumps(header))

    def output(self, data: str):
        if self.fd is None:
            return
        delta = round(time.time() - self.start, 6)
        self._write_line(json.dumps([delta, 'o', data]))

    def input(self, data: str):
        if self.fd is None or not self.record_input:
            return
        delta = round(time.time() - self.start, 6)
        self._write_line(json.dumps([delta, 'i', data]))

    def _write_line(self, line: str):
        if self.fd is None:
            return
        # Cap file size — at the cap we stop recording but keep proxying
        # bytes. We log a warning so an admin can investigate why a session
        # produced 10 MiB of output (probably a `cat` of a huge log file).
        if self.bytes_written + len(line) + 1 > MAX_RECORDING_BYTES:
            log.warning("recording for %s hit %d byte cap, stopping", self.path,
                        MAX_RECORDING_BYTES)
            self.close()
            return
        try:
            self.fd.write(line + '\n')
            self.bytes_written += len(line) + 1
        except OSError as e:
            log.warning("recording write failed: %s", e)
            self.close()

    def close(self):
        if self.fd is not None:
            try:
                self.fd.close()
            except OSError:
                pass
            self.fd = None


# ─── Session metadata reporting ──────────────────────────────────────────────


def post_audit(api_base: str, secret: str, payload: dict):
    """Best-effort POST to /api/webterm/audit. Synchronous (called at session end)."""
    try:
        url = f"{api_base.rstrip('/')}/webterm/audit"
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Webterm-Secret', secret)
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        # Audit log delivery isn't critical-path. Log and move on.
        log.warning("audit POST failed: %s", e)


# ─── The actual proxy ────────────────────────────────────────────────────────


def _validate_ssh_creds(creds: dict):
    """Sanity-check the SSH connection params. Returns (ok, error_msg)."""
    host = (creds.get('host') or '').strip()
    user = (creds.get('user') or '').strip()
    password = creds.get('password') or ''
    port = creds.get('port', 22)
    if not host:
        return False, 'host required'
    # Hostname/IP check — no fancy regex, just rule out shell-meta and
    # absurdly long values
    if len(host) > 253 or any(c in host for c in ' \t\r\n;|&$`<>"\''):
        return False, 'invalid host'
    if not user:
        return False, 'user required'
    if not re.match(r'^[a-zA-Z0-9._\-]{1,32}$', user):
        return False, 'invalid user'
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False, 'invalid port'
    if not password:
        return False, 'password required'
    if len(password) > 4096:
        return False, 'password too long'
    return True, ''


class WebtermSession:
    """One browser ↔ SSH session.

    Lifecycle:
      __init__         — set up
      run(websocket)   — main loop, returns when either side closes
    """

    def __init__(self, args, ticket_store):
        self.args = args
        self.ticket_store = ticket_store
        self.session_id = secrets.token_hex(8)
        self.actor = '?'
        self.device_id = '?'
        self.ssh_host = '?'
        self.ssh_user = '?'
        self.bytes_in = 0    # browser → SSH
        self.bytes_out = 0   # SSH → browser
        self.started = time.time()
        self.recorder = None
        self.reason = 'unknown'

    async def _send_json(self, ws, obj):
        try:
            await ws.send(json.dumps(obj))
        except ConnectionClosed:
            pass

    async def run(self, websocket):
        """Top-level handler. Always reports an audit event when it returns."""
        try:
            await self._run_inner(websocket)
        except Exception as e:
            log.exception("session %s crashed: %s", self.session_id, e)
            self.reason = f'crash: {type(e).__name__}'
            await self._send_json(websocket, {'type': 'error', 'message': str(e)[:200]})
        finally:
            duration = int(time.time() - self.started)
            if self.recorder:
                self.recorder.close()
            log.info("session %s ended: actor=%s device=%s ssh=%s@%s "
                     "duration=%ds in=%d out=%d reason=%s",
                     self.session_id, self.actor, self.device_id,
                     self.ssh_user, self.ssh_host, duration,
                     self.bytes_in, self.bytes_out, self.reason)
            post_audit(self.args.api_base, self.args.secret, {
                'actor':      self.actor,
                'device_id':  self.device_id,
                'ssh_user':   self.ssh_user,
                'ssh_host':   self.ssh_host,
                'session_id': self.session_id,
                'duration_s': duration,
                'bytes_in':   self.bytes_in,
                'bytes_out':  self.bytes_out,
                'reason':     self.reason,
            })

    async def _run_inner(self, websocket):
        # Step 1: extract ticket from query string
        try:
            qs = urllib.parse.urlparse(websocket.request.path).query
        except AttributeError:
            # Older websockets versions expose .path differently
            qs = urllib.parse.urlparse(getattr(websocket, 'path', '')).query
        params = urllib.parse.parse_qs(qs)
        ticket = (params.get('ticket', [''])[0] or '').strip()
        if not ticket:
            self.reason = 'no ticket'
            await self._send_json(websocket, {'type': 'error', 'message': 'No ticket provided'})
            return

        meta = self.ticket_store.consume(ticket)
        if not meta:
            self.reason = 'invalid ticket'
            await self._send_json(websocket, {'type': 'error', 'message': 'Invalid or expired ticket'})
            return
        self.actor = meta.get('actor', '?')
        self.device_id = meta.get('device_id', '?')

        # Step 2: wait for SSH credentials as the first WS message
        try:
            first = await asyncio.wait_for(websocket.recv(), timeout=30)
        except asyncio.TimeoutError:
            self.reason = 'cred timeout'
            await self._send_json(websocket, {'type': 'error', 'message': 'Timed out waiting for SSH credentials'})
            return

        try:
            creds = json.loads(first)
        except json.JSONDecodeError:
            self.reason = 'bad cred json'
            await self._send_json(websocket, {'type': 'error', 'message': 'First message must be JSON'})
            return

        ok, msg = _validate_ssh_creds(creds)
        if not ok:
            self.reason = f'bad creds: {msg}'
            await self._send_json(websocket, {'type': 'error', 'message': msg})
            return
        self.ssh_host = creds['host']
        self.ssh_user = creds['user']
        ssh_port = creds.get('port', 22)
        cols = int(creds.get('cols', 80)) if isinstance(creds.get('cols'), int) else 80
        rows = int(creds.get('rows', 24)) if isinstance(creds.get('rows'), int) else 24

        await self._send_json(websocket, {'type': 'connecting'})

        # Step 3: SSH connect. We disable host-key checking deliberately —
        # the user typed in this hostname; they know what they're connecting
        # to. Adding strict host key checking would mean a known_hosts
        # file the daemon manages and re-prompting on first connect, which
        # is more security theatre than security in this flow. The user is
        # already authenticated to RemotePower as admin and explicitly
        # authorised this connection.
        log.info("session %s connecting: actor=%s device=%s ssh=%s@%s:%d",
                 self.session_id, self.actor, self.device_id,
                 self.ssh_user, self.ssh_host, ssh_port)
        try:
            ssh_conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.ssh_host,
                    port=ssh_port,
                    username=self.ssh_user,
                    password=creds['password'],
                    known_hosts=None,    # see comment above
                    keepalive_interval=SSH_KEEPALIVE_INTERVAL,
                ),
                timeout=SSH_CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            self.reason = 'ssh connect timeout'
            await self._send_json(websocket, {'type': 'error',
                                              'message': f'SSH connect timed out after {SSH_CONNECT_TIMEOUT}s'})
            return
        except asyncssh.PermissionDenied:
            self.reason = 'ssh auth failed'
            await self._send_json(websocket, {'type': 'error',
                                              'message': 'SSH authentication failed'})
            return
        except (asyncssh.Error, OSError) as e:
            self.reason = f'ssh error: {type(e).__name__}'
            await self._send_json(websocket, {'type': 'error',
                                              'message': f'SSH connection failed: {str(e)[:200]}'})
            return

        # Step 4: open a PTY shell
        try:
            ssh_proc = await ssh_conn.create_process(
                term_type='xterm-256color',
                term_size=(cols, rows),
            )
        except asyncssh.Error as e:
            self.reason = f'pty fail: {type(e).__name__}'
            await self._send_json(websocket, {'type': 'error',
                                              'message': f'PTY allocation failed: {e}'})
            ssh_conn.close()
            return

        # Step 5: open recording
        try:
            recording_path = (DEFAULT_DATA_DIR / 'webterm-sessions' /
                              f'{self.session_id}.cast')
            self.recorder = SessionRecorder(
                recording_path,
                width=cols, height=rows,
                title=f'{self.actor}@{self.ssh_host} → {self.ssh_user}',
                record_input=bool(os.environ.get('RECORD_INPUT')),
            )
        except OSError as e:
            log.warning("session %s: recording open failed: %s", self.session_id, e)
            self.recorder = None  # carry on without recording

        await self._send_json(websocket, {'type': 'connected', 'session_id': self.session_id})

        # Step 6: byte pump. Two coroutines, whichever finishes first wins
        # and we tear the other down.

        async def ws_to_ssh():
            try:
                async for msg in websocket:
                    # Browser sends text frames only
                    if isinstance(msg, bytes):
                        msg = msg.decode('utf-8', errors='replace')
                    # Special control messages — JSON objects with a 'type' field
                    if msg.startswith('{'):
                        try:
                            obj = json.loads(msg)
                            if obj.get('type') == 'resize':
                                new_cols = int(obj.get('cols', cols))
                                new_rows = int(obj.get('rows', rows))
                                if 1 <= new_cols <= 500 and 1 <= new_rows <= 200:
                                    ssh_proc.change_terminal_size(new_cols, new_rows)
                                continue
                            if obj.get('type') == 'ping':
                                await self._send_json(websocket, {'type': 'pong'})
                                continue
                            # Unknown JSON control — fall through to treat as input
                        except (json.JSONDecodeError, ValueError):
                            pass
                    self.bytes_in += len(msg)
                    if self.recorder:
                        self.recorder.input(msg)
                    ssh_proc.stdin.write(msg)
                self.reason = 'ws closed'
            except ConnectionClosed:
                self.reason = 'ws closed'
            except Exception as e:
                self.reason = f'ws_to_ssh: {type(e).__name__}'
                log.exception("ws_to_ssh in session %s: %s", self.session_id, e)

        async def ssh_to_ws():
            try:
                while True:
                    chunk = await ssh_proc.stdout.read(4096)
                    if not chunk:
                        self.reason = 'ssh eof'
                        break
                    if isinstance(chunk, bytes):
                        chunk = chunk.decode('utf-8', errors='replace')
                    self.bytes_out += len(chunk)
                    if self.recorder:
                        self.recorder.output(chunk)
                    await websocket.send(chunk)
            except ConnectionClosed:
                self.reason = 'ws closed'
            except asyncssh.Error as e:
                self.reason = f'ssh: {type(e).__name__}'
            except Exception as e:
                self.reason = f'ssh_to_ws: {type(e).__name__}'
                log.exception("ssh_to_ws in session %s: %s", self.session_id, e)

        try:
            done, pending = await asyncio.wait(
                [asyncio.create_task(ws_to_ssh()),
                 asyncio.create_task(ssh_to_ws())],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
        finally:
            try:
                ssh_proc.close()
            except Exception:
                pass
            try:
                ssh_conn.close()
            except Exception:
                pass


# ─── Daemon entry point ──────────────────────────────────────────────────────


async def main_async(args):
    ticket_store = TicketStore(Path(args.tickets_file))

    async def handler(websocket):
        session = WebtermSession(args, ticket_store)
        await session.run(websocket)

    log.info("remotepower-webterm v%s listening on %s:%d", VERSION, args.host, args.port)
    log.info("api_base=%s tickets=%s", args.api_base, args.tickets_file)

    async with websockets.serve(handler, args.host, args.port,
                                 ping_interval=20, ping_timeout=20,
                                 max_size=64 * 1024):
        # Graceful shutdown via SIGTERM
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                # Windows
                pass
        await stop.wait()
        log.info("shutting down")


def main():
    p = argparse.ArgumentParser(
        description='RemotePower web terminal daemon (browser ↔ SSH proxy)')
    p.add_argument('--host', default=os.environ.get('WEBTERM_HOST', DEFAULT_BIND_HOST))
    p.add_argument('--port', type=int, default=int(os.environ.get('WEBTERM_PORT', DEFAULT_BIND_PORT)))
    p.add_argument('--data-dir', default=os.environ.get('WEBTERM_DATA_DIR', str(DEFAULT_DATA_DIR)))
    p.add_argument('--api-base', default=os.environ.get('WEBTERM_API_BASE', DEFAULT_API_BASE),
                   help='URL prefix for /webterm/audit POSTs back to CGI')
    p.add_argument('--secret-file', default=os.environ.get('WEBTERM_SECRET_FILE', str(DEFAULT_SECRET_FILE)),
                   help='File containing the shared secret CGI uses to authenticate audit POSTs')
    p.add_argument('--tickets-file', default=None,
                   help='Path to webterm_tickets.json (default: <data-dir>/webterm_tickets.json)')
    p.add_argument('--verbose', '-v', action='count', default=0)
    args = p.parse_args()

    level = logging.WARNING
    if args.verbose >= 1:
        level = logging.INFO
    if args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        stream=sys.stderr,
    )

    args.data_dir = Path(args.data_dir)
    if not args.tickets_file:
        args.tickets_file = str(args.data_dir / 'webterm_tickets.json')
    try:
        args.secret = Path(args.secret_file).read_text().strip()
    except OSError as e:
        log.error("Could not read secret file %s: %s", args.secret_file, e)
        log.error("Generate one with: openssl rand -hex 32 > %s && chmod 600 %s",
                  args.secret_file, args.secret_file)
        sys.exit(2)
    if not args.secret:
        log.error("Secret file %s is empty", args.secret_file)
        sys.exit(2)

    asyncio.run(main_async(args))


if __name__ == '__main__':
    main()
