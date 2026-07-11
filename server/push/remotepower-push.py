#!/usr/bin/env python3
"""
remotepower-push — companion daemon for a real agent push channel
====================================================================

docs/master-improvement-scoping-internal.md #1 ("Real push channel WS/SSE").

Why a separate daemon (not built into the main app)?
------------------------------------------------------

RemotePower's main API runs on gunicorn with a FIXED thread pool
(`--workers 4 --threads 8`, see docs/wsgi.md) sized for short request/
response cycles. A gthread worker holding a WebSocket open INDEFINITELY
(not the existing bounded 90-120s long-poll exec-wait) would permanently
pin a thread per connected agent — even a moderate number of concurrently-
connected agents would exhaust the whole pool and start blocking unrelated
heartbeat/API traffic fleet-wide. asyncio handles many concurrent idle
connections on very few real OS threads, which is why the existing
web-terminal daemon (server/webterm/remotepower-webterm.py) already uses
this exact "separate async companion process" shape for the same underlying
reason (long-lived connections don't mix with a fixed-size sync thread
pool) — this daemon follows the same precedent.

Deliberately narrow scope: a WAKE-ONLY push, not a full command-push
channel
---------------------------------------------------------------------

This does NOT replace the agent's existing 60s heartbeat poll, and does
NOT push command payloads over the WebSocket. It sends a tiny nudge
("you have pending work, poll now") when an agent has commands queued
in CMDS_FILE; the agent's EXISTING, already-correct poll-and-execute code
path does the rest, unchanged. Two consequences of that choice:

  1. The push channel is a pure LATENCY optimization (command dispatch
     drops from "up to 60s" to "near-instant" for a connected agent), not
     a new correctness-critical path. If the daemon crashes, a WS
     connection drops, or this whole subsystem is never installed, the
     product behaves EXACTLY as it does today — commands still get
     delivered on the next scheduled poll. Nothing regresses.
  2. It avoids re-implementing command-delivery semantics (dedup,
     ordering, quarantine/audit-mode gating, etc.) in a second place —
     that logic stays exactly where it already lives, in the agent's own
     heartbeat handler and the server's existing command-queue handlers.

Honest limitation, not yet closed: this has NOT been verified under real
multi-agent concurrent-connection load (this development environment has
no way to spin up hundreds of real concurrent agent connections). Ship
disabled by default (`push_enabled` config flag, off) until an operator
who can load-test a real fleet opts in.

Auth model
----------

An agent authenticates the SAME way it already does on every heartbeat:
its device token (DEVICES_FILE[dev_id]['token_hash'], SHA-256, or the
legacy plaintext 'token' field pre-migration) — verified with the exact
same constant-time comparison logic as api.py's _device_token_ok(), ported
here as a pure function (no api.py import; this daemon shares only the
on-disk DATA_DIR files, not the process). device_id travels in the query
string (not sensitive, same as any other device id already visible in
URLs across the product); the token travels in a custom header
(X-RP-Push-Token) rather than the query string specifically so it doesn't
land in nginx's default access-log line the way a query-string secret
would (nginx's default log format captures the full request line,
including the query string, but not arbitrary custom headers).

Dependencies
------------

- Python 3.8+
- websockets >= 10 (same version floor as remotepower-webterm; already an
  accepted optional server dependency for this class of companion daemon)

On Debian/Ubuntu: apt install python3-websockets
On Fedora/RHEL:   dnf install python3-websockets
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

# v6.1.1: deliberately NOT a hard sys.exit()-on-missing-import at module
# scope (unlike remotepower-webterm.py's otherwise-identical pattern) --
# the auth/caching/nudge-dedup logic below is pure Python with no actual
# websockets dependency, and keeping this module importable without the
# optional library installed lets that logic be unit-tested directly
# (see tests/test_v611_push.py). The hard failure-with-install-instructions
# still happens, just deferred to main() -- actually RUNNING the daemon
# without websockets installed behaves exactly the same as before.
try:
    import websockets
    from websockets.exceptions import ConnectionClosed
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False
    ConnectionClosed = Exception   # placeholder so `except ConnectionClosed` below still parses

VERSION = '6.1.1'

DEFAULT_BIND_HOST = '127.0.0.1'
DEFAULT_BIND_PORT = 8766
DEFAULT_DATA_DIR = Path('/var/lib/remotepower')

POLL_INTERVAL_S = 2          # how often to check CMDS_FILE for connected devices
NUDGE_COOLDOWN_S = 30        # don't re-nudge the same still-pending work more than this often

log = logging.getLogger('push')


# ─── Device-token verification — ported from api.py's exact logic ───────────
# (see api.py's _hash_device_token / _device_token_ok docstrings — kept
# byte-for-byte identical here; a divergence would silently split which
# tokens the daemon accepts vs. what the main API accepts).

def _hash_device_token(raw):
    return hashlib.sha256(str(raw).encode()).hexdigest()


def _device_token_ok(dev, presented):
    if not presented or not isinstance(dev, dict):
        return False
    th = dev.get('token_hash')
    if th:
        return hmac.compare_digest(str(th), _hash_device_token(presented))
    legacy = dev.get('token', '')
    if legacy:
        return hmac.compare_digest(legacy, presented)
    return False


def _load_json(path):
    """Best-effort JSON read. Missing/corrupt file -> {} (never raises) --
    this daemon reads shared state the main API owns; a transient partial
    write (caught mid-rewrite) must not crash the daemon or drop every
    connected agent's auth for one bad read."""
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


# v6.1.1: how long a DB-backend device/command read is cached (no file mtime to
# invalidate on, so bound staleness by time instead — same intent as the
# mtime-keyed DeviceStore, just time-bounded).
DB_STORE_TTL_S = 5


def _find_cgi_bin():
    """Locate the server's cgi-bin dir (storage.py / storage_pg.py) across dev
    AND installed layouts. In the repo the daemon runs from server/push/ so the
    module sits at ../cgi-bin; but installed to /usr/local/bin the app code lives
    at /var/www/remotepower/cgi-bin (the make / AUR-server default) — the old
    __file__-relative guess resolved to /usr/local/cgi-bin and found nothing, so
    the daemon fell back to flat-file reads and stayed broken under Postgres.
    Honor RP_CGI_BIN, then probe the known install roots; return the first dir
    that actually contains storage.py (or None → flat-file fallback)."""
    candidates = []
    env = os.environ.get('RP_CGI_BIN', '').strip()
    if env:
        candidates.append(Path(env))
    candidates += [
        Path(__file__).resolve().parent.parent / 'cgi-bin',   # repo: server/push -> server/cgi-bin
        Path('/var/www/remotepower/cgi-bin'),                 # make / AUR-server default
        Path('/usr/share/webapps/remotepower/cgi-bin'),
        Path('/opt/remotepower/cgi-bin'),
    ]
    for c in candidates:
        try:
            if (c / 'storage.py').is_file():
                return c
        except OSError:
            continue
    return None


class StoreReader:
    """Backend-aware reader for the shared state the main API owns.

    v6.1.1 fix: under the default Postgres/SQLite backend (v6.1.0+) the shared
    ``*.json`` files do NOT exist on disk — they live in the DB. The daemon used
    to ``Path(...).read_text()`` them directly, so every read returned ``{}`` and
    EVERY device was rejected (4401): auth failed closed and the push channel was
    silently dead on the default backend. This delegates to the SAME storage
    layer the app uses (``storage``/``storage_pg``), chosen from the on-disk
    storage marker, and falls back to flat-file reads for the JSON backend (or if
    the storage modules can't be located next to the daemon)."""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.backend = 'json'
        self._mod = None
        try:
            cgi = _find_cgi_bin()
            if cgi is not None and str(cgi) not in sys.path:
                sys.path.insert(0, str(cgi))
            import storage as _st
            marker = _st.read_marker(self.data_dir) or {}
            self.backend = (marker.get('backend') or 'json').lower()
            if self.backend == 'sqlite':
                self._mod = _st
            elif self.backend == 'postgres':
                import storage_pg as _pg
                # The app sources the PG DSN from the marker file (api.py:
                # `marker.get('dsn')`), with env RP_PG_DSN winning if set — NOT
                # from api.env necessarily. Mirror that here or storage_pg has no
                # DSN and every read fails, so the daemon still can't authenticate
                # anyone. This makes the daemon self-configuring from the marker,
                # same as the app.
                _dsn = marker.get('dsn')
                if _dsn and not os.environ.get('RP_PG_DSN'):
                    _pg.configure_dsn(_dsn)
                self._mod = _pg
        except Exception as e:
            log.warning("push: storage backend detection failed (%s) — "
                        "falling back to flat-file reads", e)
            self.backend, self._mod = 'json', None

    def load(self, name):
        if self._mod is not None:
            try:
                return self._mod.load(self.data_dir / name) or {}
            except Exception as e:
                log.debug("push: storage.load(%s) failed: %s", name, e)
                return {}
        return _load_json(self.data_dir / name)

    def mtime(self, name):
        """File mtime for the JSON backend (drives DeviceStore cache busting);
        None under a DB backend (no file) so the store uses a short TTL reload."""
        if self._mod is not None:
            return None
        try:
            return (self.data_dir / name).stat().st_mtime
        except OSError:
            return None


class DeviceStore:
    """Cached read access to DEVICES_FILE, keyed on the file's own mtime --
    NOT a time-based TTL. Auth happens on every connection attempt, so this
    avoids re-parsing a potentially large file on every check, but a plain
    time-based TTL would leave a real window where a just-rotated (e.g.
    compromised-key response) token still authenticates against stale
    cached data, and a just-created device's token is wrongly rejected as
    unknown. `stat()` is cheap enough to call on every check (a handful of
    microseconds, far cheaper than the JSON parse it guards) -- only an
    actual mtime change triggers a re-parse, so staleness is bounded by
    "how fast the filesystem's mtime granularity is," not an arbitrary
    seconds-wide window."""

    def __init__(self, reader, name='devices.json'):
        self.reader = reader
        self.name = name
        self._devices = {}
        self._loaded_mtime = None
        self._loaded_at = 0.0

    def _refresh(self):
        mtime = self.reader.mtime(self.name)
        if mtime is None:
            # DB backend (no file mtime): reload on a short TTL. Bounded
            # staleness, same intent as the mtime path below.
            if time.monotonic() - self._loaded_at >= DB_STORE_TTL_S:
                self._devices = self.reader.load(self.name)
                self._loaded_at = time.monotonic()
            return
        if mtime != self._loaded_mtime:
            self._devices = self.reader.load(self.name)
            self._loaded_mtime = mtime

    def check_token(self, dev_id, presented):
        self._refresh()
        dev = self._devices.get(dev_id)
        return _device_token_ok(dev, presented)


def _pending_content_key(cmds_for_device):
    """A cheap fingerprint of a device's pending-command list, used only to
    decide whether newly-arrived work warrants an early re-nudge inside the
    cooldown window. Not a security boundary -- just dedup bookkeeping."""
    if not cmds_for_device:
        return None
    return (len(cmds_for_device), str(cmds_for_device[-1])[:200])


def _should_nudge(pending, last_nudge, now, cooldown_s=NUDGE_COOLDOWN_S):
    """Pure decision function for whether a connected device should get a
    wake nudge this tick. `pending` is that device's raw CMDS_FILE list;
    `last_nudge` is the (content_key, monotonic_ts) this device was last
    nudged with (or None if never). Returns the new (content_key, ts) tuple
    to record if a nudge should fire, else None. Split out from
    PushServer.poll_and_nudge so the decision logic is testable without any
    actual async I/O or websocket connection."""
    key = _pending_content_key(pending)
    if key is None:
        return None
    last_key, last_ts = last_nudge if last_nudge is not None else (None, 0.0)
    if key == last_key and now - last_ts < cooldown_s:
        return None
    return (key, now)


class PushServer:
    def __init__(self, reader):
        self.reader = reader
        self.devices = DeviceStore(reader, 'devices.json')
        self.connections = {}     # dev_id -> websocket
        self._last_nudge = {}     # dev_id -> (content_key, monotonic_ts)

    async def handler(self, websocket):
        dev_id, presented = self._extract_credentials(websocket)
        if not dev_id or not presented or not self.devices.check_token(dev_id, presented):
            log.warning("push: rejected connection (bad/missing device credentials)")
            await websocket.close(code=4401, reason='unauthorized')
            return
        # v6.1.1: a device reconnecting (agent restart, network blip) replaces
        # its own prior entry -- only one live connection per device makes
        # sense, and closing the old one is cleaner than leaking it.
        old = self.connections.get(dev_id)
        if old is not None and old is not websocket:
            try:
                await old.close(code=4409, reason='superseded by a new connection')
            except Exception:
                pass
        self.connections[dev_id] = websocket
        log.info("push: %s connected (%d total)", dev_id, len(self.connections))
        try:
            async for _msg in websocket:
                pass   # receive-only channel; any inbound message is ignored
        except ConnectionClosed:
            pass
        finally:
            if self.connections.get(dev_id) is websocket:
                del self.connections[dev_id]
            log.info("push: %s disconnected (%d total)", dev_id, len(self.connections))

    @staticmethod
    def _extract_credentials(websocket):
        try:
            path = websocket.request.path
        except AttributeError:
            path = getattr(websocket, 'path', '')
        import urllib.parse
        qs = urllib.parse.urlparse(path).query
        dev_id = (urllib.parse.parse_qs(qs).get('device_id', [''])[0] or '').strip()
        try:
            headers = websocket.request.headers
        except AttributeError:
            headers = getattr(websocket, 'request_headers', {})
        token = (headers.get('X-RP-Push-Token', '') or '').strip()
        return dev_id, token

    async def poll_and_nudge(self):
        """Background loop: for every currently-connected device with
        pending work in CMDS_FILE, send a wake nudge -- at most once per
        NUDGE_COOLDOWN_S unless the pending content actually changed."""
        while True:
            await asyncio.sleep(POLL_INTERVAL_S)
            if not self.connections:
                continue
            cmds = self.reader.load('commands.json')
            now = time.monotonic()
            for dev_id, ws in list(self.connections.items()):
                decision = _should_nudge(cmds.get(dev_id) or [],
                                         self._last_nudge.get(dev_id), now)
                if decision is None:
                    continue
                try:
                    await ws.send(json.dumps({'type': 'wake'}))
                    self._last_nudge[dev_id] = decision
                except Exception as e:
                    log.debug("push: nudge to %s failed: %s", dev_id, e)


async def main_async(args):
    reader = StoreReader(args.data_dir)
    server = PushServer(reader)
    log.info("remotepower-push v%s listening on %s:%d (data_dir=%s, backend=%s)",
             VERSION, args.host, args.port, args.data_dir, reader.backend)

    poll_task = asyncio.create_task(server.poll_and_nudge())
    try:
        async with websockets.serve(server.handler, args.host, args.port,
                                     ping_interval=20, ping_timeout=20,
                                     max_size=4 * 1024):
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, stop.set)
                except NotImplementedError:
                    pass   # Windows
            await stop.wait()
            log.info("shutting down")
    finally:
        poll_task.cancel()


def main():
    if not _WS_AVAILABLE:
        print("ERROR: websockets library not installed.", file=sys.stderr)
        print("  Debian/Ubuntu: apt install python3-websockets", file=sys.stderr)
        print("  Fedora/RHEL:   dnf install python3-websockets", file=sys.stderr)
        print("  pip:           pip install 'websockets>=10'", file=sys.stderr)
        sys.exit(2)

    p = argparse.ArgumentParser(description='RemotePower agent push (wake-nudge) daemon')
    p.add_argument('--host', default=DEFAULT_BIND_HOST)
    p.add_argument('--port', type=int, default=DEFAULT_BIND_PORT)
    p.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR))
    p.add_argument('--verbose', action='store_true')
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s')

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
