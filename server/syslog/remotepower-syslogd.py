#!/usr/bin/env python3
"""RemotePower — agentless syslog receiver (v6.3.0).

Network appliances (switches, firewalls, printers, NAS boxes) can't run an
agent but can all speak syslog. This sidecar listens for UDP syslog
datagrams, maps each SOURCE IP to the enrolled device with that IP, and
forwards the raw lines over loopback HTTP to the EXISTING per-device ingest
endpoint (`POST /api/syslog/in/<token>`) — so parsing, the log_watch buffer,
log-alert rule evaluation and token accounting all stay in ONE place
(api.py's handler), and this daemon stays a thin network shim.

Requirements for a source to be accepted (both readable via the same
backend-aware StoreReader the push daemon uses — never raw file reads):
  * an enrolled device whose `ip` equals the datagram's source address, and
  * an enabled inbound-webhook token with kind='syslog' pinned to that
    device (Settings → Integrations → Inbound webhooks).
Unknown sources are dropped and logged at most once per 10 minutes each.

Batching: lines accumulate per source and flush every FLUSH_S seconds or
MAX_BATCH lines, whichever first — one POST per burst, not per datagram.

Environment (systemd unit sets these; defaults suit a standard install):
  RP_SYSLOG_BIND        listen address        (default 0.0.0.0:5514 — an
                        unprivileged port; to use classic 514/udp give the
                        unit AmbientCapabilities=CAP_NET_BIND_SERVICE)
  RP_SYSLOG_SERVER_URL  loopback API base     (default http://127.0.0.1:8090)
  RP_DATA_DIR           shared data dir       (default /var/lib/remotepower)
"""

import json
import logging
import os
import select
import socket
import sys
import time
import urllib.request
from pathlib import Path

log = logging.getLogger('remotepower-syslogd')
logging.basicConfig(level=logging.INFO,
                    format='[remotepower-syslogd] %(levelname)s %(message)s')

DATA_DIR = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
SERVER_URL = (os.environ.get('RP_SYSLOG_SERVER_URL')
              or 'http://127.0.0.1:8090').rstrip('/')
BIND = os.environ.get('RP_SYSLOG_BIND', '0.0.0.0:5514')

MAP_TTL_S = 30          # how long the ip→token map is trusted before re-read
FLUSH_S = 2.0           # max seconds a line waits before its batch is POSTed
MAX_BATCH = 200         # lines per source per POST (endpoint caps server-side)
MAX_LINE = 8192         # bytes per datagram we accept
UNKNOWN_LOG_EVERY_S = 600


def _find_cgi_bin():
    """Locate server/cgi-bin next to this daemon (same layout as the repo /
    the deployed tree), so the storage modules can be imported."""
    here = Path(__file__).resolve()
    for base in (here.parent.parent, here.parent.parent.parent):
        cand = base / 'cgi-bin'
        if (cand / 'storage.py').exists():
            return cand
        cand = base / 'server' / 'cgi-bin'
        if (cand / 'storage.py').exists():
            return cand
    return None


class StoreReader:
    """Backend-aware reader — same pattern (and reason) as the push daemon's:
    under the default SQLite/Postgres backend the ``*.json`` stores are DB
    rows, not files, so a raw read would return {} and every source would be
    silently rejected. Delegates to the app's own storage layer, flat-file
    fallback for the JSON backend."""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self._mod = None
        try:
            cgi = _find_cgi_bin()
            if cgi is not None and str(cgi) not in sys.path:
                sys.path.insert(0, str(cgi))
            import storage as _st
            marker = _st.read_marker(self.data_dir) or {}
            backend = (marker.get('backend') or 'json').lower()
            if backend == 'sqlite':
                self._mod = _st
            elif backend == 'postgres':
                import storage_pg as _pg
                _dsn = marker.get('dsn')
                if _dsn and not os.environ.get('RP_PG_DSN'):
                    _pg.configure_dsn(_dsn)
                self._mod = _pg
        except Exception as e:
            log.warning('storage backend detection failed (%s) — flat-file reads', e)
            self._mod = None

    def load(self, name):
        if self._mod is not None:
            try:
                return self._mod.load(self.data_dir / name) or {}
            except Exception as e:
                log.debug('storage.load(%s) failed: %s', name, e)
                return {}
        try:
            return json.loads((self.data_dir / name).read_text()) or {}
        except (OSError, ValueError):
            return {}


class SourceMap:
    """source IP → per-device syslog ingest token, TTL-refreshed."""

    def __init__(self, reader):
        self.reader = reader
        self._map = {}
        self._at = 0.0

    def _refresh(self):
        devices = self.reader.load('devices.json') or {}
        hooks = self.reader.load('inbound_webhooks.json') or {}
        by_dev = {}
        for t in hooks.get('tokens', []):
            if (t.get('kind') == 'syslog' and t.get('enabled', True)
                    and t.get('scope_device_id') and t.get('token')):
                by_dev[t['scope_device_id']] = t['token']
        m = {}
        for dev_id, dev in devices.items():
            ip = (dev or {}).get('ip')
            tok = by_dev.get(dev_id)
            if ip and tok:
                m[str(ip)] = tok
        self._map = m
        self._at = time.monotonic()

    def token_for(self, src_ip):
        if time.monotonic() - self._at >= MAP_TTL_S:
            try:
                self._refresh()
            except Exception as e:
                log.warning('source-map refresh failed: %s', e)
                self._at = time.monotonic()   # don't hot-loop a broken refresh
        return self._map.get(src_ip)


def post_lines(token, lines, server_url=SERVER_URL, timeout=10):
    """One batch → the existing ingest endpoint. Returns True on 2xx."""
    req = urllib.request.Request(
        f'{server_url}/api/syslog/in/{token}',
        data=json.dumps({'lines': lines}).encode(),
        headers={'Content-Type': 'application/json',
                 'User-Agent': 'RemotePower-Syslogd'},
        method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        log.warning('forward failed (%d lines): %s', len(lines), e)
        return False


def serve(bind=BIND, reader=None, once=False):
    host, _, port = bind.rpartition(':')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host or '0.0.0.0', int(port)))
    sock.setblocking(False)
    log.info('listening on udp/%s → %s', bind, SERVER_URL)
    srcmap = SourceMap(reader or StoreReader(DATA_DIR))
    pending = {}          # src_ip -> [lines]
    first_at = {}         # src_ip -> monotonic time of oldest pending line
    unknown_logged = {}   # src_ip -> monotonic time last complained

    def flush(src):
        lines = pending.pop(src, None)
        first_at.pop(src, None)
        if not lines:
            return
        tok = srcmap.token_for(src)
        if not tok:
            now = time.monotonic()
            if now - unknown_logged.get(src, 0) >= UNKNOWN_LOG_EVERY_S:
                unknown_logged[src] = now
                log.info('dropping syslog from unknown source %s (no enrolled '
                         'device with this IP + a syslog inbound token)', src)
            return
        post_lines(tok, lines)

    while True:
        ready, _, _ = select.select([sock], [], [], 0.5)
        if ready:
            try:
                data, (src, _sport) = sock.recvfrom(MAX_LINE)
            except OSError:
                continue
            text = data.decode('utf-8', errors='replace')
            lines = [ln.strip() for ln in text.split('\n') if ln.strip()]
            if lines:
                buf = pending.setdefault(src, [])
                first_at.setdefault(src, time.monotonic())
                buf.extend(lines)
                if len(buf) >= MAX_BATCH:
                    flush(src)
        now = time.monotonic()
        for src in [s for s, t0 in first_at.items() if now - t0 >= FLUSH_S]:
            flush(src)
        if once and not ready:
            for src in list(pending):
                flush(src)
            return


def main():
    try:
        serve()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
