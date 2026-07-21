#!/usr/bin/env python3
"""RemotePower — agentless NetFlow / IPFIX receiver (v6.3.1).

The network-flow sibling of remotepower-syslogd. Routers, firewalls and L3
switches can't run an agent but almost all export NetFlow/IPFIX. This sidecar
listens for UDP flow-export datagrams, maps each EXPORTER source IP to the
enrolled device with that IP, aggregates the flow records per exporter over a
short window (top talkers by bytes, top conversations, protocol breakdown),
and forwards the compact aggregate over loopback HTTP to the per-device ingest
endpoint (`POST /api/flow/in/<token>`). Parsing, storage and the UI all live in
api.py — this daemon is a thin network shim, exactly like the syslog one.

Requirements for an exporter to be accepted (read via the same backend-aware
StoreReader the syslog/push daemons use — never raw file reads):
  * an enrolled device whose `ip` equals the datagram's source address, and
  * an enabled inbound-webhook token with kind='flow' pinned to that device.
Unknown exporters are dropped and logged at most once per 10 min each.

Aggregation: raw flow records accumulate per exporter and flush every FLUSH_S
seconds (or when a record cap is hit) as ONE POST of the top-N rollup, not one
POST per datagram — a busy router emits thousands of flows/s.

Environment (the systemd unit sets these; defaults suit a standard install):
  RP_FLOW_BIND        listen address   (default 0.0.0.0:2055 — the de-facto
                      NetFlow port; unprivileged)
  RP_FLOW_SERVER_URL  loopback API base (default http://127.0.0.1:8090)
  RP_DATA_DIR         shared data dir   (default /var/lib/remotepower)

sFlow v5 (packet sampling) IS parsed too — flow_parse dissects the sampled
headers (Ethernet -> IPv4/IPv6 -> TCP/UDP) and scales by the sampling rate.
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

log = logging.getLogger('remotepower-flowd')
logging.basicConfig(level=logging.INFO,
                    format='[remotepower-flowd] %(levelname)s %(message)s')

DATA_DIR = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
SERVER_URL = (os.environ.get('RP_FLOW_SERVER_URL')
              or 'http://127.0.0.1:8090').rstrip('/')
BIND = os.environ.get('RP_FLOW_BIND', '0.0.0.0:2055')

MAP_TTL_S = 30
FLUSH_S = 10.0            # aggregate window per exporter
MAX_RECORDS = 20000       # records held per exporter before a forced flush
MAX_LINE = 65535          # UDP datagram ceiling
TOP_N = 20                # top talkers/flows reported per flush
UNKNOWN_LOG_EVERY_S = 600


def _find_cgi_bin():
    here = Path(__file__).resolve()
    for base in (here.parent.parent, here.parent.parent.parent):
        for sub in ('cgi-bin', 'server/cgi-bin'):
            cand = base / sub
            if (cand / 'storage.py').exists():
                return cand
    return None


# flow_parse lives next to this daemon.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import flow_parse  # noqa: E402


class StoreReader:
    """Backend-aware reader — identical pattern/reason to the syslog daemon's:
    under SQLite/Postgres the *.json stores are DB rows, so a raw read returns
    {} and every exporter is silently rejected. Delegate to the app's storage
    layer; flat-file fallback for the JSON backend."""

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
    """exporter IP → per-device flow ingest token, TTL-refreshed."""

    def __init__(self, reader):
        self.reader = reader
        self._map = {}
        self._at = 0.0

    def _refresh(self):
        devices = self.reader.load('devices.json') or {}
        hooks = self.reader.load('inbound_webhooks.json') or {}
        by_dev = {}
        for t in hooks.get('tokens', []):
            if (t.get('kind') == 'flow' and t.get('enabled', True)
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
                log.debug('source-map refresh failed: %s', e)
        return self._map.get(src_ip)


def _aggregate(records):
    """Roll raw flow records into a compact, bounded summary:
      { total_bytes, total_packets, flows, talkers:[{ip,bytes,pkts}],
        conversations:[{src,dst,dport,proto,bytes,pkts}], protos:{name:bytes} }
    Only the top-N by bytes are kept, so the POST stays small no matter how
    many raw flows arrived."""
    talkers = {}            # ip -> [bytes, pkts]
    convs = {}              # (src,dst,dport,proto) -> [bytes, pkts]
    protos = {}             # proto-num -> bytes
    total_b = total_p = 0
    for r in records:
        b = int(r.get('bytes') or 0)
        p = int(r.get('packets') or 0)
        total_b += b
        total_p += p
        for ip in (r.get('src'), r.get('dst')):
            if ip:
                t = talkers.setdefault(ip, [0, 0])
                t[0] += b
                t[1] += p
        key = (r.get('src'), r.get('dst'), int(r.get('dport') or 0),
               int(r.get('proto') or 0))
        c = convs.setdefault(key, [0, 0])
        c[0] += b
        c[1] += p
        protos[int(r.get('proto') or 0)] = protos.get(int(r.get('proto') or 0), 0) + b
    _pname = {1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 58: 'icmp6'}
    top_talkers = sorted(talkers.items(), key=lambda kv: -kv[1][0])[:TOP_N]
    top_convs = sorted(convs.items(), key=lambda kv: -kv[1][0])[:TOP_N]
    return {
        'total_bytes': total_b, 'total_packets': total_p, 'flows': len(records),
        'talkers': [{'ip': ip, 'bytes': bp[0], 'pkts': bp[1]} for ip, bp in top_talkers],
        'conversations': [{'src': k[0], 'dst': k[1], 'dport': k[2], 'proto': k[3],
                           'bytes': bp[0], 'pkts': bp[1]} for k, bp in top_convs],
        'protos': {(_pname.get(pn, str(pn))): by for pn, by in
                   sorted(protos.items(), key=lambda kv: -kv[1])[:12]},
    }


def _post(token, agg):
    url = f'{SERVER_URL}/api/flow/in/{token}'
    body = json.dumps(agg).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={'Content-Type': 'application/json'},
                                 method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        return True
    except Exception as e:
        log.warning('flow POST failed for token …%s: %s', str(token)[-6:], e)
        return False


def serve():
    host, _, port = BIND.rpartition(':')
    host = host or '0.0.0.0'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    log.info('listening for NetFlow/IPFIX on %s:%s → %s', host, port, SERVER_URL)

    reader = StoreReader(DATA_DIR)
    smap = SourceMap(reader)
    templates = {}                      # exporter_ip -> flow_parse.TemplateCache
    buckets = {}                        # exporter_ip -> list of flow records
    last_flush = time.monotonic()
    unknown_seen = {}

    def flush():
        for src_ip, recs in list(buckets.items()):
            if not recs:
                continue
            token = smap.token_for(src_ip)
            if not token:
                continue
            _post(token, _aggregate(recs))
            buckets[src_ip] = []

    while True:
        # Wake at least every FLUSH_S to flush, even with no traffic.
        timeout = max(0.1, FLUSH_S - (time.monotonic() - last_flush))
        r, _, _ = select.select([sock], [], [], timeout)
        if r:
            try:
                data, addr = sock.recvfrom(MAX_LINE)
            except OSError:
                continue
            src_ip = addr[0]
            token = smap.token_for(src_ip)
            if not token:
                now = time.monotonic()
                if now - unknown_seen.get(src_ip, 0) > UNKNOWN_LOG_EVERY_S:
                    log.info('flow from unmapped exporter %s dropped (enrol it + '
                             'add a kind=flow inbound token)', src_ip)
                    unknown_seen[src_ip] = now
                continue
            tc = templates.setdefault(src_ip, flow_parse.TemplateCache())
            recs = flow_parse.parse(data, src_ip, tc)
            if recs:
                buf = buckets.setdefault(src_ip, [])
                buf.extend(recs)
                if len(buf) >= MAX_RECORDS:
                    token2 = smap.token_for(src_ip)
                    if token2:
                        _post(token2, _aggregate(buf))
                    buckets[src_ip] = []
        if time.monotonic() - last_flush >= FLUSH_S:
            flush()
            last_flush = time.monotonic()


def main():
    try:
        serve()
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        log.error('fatal: %s', e)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
