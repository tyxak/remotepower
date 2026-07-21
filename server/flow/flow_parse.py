#!/usr/bin/env python3
"""RemotePower — NetFlow / IPFIX parsing (pure, stdlib, unit-testable).

Turns a raw UDP flow-export datagram into a list of normalised flow records:

    {'src','dst','sport','dport','proto','bytes','packets'}

Supported exports (the ones routers/firewalls actually emit):
  * NetFlow v5   — fixed 48-byte records, no templates (simplest, still common
                   on older/edge gear).
  * NetFlow v9   — template-based; templates (field-id→length) arrive in their
                   own FlowSets and are cached PER EXPORTER + source-id, then
                   applied to data FlowSets. A data record whose template hasn't
                   been seen yet is skipped (normal on startup — the exporter
                   resends templates periodically).
  * IPFIX (v10)  — same template model as v9 with a slightly different header;
                   handled by the same field-map logic.
  * sFlow v5     — a different, packet-SAMPLING protocol: it ships sampled raw
                   packet headers rather than flow aggregates. We dissect each
                   sampled header (Ethernet → IPv4/IPv6 → TCP/UDP) and scale
                   bytes/packets by the sampling rate to estimate the flow's
                   contribution, yielding the same normalised record shape.
                   Counter samples are skipped.

The daemon aggregates whatever this returns.

Templates are stateful, so the caller holds a TemplateCache and passes it in.
Nothing here does IO or raises on malformed input — a bad datagram yields [].
"""

import ipaddress
import struct

# NetFlow v9 / IPFIX field type ids we care about (RFC 3954 / RFC 7011).
_IN_BYTES, _IN_PKTS = 1, 2
_PROTOCOL = 4
_L4_SRC_PORT, _L4_DST_PORT = 7, 11
_IPV4_SRC, _IPV4_DST = 8, 12
_IPV6_SRC, _IPV6_DST = 27, 28


class TemplateCache:
    """Per-exporter template store: (exporter_ip, source_id, template_id) →
    list of (field_type, field_length). Bounded so a hostile exporter can't
    grow it without limit."""

    _MAX = 4096

    def __init__(self):
        self._t = {}

    def put(self, key, fields):
        if len(self._t) >= self._MAX:
            self._t.clear()   # crude but bounded; templates re-arrive
        self._t[key] = fields

    def get(self, key):
        return self._t.get(key)


def _u(data, off, length):
    """Big-endian unsigned int of `length` bytes at `off`; 0 if out of range."""
    if off + length > len(data) or length <= 0:
        return 0
    v = 0
    for i in range(length):
        v = (v << 8) | data[off + i]
    return v


def parse(data, exporter_ip, templates):
    """Parse one datagram. Returns a list of normalised flow dicts (possibly
    empty). `templates` is a TemplateCache (mutated for v9/IPFIX).

    Disambiguation: NetFlow v5 begins 0x0005 (u16 version); sFlow v5 begins
    0x00000005 (u32 version). So a leading 4 zero-then-5 bytes is sFlow, and a
    leading 0x0005 is NetFlow v5 — they don't collide."""
    if not data or len(data) < 4:
        return []
    try:
        if data[:4] == b'\x00\x00\x00\x05':
            return _parse_sflow(data)
        version = _u(data, 0, 2)
        if version == 5:
            return _parse_v5(data)
        if version == 9:
            return _parse_v9(data, exporter_ip, templates, ipfix=False)
        if version == 10:
            return _parse_v9(data, exporter_ip, templates, ipfix=True)
    except Exception:
        return []
    return []


def _parse_v5(data):
    # Header 24 bytes; count at offset 2. Records are 48 bytes each.
    count = _u(data, 2, 2)
    out = []
    off = 24
    for _ in range(min(count, 1000)):
        if off + 48 > len(data):
            break
        src = str(ipaddress.IPv4Address(data[off:off + 4]))
        dst = str(ipaddress.IPv4Address(data[off + 4:off + 8]))
        pkts = _u(data, off + 16, 4)
        octets = _u(data, off + 20, 4)
        sport = _u(data, off + 32, 2)
        dport = _u(data, off + 34, 2)
        proto = _u(data, off + 38, 1)
        out.append({'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
                    'proto': proto, 'bytes': octets, 'packets': pkts})
        off += 48
    return out


def _parse_v9(data, exporter_ip, templates, ipfix):
    # v9 header: version(2) count(2) uptime(4) unixsecs(4) seq(4) source_id(4) = 20
    # ipfix header: version(2) length(2) exporttime(4) seq(4) domain(4)      = 16
    if ipfix:
        total_len = _u(data, 2, 2) or len(data)
        source_id = _u(data, 12, 4)
        off = 16
        end = min(total_len, len(data))
        # IPFIX template FlowSet id = 2; data FlowSets id >= 256.
        tmpl_setid = 2
    else:
        source_id = _u(data, 16, 4)
        off = 20
        end = len(data)
        tmpl_setid = 0   # v9 template FlowSet id = 0

    out = []
    guard = 0
    while off + 4 <= end and guard < 512:
        guard += 1
        set_id = _u(data, off, 2)
        set_len = _u(data, off + 2, 2)
        if set_len < 4 or off + set_len > end:
            break
        body_off = off + 4
        body_end = off + set_len
        if set_id == tmpl_setid:
            _read_templates(data, body_off, body_end, exporter_ip, source_id, templates)
        elif set_id > 255:
            fields = templates.get((exporter_ip, source_id, set_id))
            if fields:
                out.extend(_read_data_records(data, body_off, body_end, fields))
        off = body_end
    return out


def _read_templates(data, off, end, exporter_ip, source_id, templates):
    while off + 4 <= end:
        template_id = _u(data, off, 2)
        field_count = _u(data, off + 2, 2)
        off += 4
        fields = []
        for _ in range(min(field_count, 128)):
            if off + 4 > end:
                return
            ftype = _u(data, off, 2)
            flen = _u(data, off + 2, 2)
            # Enterprise fields (high bit set) carry a 4-byte PEN — skip its id
            # space but keep the length so the record offset stays aligned.
            if ftype & 0x8000:
                off += 4   # skip the enterprise number
            fields.append((ftype & 0x7fff, flen))
            off += 4
        if fields and template_id >= 256:
            templates.put((exporter_ip, source_id, template_id), fields)


def _read_data_records(data, off, end, fields):
    rec_len = sum(fl for _ft, fl in fields)
    if rec_len <= 0:
        return []
    out = []
    while off + rec_len <= end:
        rec = {}
        p = off
        for ftype, flen in fields:
            rec[ftype] = data[p:p + flen]
            p += flen
        out.append(_normalise_v9(rec))
        off += rec_len
    return [r for r in out if r]


def _ip(raw):
    try:
        if len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
    except Exception:
        pass
    return ''


def _int(raw):
    v = 0
    for b in raw:
        v = (v << 8) | b
    return v


def _normalise_v9(rec):
    src = _ip(rec.get(_IPV4_SRC) or rec.get(_IPV6_SRC) or b'')
    dst = _ip(rec.get(_IPV4_DST) or rec.get(_IPV6_DST) or b'')
    if not src or not dst:
        return None
    return {
        'src': src, 'dst': dst,
        'sport': _int(rec.get(_L4_SRC_PORT) or b''),
        'dport': _int(rec.get(_L4_DST_PORT) or b''),
        'proto': _int(rec.get(_PROTOCOL) or b''),
        'bytes': _int(rec.get(_IN_BYTES) or b''),
        'packets': _int(rec.get(_IN_PKTS) or b''),
    }


# ── sFlow v5 (packet-sampling) ───────────────────────────────────────────────
# sFlow is fundamentally different from NetFlow: instead of flow aggregates it
# ships SAMPLED PACKET HEADERS. We dissect each sampled header (Ethernet →
# IPv4/IPv6 → TCP/UDP) and scale bytes/packets by the sampling rate to estimate
# the flow's contribution — the same normalised {src,dst,sport,dport,proto,
# bytes,packets} shape the aggregator already consumes. Counter samples are
# skipped. Only the raw-packet-header record format (data_format 1) is read;
# everything is bounds-checked and never raises.

_SFLOW_MAX_SAMPLES = 512
_SFLOW_MAX_RECORDS = 64


def _parse_sflow(data):
    # header: version(4) agent_addr_type(4) agent_addr(4|16) sub_agent(4)
    #         seq(4) uptime(4) num_samples(4)
    off = 4
    addr_type = _u(data, off, 4)
    off += 4
    off += 16 if addr_type == 2 else 4        # IPv6 agent addr is 16 bytes
    off += 4 + 4 + 4                           # sub-agent, seq, uptime
    num_samples = _u(data, off, 4)
    off += 4
    out = []
    for _ in range(min(num_samples, _SFLOW_MAX_SAMPLES)):
        if off + 8 > len(data):
            break
        sample_type = _u(data, off, 4)          # enterprise(20)|format(12)
        sample_len = _u(data, off + 4, 4)
        body = off + 8
        end = body + sample_len
        if sample_len <= 0 or end > len(data):
            break
        fmt = sample_type & 0xfff
        if fmt in (1, 3):                        # flow_sample / expanded
            out.extend(_parse_sflow_flow_sample(data, body, end, expanded=(fmt == 3)))
        off = end
    return out


def _parse_sflow_flow_sample(data, off, end, expanded):
    # flow_sample: seq(4) source_id(4|8 expanded) sampling_rate(4) sample_pool(4)
    #              drops(4) input(4|8) output(4|8) num_records(4) records...
    off += 4                                     # sequence
    off += 8 if expanded else 4                  # source id
    rate = _u(data, off, 4) or 1
    off += 4 + 4 + 4                             # rate, pool, drops
    off += 16 if expanded else 8                 # input + output ifIndex
    num_records = _u(data, off, 4)
    off += 4
    out = []
    for _ in range(min(num_records, _SFLOW_MAX_RECORDS)):
        if off + 8 > end:
            break
        data_format = _u(data, off, 4) & 0xfff
        rec_len = _u(data, off + 4, 4)
        rbody = off + 8
        rend = rbody + rec_len
        if rec_len <= 0 or rend > end:
            break
        if data_format == 1:                     # raw packet header
            rec = _parse_sflow_raw_header(data, rbody, rend, rate)
            if rec:
                out.append(rec)
        off = rend
    return out


def _parse_sflow_raw_header(data, off, end, rate):
    # raw header: header_protocol(4) frame_length(4) stripped(4) header_length(4)
    #             header bytes...
    header_proto = _u(data, off, 4)
    frame_length = _u(data, off + 4, 4)
    header_length = _u(data, off + 12, 4)
    hoff = off + 16
    hend = min(hoff + header_length, end)
    if header_proto != 1:                        # 1 = ISO88023/Ethernet
        return None
    rec = _dissect_ethernet(data, hoff, hend)
    if not rec:
        return None
    # sFlow samples 1-in-`rate` packets; scale to estimate the real volume.
    rec['bytes'] = max(frame_length, 1) * rate
    rec['packets'] = rate
    return rec


def _dissect_ethernet(data, off, end):
    if off + 14 > end:
        return None
    ethertype = _u(data, off + 12, 2)
    p = off + 14
    # up to two 802.1Q VLAN tags
    for _ in range(2):
        if ethertype == 0x8100 and p + 4 <= end:
            ethertype = _u(data, p + 2, 2)
            p += 4
        else:
            break
    if ethertype == 0x0800:
        return _dissect_ipv4(data, p, end)
    if ethertype == 0x86dd:
        return _dissect_ipv6(data, p, end)
    return None


def _dissect_ipv4(data, off, end):
    if off + 20 > end:
        return None
    ihl = (data[off] & 0x0f) * 4
    if ihl < 20:
        return None
    proto = data[off + 9]
    src = _ip(data[off + 12:off + 16])
    dst = _ip(data[off + 16:off + 20])
    sport, dport = _l4_ports(data, off + ihl, end, proto)
    return {'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
            'proto': proto, 'bytes': 0, 'packets': 0}


def _dissect_ipv6(data, off, end):
    if off + 40 > end:
        return None
    proto = data[off + 6]                         # next-header (no ext-hdr walk)
    src = _ip(data[off + 8:off + 24])
    dst = _ip(data[off + 24:off + 40])
    sport, dport = _l4_ports(data, off + 40, end, proto)
    return {'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
            'proto': proto, 'bytes': 0, 'packets': 0}


def _l4_ports(data, off, end, proto):
    if proto in (6, 17) and off + 4 <= end:       # TCP / UDP
        return _u(data, off, 2), _u(data, off + 2, 2)
    return 0, 0


# Convenience: build a NetFlow v5 datagram (used by the test suite + docs).
def build_v5(records):
    """records: list of (src_ip, dst_ip, sport, dport, proto, octets, pkts)."""
    hdr = struct.pack('!HHIIIIBBH', 5, len(records), 0, 0, 0, 0, 0, 0, 0)
    body = b''
    for (src, dst, sport, dport, proto, octets, pkts) in records:
        body += ipaddress.IPv4Address(src).packed
        body += ipaddress.IPv4Address(dst).packed
        body += ipaddress.IPv4Address('0.0.0.0').packed   # nexthop
        body += struct.pack('!HH', 0, 0)                  # snmp in/out
        body += struct.pack('!II', pkts, octets)          # dPkts, dOctets
        body += struct.pack('!II', 0, 0)                  # first/last uptime
        body += struct.pack('!HH', sport, dport)          # ports
        body += struct.pack('!BBBBHHBBH', 0, 0, proto, 0, 0, 0, 0, 0, 0)
    return hdr + body
