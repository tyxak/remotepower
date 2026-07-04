"""W6-41: minimal, dependency-free MaxMind DB (.mmdb) reader.

RemotePower stays stdlib-only, so this is a compact pure-python reader for the
MaxMind DB binary format — enough to look up a country/ASN for an IP from an
operator-supplied GeoLite2-Country / GeoLite2-ASN file. No network, no external
package (the `geoip2`/`maxminddb` libs are NOT vendored).

It implements the two pieces of the format spec we need:
  * the binary search tree (record size 24/28/32 bits), walked bit-by-bit over
    the IP's bytes, and
  * the data-section decoder (map / utf8 / uint / pointer / array / …).

Everything is defensive: a malformed or absent file yields ``None`` from
``lookup`` rather than raising, so the caller degrades to "no geo data".

Usage:
    r = Reader('/var/lib/GeoLite2-Country.mmdb')
    r.lookup('8.8.8.8')  -> {'country': {'iso_code': 'US', ...}, ...} or None
"""
import ipaddress
import struct

_METADATA_MARKER = b'\xab\xcd\xefMaxMind.com'
_DATA_SECTION_SEPARATOR = 16   # bytes of \x00 between tree and data section


class Reader:
    """Read-only MMDB reader. Construct once (parses metadata) and reuse."""

    def __init__(self, path):
        with open(path, 'rb') as fh:
            self._buf = fh.read()
        meta_start = self._buf.rfind(_METADATA_MARKER)
        if meta_start < 0:
            raise ValueError('not a MaxMind DB file (no metadata marker)')
        self._decoder_meta_base = meta_start + len(_METADATA_MARKER)
        meta, _ = self._decode(self._decoder_meta_base, self._decoder_meta_base)
        self.node_count = int(meta.get('node_count', 0))
        self.record_size = int(meta.get('record_size', 0))
        self.ip_version = int(meta.get('ip_version', 6))
        if self.record_size not in (24, 28, 32):
            raise ValueError(f'unsupported record_size {self.record_size}')
        self._node_bytes = self.record_size * 2 // 8
        # The data section starts after the tree + a 16-byte separator.
        self._data_start = self.node_count * self._node_bytes + _DATA_SECTION_SEPARATOR

    # ── search tree ─────────────────────────────────────────────────────────
    def _read_node(self, node, index):
        base = node * self._node_bytes
        rs = self.record_size
        if rs == 24:
            off = base + index * 3
            return (self._buf[off] << 16) | (self._buf[off + 1] << 8) | self._buf[off + 2]
        if rs == 28:
            if index == 0:
                off = base
                mid = self._buf[base + 3]
                return ((mid & 0xF0) << 20) | (self._buf[off] << 16) \
                    | (self._buf[off + 1] << 8) | self._buf[off + 2]
            off = base + 4
            mid = self._buf[base + 3]
            return ((mid & 0x0F) << 24) | (self._buf[off] << 16) \
                | (self._buf[off + 1] << 8) | self._buf[off + 2]
        # 32-bit
        off = base + index * 4
        return struct.unpack('>I', self._buf[off:off + 4])[0]

    def _find_address(self, ip):
        addr = ipaddress.ip_address(ip)
        bits = addr.packed
        # An IPv4 address in a v6 database is looked up as ::ffff:a.b.c.d — but
        # GeoLite2 stores v4 under ::/96 so walking the 128-bit form works when
        # the tree is v6. For a v4-only DB, walk the 32-bit form directly.
        if addr.version == 4 and self.ip_version == 6:
            bits = ipaddress.ip_address('::ffff:' + str(addr)).packed
        node = 0
        total_bits = len(bits) * 8
        for i in range(total_bits):
            if node >= self.node_count:
                break
            byte = bits[i >> 3]
            bit = (byte >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None        # empty (no data for this address)
        if node > self.node_count:
            # Resolve the record → an absolute offset into the data section.
            # (spec: record - node_count + search_tree_size)
            return (node - self.node_count) + self.node_count * self._node_bytes
        return None

    # ── data section decoder ────────────────────────────────────────────────
    def _decode(self, offset, base):
        ctrl = self._buf[offset]
        offset += 1
        dtype = ctrl >> 5
        if dtype == 1:      # pointer
            return self._decode_pointer(ctrl, offset, base)
        size = ctrl & 0x1F
        if size >= 29:
            if size == 29:
                size = 29 + self._buf[offset]
                offset += 1
            elif size == 30:
                size = 285 + struct.unpack('>H', self._buf[offset:offset + 2])[0]
                offset += 2
            else:   # 31
                size = 65821 + int.from_bytes(self._buf[offset:offset + 3], 'big')
                offset += 3
        if dtype == 0:      # extended type
            dtype = 7 + self._buf[offset]
            offset += 1
        return self._decode_by_type(dtype, size, offset, base)

    def _decode_pointer(self, ctrl, offset, base):
        psize = (ctrl >> 3) & 0x3
        p0 = ctrl & 0x7
        if psize == 0:
            ptr = (p0 << 8) | self._buf[offset]
            offset += 1
        elif psize == 1:
            ptr = (p0 << 16) | struct.unpack('>H', self._buf[offset:offset + 2])[0]
            offset += 2
            ptr += 2048
        elif psize == 2:
            ptr = (p0 << 24) | int.from_bytes(self._buf[offset:offset + 3], 'big')
            offset += 3
            ptr += 526336
        else:
            ptr = struct.unpack('>I', self._buf[offset:offset + 4])[0]
            offset += 4
        # Pointers are relative to their own section base (data OR metadata).
        target = base + ptr
        val, _ = self._decode(target, base)
        return val, offset

    def _data_section(self):
        return self.node_count * self._node_bytes + _DATA_SECTION_SEPARATOR

    def _decode_by_type(self, dtype, size, offset, base):
        if dtype == 2:      # utf8 string
            return self._buf[offset:offset + size].decode('utf-8', 'replace'), offset + size
        if dtype == 3:      # double
            return struct.unpack('>d', self._buf[offset:offset + 8])[0], offset + 8
        if dtype == 4:      # bytes
            return self._buf[offset:offset + size], offset + size
        if dtype in (5, 6, 9, 10):   # uint16/32/64/128
            return int.from_bytes(self._buf[offset:offset + size], 'big'), offset + size
        if dtype == 7:      # map
            out = {}
            for _ in range(size):
                key, offset = self._decode(offset, base)
                val, offset = self._decode(offset, base)
                out[key] = val
            return out, offset
        if dtype == 8:      # int32 (signed)
            v = int.from_bytes(self._buf[offset:offset + size], 'big')
            if size and (self._buf[offset] & 0x80):
                v -= 1 << (size * 8)
            return v, offset + size
        if dtype == 11:     # array
            out = []
            for _ in range(size):
                val, offset = self._decode(offset, base)
                out.append(val)
            return out, offset
        if dtype == 14:     # boolean
            return bool(size), offset
        if dtype == 15:     # float
            return struct.unpack('>f', self._buf[offset:offset + 4])[0], offset + 4
        # data-cache container (12) / end-marker (13): treat as empty
        return None, offset

    def lookup(self, ip):
        """Return the decoded record dict for `ip`, or None (unknown/bad input)."""
        try:
            pos = self._find_address(ip)
            if not pos:
                return None
            val, _ = self._decode(pos, self._data_section())
            return val
        except Exception:
            return None


def open_reader(path):
    """Best-effort constructor: returns a Reader or None on any failure."""
    try:
        return Reader(path) if path else None
    except Exception:
        return None


def geo_of(reader, ip):
    """Flatten a lookup into {'country', 'country_code', 'asn', 'org'} — the
    subset RemotePower surfaces. Empty dict when unknown."""
    if reader is None:
        return {}
    rec = reader.lookup(ip)
    if not isinstance(rec, dict):
        return {}
    out = {}
    country = rec.get('country') or rec.get('registered_country') or {}
    if isinstance(country, dict):
        if country.get('iso_code'):
            out['country_code'] = country['iso_code']
        names = country.get('names') or {}
        if isinstance(names, dict) and names.get('en'):
            out['country'] = names['en']
    # ASN database (separate file) exposes these at the top level.
    if rec.get('autonomous_system_number'):
        out['asn'] = rec['autonomous_system_number']
    if rec.get('autonomous_system_organization'):
        out['org'] = rec['autonomous_system_organization']
    return out
