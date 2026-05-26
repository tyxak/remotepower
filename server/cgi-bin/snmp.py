"""
Minimal SNMPv2c (community-string) client — pure stdlib.

v3.2.0 (B5): used by api.py to poll agentless devices (switches, APs,
printers, IPMI cards) for the sys* group OIDs. SNMPv1 and SNMPv3 are
deliberately out of scope:

  - SNMPv1 is obsolete (counters wrap at 32 bits in 30 seconds on a
    10G interface; no GETBULK; no Counter64).
  - SNMPv3 requires HMAC/AES from the security model. The pure-stdlib
    cost is high and most homelab equipment runs v2c with a community
    string on a private VLAN. v3 may land in a later release; the
    interface here leaves room for it.

What this supports:
  * GetRequest PDU (0xA0)
  * INTEGER / OCTET STRING / NULL / OBJECT IDENTIFIER encoding
  * IpAddress, Counter32, Gauge32, TimeTicks, Counter64 decoding
  * UDP/161 transport with timeout + single retry
  * Multi-OID GET in one round trip

Intentionally NOT supported (would inflate the file without payoff in
the agentless-monitoring scope):
  * SET requests — RemotePower is read-only against SNMP targets.
  * GETBULK / table walks — covered by the existing CMDB / ifTable
    polling roadmap; keep this minimal until that lands.
  * Trap reception — different transport, requires a daemon.

API:
    >>> from snmp import snmp_get
    >>> snmp_get('192.0.2.10', 'public', [
    ...     '1.3.6.1.2.1.1.1.0',     # sysDescr
    ...     '1.3.6.1.2.1.1.5.0',     # sysName
    ... ])
    {'1.3.6.1.2.1.1.1.0': 'Cisco IOS ...',
     '1.3.6.1.2.1.1.5.0': 'sw-core01'}
"""
from __future__ import annotations

import socket
import struct
import time

# ── ASN.1 BER tags ─────────────────────────────────────────────────────────
TAG_INTEGER       = 0x02
TAG_OCTET_STRING  = 0x04
TAG_NULL          = 0x05
TAG_OID           = 0x06
TAG_SEQUENCE      = 0x30  # constructed
TAG_IP_ADDRESS    = 0x40  # application 0
TAG_COUNTER32     = 0x41  # application 1
TAG_GAUGE32       = 0x42  # application 2
TAG_TIMETICKS     = 0x43  # application 3
TAG_OPAQUE        = 0x44
TAG_COUNTER64     = 0x46

# SNMP PDU tags (context-specific, constructed)
PDU_GET_REQUEST   = 0xA0
PDU_GET_NEXT      = 0xA1
PDU_GET_RESPONSE  = 0xA2

SNMP_V2C = 1   # version field in the message; 0 = v1, 1 = v2c, 3 = v3

# Error-status names from RFC 3416 §3
ERROR_STATUS = {
    0: 'noError',
    1: 'tooBig',
    2: 'noSuchName',
    3: 'badValue',
    4: 'readOnly',
    5: 'genErr',
    6: 'noAccess',
    7: 'wrongType',
}


class SnmpError(Exception):
    pass


# ── BER encoders ───────────────────────────────────────────────────────────

def _encode_length(n):
    """ASN.1 BER length encoding."""
    if n < 128:
        return bytes([n])
    out = b''
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _encode_tlv(tag, value):
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(n):
    """Encode an integer as a two's-complement byte string with the
    minimum number of bytes needed. Positives get a leading 0x00 if the
    top bit would otherwise look negative."""
    if n == 0:
        body = b'\x00'
    else:
        # Compute two's-complement bytes
        if n < 0:
            # Use enough bytes so the sign extends correctly
            nbits = (-n).bit_length() + 1
            nbytes = (nbits + 7) // 8
            n_unsigned = (1 << (nbytes * 8)) + n
            body = n_unsigned.to_bytes(nbytes, 'big')
        else:
            nbytes = (n.bit_length() + 7) // 8 or 1
            body = n.to_bytes(nbytes, 'big')
            if body[0] & 0x80:
                body = b'\x00' + body
    return _encode_tlv(TAG_INTEGER, body)


def _encode_octet_string(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return _encode_tlv(TAG_OCTET_STRING, s)


def _encode_null():
    return _encode_tlv(TAG_NULL, b'')


def _encode_oid(oid_str):
    """Encode an OID like '1.3.6.1.2.1.1.5.0' into BER."""
    parts = [int(x) for x in oid_str.split('.')]
    if len(parts) < 2:
        raise SnmpError(f'OID must have >= 2 arcs: {oid_str}')
    body = bytes([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        if arc < 128:
            body += bytes([arc])
        else:
            stack = []
            stack.append(arc & 0x7F)
            arc >>= 7
            while arc:
                stack.append((arc & 0x7F) | 0x80)
                arc >>= 7
            body += bytes(reversed(stack))
    return _encode_tlv(TAG_OID, body)


# ── BER decoders ───────────────────────────────────────────────────────────

def _decode_length(buf, offset):
    """Returns (length, new_offset)."""
    b = buf[offset]
    offset += 1
    if b < 128:
        return b, offset
    n = b & 0x7F
    if n == 0:
        raise SnmpError('indefinite-length form not supported')
    length = int.from_bytes(buf[offset:offset + n], 'big')
    return length, offset + n


def _decode_tlv(buf, offset):
    """Decode one TLV. Returns (tag, body_bytes, new_offset)."""
    tag = buf[offset]
    offset += 1
    length, offset = _decode_length(buf, offset)
    return tag, buf[offset:offset + length], offset + length


def _decode_integer(body, signed=True):
    if not body:
        return 0
    if signed:
        return int.from_bytes(body, 'big', signed=True)
    return int.from_bytes(body, 'big', signed=False)


def _decode_oid(body):
    if not body:
        return ''
    first = body[0]
    arcs = [first // 40, first % 40]
    val = 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(val)
            val = 0
    return '.'.join(str(a) for a in arcs)


def _decode_value(tag, body):
    """Decode an SNMP variable value into a Python value."""
    if tag == TAG_INTEGER:
        return _decode_integer(body)
    if tag == TAG_OCTET_STRING:
        # Strip trailing NULs; try utf-8, else hex-encode binary blobs
        s = body.rstrip(b'\x00')
        try:
            return s.decode('utf-8')
        except UnicodeDecodeError:
            return s.hex()
    if tag == TAG_NULL:
        return None
    if tag == TAG_OID:
        return _decode_oid(body)
    if tag == TAG_IP_ADDRESS:
        if len(body) == 4:
            return '.'.join(str(b) for b in body)
        return body.hex()
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS):
        return _decode_integer(body, signed=False)
    if tag == TAG_COUNTER64:
        return _decode_integer(body, signed=False)
    # noSuchObject / noSuchInstance / endOfMibView — SNMPv2 exception tags
    if tag in (0x80, 0x81, 0x82):
        return None
    return body.hex()


# ── SNMP message construction + parsing ────────────────────────────────────

def _build_get_request(community, request_id, oids):
    """Build a single GetRequest PDU for the given list of OIDs."""
    # Variable bindings: SEQUENCE OF SEQUENCE { OID, NULL }
    var_binds_body = b''
    for oid in oids:
        vb = _encode_oid(oid) + _encode_null()
        var_binds_body += _encode_tlv(TAG_SEQUENCE, vb)
    var_binds = _encode_tlv(TAG_SEQUENCE, var_binds_body)

    pdu_body = (
        _encode_integer(request_id) +
        _encode_integer(0) +   # error-status
        _encode_integer(0) +   # error-index
        var_binds
    )
    pdu = _encode_tlv(PDU_GET_REQUEST, pdu_body)

    msg_body = (
        _encode_integer(SNMP_V2C) +
        _encode_octet_string(community) +
        pdu
    )
    return _encode_tlv(TAG_SEQUENCE, msg_body)


def _parse_response(buf, expected_request_id):
    """Parse an SNMP response and return {oid: value}."""
    tag, body, _ = _decode_tlv(buf, 0)
    if tag != TAG_SEQUENCE:
        raise SnmpError(f'response not a SEQUENCE (tag=0x{tag:02x})')
    offset = 0
    # Version
    t, v, offset = _decode_tlv(body, offset)
    if t != TAG_INTEGER:
        raise SnmpError('version field missing')
    # Community
    t, v, offset = _decode_tlv(body, offset)
    if t != TAG_OCTET_STRING:
        raise SnmpError('community field missing')
    # PDU
    pdu_tag, pdu_body, offset = _decode_tlv(body, offset)
    if pdu_tag != PDU_GET_RESPONSE:
        raise SnmpError(f'expected GetResponse, got tag 0x{pdu_tag:02x}')

    inner = 0
    t, rid_bytes, inner = _decode_tlv(pdu_body, inner)
    if t != TAG_INTEGER:
        raise SnmpError('request-id field missing')
    request_id = _decode_integer(rid_bytes)
    if request_id != expected_request_id:
        raise SnmpError(f'request-id mismatch: got {request_id}, expected {expected_request_id}')

    t, es_bytes, inner = _decode_tlv(pdu_body, inner)
    error_status = _decode_integer(es_bytes)
    t, ei_bytes, inner = _decode_tlv(pdu_body, inner)
    error_index = _decode_integer(ei_bytes)
    if error_status != 0:
        raise SnmpError(f'agent returned {ERROR_STATUS.get(error_status, "?")} '
                        f'at index {error_index}')

    # Variable bindings: SEQUENCE OF SEQUENCE { OID, value }
    t, vb_body, inner = _decode_tlv(pdu_body, inner)
    if t != TAG_SEQUENCE:
        raise SnmpError('variable bindings not a SEQUENCE')

    result = {}
    vb_off = 0
    while vb_off < len(vb_body):
        t, one_vb_body, vb_off = _decode_tlv(vb_body, vb_off)
        if t != TAG_SEQUENCE:
            continue
        sub = 0
        t, oid_bytes, sub = _decode_tlv(one_vb_body, sub)
        if t != TAG_OID:
            continue
        oid_str = _decode_oid(oid_bytes)
        val_tag, val_body, _ = _decode_tlv(one_vb_body, sub)
        result[oid_str] = _decode_value(val_tag, val_body)
    return result


# ── Public API ─────────────────────────────────────────────────────────────

def snmp_get(host, community, oids, port=161, timeout=2.0, retries=1):
    """Synchronously fetch one or more OIDs via SNMPv2c GET.

    Returns a dict {oid: decoded_value}. Raises SnmpError on transport
    failure, timeout, or agent error-status != noError. Performs at most
    one retry on timeout (network blips happen, especially over VPN).
    """
    if isinstance(oids, str):
        oids = [oids]
    request_id = int(time.time() * 1000) & 0x7FFFFFFF
    msg = _build_get_request(community, request_id, oids)

    last_err = None
    attempts = retries + 1
    for _ in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (host, port))
            buf, _addr = sock.recvfrom(65536)
            return _parse_response(buf, request_id)
        except socket.timeout:
            last_err = SnmpError(f'timeout after {timeout}s to {host}:{port}')
        except OSError as e:
            last_err = SnmpError(f'transport error: {e}')
        finally:
            sock.close()
    raise last_err if last_err else SnmpError('unknown')


# Standard sys* OIDs — RFC 3418 SNMPv2-MIB::system
SYSTEM_OIDS = {
    'sysDescr':    '1.3.6.1.2.1.1.1.0',
    'sysObjectID': '1.3.6.1.2.1.1.2.0',
    'sysUpTime':   '1.3.6.1.2.1.1.3.0',
    'sysContact':  '1.3.6.1.2.1.1.4.0',
    'sysName':     '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
}


def poll_system(host, community, port=161, timeout=2.0):
    """Poll the standard system group. Returns a dict with named fields
    plus an `_oids` dict of raw OID→value for callers that need them."""
    oids = list(SYSTEM_OIDS.values())
    raw = snmp_get(host, community, oids, port=port, timeout=timeout)
    out = {}
    for name, oid in SYSTEM_OIDS.items():
        out[name] = raw.get(oid)
    out['_oids'] = raw
    return out
