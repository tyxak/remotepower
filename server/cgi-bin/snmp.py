"""
Minimal SNMPv2c + SNMPv3/USM client — pure stdlib (AES privacy via the
`cryptography` package the server already ships for backups/TLS).

v3.2.0 (B5): used by api.py to poll agentless devices (switches, APs,
printers, IPMI cards) for the sys* group OIDs. SNMPv1 stays out of scope
(counters wrap at 32 bits in 30 seconds on a 10G interface; no Counter64).

v5.8.0: SNMPv3 (User-based Security Model, RFC 3414/3826/7860):
  * security levels noAuthNoPriv / authNoPriv / authPriv
  * auth: HMAC-MD5-96, HMAC-SHA-96 and the SHA-2 family
    (SHA-224/256/384/512 per RFC 7860) — pure hashlib/hmac
  * privacy: AES-128-CFB (RFC 3826) via `cryptography`. DES-CBC is
    deliberately REJECTED (single DES is broken; every v3-capable agent
    this decade offers AES)
  * engine discovery + time-window sync (REPORT handling, one retry)
  * response authentication (constant-time HMAC check) and decryption

Every public helper (snmp_get / snmp_walk / poll_*) takes the same
`community` argument it always did; pass a **string** for v2c or a
**dict of v3 credentials** and the right envelope is used:

    {'user': 'monitor', 'auth_proto': 'sha256', 'auth_secret': '…',
     'priv_proto': 'aes', 'priv_secret': '…', 'context': ''}

What the v2c layer supports:
  * GetRequest PDU (0xA0)
  * INTEGER / OCTET STRING / NULL / OBJECT IDENTIFIER encoding
  * IpAddress, Counter32, Gauge32, TimeTicks, Counter64 decoding
  * UDP/161 transport with timeout + single retry
  * Multi-OID GET in one round trip

Intentionally NOT supported (would inflate the file without payoff in
the agentless-monitoring scope):
  * SET requests — RemotePower is read-only against SNMP targets.
  * GETBULK — GETNEXT walks cover the current polling scope.
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

import hashlib
import hmac as _hmac
import os
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
    """Parse a v2c SNMP response and return {oid: value}."""
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
    return _parse_pdu_body(pdu_body, expected_request_id)


def _parse_pdu_body(pdu_body, expected_request_id):
    """Parse a GetResponse PDU *body* (request-id / error-status / varbinds)
    into {oid: value}. Shared by the v2c and v3 response paths."""
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
    """Synchronously fetch one or more OIDs via SNMP GET.

    `community` is a v2c community **string**, or a **dict** of SNMPv3/USM
    credentials (see the module docstring) — every caller up the stack
    (poll_system, poll_interfaces, …) inherits v3 support through this
    dispatch without changes.

    Returns a dict {oid: decoded_value}. Raises SnmpError on transport
    failure, timeout, or agent error-status != noError. Performs at most
    one retry on timeout (network blips happen, especially over VPN).
    """
    if isinstance(oids, str):
        oids = [oids]
    if isinstance(community, dict):
        return _v3_request(host, community, PDU_GET_REQUEST, oids,
                           port=port, timeout=timeout, retries=retries)
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


# ── GETNEXT / walk ─────────────────────────────────────────────────────────

def _build_get_next_request(community, request_id, oid):
    """Build a GetNextRequest PDU for a single OID."""
    vb = _encode_oid(oid) + _encode_null()
    var_binds = _encode_tlv(TAG_SEQUENCE, _encode_tlv(TAG_SEQUENCE, vb))
    pdu_body = (
        _encode_integer(request_id) +
        _encode_integer(0) +
        _encode_integer(0) +
        var_binds
    )
    pdu = _encode_tlv(PDU_GET_NEXT, pdu_body)
    msg_body = (
        _encode_integer(SNMP_V2C) +
        _encode_octet_string(community) +
        pdu
    )
    return _encode_tlv(TAG_SEQUENCE, msg_body)


def _oid_in_subtree(oid_str, root_str):
    """True if oid_str == root_str OR is a descendant."""
    if oid_str == root_str:
        return True
    return oid_str.startswith(root_str + '.')


def snmp_walk(host, community, root_oid, port=161, timeout=2.0, retries=1,
              max_results=256):
    """Walk an OID subtree via repeated GETNEXT. Returns {oid: value}.

    Stops when:
      * the next OID falls outside `root_oid`'s subtree (normal completion),
      * the agent returns an endOfMibView exception, or
      * `max_results` is reached (safety cap against runaway walks on
        gigantic ifTables).

    Each round trip uses a fresh request-id so we can detect mismatched
    replies. Per-step retry on timeout matches `snmp_get`'s posture.
    """
    results = {}
    current = root_oid
    base_rid = int(time.time() * 1000) & 0x7FFFFFFF
    for step in range(max_results):
        request_id = (base_rid + step) & 0x7FFFFFFF
        if isinstance(community, dict):
            # v3: one GETNEXT round trip through the USM envelope. The engine
            # cache means only the first step pays the discovery round trip.
            try:
                got = _v3_request(host, community, PDU_GET_NEXT, [current],
                                  port=port, timeout=timeout, retries=retries)
            except SnmpError as e:
                if results:
                    return results          # partial walk — keep what we have
                raise
            if not got:
                return results
            next_oid, value = next(iter(got.items()))
            if value is None and next_oid == current:
                return results
            if not _oid_in_subtree(next_oid, root_oid):
                return results
            results[next_oid] = value
            current = next_oid
            continue
        msg = _build_get_next_request(community, request_id, current)
        last_err = None
        got = None
        for _attempt in range(retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(msg, (host, port))
                buf, _ = sock.recvfrom(65536)
                got = _parse_response(buf, request_id)
                break
            except socket.timeout:
                last_err = SnmpError(f'timeout at OID {current}')
            except OSError as e:
                last_err = SnmpError(f'transport error at OID {current}: {e}')
            finally:
                sock.close()
        if got is None:
            if results:
                # Partial walk — return what we have rather than dropping it
                return results
            raise last_err if last_err else SnmpError('walk failed (no response)')
        if not got:
            return results
        next_oid, value = next(iter(got.items()))
        # endOfMibView from _decode_value returns None for the value AND
        # the OID often remains the same one we asked from. Bail out.
        if value is None and next_oid == current:
            return results
        if not _oid_in_subtree(next_oid, root_oid):
            return results
        results[next_oid] = value
        current = next_oid
    return results


# ── SNMPv3 / USM (RFC 3414, 3826, 7860) ─────────────────────────────────────
#
# Design: the PDU layer above is untouched — v3 only adds a different message
# ENVELOPE (header + security parameters + scopedPDU) around the same
# GetRequest/GetNext PDUs, so _parse_pdu_body / _decode_value are shared.
# Auth is pure hashlib/hmac; AES-128-CFB privacy uses the `cryptography`
# package the server already depends on elsewhere (backups, TLS parsing).
# DES-CBC is deliberately unsupported — single DES is cryptographically
# broken and every v3-capable agent this decade offers AES.

SNMP_V3 = 3
PDU_REPORT = 0xA8

# auth proto → (hash constructor, HMAC truncation length per RFC 3414 §6 /
# RFC 7860 §4.1). 'sha' is HMAC-SHA-96 (SHA-1), the classic default.
_V3_AUTH = {
    'md5':    (hashlib.md5,    12),
    'sha':    (hashlib.sha1,   12),
    'sha224': (hashlib.sha224, 16),
    'sha256': (hashlib.sha256, 24),
    'sha384': (hashlib.sha384, 32),
    'sha512': (hashlib.sha512, 48),
}
V3_AUTH_PROTOCOLS = ('none',) + tuple(sorted(_V3_AUTH))
V3_PRIV_PROTOCOLS = ('none', 'aes')          # aes = AES-128-CFB (RFC 3826)

# usmStats REPORT counters (1.3.6.1.6.3.15.1.1.x) → operator-readable error.
_USM_REPORTS = {
    '1.3.6.1.6.3.15.1.1.1.0': 'unsupported security level',
    '1.3.6.1.6.3.15.1.1.2.0': 'not in time window',
    '1.3.6.1.6.3.15.1.1.3.0': 'unknown user name',
    '1.3.6.1.6.3.15.1.1.4.0': 'unknown engine id',
    '1.3.6.1.6.3.15.1.1.5.0': 'wrong digest (check the auth password/protocol)',
    '1.3.6.1.6.3.15.1.1.6.0': 'decryption error (check the priv password/protocol)',
}

# Engine cache: (host, port, user) → discovered engine parameters, so repeated
# polls in one process (WSGI tier, walks, multi-group polls) skip the
# discovery round trip. engineTime is re-estimated from a monotonic clock.
_V3_ENGINE_CACHE: dict = {}


def _v3_validate(creds):
    """Normalize + validate a v3 credential dict. Returns
    (user, auth_proto, auth_secret, priv_proto, priv_secret, context)."""
    user = str(creds.get('user') or '')
    if not user:
        raise SnmpError('SNMPv3: user required')
    auth_proto = str(creds.get('auth_proto') or 'none').lower()
    priv_proto = str(creds.get('priv_proto') or 'none').lower()
    auth_secret = str(creds.get('auth_secret') or '')
    priv_secret = str(creds.get('priv_secret') or '')
    if auth_proto != 'none' and auth_proto not in _V3_AUTH:
        raise SnmpError(f'SNMPv3: unsupported auth protocol {auth_proto!r}')
    if priv_proto not in V3_PRIV_PROTOCOLS:
        if priv_proto in ('des', '3des', 'des-cbc'):
            raise SnmpError('SNMPv3: DES privacy is not supported (broken '
                            'cipher) — configure AES on the agent')
        raise SnmpError(f'SNMPv3: unsupported priv protocol {priv_proto!r}')
    if priv_proto != 'none' and auth_proto == 'none':
        raise SnmpError('SNMPv3: privacy requires authentication (authPriv)')
    if auth_proto != 'none' and len(auth_secret) < 8:
        raise SnmpError('SNMPv3: auth password must be at least 8 characters')
    if priv_proto != 'none' and len(priv_secret) < 8:
        raise SnmpError('SNMPv3: priv password must be at least 8 characters')
    return (user, auth_proto, auth_secret, priv_proto, priv_secret,
            str(creds.get('context') or ''))


def _usm_password_to_key(hash_fn, password):
    """RFC 3414 A.2: stretch the passphrase over 1MB of repetitions → Ku."""
    pw = password.encode('utf-8')
    h = hash_fn()
    reps, rem = divmod(1024 * 1024, len(pw))
    h.update(pw * reps + pw[:rem])
    return h.digest()


def _usm_localize_key(hash_fn, password, engine_id):
    """RFC 3414 §2.6: Kul = H(Ku || engineID || Ku)."""
    ku = _usm_password_to_key(hash_fn, password)
    return hash_fn(ku + engine_id + ku).digest()


def _aes_cfb(key16, iv16, data, encrypt):
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
    except ImportError:
        raise SnmpError('SNMPv3 AES privacy needs the python "cryptography" '
                        'package (pip install cryptography)')
    c = Cipher(algorithms.AES(key16), modes.CFB(iv16))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _v3_encode(msg_id, flags, engine_id, boots, etime, user,
               auth_params, priv_params, msg_data):
    """Assemble one SNMPv3Message. `msg_data` is the scopedPDU SEQUENCE bytes
    (plaintext) or an already-encrypted OCTET STRING TLV."""
    global_data = _encode_tlv(TAG_SEQUENCE, (
        _encode_integer(msg_id) +
        _encode_integer(65507) +                      # msgMaxSize
        _encode_octet_string(bytes([flags])) +
        _encode_integer(3)))                          # msgSecurityModel = USM
    sec_params = _encode_tlv(TAG_SEQUENCE, (
        _encode_octet_string(engine_id) +
        _encode_integer(boots) +
        _encode_integer(etime) +
        _encode_octet_string(user) +
        _encode_octet_string(auth_params) +
        _encode_octet_string(priv_params)))
    return _encode_tlv(TAG_SEQUENCE, (
        _encode_integer(SNMP_V3) +
        global_data +
        _encode_octet_string(sec_params) +
        msg_data))


def _v3_scoped_pdu(engine_id, context, pdu):
    return _encode_tlv(TAG_SEQUENCE, (
        _encode_octet_string(engine_id) +
        _encode_octet_string(context) +
        pdu))


def _encode_pdu(pdu_tag, request_id, oids):
    """A bare GetRequest/GetNext PDU (no v2c envelope) for the v3 path."""
    vb = b''
    for oid in oids:
        vb += _encode_tlv(TAG_SEQUENCE, _encode_oid(oid) + _encode_null())
    return _encode_tlv(pdu_tag, (
        _encode_integer(request_id) +
        _encode_integer(0) +
        _encode_integer(0) +
        _encode_tlv(TAG_SEQUENCE, vb)))


def _v3_parse(buf):
    """Parse an SNMPv3Message into a dict of its parts. Tracks the absolute
    byte offset of the authParams value in `buf` so the caller can zero it
    in place for HMAC verification (re-encoding the message risks byte
    differences if the agent used non-minimal BER lengths)."""
    tag, body, msg_end = _decode_tlv(buf, 0)
    if tag != TAG_SEQUENCE:
        raise SnmpError(f'v3 response not a SEQUENCE (tag=0x{tag:02x})')
    body_abs = msg_end - len(body)      # absolute offset of `body` within buf

    off = 0
    t, ver, off = _decode_tlv(body, off)
    if t != TAG_INTEGER or _decode_integer(ver) != SNMP_V3:
        raise SnmpError('not an SNMPv3 message')
    t, gd, off = _decode_tlv(body, off)
    if t != TAG_SEQUENCE:
        raise SnmpError('v3 msgGlobalData missing')
    g = 0
    _t, mid, g = _decode_tlv(gd, g)
    msg_id = _decode_integer(mid)
    _t, _sz, g = _decode_tlv(gd, g)
    _t, fl, g = _decode_tlv(gd, g)
    flags = fl[0] if fl else 0
    # msgSecurityParameters: OCTET STRING wrapping a SEQUENCE
    t, sp, off = _decode_tlv(body, off)
    if t != TAG_OCTET_STRING:
        raise SnmpError('v3 msgSecurityParameters missing')
    sp_val_abs = body_abs + off - len(sp)   # absolute offset of sp bytes in buf
    t, spb, spb_end = _decode_tlv(sp, 0)
    if t != TAG_SEQUENCE:
        raise SnmpError('v3 USM security parameters not a SEQUENCE')
    spb_abs = sp_val_abs + spb_end - len(spb)
    s = 0
    _t, eng, s = _decode_tlv(spb, s)
    _t, boots, s = _decode_tlv(spb, s)
    _t, etime, s = _decode_tlv(spb, s)
    _t, usr, s = _decode_tlv(spb, s)
    _t, auth, s = _decode_tlv(spb, s)
    auth_abs = spb_abs + s - len(auth)  # absolute offset of authParams value
    _t, priv, s = _decode_tlv(spb, s)
    # msgData: plaintext scopedPDU SEQUENCE, or OCTET STRING of ciphertext
    dtag, ddata, _ = _decode_tlv(body, off)
    return {
        'msg_id': msg_id, 'flags': flags,
        'engine_id': eng, 'boots': _decode_integer(boots),
        'time': _decode_integer(etime), 'user': usr,
        'auth_params': auth, 'auth_params_abs': auth_abs,
        'priv_params': priv,
        'data_tag': dtag, 'data': ddata,
    }


def _v3_scoped_parse(scoped_body, expected_request_id):
    """contextEngineID + contextName + PDU → {oid: value}; REPORT → SnmpError."""
    off = 0
    _t, _ceid, off = _decode_tlv(scoped_body, off)
    _t, _cname, off = _decode_tlv(scoped_body, off)
    pdu_tag, pdu_body, _ = _decode_tlv(scoped_body, off)
    if pdu_tag == PDU_REPORT:
        # The varbind OID names the usmStats counter that fired.
        try:
            inner = 0
            _t, _rid, inner = _decode_tlv(pdu_body, inner)
            _t, _es, inner = _decode_tlv(pdu_body, inner)
            _t, _ei, inner = _decode_tlv(pdu_body, inner)
            _t, vb, inner = _decode_tlv(pdu_body, inner)
            _t, one, _ = _decode_tlv(vb, 0)
            _t, oid_b, _ = _decode_tlv(one, 0)
            oid = _decode_oid(oid_b)
        except Exception:
            oid = '?'
        reason = _USM_REPORTS.get(oid, f'agent REPORT ({oid})')
        err = SnmpError(f'SNMPv3: {reason}')
        err.usm_report_oid = oid
        raise err
    if pdu_tag != PDU_GET_RESPONSE:
        raise SnmpError(f'expected GetResponse, got tag 0x{pdu_tag:02x}')
    return _parse_pdu_body(pdu_body, expected_request_id)


def _v3_exchange(host, port, msg, timeout, retries):
    """One UDP round trip (with retry) used by the v3 paths."""
    last_err = None
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (host, port))
            buf, _addr = sock.recvfrom(65536)
            return buf
        except socket.timeout:
            last_err = SnmpError(f'timeout after {timeout}s to {host}:{port}')
        except OSError as e:
            last_err = SnmpError(f'transport error: {e}')
        finally:
            sock.close()
    raise last_err if last_err else SnmpError('unknown')


def _v3_discover(host, port, timeout, retries):
    """Engine discovery (RFC 3414 §4): an unauthenticated request with an
    empty engineID; the agent's REPORT carries its engineID/boots/time."""
    msg_id = int(time.time() * 1000) & 0x7FFFFFFF
    pdu = _encode_pdu(PDU_GET_REQUEST, msg_id, [])
    msg = _v3_encode(msg_id, 0x04, b'', 0, 0, b'', b'', b'',
                     _v3_scoped_pdu(b'', b'', pdu))
    buf = _v3_exchange(host, port, msg, timeout, retries)
    parts = _v3_parse(buf)
    if not parts['engine_id']:
        raise SnmpError('SNMPv3: engine discovery failed (no engineID)')
    return parts


def _v3_engine(host, port, timeout, retries, user):
    """Cached engine parameters; engineTime advances on a monotonic clock."""
    key = (host, port, user)
    ent = _V3_ENGINE_CACHE.get(key)
    if ent is None:
        parts = _v3_discover(host, port, timeout, retries)
        ent = {'engine_id': parts['engine_id'], 'boots': parts['boots'],
               'time': parts['time'], 'stamp': time.monotonic()}
        _V3_ENGINE_CACHE[key] = ent
    return ent


def _v3_request(host, creds, pdu_tag, oids, port=161, timeout=2.0, retries=1,
                _resync=True):
    """One authenticated (and optionally encrypted) SNMPv3 GET/GETNEXT."""
    (user, auth_proto, auth_secret,
     priv_proto, priv_secret, context) = _v3_validate(creds)
    ent = _v3_engine(host, port, timeout, retries, user)
    engine_id = ent['engine_id']
    boots = ent['boots']
    etime = ent['time'] + int(time.monotonic() - ent['stamp'])

    request_id = int(time.time() * 1000) & 0x7FFFFFFF
    pdu = _encode_pdu(pdu_tag, request_id, oids)
    scoped = _v3_scoped_pdu(engine_id, context.encode(), pdu)

    flags = 0x04                                     # reportable
    priv_params = b''
    msg_data = scoped
    if auth_proto != 'none':
        flags |= 0x01
        hash_fn, trunc = _V3_AUTH[auth_proto]
        auth_kul = _usm_localize_key(hash_fn, auth_secret, engine_id)
        if priv_proto == 'aes':
            flags |= 0x02
            priv_kul = _usm_localize_key(hash_fn, priv_secret, engine_id)
            if len(priv_kul) < 16:                    # md5 gives exactly 16
                raise SnmpError('SNMPv3: priv key derivation too short')
            salt = os.urandom(8)
            iv = struct.pack('>II', boots, etime) + salt
            cipher = _aes_cfb(priv_kul[:16], iv, scoped, encrypt=True)
            msg_data = _encode_octet_string(cipher)
            priv_params = salt
        # Two-pass auth: build with zeroed authParams, HMAC the exact bytes,
        # rebuild the identical structure with the real MAC spliced in.
        msg0 = _v3_encode(request_id, flags, engine_id, boots, etime,
                          user.encode(), b'\x00' * trunc, priv_params, msg_data)
        mac = _hmac.new(auth_kul, msg0, hash_fn).digest()[:trunc]
        msg = _v3_encode(request_id, flags, engine_id, boots, etime,
                         user.encode(), mac, priv_params, msg_data)
    else:
        msg = _v3_encode(request_id, flags, engine_id, boots, etime,
                         user.encode(), b'', b'', msg_data)

    buf = _v3_exchange(host, port, msg, timeout, retries)
    parts = _v3_parse(buf)

    # Authenticate the response before trusting anything in it.
    if auth_proto != 'none' and (parts['flags'] & 0x01):
        hash_fn, trunc = _V3_AUTH[auth_proto]
        auth_kul = _usm_localize_key(hash_fn, auth_secret, engine_id)
        got_mac = parts['auth_params']
        a = parts['auth_params_abs']
        zeroed = buf[:a] + b'\x00' * len(got_mac) + buf[a + len(got_mac):]
        want = _hmac.new(auth_kul, zeroed, hash_fn).digest()[:trunc]
        if len(got_mac) != trunc or not _hmac.compare_digest(got_mac, want):
            raise SnmpError('SNMPv3: response authentication failed')

    if parts['data_tag'] == TAG_OCTET_STRING:        # encrypted scopedPDU
        if priv_proto != 'aes':
            raise SnmpError('SNMPv3: unexpected encrypted response')
        hash_fn, _tr = _V3_AUTH[auth_proto]
        priv_kul = _usm_localize_key(hash_fn, priv_secret, engine_id)
        iv = struct.pack('>II', parts['boots'], parts['time']) + parts['priv_params']
        plain = _aes_cfb(priv_kul[:16], iv, parts['data'], encrypt=False)
        t, scoped_body, _ = _decode_tlv(plain, 0)
        if t != TAG_SEQUENCE:
            raise SnmpError('SNMPv3: decryption produced garbage '
                            '(check the priv password/protocol)')
    else:
        scoped_body = parts['data']

    try:
        return _v3_scoped_parse(scoped_body, request_id)
    except SnmpError as e:
        oid = getattr(e, 'usm_report_oid', '')
        # Time-window / engine drift: refresh from this REPORT and retry once
        # (an agent reboot bumps engineBoots and invalidates our cache).
        if _resync and oid in ('1.3.6.1.6.3.15.1.1.2.0',
                               '1.3.6.1.6.3.15.1.1.4.0'):
            key = (host, port, user)
            if parts['engine_id'] and parts.get('boots') is not None:
                _V3_ENGINE_CACHE[key] = {
                    'engine_id': parts['engine_id'], 'boots': parts['boots'],
                    'time': parts['time'], 'stamp': time.monotonic()}
            else:
                _V3_ENGINE_CACHE.pop(key, None)
            return _v3_request(host, creds, pdu_tag, oids, port=port,
                               timeout=timeout, retries=retries, _resync=False)
        raise


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


# ── Interface table walks ──────────────────────────────────────────────────

# RFC 1213 IF-MIB ifTable columns
_IF_COLUMNS = {
    'ifDescr':       '1.3.6.1.2.1.2.2.1.2',
    'ifType':        '1.3.6.1.2.1.2.2.1.3',
    'ifMtu':         '1.3.6.1.2.1.2.2.1.4',
    'ifSpeed':       '1.3.6.1.2.1.2.2.1.5',
    'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus':  '1.3.6.1.2.1.2.2.1.8',
    'ifInOctets':    '1.3.6.1.2.1.2.2.1.10',
    'ifOutOctets':   '1.3.6.1.2.1.2.2.1.16',
    'ifInErrors':    '1.3.6.1.2.1.2.2.1.14',
    'ifOutErrors':   '1.3.6.1.2.1.2.2.1.20',
}
# IF-MIB enums for status
_IF_ADMIN_STATUS = {1: 'up', 2: 'down', 3: 'testing'}
_IF_OPER_STATUS  = {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown',
                    5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown'}


def poll_interfaces(host, community, port=161, timeout=2.0, max_interfaces=64):
    """Walk IF-MIB::ifTable. Returns a list of per-interface dicts.

    Each entry: {index, descr, type, mtu, speed_bps, mac, admin, oper,
                 in_octets, out_octets, in_errors, out_errors}.

    Bounded at max_interfaces × len(_IF_COLUMNS) walk steps. A switch
    with 200 ports won't blow up the response.
    """
    rows = {}  # idx → dict
    # Walk each column separately. Cheaper than walking the whole ifTable
    # subtree because we skip columns we don't display.
    for name, oid in _IF_COLUMNS.items():
        try:
            walked = snmp_walk(host, community, oid, port=port,
                               timeout=timeout, retries=1,
                               max_results=max_interfaces)
        except SnmpError:
            continue
        for found_oid, value in walked.items():
            # ifTable column.index → the trailing arc is the interface index
            idx_str = found_oid[len(oid) + 1:]
            if not idx_str.isdigit():
                continue
            idx = int(idx_str)
            rows.setdefault(idx, {'index': idx})[name] = value
    # Map to a friendlier shape
    out = []
    for idx in sorted(rows.keys()):
        r = rows[idx]
        out.append({
            'index':       idx,
            'descr':       r.get('ifDescr', ''),
            'type':        r.get('ifType'),
            'mtu':         r.get('ifMtu'),
            'speed_bps':   r.get('ifSpeed'),
            'mac':         r.get('ifPhysAddress', ''),
            'admin':       _IF_ADMIN_STATUS.get(r.get('ifAdminStatus'), '?'),
            'oper':        _IF_OPER_STATUS.get(r.get('ifOperStatus'), '?'),
            'in_octets':   r.get('ifInOctets', 0),
            'out_octets':  r.get('ifOutOctets', 0),
            'in_errors':   r.get('ifInErrors', 0),
            'out_errors':  r.get('ifOutErrors', 0),
        })
    return out


# ── Host Resources MIB (RFC 2790) — best effort, many vendors implement it ──

HRMIB_SCALARS = {
    'hrSystemUptime':     '1.3.6.1.2.1.25.1.1.0',     # TimeTicks
    'hrSystemNumUsers':   '1.3.6.1.2.1.25.1.5.0',
    'hrSystemProcesses':  '1.3.6.1.2.1.25.1.6.0',
    'hrMemorySize':       '1.3.6.1.2.1.25.2.2.0',     # kB
}


def poll_host_resources(host, community, port=161, timeout=2.0):
    """Best-effort fetch of the well-known scalars from Host Resources MIB.

    Many vendors (Linux, BSD/OPNsense, Windows, Mikrotik) implement these.
    Returns a dict with the values present; OIDs the agent doesn't expose
    are simply omitted rather than raising.
    """
    out = {}
    try:
        raw = snmp_get(host, community, list(HRMIB_SCALARS.values()),
                       port=port, timeout=timeout)
    except SnmpError:
        return out
    for name, oid in HRMIB_SCALARS.items():
        val = raw.get(oid)
        if val is not None:
            out[name] = val
    return out


def poll_hr_storage(host, community, port=161, timeout=2.0, max_entries=24):
    """Walk hrStorageTable for memory + filesystems.

    Returns a list of {descr, type, units, size, used, used_pct}.
    Walks 3 columns: hrStorageDescr (.3), hrStorageAllocationUnits (.4),
    hrStorageSize (.5), hrStorageUsed (.6). Skips entries with size=0.
    """
    cols = {
        'descr':  '1.3.6.1.2.1.25.2.3.1.3',
        'units':  '1.3.6.1.2.1.25.2.3.1.4',
        'size':   '1.3.6.1.2.1.25.2.3.1.5',
        'used':   '1.3.6.1.2.1.25.2.3.1.6',
    }
    rows = {}
    for key, oid in cols.items():
        try:
            walked = snmp_walk(host, community, oid, port=port,
                               timeout=timeout, retries=1,
                               max_results=max_entries)
        except SnmpError:
            continue
        for found_oid, value in walked.items():
            idx_str = found_oid[len(oid) + 1:]
            if not idx_str.isdigit():
                continue
            idx = int(idx_str)
            rows.setdefault(idx, {})[key] = value
    out = []
    for idx in sorted(rows.keys()):
        r = rows[idx]
        size = r.get('size')
        used = r.get('used')
        units = r.get('units') or 1
        try:
            size_bytes = int(size) * int(units) if size is not None else None
            used_bytes = int(used) * int(units) if used is not None else None
        except (TypeError, ValueError):
            size_bytes = used_bytes = None
        used_pct = None
        if size_bytes and used_bytes is not None and size_bytes > 0:
            used_pct = round(used_bytes * 100.0 / size_bytes, 1)
        if not size_bytes:
            continue   # Skip placeholder rows
        out.append({
            'index':     idx,
            'descr':     r.get('descr', ''),
            'size_bytes': size_bytes,
            'used_bytes': used_bytes,
            'used_pct':  used_pct,
        })
    return out


# ── Mikrotik vendor MIB (1.3.6.1.4.1.14988.*) ──────────────────────────────

MIKROTIK_OIDS = {
    'mtxrSystemVersion':  '1.3.6.1.4.1.14988.1.1.4.4.0',
    'mtxrSystemUptime':   '1.3.6.1.4.1.14988.1.1.7.1.0',   # 1/100 sec
    'mtxrHlCoreVoltage':  '1.3.6.1.4.1.14988.1.1.3.8.0',   # mV
    'mtxrHlTemperature':  '1.3.6.1.4.1.14988.1.1.3.10.0',  # °C × 1
    'mtxrHlBoardTemp':    '1.3.6.1.4.1.14988.1.1.3.11.0',
    'mtxrHlCpuFrequency': '1.3.6.1.4.1.14988.1.1.3.14.0',  # MHz
}


def poll_mikrotik(host, community, port=161, timeout=2.0):
    """Mikrotik RouterBOARD health (temp, voltage, CPU freq, version).

    Detected by sysObjectID prefix 1.3.6.1.4.1.14988. Best effort —
    units that don't expose health (cloud routers) just return empties.
    """
    out = {}
    try:
        raw = snmp_get(host, community, list(MIKROTIK_OIDS.values()),
                       port=port, timeout=timeout)
    except SnmpError:
        return out
    for name, oid in MIKROTIK_OIDS.items():
        v = raw.get(oid)
        if v is not None:
            out[name] = v
    return out


# ── UCD-SNMP-MIB (1.3.6.1.4.1.2021) — standardized on net-snmp ─────────────
# Works on every device that runs net-snmp (Linux, FreeBSD/OPNsense, Solaris,
# Windows snmp-service via NET-SNMP extension). Mikrotik does NOT expose this.

UCD_SNMP_OIDS = {
    'laLoad_1m':       '1.3.6.1.4.1.2021.10.1.3.1',   # Returns OCTET STRING "0.42"
    'laLoad_5m':       '1.3.6.1.4.1.2021.10.1.3.2',
    'laLoad_15m':      '1.3.6.1.4.1.2021.10.1.3.3',
    'ssCpuRawUser':    '1.3.6.1.4.1.2021.11.50.0',    # Cumulative ticks
    'ssCpuRawNice':    '1.3.6.1.4.1.2021.11.51.0',
    'ssCpuRawSystem':  '1.3.6.1.4.1.2021.11.52.0',
    'ssCpuRawIdle':    '1.3.6.1.4.1.2021.11.53.0',
    'ssCpuRawWait':    '1.3.6.1.4.1.2021.11.54.0',
    'memTotalReal':    '1.3.6.1.4.1.2021.4.5.0',      # kB
    'memAvailReal':    '1.3.6.1.4.1.2021.4.6.0',      # kB
    'memTotalSwap':    '1.3.6.1.4.1.2021.4.3.0',
    'memAvailSwap':    '1.3.6.1.4.1.2021.4.4.0',
}


def poll_ucd_snmp(host, community, port=161, timeout=2.0):
    """UCD-SNMP-MIB load averages + raw CPU ticks + memory totals.

    Best effort — devices that don't expose net-snmp's enterprise OIDs
    (Mikrotik, most enterprise switches) return nothing. Load averages
    are returned as float-as-string by net-snmp ("0.42") — we parse them
    here so the caller gets floats.
    """
    out = {}
    try:
        raw = snmp_get(host, community, list(UCD_SNMP_OIDS.values()),
                       port=port, timeout=timeout)
    except SnmpError:
        return out
    for name, oid in UCD_SNMP_OIDS.items():
        v = raw.get(oid)
        if v is None:
            continue
        # Load averages arrive as octet strings — convert to float
        if name.startswith('laLoad_') and isinstance(v, str):
            try:
                v = float(v)
            except ValueError:
                continue
        out[name] = v
    return out


# ── hrProcessorTable (RFC 2790) — per-CPU load % ──────────────────────────
# Works on most devices that expose Host Resources MIB. Mikrotik supports
# it. OPNsense exposes a single aggregate entry. Linux net-snmp gives
# one entry per logical CPU.

def poll_processors(host, community, port=161, timeout=2.0, max_cpus=64):
    """Walk hrProcessorTable. Returns [{index, load_pct}, ...] for every
    advertised CPU. The MIB itself gives per-CPU load already as a
    percentage, so no client-side delta computation needed."""
    cols = {
        'load_pct': '1.3.6.1.2.1.25.3.3.1.2',
    }
    rows = {}
    for key, oid in cols.items():
        try:
            walked = snmp_walk(host, community, oid, port=port,
                                timeout=timeout, retries=1,
                                max_results=max_cpus)
        except SnmpError:
            continue
        for found_oid, value in walked.items():
            idx_str = found_oid[len(oid) + 1:]
            if not idx_str.isdigit():
                continue
            rows.setdefault(int(idx_str), {})[key] = value
    out = []
    for idx in sorted(rows.keys()):
        out.append({'index': idx, 'load_pct': rows[idx].get('load_pct')})
    return out


# ── Ubiquiti UniFi vendor MIB (1.3.6.1.4.1.41112) ─────────────────────────
# Common in homelabs — UAP-AC family, UDM, USW switches. The MIB is more
# narrowly populated than Mikrotik's; most useful data lives on APs.

UBNT_OIDS = {
    # System (works across UAP/UDM/USW)
    'unifiApSystemModel':      '1.3.6.1.4.1.41112.1.6.3.3.0',
    'unifiApSystemVersion':    '1.3.6.1.4.1.41112.1.6.3.4.0',
    # AirOS / older Ubiquiti devices also expose:
    'airosVersion':            '1.3.6.1.4.1.41112.1.4.5.1.4.1',
    # AP-only — radios at 1.3.6.1.4.1.41112.1.6.1.2 (table walked separately)
}


def poll_ubnt(host, community, port=161, timeout=2.0):
    """Best-effort fetch of Ubiquiti scalars + radio summary.

    Detected by sysObjectID prefix 1.3.6.1.4.1.41112. Different UniFi
    product lines populate different subsets — UDM/USW returns very
    little here, APs return model/version. The radio walk gives
    per-radio client counts for APs.
    """
    out = {}
    try:
        raw = snmp_get(host, community, list(UBNT_OIDS.values()),
                       port=port, timeout=timeout)
    except SnmpError:
        return out
    for name, oid in UBNT_OIDS.items():
        v = raw.get(oid)
        if v is not None:
            out[name] = v
    # AP radio table — best effort walk. Each entry: radio name + clients.
    try:
        radio_clients = snmp_walk(host, community,
            '1.3.6.1.4.1.41112.1.6.1.2.1.8',   # unifiRadioNumStations
            port=port, timeout=timeout, retries=0, max_results=8)
        radio_names = snmp_walk(host, community,
            '1.3.6.1.4.1.41112.1.6.1.2.1.2',   # unifiRadioName
            port=port, timeout=timeout, retries=0, max_results=8)
    except SnmpError:
        radio_clients = {}
        radio_names = {}
    if radio_clients:
        # Map suffix → row
        rows = {}
        clients_prefix = '1.3.6.1.4.1.41112.1.6.1.2.1.8'
        names_prefix   = '1.3.6.1.4.1.41112.1.6.1.2.1.2'
        for oid, val in radio_clients.items():
            idx = oid[len(clients_prefix) + 1:]
            if idx:
                rows.setdefault(idx, {})['clients'] = val
        for oid, val in radio_names.items():
            idx = oid[len(names_prefix) + 1:]
            if idx:
                rows.setdefault(idx, {})['name'] = val
        out['radios'] = [
            {'index': idx, 'name': r.get('name'), 'clients': r.get('clients')}
            for idx, r in sorted(rows.items())
        ]
    return out


# ── Synology DSM vendor MIBs (1.3.6.1.4.1.6574) ───────────────────────────
# Synology NAS boxes run net-snmp, so their sysObjectID is usually the
# generic Linux OID (1.3.6.1.4.1.8072.*), NOT 6574 — sysObjectID-based
# detection is unreliable. Instead we probe the Synology system MIB: a
# single GET of the system scalars. If nothing comes back, it isn't a
# Synology (or the MIB isn't exposed) and we skip the disk/RAID walks, so
# non-Synology devices pay only one cheap GET.
#
# OIDs from Synology's published MIBs (SYNOLOGY-SYSTEM-MIB / -DISK-MIB /
# -RAID-MIB). Enable SNMP in DSM → Control Panel → Terminal & SNMP.
SYNOLOGY_SYSTEM_OIDS = {
    'systemStatus':     '1.3.6.1.4.1.6574.1.1.0',     # 1=Normal 2=Failed
    'temperature_c':    '1.3.6.1.4.1.6574.1.2.0',     # system temp, °C
    'powerStatus':      '1.3.6.1.4.1.6574.1.3.0',     # 1=Normal 2=Failed
    'systemFanStatus':  '1.3.6.1.4.1.6574.1.4.1.0',   # 1=Normal 2=Failed
    'cpuFanStatus':     '1.3.6.1.4.1.6574.1.4.2.0',
    'modelName':        '1.3.6.1.4.1.6574.1.5.1.0',
    'serialNumber':     '1.3.6.1.4.1.6574.1.5.2.0',
    'dsmVersion':       '1.3.6.1.4.1.6574.1.5.3.0',
    'upgradeAvailable': '1.3.6.1.4.1.6574.1.5.4.0',   # 1=Available 2=Unavailable …
}

_SYNO_OKFAIL    = {1: 'normal', 2: 'failed'}
_SYNO_UPGRADE   = {1: 'available', 2: 'unavailable', 3: 'connecting',
                   4: 'disconnected', 5: 'others'}
_SYNO_DISK_STAT = {1: 'normal', 2: 'initialized', 3: 'not_initialized',
                   4: 'system_partition_failed', 5: 'crashed'}
_SYNO_RAID_STAT = {1: 'normal', 2: 'repairing', 3: 'migrating', 4: 'expanding',
                   5: 'deleting', 6: 'creating', 7: 'syncing',
                   8: 'parity_checking', 9: 'assembling', 10: 'canceling',
                   11: 'degraded', 12: 'crashed', 13: 'data_scrubbing',
                   14: 'deploying', 15: 'undeploying'}


def _syno_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def poll_synology(host, community, port=161, timeout=2.0):
    """Synology DSM health: system status/temp/power/fans + per-disk and
    per-volume (RAID) status. Returns {} if the box doesn't answer the
    Synology MIB (i.e. not a Synology, or SNMP-on-DSM not enabled), so the
    caller can run it unconditionally as a cheap probe.

    Shape:
      {'system': {model, serial, dsm_version, system, power, temperature_c,
                  fan, cpu_fan, upgrade},
       'disks':   [{id, model, type, status, temperature_c}, ...],
       'volumes': [{name, status}, ...]}
    """
    try:
        raw = snmp_get(host, community, list(SYNOLOGY_SYSTEM_OIDS.values()),
                       port=port, timeout=timeout)
    except SnmpError:
        return {}
    sysv = {name: raw.get(oid) for name, oid in SYNOLOGY_SYSTEM_OIDS.items()}
    # Probe gate: no model AND no system status -> not a Synology MIB.
    if sysv.get('modelName') is None and sysv.get('systemStatus') is None:
        return {}

    system = {
        'model':         sysv.get('modelName'),
        'serial':        sysv.get('serialNumber'),
        'dsm_version':   sysv.get('dsmVersion'),
        'system':        _SYNO_OKFAIL.get(_syno_int(sysv.get('systemStatus'))),
        'power':         _SYNO_OKFAIL.get(_syno_int(sysv.get('powerStatus'))),
        'fan':           _SYNO_OKFAIL.get(_syno_int(sysv.get('systemFanStatus'))),
        'cpu_fan':       _SYNO_OKFAIL.get(_syno_int(sysv.get('cpuFanStatus'))),
        'temperature_c': _syno_int(sysv.get('temperature_c')),
        'upgrade':       _SYNO_UPGRADE.get(_syno_int(sysv.get('upgradeAvailable'))),
    }

    disks = _syno_walk_table(
        host, community, port, timeout,
        base='1.3.6.1.4.1.6574.2.1.1',
        cols={'id': '2', 'model': '3', 'type': '4', 'status': '5', 'temp': '6'},
        build=lambda r: {
            'id':            r.get('id'),
            'model':         r.get('model'),
            'type':          r.get('type'),
            'status':        _SYNO_DISK_STAT.get(_syno_int(r.get('status'))),
            'temperature_c': _syno_int(r.get('temp')),
        })
    volumes = _syno_walk_table(
        host, community, port, timeout,
        base='1.3.6.1.4.1.6574.3.1.1',
        cols={'name': '2', 'status': '3'},
        build=lambda r: {
            'name':   r.get('name'),
            'status': _SYNO_RAID_STAT.get(_syno_int(r.get('status'))),
        })
    return {'system': system, 'disks': disks, 'volumes': volumes}


def _syno_walk_table(host, community, port, timeout, base, cols, build,
                     max_rows=64):
    """Walk a Synology table: one bounded walk per column, joined by the
    row index (the OID suffix after <base>.<col>). Returns [build(row), …]
    ordered by index. Best effort — a column walk that errors is skipped."""
    rows = {}
    for key, col in cols.items():
        col_oid = f'{base}.{col}'
        try:
            walked = snmp_walk(host, community, col_oid, port=port,
                               timeout=timeout, retries=0, max_results=max_rows)
        except SnmpError:
            continue
        for found_oid, value in walked.items():
            idx = found_oid[len(col_oid) + 1:]
            if idx:
                rows.setdefault(idx, {})[key] = value
    out = []
    for idx in sorted(rows.keys(), key=lambda s: (len(s), s)):
        out.append(build(rows[idx]))
    return out
