"""SSH gateway — pure helpers shared by the API handlers and the sidecar daemon.

The gateway (server/sshgw/remotepower-sshgw.py) lets an operator reach a
managed host with a normal SSH client and no inbound port on the host:

    ssh -J alice@gw.example.com:2222 root@web01.rp

The operator's SSH session stays end-to-end encrypted to the host's own sshd.
The gateway only checks who is asking (their public key, registered in
RemotePower) and whether their role may reach that host, then relays bytes
through a WebSocket the AGENT opened outbound. Nothing on the host listens on
the network for this.

This module is stdlib-only and holds what is worth testing without a network:
public-key parsing and fingerprints, target-name resolution, and the binary
frame format of the agent tunnel. The agent carries its own copy of the frame
constants (it is a single file and cannot import this); a test pins the two
copies together.
"""

import base64
import hashlib
import re
import struct

# ── Public keys ────────────────────────────────────────────────────────────────

# Key types an operator may register. ssh-dss is gone from OpenSSH and is not
# accepted; RSA is accepted at 2048 bits or more.
ALLOWED_KEY_TYPES = (
    'ssh-ed25519',
    'sk-ssh-ed25519@openssh.com',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'sk-ecdsa-sha2-nistp256@openssh.com',
    'ssh-rsa',
)
MIN_RSA_BITS = 2048
MAX_KEYS_PER_USER = 20
MAX_KEY_LINE = 16384
MAX_KEY_NAME = 64

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
_NAME_RE = re.compile(r'^[\w .@:+-]{1,64}$')


def _read_string(blob, off):
    if off + 4 > len(blob):
        raise ValueError('truncated key')
    (n,) = struct.unpack('>I', blob[off:off + 4])
    off += 4
    if n > len(blob) - off:
        raise ValueError('truncated key')
    return blob[off:off + n], off + n


def parse_public_key(line):
    """Parse one OpenSSH public-key line ("type base64 [comment]").

    Returns {'type', 'blob' (bytes), 'b64', 'comment', 'fingerprint', 'bits'}
    or raises ValueError with a message an operator can act on. Options before
    the key type (authorized_keys style) are rejected: the gateway decides what
    a key may do, not the key line.
    """
    if not isinstance(line, str):
        raise ValueError('public key must be text')
    line = line.strip()
    if not line:
        raise ValueError('public key is empty')
    if len(line) > MAX_KEY_LINE:
        raise ValueError('public key is too long')
    if '\n' in line or '\r' in line:
        raise ValueError('paste one key per entry')
    parts = line.split(None, 2)
    if len(parts) < 2:
        raise ValueError('expected "<type> <base64> [comment]"')
    ktype, b64 = parts[0], parts[1]
    comment = parts[2].strip() if len(parts) > 2 else ''
    if ktype not in ALLOWED_KEY_TYPES:
        if ktype == 'ssh-dss':
            raise ValueError('DSA keys are not accepted; use ed25519')
        raise ValueError(f'unsupported key type {ktype[:40]!r}')
    if not _B64_RE.match(b64):
        raise ValueError('key data is not base64')
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        raise ValueError('key data is not base64') from None
    inner, off = _read_string(blob, 0)
    if inner.decode('ascii', 'replace') != ktype:
        raise ValueError('key type does not match the key data')
    bits = None
    if ktype == 'ssh-rsa':
        _e, off = _read_string(blob, off)
        n, off = _read_string(blob, off)
        bits = int.from_bytes(n, 'big').bit_length()
        if bits < MIN_RSA_BITS:
            raise ValueError(f'RSA keys need at least {MIN_RSA_BITS} bits (this one has {bits})')
    elif ktype == 'ssh-ed25519':
        pk, off = _read_string(blob, off)
        if len(pk) != 32:
            raise ValueError('malformed ed25519 key')
        bits = 256
    # Comments are free text in the wild; keep printable ASCII only.
    comment = ''.join(ch for ch in comment if 32 <= ord(ch) < 127)[:120]
    return {
        'type': ktype,
        'blob': blob,
        'b64': b64,
        'comment': comment,
        'fingerprint': fingerprint(blob),
        'bits': bits,
    }


def fingerprint(blob):
    """OpenSSH-style SHA256 fingerprint of a raw public-key blob."""
    digest = hashlib.sha256(blob).digest()
    return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')


_FP_RE = re.compile(r'^SHA256:[A-Za-z0-9+/]{43}$')


def valid_fingerprint(fp):
    return isinstance(fp, str) and bool(_FP_RE.match(fp))


def clean_key_name(name, fallback):
    name = (name or '').strip() if isinstance(name, str) else ''
    if not name:
        name = fallback or 'key'
    name = ''.join(ch for ch in name if ch.isprintable())[:MAX_KEY_NAME].strip()
    return name if _NAME_RE.match(name) else 'key'


# ── Targets ─────────────────────────────────────────────────────────────────────

# `web01.rp` and `web01` both name the device whose hostname or name is web01.
# The suffix lets an operator write one `Host *.rp` block in ~/.ssh/config.
TARGET_SUFFIX = '.rp'
_TARGET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')


def normalize_target(host):
    """Lower-cased target name with the .rp suffix removed, or '' if the name
    cannot be a device reference."""
    if not isinstance(host, str):
        return ''
    h = host.strip().rstrip('.').lower()
    if h.endswith(TARGET_SUFFIX):
        h = h[:-len(TARGET_SUFFIX)]
    return h if _TARGET_RE.match(h) else ''


def resolve_target(devices, host):
    """Map a target name to a device id.

    Returns (device_id, None) or (None, reason). Tried in order: an exact device
    id, then a unique match on the device name, then a unique match on the
    reported hostname (short or fully qualified). Two devices answering to the
    same name is an error, not a guess: connecting to the wrong host with a
    root shell is worse than refusing.
    """
    name = normalize_target(host)
    if not name:
        return None, 'invalid target name'
    devices = devices if isinstance(devices, dict) else {}
    for did in devices:
        if isinstance(did, str) and did.lower() == name:
            return did, None
    for field in ('name', 'hostname'):
        hits = []
        for did, dev in devices.items():
            if not isinstance(dev, dict):
                continue
            val = str(dev.get(field) or '').strip().rstrip('.').lower()
            if not val:
                continue
            if val == name or val.split('.', 1)[0] == name:
                hits.append(did)
        if len(hits) == 1:
            return hits[0], None
        if len(hits) > 1:
            return None, f'"{name}" matches {len(hits)} devices; use the device id'
    return None, f'no device named "{name}"'


# ── Agent tunnel frames ─────────────────────────────────────────────────────────
#
# One WebSocket per agent carries many SSH streams. Every binary message is one
# frame: 1-byte kind, 4-byte big-endian stream id, then the payload.
#
#   OPEN      gateway → agent   open a stream to the local sshd (no payload;
#                               the agent decides the port, never the gateway)
#   OPEN_OK   agent → gateway   the local connect succeeded
#   OPEN_FAIL agent → gateway   it did not; payload is a short UTF-8 reason
#   DATA      both ways         stream bytes
#   CLOSE     both ways         the stream is finished
#   PAUSE     both ways         stop sending DATA on this stream for now
#   RESUME    both ways         carry on
FRAME_OPEN = 1
FRAME_OPEN_OK = 2
FRAME_OPEN_FAIL = 3
FRAME_DATA = 4
FRAME_CLOSE = 5
FRAME_PAUSE = 6
FRAME_RESUME = 7
FRAME_KINDS = frozenset(range(1, 8))
FRAME_HEADER = struct.Struct('>BI')
MAX_FRAME_PAYLOAD = 64 * 1024
MAX_STREAM_ID = 0xFFFFFFFF


def encode_frame(kind, stream_id, payload=b''):
    if kind not in FRAME_KINDS:
        raise ValueError('bad frame kind')
    if not 0 < stream_id <= MAX_STREAM_ID:
        raise ValueError('bad stream id')
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise ValueError('frame payload too large')
    return FRAME_HEADER.pack(kind, stream_id) + bytes(payload)


def decode_frame(buf):
    """(kind, stream_id, payload) or ValueError on anything malformed."""
    if not isinstance(buf, (bytes, bytearray)):
        raise ValueError('frame must be binary')
    if len(buf) < FRAME_HEADER.size:
        raise ValueError('short frame')
    if len(buf) > FRAME_HEADER.size + MAX_FRAME_PAYLOAD:
        raise ValueError('frame too large')
    kind, sid = FRAME_HEADER.unpack_from(buf, 0)
    if kind not in FRAME_KINDS or sid == 0:
        raise ValueError('bad frame header')
    return kind, sid, bytes(buf[FRAME_HEADER.size:])
