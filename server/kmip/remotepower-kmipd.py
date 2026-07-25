#!/usr/bin/env python3
"""RemotePower — KMIP key-management sidecar (v6.4.1).

A minimal KMIP server (TTLV over mutually-authenticated TLS, port 5696) so
appliances that speak the KMIP client protocol — Synology DSM encrypted
volumes/shared folders, TrueNAS SED/dataset keys, VMware vSphere VM
encryption/vTPM, and generic PKCS#11-style clients — can keep their
encryption-key vault on the RemotePower server instead of on the same disks
they encrypt.

Architecture — a THIN PROTOCOL SHIM, deliberately stateless:
  * This daemon parses/serializes TTLV and terminates mTLS. Nothing else.
  * ALL object storage, at-rest encryption (AES-256-GCM via cmdb_vault
    primitives, master key held by the API process only), locking, client
    registration and the activity log live in api.py (kmip_handlers.py).
  * Every operation becomes ONE loopback HTTP call authenticated with a
    shared secret (`RP_KMIP_SECRET`, root-installed env file — the webterm
    daemon-secret pattern). The daemon holds no DATA_DIR access at all,
    which is why its systemd sandbox is even tighter than syslogd's.
  * TLS material + the registered-client fingerprint set are fetched from
    `GET /api/kmip/daemon/state` by a BACKGROUND THREAD every STATE_TTL_S and
    cached in memory. On a clock, not on traffic: the accept loop blocks, so a
    lazily-refreshed daemon with no clients yet never calls home at all and
    looks dead to the server. That poll doubles as the heartbeat, and it means
    enable/disable and client revocations land within STATE_TTL_S. A brief API
    restart does not drop the TLS listener; operations needing object access
    fail fast with a KMIP GeneralFailure and the client retries.

Client authentication is mandatory mTLS: the TLS handshake requires a
certificate signed by the RemotePower KMIP CA, and the peer certificate's
SHA-256 fingerprint must match a registered, non-revoked client. Unknown or
revoked fingerprints are dropped and logged (auth_fail) to the KMIP activity
log — every connection, auth failure and operation is traceable there.

KMIP coverage (the subset the supported appliances actually use — KMIP 1.x
message format, versions 1.0-1.4 negotiated):
  DiscoverVersions, Query, Register, Create, Get, GetAttributes,
  GetAttributeList, Activate, Locate, Revoke, Destroy.
Objects: SymmetricKey, SecretData, OpaqueObject.

Environment (the systemd unit sets these; defaults suit a standard install):
  RP_KMIP_BIND         listen address    (default 0.0.0.0:5696 — IANA KMIP)
  RP_KMIP_SERVER_URL   loopback API base (default http://127.0.0.1:8090)
  RP_KMIP_SECRET       shared daemon secret (normally injected by systemd
                       via EnvironmentFile=/etc/remotepower/kmipd.env)
"""

import base64
import json
import logging
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import urllib.request

log = logging.getLogger('remotepower-kmipd')
logging.basicConfig(level=logging.INFO,
                    format='[remotepower-kmipd] %(levelname)s %(message)s')

SERVER_URL = (os.environ.get('RP_KMIP_SERVER_URL')
              or 'http://127.0.0.1:8090').rstrip('/')
BIND = os.environ.get('RP_KMIP_BIND', '0.0.0.0:5696')
# Opt-in legacy TLS suites for appliances that offer nothing modern. Off by
# default: it disables forward secrecy and permits CBC, which is only worth it
# when the alternative is an appliance that cannot connect at all.
LEGACY_CIPHERS = (os.environ.get('RP_KMIP_LEGACY_CIPHERS') or '').strip() in ('1', 'true', 'yes')

STATE_TTL_S = 30          # registered-client / TLS-material refresh cadence
IDLE_TIMEOUT_S = 120      # per-connection socket timeout
MAX_MESSAGE = 1 << 20     # 1 MiB cap on a single KMIP request message
MAX_CONNS = 64            # concurrent connection cap
AUTH_FAIL_LOG_EVERY_S = 60   # per-peer-IP auth-failure log throttle
AUTH_FAIL_SEEN_MAX = 4096    # bound the throttle map (spoof-flood safety)
LEASE_TIME_S = 3600          # advertised lease for ObtainLease


def _secret():
    """The shared daemon secret. Env wins; systemd injects it from the
    root-owned /etc/remotepower/kmipd.env via EnvironmentFile."""
    return (os.environ.get('RP_KMIP_SECRET') or '').strip()


# ── TTLV codec ───────────────────────────────────────────────────────────────
# KMIP tag constants (OASIS KMIP 1.x tag registry, 0x42xxxx).
T_ACTIVATION_DATE = 0x420001
T_ATTRIBUTE = 0x420008
T_ATTRIBUTE_INDEX = 0x420009
T_ATTRIBUTE_NAME = 0x42000A
T_ATTRIBUTE_VALUE = 0x42000B
T_BATCH_COUNT = 0x42000D
T_BATCH_ITEM = 0x42000F
T_CRYPTO_ALGORITHM = 0x420028
T_CRYPTO_LENGTH = 0x42002A
T_CRYPTO_USAGE_MASK = 0x42002C
T_INITIAL_DATE = 0x420039
T_KEY = 0x42003F
T_KEY_BLOCK = 0x420040
T_KEY_FORMAT_TYPE = 0x420042
T_KEY_MATERIAL = 0x420043
T_KEY_VALUE = 0x420045
T_LAST_CHANGE_DATE = 0x420048
T_MAXIMUM_ITEMS = 0x42004F
T_NAME = 0x420053
T_NAME_TYPE = 0x420054
T_NAME_VALUE = 0x420055
T_OBJECT_TYPE = 0x420057
T_OPAQUE_DATA_TYPE = 0x420059
T_OPAQUE_DATA_VALUE = 0x42005A
T_OPAQUE_OBJECT = 0x42005B
T_OPERATION = 0x42005C
T_PROTOCOL_VERSION = 0x420069
T_PROTOCOL_VERSION_MAJOR = 0x42006A
T_PROTOCOL_VERSION_MINOR = 0x42006B
T_QUERY_FUNCTION = 0x420074
T_REQUEST_HEADER = 0x420077
T_REQUEST_MESSAGE = 0x420078
T_REQUEST_PAYLOAD = 0x420079
T_RESPONSE_HEADER = 0x42007A
T_RESPONSE_MESSAGE = 0x42007B
T_RESPONSE_PAYLOAD = 0x42007C
T_RESULT_MESSAGE = 0x42007D
T_RESULT_REASON = 0x42007E
T_RESULT_STATUS = 0x42007F
T_REVOCATION_REASON = 0x420081
T_REVOCATION_REASON_CODE = 0x420082
T_SECRET_DATA = 0x420085
T_SECRET_DATA_TYPE = 0x420086
T_SERVER_INFORMATION = 0x420088
T_STATE = 0x42008D
T_SYMMETRIC_KEY = 0x42008F
T_TEMPLATE_ATTRIBUTE = 0x420091
T_TIME_STAMP = 0x420092
T_UNIQUE_BATCH_ITEM_ID = 0x420093
T_UNIQUE_IDENTIFIER = 0x420094
T_VENDOR_IDENTIFICATION = 0x42009D

# TTLV item types.
TY_STRUCT = 0x01
TY_INT = 0x02
TY_LONG = 0x03
TY_BIGINT = 0x04
TY_ENUM = 0x05
TY_BOOL = 0x06
TY_TEXT = 0x07
TY_BYTES = 0x08
TY_DATETIME = 0x09
TY_INTERVAL = 0x0A

# Operation enumeration values (KMIP 1.x).
OP_CREATE = 0x01
OP_REGISTER = 0x03
OP_LOCATE = 0x08
OP_GET = 0x0A
OP_GET_ATTRIBUTES = 0x0B
OP_GET_ATTRIBUTE_LIST = 0x0C
OP_CHECK = 0x09
OP_ADD_ATTRIBUTE = 0x0D
OP_MODIFY_ATTRIBUTE = 0x0E
OP_DELETE_ATTRIBUTE = 0x0F
OP_OBTAIN_LEASE = 0x10
OP_GET_USAGE_ALLOCATION = 0x11
OP_ACTIVATE = 0x12
OP_REVOKE = 0x13
OP_DESTROY = 0x14
OP_ARCHIVE = 0x15
OP_RECOVER = 0x16
OP_QUERY = 0x18
OP_DISCOVER_VERSIONS = 0x1E

OP_NAMES = {
    OP_CREATE: 'create', OP_REGISTER: 'register', OP_LOCATE: 'locate',
    OP_GET: 'get', OP_GET_ATTRIBUTES: 'get_attributes',
    OP_GET_ATTRIBUTE_LIST: 'get_attribute_list', OP_ACTIVATE: 'activate',
    OP_REVOKE: 'revoke', OP_DESTROY: 'destroy', OP_QUERY: 'query',
    OP_DISCOVER_VERSIONS: 'discover_versions',
    # The rest of what a real appliance uses. The reference DSM setup's
    # PyKMIP policy grants exactly this set, which is the best available
    # statement of what DSM actually calls — a missing one is answered with
    # "operation not supported" and the appliance aborts the whole vault
    # setup with a generic error.
    OP_CHECK: 'check', OP_ADD_ATTRIBUTE: 'add_attribute',
    OP_MODIFY_ATTRIBUTE: 'modify_attribute',
    OP_DELETE_ATTRIBUTE: 'delete_attribute',
    OP_OBTAIN_LEASE: 'obtain_lease',
    OP_GET_USAGE_ALLOCATION: 'get_usage_allocation',
    OP_ARCHIVE: 'archive', OP_RECOVER: 'recover',
}

# Lease Time is an Interval; Last Change Date a DateTime (KMIP 1.x registry).
T_LEASE_TIME = 0x42004A

# Object type enumeration.
OT_CERTIFICATE = 1
OT_SYMMETRIC_KEY = 2
OT_SECRET_DATA = 7
OT_OPAQUE = 8
OT_NAMES = {OT_SYMMETRIC_KEY: 'symmetric_key', OT_SECRET_DATA: 'secret_data',
            OT_OPAQUE: 'opaque'}
OT_BY_NAME = {v: k for k, v in OT_NAMES.items()}

# Result status / reason enumerations.
RS_SUCCESS = 0
RS_FAILED = 1
RR_ITEM_NOT_FOUND = 0x01
RR_AUTH_FAILED = 0x03
RR_INVALID_MESSAGE = 0x04
RR_OP_NOT_SUPPORTED = 0x05
RR_MISSING_DATA = 0x06
RR_INVALID_FIELD = 0x07
RR_PERMISSION_DENIED = 0x0B
RR_ILLEGAL_STATE = 0x0D          # object state forbids the operation
RR_GENERAL_FAILURE = 0x100

# Key format type enumeration.
KF_RAW = 0x01
KF_OPAQUE = 0x02
KF_TRANSPARENT_SYMMETRIC = 0x07

# Supported protocol versions, server preference order.
VERSIONS = ((1, 4), (1, 3), (1, 2), (1, 1), (1, 0))


def ttlv_encode(items):
    """Encode a list of (tag, type, value) items to TTLV bytes.
    A TY_STRUCT value is a nested list of items."""
    out = bytearray()
    for tag, ty, val in items:
        if ty == TY_STRUCT:
            body = ttlv_encode(val)
        elif ty in (TY_INT, TY_ENUM, TY_INTERVAL):
            body = struct.pack('>I', int(val) & 0xFFFFFFFF)
        elif ty in (TY_LONG, TY_DATETIME):
            body = struct.pack('>q', int(val))
        elif ty == TY_BOOL:
            body = struct.pack('>q', 1 if val else 0)
        elif ty == TY_TEXT:
            body = str(val).encode('utf-8')
        elif ty == TY_BYTES:
            body = bytes(val)
        else:
            raise ValueError(f'unsupported TTLV type {ty}')
        out += struct.pack('>I', tag)[1:]          # 3-byte tag
        out.append(ty)
        out += struct.pack('>I', len(body))
        out += body
        pad = (8 - len(body) % 8) % 8
        if ty not in (TY_STRUCT,):
            out += b'\x00' * pad
    return bytes(out)


def ttlv_decode(buf, offset=0, end=None):
    """Decode TTLV bytes → list of (tag, type, value). Struct values nest."""
    items = []
    end = len(buf) if end is None else end
    while offset + 8 <= end:
        tag = struct.unpack('>I', b'\x00' + buf[offset:offset + 3])[0]
        ty = buf[offset + 3]
        (length,) = struct.unpack('>I', buf[offset + 4:offset + 8])
        offset += 8
        if offset + length > end:
            raise ValueError('TTLV item overruns buffer')
        raw = buf[offset:offset + length]
        if ty == TY_STRUCT:
            val = ttlv_decode(buf, offset, offset + length)
        elif ty in (TY_INT, TY_ENUM, TY_INTERVAL):
            val = struct.unpack('>I', raw[:4])[0]
        elif ty in (TY_LONG, TY_DATETIME):
            val = struct.unpack('>q', raw[:8])[0]
        elif ty == TY_BOOL:
            val = bool(struct.unpack('>q', raw[:8])[0])
        elif ty == TY_TEXT:
            val = raw.decode('utf-8', errors='replace')
        elif ty == TY_BYTES:
            val = bytes(raw)
        elif ty == TY_BIGINT:
            val = int.from_bytes(raw, 'big', signed=True)
        else:
            val = bytes(raw)
        items.append((tag, ty, val))
        offset += length
        if ty != TY_STRUCT:
            offset += (8 - length % 8) % 8
    return items


def _find(items, tag):
    """First item with `tag` → (type, value) or None."""
    for t, ty, v in items:
        if t == tag:
            return ty, v
    return None


def _find_val(items, tag, default=None):
    hit = _find(items, tag)
    return hit[1] if hit else default


def _find_all(items, tag):
    return [(ty, v) for t, ty, v in items if t == tag]


def _parse_attributes(items):
    """TemplateAttribute/Attribute list → {name, algorithm, length, usage_mask,
    raw attribute list}. KMIP 1.x Attribute = {AttributeName, [Index], Value}."""
    out = {'name': None, 'algorithm': None, 'length': None, 'usage_mask': None}
    for ty, val in _find_all(items, T_ATTRIBUTE):
        if ty != TY_STRUCT:
            continue
        aname = _find_val(val, T_ATTRIBUTE_NAME, '')
        avalue = _find(val, T_ATTRIBUTE_VALUE)
        if avalue is None:
            continue
        aty, av = avalue
        low = str(aname).strip().lower()
        if low == 'name' and aty == TY_STRUCT:
            out['name'] = str(_find_val(av, T_NAME_VALUE, '') or '')
        elif low == 'cryptographic algorithm':
            out['algorithm'] = int(av) if not isinstance(av, list) else None
        elif low == 'cryptographic length':
            out['length'] = int(av) if not isinstance(av, list) else None
        elif low == 'cryptographic usage mask':
            out['usage_mask'] = int(av) if not isinstance(av, list) else None
    return out


def _parse_managed_object(items):
    """Extract (object_type_enum, key_format, material bytes, algorithm,
    length, secret_data_type, opaque_data_type) from a Register payload."""
    # nosec B105 — 'secret_data_type' is the KMIP SecretDataType enum field
    # name (Password=1 / Seed=2), not a credential value.
    info = {'material': None, 'key_format': None, 'algorithm': None,
            'length': None, 'secret_data_type': None,  # nosec B105
            'opaque_data_type': None}

    def _from_key_block(kb):
        info['key_format'] = _find_val(kb, T_KEY_FORMAT_TYPE)
        info['algorithm'] = _find_val(kb, T_CRYPTO_ALGORITHM, info['algorithm'])
        info['length'] = _find_val(kb, T_CRYPTO_LENGTH, info['length'])
        kv = _find(kb, T_KEY_VALUE)
        if not kv:
            return
        kty, kval = kv
        if kty == TY_STRUCT:
            km = _find(kval, T_KEY_MATERIAL)
            if km:
                mty, mval = km
                if mty == TY_BYTES:
                    info['material'] = mval
                elif mty == TY_STRUCT:
                    # TransparentSymmetricKey: KeyMaterial{Key ByteString}
                    key = _find(mval, T_KEY)
                    if key and key[0] == TY_BYTES:
                        info['material'] = key[1]
        elif kty == TY_BYTES:
            # KeyValue delivered as an opaque byte blob (wrapped form).
            info['material'] = kval

    sym = _find(items, T_SYMMETRIC_KEY)
    sec = _find(items, T_SECRET_DATA)
    opq = _find(items, T_OPAQUE_OBJECT)
    if sym and sym[0] == TY_STRUCT:
        kb = _find(sym[1], T_KEY_BLOCK)
        if kb and kb[0] == TY_STRUCT:
            _from_key_block(kb[1])
        return OT_SYMMETRIC_KEY, info
    if sec and sec[0] == TY_STRUCT:
        info['secret_data_type'] = _find_val(sec[1], T_SECRET_DATA_TYPE)
        kb = _find(sec[1], T_KEY_BLOCK)
        if kb and kb[0] == TY_STRUCT:
            _from_key_block(kb[1])
        return OT_SECRET_DATA, info
    if opq and opq[0] == TY_STRUCT:
        info['opaque_data_type'] = _find_val(opq[1], T_OPAQUE_DATA_TYPE)
        od = _find(opq[1], T_OPAQUE_DATA_VALUE)
        if od and od[0] == TY_BYTES:
            info['material'] = od[1]
        return OT_OPAQUE, info
    return None, info


def _attr_value_to_json(aval):
    """A TTLV AttributeValue reduced to something JSON can carry."""
    if not aval:
        return None
    ty, val = aval
    if ty == TY_BYTES:
        return {'_b64': base64.b64encode(val).decode()}
    if ty == TY_STRUCT:
        # Named structures (Name, Cryptographic Parameters …) — keep the
        # readable leaves so the UI can show something meaningful.
        out = {}
        for t, sty, sv in val:
            if sty in (TY_TEXT, TY_INT, TY_ENUM, TY_LONG, TY_DATETIME, TY_BOOL):
                out[hex(t)] = sv
        return out or None
    return val


def _key_block(obj):
    """Server-side object dict → KeyBlock TTLV items."""
    material = base64.b64decode(obj.get('material_b64') or '')
    kb = [(T_KEY_FORMAT_TYPE, TY_ENUM, obj.get('key_format') or KF_RAW),
          (T_KEY_VALUE, TY_STRUCT, [(T_KEY_MATERIAL, TY_BYTES, material)])]
    if obj.get('algorithm'):
        kb.append((T_CRYPTO_ALGORITHM, TY_ENUM, obj['algorithm']))
    if obj.get('length'):
        kb.append((T_CRYPTO_LENGTH, TY_INT, obj['length']))
    return kb


def _managed_object_items(obj):
    """Server-side object dict → the object structure for a Get response."""
    ot = OT_BY_NAME.get(obj.get('object_type'), OT_SECRET_DATA)
    if ot == OT_SYMMETRIC_KEY:
        return ot, (T_SYMMETRIC_KEY, TY_STRUCT,
                    [(T_KEY_BLOCK, TY_STRUCT, _key_block(obj))])
    if ot == OT_OPAQUE:
        material = base64.b64decode(obj.get('material_b64') or '')
        return ot, (T_OPAQUE_OBJECT, TY_STRUCT,
                    [(T_OPAQUE_DATA_TYPE, TY_ENUM, obj.get('opaque_data_type') or 1),
                     (T_OPAQUE_DATA_VALUE, TY_BYTES, material)])
    body = [(T_SECRET_DATA_TYPE, TY_ENUM, obj.get('secret_data_type') or 1),
            (T_KEY_BLOCK, TY_STRUCT, _key_block(obj))]
    return OT_SECRET_DATA, (T_SECRET_DATA, TY_STRUCT, body)


def _attr_items(obj, names=None):
    """Server-side object dict → Attribute TTLV items (GetAttributes)."""
    want = {n.strip().lower() for n in names} if names else None

    def _want(n):
        return want is None or n in want

    out = []

    def _add(name, ty, val):
        out.append((T_ATTRIBUTE, TY_STRUCT,
                    [(T_ATTRIBUTE_NAME, TY_TEXT, name),
                     (T_ATTRIBUTE_VALUE, ty, val)]))

    if _want('unique identifier'):
        _add('Unique Identifier', TY_TEXT, obj['uid'])
    if _want('object type'):
        _add('Object Type', TY_ENUM, OT_BY_NAME.get(obj.get('object_type'), OT_SECRET_DATA))
    if _want('state'):
        _add('State', TY_ENUM, obj.get('state_enum') or 1)
    if obj.get('name') and _want('name'):
        _add('Name', TY_STRUCT, [(T_NAME_VALUE, TY_TEXT, obj['name']),
                                 (T_NAME_TYPE, TY_ENUM, 1)])
    if obj.get('algorithm') and _want('cryptographic algorithm'):
        _add('Cryptographic Algorithm', TY_ENUM, obj['algorithm'])
    if obj.get('length') and _want('cryptographic length'):
        _add('Cryptographic Length', TY_INT, obj['length'])
    if obj.get('created') and _want('initial date'):
        _add('Initial Date', TY_DATETIME, int(obj['created']))
    if obj.get('activated') and _want('activation date'):
        _add('Activation Date', TY_DATETIME, int(obj['activated']))
    if obj.get('updated') and _want('last change date'):
        _add('Last Change Date', TY_DATETIME, int(obj['updated']))
    return out


_ATTR_NAME_LIST = ('Unique Identifier', 'Object Type', 'State', 'Name',
                   'Cryptographic Algorithm', 'Cryptographic Length',
                   'Initial Date', 'Activation Date', 'Last Change Date')


# ── loopback API client ──────────────────────────────────────────────────────
class ApiClient:
    """All state lives behind these three endpoints in api.py."""

    def _call(self, path, payload=None, timeout=10):
        req = urllib.request.Request(
            f'{SERVER_URL}{path}',
            data=(json.dumps(payload).encode() if payload is not None else None),
            headers={'Content-Type': 'application/json',
                     'X-KMIP-Secret': _secret(),
                     'User-Agent': 'RemotePower-Kmipd'},
            method='POST' if payload is not None else 'GET')
        # nosec B310 — SERVER_URL is a fixed loopback base from the systemd
        # unit (http://127.0.0.1:8090), never attacker-influenced; the path is
        # a literal. No file:/ or custom scheme can reach here.
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
            return json.loads(r.read().decode() or '{}')

    def state(self):
        return self._call('/api/kmip/daemon/state')

    def op(self, payload):
        """One KMIP operation → {'ok': True, ...} or {'ok': False, 'reason',
        'message'}. Raises on transport failure (API down)."""
        return self._call('/api/kmip/daemon/op', payload)

    def event(self, payload):
        """Best-effort activity-log event (connect / auth_fail / started)."""
        try:
            self._call('/api/kmip/daemon/event', payload, timeout=5)
        except Exception as e:
            log.debug('event post failed: %s', e)


# ── server state (TLS material + client registry), TTL-cached ────────────────
class ServerState:
    def __init__(self, api):
        self.api = api
        self._lock = threading.Lock()
        self._state = None
        self._ctx = None
        self._rev = None
        self._at = 0.0

    def refresh(self, force=False):
        with self._lock:
            if not force and self._state is not None \
                    and time.monotonic() - self._at < STATE_TTL_S:
                return self._state
            try:
                st = self.api.state()
            except Exception as e:
                # A 403 means the secret does not match what the API has —
                # the one failure an operator cannot guess from the outside,
                # so say it plainly and every time rather than once.
                if getattr(e, 'code', None) == 403:
                    log.error('control plane REJECTED our secret (403). The '
                              'value in %s does not match the one the server '
                              'has. Re-run the install snippet from the KMIP '
                              'page, then restart this service.',
                              os.environ.get('RP_KMIP_SECRET_FILE',
                                             '/etc/remotepower/kmipd.env'))
                elif self._state is None:
                    log.warning('control plane unreachable (%s) — retrying', e)
                else:
                    log.debug('state refresh failed (%s) — keeping cached', e)
                return self._state
            self._at = time.monotonic()
            if st.get('rev') != self._rev:
                ctx = self._build_ctx(st)
                if ctx is not None:
                    self._ctx = ctx
                    self._rev = st.get('rev')
            self._state = st
            return self._state

    @staticmethod
    def _build_ctx(st):
        """TLS context from PEM material. The private key only ever touches
        PrivateTmp (unit sandbox) for the duration of load_cert_chain."""
        ca = st.get('ca_pem') or ''
        cert = st.get('server_cert_pem') or ''
        key = st.get('server_key_pem') or ''
        if not (ca and cert and key):
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.verify_mode = ssl.CERT_REQUIRED
            if LEGACY_CIPHERS:
                # Opt-in, OFF by default. Some appliances only offer legacy
                # suites — the community DSM setup pins
                # TLS_RSA_WITH_AES_256_CBC_SHA256, which modern OpenSSL
                # disables (no forward secrecy, CBC). Enabling it lowers the
                # security level for THIS listener only; it is a deliberate
                # trade to make an otherwise-impossible appliance work, never
                # the default.
                try:
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=1:AES256-SHA256:AES256-SHA')
                    log.warning('legacy cipher suites ENABLED '
                                '(RP_KMIP_LEGACY_CIPHERS=1) — required by some '
                                'appliances, but weaker than the default set')
                except ssl.SSLError as e:
                    log.error('could not enable legacy ciphers: %s', e)
            ctx.load_verify_locations(cadata=ca)
            kf = cf = None
            try:
                with tempfile.NamedTemporaryFile('w', suffix='.pem',
                                                 delete=False) as f:
                    f.write(cert)
                    cf = f.name
                with tempfile.NamedTemporaryFile('w', suffix='.pem',
                                                 delete=False) as f:
                    f.write(key)
                    kf = f.name
                os.chmod(kf, 0o600)
                ctx.load_cert_chain(cf, kf)
            finally:
                for p in (cf, kf):
                    if p:
                        try:
                            os.unlink(p)
                        except OSError:
                            pass
            return ctx
        except Exception as e:
            log.error('TLS context build failed: %s', e)
            return None

    def context(self):
        self.refresh()
        return self._ctx

    def client_for(self, fingerprint):
        st = self.refresh() or {}
        for c in st.get('clients') or []:
            if c.get('fingerprint') == fingerprint:
                return c
        return None

    def enabled(self):
        st = self.refresh() or {}
        return bool(st.get('enabled'))


# ── KMIP request handling ────────────────────────────────────────────────────
def _error_item(op, reason, message, batch_id=None):
    body = [(T_OPERATION, TY_ENUM, op)]
    if batch_id is not None:
        body.append((T_UNIQUE_BATCH_ITEM_ID, TY_BYTES, batch_id))
    body += [(T_RESULT_STATUS, TY_ENUM, RS_FAILED),
             (T_RESULT_REASON, TY_ENUM, reason),
             (T_RESULT_MESSAGE, TY_TEXT, message)]
    return (T_BATCH_ITEM, TY_STRUCT, body)


_API_REASONS = {'not_found': RR_ITEM_NOT_FOUND, 'invalid': RR_INVALID_FIELD,
                'missing': RR_MISSING_DATA, 'state': RR_ILLEGAL_STATE,
                'denied': RR_PERMISSION_DENIED,
                'unsupported': RR_OP_NOT_SUPPORTED}


def handle_message(raw, client, api):
    """One TTLV request message → TTLV response bytes.
    `client` is the registered-client dict from ServerState.client_for()."""
    try:
        top = ttlv_decode(raw)
        req = _find_val(top, T_REQUEST_MESSAGE)
        if req is None:
            raise ValueError('no RequestMessage')
        header = _find_val(req, T_REQUEST_HEADER) or []
        pv = _find_val(header, T_PROTOCOL_VERSION) or []
        pv_major = int(_find_val(pv, T_PROTOCOL_VERSION_MAJOR, 1) or 1)
        pv_minor = int(_find_val(pv, T_PROTOCOL_VERSION_MINOR, 0) or 0)
        batch = [v for t, ty, v in req if t == T_BATCH_ITEM and ty == TY_STRUCT]
    except Exception as e:
        log.info('malformed request from %s: %s', client.get('name'), e)
        pv_major, pv_minor, batch = 1, 0, []
        resp_items = [_error_item(0, RR_INVALID_MESSAGE, 'malformed request')]
        return _wrap_response(pv_major, pv_minor, resp_items)

    resp_items = []
    id_placeholder = None
    for item in batch:
        op = int(_find_val(item, T_OPERATION, 0) or 0)
        batch_id = _find_val(item, T_UNIQUE_BATCH_ITEM_ID)
        payload = _find_val(item, T_REQUEST_PAYLOAD) or []
        try:
            result, id_placeholder = _handle_op(op, payload, client, api,
                                                id_placeholder)
            body = [(T_OPERATION, TY_ENUM, op)]
            if batch_id is not None:
                body.append((T_UNIQUE_BATCH_ITEM_ID, TY_BYTES, batch_id))
            body.append((T_RESULT_STATUS, TY_ENUM, RS_SUCCESS))
            if result is not None:
                body.append((T_RESPONSE_PAYLOAD, TY_STRUCT, result))
            resp_items.append((T_BATCH_ITEM, TY_STRUCT, body))
        except KmipOpError as e:
            # A protocol-level rejection never reached the activity log, so an
            # appliance aborting on "operation not supported" was invisible in
            # the UI — the operator saw a generic appliance error and had
            # nothing on this side to look at. Report every one, with the
            # numeric code, so an unimplemented operation names itself.
            log.info('op %s from %s rejected: %s',
                     OP_NAMES.get(op, hex(op)), client.get('name'), e.message)
            _report(api, {'kind': 'op_failed', 'client_id': client.get('id'),
                          'op': OP_NAMES.get(op, hex(op)),
                          'detail': f'{e.message} (operation {hex(op)})'})
            resp_items.append(_error_item(op, e.reason, e.message, batch_id))
        except Exception as e:
            log.warning('op %s failed for %s: %s',
                        OP_NAMES.get(op, hex(op)), client.get('name'), e)
            _report(api, {'kind': 'op_failed', 'client_id': client.get('id'),
                          'op': OP_NAMES.get(op, hex(op)),
                          'detail': f'control plane unavailable: {e}'})
            resp_items.append(_error_item(
                op, RR_GENERAL_FAILURE, 'control plane unavailable', batch_id))
    return _wrap_response(pv_major, pv_minor, resp_items)


def _report(api, payload):
    """Best-effort activity-log post. Reporting a failure must never turn into
    a second failure — the client is still owed a response."""
    try:
        api.event(payload)
    except Exception as e:                       # incl. a stubbed api client
        log.debug('event post failed: %s', e)


def _wrap_response(pv_major, pv_minor, batch_items):
    header = [(T_PROTOCOL_VERSION, TY_STRUCT,
               [(T_PROTOCOL_VERSION_MAJOR, TY_INT, pv_major),
                (T_PROTOCOL_VERSION_MINOR, TY_INT, pv_minor)]),
              (T_TIME_STAMP, TY_DATETIME, int(time.time())),
              (T_BATCH_COUNT, TY_INT, len(batch_items))]
    msg = [(T_RESPONSE_MESSAGE, TY_STRUCT,
            [(T_RESPONSE_HEADER, TY_STRUCT, header)] + batch_items)]
    return ttlv_encode(msg)


class KmipOpError(Exception):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason
        self.message = message


def _api_op(api, client, op_name, params):
    """Call the API op endpoint; translate failures to KMIP errors."""
    try:
        resp = api.op({'client_id': client.get('id'),
                       'fingerprint': client.get('fingerprint'),
                       'op': op_name, 'params': params})
    except Exception as e:
        log.warning('control plane call failed (%s %s): %s',
                    op_name, client.get('name'), e)
        raise KmipOpError(RR_GENERAL_FAILURE, 'control plane unavailable')
    if not isinstance(resp, dict) or not resp.get('ok'):
        reason = _API_REASONS.get((resp or {}).get('reason'),
                                  RR_GENERAL_FAILURE)
        raise KmipOpError(reason, (resp or {}).get('message') or 'failed')
    return resp


def _uid_from(payload, id_placeholder):
    uid = _find_val(payload, T_UNIQUE_IDENTIFIER)
    uid = str(uid).strip() if uid else (id_placeholder or '')
    if not uid:
        raise KmipOpError(RR_MISSING_DATA, 'unique identifier required')
    return uid


def _handle_op(op, payload, client, api, id_placeholder):
    """One batch item → (response payload items or None, new id_placeholder)."""
    if op == OP_DISCOVER_VERSIONS:
        asked = [(int(_find_val(v, T_PROTOCOL_VERSION_MAJOR, 0) or 0),
                  int(_find_val(v, T_PROTOCOL_VERSION_MINOR, 0) or 0))
                 for ty, v in _find_all(payload, T_PROTOCOL_VERSION)
                 if ty == TY_STRUCT]
        offer = [v for v in VERSIONS if not asked or v in asked]
        out = [(T_PROTOCOL_VERSION, TY_STRUCT,
                [(T_PROTOCOL_VERSION_MAJOR, TY_INT, ma),
                 (T_PROTOCOL_VERSION_MINOR, TY_INT, mi)]) for ma, mi in offer]
        return out, id_placeholder

    if op == OP_QUERY:
        out = []
        funcs = {int(v) for ty, v in _find_all(payload, T_QUERY_FUNCTION)}
        if not funcs or 1 in funcs:            # QueryOperations
            for o in sorted(OP_NAMES):
                out.append((T_OPERATION, TY_ENUM, o))
        if not funcs or 2 in funcs:            # QueryObjects
            for ot in (OT_SYMMETRIC_KEY, OT_SECRET_DATA, OT_OPAQUE):
                out.append((T_OBJECT_TYPE, TY_ENUM, ot))
        if not funcs or 3 in funcs:            # QueryServerInformation
            out.append((T_VENDOR_IDENTIFICATION, TY_TEXT,
                        'RemotePower KMIP server'))
            out.append((T_SERVER_INFORMATION, TY_STRUCT, []))
        return out, id_placeholder

    if op == OP_REGISTER:
        ot, info = _parse_managed_object(payload)
        if ot is None or info['material'] is None:
            raise KmipOpError(RR_INVALID_FIELD, 'unsupported object payload')
        attrs = _parse_attributes(_find_val(payload, T_TEMPLATE_ATTRIBUTE) or [])
        resp = _api_op(api, client, 'register', {
            'object_type': OT_NAMES.get(ot, 'secret_data'),
            'key_format': info['key_format'] or KF_RAW,
            'material_b64': base64.b64encode(info['material']).decode(),
            'algorithm': info['algorithm'] or attrs['algorithm'],
            'length': info['length'] or attrs['length'],
            'usage_mask': attrs['usage_mask'],
            'secret_data_type': info['secret_data_type'],
            'opaque_data_type': info['opaque_data_type'],
            'name': attrs['name'],
        })
        uid = resp['uid']
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op == OP_CREATE:
        ot = int(_find_val(payload, T_OBJECT_TYPE, OT_SYMMETRIC_KEY)
                 or OT_SYMMETRIC_KEY)
        if ot != OT_SYMMETRIC_KEY:
            raise KmipOpError(RR_INVALID_FIELD,
                              'only symmetric keys can be created')
        attrs = _parse_attributes(_find_val(payload, T_TEMPLATE_ATTRIBUTE) or [])
        resp = _api_op(api, client, 'create', {
            'algorithm': attrs['algorithm'] or 3,        # AES
            'length': attrs['length'] or 256,
            'usage_mask': attrs['usage_mask'],
            'name': attrs['name'],
        })
        uid = resp['uid']
        return [(T_OBJECT_TYPE, TY_ENUM, ot),
                (T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op == OP_GET:
        uid = _uid_from(payload, id_placeholder)
        resp = _api_op(api, client, 'get', {'uid': uid})
        obj = resp['object']
        ot, obj_item = _managed_object_items(obj)
        return [(T_OBJECT_TYPE, TY_ENUM, ot),
                (T_UNIQUE_IDENTIFIER, TY_TEXT, uid), obj_item], uid

    if op == OP_GET_ATTRIBUTES:
        uid = _uid_from(payload, id_placeholder)
        names = [str(v) for ty, v in _find_all(payload, T_ATTRIBUTE_NAME)]
        resp = _api_op(api, client, 'get_attributes', {'uid': uid})
        out = [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)]
        out += _attr_items(resp['object'], names or None)
        return out, uid

    if op == OP_GET_ATTRIBUTE_LIST:
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'get_attributes', {'uid': uid})
        out = [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)]
        out += [(T_ATTRIBUTE_NAME, TY_TEXT, n) for n in _ATTR_NAME_LIST]
        return out, uid

    if op == OP_LOCATE:
        attrs = _parse_attributes(payload)
        max_items = _find_val(payload, T_MAXIMUM_ITEMS)
        want_ot = _find_val(payload, T_OBJECT_TYPE)
        resp = _api_op(api, client, 'locate', {
            'name': attrs['name'],
            'object_type': OT_NAMES.get(int(want_ot)) if want_ot else None,
            'max_items': int(max_items) if max_items else None,
        })
        uids = resp.get('uids') or []
        out = [(T_UNIQUE_IDENTIFIER, TY_TEXT, u) for u in uids]
        return out, (uids[0] if uids else id_placeholder)

    if op == OP_ACTIVATE:
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'activate', {'uid': uid})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op == OP_REVOKE:
        uid = _uid_from(payload, id_placeholder)
        rr = _find_val(payload, T_REVOCATION_REASON) or []
        code = int(_find_val(rr, T_REVOCATION_REASON_CODE, 1) or 1)
        _api_op(api, client, 'revoke', {'uid': uid, 'reason_code': code})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op == OP_DESTROY:
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'destroy', {'uid': uid})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op == OP_CHECK:
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'check', {'uid': uid})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op in (OP_ADD_ATTRIBUTE, OP_MODIFY_ATTRIBUTE):
        uid = _uid_from(payload, id_placeholder)
        attr = _find(payload, T_ATTRIBUTE)
        if not attr or attr[0] != TY_STRUCT:
            raise KmipOpError(RR_MISSING_DATA, 'attribute required')
        name = str(_find_val(attr[1], T_ATTRIBUTE_NAME, '') or '')
        aval = _find(attr[1], T_ATTRIBUTE_VALUE)
        _api_op(api, client, 'set_attribute', {
            'uid': uid, 'name': name,
            'value': _attr_value_to_json(aval),
            'replace': op == OP_MODIFY_ATTRIBUTE})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid),
                (T_ATTRIBUTE, TY_STRUCT, attr[1])], uid

    if op == OP_DELETE_ATTRIBUTE:
        uid = _uid_from(payload, id_placeholder)
        name = str(_find_val(payload, T_ATTRIBUTE_NAME, '') or '')
        _api_op(api, client, 'delete_attribute', {'uid': uid, 'name': name})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid),
                (T_ATTRIBUTE, TY_STRUCT,
                 [(T_ATTRIBUTE_NAME, TY_TEXT, name)])], uid

    if op == OP_OBTAIN_LEASE:
        uid = _uid_from(payload, id_placeholder)
        resp = _api_op(api, client, 'get_attributes', {'uid': uid})
        obj = resp.get('object') or {}
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid),
                (T_LEASE_TIME, TY_INTERVAL, LEASE_TIME_S),
                (T_LAST_CHANGE_DATE, TY_DATETIME,
                 int(obj.get('updated') or obj.get('created') or time.time()))], uid

    if op == OP_GET_USAGE_ALLOCATION:
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'check', {'uid': uid})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    if op in (OP_ARCHIVE, OP_RECOVER):
        uid = _uid_from(payload, id_placeholder)
        _api_op(api, client, 'check', {'uid': uid})
        return [(T_UNIQUE_IDENTIFIER, TY_TEXT, uid)], uid

    raise KmipOpError(RR_OP_NOT_SUPPORTED,
                      f'operation {OP_NAMES.get(op, hex(op))} not supported')


# ── connection handling ──────────────────────────────────────────────────────
def _fingerprint(der):
    import hashlib
    return hashlib.sha256(der).hexdigest()


def _read_message(conn):
    """Read one complete TTLV message (outer item header declares length)."""
    head = b''
    while len(head) < 8:
        chunk = conn.recv(8 - len(head))
        if not chunk:
            return None
        head += chunk
    (length,) = struct.unpack('>I', head[4:8])
    if length > MAX_MESSAGE:
        raise ValueError(f'message too large ({length} bytes)')
    body = b''
    while len(body) < length:
        chunk = conn.recv(min(65536, length - len(body)))
        if not chunk:
            return None
        body += chunk
    return head + body


def handle_connection(conn, addr, state, api, sem):
    peer = addr[0]
    client = None
    try:
        conn.settimeout(IDLE_TIMEOUT_S)
        der = conn.getpeercert(binary_form=True)
        if not der:
            api.event({'kind': 'auth_fail', 'peer': peer,
                       'detail': 'no client certificate'})
            return
        fp = _fingerprint(der)
        client = state.client_for(fp)
        if client is None or client.get('revoked'):
            api.event({'kind': 'auth_fail', 'peer': peer, 'fingerprint': fp,
                       'detail': ('revoked client certificate' if client
                                  else 'unknown client certificate')})
            return
        api.event({'kind': 'connect', 'peer': peer,
                   'client_id': client.get('id'), 'fingerprint': fp})
        while True:
            raw = _read_message(conn)
            if raw is None:
                return
            resp = handle_message(raw, client, api)
            conn.sendall(resp)
    except (socket.timeout, TimeoutError):
        pass
    except ssl.SSLError as e:
        log.debug('TLS error from %s: %s', peer, e)
    except Exception as e:
        log.info('connection from %s (%s) errored: %s', peer,
                 (client or {}).get('name') or 'unauthenticated', e)
    finally:
        sem.release()
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


# OpenSSL's handshake errors name the protocol failure, not the operator's
# mistake. On a real DSM setup these three appear constantly and each means
# something completely different — one is the appliance rejecting US, one is us
# rejecting IT, and one is not TLS at all. Translate them, or every setup
# session is a guessing game.
_TLS_HINTS = (
    ('TLSV1_ALERT_UNKNOWN_CA',
     'the appliance does not trust our CA — it rejected our server '
     'certificate. Upload ca.crt (from the Add-client wizard) into the '
     "appliance's trusted/CA store"),
    ('UNABLE TO GET LOCAL ISSUER CERTIFICATE',
     'the appliance presented a certificate signed by a DIFFERENT CA — almost '
     'always an old client.crt kept after the CA was re-issued. Download the '
     'files again from the Add-client wizard (or Re-issue on its row) and '
     'reinstall all three on the appliance'),
    ('SELF-SIGNED CERTIFICATE',
     'the appliance presented its own self-signed certificate, not the '
     'client.crt issued here — it is sending its default certificate, or '
     'client.crt was never selected for KMIP'),
    ('SELF SIGNED CERTIFICATE',
     'the appliance presented its own self-signed certificate, not the '
     'client.crt issued here — it is sending its default certificate, or '
     'client.crt was never selected for KMIP'),
    ('CERTIFICATE_VERIFY_FAILED',
     'this server could not verify the certificate the appliance presented — '
     'it was not issued by this KMIP CA. Re-download the files from the '
     'Add-client wizard and reinstall them'),
    ('NO_SHARED_CIPHER',
     'no cipher suite in common. Older appliances offer only legacy suites '
     '(Synology DSM negotiates TLS_RSA_WITH_AES_256_CBC_SHA256) — set '
     'RP_KMIP_LEGACY_CIPHERS=1 in /etc/remotepower/kmipd.env and restart'),
    ('SSLV3_ALERT_HANDSHAKE_FAILURE',
     'the appliance rejected every cipher suite offered. Older appliances need '
     'the legacy suites — set RP_KMIP_LEGACY_CIPHERS=1 in the sidecar env file '
     'and restart'),
    ('TLSV1_ALERT_UNKNOWN_PSK_IDENTITY',
     'the appliance sent no client certificate — mutual TLS is mandatory; '
     'install client.crt + client.key on it'),
    ('PEER_DID_NOT_RETURN_A_CERTIFICATE',
     'the appliance sent no client certificate — mutual TLS is mandatory; '
     'install client.crt + client.key on it'),
    ('WRONG_VERSION_NUMBER',
     'the peer spoke plain TCP, not TLS — something connected to the port '
     'without TLS (a port scan or health check), or the client is configured '
     'for an unencrypted KMIP port'),
    ('UNSUPPORTED_PROTOCOL',
     'the appliance offered only TLS 1.0/1.1, which this server refuses — it '
     'requires TLS 1.2 or newer'),
    ('SSLV3_ALERT_CERTIFICATE_EXPIRED',
     "the appliance's client certificate has expired — use Re-issue on its "
     'row to mint a replacement (its stored keys are kept)'),
    ('TLSV1_ALERT_DECRYPT_ERROR',
     'the appliance rejected our certificate signature — usually a stale '
     'ca.crt after the server certificate was re-issued'),
)


def tls_error_hint(err):
    """Plain-language cause for an OpenSSL handshake failure, or None."""
    text = str(err).upper()
    for needle, hint in _TLS_HINTS:
        if needle in text:
            return hint
    return None


def state_refresher(state, stop=None, once=False):
    """Poll the control plane on a timer, forever.

    The accept loop below BLOCKS in `sock.accept()`, and the lazy refresh only
    runs once a client connects — so with no KMIP clients yet (the normal state
    right after install) the daemon never called the control plane at all, the
    server never recorded a check-in, and the page reported "the sidecar has
    not checked in" about a daemon that was running perfectly. The state fetch
    IS the heartbeat, so it has to be driven by a clock, not by traffic.

    It also means config changes (enable/disable, a new or revoked client)
    land within STATE_TTL_S instead of at the next connection.
    """
    while True:
        try:
            state.refresh(force=True)
        except Exception as e:                     # never let the thread die
            log.debug('state refresh failed: %s', e)
        if once:
            return
        if stop is not None and stop.wait(STATE_TTL_S):
            return
        if stop is None:
            time.sleep(STATE_TTL_S)


def serve():
    if not _secret():
        log.error('RP_KMIP_SECRET is not set — install /etc/remotepower/'
                  'kmipd.env (the KMIP page in the UI prints the exact '
                  'command) and restart. Refusing to start without it.')
        return 1
    host, _, port = BIND.rpartition(':')
    # nosec B104 — binding all interfaces is the FEATURE: the NAS/hypervisor
    # clients connect over the LAN. Access is gated by mandatory mutual TLS
    # (an unknown client certificate never gets past the handshake), and the
    # operator can pin a single interface with RP_KMIP_BIND. Same by-design
    # bind as remotepower-syslogd/flowd.
    host = host or '0.0.0.0'  # nosec B104
    api = ApiClient()
    state = ServerState(api)
    auth_fail_seen = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    sock.listen(16)
    log.info('KMIP listening on %s:%s (mTLS required) → %s',
             host, port, SERVER_URL)
    api.event({'kind': 'started', 'detail': f'listening on {host}:{port}'})
    # The heartbeat + config poll. Must run on its own thread: the accept loop
    # blocks, so a traffic-driven refresh leaves an idle daemon looking dead.
    threading.Thread(target=state_refresher, args=(state,),
                     name='kmip-state', daemon=True).start()
    sem = threading.Semaphore(MAX_CONNS)

    while True:
        try:
            plain, addr = sock.accept()
        except OSError:
            continue
        ctx = state.context()
        if ctx is None or not state.enabled():
            # Not configured/enabled yet (or control plane never reachable).
            plain.close()
            continue
        if not sem.acquire(blocking=False):
            log.warning('connection cap reached — dropping %s', addr[0])
            plain.close()
            continue
        try:
            plain.settimeout(15)
            conn = ctx.wrap_socket(plain, server_side=True)
        except (ssl.SSLError, OSError, socket.timeout, TimeoutError) as e:
            sem.release()
            now = time.monotonic()
            if now - auth_fail_seen.get(addr[0], 0) > AUTH_FAIL_LOG_EVERY_S:
                if len(auth_fail_seen) >= AUTH_FAIL_SEEN_MAX:
                    auth_fail_seen.clear()
                auth_fail_seen[addr[0]] = now
                _hint = tls_error_hint(e)
                if _hint:
                    log.info('TLS handshake failed from %s — %s (%s)',
                             addr[0], _hint, e)
                else:
                    log.info('TLS handshake failed from %s: %s', addr[0], e)
                api.event({'kind': 'auth_fail', 'peer': addr[0],
                           'detail': (f'TLS handshake failed — {_hint}'
                                      if _hint
                                      else f'TLS handshake failed: {e}')})
            plain.close()
            continue
        t = threading.Thread(target=handle_connection,
                             args=(conn, addr, state, api, sem), daemon=True)
        t.start()


def main():
    try:
        return serve() or 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        log.error('fatal: %s', e)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
