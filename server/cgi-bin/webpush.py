#!/usr/bin/env python3
"""
v3.14.0 (#42): minimal Web Push (RFC 8030) sender — VAPID (RFC 8292) + the
aes128gcm content encoding (RFC 8188) keyed per RFC 8291. Built on the
`cryptography` library, which the server already depends on (tls_monitor.py,
cmdb_vault.py); NO new dependency.

Scope: just enough to push a small JSON notification to a browser PushManager
subscription. Not a general Web Push client. Stdlib `urllib` does the POST so
this stays dependency-light beyond `cryptography`.

The encryption is verified against the published RFC 8188 §3.1 test vector in
tests/test_v3140.py (so it interoperates with real push services, not just
with itself).
"""
import base64
import json
import os
import struct
import time
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64u_decode(s):
    if isinstance(s, str):
        s = s.encode('ascii')
    return base64.urlsafe_b64decode(s + b'=' * (-len(s) % 4))


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


# ─── VAPID (RFC 8292) ────────────────────────────────────────────────────────

def generate_vapid_keys():
    """Return (private_pem_str, public_key_b64url). The public key is the
    uncompressed P-256 point, base64url — what the browser passes as
    applicationServerKey."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode('ascii')
    pub_point = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    return pem, b64u_encode(pub_point)


def _load_priv(pem):
    return serialization.load_pem_private_key(pem.encode('ascii'), password=None)


def vapid_public_key_b64(pem):
    pub = _load_priv(pem).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return b64u_encode(pub)


def _es256_jwt(claims, priv):
    """Sign a JWT with ES256 (the VAPID requirement). cryptography produces a
    DER ECDSA signature; JWS wants raw r||s, so we convert."""
    header = b64u_encode(json.dumps({'typ': 'JWT', 'alg': 'ES256'},
                                    separators=(',', ':')).encode())
    body = b64u_encode(json.dumps(claims, separators=(',', ':')).encode())
    signing_input = f'{header}.{body}'.encode('ascii')
    der_sig = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return f'{header}.{body}.{b64u_encode(raw_sig)}'


def vapid_headers(endpoint, priv_pem, subject, now=None):
    """Authorization + Crypto-Key headers for a push to `endpoint`. `subject` is
    a contact mailto:/https: URI the push service can reach you at."""
    from urllib.parse import urlparse
    p = urlparse(endpoint)
    aud = f'{p.scheme}://{p.netloc}'
    now = int(now or time.time())
    priv = _load_priv(priv_pem)
    jwt = _es256_jwt({'aud': aud, 'exp': now + 12 * 3600, 'sub': subject}, priv)
    pub_b64 = vapid_public_key_b64(priv_pem)
    return {
        'Authorization': f'vapid t={jwt}, k={pub_b64}',
        # legacy header some push services still read
        'Crypto-Key': f'p256ecdsa={pub_b64}',
    }


# ─── aes128gcm content encoding (RFC 8188), keyed per RFC 8291 ────────────────

def _hkdf(salt, ikm, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


def aes128gcm_record(plaintext, ikm, salt, keyid=b'', rs=4096):
    """The RFC 8188 §2 aes128gcm content encoding for a single record, given the
    input keying material directly. Exposed so the published RFC 8188 §3.1 test
    vector can drive it (which is how we prove interoperability). Returns
    header(salt||rs||idlen||keyid) || ciphertext."""
    cek = _hkdf(salt, ikm, b'Content-Encoding: aes128gcm\x00', 16)
    nonce = _hkdf(salt, ikm, b'Content-Encoding: nonce\x00', 12)
    record = plaintext + b'\x02'        # single-record padding delimiter
    ciphertext = AESGCM(cek).encrypt(nonce, record, None)
    rs = max(rs, len(ciphertext) + 16)
    header = salt + struct.pack('>I', rs) + struct.pack('B', len(keyid)) + keyid
    return header + ciphertext


def encrypt_aes128gcm(plaintext, as_priv, salt, ua_pub_bytes, auth_secret):
    """Full RFC 8291 path: derive the IKM from an ECDH exchange + the auth
    secret, then emit the RFC 8188 record with our public key as the keyid.

      as_priv       — the application server's (our) EC private key object
      salt          — 16-byte content-encoding salt
      ua_pub_bytes  — the subscription's p256dh public point (65 bytes)
      auth_secret   — the subscription's 16-byte auth secret
    """
    as_pub_bytes = as_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ua_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_pub_bytes)
    ecdh_secret = as_priv.exchange(ec.ECDH(), ua_pub)
    # RFC 8291 §3.4: IKM from the ECDH secret, keyed by the auth secret.
    key_info = b'WebPush: info\x00' + ua_pub_bytes + as_pub_bytes
    ikm = _hkdf(auth_secret, ecdh_secret, key_info, 32)
    return aes128gcm_record(plaintext, ikm, salt, keyid=as_pub_bytes)


def encrypt(payload, p256dh_b64, auth_b64):
    """High-level: encrypt `payload` (bytes) for a subscription. Generates a
    fresh ephemeral key + salt each call. Returns the aes128gcm body."""
    as_priv = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(16)
    ua_pub_bytes = b64u_decode(p256dh_b64)
    auth_secret = b64u_decode(auth_b64)
    return encrypt_aes128gcm(payload, as_priv, salt, ua_pub_bytes, auth_secret)


def send(subscription, payload, vapid_priv_pem, subject, ttl=2419200, timeout=10,
         opener=None):
    """POST an encrypted notification to one subscription. `subscription` is the
    browser PushSubscription dict {endpoint, keys:{p256dh, auth}}. Returns the
    HTTP status; raises on transport error. 404/410 mean the subscription is
    gone and the caller should drop it.

    `opener`: optional SSRF-safe urllib opener injected by the caller — it
    rechecks the resolved peer IP at connect time and refuses redirects, closing
    the DNS-rebinding / redirect-to-metadata gap the (browser-supplied) endpoint
    preflight alone can't. Falls back to urlopen when not injected."""
    endpoint = subscription['endpoint']
    keys = subscription.get('keys') or {}
    body = encrypt(payload if isinstance(payload, bytes) else payload.encode(),
                   keys['p256dh'], keys['auth'])
    headers = {
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'TTL': str(ttl),
        'Content-Length': str(len(body)),
    }
    headers.update(vapid_headers(endpoint, vapid_priv_pem, subject))
    req = urllib.request.Request(endpoint, data=body, headers=headers, method='POST')
    try:
        _open = opener.open if opener is not None else urllib.request.urlopen
        with _open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
