"""backup_crypto.py — at-rest encryption for disaster-recovery backups (v5.0.0 #C2).

The full backup tarball (`remotepower_data_*.tar.gz`) contains the entire data
directory — audit logs, configs, and the encrypted credentials vault. Writing it
plaintext to `backup_path` (often a mounted share or off-box copy) is the weakest
link. When an operator sets the `RP_BACKUP_PASSPHRASE` environment variable, the
server encrypts the tarball to `*.tar.gz.enc` and deletes the plaintext.

Design:
  - AES-256-GCM via the low-level streaming Cipher API, so a multi-GB backup is
    encrypted/decrypted in bounded memory (64 KiB chunks) — never loaded whole.
  - PBKDF2-SHA256(passphrase, salt, 600k iters) → 32-byte key (OWASP 2023 floor;
    matches cmdb_vault).
  - The passphrase comes ONLY from the environment — never persisted, never in
    the data dir (which would be circular: the thing the backup protects).

File format (`.enc`):
    MAGIC(8) | KDF_ITERS(4, big-endian) | salt(16) | nonce(12) | ciphertext… | tag(16)

The GCM tag is appended LAST; decryption seeks to read it before streaming the
ciphertext region, so verification still covers the whole stream.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Callable

MAGIC = b"RPBKENC1"
KDF_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN  # 8 + 4 + 16 + 12 = 40
_CHUNK = 64 * 1024


class BackupCryptoError(Exception):
    """Encryption/decryption failure (missing lib, bad passphrase, corrupt file)."""


def available() -> bool:
    """True when the `cryptography` library is importable (else encryption is a no-op)."""
    try:
        import cryptography.hazmat.primitives.ciphers  # noqa: F401

        return True
    except Exception:
        return False


def _ciphers():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        return Cipher, algorithms, modes, PBKDF2HMAC, hashes
    except Exception as exc:  # pragma: no cover - only when lib absent
        raise BackupCryptoError(
            "the 'cryptography' library is required for backup encryption"
        ) from exc


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not passphrase:
        raise BackupCryptoError("empty backup passphrase")
    _, _, _, PBKDF2HMAC, hashes = _ciphers()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, passphrase: str) -> Path:
    """Stream-encrypt `src` → `dst` (AES-256-GCM). Returns `dst`. Atomic via a
    `.tmp` sidecar + rename, written 0600. Raises BackupCryptoError on failure."""
    Cipher, algorithms, modes, _, _ = _ciphers()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt, KDF_ITERATIONS)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as out, open(src, "rb") as fin:
            out.write(MAGIC)
            out.write(struct.pack(">I", KDF_ITERATIONS))
            out.write(salt)
            out.write(nonce)
            while True:
                chunk = fin.read(_CHUNK)
                if not chunk:
                    break
                out.write(enc.update(chunk))
            out.write(enc.finalize())
            out.write(enc.tag)  # 16 bytes, trailing
        os.replace(str(tmp), str(dst))
    except Exception as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise BackupCryptoError(f"backup encryption failed: {exc}") from exc
    return dst


def decrypt_file(
    src: Path, dst: Path, passphrase: str, progress: Callable[[int], None] | None = None
) -> Path:
    """Stream-decrypt `src` (an `.enc` produced by `encrypt_file`) → `dst`.
    Raises BackupCryptoError on a wrong passphrase or tampering (GCM tag fail)."""
    Cipher, algorithms, modes, _, _ = _ciphers()
    size = src.stat().st_size
    if size < HEADER_LEN + TAG_LEN:
        raise BackupCryptoError("encrypted backup is truncated")
    with open(src, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise BackupCryptoError("not a RemotePower encrypted backup (bad magic)")
        iterations = struct.unpack(">I", fin.read(4))[0]
        salt = fin.read(SALT_LEN)
        nonce = fin.read(NONCE_LEN)
        # GCM tag is the trailing 16 bytes — read it before streaming the body.
        fin.seek(size - TAG_LEN)
        tag = fin.read(TAG_LEN)
        key = _derive_key(passphrase, salt, iterations)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        ct_len = size - HEADER_LEN - TAG_LEN
        fin.seek(HEADER_LEN)
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        remaining = ct_len
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = fin.read(min(_CHUNK, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    out.write(dec.update(chunk))
                    if progress:
                        progress(len(chunk))
                out.write(dec.finalize())  # raises InvalidTag on bad key/tamper
            os.replace(str(tmp), str(dst))
        except Exception as exc:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            raise BackupCryptoError(
                "backup decryption failed (wrong passphrase or corrupt file)"
            ) from exc
    return dst


def is_encrypted(path: Path) -> bool:
    """Cheap magic-byte sniff: does `path` look like an encrypted backup?"""
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False
