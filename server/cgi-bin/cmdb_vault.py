"""
RemotePower CMDB vault — v1.9.0
Symmetric-encrypted credential storage for the CMDB.

Crypto:
  - PBKDF2-SHA256(passphrase, salt, iterations) → 32-byte key
  - AES-GCM(key, 12-byte nonce, plaintext)      → ciphertext + tag

Design:
  - The passphrase is *never* persisted server-side. It is entered by an
    admin via the UI, the derived key is returned to the browser, and the
    browser sends the key back as a header on every credential operation.
  - A small canary blob is stored encrypted in the vault metadata so we
    can verify a candidate key without having to decrypt real data.
  - The cryptography library is imported lazily so the rest of the API
    stays usable on servers that don't have it installed yet.

This module is intentionally tiny — all the routing/auth/audit logic
lives in api.py. Keep it that way.
"""

import hmac
import os
import secrets

# Constants — bumping these is a breaking change. The vault file records
# whichever values were used at setup time so we can rotate later without
# losing access to existing data.
KDF_NAME = "pbkdf2-sha256"
KDF_ITERATIONS = 600_000  # OWASP 2023 minimum for PBKDF2-SHA256
KDF_KEY_LEN = 32  # 256-bit AES key
KDF_SALT_LEN = 32
GCM_NONCE_LEN = 12
CANARY_PLAINTEXT = b"RP_CMDB_VAULT_OK"

MIN_PASSPHRASE_LEN = 12
MAX_PASSPHRASE_LEN = 256

# Per-credential plaintext caps — applied at the api.py layer too, but we
# duplicate here so callers using this module standalone get sane behaviour.
MAX_USERNAME_LEN = 128
MAX_PASSWORD_LEN = 1024
MAX_LABEL_LEN = 64


class VaultError(Exception):
    """Base class for vault-related failures."""


class VaultLockedError(VaultError):
    """Raised when an operation requires an unlocked vault."""


class VaultKeyError(VaultError):
    """Raised on a bad passphrase / bad derived key."""


class VaultNotInstalledError(VaultError):
    """Raised when the cryptography library is missing."""


def _crypto() -> tuple:
    """Lazy import — keeps the rest of the API alive when cryptography is missing.

    Returns:
        Three-tuple of ``(hashes, PBKDF2HMAC, AESGCM)`` from
        ``cryptography.hazmat.primitives``.

    Raises:
        VaultNotInstalledError: The ``cryptography`` package is not
            available — caller should surface this as a 500 with a
            recovery hint pointing at ``install-server.sh``.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as e:
        raise VaultNotInstalledError(
            "Python 'cryptography' package is required for the CMDB vault. "
            "Re-run install-server.sh or 'pip install cryptography'."
        ) from e
    return hashes, PBKDF2HMAC, AESGCM


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-SHA256 → 32-byte key. Raises VaultKeyError on bad inputs."""
    if not isinstance(passphrase, str) or not passphrase:
        raise VaultKeyError("passphrase required")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise VaultKeyError("invalid salt")
    if not isinstance(iterations, int) or iterations < 100_000:
        raise VaultKeyError("iterations too low")

    hashes, PBKDF2HMAC, _ = _crypto()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KDF_KEY_LEN,
        salt=bytes(salt),
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def validate_passphrase(passphrase: str) -> "str | None":
    """Validate a candidate vault passphrase.

    Args:
        passphrase: The candidate string.

    Returns:
        ``None`` if the passphrase is acceptable, else a human-readable
        error string explaining why not. Caller surfaces the string to
        the UI.
    """
    if not isinstance(passphrase, str):
        return "passphrase must be a string"
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        return f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
    if len(passphrase) > MAX_PASSPHRASE_LEN:
        return f"passphrase must be at most {MAX_PASSPHRASE_LEN} characters"
    # Encourage some variety — at least two of: lower, upper, digit, symbol
    classes = sum(
        [
            any(c.islower() for c in passphrase),
            any(c.isupper() for c in passphrase),
            any(c.isdigit() for c in passphrase),
            any(not c.isalnum() for c in passphrase),
        ]
    )
    if classes < 2:
        return "passphrase must contain at least 2 of: lowercase, uppercase, digit, symbol"
    return None


def setup_vault(passphrase: str) -> dict:
    """Create a fresh vault metadata dict. Caller persists it."""
    err = validate_passphrase(passphrase)
    if err:
        raise VaultKeyError(err)

    _, _, AESGCM = _crypto()
    salt = secrets.token_bytes(KDF_SALT_LEN)
    key = _derive_key(passphrase, salt, KDF_ITERATIONS)
    nonce = secrets.token_bytes(GCM_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, CANARY_PLAINTEXT, None)
    return {
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "salt": salt.hex(),
        "canary_nonce": nonce.hex(),
        "canary_ct": ct.hex(),
    }


def derive_key_from_meta(passphrase: str, vault_meta: dict) -> bytes:
    """Re-derive the key using the params stored in cmdb_vault.json."""
    if not vault_meta:
        raise VaultLockedError("vault not configured")
    try:
        salt = bytes.fromhex(vault_meta["salt"])
        iterations = int(vault_meta.get("iterations", KDF_ITERATIONS))
    except (KeyError, ValueError, TypeError) as e:
        raise VaultKeyError(f"corrupt vault metadata: {e}")
    return _derive_key(passphrase, salt, iterations)


def verify_key(key: bytes, vault_meta: dict) -> bool:
    """Constant-time-ish check that `key` decrypts the canary correctly."""
    if not vault_meta:
        return False
    if not isinstance(key, (bytes, bytearray)) or len(key) != KDF_KEY_LEN:
        return False
    try:
        _, _, AESGCM = _crypto()
        nonce = bytes.fromhex(vault_meta["canary_nonce"])
        ct = bytes.fromhex(vault_meta["canary_ct"])
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ct, None)
    except VaultNotInstalledError:
        raise
    except Exception:
        return False
    return hmac.compare_digest(plaintext, CANARY_PLAINTEXT)


def encrypt(key: bytes, plaintext: str) -> dict:
    """Encrypt a UTF-8 string. Returns {'nonce': hex, 'ct': hex}."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KDF_KEY_LEN:
        raise VaultKeyError("invalid key")
    if not isinstance(plaintext, str):
        raise VaultError("plaintext must be a string")
    _, _, AESGCM = _crypto()
    nonce = secrets.token_bytes(GCM_NONCE_LEN)
    ct = AESGCM(bytes(key)).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"nonce": nonce.hex(), "ct": ct.hex()}


def decrypt(key: bytes, blob: dict) -> str:
    """Decrypt a {'nonce': hex, 'ct': hex} blob → UTF-8 string."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KDF_KEY_LEN:
        raise VaultKeyError("invalid key")
    if not isinstance(blob, dict) or "nonce" not in blob or "ct" not in blob:
        raise VaultError("invalid ciphertext blob")
    try:
        nonce = bytes.fromhex(blob["nonce"])
        ct = bytes.fromhex(blob["ct"])
    except ValueError as e:
        raise VaultError(f"corrupt ciphertext blob: {e}")
    _, _, AESGCM = _crypto()
    try:
        pt = AESGCM(bytes(key)).decrypt(nonce, ct, None)
    except Exception as e:
        # Don't leak whether it's auth-tag failure vs key mismatch
        raise VaultKeyError("decryption failed") from e
    return pt.decode("utf-8")


def parse_key_header(value: str) -> bytes:
    """Decode a hex key sent in the X-RP-Vault-Key header. Strict on length."""
    if not isinstance(value, str) or not value:
        raise VaultLockedError("vault key header missing")
    value = value.strip()
    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise VaultKeyError("vault key must be hex")
    if len(key) != KDF_KEY_LEN:
        raise VaultKeyError(f"vault key must be {KDF_KEY_LEN} bytes")
    return key


def is_configured(vault_meta: dict) -> bool:
    """Truthy if a vault has been set up."""
    return bool(vault_meta and vault_meta.get("salt") and vault_meta.get("canary_ct"))
