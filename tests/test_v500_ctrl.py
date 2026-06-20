"""v5.0.0 "CTRLMatters" — control-plane hardening tests.

Covers the T1 security spine landed so far:
  #C4 per-API-key rate limiting
  #C2 at-rest encrypted DR backups (backup_crypto module + api wiring)
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

# Import api against a throwaway data dir so the file-backed helpers are safe.
_DATA = tempfile.mkdtemp(prefix="rp-v500-")
os.environ["RP_DATA_DIR"] = _DATA
_spec = importlib.util.spec_from_file_location("api_v500", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import backup_crypto  # noqa: E402

API_SRC = (_CGI / "api.py").read_text()
APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
HTML = (_ROOT / "server" / "html" / "index.html").read_text()


# ─────────────────────────── #C4 per-API-key rate limit ────────────────────────
class TestApiKeyRateLimit(unittest.TestCase):
    def setUp(self):
        # fresh ratelimit store each test
        api.save(api.RATELIMIT_FILE, {})
        api._APIKEY_RL_CHECKED = False

    def test_key_ratelimit_window(self):
        # limit=3 → first 3 allowed, 4th denied within the same minute
        kid = "deadbeef"
        self.assertTrue(api._key_ratelimit(kid, 3))
        self.assertTrue(api._key_ratelimit(kid, 3))
        self.assertTrue(api._key_ratelimit(kid, 3))
        self.assertFalse(api._key_ratelimit(kid, 3))

    def test_zero_is_unlimited(self):
        kid = "cafef00d"
        for _ in range(50):
            self.assertTrue(api._key_ratelimit(kid, 0))

    def test_distinct_keys_independent(self):
        self.assertTrue(api._key_ratelimit("k1", 1))
        self.assertFalse(api._key_ratelimit("k1", 1))
        # different key id has its own bucket
        self.assertTrue(api._key_ratelimit("k2", 1))

    def test_enforce_charges_once_per_request(self):
        # the per-request guard means a second verify_token call doesn't
        # double-charge (auditor path calls verify_token twice).
        api._APIKEY_RL_CHECKED = False
        kid = "abcd1234"
        # 1/min limit: first enforce records a hit; second enforce is a no-op
        api._enforce_apikey_ratelimit(kid, {"rate_limit": 1})
        self.assertTrue(api._APIKEY_RL_CHECKED)
        # second call short-circuits (guard) → does NOT 429 even though the
        # bucket is now full
        api._enforce_apikey_ratelimit(kid, {"rate_limit": 1})

    def test_create_validates_and_persists_rate_limit(self):
        i = API_SRC.index("def handle_apikeys_create(")
        block = API_SRC[i:API_SRC.index("def handle_apikeys_delete(")]
        self.assertIn("rate_limit", block)
        self.assertIn("0..100000", block)
        self.assertIn("'rate_limit': rate_limit", block)
        # list endpoint returns it
        j = API_SRC.index("def handle_apikeys_list(")
        self.assertIn("'rate_limit'", API_SRC[j:j + 600])

    def test_verify_token_enforces(self):
        i = API_SRC.index("# API keys — full constant-time scan")
        self.assertIn("_enforce_apikey_ratelimit(matched_kid", API_SRC[i:i + 1400])

    def test_frontend_wires_rate(self):
        self.assertIn('id="apikey-rate"', HTML)
        self.assertIn('data-col="rate"', HTML)
        self.assertIn("body.rate_limit = rlVal", APP)
        self.assertIn("rate:    k.rate_limit", APP)


# ─────────────────────────── #C2 encrypted backups ─────────────────────────────
class TestBackupCryptoModule(unittest.TestCase):
    @unittest.skipUnless(backup_crypto.available(), "cryptography not installed")
    def test_roundtrip(self):
        d = Path(tempfile.mkdtemp())
        src = d / "plain.bin"
        src.write_bytes(os.urandom(200000))  # multi-chunk
        enc = d / "c.enc"
        dec = d / "out.bin"
        backup_crypto.encrypt_file(src, enc, "s3cr3t-passphrase")
        self.assertTrue(backup_crypto.is_encrypted(enc))
        self.assertFalse(backup_crypto.is_encrypted(src))
        backup_crypto.decrypt_file(enc, dec, "s3cr3t-passphrase")
        self.assertEqual(dec.read_bytes(), src.read_bytes())

    @unittest.skipUnless(backup_crypto.available(), "cryptography not installed")
    def test_wrong_passphrase_rejected(self):
        d = Path(tempfile.mkdtemp())
        src = d / "p.bin"
        src.write_bytes(b"top secret fleet data")
        enc = d / "c.enc"
        backup_crypto.encrypt_file(src, enc, "right")
        with self.assertRaises(backup_crypto.BackupCryptoError):
            backup_crypto.decrypt_file(enc, d / "x.bin", "wrong")

    @unittest.skipUnless(backup_crypto.available(), "cryptography not installed")
    def test_tamper_detected(self):
        d = Path(tempfile.mkdtemp())
        src = d / "p.bin"
        src.write_bytes(os.urandom(70000))
        enc = d / "c.enc"
        backup_crypto.encrypt_file(src, enc, "k")
        b = bytearray(enc.read_bytes())
        b[backup_crypto.HEADER_LEN + 10] ^= 0xFF  # flip a ciphertext byte
        enc.write_bytes(bytes(b))
        with self.assertRaises(backup_crypto.BackupCryptoError):
            backup_crypto.decrypt_file(enc, d / "x.bin", "k")

    def test_truncated_rejected(self):
        d = Path(tempfile.mkdtemp())
        bad = d / "short.enc"
        bad.write_bytes(backup_crypto.MAGIC + b"\x00\x00")
        with self.assertRaises(backup_crypto.BackupCryptoError):
            backup_crypto.decrypt_file(bad, d / "x", "k")


class TestBackupApiWiring(unittest.TestCase):
    def test_passphrase_from_env_only(self):
        self.assertIn("RP_BACKUP_PASSPHRASE", API_SRC)
        i = API_SRC.index("def _backup_passphrase(")
        self.assertIn("os.environ.get('RP_BACKUP_PASSPHRASE'", API_SRC[i:i + 400])

    def test_backup_run_encrypts(self):
        i = API_SRC.index("def _run_data_backup(")
        block = API_SRC[i:i + 3500]
        self.assertIn("backup_crypto.encrypt_file", block)
        self.assertIn("refusing to write a plaintext backup", block)
        self.assertIn(".tar.gz.enc", block)

    def test_restore_decrypts(self):
        i = API_SRC.index("def handle_backup_restore(")
        block = API_SRC[i:i + 2000]
        self.assertIn("backup_crypto.MAGIC", block)
        self.assertIn("X-RP-Backup-Passphrase", block)
        self.assertIn("backup_crypto.decrypt_file", block)

    def test_env_passphrase_helper(self):
        os.environ.pop("RP_BACKUP_PASSPHRASE", None)
        self.assertEqual(api._backup_passphrase(), "")
        os.environ["RP_BACKUP_PASSPHRASE"] = "  hunter2  "
        try:
            self.assertEqual(api._backup_passphrase(), "hunter2")
        finally:
            os.environ.pop("RP_BACKUP_PASSPHRASE", None)


if __name__ == "__main__":
    unittest.main()
