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
APP_CMDB = (_ROOT / "server" / "html" / "static" / "js" / "app-cmdb.js").read_text()
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


# ─────────────────────────── #C3 break-glass reveals ───────────────────────────
class TestBreakGlass(unittest.TestCase):
    def setUp(self):
        api.save(api.BREAKGLASS_FILE, {})

    def test_open_creates_pending(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "root pw", "incident")
        self.assertTrue(rid.startswith("bg_"))
        store = api._breakglass_load()
        self.assertEqual(store[rid]["status"], "pending")
        self.assertEqual(store[rid]["requester"], "alice")

    def test_check_rejects_unapproved(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        ok, why = api._breakglass_check(rid, "dev1", "cred_aa", "alice")
        self.assertFalse(ok)
        self.assertIn("not approved", why)

    def test_full_two_person_flow(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        # second admin approves
        store = api._breakglass_load()
        store[rid]["status"] = "approved"
        store[rid]["approved_by"] = "bob"
        store[rid]["approved_at"] = int(__import__("time").time())
        api.save(api.BREAKGLASS_FILE, store)
        ok, why = api._breakglass_check(rid, "dev1", "cred_aa", "alice")
        self.assertTrue(ok, why)

    def test_self_approval_blocked(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        store = api._breakglass_load()
        store[rid].update(status="approved", approved_by="alice",
                          approved_at=int(__import__("time").time()))
        api.save(api.BREAKGLASS_FILE, store)
        ok, why = api._breakglass_check(rid, "dev1", "cred_aa", "alice")
        self.assertFalse(ok)
        self.assertIn("self-approval", why)

    def test_wrong_requester_blocked(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        store = api._breakglass_load()
        store[rid].update(status="approved", approved_by="bob",
                          approved_at=int(__import__("time").time()))
        api.save(api.BREAKGLASS_FILE, store)
        ok, why = api._breakglass_check(rid, "dev1", "cred_aa", "carol")
        self.assertFalse(ok)
        self.assertIn("original requester", why)

    def test_mismatched_cred_blocked(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        store = api._breakglass_load()
        store[rid].update(status="approved", approved_by="bob",
                          approved_at=int(__import__("time").time()))
        api.save(api.BREAKGLASS_FILE, store)
        ok, why = api._breakglass_check(rid, "dev1", "cred_BB", "alice")
        self.assertFalse(ok)

    def test_approval_expiry(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        store = api._breakglass_load()
        store[rid].update(status="approved", approved_by="bob",
                          approved_at=int(__import__("time").time()) - api._BREAKGLASS_TTL - 5)
        api.save(api.BREAKGLASS_FILE, store)
        ok, why = api._breakglass_check(rid, "dev1", "cred_aa", "alice")
        self.assertFalse(ok)
        self.assertIn("expired", why)

    def test_consume(self):
        rid = api._breakglass_open("alice", "dev1", "cred_aa", "l", "")
        api._breakglass_consume(rid)
        self.assertEqual(api._breakglass_load()[rid]["status"], "consumed")

    def test_event_registered_all_registries(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn("vault_break_glass", names)
        self.assertEqual(api._ALERT_RULES.get("vault_break_glass")[0], "high")
        # CHANNEL_KINDS row
        kinds = {row[0] for row in api.CHANNEL_KINDS}
        self.assertIn("break_glass", kinds)
        # title
        self.assertIn("Break-Glass", api._webhook_title("vault_break_glass"))
        # frontend FLEET_EVENTS + dispatch
        self.assertIn("vault_break_glass", APP)
        self.assertIn("data-home-act=\"cmdb\"", APP)

    def test_routing(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/cmdb/break-glass")[0],
                         "handle_breakglass_list")
        self.assertEqual(resolve_route("POST", "/api/cmdb/break-glass/bg_abc/approve")[0],
                         "handle_breakglass_approve")

    def test_cred_add_stores_flag(self):
        i = API_SRC.index("def handle_cmdb_credentials_add(")
        self.assertIn("'break_glass': bool(body.get('break_glass'))",
                      API_SRC[i:i + 4000])

    def test_frontend_wires(self):
        self.assertIn('id="cmdb-cred-breakglass"', HTML)
        self.assertIn('id="cmdb-breakglass-card"', HTML)
        self.assertIn("function loadBreakGlass", APP_CMDB)
        self.assertIn("cmdbBreakGlassApprove", APP_CMDB)


# ─────────────────────────── #C1 mutual TLS for agents ─────────────────────────
class TestAgentMtls(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {"dev1": {"token": "t", "mtls_fingerprint": ""}})
        for k in ("HTTP_X_SSL_CLIENT_VERIFY", "HTTP_X_SSL_CLIENT_FINGERPRINT",
                  "HTTP_X_SSL_CLIENT_DN"):
            os.environ.pop(k, None)

    def test_off_by_default_allows(self):
        ok, why = api._agent_mtls_ok("dev1")
        self.assertTrue(ok, why)

    def test_on_requires_verified_cert(self):
        api.save(api.CONFIG_FILE, {"require_agent_mtls": True})
        ok, why = api._agent_mtls_ok("dev1")
        self.assertFalse(ok)
        self.assertIn("no verified client certificate", why)

    def test_on_with_verified_cert_allows(self):
        api.save(api.CONFIG_FILE, {"require_agent_mtls": True})
        os.environ["HTTP_X_SSL_CLIENT_VERIFY"] = "SUCCESS"
        os.environ["HTTP_X_SSL_CLIENT_FINGERPRINT"] = "aabbcc"
        ok, why = api._agent_mtls_ok("dev1")
        self.assertTrue(ok, why)

    def test_pin_mismatch_blocked(self):
        api.save(api.CONFIG_FILE, {"require_agent_mtls": True})
        api.save(api.DEVICES_FILE, {"dev1": {"token": "t", "mtls_fingerprint": "AA:BB:CC"}})
        os.environ["HTTP_X_SSL_CLIENT_VERIFY"] = "SUCCESS"
        os.environ["HTTP_X_SSL_CLIENT_FINGERPRINT"] = "ddeeff"
        ok, why = api._agent_mtls_ok("dev1")
        self.assertFalse(ok)
        self.assertIn("does not match", why)

    def test_pin_match_allows(self):
        api.save(api.CONFIG_FILE, {"require_agent_mtls": True})
        api.save(api.DEVICES_FILE, {"dev1": {"token": "t", "mtls_fingerprint": "SHA1:AA:BB:CC"}})
        os.environ["HTTP_X_SSL_CLIENT_VERIFY"] = "SUCCESS"
        os.environ["HTTP_X_SSL_CLIENT_FINGERPRINT"] = "aabbcc"
        ok, why = api._agent_mtls_ok("dev1")
        self.assertTrue(ok, why)

    def test_identity_normalizes_fingerprint(self):
        os.environ["HTTP_X_SSL_CLIENT_VERIFY"] = "SUCCESS"
        os.environ["HTTP_X_SSL_CLIENT_FINGERPRINT"] = "SHA1:AA:BB:CC"
        verified, fp, _dn = api._client_cert_identity()
        self.assertTrue(verified)
        self.assertEqual(fp, "aabbcc")

    def test_heartbeat_enforces(self):
        i = API_SRC.index("def handle_heartbeat(")
        self.assertIn("_agent_mtls_ok(dev_id)", API_SRC[i:i + 3000])

    def test_config_wiring(self):
        self.assertIn("cfg['require_agent_mtls'] = bool(body['require_agent_mtls'])", API_SRC)
        self.assertIn("safe.setdefault('require_agent_mtls', False)", API_SRC)

    def test_agent_presents_client_cert(self):
        agent = (_ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertIn("RP_CLIENT_CERT", agent)
        self.assertIn("load_cert_chain", agent)
        # extensionless copy stays byte-identical
        ext = (_ROOT / "client" / "remotepower-agent").read_text()
        self.assertEqual(agent, ext)

    def test_nginx_snippet(self):
        conf = (_ROOT / "deploy" / "nginx" / "remotepower.conf").read_text()
        self.assertIn("ssl_verify_client", conf)
        self.assertIn("HTTP_X_SSL_CLIENT_FINGERPRINT", conf)

    def test_frontend_toggle(self):
        self.assertIn('id="cfg-require-agent-mtls"', HTML)
        self.assertIn("require_agent_mtls:", APP)


if __name__ == "__main__":
    unittest.main()
