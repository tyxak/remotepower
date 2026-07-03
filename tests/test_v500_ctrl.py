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
import sys as _as_sys
from pathlib import Path as _as_Path
_as_sys.path.insert(0, str(_as_Path(__file__).resolve().parent))
from apisrc import api_source as _apisrc_combined   # api.py + *_handlers.py bound modules (decomposition-safe pins)
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
from clientjs import client_js  # noqa: E402  (app.js was split into page modules)

API_SRC = _apisrc_combined()
APP = client_js()
APP_CMDB = (_ROOT / "server" / "html" / "static" / "js" / "app-cmdb.js").read_text()
HTML = (_ROOT / "server" / "html" / "index.html").read_text()
CSS = (_ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()


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
        # v5.4.1: widened 1400→1800 (C1 key-hashing) →2300 (D7 ip_allow check added
        # ahead of the enforce call), pushing the enforce call further down.
        self.assertIn("_enforce_apikey_ratelimit(matched_kid", API_SRC[i:i + 2300])

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
        # v5.4.1 (C8): sourced via _secret_from_env (env var OR a *_CMD helper) —
        # still never from the config/data dir (which the backup itself contains).
        self.assertIn("_secret_from_env('RP_BACKUP_PASSPHRASE')", API_SRC[i:i + 800])

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
        # deploy/ is gitignored + excluded from `make dist` — skip when absent so
        # the release build (staged tree) doesn't error (CLAUDE.md gotcha).
        conf_path = _ROOT / "deploy" / "nginx" / "remotepower.conf"
        if not conf_path.exists():
            self.skipTest("deploy/nginx/remotepower.conf not present (excluded tree)")
        conf = conf_path.read_text()
        self.assertIn("ssl_verify_client", conf)
        self.assertIn("HTTP_X_SSL_CLIENT_FINGERPRINT", conf)

    def test_frontend_toggle(self):
        self.assertIn('id="cfg-require-agent-mtls"', HTML)
        self.assertIn("require_agent_mtls:", APP)


# ─────────────────────────── #R1 server disk watchdog ──────────────────────────
class TestDiskWatchdog(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        try:
            (api.DATA_DIR / "disk_watchdog_state.json").unlink()
        except (OSError, FileNotFoundError):
            pass

    def test_events_registered(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn("server_disk_low", names)
        self.assertIn("server_disk_ok", names)
        self.assertEqual(api._ALERT_RULES.get("server_disk_low")[0], "high")
        self.assertEqual(api._ALERT_RECOVER.get("server_disk_ok"), "server_disk_low")
        kinds = {row[0] for row in api.CHANNEL_KINDS}
        self.assertIn("server_disk", kinds)

    def test_recover_matches_by_target(self):
        # the server_disk_ok branch in _auto_resolve_alerts matches on 'target'
        i = API_SRC.index("def _auto_resolve_alerts(")
        block = API_SRC[i:i + 4000]
        self.assertIn("event == 'server_disk_ok'", block)
        self.assertIn("sub_match['target'] = p.get('target')", block)

    def test_target_in_record_alert_whitelist(self):
        # 'target' must be a whitelisted key or the recover never resolves
        i = API_SRC.index("def _record_alert(")
        self.assertIn("'target'", API_SRC[i:i + 2800])   # window widened v5.6.0 (mute check inserted)

    def test_low_fires_then_recovers(self):
        # Drive the watchdog by stubbing os.statvfs + bypassing the 30-min gate.
        import os as _os
        fired = []
        real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, pl=None: fired.append((ev, pl))
        real_statvfs = _os.statvfs

        class _FakeVfs:
            def __init__(self, used):
                self.f_frsize = 4096
                self.f_blocks = 1000
                self.f_bavail = int(1000 * (1 - used))

        try:
            api.save(api.CONFIG_FILE, {"disk_watchdog_pct": 85})
            # 1) 95% used → fires server_disk_low
            _os.statvfs = lambda p: _FakeVfs(0.95)
            api._maybe_check_disk_space()
            self.assertEqual(fired[-1][0], "server_disk_low")
            self.assertEqual(fired[-1][1]["target"], "server")
            # force the gate open again
            st = api.load(api.DATA_DIR / "disk_watchdog_state.json")
            st["last_check"] = 0
            api.save(api.DATA_DIR / "disk_watchdog_state.json", st)
            # 2) recovered to 50% → fires server_disk_ok
            _os.statvfs = lambda p: _FakeVfs(0.50)
            api._maybe_check_disk_space()
            self.assertEqual(fired[-1][0], "server_disk_ok")
        finally:
            api.fire_webhook = real_fire
            _os.statvfs = real_statvfs

    def test_threshold_zero_disables(self):
        api.save(api.CONFIG_FILE, {"disk_watchdog_pct": 0})
        fired = []
        real = api.fire_webhook
        api.fire_webhook = lambda ev, pl=None: fired.append(ev)
        try:
            api._maybe_check_disk_space()
            self.assertEqual(fired, [])
        finally:
            api.fire_webhook = real

    def test_heartbeat_calls_watchdog(self):
        self.assertIn("_maybe_check_disk_space()", API_SRC)
        i = API_SRC.index("def handle_heartbeat(")
        self.assertIn("_maybe_check_disk_space()", API_SRC[i:i + 1500])

    def test_config_and_frontend(self):
        self.assertIn("cfg['disk_watchdog_pct'] = v", API_SRC)
        self.assertIn("safe.setdefault('disk_watchdog_pct', 85)", API_SRC)
        self.assertIn('id="cfg-disk-watchdog-pct"', HTML)
        self.assertIn("server_disk_low", APP)
        self.assertIn('data-home-act="self"', APP)


# ─────────────────────────── #R2 webhook DLQ + replay ──────────────────────────
class TestWebhookDlq(unittest.TestCase):
    def setUp(self):
        api.save(api.WEBHOOK_DLQ_FILE, {"entries": []})

    def test_record_appends(self):
        api._dlq_record("device_offline", {"url": "https://x/y", "secret": "z"},
                        {"device_id": "d1"}, "msg", "Title", 0, "HTTP 500")
        entries = api.load(api.WEBHOOK_DLQ_FILE)["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event"], "device_offline")
        self.assertTrue(entries[0]["id"].startswith("dlq_"))
        self.assertEqual(entries[0]["attempts"], 1)

    def test_record_capped(self):
        for i in range(api.MAX_WEBHOOK_DLQ + 25):
            api._dlq_record("e", {"url": "u"}, {}, "m", "t", 0, "err")
        self.assertEqual(len(api.load(api.WEBHOOK_DLQ_FILE)["entries"]),
                         api.MAX_WEBHOOK_DLQ)

    def test_retry_entry_success_and_fail(self):
        real = api._dispatch_one_webhook
        try:
            api._dispatch_one_webhook = lambda *a, **k: None  # succeeds
            self.assertTrue(api._dlq_retry_entry({"event": "e", "dest": {"url": "u"}}))

            def _boom(*a, **k):
                raise RuntimeError("still down")
            api._dispatch_one_webhook = _boom
            self.assertFalse(api._dlq_retry_entry({"event": "e", "dest": {"url": "u"}}))
        finally:
            api._dispatch_one_webhook = real

    def test_failure_path_records_dlq(self):
        # the three except branches in _dispatch_one_webhook must call _dlq_record
        # (the _build_* payload builders moved to notify.py — anchor on the
        # function itself, not its old neighbour)
        from srcpin import py_function
        block = py_function(API_SRC, '_dispatch_one_webhook')
        self.assertEqual(block.count("_dlq_record("), 3)

    def test_routes(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/webhook/dlq")[0], "handle_webhook_dlq_list")
        self.assertEqual(resolve_route("POST", "/api/webhook/dlq/retry")[0], "handle_webhook_dlq_retry")
        self.assertEqual(resolve_route("DELETE", "/api/webhook/dlq")[0], "handle_webhook_dlq_clear")
        self.assertEqual(resolve_route("POST", "/api/webhook/replay")[0], "handle_webhook_replay")

    def test_list_scrubs_dest(self):
        # handle_webhook_dlq_list must drop the dest blob (carries tokens)
        i = API_SRC.index("def handle_webhook_dlq_list(")
        self.assertIn("d.pop('dest', None)", API_SRC[i:i + 700])

    def test_frontend(self):
        self.assertIn('id="webhook-dlq-wrap"', HTML)
        self.assertIn("function loadWebhookDlq", APP)
        self.assertIn("retryAllDlq", APP)


# ─────────────────────────── #R3 runtime maintenance mode ──────────────────────
class TestMaintenanceMode(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})

    def test_inactive_by_default(self):
        active, reason = api._maintenance_active()
        self.assertFalse(active)
        self.assertEqual(reason, "")

    def test_active_with_reason(self):
        api.save(api.CONFIG_FILE, {"maintenance_mode": True, "maintenance_reason": "upgrade"})
        active, reason = api._maintenance_active()
        self.assertTrue(active)
        self.assertEqual(reason, "upgrade")

    def test_block_helper_503s(self):
        api.save(api.CONFIG_FILE, {"maintenance_mode": True})
        with self.assertRaises(api.HTTPError) as ctx:   # respond() raises HTTPError
            api._block_if_maintenance("reboot")
        self.assertEqual(ctx.exception.status, 503)

    def test_poll_interval_exempt(self):
        api.save(api.CONFIG_FILE, {"maintenance_mode": True})
        # poll_interval must NOT raise (agent-local timer only)
        api._block_if_maintenance("poll_interval:300")

    def test_queue_command_gated(self):
        i = API_SRC.index("def _queue_command(")
        self.assertIn("_block_if_maintenance(command)", API_SRC[i:i + 400])
        j = API_SRC.index("def _queue_command_batch(")
        self.assertIn("_block_if_maintenance(command)", API_SRC[j:j + 200])

    def test_routes(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/maintenance-mode")[0], "handle_maintenance_mode_get")
        self.assertEqual(resolve_route("POST", "/api/maintenance-mode")[0], "handle_maintenance_mode_set")

    def test_frontend(self):
        self.assertIn('id="cfg-maintenance-mode"', HTML)
        self.assertIn('id="maintenance-banner"', HTML)
        self.assertIn("function toggleMaintenanceMode", APP)


# ─────────────────────────── #R4 graceful long-poll SIGTERM ────────────────────
class TestLongpollGracefulShutdown(unittest.TestCase):
    def test_handler_installs_sigterm(self):
        i = API_SRC.index("def handle_longpoll_exec(")
        block = API_SRC[i:i + 3500]
        self.assertIn("signal.SIGTERM", block)
        self.assertIn("_shutting_down", block)
        self.assertIn("'shutdown': True", block)
        self.assertIn("_restore_signal()", block)


# ─────────────────────────── #R5 OSV circuit breaker ───────────────────────────
class TestOsvCircuitBreaker(unittest.TestCase):
    def setUp(self):
        import cve_scanner
        self.cve = cve_scanner
        self.dir = Path(tempfile.mkdtemp())

    def test_closed_by_default(self):
        self.assertFalse(self.cve.osv_breaker_open(self.dir))

    def test_opens_after_threshold(self):
        for _ in range(self.cve.OSV_FAIL_THRESHOLD - 1):
            self.cve.osv_breaker_record(self.dir, ok=False)
        self.assertFalse(self.cve.osv_breaker_open(self.dir))   # not yet
        self.cve.osv_breaker_record(self.dir, ok=False)         # trips it
        self.assertTrue(self.cve.osv_breaker_open(self.dir))

    def test_success_resets(self):
        for _ in range(self.cve.OSV_FAIL_THRESHOLD):
            self.cve.osv_breaker_record(self.dir, ok=False)
        self.assertTrue(self.cve.osv_breaker_open(self.dir))
        self.cve.osv_breaker_record(self.dir, ok=True)
        self.assertFalse(self.cve.osv_breaker_open(self.dir))

    def test_cooldown_expires(self):
        now = 1_000_000
        for _ in range(self.cve.OSV_FAIL_THRESHOLD):
            self.cve.osv_breaker_record(self.dir, ok=False, now=now)
        self.assertTrue(self.cve.osv_breaker_open(self.dir, now=now + 1))
        self.assertFalse(self.cve.osv_breaker_open(self.dir,
                                                   now=now + self.cve.OSV_COOLDOWN + 1))

    def test_scan_device_skips_when_open(self):
        for _ in range(self.cve.OSV_FAIL_THRESHOLD):
            self.cve.osv_breaker_record(self.dir, ok=False)
        res = self.cve.scan_device("d1", [{"name": "openssl", "version": "1.0"}],
                                   "Debian:12", self.dir)
        self.assertTrue(res.get("skipped"))
        self.assertIn("circuit breaker", res.get("error", ""))

    def test_scan_device_records_failure(self):
        # stub _osv_querybatch to raise → scan_device records a breaker failure
        real = self.cve._osv_querybatch

        def _boom(_b):
            raise RuntimeError("osv down")
        self.cve._osv_querybatch = _boom
        try:
            self.cve.scan_device("d1", [{"name": "openssl", "version": "1.0"}],
                                 "Debian:12", self.dir)
            st = self.cve._load_json(self.cve._breaker_path(self.dir))
            self.assertEqual(st.get("failures"), 1)
        finally:
            self.cve._osv_querybatch = real


# ─────────────────────────── #F1/#F2 bulk device ops ───────────────────────────
class TestBulkDeviceOps(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "one", "token": "t", "tags": ["a"]},
            "d2": {"name": "two", "token": "t", "tags": ["a", "b"]},
            "d3": {"name": "three", "token": "t", "tags": []},
        })

    def test_purge_device_returns_bool(self):
        self.assertTrue(api._purge_device("d1"))
        self.assertFalse(api._purge_device("d1"))  # already gone
        self.assertNotIn("d1", api.load(api.DEVICES_FILE))

    def test_clean_tags(self):
        self.assertEqual(api._clean_tags(["a b", "ok", "", "x!@#y"]),
                         ["ab", "ok", "xy"])

    def test_bulk_delete_route(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("POST", "/api/devices/bulk-delete")[0],
                         "handle_devices_bulk_delete")
        self.assertEqual(resolve_route("POST", "/api/devices/bulk-tags")[0],
                         "handle_devices_bulk_tags")

    def test_bulk_tags_merge_logic(self):
        # exercise the add/remove set-merge directly against the store
        with api._LockedUpdate(api.DEVICES_FILE) as devices:
            for dev_id in ("d1", "d2"):
                dev = devices[dev_id]
                cur = [t for t in (dev.get("tags") or []) if t not in {"a"}]
                for t in ["prod"]:
                    if t not in cur:
                        cur.append(t)
                dev["tags"] = cur
        d = api.load(api.DEVICES_FILE)
        self.assertEqual(d["d1"]["tags"], ["prod"])        # a removed, prod added
        self.assertEqual(d["d2"]["tags"], ["b", "prod"])   # a removed, b kept

    def test_handlers_exist_and_audit(self):
        for fn in ("handle_devices_bulk_delete", "handle_devices_bulk_tags"):
            self.assertIn(f"def {fn}(", API_SRC)
        self.assertIn("'devices_bulk_delete'", API_SRC)
        self.assertIn("'devices_bulk_tags'", API_SRC)

    def test_frontend(self):
        self.assertIn('data-action="batchDelete"', HTML)
        self.assertIn('data-action="batchTags"', HTML)
        self.assertIn("function batchDelete", APP)
        self.assertIn("/devices/bulk-tags", APP)


# ─────────────────────────── #F3 per-command timeout ───────────────────────────
class TestPerCommandTimeout(unittest.TestCase):
    def test_server_encodes_prefix(self):
        i = API_SRC.index("def handle_custom_cmd(")
        block = API_SRC[i:i + 1400]
        self.assertIn("to={_to}:", block)
        self.assertIn("1..3600 seconds", block)
        self.assertIn("_queued = f'exec:{_exec_pfx}{cmd_str}'", block)

    def test_linux_agent_parses(self):
        agent = (_ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertIn("exec_timeout_override", agent)
        self.assertIn(r"^to=(\d{1,5}):(.*)$", agent)
        # byte-identical extensionless copy
        self.assertEqual(agent, (_ROOT / "client" / "remotepower-agent").read_text())

    def test_win_mac_agents_strip_prefix(self):
        for fn in ("remotepower-agent-win.py", "remotepower-agent-mac.py"):
            src = (_ROOT / "client" / fn).read_text()
            self.assertIn("_exec_timeout_override", src,
                          f"{fn} missing timeout parse")
            self.assertIn(r"^to=\d{1,5}:(.*)$", src,
                          f"{fn} doesn't strip the to= prefix")

    def test_frontend(self):
        self.assertIn('id="exec-timeout"', HTML)
        self.assertIn("body.timeout = to", APP)

    def test_prefix_roundtrip_regex(self):
        # the exact regex the agents use, exercised here
        import re
        m = re.match(r'^to=(\d{1,5}):(.*)$', "to=120:systemctl restart nginx", re.DOTALL)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "120")
        self.assertEqual(m.group(2), "systemctl restart nginx")
        # a normal command is untouched
        self.assertIsNone(re.match(r'^to=(\d{1,5}):(.*)$', "echo hello", re.DOTALL))


# ─────────────────────────── #F4 agent version-compat ──────────────────────────
class TestAgentCompat(unittest.TestCase):
    def test_ver_tuple(self):
        self.assertEqual(api._ver_tuple("4.10.0"), (4, 10, 0))
        self.assertEqual(api._ver_tuple("5"), (5, 0, 0))
        self.assertEqual(api._ver_tuple("4.9"), (4, 9, 0))
        self.assertEqual(api._ver_tuple(""), (0, 0, 0))

    def test_up_to_date(self):
        c = api._agent_compat("5.0.0", "5.0.0")
        self.assertTrue(c["compatible"])
        self.assertFalse(c["update_available"])

    def test_update_available(self):
        c = api._agent_compat("4.10.0", "5.0.0")
        self.assertTrue(c["compatible"])
        self.assertTrue(c["update_available"])

    def test_agent_newer_incompatible(self):
        c = api._agent_compat("6.0.0", "5.0.0")
        self.assertFalse(c["compatible"])
        self.assertIn("newer than server", c["reason"])

    def test_too_far_behind_incompatible(self):
        c = api._agent_compat("3.0.0", "5.0.0")
        self.assertFalse(c["compatible"])
        self.assertIn("major behind", c["reason"])

    def test_unknown_version_ok(self):
        c = api._agent_compat("", "5.0.0")
        self.assertTrue(c["compatible"])

    def test_update_handler_gates(self):
        i = API_SRC.index("def handle_update_device(")
        block = API_SRC[i:i + 900]
        self.assertIn("_agent_compat(", block)
        self.assertIn("body.get('force')", block)
        self.assertIn("'incompatible': True", block)

    def test_route(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/agent-compat")[0], "handle_agent_compat")

    def test_frontend_force(self):
        self.assertIn("data?.incompatible", APP)
        self.assertIn("force: true", APP)


# ─────────────────────────── #F5 rollout rollback ──────────────────────────────
class TestRolloutRollback(unittest.TestCase):
    def test_create_accepts_rollback_script(self):
        i = API_SRC.index("def handle_rollouts_create(")
        block = API_SRC[i:i + 2600]
        self.assertIn("rollback_script_id", block)
        self.assertIn("rollback_script_id not found", block)

    def test_action_handler_has_rollback(self):
        i = API_SRC.index("def handle_rollout_action(")
        block = API_SRC[i:API_SRC.index("def handle_rollout_delete(")]
        self.assertIn("action == 'rollback'", block)
        # gathers dispatched_ids across rings + makes a new script rollout
        self.assertIn("dispatched_ids", block)
        self.assertIn("'rolled_back_from': roll_id", block)
        self.assertIn("agent-binary rollback requires a", block)

    def test_response_surfaces_rollback_id(self):
        i = API_SRC.index("def handle_rollout_action(")
        block = API_SRC[i:API_SRC.index("def handle_rollout_delete(")]
        self.assertIn("'rollback_id': err_box[1]", block)

    def test_frontend(self):
        self.assertIn("data-arg2=\"rollback\"", APP)
        self.assertIn("rollback_script_id", APP)
        self.assertIn('id="ro-rollback-script"', HTML)


# ─────────────────────────── #S1 cross-device OSV batching ─────────────────────
class TestOsvPrefetch(unittest.TestCase):
    def setUp(self):
        import cve_scanner
        self.cve = cve_scanner
        self.dir = Path(tempfile.mkdtemp())
        self._real = cve_scanner._osv_querybatch
        self.calls = {"n": 0}

        def _fake(batch):
            self.calls["n"] += 1
            return [{"vulns": []} for _ in batch]
        cve_scanner._osv_querybatch = _fake

    def tearDown(self):
        self.cve._osv_querybatch = self._real

    def test_prefetch_dedups_across_devices(self):
        store = {
            "a": {"ecosystem": "Debian:12",
                  "packages": [{"name": "openssl", "version": "1.0"},
                               {"name": "bash", "version": "5.0"}]},
            "b": {"ecosystem": "Debian:12",
                  "packages": [{"name": "openssl", "version": "1.0"}]},  # dup
        }
        pf = self.cve.prefetch_osv(store, self.dir)
        self.assertEqual(len(pf), 2)               # openssl1.0 + bash5.0, deduped
        self.assertEqual(self.calls["n"], 1)       # one querybatch for the fleet
        self.assertIn(("Debian:12", "openssl", "1.0"), pf)

    def test_scan_device_with_prefetch_makes_no_osv_calls(self):
        store = {"a": {"ecosystem": "Debian:12",
                       "packages": [{"name": "openssl", "version": "1.0"}]}}
        pf = self.cve.prefetch_osv(store, self.dir)
        self.calls["n"] = 0
        r = self.cve.scan_device("a", store["a"]["packages"], "Debian:12",
                                 self.dir, osv_prefetch=pf)
        self.assertEqual(self.calls["n"], 0)       # served entirely from the map
        self.assertIsNone(r.get("error"))

    def test_prefetch_empty_when_breaker_open(self):
        for _ in range(self.cve.OSV_FAIL_THRESHOLD):
            self.cve.osv_breaker_record(self.dir, ok=False)
        self.assertEqual(self.cve.prefetch_osv({"a": {"ecosystem": "Debian:12",
                         "packages": [{"name": "x", "version": "1"}]}}, self.dir), {})

    def test_worker_uses_prefetch_for_fleet(self):
        i = API_SRC.index("def _cve_scan_worker(")
        block = API_SRC[i:i + 2000]
        self.assertIn("cve_scanner.prefetch_osv(", block)
        self.assertIn("osv_prefetch=osv_prefetch", block)
        # single-device scans don't prefetch (guarded by `not target and total>1`)
        self.assertIn("if not target and total > 1:", block)


# ─────────────────────────── T5 operator polish ────────────────────────────────
class TestT5Polish(unittest.TestCase):
    def test_u1_clipboard_helper(self):
        self.assertIn("function copyText(", APP)
        self.assertIn("function copyApiKeyValue(", APP)
        self.assertIn('data-action="copyApiKeyValue"', HTML)

    def test_u2_webhook_dot(self):
        # the webhook log row carries an explicit green/red delivery dot
        i = APP.index("function loadWebhookLog(")
        self.assertIn("Delivered", APP[i:i + 1500])

    def test_u4_pending_commands_badge(self):
        # backend exposes commands_pending in nav-counts (admin only)
        i = API_SRC.index("def handle_nav_counts(")
        block = API_SRC[i:i + 8000]
        self.assertIn("out['commands_pending']", block)
        # CMDS_FILE added to the cache-invalidation sources so the badge is fresh
        self.assertIn("ALERTS_FILE, CONFIRMATIONS_FILE, CMDS_FILE", API_SRC)
        # frontend badge element + painter
        self.assertIn('id="cmdqueue-badge"', HTML)
        self.assertIn("c.commands_pending", APP)

    def test_u5_rename_duplicate_query(self):
        self.assertIn("function renameFleetQuery(", APP)
        self.assertIn("function duplicateFleetQuery(", APP)
        self.assertIn('data-action="renameFleetQuery"', APP)
        self.assertIn('data-action="duplicateFleetQuery"', APP)

    def test_u6_field_tooltips(self):
        # representative hover help added to fields that lacked it
        i = HTML.index('id="cfg-online-ttl"')
        self.assertIn("title=", HTML[i:i + 300])

    def test_u9_self_test(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/self-test")[0], "handle_self_test")
        i = API_SRC.index("def handle_self_test(")
        block = API_SRC[i:i + 2500]
        for label in ("Storage backend", "Disk space", "Audit chain", "Agent reachability"):
            self.assertIn(label, block)
        self.assertIn("function runSelfTest(", APP)
        self.assertIn('data-action="runSelfTest"', HTML)

    def test_u3_snooze(self):
        self.assertIn("function snoozeDeviceAlerts(", APP)
        self.assertIn("'Snooze alerts 1h'", APP)
        # builds a one-shot device maintenance window (which suppresses alerts)
        i = APP.index("function snoozeDeviceAlerts(")
        block = APP[i:i + 700]
        self.assertIn("scope: 'device'", block)
        self.assertIn("/maintenance'", block)

    def test_u7_palette_command_history(self):
        self.assertIn("window._cmdHistCache", APP)
        self.assertIn("kind: 'history'", APP)

    def test_u9_self_test_runs(self):
        # behavioral: the helper builds a checks list with an overall ok bool
        # (can't call the handler directly — it needs auth/respond — so assert the
        # shape via the source contract instead).
        i = API_SRC.index("def handle_self_test(")
        # window widened for the v5.4.1 (G3) uptime + (Stage D) scheduler-nudge blocks.
        self.assertIn("'ok': overall", API_SRC[i:i + 4600])
        self.assertIn("all(c['ok'] for c in checks)", API_SRC[i:i + 4600])


# ─────────────────────────── T6 industrial design pass ─────────────────────────
class TestT6Design(unittest.TestCase):
    def test_board_route_and_handler(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("GET", "/api/board")[0], "handle_board")
        i = API_SRC.index("def handle_board(")
        block = API_SRC[i:i + 3000]
        # big-fleet shape: rollup tiles + capped problem strip + totals, not raw tiles
        self.assertIn("not in ('group', 'site', 'tag')", block)
        self.assertIn("len(problems) < 80", block)        # problem strip capped
        self.assertIn("tile_list[:120]", block)           # tiles capped
        self.assertIn("_scope_filter_devices", block)     # scoped
        self.assertIn("'totals'", block)

    def test_board_frontend(self):
        self.assertIn('id="page-board"', HTML)
        self.assertIn('data-page="board"', HTML)
        self.assertIn("function loadBoard(", APP)
        self.assertIn("function boardBy(", APP)
        # bar widths set via .style (no inline style strings → CSP-safe)
        self.assertIn("s.style.width", APP)

    def test_css_tabular_numerals(self):
        self.assertIn("font-variant-numeric: tabular-nums", CSS)

    def test_css_semaphore_and_segmented(self):
        for cls in (".sem-ok", ".sem-warn", ".sem-down", ".segmented"):
            self.assertIn(cls, CSS, cls)

    def test_css_density_and_board(self):
        self.assertIn("body.density-compact td", CSS)
        for cls in (".board-grid", ".board-tile", ".board-bar", ".vitals"):
            self.assertIn(cls, CSS, cls)

    def test_density_toggle_and_vitals_wired(self):
        self.assertIn("function toggleDensity(", APP)
        self.assertIn("rp_density", APP)
        self.assertIn('id="density-toggle"', HTML)
        self.assertIn('id="header-vitals"', HTML)
        self.assertIn("function _paintVitals(", APP)

    def test_icons_and_board_badge(self):
        # Lucide icons (no emoji) on the board/vitals + a Status Board nav badge.
        self.assertIn('id="board-badge"', HTML)
        self.assertIn("board-badge", APP)               # painted in refreshNavCounts
        self.assertIn("_reasonIcon", APP)               # problem-chip reason icons
        self.assertIn("alertTriangle:", APP)            # new icon registered
        self.assertIn("wifiOff", APP)
        # vitals strip carries icons
        i = APP.index("function _paintVitals(")
        self.assertIn("_icon('server'", APP[i:i + 900])

    def test_no_emoji_in_v5_surfaces(self):
        import re
        emoji = re.compile("[\U0001F000-\U0001FAFF☀-➿]")
        for name, src in (("app.js", APP), ("index.html", HTML)):
            # the board/vitals code must use SVG icons, not emoji
            i = src.find("board-vitals")
            if i >= 0:
                self.assertIsNone(emoji.search(src[i:i + 4000]),
                                  f"emoji found near board code in {name}")

    def test_no_inline_style_or_handlers_in_board_markup(self):
        # CSP discipline: the board page markup must not carry style= or on*=.
        i = HTML.index('id="page-board"')
        block = HTML[i:HTML.index('id="page-home"')]
        self.assertNotIn("style=", block)
        self.assertNotIn("onclick=", block)


if __name__ == "__main__":
    unittest.main()
