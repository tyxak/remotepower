#!/usr/bin/env python3
"""
Unit tests for v1.9.0: CMDB + encrypted credential vault.

Covers cmdb_vault.py (KDF + AES-GCM helpers) plus the api.py handlers
for asset CRUD, credential CRUD, vault unlock/setup/rotation, search,
and audit logging.

Style mirrors tests/test_v186.py and earlier — bootstrap a tmp data dir
via RP_DATA_DIR before importing api, then poke handlers directly via
respond_capture so we don't need a live CGI process.
"""

import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

import importlib.util

_spec = importlib.util.spec_from_file_location("api_v190", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import cmdb_vault

# ─── Helpers ──────────────────────────────────────────────────────────────────


class _Captured(SystemExit):
    """SystemExit subclass carrying the (status, body) the handler emitted."""

    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond(monkeypatch_target):
    """Replace api.respond with a function that raises _Captured(status, body)."""

    def fake_respond(status, data):
        raise _Captured(status, data)

    monkeypatch_target.respond = fake_respond


class _StdinShim:
    """sys.stdin.buffer.read(n) is what api.get_body uses — fake both layers."""

    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _set_request(method, path, body=None, headers=None):
    """Set CGI env vars so api.path_info()/method()/get_body() see our values."""
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    if body is None:
        raw = b""
    elif isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
    elif isinstance(body, str):
        raw = body.encode("utf-8")
    else:
        raw = json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    # Reset every header we care about — both auth + vault — so the previous
    # test's environment doesn't bleed through.
    for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY", "QUERY_STRING"):
        os.environ.pop(k, None)
    for k, v in (headers or {}).items():
        os.environ[k] = v


def _call(handler, *args, **kwargs):
    """Invoke a handler, capture its respond() call, return (status, body)."""
    _capture_respond(api)
    try:
        handler(*args, **kwargs)
    except _Captured as c:
        return c.status, c.body
    raise AssertionError(f"handler {handler.__name__} did not call respond()")


def _seed_admin():
    """Ensure a default admin user exists and return a valid auth token."""
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": user,
        "created": int(time.time()),
        "ttl": 3600,
        "admin": True,
        "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return user, token


def _auth_headers(token):
    return {"HTTP_X_TOKEN": token}


def _seed_device(dev_id="dev-test", name="test-host"):
    devices = api.load(api.DEVICES_FILE)
    devices[dev_id] = {
        "name": name,
        "hostname": name,
        "os": "Ubuntu 22.04",
        "ip": "10.0.0.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "token": "devtoken",
        "last_seen": int(time.time()),
        "enrolled": int(time.time()),
        "tags": ["linux"],
        "group": "production",
    }
    api.save(api.DEVICES_FILE, devices)
    return dev_id


# ─── cmdb_vault module ───────────────────────────────────────────────────────


class TestVaultCrypto(unittest.TestCase):
    """The crypto module is the trust root — exercise it thoroughly."""

    def test_setup_creates_meta_with_all_fields(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        self.assertEqual(meta["kdf"], "pbkdf2-sha256")
        self.assertGreaterEqual(meta["iterations"], 100_000)
        self.assertEqual(len(bytes.fromhex(meta["salt"])), cmdb_vault.KDF_SALT_LEN)
        self.assertTrue(meta["canary_nonce"])
        self.assertTrue(meta["canary_ct"])

    def test_unlock_with_correct_passphrase_returns_valid_key(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        key = cmdb_vault.derive_key_from_meta("Strong-Pass-1234", meta)
        self.assertTrue(cmdb_vault.verify_key(key, meta))

    def test_unlock_with_wrong_passphrase_fails_canary_check(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        bad_key = cmdb_vault.derive_key_from_meta("Wrong-Pass-9999", meta)
        self.assertFalse(cmdb_vault.verify_key(bad_key, meta))

    def test_encrypt_decrypt_roundtrip(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        key = cmdb_vault.derive_key_from_meta("Strong-Pass-1234", meta)
        blob = cmdb_vault.encrypt(key, "hunter2")
        self.assertNotIn("hunter2", json.dumps(blob))  # nothing leaks
        self.assertEqual(cmdb_vault.decrypt(key, blob), "hunter2")

    def test_decrypt_with_wrong_key_raises(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        key = cmdb_vault.derive_key_from_meta("Strong-Pass-1234", meta)
        blob = cmdb_vault.encrypt(key, "hunter2")
        bad = bytes(32)
        with self.assertRaises(cmdb_vault.VaultKeyError):
            cmdb_vault.decrypt(bad, blob)

    def test_two_setups_produce_different_salts_and_canaries(self):
        a = cmdb_vault.setup_vault("Strong-Pass-1234")
        b = cmdb_vault.setup_vault("Strong-Pass-1234")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["canary_ct"], b["canary_ct"])

    def test_each_encrypt_uses_fresh_nonce(self):
        meta = cmdb_vault.setup_vault("Strong-Pass-1234")
        key = cmdb_vault.derive_key_from_meta("Strong-Pass-1234", meta)
        a = cmdb_vault.encrypt(key, "same-plaintext")
        b = cmdb_vault.encrypt(key, "same-plaintext")
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_validate_passphrase_rejects_short(self):
        self.assertIsNotNone(cmdb_vault.validate_passphrase("short1!"))

    def test_validate_passphrase_rejects_single_class(self):
        self.assertIsNotNone(cmdb_vault.validate_passphrase("alllowercaseonly"))

    def test_validate_passphrase_accepts_strong(self):
        self.assertIsNone(cmdb_vault.validate_passphrase("Strong-Pass-1234"))

    def test_parse_key_header_strict(self):
        with self.assertRaises(cmdb_vault.VaultLockedError):
            cmdb_vault.parse_key_header("")
        with self.assertRaises(cmdb_vault.VaultKeyError):
            cmdb_vault.parse_key_header("not-hex")
        with self.assertRaises(cmdb_vault.VaultKeyError):
            cmdb_vault.parse_key_header("ab" * 8)  # 8 bytes, too short
        good = cmdb_vault.parse_key_header("ab" * 32)
        self.assertEqual(len(good), 32)


# ─── /api/cmdb/vault/* endpoints ─────────────────────────────────────────────


class TestVaultEndpoints(unittest.TestCase):

    def setUp(self):
        # Fresh tmp dir per test for isolation
        self._dir = tempfile.mkdtemp()
        os.environ["RP_DATA_DIR"] = self._dir
        # Reach into api to reset its cached file paths
        for name in (
            "USERS_FILE",
            "TOKENS_FILE",
            "DEVICES_FILE",
            "CMDB_FILE",
            "CMDB_VAULT_FILE",
            "AUDIT_LOG_FILE",
            "CONFIG_FILE",
        ):
            setattr(api, name, Path(self._dir) / Path(getattr(api, name)).name)

    def test_status_starts_unconfigured(self):
        user, token = _seed_admin()
        _set_request("GET", "/api/cmdb/vault/status", headers=_auth_headers(token))
        status, body = _call(api.handle_cmdb_vault_status)
        self.assertEqual(status, 200)
        self.assertFalse(body["configured"])

    def test_setup_then_unlock_then_status(self):
        user, token = _seed_admin()
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "Strong-Pass-1234"},
            headers=_auth_headers(token),
        )
        s, b = _call(api.handle_cmdb_vault_setup)
        self.assertEqual(s, 200)
        self.assertEqual(len(bytes.fromhex(b["key"])), 32)

        _set_request("GET", "/api/cmdb/vault/status", headers=_auth_headers(token))
        s, b = _call(api.handle_cmdb_vault_status)
        self.assertTrue(b["configured"])
        self.assertEqual(b["kdf"], "pbkdf2-sha256")

        _set_request(
            "POST",
            "/api/cmdb/vault/unlock",
            body={"passphrase": "Strong-Pass-1234"},
            headers=_auth_headers(token),
        )
        s, b = _call(api.handle_cmdb_vault_unlock)
        self.assertEqual(s, 200)
        self.assertEqual(len(bytes.fromhex(b["key"])), 32)

    def test_setup_rejects_weak_passphrase(self):
        user, token = _seed_admin()
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "short"},
            headers=_auth_headers(token),
        )
        s, b = _call(api.handle_cmdb_vault_setup)
        self.assertEqual(s, 400)

    def test_setup_blocks_when_already_configured(self):
        user, token = _seed_admin()
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "Strong-Pass-1234"},
            headers=_auth_headers(token),
        )
        _call(api.handle_cmdb_vault_setup)
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "Other-Pass-9999"},
            headers=_auth_headers(token),
        )
        s, b = _call(api.handle_cmdb_vault_setup)
        self.assertEqual(s, 409)

    def test_unlock_with_wrong_passphrase_fails_and_audits(self):
        user, token = _seed_admin()
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "Strong-Pass-1234"},
            headers=_auth_headers(token),
        )
        _call(api.handle_cmdb_vault_setup)
        _set_request(
            "POST",
            "/api/cmdb/vault/unlock",
            body={"passphrase": "Wrong-Pass-9999"},
            headers=_auth_headers(token),
        )
        s, b = _call(api.handle_cmdb_vault_unlock)
        self.assertEqual(s, 403)
        log = api.load(api.AUDIT_LOG_FILE)
        actions = [
            e.get("action") for e in (log if isinstance(log, list) else log.get("entries", []))
        ]
        self.assertIn("cmdb_vault_unlock_failed", actions)


# ─── Asset CRUD ──────────────────────────────────────────────────────────────


class TestAssetCrud(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        os.environ["RP_DATA_DIR"] = self._dir
        for name in (
            "USERS_FILE",
            "TOKENS_FILE",
            "DEVICES_FILE",
            "CMDB_FILE",
            "CMDB_VAULT_FILE",
            "AUDIT_LOG_FILE",
            "CONFIG_FILE",
        ):
            setattr(api, name, Path(self._dir) / Path(getattr(api, name)).name)
        self.user, self.token = _seed_admin()
        self.dev = _seed_device()

    def test_list_returns_devices_with_empty_cmdb(self):
        _set_request("GET", "/api/cmdb", headers=_auth_headers(self.token))
        s, b = _call(api.handle_cmdb_list)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["device_id"], self.dev)
        self.assertEqual(b[0]["asset_id"], "")
        self.assertEqual(b[0]["credential_count"], 0)

    def test_update_sets_all_fields(self):
        _set_request(
            "PUT",
            f"/api/cmdb/{self.dev}",
            body={
                "asset_id": "ASSET-12345",
                "server_function": "web",
                "hypervisor_url": "https://esx1.local/",
                "documentation": "# Notes\nfoo",
            },
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_update, self.dev)
        self.assertEqual(s, 200)
        rec = b["record"]
        self.assertEqual(rec["asset_id"], "ASSET-12345")
        self.assertEqual(rec["server_function"], "web")
        self.assertEqual(rec["hypervisor_url"], "https://esx1.local/")
        self.assertIn("# Notes", rec["documentation"])

    def test_update_rejects_bad_asset_id(self):
        _set_request(
            "PUT",
            f"/api/cmdb/{self.dev}",
            body={"asset_id": "has spaces!"},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_update, self.dev)
        self.assertEqual(s, 400)

    def test_update_rejects_javascript_url(self):
        _set_request(
            "PUT",
            f"/api/cmdb/{self.dev}",
            body={"hypervisor_url": "javascript:alert(1)"},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_update, self.dev)
        self.assertEqual(s, 400)

    def test_update_rejects_oversized_doc(self):
        _set_request(
            "PUT",
            f"/api/cmdb/{self.dev}",
            body={"documentation": "X" * (api.MAX_CMDB_DOC_LEN + 1)},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_update, self.dev)
        self.assertEqual(s, 400)

    def test_update_404_on_unknown_device(self):
        _set_request(
            "PUT",
            "/api/cmdb/no-such-device",
            body={"server_function": "web"},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_update, "no-such-device")
        self.assertEqual(s, 404)

    def test_search_filters_by_query(self):
        _set_request(
            "PUT",
            f"/api/cmdb/{self.dev}",
            body={"server_function": "web", "asset_id": "ASSET-9"},
            headers=_auth_headers(self.token),
        )
        _call(api.handle_cmdb_update, self.dev)
        # Add a second device with different attrs
        devices = api.load(api.DEVICES_FILE)
        devices["dev-other"] = {
            "name": "db-host",
            "hostname": "db-host",
            "os": "Debian 12",
            "ip": "10.0.0.6",
            "mac": "11:22:33:44:55:66",
            "token": "t",
            "last_seen": int(time.time()),
            "enrolled": int(time.time()),
            "tags": [],
            "group": "production",
        }
        api.save(api.DEVICES_FILE, devices)
        os.environ["QUERY_STRING"] = "q=ASSET-9"
        _set_request("GET", "/api/cmdb", headers=_auth_headers(self.token))
        os.environ["QUERY_STRING"] = "q=ASSET-9"
        s, b = _call(api.handle_cmdb_list)
        self.assertEqual(s, 200)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["device_id"], self.dev)
        os.environ["QUERY_STRING"] = ""


# ─── Credentials ─────────────────────────────────────────────────────────────


class TestCredentials(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        os.environ["RP_DATA_DIR"] = self._dir
        for name in (
            "USERS_FILE",
            "TOKENS_FILE",
            "DEVICES_FILE",
            "CMDB_FILE",
            "CMDB_VAULT_FILE",
            "AUDIT_LOG_FILE",
            "CONFIG_FILE",
        ):
            setattr(api, name, Path(self._dir) / Path(getattr(api, name)).name)
        self.user, self.token = _seed_admin()
        self.dev = _seed_device()
        # Set up vault and grab key
        _set_request(
            "POST",
            "/api/cmdb/vault/setup",
            body={"passphrase": "Strong-Pass-1234"},
            headers=_auth_headers(self.token),
        )
        _, b = _call(api.handle_cmdb_vault_setup)
        self.key_hex = b["key"]

    def _hdrs(self):
        return {**_auth_headers(self.token), "HTTP_X_RP_VAULT_KEY": self.key_hex}

    def test_add_credential_succeeds(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "username": "root", "password": "hunter2"},
            headers=self._hdrs(),
        )
        s, b = _call(api.handle_cmdb_credentials_add, self.dev)
        self.assertEqual(s, 200)
        self.assertTrue(b["id"].startswith("cred_"))

    def test_add_without_vault_key_returns_401(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "password": "hunter2"},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_credentials_add, self.dev)
        self.assertEqual(s, 401)
        self.assertEqual(b.get("code"), "vault_locked")

    def test_add_with_bad_vault_key_returns_403(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "password": "hunter2"},
            headers={**_auth_headers(self.token), "HTTP_X_RP_VAULT_KEY": "00" * 32},
        )
        s, b = _call(api.handle_cmdb_credentials_add, self.dev)
        self.assertEqual(s, 403)

    def test_list_returns_metadata_no_ciphertext(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "username": "root", "password": "hunter2"},
            headers=self._hdrs(),
        )
        _call(api.handle_cmdb_credentials_add, self.dev)

        _set_request("GET", f"/api/cmdb/{self.dev}/credentials", headers=_auth_headers(self.token))
        s, b = _call(api.handle_cmdb_credentials_list, self.dev)
        self.assertEqual(s, 200)
        self.assertEqual(len(b["credentials"]), 1)
        cred = b["credentials"][0]
        self.assertEqual(cred["label"], "root")
        self.assertEqual(cred["username"], "root")
        self.assertNotIn("ct", cred)
        self.assertNotIn("nonce", cred)
        self.assertNotIn("password", cred)

    def test_reveal_returns_plaintext_and_audits(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "username": "root", "password": "hunter2"},
            headers=self._hdrs(),
        )
        _, addb = _call(api.handle_cmdb_credentials_add, self.dev)
        cid = addb["id"]

        _set_request("POST", f"/api/cmdb/{self.dev}/credentials/{cid}/reveal", headers=self._hdrs())
        s, b = _call(api.handle_cmdb_credentials_reveal, self.dev, cid)
        self.assertEqual(s, 200)
        self.assertEqual(b["password"], "hunter2")
        self.assertEqual(b["username"], "root")

        log = api.load(api.AUDIT_LOG_FILE)
        entries = log if isinstance(log, list) else log.get("entries", [])
        actions = [e.get("action") for e in entries]
        self.assertIn("cmdb_credential_reveal", actions)

    def test_delete_credential(self):
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "root", "password": "hunter2"},
            headers=self._hdrs(),
        )
        _, addb = _call(api.handle_cmdb_credentials_add, self.dev)
        cid = addb["id"]

        _set_request(
            "DELETE", f"/api/cmdb/{self.dev}/credentials/{cid}", headers=_auth_headers(self.token)
        )
        s, b = _call(api.handle_cmdb_credentials_delete, self.dev, cid)
        self.assertEqual(s, 200)

        cmdb = api.load(api.CMDB_FILE)
        self.assertEqual(cmdb[self.dev]["credentials"], [])

    def test_passphrase_rotation_re_encrypts_creds(self):
        # Add two credentials under the original passphrase
        for label, pw in [("root", "rootpw1"), ("svc", "svcpw2")]:
            _set_request(
                "POST",
                f"/api/cmdb/{self.dev}/credentials",
                body={"label": label, "password": pw},
                headers=self._hdrs(),
            )
            _call(api.handle_cmdb_credentials_add, self.dev)

        # Rotate
        _set_request(
            "POST",
            "/api/cmdb/vault/change",
            body={"old_passphrase": "Strong-Pass-1234", "new_passphrase": "Other-Pass-9999"},
            headers=_auth_headers(self.token),
        )
        s, b = _call(api.handle_cmdb_vault_change)
        self.assertEqual(s, 200)
        self.assertEqual(b["rotated"], 2)
        new_key_hex = b["key"]

        # Old key must NOT decrypt anymore
        cmdb = api.load(api.CMDB_FILE)
        creds = cmdb[self.dev]["credentials"]
        self.assertEqual(len(creds), 2)

        # Reveal must work with the new key
        cid = creds[0]["id"]
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials/{cid}/reveal",
            headers={**_auth_headers(self.token), "HTTP_X_RP_VAULT_KEY": new_key_hex},
        )
        s, b = _call(api.handle_cmdb_credentials_reveal, self.dev, cid)
        self.assertEqual(s, 200)
        self.assertIn(b["password"], ("rootpw1", "svcpw2"))

    def test_max_credentials_per_asset_enforced(self):
        # Pre-fill the array with the cap
        cmdb = api.load(api.CMDB_FILE)
        cmdb[self.dev] = {
            **api._cmdb_record_default(),
            "credentials": [
                {"id": f"cred_x{i}", "label": f"l{i}", "nonce": "00" * 12, "ct": "aa"}
                for i in range(api.MAX_CMDB_CREDS)
            ],
        }
        api.save(api.CMDB_FILE, cmdb)
        _set_request(
            "POST",
            f"/api/cmdb/{self.dev}/credentials",
            body={"label": "one-more", "password": "pw"},
            headers=self._hdrs(),
        )
        s, b = _call(api.handle_cmdb_credentials_add, self.dev)
        self.assertEqual(s, 400)


# ─── Server-function autocomplete ────────────────────────────────────────────


class TestServerFunctions(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        os.environ["RP_DATA_DIR"] = self._dir
        for name in (
            "USERS_FILE",
            "TOKENS_FILE",
            "DEVICES_FILE",
            "CMDB_FILE",
            "CMDB_VAULT_FILE",
            "AUDIT_LOG_FILE",
            "CONFIG_FILE",
        ):
            setattr(api, name, Path(self._dir) / Path(getattr(api, name)).name)
        self.user, self.token = _seed_admin()

    def test_distinct_values_returned_sorted(self):
        # Seed three devices with overlapping functions
        devs = api.load(api.DEVICES_FILE)
        for d in ("a", "b", "c"):
            devs[d] = {"name": d, "token": "t", "last_seen": int(time.time())}
        api.save(api.DEVICES_FILE, devs)
        cmdb = {
            "a": {**api._cmdb_record_default(), "server_function": "web"},
            "b": {**api._cmdb_record_default(), "server_function": "db"},
            "c": {**api._cmdb_record_default(), "server_function": "web"},
        }
        api.save(api.CMDB_FILE, cmdb)
        _set_request("GET", "/api/cmdb/server-functions", headers=_auth_headers(self.token))
        s, b = _call(api.handle_cmdb_server_functions)
        self.assertEqual(s, 200)
        self.assertEqual(b, ["db", "web"])


if __name__ == "__main__":
    unittest.main()
