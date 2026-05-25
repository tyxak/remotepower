#!/usr/bin/env python3
"""Unit tests for v1.11.11: web terminal CGI endpoints.

The actual websocket+SSH proxy lives in the remotepower-webterm daemon,
which we don't unit-test here (would need a real SSH server). What we DO
test is the CGI-side surface:

  - POST /api/webterm/auth re-prompts admin password and issues a ticket
  - Wrong password rejected, audit-logged
  - Unknown device 404
  - Unauthenticated rejected
  - Tickets stored in WEBTERM_TICKETS_FILE with right shape
  - Tickets expire on schedule
  - POST /api/webterm/audit accepts daemon's session-end report
  - Audit endpoint authenticates via shared secret
  - Wrong shared secret rejected
  - Audit details show up in audit_log.json
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v11111", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _capture(t):
    def fake(status, data):
        raise _Captured(status, data)
    t.respond = fake


def _set_request(method, path, body=None, headers=None):
    os.environ["REQUEST_METHOD"] = method
    os.environ["PATH_INFO"] = path
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    for k in ("HTTP_X_TOKEN", "HTTP_X_WEBTERM_SECRET"):
        os.environ.pop(k, None)
    for k, v in (headers or {}).items():
        os.environ[k] = v


def _call(handler, *args, **kwargs):
    _capture(api)
    try:
        handler(*args, **kwargs)
    except _Captured as c:
        return c.status, c.body
    raise AssertionError(f"{handler.__name__} did not call respond()")


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE", "TOKENS_FILE", "DEVICES_FILE",
        "AUDIT_LOG_FILE", "CONFIG_FILE", "PINS_FILE",
        "ENROLL_TOKENS_FILE", "WEBTERM_TICKETS_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


def _seed_admin(password='admin-secret-pw'):
    """Create an admin user and an active session token."""
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    user = next(iter(users))
    # Set a known password so we can re-validate later
    users[user]['password_hash'] = api.hash_password(password)
    api.save(api.USERS_FILE, users)
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": user, "created": int(time.time()),
        "ttl": 3600, "admin": True, "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return user, token, password


def _seed_device():
    """Create a device for the auth handler to look up."""
    devices = api.load(api.DEVICES_FILE)
    devices["dev-test"] = {
        "name": "test-host", "hostname": "test-host", "os": "Linux",
        "ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff",
        "token": "device-secret",
        "tags": [], "group": "",
        "enrolled": int(time.time()), "last_seen": int(time.time()),
    }
    api.save(api.DEVICES_FILE, devices)
    return "dev-test"


# ─── /api/webterm/auth ────────────────────────────────────────────────────────


class TestWebtermAuth(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        _, self.token, self.pw = _seed_admin()
        self.dev_id = _seed_device()

    def _auth_headers(self):
        return {"HTTP_X_TOKEN": self.token}

    def test_correct_password_issues_ticket(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw},
                     headers=self._auth_headers())
        status, body = _call(api.handle_webterm_auth)
        self.assertEqual(status, 200)
        # 32 url-safe bytes ≈ 43 chars
        self.assertGreaterEqual(len(body["ticket"]), 32)
        self.assertGreater(body["expires"], int(time.time()))
        self.assertLess(body["expires"], int(time.time()) + 120)
        self.assertEqual(body["device"]["id"], self.dev_id)
        self.assertEqual(body["device"]["ip"], "10.0.0.5")

    def test_ticket_persisted_to_disk(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw},
                     headers=self._auth_headers())
        _, body = _call(api.handle_webterm_auth)
        # The exact ticket should appear in WEBTERM_TICKETS_FILE
        tickets = api.load(api.WEBTERM_TICKETS_FILE)
        self.assertIn(body["ticket"], tickets)
        meta = tickets[body["ticket"]]
        self.assertEqual(meta["device_id"], self.dev_id)
        self.assertFalse(meta["used"])
        self.assertGreater(meta["expires"], meta["created"])

    def test_wrong_password_rejected(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": "wrong"},
                     headers=self._auth_headers())
        status, body = _call(api.handle_webterm_auth)
        self.assertEqual(status, 403)

    def test_wrong_password_audit_logged(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": "wrong"},
                     headers=self._auth_headers())
        _call(api.handle_webterm_auth)
        # The audit log should have webterm_auth_failed entry
        log = api.load(api.AUDIT_LOG_FILE)
        entries = log.get("entries", []) if isinstance(log, dict) else log
        actions = [e.get("action") for e in entries]
        self.assertIn("webterm_auth_failed", actions)

    def test_correct_password_audit_logged(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw},
                     headers=self._auth_headers())
        _call(api.handle_webterm_auth)
        log = api.load(api.AUDIT_LOG_FILE)
        entries = log.get("entries", []) if isinstance(log, dict) else log
        actions = [e.get("action") for e in entries]
        self.assertIn("webterm_ticket_issued", actions)

    def test_unauthenticated_rejected(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw})
        status, _ = _call(api.handle_webterm_auth)
        self.assertIn(status, (401, 403))

    def test_unknown_device_404(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": "nonexistent", "admin_password": self.pw},
                     headers=self._auth_headers())
        status, _ = _call(api.handle_webterm_auth)
        # Unknown device id might fail _validate_id (400) or device lookup (404)
        self.assertIn(status, (400, 404))

    def test_missing_device_id_400(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"admin_password": self.pw},
                     headers=self._auth_headers())
        status, _ = _call(api.handle_webterm_auth)
        self.assertEqual(status, 400)

    def test_missing_admin_password_400(self):
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id},
                     headers=self._auth_headers())
        status, _ = _call(api.handle_webterm_auth)
        self.assertEqual(status, 400)

    def test_get_method_not_allowed(self):
        _set_request("GET", "/api/webterm/auth", headers=self._auth_headers())
        status, _ = _call(api.handle_webterm_auth)
        self.assertEqual(status, 405)

    def test_each_call_issues_different_ticket(self):
        # Two consecutive calls should produce distinct tickets — important
        # because each ticket is single-use, so a UI re-fetch shouldn't
        # collide with a stored one.
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw},
                     headers=self._auth_headers())
        _, body1 = _call(api.handle_webterm_auth)
        _set_request("POST", "/api/webterm/auth",
                     body={"device_id": self.dev_id, "admin_password": self.pw},
                     headers=self._auth_headers())
        _, body2 = _call(api.handle_webterm_auth)
        self.assertNotEqual(body1["ticket"], body2["ticket"])


# ─── /api/webterm/audit ───────────────────────────────────────────────────────


class TestWebtermSessionAudit(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        # Set up a daemon secret in config
        cfg = api.load(api.CONFIG_FILE)
        self.secret = "shared-daemon-secret-abcdefghij"
        cfg["webterm_daemon_secret"] = self.secret
        api.save(api.CONFIG_FILE, cfg)

    def test_correct_secret_accepted(self):
        _set_request("POST", "/api/webterm/audit",
                     body={
                         "actor": "alice", "device_id": "dev-1",
                         "ssh_user": "root", "ssh_host": "10.0.0.5",
                         "duration_s": 120, "bytes_in": 350, "bytes_out": 4200,
                         "reason": "ws closed", "session_id": "abc123",
                     },
                     headers={"HTTP_X_WEBTERM_SECRET": self.secret})
        status, body = _call(api.handle_webterm_session_audit)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"))

    def test_wrong_secret_rejected(self):
        _set_request("POST", "/api/webterm/audit",
                     body={"actor": "alice"},
                     headers={"HTTP_X_WEBTERM_SECRET": "wrong-secret"})
        status, _ = _call(api.handle_webterm_session_audit)
        self.assertEqual(status, 403)

    def test_missing_secret_rejected(self):
        _set_request("POST", "/api/webterm/audit", body={"actor": "alice"})
        status, _ = _call(api.handle_webterm_session_audit)
        self.assertEqual(status, 403)

    def test_no_secret_configured_rejects(self):
        # Wipe config secret
        cfg = api.load(api.CONFIG_FILE)
        cfg["webterm_daemon_secret"] = ""
        api.save(api.CONFIG_FILE, cfg)
        _set_request("POST", "/api/webterm/audit", body={"actor": "alice"},
                     headers={"HTTP_X_WEBTERM_SECRET": "anything"})
        status, _ = _call(api.handle_webterm_session_audit)
        self.assertEqual(status, 403)

    def test_audit_appears_in_log(self):
        _set_request("POST", "/api/webterm/audit",
                     body={
                         "actor": "alice", "device_id": "dev-1",
                         "ssh_user": "root", "ssh_host": "10.0.0.5",
                         "duration_s": 60, "session_id": "xyz789",
                         "reason": "ws closed",
                     },
                     headers={"HTTP_X_WEBTERM_SECRET": self.secret})
        _call(api.handle_webterm_session_audit)
        log = api.load(api.AUDIT_LOG_FILE)
        entries = log.get("entries", []) if isinstance(log, dict) else log
        webterm_entries = [e for e in entries if e.get("action") == "webterm_session"]
        self.assertEqual(len(webterm_entries), 1)
        # Detail should contain the session ID and host
        detail = webterm_entries[0].get("detail", "")
        self.assertIn("xyz789", detail)
        self.assertIn("10.0.0.5", detail)
        self.assertIn("root", detail)

    def test_get_method_not_allowed(self):
        _set_request("GET", "/api/webterm/audit",
                     headers={"HTTP_X_WEBTERM_SECRET": self.secret})
        status, _ = _call(api.handle_webterm_session_audit)
        self.assertEqual(status, 405)


# ─── Ticket helper ────────────────────────────────────────────────────────────


class TestTicketPurge(unittest.TestCase):
    def setUp(self):
        _isolate(self)

    def test_purge_drops_expired(self):
        now = int(time.time())
        tickets = {
            "fresh-ticket": {"expires": now + 60, "used": False},
            "expired-ticket": {"expires": now - 60, "used": False},
            "used-ticket": {"expires": now + 60, "used": True},
        }
        out = api._purge_expired_webterm_tickets(tickets, now)
        self.assertIn("fresh-ticket", out)
        self.assertNotIn("expired-ticket", out)
        self.assertNotIn("used-ticket", out)


# ─── Webterm constants ────────────────────────────────────────────────────────


class TestWebtermConstants(unittest.TestCase):
    """Sanity-check the constants used by the daemon are at sensible values.

    The daemon reads these via runtime config, but the CGI's defaults
    are the canonical source. Catching changes here forces a conscious
    decision rather than a silent drift.
    """

    def test_ticket_ttl_in_range(self):
        self.assertGreaterEqual(api.WEBTERM_TICKET_TTL, 30)
        self.assertLessEqual(api.WEBTERM_TICKET_TTL, 600)

    def test_session_dir_under_data_dir(self):
        # The daemon writes recordings into this directory; should be
        # under DATA_DIR so the existing data-dir backup/permissions
        # cover it.
        self.assertEqual(api.WEBTERM_SESSION_DIR.parent, api.DATA_DIR)

    def test_max_session_log_bytes_reasonable(self):
        # 1 MB minimum (long sessions) and 100 MB max (footgun for grep)
        self.assertGreaterEqual(api.WEBTERM_MAX_SESSION_LOG_BYTES, 1 * 1024 * 1024)
        self.assertLessEqual(api.WEBTERM_MAX_SESSION_LOG_BYTES, 100 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
