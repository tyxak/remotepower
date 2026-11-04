#!/usr/bin/env python3
"""Changing your own password keeps the session you changed it in (7.5.0 docs review).

The page says a password change "signs out every other session that is signed in as you", the guide says the same, and the page toasts
"Password updated" and carries on. The handler removed every token of the account, the current one too, so the next request sent the
person to the sign-in page. An administrator who resets someone else's password still signs that account out of everything.

Real token store, real handler; only the caller's identity and token are set.
"""
import hashlib
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-pwsess-"))
ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v750_pwsess", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

OLD, NEW = "Old-Passw0rd-Str0ng!x", "New-Passw0rd-Str0ng!y"


def row(user):
    return {"user": user, "created": int(time.time()), "ttl": 3600, "ip": "192.0.2.1"}


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n) for n in ("require_auth", "verify_token", "get_token_from_request", "audit_log", "method",
                                                    "get_json_obj", "get_json_body", "respond")}
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "POST"
        api.save(api.USERS_FILE, {"alice": {"password_hash": api.hash_password(OLD), "role": "operator"},
                                  "bob": {"password_hash": api.hash_password(OLD), "role": "viewer"},
                                  "root": {"password_hash": api.hash_password(OLD), "role": "admin"}})
        raw_hashed = hashlib.sha256(b"tokH").hexdigest()
        api.save(api.TOKENS_FILE, {"tokA": row("alice"), "tokB": row("alice"), raw_hashed: row("alice"), "tokC": row("bob"),
                                   "tokR": row("root")})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, who, role, token, body):
        api.require_auth = lambda *a, **k: who
        api.verify_token = lambda *a, **k: (who, role)
        api.get_token_from_request = lambda: token
        api.get_json_obj = lambda: body
        api.get_json_body = lambda: body
        out = {}

        def respond(status, data=None):
            out["s"], out["d"] = status, data
            raise api.HTTPError(status, data)
        api.respond = respond
        try:
            api.handle_user_passwd()
        except api.HTTPError:
            pass
        return out.get("s"), out.get("d")

    def sessions(self):
        api._LOAD_CACHE.clear()
        return sorted(api.load(api.TOKENS_FILE))


class TestChangingYourOwn(_Base):

    def test_the_session_you_did_it_in_survives_and_the_others_do_not(self):
        st, d = self.call("alice", "operator", "tokA", {"username": "alice", "old_password": OLD, "new_password": NEW})
        self.assertEqual((st, d), (200, {"ok": True}))
        left = self.sessions()
        self.assertIn("tokA", left)
        self.assertNotIn("tokB", left)
        self.assertNotIn(hashlib.sha256(b"tokH").hexdigest(), left)

    def test_a_session_stored_under_its_hash_is_found_too(self):
        st, _d = self.call("alice", "operator", "tokH", {"username": "alice", "old_password": OLD, "new_password": NEW})
        self.assertEqual(st, 200)
        self.assertEqual([t for t in self.sessions() if t in ("tokA", "tokB", hashlib.sha256(b"tokH").hexdigest())],
                         [hashlib.sha256(b"tokH").hexdigest()])

    def test_nobody_elses_sessions_are_touched(self):
        self.call("alice", "operator", "tokA", {"username": "alice", "old_password": OLD, "new_password": NEW})
        left = self.sessions()
        self.assertIn("tokC", left)
        self.assertIn("tokR", left)

    def test_the_password_changed(self):
        self.call("alice", "operator", "tokA", {"username": "alice", "old_password": OLD, "new_password": NEW})
        api._LOAD_CACHE.clear()
        h = api.load(api.USERS_FILE)["alice"]["password_hash"]
        self.assertTrue(api.verify_password(NEW, h))
        self.assertFalse(api.verify_password(OLD, h))

    def test_a_wrong_old_password_signs_nobody_out_and_changes_nothing(self):
        st, _d = self.call("alice", "operator", "tokA", {"username": "alice", "old_password": "wrong", "new_password": NEW})
        self.assertEqual(st, 403)
        self.assertEqual(self.sessions(), sorted(["tokA", "tokB", hashlib.sha256(b"tokH").hexdigest(), "tokC", "tokR"]))
        api._LOAD_CACHE.clear()
        self.assertTrue(api.verify_password(OLD, api.load(api.USERS_FILE)["alice"]["password_hash"]))

    def test_a_request_without_a_token_keeps_nothing_it_cannot_name(self):
        """No token to keep (an API key call): every session of the account goes, as a reset does."""
        st, _d = self.call("alice", "operator", "", {"username": "alice", "old_password": OLD, "new_password": NEW})
        self.assertEqual(st, 200)
        left = self.sessions()
        self.assertFalse({"tokA", "tokB"} & set(left))


class TestAnAdministratorResettingSomeoneElses(_Base):

    def test_that_account_is_signed_out_of_everything_and_the_admin_keeps_theirs(self):
        st, _d = self.call("root", "admin", "tokR", {"username": "alice", "new_password": NEW})
        self.assertEqual(st, 200)
        left = self.sessions()
        self.assertFalse({"tokA", "tokB", hashlib.sha256(b"tokH").hexdigest()} & set(left))
        self.assertIn("tokR", left)
        self.assertIn("tokC", left)

    def test_resetting_your_own_as_an_admin_is_a_self_change(self):
        api.save(api.TOKENS_FILE, {"tokR": row("root"), "tokR2": row("root")})
        api._LOAD_CACHE.clear()
        st, _d = self.call("root", "admin", "tokR", {"username": "root", "old_password": OLD, "new_password": NEW})
        self.assertEqual(st, 200)
        self.assertEqual(self.sessions(), ["tokR"])

    def test_a_row_that_is_not_a_map_does_not_break_the_sweep(self):
        api.save(api.TOKENS_FILE, {"tokA": row("alice"), "junk": "x", "junk2": None, "tokB": row("alice")})
        api._LOAD_CACHE.clear()
        st, _d = self.call("alice", "operator", "tokA", {"username": "alice", "old_password": OLD, "new_password": NEW})
        self.assertEqual(st, 200)
        self.assertIn("tokA", self.sessions())


class TestTheTextsAgree(unittest.TestCase):
    def test_the_page_and_the_guide_still_say_every_other_session(self):
        self.assertIn("signs out every other session", (ROOT / "server/html/index.html").read_text())
        self.assertIn("every other session is signed out", (ROOT / "docs/my-account.md").read_text())


if __name__ == "__main__":
    unittest.main()
