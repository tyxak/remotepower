"""v6.4.2: a password someone else chose must be replaced on first use.

The enforcement half was fully built — `_enforce_password_change()` runs
pre-dispatch, `_PWCHG_ALLOWED_PATHS` whitelists the escape routes, the client
shows a banner — and exactly ONE place ever set the flag: the seeded default
admin. So:

  * an account an admin created kept the admin's invented password forever, and
  * the forgotten-password path (an admin resets it and reads it down the phone)
    ended by CLEARING the flag, which is precisely the case it exists for.

Run: python3 -m pytest tests/test_v642_forced_password_change.py -q
"""
import os
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_pwchg", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_PW = "Str0ng-Passw0rd!x"


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "require_auth", "verify_token",
                       "get_token_from_request", "audit_log", "method",
                       "_fire_control_plane_change")}
        api.require_admin_auth = lambda *a, **k: "root"
        api.audit_log = lambda *a, **k: None
        api._fire_control_plane_change = lambda *a, **k: None
        api.method = lambda: "POST"
        api.get_token_from_request = lambda: "tok"
        api.save(api.USERS_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def _call(self, fn, body, *a):
        api.get_json_obj = lambda: body
        api.get_json_body = lambda: body
        try:
            fn(*a)
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, "status", None), getattr(e, "body", None)
        return None, None

    def _flag(self, user):
        api._LOAD_CACHE.clear()
        return (api.load(api.USERS_FILE) or {}).get(user, {}).get("must_change_password")

    def _as(self, user, role="admin"):
        api.require_auth = lambda *a, **k: user
        api.verify_token = lambda *a, **k: (user, role)


class TestCreatedAccounts(_Base):
    def test_a_created_account_must_change_on_first_login(self):
        st, _b = self._call(api.handle_user_create,
                            {"username": "alice", "password": _PW, "role": "viewer"})
        self.assertEqual(st, 201)
        self.assertTrue(self._flag("alice"))

    def test_a_provisioner_can_opt_out(self):
        """An automated provisioner setting a real credential out of band."""
        self._call(api.handle_user_create,
                   {"username": "bot", "password": _PW, "role": "viewer",
                    "must_change_password": False})
        self.assertFalse(self._flag("bot"))

    def test_omitting_the_flag_gets_the_SAFER_behaviour(self):
        """An existing API caller that has never heard of this field must end up
        flagged, not unflagged — absent is not the same as false here."""
        self._call(api.handle_user_create,
                   {"username": "carol", "password": _PW, "role": "viewer"})
        self.assertTrue(self._flag("carol"))


class TestAdminResetVsSelfChange(_Base):
    def setUp(self):
        super().setUp()
        self._call(api.handle_user_create,
                   {"username": "alice", "password": _PW, "role": "viewer"})

    def test_an_admin_reset_re_flags_the_account(self):
        """The actual forgotten-password path: the admin invents a password and
        conveys it somehow. Clearing the flag there left a shared secret the
        product never asked anyone to replace."""
        self._as("root", "admin")
        st, b = self._call(api.handle_user_passwd,
                           {"username": "alice", "new_password": "An0ther-Passw0rd!"})
        self.assertEqual(st, 200, b)
        self.assertTrue(self._flag("alice"))

    def test_a_self_change_clears_it(self):
        """The pre-existing behaviour, now conditional — it must still work, or
        a user could never get out of the gate."""
        self._as("root", "admin")
        self._call(api.handle_user_passwd,
                   {"username": "alice", "new_password": "An0ther-Passw0rd!"})
        self._as("alice", "viewer")
        st, b = self._call(api.handle_user_passwd,
                           {"username": "alice", "old_password": "An0ther-Passw0rd!",
                            "new_password": "Alice-0wn-Passw0rd!"})
        self.assertEqual(st, 200, b)
        self.assertIsNone(self._flag("alice"))

    def test_a_self_change_still_requires_the_old_password(self):
        self._as("alice", "viewer")
        st, _b = self._call(api.handle_user_passwd,
                            {"username": "alice", "new_password": "Alice-0wn-Passw0rd!"})
        self.assertEqual(st, 401)


class TestTheGateItSetsIsReal(unittest.TestCase):
    """The flag is only worth setting because something enforces it."""

    def test_the_pre_dispatch_enforcement_exists(self):
        self.assertTrue(callable(getattr(api, "_enforce_password_change", None)))

    def test_the_change_password_route_is_reachable_while_gated(self):
        """Otherwise a flagged user is locked out with no way to comply."""
        allowed = getattr(api, "_PWCHG_ALLOWED_PATHS", ())
        self.assertTrue(any("passwd" in str(p) for p in allowed),
                        f"no password-change escape in {allowed!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
