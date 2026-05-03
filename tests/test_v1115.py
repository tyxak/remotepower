#!/usr/bin/env python3
"""Unit tests for v1.11.5: per-user UI preferences (density / filter / sort).

Covers:
  - _sanitise_ui_prefs strips unknown fields, caps lengths/lists, validates
    enums, and returns {} on overall size overflow.
  - GET /api/ui-prefs returns {} for fresh users, persisted dict otherwise.
  - POST /api/ui-prefs replaces (not merges) the stored prefs.
  - DELETE /api/ui-prefs wipes the stored prefs.
  - Auth required for all three endpoints.
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

_spec = importlib.util.spec_from_file_location("api_v1115", _CGI_BIN / "api.py")
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
    os.environ["QUERY_STRING"] = ""
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    os.environ["CONTENT_LENGTH"] = str(len(raw))
    api.sys.stdin = _StdinShim(raw)
    for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
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
        "USERS_FILE", "TOKENS_FILE", "DEVICES_FILE", "CMDB_FILE",
        "AUDIT_LOG_FILE", "CONFIG_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)
    t._data_dir = d


def _seed_user(username="testuser"):
    api.ensure_default_user()
    users = api.load(api.USERS_FILE)
    if username not in users:
        users[username] = {
            "password_hash": "x",
            "created": int(time.time()),
            "role": "admin",
        }
        api.save(api.USERS_FILE, users)
    token = api.make_token()
    tokens = api.load(api.TOKENS_FILE)
    tokens[token] = {
        "user": username,
        "created": int(time.time()),
        "ttl": 3600,
        "admin": True,
        "remember": False,
    }
    api.save(api.TOKENS_FILE, tokens)
    return username, token


class TestSanitiseUiPrefs(unittest.TestCase):
    """Schema enforcement on incoming prefs payloads."""

    def test_non_dict_returns_empty(self):
        self.assertEqual(api._sanitise_ui_prefs(None), {})
        self.assertEqual(api._sanitise_ui_prefs("string"), {})
        self.assertEqual(api._sanitise_ui_prefs([1, 2, 3]), {})

    def test_valid_density(self):
        out = api._sanitise_ui_prefs({"devices": {"density": "compact"}})
        self.assertEqual(out, {"devices": {"density": "compact"}})

    def test_invalid_density_dropped(self):
        out = api._sanitise_ui_prefs({"devices": {"density": "extreme"}})
        # Density was bad but the table key had no other valid fields → dropped
        self.assertEqual(out, {})

    def test_filter_truncated(self):
        long_str = "x" * 500
        out = api._sanitise_ui_prefs({"cves": {"filter": long_str}})
        self.assertLessEqual(len(out["cves"]["filter"]), api.MAX_UI_PREFS_FILTER_LEN)

    def test_sort_capped(self):
        sort = [{"col": f"col{i}", "dir": "asc"} for i in range(20)]
        out = api._sanitise_ui_prefs({"services": {"sort": sort}})
        self.assertLessEqual(len(out["services"]["sort"]), api.MAX_UI_PREFS_SORT_KEYS)

    def test_invalid_sort_direction_defaults_to_asc(self):
        out = api._sanitise_ui_prefs({"services": {"sort": [{"col": "name", "dir": "sideways"}]}})
        self.assertEqual(out["services"]["sort"][0]["dir"], "asc")

    def test_unknown_field_dropped(self):
        out = api._sanitise_ui_prefs({
            "devices": {
                "density": "compact",
                "evil_field": "drop me",
                "another": {"nested": "junk"},
            }
        })
        self.assertEqual(out["devices"], {"density": "compact"})

    def test_table_name_sanitised(self):
        # Special chars in table names get stripped
        out = api._sanitise_ui_prefs({"foo/../etc/passwd": {"density": "compact"}})
        # Should end up as "foo..etcpasswd" or similar — definitely not the path
        self.assertEqual(len(out), 1)
        self.assertNotIn("/", list(out.keys())[0])

    def test_empty_table_name_dropped(self):
        out = api._sanitise_ui_prefs({"!!!": {"density": "compact"}})
        # All chars stripped → empty key → dropped entirely
        self.assertEqual(out, {})

    def test_table_count_capped(self):
        many = {f"table_{i}": {"density": "compact"} for i in range(100)}
        out = api._sanitise_ui_prefs(many)
        self.assertLessEqual(len(out), api.MAX_UI_PREFS_TABLES)

    def test_oversized_payload_returns_empty(self):
        # Build something that passes per-field caps but overflows the
        # 16 KB total budget. Table-name cap is 50, filter cap is 256,
        # so we need to put more chars into each filter than 256 to
        # exceed 16 KB across 50 tables. Make each filter exactly the
        # 256-char max and then add 50 sort entries × col strings to
        # bulk it up beyond budget.
        bloat = {}
        for i in range(api.MAX_UI_PREFS_TABLES):
            bloat[f"t{i}"] = {
                "filter": "x" * api.MAX_UI_PREFS_FILTER_LEN,
                "sort": [{"col": "a" * 64, "dir": "asc"}
                         for _ in range(api.MAX_UI_PREFS_SORT_KEYS)],
            }
        out = api._sanitise_ui_prefs(bloat)
        self.assertEqual(out, {})

    def test_realistic_payload_round_trip(self):
        payload = {
            "devices": {"density": "spacious", "filter": "ubuntu"},
            "cves":    {"sort": [{"col": "critical", "dir": "desc"},
                                 {"col": "name",     "dir": "asc"}]},
            "tls":     {"filter": ".com", "density": "compact"},
        }
        out = api._sanitise_ui_prefs(payload)
        self.assertEqual(out, payload)


class TestUiPrefsEndpoints(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_user()

    def _auth(self):
        return {"HTTP_X_TOKEN": self.token}

    def test_get_returns_empty_for_fresh_user(self):
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        status, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(status, 200)
        self.assertEqual(body, {})

    def test_post_then_get_round_trip(self):
        prefs = {
            "devices": {"density": "compact", "filter": "linux"},
            "services": {"sort": [{"col": "name", "dir": "asc"}]},
        }
        _set_request("POST", "/api/ui-prefs", body=prefs, headers=self._auth())
        status, body = _call(api.handle_ui_prefs_set)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        # Now GET it back
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        status, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(status, 200)
        self.assertEqual(body, prefs)

    def test_post_replaces_not_merges(self):
        # First POST sets two tables
        first = {"devices": {"density": "compact"}, "cves": {"filter": "abc"}}
        _set_request("POST", "/api/ui-prefs", body=first, headers=self._auth())
        _call(api.handle_ui_prefs_set)
        # Second POST sets only one — the other should be gone
        second = {"tls": {"density": "spacious"}}
        _set_request("POST", "/api/ui-prefs", body=second, headers=self._auth())
        _call(api.handle_ui_prefs_set)

        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        _, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(body, second)
        self.assertNotIn("devices", body)
        self.assertNotIn("cves", body)

    def test_post_sanitises_input(self):
        # Send junk; expect it dropped silently in storage
        _set_request("POST", "/api/ui-prefs", body={
            "devices": {"density": "neon", "evil": "drop"},
        }, headers=self._auth())
        status, body = _call(api.handle_ui_prefs_set)
        self.assertEqual(status, 200)
        # Density invalid + no other valid fields → table dropped
        self.assertEqual(body["prefs"], {})

    def test_delete_clears(self):
        _set_request("POST", "/api/ui-prefs",
                     body={"devices": {"density": "compact"}},
                     headers=self._auth())
        _call(api.handle_ui_prefs_set)
        _set_request("DELETE", "/api/ui-prefs", headers=self._auth())
        status, body = _call(api.handle_ui_prefs_clear)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        # GET should now be empty
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        _, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(body, {})

    def test_get_requires_auth(self):
        _set_request("GET", "/api/ui-prefs")  # no auth header
        status, _ = _call(api.handle_ui_prefs_get)
        self.assertIn(status, (401, 403))

    def test_post_requires_auth(self):
        _set_request("POST", "/api/ui-prefs", body={"devices": {"density": "compact"}})
        status, _ = _call(api.handle_ui_prefs_set)
        self.assertIn(status, (401, 403))

    def test_post_rejects_non_object_body(self):
        _set_request("POST", "/api/ui-prefs", body=[1, 2, 3], headers=self._auth())
        status, _ = _call(api.handle_ui_prefs_set)
        self.assertEqual(status, 400)

    def test_per_user_isolation(self):
        # Second user should not see first user's prefs
        user2, token2 = _seed_user("otheruser")

        # User 1 stores prefs
        _set_request("POST", "/api/ui-prefs",
                     body={"devices": {"density": "spacious"}},
                     headers=self._auth())
        _call(api.handle_ui_prefs_set)

        # User 2 GETs — should see nothing
        _set_request("GET", "/api/ui-prefs", headers={"HTTP_X_TOKEN": token2})
        _, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(body, {})

        # User 1 still sees their own
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        _, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(body["devices"]["density"], "spacious")

    def test_post_method_check(self):
        # Wrong method to handler → 405
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        status, _ = _call(api.handle_ui_prefs_set)
        self.assertEqual(status, 405)

    def test_delete_method_check(self):
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        status, _ = _call(api.handle_ui_prefs_clear)
        self.assertEqual(status, 405)


# v1.11.6 — minimal density mode (one device per row)
class TestMinimalDensityMode(unittest.TestCase):
    """Confirm the new 'minimal' mode is accepted server-side. Prior to
    v1.11.6 the only allowed density values were compact/comfortable/
    spacious; v1.11.6 adds 'minimal' for the Devices grid one-line layout.
    """

    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_user("minuser")

    def _auth(self):
        return {"HTTP_X_TOKEN": self.token}

    def test_minimal_value_accepted(self):
        out = api._sanitise_ui_prefs({"devices": {"density": "minimal"}})
        self.assertEqual(out, {"devices": {"density": "minimal"}})

    def test_minimal_in_allowed_set(self):
        self.assertIn("minimal", api.UI_DENSITY_VALUES)
        # Default should remain unchanged — minimal is opt-in, not the
        # new default. Users on existing accounts should keep
        # 'comfortable' until they switch.
        self.assertEqual(api.UI_DENSITY_DEFAULT, "comfortable")

    def test_minimal_round_trips_through_endpoint(self):
        _set_request("POST", "/api/ui-prefs",
                     body={"devices": {"density": "minimal"}},
                     headers=self._auth())
        status, body = _call(api.handle_ui_prefs_set)
        self.assertEqual(status, 200)
        self.assertEqual(body["prefs"]["devices"]["density"], "minimal")
        # And it persists
        _set_request("GET", "/api/ui-prefs", headers=self._auth())
        _, body = _call(api.handle_ui_prefs_get)
        self.assertEqual(body["devices"]["density"], "minimal")

    def test_old_3_modes_still_work(self):
        # Regression check: nothing about adding a 4th mode broke the
        # existing three.
        for mode in ("compact", "comfortable", "spacious"):
            with self.subTest(mode=mode):
                out = api._sanitise_ui_prefs({"devices": {"density": mode}})
                self.assertEqual(out["devices"]["density"], mode)

    def test_unknown_density_still_rejected(self):
        # Adding 'minimal' shouldn't loosen the allowlist
        out = api._sanitise_ui_prefs({"devices": {"density": "ultracompact"}})
        self.assertEqual(out, {})


if __name__ == "__main__":
    unittest.main()
