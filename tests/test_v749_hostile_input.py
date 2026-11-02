#!/usr/bin/env python3
"""Hostile input no longer answers 500 (7.4.9; the fuzz sweep, findings F1 to F5 and F10).

The fuzz agent sent 31,982 hostile requests to the routes of a seeded stack, mutated stored rows and replayed hostile heartbeats.
Five classes of 500 came out of the request side, each from a rule that was applied in a few places and missed in the rest:

  * `hmac.compare_digest` raises TypeError on a `str` with a non-ASCII character. All 20 call sites compared a `str`, so a
    non-ASCII token was a 500 before authentication (`/api/heartbeat` and seven more agent routes). One helper, `secure_eq`,
    compares the UTF-8 bytes and never raises; a ratchet fails on a bare compare_digest anywhere else.
  * a lone surrogate in any JSON string (`"\\ud83d"`) is valid to Python and cannot be encoded, so the first `.encode()` raised
    (12 routes, two of them public portal routes). One scrub in `get_json_body` replaces it with U+FFFD.
  * `Infinity` reached `int()` in four shared coercers, which catch TypeError and ValueError but not OverflowError (25 routes).
  * a host's own token could answer itself 500: `live-sample` and the SCAP report held `NaN`, `Infinity` and 10**400, and
    `last_oom_ts` = `Infinity` made the whole heartbeat raise.
  * a list or dict where a string is expected, used in a membership test or as a key, is unhashable (three admin routes).

Each is driven through the real code. The controls: a good value is still accepted, and with the fix taken out the 500 comes back.
"""
import ast
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-hostile-"))
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v749_hostile", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]
import request_models  # noqa: E402
import secure_eq  # noqa: E402

DEV = "h1"
TOKEN = "legacy-plain-token"


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


class TestSecureEq(unittest.TestCase):

    def test_equal_and_unequal_text(self):
        self.assertTrue(secure_eq.secure_eq("abc", "abc"))
        self.assertFalse(secure_eq.secure_eq("abc", "abd"))
        self.assertFalse(secure_eq.secure_eq("abc", "abcd"))

    def test_non_ascii_text_does_not_raise(self):
        self.assertTrue(secure_eq.secure_eq("é", "é"))
        self.assertFalse(secure_eq.secure_eq("é", "e"))
        self.assertFalse(secure_eq.secure_eq("abc", "é"))
        self.assertFalse(secure_eq.secure_eq("…", "abc"))

    def test_a_lone_surrogate_is_not_equal_and_does_not_raise(self):
        self.assertFalse(secure_eq.secure_eq("\ud83d", "abc"))
        self.assertFalse(secure_eq.secure_eq("abc", "\ud83d"))

    def test_bytes_and_mixed_types(self):
        self.assertTrue(secure_eq.secure_eq(b"abc", "abc"))
        self.assertFalse(secure_eq.secure_eq(b"abc", b"abd"))
        self.assertFalse(secure_eq.secure_eq(123, "123"), "a number is not a secret")

    def test_empty_or_missing_is_never_equal(self):
        for a, b in (("", ""), (None, None), ("", "x"), ("x", None), (b"", b"")):
            with self.subTest(a=a, b=b):
                self.assertFalse(secure_eq.secure_eq(a, b))

    def test_control_the_standard_call_raises_on_the_same_input(self):
        import hmac
        with self.assertRaises(TypeError):
            hmac.compare_digest("é", "e")


class TestNoCallerBypassesIt(unittest.TestCase):

    def test_no_bare_compare_digest_is_left_in_the_server(self):
        offenders, files = [], sorted(p for p in _CGI.glob("*.py") if p.name != "secure_eq.py")
        self.assertGreater(len(files), 40)
        for f in files:
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "compare_digest":
                    offenders.append(f"{f.name}:{node.lineno}")
        self.assertEqual(offenders, [], "compare secrets with secure_eq, which never raises")

    def test_the_ratchet_sees_a_bare_call(self):
        tree = ast.parse("import hmac\nhmac.compare_digest(a, b)\n")
        self.assertTrue(any(isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "compare_digest" for n in ast.walk(tree)))


class _Handler(unittest.TestCase):

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond", "verify_token")}
        self._env = dict(os.environ)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {DEV: {"id": DEV, "name": "h1", "hostname": "h1", "token": TOKEN, "last_seen": now,
                                          "enrolled": now, "tags": [], "group": "", "sysinfo": {}, "monitored": True}})
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.CONFIG_FILE, {}),
                         (api.MAINT_FILE, {"windows": []}), (api.MAINT_SUPPRESS_LOG, {"entries": []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

        def fake(status, data, *a, **k):
            raise _Captured(status, data)
        setattr(api, "respond", fake)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def run_handler(self, fn, verb, path, body_text, *args, who=None):
        raw = body_text if isinstance(body_text, bytes) else body_text.encode("utf-8", "surrogatepass")
        os.environ.update({"REQUEST_METHOD": verb, "PATH_INFO": path, "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw)),
                           "HTTP_X_TOKEN": "tok"})
        if who:
            setattr(api, "verify_token", lambda *_a, **_k: who)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            fn(*args)
        except _Captured as c:
            return c.status, c.body
        self.fail("the handler did not respond")


class TestANonAsciiTokenIsRefusedNotAFault(_Handler):

    def test_device_token_check_returns_false(self):
        dev = {"token": TOKEN}
        self.assertFalse(api._device_token_ok(dev, "é"))
        self.assertFalse(api._device_token_ok({"token_hash": api._hash_device_token(TOKEN)}, "é"))
        self.assertTrue(api._device_token_ok(dev, TOKEN), "the right token still works")

    def test_the_heartbeat_answers_403(self):
        body = json.dumps({"device_id": DEV, "token": "é"})
        status, _ = self.run_handler(api.handle_heartbeat, "POST", "/api/heartbeat", body)
        self.assertEqual(status, 403)

    def test_the_live_sample_route_answers_403(self):
        body = json.dumps({"token": "é", "cpu": 1})
        status, _ = self.run_handler(api.handle_device_live_sample, "POST", f"/api/devices/{DEV}/live-sample", body, DEV)
        self.assertEqual(status, 403)


class TestALoneSurrogateIsScrubbed(_Handler):

    def test_every_string_and_key_is_cleaned_at_the_boundary(self):
        raw = '{"token": "\\ud83d", "k\\ud83d": ["a\\ud83dz", {"deep\\ude00": "x\\udc00"}], "n": 5, "ok": "fine"}'
        os.environ.update({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw.encode())
        body = api.get_json_body()
        text = json.dumps(body, ensure_ascii=True)
        self.assertNotRegex(text, r"\\ud[89a-f][0-9a-f]{2}", "no surrogate is left in any string or key")
        self.assertEqual(body["token"], "�")
        self.assertEqual(body["n"], 5)
        self.assertEqual(body["ok"], "fine")
        body["token"].encode("utf-8")           # encodable now

    def test_the_portal_hash_that_raised_no_longer_does(self):
        raw = '{"token": "\\ud83d"}'
        os.environ.update({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw.encode())
        api._portal_hash(api.get_json_body()["token"])

    def test_control_without_the_scrub_the_string_cannot_be_encoded(self):
        import json as _json
        s = _json.loads('"\\ud83d"')
        with self.assertRaises(UnicodeEncodeError):
            s.encode("utf-8")

    def test_ordinary_unicode_is_untouched(self):
        raw = json.dumps({"name": "Zoë – 日本語 😀"}, ensure_ascii=False)
        os.environ.update({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(raw.encode()))})
        api.sys.stdin = _Stdin(raw.encode())
        self.assertEqual(api.get_json_body()["name"], "Zoë – 日本語 😀")


class TestInfinityAndHugeNumbersAreRefusedNotAFault(_Handler):

    def test_no_request_model_raises_on_a_number_it_cannot_hold(self):
        models = [m for m in vars(request_models).values()
                  if isinstance(m, type) and hasattr(m, "model_fields") and m.__module__ == request_models.__name__]
        self.assertGreater(len(models), 100, "the population is the request models")
        bad = [float("inf"), float("-inf"), float("nan"), 10 ** 400, -(10 ** 400)]
        tried = 0
        for m in models:
            for field in m.model_fields:
                for v in bad:
                    tried += 1
                    try:
                        request_models.validate(m, {field: v})
                    except Exception as e:                       # noqa: BLE001 - any exception is the defect
                        self.fail(f"{m.__name__}.{field} = {v!r:.20} raised {type(e).__name__}: {e}")
        self.assertGreater(tried, 3000)

    def test_a_host_token_cannot_make_the_live_sample_route_fail(self):
        for cpu in ("Infinity", "-Infinity", "NaN", "1" + "0" * 400):
            with self.subTest(cpu=cpu[:12]):
                body = '{"token": "%s", "cpu": %s, "mem": 40.5}' % (TOKEN, cpu)
                status, _ = self.run_handler(api.handle_device_live_sample, "POST", f"/api/devices/{DEV}/live-sample", body, DEV)
                self.assertEqual(status, 200)
        api._LOAD_CACHE.clear()
        ring = api.load(api.LIVE_SAMPLES_FILE)[DEV]
        self.assertTrue(all(s["cpu"] is None for s in ring[:4]), "a reading that is not a number is stored as none")
        self.assertEqual(ring[-1]["mem"], 40.5, "a good reading is kept")

    def test_last_oom_ts_infinity_does_not_fail_the_heartbeat(self):
        for ts in ("Infinity", "NaN", "1" + "0" * 400):
            with self.subTest(ts=ts[:12]):
                body = '{"device_id": "%s", "token": "%s", "sysinfo": {"last_oom_ts": %s, "hostname": "h1"}}' % (DEV, TOKEN, ts)
                status, _ = self.run_handler(api.handle_heartbeat, "POST", "/api/heartbeat", body)
                self.assertEqual(status, 200)

    def test_a_real_oom_time_is_still_recorded(self):
        body = '{"device_id": "%s", "token": "%s", "sysinfo": {"last_oom_ts": 1700000000, "hostname": "h1"}}' % (DEV, TOKEN)
        status, _ = self.run_handler(api.handle_heartbeat, "POST", "/api/heartbeat", body)
        self.assertEqual(status, 200)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.DEVICES_FILE)[DEV]["sysinfo"].get("last_oom_ts"), 1700000000)


class TestAListWhereAStringIsExpected(_Handler):

    def test_a_role_body_with_unhashable_permissions_is_cleaned(self):
        out, err = api._clean_role_body({"name": "ops", "permissions": [{}, [], "exec", "nonsense"]})
        self.assertIsNone(err)
        self.assertEqual(out["permissions"], ["exec"], "the unhashable and unknown entries are dropped, the real one kept")

    def test_an_api_key_role_that_is_a_list_is_a_400(self):
        api.save(api.APIKEYS_FILE, {"k1": {"name": "n", "role": "viewer", "key_hash": "x", "created": 1}})
        api._LOAD_CACHE.clear()
        for role in ("[]", "{}"):
            with self.subTest(role=role):
                status, _ = self.run_handler(api.handle_apikeys_update, "PATCH", "/api/apikeys/k1", '{"role": %s}' % role,
                                             "k1", who=("admin1", "admin"))
                self.assertEqual(status, 400)

    def test_an_incident_with_unhashable_alert_ids_is_not_a_fault(self):
        status, _ = self.run_handler(api.handle_incidents, "POST", "/api/incidents", '{"title": "t", "alert_ids": [{}, [], "a1"]}',
                                     who=("admin1", "admin"))
        self.assertIn(status, (200, 201, 400))


if __name__ == "__main__":
    unittest.main()
