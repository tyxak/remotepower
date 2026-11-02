#!/usr/bin/env python3
"""A read-only role cannot rewrite a host's service and log-watch rules by changing the HTTP verb (7.4.9, High).

`/api/devices/{id}/services/config` is an any-method route. `handle_services_config` asked for the `services` permission only when
the verb was POST (`require_perm(...) if method() == 'POST' else None`), so a PUT, PATCH or DELETE went to the write code below
the GET branch with a bare `require_auth()`. A viewer, an auditor, a finance user, a read-only API key or a tenant viewer could
replace the host's watched services and its log-watch rules, which include file-tail rules the agent turns into reads of a file
path, and could empty the rules the operator had set. The audit row had an empty actor. Found by the authorization matrix (the
authz agent), reproduced here through the real handler with only `verify_token` stubbed, so the real gates run.

Only GET and POST are routes of this endpoint, so every other verb is now refused after authentication with a 405.

The ratchet looks for the shape of the miss, a permission asked for inside a method conditional expression, because the file read
as though the rule was applied.
"""
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-svc-"))
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v749_svc", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]

DEV = "h1"
RULES = {"services_watched": ["sshd.service"],
         "log_watch": [{"path": "/var/log/auth.log", "pattern": "Failed", "threshold": 1, "severity": "WARN"}]}
ORIGINAL = {"services_watched": ["nginx.service"], "log_watch": []}


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


class TestEveryVerbIsGated(unittest.TestCase):

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond", "verify_token")}
        self._env = dict(os.environ)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {DEV: {"id": DEV, "name": "h1", "hostname": "h1", "token": "t", "last_seen": now,
                                          "enrolled": now, "tags": [], "group": "", "sysinfo": {}, "monitored": True,
                                          **ORIGINAL}})
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

    def call(self, verb, user, role, body=None):
        raw = json.dumps(body or {}).encode()
        os.environ.update({"REQUEST_METHOD": verb, "PATH_INFO": f"/api/devices/{DEV}/services/config", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw)), "HTTP_X_TOKEN": "tok"})
        setattr(api, "verify_token", lambda *_a, **_k: (user, role) if user else (None, None))
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_services_config(DEV)
        except _Captured as c:
            return c.status, c.body
        self.fail("the handler did not respond")

    def stored(self):
        api._LOAD_CACHE.clear()
        d = api.load(api.DEVICES_FILE)[DEV]
        return {"services_watched": d.get("services_watched"), "log_watch": d.get("log_watch")}

    def test_a_viewer_cannot_change_the_rules_with_any_verb(self):
        for verb in ("PUT", "PATCH", "DELETE", "POST"):
            with self.subTest(verb=verb):
                status, _ = self.call(verb, "viewer1", "viewer", RULES)
                self.assertIn(status, (403, 405))
                self.assertEqual(self.stored(), ORIGINAL, "nothing was written")

    def test_a_viewer_cannot_empty_the_rules(self):
        status, _ = self.call("PATCH", "viewer1", "viewer", {})
        self.assertIn(status, (403, 405))
        self.assertEqual(self.stored(), ORIGINAL)

    def test_the_other_read_only_roles_are_refused_too(self):
        for role in ("auditor", "finance", "mcp"):
            for verb in ("PUT", "PATCH", "DELETE", "POST"):
                with self.subTest(role=role, verb=verb):
                    status, _ = self.call(verb, f"{role}1", role, RULES)
                    self.assertIn(status, (403, 405))
                    self.assertEqual(self.stored(), ORIGINAL)

    def test_an_anonymous_caller_gets_401_for_every_verb(self):
        for verb in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(verb=verb):
                status, _ = self.call(verb, None, None, RULES)
                self.assertEqual(status, 401)
                self.assertEqual(self.stored(), ORIGINAL)

    def test_the_routes_that_exist_still_work(self):
        status, body = self.call("GET", "viewer1", "viewer")
        self.assertEqual(status, 200)
        self.assertEqual(body["services_watched"], ORIGINAL["services_watched"], "a viewer may read the rules")
        status, body = self.call("POST", "admin1", "admin", RULES)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.stored()["services_watched"], ["sshd.service"])
        self.assertEqual(len(self.stored()["log_watch"]), 1)

    def test_an_administrator_gets_a_405_for_a_verb_that_is_not_a_route(self):
        status, _ = self.call("PUT", "admin1", "admin", RULES)
        self.assertEqual(status, 405)
        self.assertEqual(self.stored(), ORIGINAL)


class TestNoPermissionIsAskedForInsideAMethodConditional(unittest.TestCase):

    SHAPE = re.compile(r"require_(?:perm|admin_auth|write_role)\([^)]*\)\s+if\s+method\(\)")

    def test_no_handler_gates_by_a_method_conditional_expression(self):
        files = sorted(_CGI.glob("*.py"))
        self.assertGreater(len(files), 40)
        hits = []
        for f in files:
            for no, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if self.SHAPE.search(line):
                    hits.append(f"{f.name}:{no}")
        self.assertEqual(hits, [], "a permission asked for only on some verbs leaves the others open")

    def test_the_ratchet_sees_the_old_line(self):
        old = "    actor = require_perm('services', [dev_id]) if method() == 'POST' else None  # v3.12.0 RBAC"
        self.assertTrue(self.SHAPE.search(old))


if __name__ == "__main__":
    unittest.main()
