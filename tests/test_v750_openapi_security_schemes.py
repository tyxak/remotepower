#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, findings W2-F8 and W2-F9): the API reference names only what it defines, and says what the handlers answer.

* `POST /heartbeat` named a security scheme, `DeviceToken`, that `components.securitySchemes` did not define. A client generator
  rejects a document like that, and the reference invites client generation. Every scheme any operation names has to be defined.
* The ingest endpoints (syslog, SNMP trap, webhook, ITSM callback) documented a 403 for an unknown token. None of them answers 403:
  they answer 401 for an unknown, disabled or revoked token and 400 for a token of another kind. A spec that promises an answer the
  server never gives sends integrators to handle the wrong one.

What this holds: a ratchet over the whole spec for the first (with a control that the walk sees operations and schemes at all), the
`DeviceToken` scheme itself (an `X-Token` header, as the operation says), and the second against the real handlers: each ingest
handler is driven with an unknown token and its status is compared with the one the spec lists.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-spec-"))
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

_spec = importlib.util.spec_from_file_location("api_v750_spec", _ROOT / "server" / "cgi-bin" / "api.py")
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("api", api)
_spec.loader.exec_module(api)
import openapi_spec as osp  # noqa: E402


def _document():
    routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
    return osp.build_spec(api.SERVER_VERSION, routes)


class TestEverySchemeAnOperationNamesIsDefined(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.doc = _document()
        cls.defined = set((cls.doc.get("components") or {}).get("securitySchemes") or {})
        cls.used = {}
        for path, item in cls.doc["paths"].items():
            for verb, op in item.items():
                if isinstance(op, dict):
                    for req in op.get("security") or []:
                        for name in req:
                            cls.used.setdefault(name, []).append(f"{verb.upper()} {path}")
        for name in (cls.doc.get("security") or []):
            for key in name:
                cls.used.setdefault(key, []).append("(document)")

    def test_the_walk_sees_something(self):
        """Control: a spec that built empty would pass the check below having inspected nothing."""
        self.assertGreater(len(self.doc["paths"]), 500)
        self.assertTrue({"SessionToken", "ApiKey"} <= self.defined)
        self.assertTrue({"DeviceToken", "SessionToken", "ApiKey"} <= set(self.used) | {"SessionToken", "ApiKey"})

    def test_every_scheme_that_is_named_is_defined(self):
        missing = {n: where[:3] for n, where in self.used.items() if n not in self.defined}
        self.assertEqual(missing, {}, "operations name security schemes that components.securitySchemes does not define")

    def test_the_device_token_is_the_x_token_header_the_heartbeat_says(self):
        scheme = self.doc["components"]["securitySchemes"]["DeviceToken"]
        self.assertEqual((scheme["type"], scheme["in"], scheme["name"]), ("apiKey", "header", "X-Token"))
        self.assertEqual(self.doc["paths"]["/heartbeat"]["post"]["security"], [{"DeviceToken": []}])


class TestTheIngestStatusCodesAreTheHandlers(unittest.TestCase):
    """The spec lists the answer for an unknown token; the handler is asked with one and must give the same status."""

    PATHS = {
        "/syslog/in/{token}": ("handle_syslog_in", "POST"),
        "/snmp/trap/{token}": ("handle_snmp_trap_in", "POST"),
        "/webhook/in/{token}": ("handle_inbound_webhook", "POST"),
        "/itsm/in/{token}": ("handle_itsm_callback", "POST"),
    }

    def test_an_unknown_token_gets_the_status_the_spec_lists(self):
        doc = _document()
        listed = {}
        for path, (handler, method) in self.PATHS.items():
            responses = doc["paths"][path]["post"]["responses"]
            self.assertIn("401", responses, path)
            self.assertNotIn("403", responses, path)
            listed[path] = 401
        for path, (handler, method) in self.PATHS.items():
            with self.subTest(path=path), mock.patch.object(api, "method", lambda m=method: m), \
                    mock.patch.object(api, "get_json_body", lambda: {}), mock.patch.object(api, "get_json_obj", lambda: {}), \
                    mock.patch.object(api, "audit_log", lambda *a, **k: None):
                try:
                    getattr(api, handler)("this-token-does-not-exist")
                except api.HTTPError as e:
                    self.assertEqual(e.status, listed[path], (path, e.body))
                    continue
                self.fail(f"{handler} answered nothing")

    def test_the_400_is_described_for_what_it_covers(self):
        doc = _document()
        text = doc["paths"]["/syslog/in/{token}"]["post"]["responses"]["400"]["description"].lower()
        self.assertIn("another kind", text)
        self.assertIn("pinned", text)


if __name__ == "__main__":
    unittest.main()
