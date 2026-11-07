#!/usr/bin/env python3
"""8.0.0: the single sign-on guide checks an issuer that is not saved yet.

POST /api/auth/oidc/test tested the SAVED issuer only, and the Test discovery button saved the form first so that it had something to test. The
guide must not store an issuer it has not checked, so the route takes an optional `issuer`. That is a destination from the request that the server
connects to, so it is the platform operator's, like the mail, directory and Proxmox tests (tests/test_v743_security.py lists them): a tenant
admin would otherwise read a JSON document from any host the server can reach. The saved issuer is still tested by any admin, as before.

The report also names the client authentication methods the provider lists: RemotePower sends the client secret in the request body, and a
provider that lists only the Basic method would refuse every sign-in with a message that does not say why.

A fake provider on the loopback serves the discovery document and records what it was asked.
"""
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import api  # noqa: E402  (one shared import of api.py, with RP_DATA_DIR pinned before it)
from test_v800_smtp_guide import _call  # noqa: E402


class _Idp(BaseHTTPRequestHandler):
    hits = []
    doc = {}

    def do_GET(self):
        type(self).hits.append(self.path)
        if self.path.endswith("/.well-known/openid-configuration"):
            body = json.dumps(type(self).doc).encode()
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a, **k):
        pass


def _document(base, **extra):
    doc = {"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "userinfo_endpoint": base + "/userinfo",
           "jwks_uri": base + "/jwks", "scopes_supported": ["openid", "profile", "email", "groups"], "grant_types_supported": ["authorization_code"],
           "response_types_supported": ["code"], "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]}
    doc.update(extra)
    return doc


class _Base(unittest.TestCase):

    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), _Idp)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d/application/o/rp" % self.server.server_address[1]
        _Idp.hits.clear()
        _Idp.doc = _document(self.base)
        api.save(api.CONFIG_FILE, {"oidc_issuer": "http://127.0.0.1:1/never-asked", "oidc_client_id": "saved-id", "oidc_client_secret": "saved-secret"})
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1}})
        api._OIDC_METADATA_CACHE.clear()
        api._LOAD_CACHE.clear()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def press(self, body, **kw):
        return _call(api.handle_oidc_test, body, **kw)


class TestTheTestWithAnIssuerThatIsNotSaved(_Base):

    def test_the_typed_issuer_is_fetched_and_the_saved_one_is_not(self):
        before = json.dumps(api.load(api.CONFIG_FILE), sort_keys=True)
        box = self.press({"issuer": self.base})
        self.assertEqual(box["status"], 200, box)
        self.assertTrue(box["body"]["ok"])
        self.assertEqual(_Idp.hits, ["/application/o/rp/.well-known/openid-configuration"])
        self.assertEqual(box["body"]["endpoints"]["token"], self.base + "/token")
        api._LOAD_CACHE.clear()
        self.assertEqual(json.dumps(api.load(api.CONFIG_FILE), sort_keys=True), before, "nothing was stored")

    def test_a_slash_at_the_end_of_the_issuer_makes_no_difference(self):
        box = self.press({"issuer": self.base + "/"})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(_Idp.hits, ["/application/o/rp/.well-known/openid-configuration"])

    def test_without_an_issuer_the_saved_one_is_tested_as_before(self):
        api.save(api.CONFIG_FILE, {"oidc_issuer": self.base})
        api._LOAD_CACHE.clear()
        box = self.press({})
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(_Idp.hits, ["/application/o/rp/.well-known/openid-configuration"])
        self.assertFalse(any("not saved" in json.dumps(a) for a in box["audit"]), "the trail says nothing about unsaved settings for a saved issuer")

    def test_with_no_issuer_anywhere_it_is_a_400_as_before(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        box = self.press({})
        self.assertEqual(box["status"], 400, box)
        self.assertEqual(box["body"]["error"], "oidc_issuer not set in config")
        self.assertEqual(_Idp.hits, [])

    def test_an_issuer_that_is_not_an_http_address_is_refused_before_any_connection(self):
        for issuer in ("auth.example.com", "ftp://auth.example.com", "javascript:alert(1)", "file:///etc/passwd", "//auth.example.com", "http://"):
            with self.subTest(issuer):
                box = self.press({"issuer": issuer})
                self.assertEqual(box["status"], 400, box)
                self.assertEqual(box["body"]["error"], "issuer must be an http(s) address")
        self.assertEqual(_Idp.hits, [])

    def test_an_issuer_with_whitespace_in_it_is_refused_as_the_save_refuses_it(self):
        for issuer in (self.base + "/a b", self.base + "/a\tb", self.base + "/a\nb"):
            with self.subTest(repr(issuer)):
                box = self.press({"issuer": issuer})
                self.assertEqual(box["status"], 400, box)
                self.assertEqual(box["body"]["error"], "issuer must not contain whitespace")
        self.assertEqual(_Idp.hits, [])

    def test_the_cloud_metadata_address_is_still_refused(self):
        box = self.press({"issuer": "http://169.254.169.254/latest"})
        self.assertEqual(box["status"], 502, box)
        self.assertFalse(box["body"]["ok"])
        self.assertIn("blocked", box["body"]["error"])

    def test_an_issuer_that_does_not_answer_is_a_502_with_the_reason(self):
        box = self.press({"issuer": "http://127.0.0.1:1/x"})
        self.assertEqual(box["status"], 502, box)
        self.assertFalse(box["body"]["ok"])
        self.assertTrue(box["body"]["error"])

    def test_the_trail_names_the_issuer_and_says_it_was_not_saved(self):
        box = self.press({"issuer": self.base})
        line = json.dumps(box["audit"])
        self.assertIn("oidc_test", line)
        self.assertIn(self.base, line)
        self.assertIn("not saved", line)

    def test_the_cache_does_not_answer_for_a_typed_issuer(self):
        self.press({"issuer": self.base})
        _Idp.hits.clear()
        _Idp.doc = _document(self.base, scopes_supported=["openid"])
        box = self.press({"issuer": self.base})
        self.assertEqual(box["body"]["scopes_supported"], ["openid"], "a second press reads the provider again")
        self.assertEqual(len(_Idp.hits), 1)


class TestTheReportNamesHowTheClientAuthenticates(_Base):

    def test_the_methods_the_provider_lists_are_in_the_report(self):
        box = self.press({"issuer": self.base})
        self.assertEqual(box["body"]["token_endpoint_auth_methods_supported"], ["client_secret_basic", "client_secret_post"])
        self.assertFalse([w for w in box["body"]["warnings"] if "client_secret_post" in w])

    def test_a_provider_that_lists_no_post_method_gets_a_warning(self):
        _Idp.doc = _document(self.base, token_endpoint_auth_methods_supported=["client_secret_basic", "private_key_jwt"])
        box = self.press({"issuer": self.base})
        self.assertEqual(box["status"], 200)
        self.assertTrue([w for w in box["body"]["warnings"] if "client_secret_post" in w], box["body"]["warnings"])

    def test_a_provider_that_lists_nothing_gets_no_warning(self):
        doc = _document(self.base)
        del doc["token_endpoint_auth_methods_supported"]
        _Idp.doc = doc
        box = self.press({"issuer": self.base})
        self.assertIsNone(box["body"]["token_endpoint_auth_methods_supported"])
        self.assertFalse([w for w in box["body"]["warnings"] if "client_secret_post" in w], "the specification's default is Basic, but a missing list says nothing")


class TestWhoMayTestAnIssuerThatIsNotSaved(_Base):
    """The object lets the server fetch a document from an address in the request: the platform operator's, like the other tests that do."""

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True, "oidc_issuer": self.base})
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": 1}})
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1},
                                  "tadmin": {"role": "admin", "tenant_id": "tenantA", "password_hash": "x", "created": 1},
                                  "viewer": {"role": "viewer", "password_hash": "x", "created": 1}})
        api._LOAD_CACHE.clear()

    def test_a_tenant_administrator_is_refused_and_nothing_is_fetched(self):
        box = self.press({"issuer": self.base}, user="tadmin")
        self.assertEqual(box["status"], 403, box)
        self.assertIn("platform operator", json.dumps(box["body"]))
        self.assertEqual(_Idp.hits, [])

    def test_a_viewer_is_refused_by_the_admin_gate(self):
        self.assertEqual(self.press({"issuer": self.base}, user="viewer")["status"], 403)
        self.assertEqual(_Idp.hits, [])

    def test_the_platform_operator_can(self):
        box = self.press({"issuer": self.base}, user="alice")
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(len(_Idp.hits), 1)

    def test_the_saved_issuer_is_still_tested_by_a_tenant_administrator_as_before(self):
        box = self.press({}, user="tadmin")
        self.assertEqual(box["status"], 200, box)
        self.assertEqual(len(_Idp.hits), 1)

    def test_with_tenancy_off_a_plain_admin_can_test_a_typed_issuer(self):
        api.save(api.CONFIG_FILE, {"oidc_issuer": self.base})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.press({"issuer": self.base}, user="tadmin")["status"], 200)


if __name__ == "__main__":
    unittest.main()
