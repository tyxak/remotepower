#!/usr/bin/env python3
"""Unit tests for v1.11.2.

Covers:
  - Shared link dashboard: list/add/update/delete + URL/scope validation
  - tls_monitor.parse_target with new connect_address + dane_check fields
  - tls_monitor._hostname_matches_cert (wildcard, SAN, CN fallback)
  - tls_monitor._tlsa_matches_cert (selector + matching_type combinations)
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

_spec = importlib.util.spec_from_file_location("api_v1112", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import tls_monitor


# ─── Helpers ──────────────────────────────────────────────────────────────────


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
    for k in ("HTTP_X_TOKEN",):
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


def _seed_admin():
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


def _auth(token):
    return {"HTTP_X_TOKEN": token}


def _isolate(t):
    d = tempfile.mkdtemp()
    os.environ["RP_DATA_DIR"] = d
    for name in (
        "USERS_FILE",
        "TOKENS_FILE",
        "DEVICES_FILE",
        "AUDIT_LOG_FILE",
        "CONFIG_FILE",
        "LINKS_FILE",
        "TLS_TARGETS_FILE",
        "TLS_RESULTS_FILE",
    ):
        if hasattr(api, name):
            setattr(api, name, Path(d) / Path(getattr(api, name)).name)


# ─── Link dashboard ───────────────────────────────────────────────────────────


class TestLinks(unittest.TestCase):
    def setUp(self):
        _isolate(self)
        self.user, self.token = _seed_admin()

    def test_list_empty(self):
        _set_request("GET", "/api/links", headers=_auth(self.token))
        s, b = _call(api.handle_links_list)
        self.assertEqual(s, 200)
        self.assertEqual(b["links"], [])
        self.assertEqual(b["categories"], [])

    def test_add_minimal(self):
        _set_request(
            "POST",
            "/api/links",
            body={"title": "Proxmox", "url": "https://prox.lan/", "scope": "internal"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_link_add)
        self.assertEqual(s, 200)
        self.assertTrue(b["id"].startswith("lnk_"))

    def test_add_rejects_no_title(self):
        _set_request(
            "POST",
            "/api/links",
            body={"url": "https://example.com", "scope": "external"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_link_add)
        self.assertEqual(s, 400)

    def test_add_rejects_bad_url(self):
        for bad in (
            "javascript:alert(1)",     # non-http scheme
            "ftp://example.com",       # non-http scheme
            "http://has spaces.com",   # whitespace
            "http://has\"quote.com",   # quote char
            "",                        # empty
            "x" * 2000,                # too long
        ):
            _set_request(
                "POST",
                "/api/links",
                body={"title": "x", "url": bad, "scope": "external"},
                headers=_auth(self.token),
            )
            s, b = _call(api.handle_link_add)
            self.assertEqual(s, 400, f"expected 400 for url={bad!r}")

    def test_add_rejects_bad_scope(self):
        _set_request(
            "POST",
            "/api/links",
            body={"title": "x", "url": "https://example.com", "scope": "intranet"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_link_add)
        self.assertEqual(s, 400)

    def test_default_category(self):
        _set_request(
            "POST",
            "/api/links",
            body={"title": "x", "url": "https://example.com", "scope": "external"},
            headers=_auth(self.token),
        )
        _, _b = _call(api.handle_link_add)
        _set_request("GET", "/api/links", headers=_auth(self.token))
        s, b = _call(api.handle_links_list)
        self.assertEqual(b["links"][0]["category"], "Uncategorised")

    def test_update(self):
        _set_request(
            "POST",
            "/api/links",
            body={"title": "Old", "url": "https://example.com", "scope": "external"},
            headers=_auth(self.token),
        )
        _, addb = _call(api.handle_link_add)
        link_id = addb["id"]
        _set_request(
            "PUT",
            f"/api/links/{link_id}",
            body={"title": "New", "url": "https://new.com", "scope": "internal", "category": "Tools"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_link_update, link_id)
        self.assertEqual(s, 200)
        store = api.load(api.LINKS_FILE)
        self.assertEqual(store[link_id]["title"], "New")
        self.assertEqual(store[link_id]["scope"], "internal")
        self.assertEqual(store[link_id]["category"], "Tools")

    def test_update_404(self):
        _set_request(
            "PUT",
            "/api/links/lnk_ghost",
            body={"title": "x", "url": "https://example.com", "scope": "external"},
            headers=_auth(self.token),
        )
        s, b = _call(api.handle_link_update, "lnk_ghost")
        self.assertEqual(s, 404)

    def test_delete(self):
        _set_request(
            "POST",
            "/api/links",
            body={"title": "x", "url": "https://example.com", "scope": "external"},
            headers=_auth(self.token),
        )
        _, addb = _call(api.handle_link_add)
        link_id = addb["id"]
        _set_request("DELETE", f"/api/links/{link_id}", headers=_auth(self.token))
        s, b = _call(api.handle_link_delete, link_id)
        self.assertEqual(s, 200)
        self.assertEqual(api.load(api.LINKS_FILE), {})

    def test_categories_distinct(self):
        for title, cat in (("a", "Tools"), ("b", "Tools"), ("c", "Docs")):
            _set_request(
                "POST",
                "/api/links",
                body={"title": title, "url": "https://example.com", "scope": "external", "category": cat},
                headers=_auth(self.token),
            )
            _call(api.handle_link_add)
        _set_request("GET", "/api/links", headers=_auth(self.token))
        s, b = _call(api.handle_links_list)
        self.assertEqual(sorted(b["categories"]), ["Docs", "Tools"])


# ─── tls_monitor parse_target with new fields ────────────────────────────────


class TestTLSParseTarget(unittest.TestCase):
    def test_connect_address_default_empty(self):
        t = tls_monitor.parse_target({"host": "example.com"})
        self.assertEqual(t["connect_address"], "")

    def test_connect_address_set(self):
        t = tls_monitor.parse_target({"host": "router.lan", "connect_address": "192.168.1.1"})
        self.assertEqual(t["connect_address"], "192.168.1.1")

    def test_connect_address_validation(self):
        for bad in ("has spaces", 'with"quote', "x" * 300):
            t = tls_monitor.parse_target({"host": "ok.com", "connect_address": bad})
            self.assertIsNone(t, f"expected None for connect_address={bad!r}")

    def test_dane_check_default_false(self):
        t = tls_monitor.parse_target({"host": "example.com"})
        self.assertFalse(t["dane_check"])

    def test_dane_check_set(self):
        t = tls_monitor.parse_target({"host": "example.com", "dane_check": True})
        self.assertTrue(t["dane_check"])

    def test_backwards_compatible(self):
        # Legacy targets (v1.11.0 / v1.11.1) without these fields should
        # parse fine and get the new fields with defaults.
        t = tls_monitor.parse_target({"host": "example.com", "port": 443, "warn_days": 14, "crit_days": 3})
        self.assertEqual(t["connect_address"], "")
        self.assertFalse(t["dane_check"])


# ─── tls_monitor._hostname_matches_cert ──────────────────────────────────────


class TestHostnameMatch(unittest.TestCase):
    def test_exact_san_match(self):
        parsed = {"san": ["example.com", "www.example.com"], "subject": ""}
        self.assertTrue(tls_monitor._hostname_matches_cert("example.com", parsed))
        self.assertTrue(tls_monitor._hostname_matches_cert("www.example.com", parsed))
        self.assertFalse(tls_monitor._hostname_matches_cert("other.example.com", parsed))

    def test_wildcard_san(self):
        parsed = {"san": ["*.example.com"], "subject": ""}
        self.assertTrue(tls_monitor._hostname_matches_cert("foo.example.com", parsed))
        self.assertTrue(tls_monitor._hostname_matches_cert("bar.example.com", parsed))
        # Wildcard does NOT match the apex domain itself
        self.assertFalse(tls_monitor._hostname_matches_cert("example.com", parsed))
        # Wildcard does NOT match multiple labels
        self.assertFalse(tls_monitor._hostname_matches_cert("a.b.example.com", parsed))

    def test_cn_fallback(self):
        # No SANs — fall back to CN
        parsed = {"san": [], "subject": "CN=legacy.example.com,O=Test Inc"}
        self.assertTrue(tls_monitor._hostname_matches_cert("legacy.example.com", parsed))
        self.assertFalse(tls_monitor._hostname_matches_cert("other.example.com", parsed))

    def test_case_insensitive(self):
        parsed = {"san": ["EXAMPLE.COM"], "subject": ""}
        self.assertTrue(tls_monitor._hostname_matches_cert("example.com", parsed))
        self.assertTrue(tls_monitor._hostname_matches_cert("EXAMPLE.COM", parsed))

    def test_empty_inputs(self):
        self.assertFalse(tls_monitor._hostname_matches_cert("example.com", {}))
        self.assertFalse(tls_monitor._hostname_matches_cert("example.com", {"san": [], "subject": ""}))


# ─── tls_monitor._tlsa_matches_cert ──────────────────────────────────────────


class TestTLSAMatch(unittest.TestCase):
    """Tests the cert-comparison part of DANE without needing a DNS lookup.

    We generate a cert in memory, compute its SHA-256, and verify that a
    TLSA record carrying that hash matches but a different hash doesn't.
    """

    @classmethod
    def setUpClass(cls):
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
        except ImportError:
            cls.der = None
            return
        # Build a self-signed cert
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(1)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=30))
                .sign(key, hashes.SHA256()))
        cls.der = cert.public_bytes(serialization.Encoding.DER)
        h = hashes.Hash(hashes.SHA256())
        h.update(cls.der)
        cls.cert_sha256 = h.finalize().hex()

    def test_selector0_matching1_match(self):
        if self.der is None:
            self.skipTest("cryptography not available")
        rec = {"usage": 3, "selector": 0, "matching_type": 1, "data": self.cert_sha256}
        self.assertTrue(tls_monitor._tlsa_matches_cert(rec, self.der))

    def test_selector0_matching1_mismatch(self):
        if self.der is None:
            self.skipTest("cryptography not available")
        rec = {"usage": 3, "selector": 0, "matching_type": 1, "data": "00" * 32}
        self.assertFalse(tls_monitor._tlsa_matches_cert(rec, self.der))

    def test_selector0_matching0_full_cert_match(self):
        if self.der is None:
            self.skipTest("cryptography not available")
        rec = {"usage": 3, "selector": 0, "matching_type": 0, "data": self.der.hex()}
        self.assertTrue(tls_monitor._tlsa_matches_cert(rec, self.der))

    def test_unknown_selector_returns_false(self):
        if self.der is None:
            self.skipTest("cryptography not available")
        rec = {"usage": 3, "selector": 7, "matching_type": 1, "data": self.cert_sha256}
        self.assertFalse(tls_monitor._tlsa_matches_cert(rec, self.der))

    def test_unknown_matching_type_returns_false(self):
        if self.der is None:
            self.skipTest("cryptography not available")
        rec = {"usage": 3, "selector": 0, "matching_type": 7, "data": self.cert_sha256}
        self.assertFalse(tls_monitor._tlsa_matches_cert(rec, self.der))

    def test_empty_inputs(self):
        self.assertFalse(tls_monitor._tlsa_matches_cert({}, b"some der"))
        self.assertFalse(tls_monitor._tlsa_matches_cert(
            {"usage": 3, "selector": 0, "matching_type": 1, "data": "ab" * 32}, b""))


# ─── DANE check structure (no real DNS) ──────────────────────────────────────


class TestDANECheckStructure(unittest.TestCase):
    """We can't reliably hit real DNS in tests. But we can verify the
    function returns the right shape on degenerate inputs."""

    def test_returns_dict_with_expected_keys(self):
        # Won't reach DNS — host doesn't exist — but shape must still be right
        result = tls_monitor._check_dane("nonexistent.invalid.example.invalid", 443, b"")
        self.assertIsInstance(result, dict)
        for key in ("status", "records", "error"):
            self.assertIn(key, result)
        self.assertIn(result["status"], ("missing", "error", "insecure"))


if __name__ == "__main__":
    unittest.main()
