#!/usr/bin/env python3
"""v7.4.3, issue #51: the HTTP monitor's expected status, and an alert that outlives an edit.

(1) "Apps that require a login (Sonarr, Radarr, Lidarr, Readarr, Prowlarr) answer 401 at their
root, so I set expect_status 401. The monitor stays down." urllib raises HTTPError for a 3xx it
does not follow, a 4xx and a 5xx, and that branch decided with `code < 400` first. The expected
status could only turn a pass into a failure there, never the other way, so an expected 4xx or
5xx could not pass.

(2) "I changed five failing monitors' targets (added /ping); they went green, but their open
alerts never closed." monitor_up looked for the open monitor_down by label AND target. The
target in the alert is the one the monitor had when it went down, so an edited target never
matched. Every other piece of per-monitor state (history, the down flag, the failure streak) is
keyed by label, so the label is the monitor's identity and the recovery matches on it alone.

Issue #52 adds two options to the same monitor. "Monitors always verify certificates, so every
LAN service on a self-signed certificate reads as down with URLError", and "a monitor sends HEAD
unless a body or JSON check is set. Home Assistant, Dagu and Navidrome answer HEAD with 405, and
VoidAuth with 404, so they read as down while GET works." A monitor can now turn the certificate
check off, and choose the method: Auto (HEAD, then one GET when HEAD is answered with 404, 405
or 501), HEAD or GET. Both travel through the save, the export and the import.

The first half drives the real probe against a local server. The second half goes through the
real persister, the real webhook recorder and the real alert ledger, and edits the monitor with
the real config save: a hand-built alert row would skip the one thing under test, which fields
the recovery matches.
"""
import datetime
import http.server
import importlib.util
import json
import os
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v743-mon-"))
_spec = importlib.util.spec_from_file_location("api_v743_mon", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Origin(http.server.BaseHTTPRequestHandler):
    """A small origin: path -> (status, headers, body, delay seconds)."""
    ROUTES = {
        "/ok": (200, {"Content-Type": "application/json"}, b'{"status": "ok"}', 0),
        "/moved": (301, {"Location": "/ok"}, b"", 0),
        "/login": (401, {"Content-Type": "application/json"}, b'{"error": "Unauthorized"}', 0),
        "/slow-login": (401, {"Content-Type": "application/json"}, b'{"error": "Unauthorized"}', 0.3),
        "/forbidden": (403, {}, b"no", 0),
        "/missing": (404, {}, b"gone", 0),
        "/broken": (500, {}, b"oops", 0),
        "/cf": (403, {"cf-mitigated": "challenge"}, b"", 0),
        "/cf-server": (403, {}, b"", 0),
    }

    def version_string(self):
        # BaseHTTPRequestHandler stamps its own Server header, so a route cannot add a second one.
        return "cloudflare" if self.path == "/cf-server" else super().version_string()

    def _answer(self, with_body):
        status, headers, body, delay = self.ROUTES.get(self.path, (404, {}, b"", 0))
        if delay:
            time.sleep(delay)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self):
        self._answer(True)

    def do_HEAD(self):
        self._answer(False)

    def log_message(self, *a):
        pass


def _serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class _Base(unittest.TestCase):
    def setUp(self):
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONFIG_FILE, {}),
                         (api.MON_HIST_FILE, {}), (api.MAINT_FILE, {"windows": []}),
                         (api.MAINT_SUPPRESS_LOG, {"entries": []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def set_config(self, **kw):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg.update(kw)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()


class TestAnExpectedStatusDecidesAlone(_Base):

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = _serve()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def probe(self, path, **monitor):
        self.set_config(allow_internal_monitors=True)
        return api._run_one_monitor_check("http", self.base + path, "t", dict(monitor))

    def test_without_an_expected_status_nothing_changes(self):
        """The control: the rule an install without the field has always had."""
        for path, ok in (("/ok", True), ("/moved", True), ("/login", False),
                         ("/forbidden", False), ("/missing", False), ("/broken", False)):
            with self.subTest(path=path):
                r = self.probe(path)
                self.assertIs(r["ok"], ok, r)

    def test_an_expected_4xx_or_5xx_passes_when_that_is_what_comes_back(self):
        for path, code in (("/login", 401), ("/forbidden", 403), ("/missing", 404),
                           ("/broken", 500), ("/moved", 301), ("/ok", 200)):
            with self.subTest(path=path, expect=code):
                r = self.probe(path, expect_status=code)
                self.assertTrue(r["ok"], r)
                self.assertTrue(r["detail"].startswith(f"{code} · "), r["detail"])

    def test_any_other_status_fails_and_says_what_was_expected(self):
        for path, got, want in (("/ok", 200, 401), ("/login", 401, 200), ("/login", 401, 403),
                                ("/broken", 500, 503), ("/missing", 404, 200)):
            with self.subTest(path=path, expect=want):
                r = self.probe(path, expect_status=want)
                self.assertFalse(r["ok"], r)
                self.assertEqual(r["detail"], f"{got} (expected {want})")

    def test_the_body_checks_apply_to_the_answer_that_was_expected(self):
        """A check that is configured and never evaluated would read green for nothing."""
        r = self.probe("/login", expect_status=401, body_match={"mode": "contains", "value": "Unauthorized"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, body_match={"mode": "contains", "value": "Welcome"})
        self.assertFalse(r["ok"], r)
        self.assertIn("not found", r["detail"])
        r = self.probe("/login", expect_status=401, body_match={"mode": "not_contains", "value": "Unauthorized"})
        self.assertFalse(r["ok"], r)
        r = self.probe("/login", expect_status=401, body_match={"mode": "regex", "value": "Unauth[a-z]+"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "error", "value": "Unauthorized"})
        self.assertTrue(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "error", "value": "Other"})
        self.assertFalse(r["ok"], r)
        r = self.probe("/login", expect_status=401, expect_json={"path": "missing"})
        self.assertFalse(r["ok"], r)

    def test_the_latency_limit_applies_to_the_answer_that_was_expected(self):
        r = self.probe("/slow-login", expect_status=401, max_latency_ms=60)
        self.assertFalse(r["ok"], r)
        self.assertIn("SLA", r["detail"])
        r = self.probe("/slow-login", expect_status=401, max_latency_ms=20000)
        self.assertTrue(r["ok"], r)

    def test_a_wrong_status_is_reported_before_a_body_that_does_not_match(self):
        """The status is the first question; a body that cannot be right is a second one."""
        r = self.probe("/ok", expect_status=401, body_match={"mode": "contains", "value": "Welcome"})
        self.assertEqual(r["detail"], "200 (expected 401)")

    def test_who_refused_is_still_named(self):
        """7.0.3: a bare 403 read as a host that was down. That naming survives."""
        for path, words in (("/cf", "refused by the edge"), ("/cf-server", "refused by Cloudflare")):
            for monitor in ({}, {"expect_status": 200}):
                with self.subTest(path=path, monitor=monitor):
                    r = self.probe(path, **monitor)
                    self.assertFalse(r["ok"], r)
                    self.assertIn(words, r["detail"])

    def test_a_flow_step_already_behaves_this_way(self):
        """The multi-step monitor never had the bug; this keeps the two in agreement."""
        self.set_config(allow_internal_monitors=True)
        ok, detail = api._run_http_flow({"steps": [{"method": "GET", "url": self.base + "/login",
                                                    "expect_status": 401}]})
        self.assertTrue(ok, detail)

    def test_the_save_accepts_a_4xx_and_a_5xx(self):
        for code in (401, 403, 404, 500, 503):
            with self.subTest(code=code):
                mons = _save_monitors(self, [{"type": "http", "label": "app", "target": "https://app.example/",
                                              "expect_status": code}])
                self.assertEqual(mons[0]["expect_status"], code)


def _save_monitors(case, monitors, extra=None):
    """The real config save, with only the sign-in stubbed (verify_token), as for any gate test."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
             "audit_log", "respond", "require_admin_auth")
    saved = {n: getattr(api, n) for n in names}
    body = {"monitors": monitors}
    body.update(extra or {})
    box = {}
    api.require_admin_auth = lambda: "alice"
    api.verify_token = lambda t: ("alice", "admin")
    api.get_token_from_request = lambda: "t"
    api.method = lambda: "POST"
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    case.assertEqual(box.get("status"), 200, box)
    api._LOAD_CACHE.clear()
    return (api.load(api.CONFIG_FILE) or {}).get("monitors") or []


class _MethodOrigin(http.server.BaseHTTPRequestHandler):
    """HEAD and GET answer differently, and every request is logged: path -> (HEAD answer, GET answer)."""
    LOG = []
    ROUTES = {
        "/ok": (200, 200),
        "/head-405": (405, 200),      # Home Assistant, Dagu, Navidrome
        "/head-404": (404, 200),      # VoidAuth
        "/head-501": (501, 200),
        "/head-500": (500, 200),      # a real failure, not an unsupported method
        "/both-404": (404, 404),
        "/get-500": (200, 500),
        "/slow-get": (405, 200),      # HEAD is refused at once, GET takes a third of a second
        "/slow-head": (405, 200),     # the other way round
    }

    def _answer(self, method):
        type(self).LOG.append(method)
        head, get = self.ROUTES.get(self.path, (404, 404))
        if (method, self.path) in (("GET", "/slow-get"), ("HEAD", "/slow-head")):
            time.sleep(0.3)
        status = head if method == "HEAD" else get
        body = b"" if method == "HEAD" else b"hello from " + self.path.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._answer("GET")

    def do_HEAD(self):
        self._answer("HEAD")

    def log_message(self, *a):
        pass


class TestTheRequestMethod(_Base):

    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MethodOrigin)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def probe(self, path, **monitor):
        self.set_config(allow_internal_monitors=True)
        _MethodOrigin.LOG.clear()
        r = api._run_one_monitor_check("http", self.base + path, "t", dict(monitor))
        return r, list(_MethodOrigin.LOG)

    def test_auto_is_head_when_head_works(self):
        """The control: a monitor that never had a method keeps sending one cheap HEAD."""
        for monitor in ({}, {"method": "auto"}, {"method": ""}):
            with self.subTest(monitor=monitor):
                r, sent = self.probe("/ok", **monitor)
                self.assertTrue(r["ok"], r)
                self.assertEqual(sent, ["HEAD"])

    def test_auto_tries_get_once_when_head_is_not_supported(self):
        for path, head in (("/head-405", 405), ("/head-404", 404), ("/head-501", 501)):
            with self.subTest(path=path):
                r, sent = self.probe(path)
                self.assertTrue(r["ok"], r)
                self.assertEqual(sent, ["HEAD", "GET"])
                self.assertIn(f"HEAD answered {head}", r["detail"])

    def test_auto_does_not_turn_a_real_failure_into_a_second_request(self):
        r, sent = self.probe("/head-500")
        self.assertFalse(r["ok"], r)
        self.assertEqual(sent, ["HEAD"])
        self.assertEqual(r["detail"], "500")

    def test_auto_reports_the_get_answer_when_both_fail(self):
        r, sent = self.probe("/both-404")
        self.assertFalse(r["ok"], r)
        self.assertEqual(sent, ["HEAD", "GET"])
        self.assertEqual(r["detail"], "404")
        r, sent = self.probe("/head-405", expect_status=500)
        self.assertFalse(r["ok"], r)
        self.assertEqual(r["detail"], "200 (expected 500)", "the GET answer is the one that is judged")

    def test_an_expected_status_that_head_returned_needs_no_second_request(self):
        r, sent = self.probe("/head-405", expect_status=405)
        self.assertTrue(r["ok"], r)
        self.assertEqual(sent, ["HEAD"])
        r, sent = self.probe("/head-405", expect_status=200)
        self.assertTrue(r["ok"], r)
        self.assertEqual(sent, ["HEAD", "GET"])

    def test_head_is_head_and_does_not_fall_back(self):
        r, sent = self.probe("/head-405", method="head")
        self.assertFalse(r["ok"], r)
        self.assertEqual(sent, ["HEAD"])
        self.assertEqual(r["detail"], "405")

    def test_get_is_always_get(self):
        for path in ("/ok", "/head-405"):
            with self.subTest(path=path):
                r, sent = self.probe(path, method="get")
                self.assertTrue(r["ok"], r)
                self.assertEqual(sent, ["GET"])
        r, sent = self.probe("/get-500", method="get")
        self.assertFalse(r["ok"], r)
        self.assertEqual(sent, ["GET"])

    def test_a_body_check_still_means_get(self):
        for method in ("", "auto", "head", "get"):
            with self.subTest(method=method):
                r, sent = self.probe("/ok", method=method,
                                     body_match={"mode": "contains", "value": "hello"})
                self.assertTrue(r["ok"], r)
                self.assertEqual(sent, ["GET"])

    def test_any_other_value_is_auto(self):
        for value in ("post", "DELETE", 5, None, ["get"], "GET "):
            with self.subTest(value=value):
                r, sent = self.probe("/head-405", method=value)
                self.assertTrue(r["ok"], r)
                self.assertEqual(sent, ["HEAD", "GET"])

    def test_the_latency_limit_is_judged_on_the_request_that_decided(self):
        r, sent = self.probe("/slow-get", max_latency_ms=20000)
        self.assertTrue(r["ok"], r)
        self.assertGreaterEqual(r["ms"], 250, "the recorded time is the GET that decided")
        r, sent = self.probe("/slow-get", max_latency_ms=100)
        self.assertFalse(r["ok"], r)
        self.assertIn("SLA", r["detail"])

    def test_the_recorded_time_is_the_request_that_decided(self):
        """A slow HEAD that is then refused must not inflate the response time of the GET that passed."""
        r, sent = self.probe("/slow-head")
        self.assertTrue(r["ok"], r)
        self.assertEqual(sent, ["HEAD", "GET"])
        self.assertLess(r["ms"], 250, r)

    def test_the_save_keeps_head_and_get_and_ignores_the_rest(self):
        for given, stored in (("head", "head"), ("GET", "get"), (" Head ", "head"), ("auto", None),
                              ("", None), ("post", None), (5, None), (None, None)):
            with self.subTest(method=given):
                mons = _save_monitors(self, [{"type": "http", "label": "app", "target": "https://app.example/",
                                              "method": given}])
                self.assertEqual(mons[0].get("method"), stored)

    def test_the_save_refuses_head_with_a_body_or_json_check(self):
        """HEAD has no body, so the check could never run: say so now rather than read green for nothing."""
        for extra in ({"body_match": {"mode": "contains", "value": "x"}}, {"expect_json": {"path": "a"}}):
            with self.subTest(extra=extra):
                box = _save_monitors_expecting(self, [dict({"type": "http", "label": "app",
                                                            "target": "https://app.example/", "method": "head"},
                                                           **extra)])
                self.assertEqual(box["status"], 400, box)
                self.assertIn("HEAD", box["body"]["error"])

    def test_other_monitor_types_do_not_store_the_option(self):
        mons = _save_monitors(self, [{"type": "tcp", "label": "db", "target": "10.0.0.5:5432",
                                      "method": "get", "verify_tls": False}])
        self.assertNotIn("method", mons[0])
        self.assertNotIn("verify_tls", mons[0])


def _self_signed_pair(directory):
    """A certificate for 127.0.0.1 that nothing trusts; (cert path, key path)."""
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(directory) / "c.pem", Path(directory) / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


class _QuietTlsServer(http.server.ThreadingHTTPServer):
    """A client that refuses the certificate hangs up mid-handshake; that is the point of the test."""

    def handle_error(self, request, client_address):
        pass


class TestTheCertificateCheck(_Base):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rp-v743-tls-")
        cert, key = _self_signed_pair(cls.tmp)
        cls.srv = _QuietTlsServer(("127.0.0.1", 0), _Origin)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"https://127.0.0.1:{cls.srv.server_port}/ok"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def probe(self, internal=True, **monitor):
        self.set_config(allow_internal_monitors=internal)
        return api._run_one_monitor_check("http", self.url, "t", dict(monitor))

    def test_a_self_signed_certificate_fails_by_default(self):
        """The control: the check stays on unless the monitor turns it off."""
        for monitor in ({}, {"verify_tls": True}):
            with self.subTest(monitor=monitor):
                r = self.probe(**monitor)
                self.assertFalse(r["ok"], r)
                self.assertEqual(r["detail"], "error: URLError")

    def test_the_check_can_be_turned_off_for_one_monitor(self):
        r = self.probe(verify_tls=False)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["detail"].startswith("200 · "), r["detail"])

    def test_only_a_real_false_turns_it_off(self):
        """A string or a number that reads as "off" to a person must not switch a security check off."""
        for value in ("false", "off", 0, "", None, [], {}):
            with self.subTest(value=value):
                r = self.probe(verify_tls=value)
                self.assertFalse(r["ok"], r)

    def test_turning_it_off_does_not_open_the_private_ranges(self):
        """The address guard is separate from the certificate check and stays on."""
        r = self.probe(internal=False, verify_tls=False)
        self.assertFalse(r["ok"], r)

    def test_the_unverified_context_keeps_the_protocol_floor(self):
        ctx = api._get_unverified_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        strict = api._get_ssl_context()
        self.assertEqual(strict.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(strict.check_hostname)

    def test_the_unverified_context_lifts_a_lower_floor(self):
        """On a host whose OpenSSL configuration allows TLS 1.0 the floor has to come from us."""
        from unittest import mock
        low = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        low.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        with mock.patch("ssl.create_default_context", return_value=low):
            ctx = api._get_unverified_ssl_context()
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_the_integration_client_uses_the_same_helper(self):
        """One definition of "certificate check off", not a copy in each place that offers the switch."""
        src = (_CGI / "api.py").read_text(encoding="utf-8")
        self.assertEqual(src.count("ctx.verify_mode = ssl.CERT_NONE"), 1)

    def test_the_save_stores_only_an_off_switch(self):
        for given, stored in ((False, False), (True, None), ("false", None), (0, None), (None, None)):
            with self.subTest(verify_tls=given):
                mons = _save_monitors(self, [{"type": "http", "label": "app", "target": "https://app.example/",
                                              "verify_tls": given}])
                self.assertEqual(mons[0].get("verify_tls"), stored)
                self.assertEqual("verify_tls" in mons[0], stored is not None)


class TestBothTravelThroughTheMonitorFiles(_Base):

    def monitors(self):
        return [{"type": "http", "label": "ha", "target": "https://ha.lan:8123/",
                 "verify_tls": False, "method": "get"},
                {"type": "http", "label": "plain", "target": "https://example.org/"}]

    def test_export_then_import_round_trip(self):
        import importers
        _save_monitors(self, self.monitors())
        saved = {m["label"]: m for m in (api.load(api.CONFIG_FILE) or {}).get("monitors")}
        self.assertIs(saved["ha"]["verify_tls"], False)
        out = {}
        real = (api.respond, api.verify_token, api.get_token_from_request)

        def capture(status, data=None):
            out["status"], out["body"] = status, data
            raise api.HTTPError(status, data)
        api.respond = capture
        api.verify_token = lambda t: ("alice", "admin")
        api.get_token_from_request = lambda: "t"
        try:
            try:
                api.handle_export_monitors()
            except api.HTTPError:
                pass
        finally:
            api.respond, api.verify_token, api.get_token_from_request = real
        self.assertEqual(out["status"], 200, out)
        exported = {m["label"]: m for m in out["body"]["monitors"]}
        self.assertIs(exported["ha"]["verify_tls"], False)
        self.assertEqual(exported["ha"]["method"], "get")
        self.assertNotIn("verify_tls", exported["plain"])
        self.assertNotIn("method", exported["plain"])
        again = importers.parse(json.dumps({"format": "remotepower", "monitors": list(exported.values())}), None)
        got = {m["label"]: m for m in again["monitors"]}
        self.assertIs(got["ha"]["verify_tls"], False)
        self.assertEqual(got["ha"]["method"], "get")
        self.assertNotIn("verify_tls", got["plain"])

    def test_import_drops_values_it_would_not_have_saved(self):
        import importers
        doc = {"format": "remotepower", "monitors": [
            {"type": "http", "label": "a", "target": "https://a/", "verify_tls": "false", "method": "DELETE"},
            {"type": "http", "label": "b", "target": "https://b/", "verify_tls": True, "method": "Head"},
            {"type": "http", "label": "c", "target": "https://c/", "verify_tls": False, "method": "get"}]}
        got = {m["label"]: m for m in importers.parse(json.dumps(doc), None)["monitors"]}
        self.assertNotIn("verify_tls", got["a"])
        self.assertNotIn("method", got["a"])
        self.assertNotIn("verify_tls", got["b"])
        self.assertEqual(got["b"]["method"], "head")
        self.assertIs(got["c"]["verify_tls"], False)

    def test_an_uptime_kuma_monitor_keeps_its_two_options(self):
        import importers
        doc = {"monitorList": {"1": {"name": "Home Assistant", "type": "http", "url": "https://ha.lan:8123/",
                                     "ignoreTls": True, "method": "GET"},
                               "2": {"name": "Plain", "type": "http", "url": "https://example.org/",
                                     "ignoreTls": False, "method": "POST"}}}
        got = {m["label"]: m for m in importers.parse(json.dumps(doc), None)["monitors"]}
        self.assertIs(got["Home Assistant"]["verify_tls"], False)
        self.assertEqual(got["Home Assistant"]["method"], "get")
        self.assertNotIn("verify_tls", got["Plain"])
        self.assertNotIn("method", got["Plain"], "only GET and HEAD are methods a monitor can send")


def _save_monitors_expecting(case, monitors):
    """Like _save_monitors, for a save that is meant to be refused: returns {status, body}."""
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj",
             "audit_log", "respond", "require_admin_auth")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.require_admin_auth = lambda: "alice"
    api.verify_token = lambda t: ("alice", "admin")
    api.get_token_from_request = lambda: "t"
    api.method = lambda: "POST"
    api.get_json_body = lambda: json.loads(json.dumps({"monitors": monitors}))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


class TestEditingATargetDoesNotStrandTheAlert(_Base):

    def setUp(self):
        super().setUp()
        self.events = []
        self._real_fire = api.fire_webhook

        def spy(event, payload):
            self.events.append((event, dict(payload)))
            return self._real_fire(event, payload)
        api.fire_webhook = spy

    def tearDown(self):
        api.fire_webhook = self._real_fire
        super().tearDown()

    def result(self, label, target, ok, mtype="http"):
        return {"label": label, "type": mtype, "target": target, "ok": ok,
                "detail": "200" if ok else "401", "checked": int(time.time())}

    def sweep(self, *results):
        api._LOAD_CACHE.clear()
        api._persist_monitor_results(list(results))
        api._LOAD_CACHE.clear()

    def alerts(self, event="monitor_down"):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("event") == event]

    def open_labels(self):
        return sorted((a.get("payload") or {}).get("label") for a in self.alerts() if not a.get("resolved_at"))

    def monitor(self, label, target):
        return {"type": "http", "label": label, "target": target}

    def test_a_target_edited_while_the_monitor_is_down_still_closes_on_recovery(self):
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", old)])
        self.sweep(self.result("Sonarr", old, False))
        self.assertEqual(self.open_labels(), ["Sonarr"])
        self.assertEqual((self.alerts()[0]["payload"] or {}).get("target"), old)

        _save_monitors(self, [self.monitor("Sonarr", new)])
        self.assertEqual(self.open_labels(), ["Sonarr"], "an edit alone does not claim the host is up")

        self.sweep(self.result("Sonarr", new, True))
        self.assertEqual(self.open_labels(), [], "the monitor is up under its new target")
        self.assertEqual([e for e, _ in self.events], ["monitor_down", "monitor_up"])
        self.assertEqual(self.alerts()[0].get("resolved_by"), "auto")

    def test_a_monitor_that_is_still_down_after_the_edit_keeps_one_alert(self):
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", old)])
        self.sweep(self.result("Sonarr", old, False))
        _save_monitors(self, [self.monitor("Sonarr", new)])
        self.sweep(self.result("Sonarr", new, False))
        self.sweep(self.result("Sonarr", new, False))
        self.assertEqual([e for e, _ in self.events], ["monitor_down"], "the down flag survives an edit")
        self.assertEqual(self.open_labels(), ["Sonarr"])

    def test_a_recovery_closes_only_the_monitor_it_names(self):
        a, b = "http://10.0.0.5:8989/", "http://10.0.0.5:7878/"
        self.set_config(monitors=[self.monitor("Sonarr", a), self.monitor("Radarr", b)])
        self.sweep(self.result("Sonarr", a, False), self.result("Radarr", b, False))
        self.assertEqual(self.open_labels(), ["Radarr", "Sonarr"])
        self.sweep(self.result("Sonarr", a + "ping", True), self.result("Radarr", b, False))
        self.assertEqual(self.open_labels(), ["Radarr"])

    def test_the_hosts_of_a_group_monitor_close_one_at_a_time(self):
        sep = api._MON_FANOUT_SEP
        self.set_config(monitors=[{"type": "tcp", "label": "web", "target": "web", "target_kind": "tag",
                                   "port": 443}])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"),
                   self.result("web" + sep + "h2", "10.0.0.2:443", False, "tcp"))
        self.assertEqual(len(self.open_labels()), 2)
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", True, "tcp"),
                   self.result("web" + sep + "h2", "10.0.0.2:443", False, "tcp"))
        self.assertEqual(self.open_labels(), ["web" + sep + "h2"])

    def test_an_alert_the_old_code_left_behind_closes_when_the_monitor_next_recovers(self):
        """Alerts that were stranded on 7.4.2 hold the old target; the next recovery clears them too."""
        old, new = "http://10.0.0.5:8989/", "http://10.0.0.5:8989/ping"
        self.set_config(monitors=[self.monitor("Sonarr", new)],
                        monitor_notified={"Sonarr": True}, monitor_fail_streak={"Sonarr": 1})
        api.fire_webhook("monitor_down", {"label": "Sonarr", "type": "http", "target": old, "detail": "401"})
        self.assertEqual(self.open_labels(), ["Sonarr"])
        self.sweep(self.result("Sonarr", new, True))
        self.assertEqual(self.open_labels(), [])

    def test_deleting_a_monitor_that_is_down_closes_its_alert(self):
        a, b = "http://10.0.0.5:8989/", "http://10.0.0.5:7878/"
        self.set_config(monitors=[self.monitor("Sonarr", a), self.monitor("Radarr", b)])
        self.sweep(self.result("Sonarr", a, False), self.result("Radarr", b, False))
        _save_monitors(self, [self.monitor("Radarr", b)])
        self.assertEqual(self.open_labels(), ["Radarr"], "nothing watches Sonarr any more")

    def test_renaming_a_monitor_that_is_down_closes_the_old_alert_and_the_new_name_alerts_afresh(self):
        a = "http://10.0.0.5:8989/"
        self.set_config(monitors=[self.monitor("Sonarr", a)])
        self.sweep(self.result("Sonarr", a, False))
        _save_monitors(self, [self.monitor("Sonarr (LAN)", a)])
        self.assertEqual(self.open_labels(), [])
        self.sweep(self.result("Sonarr (LAN)", a, False))
        self.assertEqual(self.open_labels(), ["Sonarr (LAN)"])

    def test_deleting_the_hosts_of_a_group_monitor_closes_their_alerts(self):
        sep = api._MON_FANOUT_SEP
        self.set_config(monitors=[{"type": "tcp", "label": "web", "target": "web", "target_kind": "tag",
                                   "port": 443}])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"))
        _save_monitors(self, [])
        self.assertEqual(self.open_labels(), [])

    def test_a_group_monitor_that_is_kept_keeps_the_alerts_of_its_hosts(self):
        """The hosts of a tag monitor are keyed 'label · host', and the monitor itself is still there."""
        sep = api._MON_FANOUT_SEP
        mon = {"type": "tcp", "label": "web", "target": "web", "target_kind": "tag", "port": 443}
        self.set_config(monitors=[mon])
        self.sweep(self.result("web" + sep + "h1", "10.0.0.1:443", False, "tcp"))
        _save_monitors(self, [mon, self.monitor("Radarr", "http://10.0.0.5:7878/")])
        self.assertEqual(self.open_labels(), ["web" + sep + "h1"])

    def test_a_save_that_does_not_touch_the_monitors_leaves_the_alerts_alone(self):
        a = "http://10.0.0.5:8989/"
        self.set_config(monitors=[self.monitor("Sonarr", a)])
        self.sweep(self.result("Sonarr", a, False))
        saved = {n: getattr(api, n) for n in ("verify_token", "get_token_from_request", "method",
                                              "get_json_body", "get_json_obj", "audit_log", "respond",
                                              "require_admin_auth")}
        api.require_admin_auth = lambda: "alice"
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"monitor_interval": 120}
        api.get_json_obj = api.get_json_body
        api.audit_log = lambda *a, **k: None
        box = {}

        def _resp(status, data=None):
            box["status"] = status
            raise api.HTTPError(status, data)
        api.respond = _resp
        try:
            try:
                api.handle_config_save()
            except api.HTTPError:
                pass
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
        self.assertEqual(box.get("status"), 200, box)
        self.assertEqual(self.open_labels(), ["Sonarr"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
