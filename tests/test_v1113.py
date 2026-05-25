#!/usr/bin/env python3
"""Unit tests for v1.11.3: STARTTLS support.

Covers:
  - parse_target accepts and validates ``starttls``
  - "auto" resolves to the right protocol per port
  - Default for missing field is "auto" → backwards-compatible
  - End-to-end probe against a local SMTP-with-STARTTLS test server
  - End-to-end probe against a local IMAP-with-STARTTLS test server
  - End-to-end probe against a local POP3-with-STLS test server
  - Server response with bad STARTTLS reply lands in tls_error
"""

import datetime
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import tls_monitor  # noqa: E402


# ─── Test cert helper ─────────────────────────────────────────────────────────


def _make_self_signed_cert():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    f.write(cert_pem + key_pem)
    f.close()
    return f.name


# Cert is shared across all tests in this module — minting one takes ~1s
# and the test duration adds up otherwise.
try:
    _TEST_CERT = _make_self_signed_cert()
except ImportError:
    _TEST_CERT = None


def _start_server(handler):
    """Bind to a random port, run ``handler(sock)`` in a thread, return port."""
    port_holder = []

    def _run():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port_holder.append(srv.getsockname()[1])
        srv.listen(1)
        srv.settimeout(5.0)
        try:
            sock, _ = srv.accept()
            try:
                handler(sock)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except socket.timeout:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    # Wait up to 2s for the server to bind
    for _ in range(40):
        if port_holder:
            return port_holder[0], t
        time.sleep(0.05)
    raise RuntimeError("test server didn't bind")


def _wrap_tls(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(_TEST_CERT)
    return ctx.wrap_socket(sock, server_side=True)


# ─── parse_target ─────────────────────────────────────────────────────────────


class TestParseStartTLS(unittest.TestCase):
    def test_default_is_auto_then_resolved(self):
        # Missing field → defaults to 'auto' → resolved to 'none' for 443
        t = tls_monitor.parse_target({"host": "example.com", "port": 443})
        self.assertEqual(t["starttls"], "none")

    def test_auto_smtp_port_25(self):
        t = tls_monitor.parse_target({"host": "mx.test", "port": 25})
        self.assertEqual(t["starttls"], "smtp")

    def test_auto_smtp_port_587(self):
        t = tls_monitor.parse_target({"host": "submission.test", "port": 587})
        self.assertEqual(t["starttls"], "smtp")

    def test_auto_imap_port_143(self):
        t = tls_monitor.parse_target({"host": "imap.test", "port": 143})
        self.assertEqual(t["starttls"], "imap")

    def test_auto_pop3_port_110(self):
        t = tls_monitor.parse_target({"host": "pop.test", "port": 110})
        self.assertEqual(t["starttls"], "pop3")

    def test_auto_ldap_port_389(self):
        t = tls_monitor.parse_target({"host": "ldap.test", "port": 389})
        self.assertEqual(t["starttls"], "ldap")

    def test_explicit_none_overrides_auto(self):
        t = tls_monitor.parse_target({"host": "mx.test", "port": 25, "starttls": "none"})
        self.assertEqual(t["starttls"], "none")

    def test_explicit_smtp_on_weird_port(self):
        t = tls_monitor.parse_target({"host": "mx.test", "port": 9025, "starttls": "smtp"})
        self.assertEqual(t["starttls"], "smtp")

    def test_invalid_protocol_rejected(self):
        self.assertIsNone(tls_monitor.parse_target({"host": "x", "starttls": "bogus"}))

    def test_v1112_record_works(self):
        # Records saved before v1.11.3 won't have the field; we should
        # still parse them and resolve auto from port.
        record = {"host": "mx.test", "port": 587, "warn_days": 14, "crit_days": 3}
        t = tls_monitor.parse_target(record)
        self.assertIsNotNone(t)
        self.assertEqual(t["starttls"], "smtp")


# ─── End-to-end probes against local STARTTLS servers ────────────────────────


@unittest.skipIf(_TEST_CERT is None, "cryptography not available")
class TestSTARTTLSEndToEnd(unittest.TestCase):
    def test_smtp_starttls_captures_cert(self):
        def handler(sock):
            sock.sendall(b"220 test.local ESMTP\r\n")
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            # EHLO reply must include STARTTLS capability
            sock.sendall(b"250-test.local Hello\r\n250 STARTTLS\r\n")
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            sock.sendall(b"220 Ready to start TLS\r\n")
            try:
                _wrap_tls(sock).recv(1)
            except Exception:
                pass

        port, _ = _start_server(handler)
        result = tls_monitor._probe_tls("localhost", port, starttls="smtp")
        self.assertGreater(result["expires_at"], 0,
                           f"no cert captured. tls_error={result.get('tls_error')!r}")
        self.assertEqual(result["tls_error"], "")
        self.assertEqual(result["starttls"], "smtp")

    def test_imap_starttls_captures_cert(self):
        def handler(sock):
            sock.sendall(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] test.local\r\n")
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            sock.sendall(b"A001 OK Begin TLS negotiation now\r\n")
            try:
                _wrap_tls(sock).recv(1)
            except Exception:
                pass

        port, _ = _start_server(handler)
        result = tls_monitor._probe_tls("localhost", port, starttls="imap")
        self.assertGreater(result["expires_at"], 0,
                           f"no cert captured. tls_error={result.get('tls_error')!r}")

    def test_pop3_stls_captures_cert(self):
        def handler(sock):
            sock.sendall(b"+OK POP3 server ready\r\n")
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            sock.sendall(b"+OK Begin TLS negotiation\r\n")
            try:
                _wrap_tls(sock).recv(1)
            except Exception:
                pass

        port, _ = _start_server(handler)
        result = tls_monitor._probe_tls("localhost", port, starttls="pop3")
        self.assertGreater(result["expires_at"], 0,
                           f"no cert captured. tls_error={result.get('tls_error')!r}")

    def test_smtp_starttls_refused_lands_in_tls_error(self):
        """A server that refuses STARTTLS should produce a clean error,
        not a hang or a confusing direct-TLS failure."""

        def handler(sock):
            sock.sendall(b"220 test.local ESMTP\r\n")
            # Read EHLO
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            # Reply WITHOUT STARTTLS capability
            sock.sendall(b"250 test.local Hello, no encryption here\r\n")
            # Read STARTTLS command
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
            sock.sendall(b"502 STARTTLS not supported\r\n")

        port, _ = _start_server(handler)
        result = tls_monitor._probe_tls("localhost", port, starttls="smtp")
        self.assertEqual(result["expires_at"], 0)
        self.assertIn("STARTTLS", result["tls_error"])
        self.assertIn("502", result["tls_error"])

    def test_direct_tls_on_smtp_port_fails_cleanly(self):
        """If a user picks 'none' on port 25, they get the v1.11.0 behaviour
        (immediate TLS handshake that the server won't speak). We're
        making sure that path still returns a clean tls_error rather than
        crashing."""

        def handler(sock):
            sock.sendall(b"220 test.local ESMTP\r\n")
            time.sleep(0.5)  # Don't speak TLS

        port, _ = _start_server(handler)
        result = tls_monitor._probe_tls("localhost", port, starttls="none")
        self.assertEqual(result["expires_at"], 0)
        self.assertTrue(result["tls_error"])  # Some error, just not crashed


if __name__ == "__main__":
    unittest.main()
