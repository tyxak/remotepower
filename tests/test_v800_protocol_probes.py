#!/usr/bin/env python3
"""8.0.0: the protocol handshakes behind the smtp, imap, ssh and ntp monitor types (server/cgi-bin/protocol_probes.py).

Run against real sockets on the loopback: a small SMTP, IMAP and SSH server in a thread each (with TLS and STARTTLS from a self-signed
certificate made when the module starts) and a UDP server for NTP that can lie in every way a server can: a refusal, a banner that is not the protocol, a
STARTTLS it does not offer, a kiss-of-death, a stratum of 16, a reply that does not answer our request, silence. The arithmetic of the NTP
offset is checked once more with a fake socket and a clock that is told what time it is, so the sign and the size of the number are held by
a case where the right answer is known.

What is held: a service that answers right is up and says what it said; every way of answering wrong or not at all is a failure with a
reason in words; STARTTLS and TLS are really negotiated (and a certificate that is not trusted fails unless the monitor says not to check it);
the address check is called with the peer and its refusal ends the probe before a byte is read; nothing is sent that changes anything (no mail,
no login).
"""
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import protocol_probes as P  # noqa: E402


def self_signed_pair():
    """A throwaway key and certificate made when the module starts, so the repository holds no private key. The client side of these
    tests either does not verify (UNVERIFIED) or must refuse the certificate because nothing trusts it, so only the pair's shape matters."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


_CTX = {}
UNVERIFIED = ssl.create_default_context()
UNVERIFIED.check_hostname = False
UNVERIFIED.verify_mode = ssl.CERT_NONE


def setUpModule():
    d = tempfile.mkdtemp(prefix="rp-probe-cert-")
    f = Path(d) / "pair.pem"
    f.write_bytes(self_signed_pair())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(f))
    _CTX["server"] = ctx


_OPEN = []


def _wrap_server(conn):
    """The server side of a TLS session, remembered so the module can close it: a handler that rebinds `conn` would leak it."""
    s = _CTX["server"].wrap_socket(conn, server_side=True)
    _OPEN.append(s)
    return s


def tearDownModule():
    for s in _OPEN:
        try:
            s.close()
        except OSError:
            pass


class _Tcp(threading.Thread):
    """A one-purpose TCP server on the loopback: `handler(conn)` runs for each connection."""

    def __init__(self, handler):
        super().__init__(daemon=True)
        self.handler = handler
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.seen = []
        self.accepts = 0
        self.start()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(3)
            self.handler(conn, self.seen)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.sock.close()


def _lines(conn, seen):
    """Lines the client sends, as text, until it closes."""
    buf = b""
    while True:
        while b"\n" not in buf:
            chunk = conn.recv(512)
            if not chunk:
                return
            buf += chunk
        line, _, buf = buf.partition(b"\n")
        text = line.rstrip(b"\r").decode("latin-1")
        seen.append(text)
        yield text


def smtp(greeting=b"220 mail.test ESMTP ready\r\n", ehlo=(b"250-mail.test\r\n", b"250-STARTTLS\r\n", b"250 8BITMIME\r\n"),
         starttls_reply=b"220 go ahead\r\n", implicit=False, ehlo_after_tls=True, after_tls=None):
    def handler(conn, seen):
        if implicit:
            conn = _wrap_server(conn)
        conn.sendall(greeting)
        wrapped = False
        for text in _lines(conn, seen):
            up = text.upper()
            if up.startswith("EHLO"):
                if wrapped and not ehlo_after_tls:
                    return
                conn.sendall(b"".join(ehlo))
            elif up == "STARTTLS":
                conn.sendall(starttls_reply)
                if starttls_reply.startswith(b"220"):
                    conn = _wrap_server(conn)
                    wrapped = True
                    # a real server forgets the session: the lines read from here on come from the encrypted socket
                    yield_from = _lines(conn, seen)
                    for t2 in yield_from:
                        if t2.upper().startswith("EHLO"):
                            if not ehlo_after_tls:
                                return
                            conn.sendall(after_tls if after_tls else b"".join(ehlo))
                        elif t2.upper() == "QUIT":
                            conn.sendall(b"221 bye\r\n")
                            return
                    return
            elif up == "QUIT":
                conn.sendall(b"221 bye\r\n")
                return
    return handler


def imap(greeting=b"* OK IMAP4rev1 ready\r\n", caps=b"IMAP4rev1 STARTTLS", cap_ok=True, starttls_ok=True, implicit=False):
    def answer(conn, tag):
        if cap_ok:
            conn.sendall(b"* CAPABILITY " + caps + b"\r\n" + tag + b" OK done\r\n")
        else:
            conn.sendall(tag + b" NO not now\r\n")

    def handler(conn, seen):
        if implicit:
            conn = _wrap_server(conn)
        conn.sendall(greeting)
        it = _lines(conn, seen)
        for text in it:
            tag, _, cmd = text.partition(" ")
            cmd = cmd.upper()
            if cmd == "CAPABILITY":
                answer(conn, tag.encode())
            elif cmd == "STARTTLS":
                if not starttls_ok:
                    conn.sendall(tag.encode() + b" NO nope\r\n")
                    continue
                conn.sendall(tag.encode() + b" OK begin\r\n")
                conn = _wrap_server(conn)
                for t2 in _lines(conn, seen):
                    tg, _, c2 = t2.partition(" ")
                    if c2.upper() == "CAPABILITY":
                        answer(conn, tg.encode())
                    elif c2.upper() == "LOGOUT":
                        conn.sendall(b"* BYE\r\n" + tg.encode() + b" OK bye\r\n")
                        return
                return
            elif cmd == "LOGOUT":
                conn.sendall(b"* BYE\r\n" + tag.encode() + b" OK bye\r\n")
                return
    return handler


def banner(data):
    def handler(conn, seen):
        if data:
            conn.sendall(data)
            time.sleep(0.05)
    return handler


def silent(conn, seen):
    time.sleep(1.5)


class _Ntp(threading.Thread):
    """A UDP server that answers an SNTP request with the time plus a skew, or any lie told by the keyword arguments."""

    def __init__(self, skew=0.0, stratum=2, li=0, mode=4, kod=b"", echo=True, zero_tx=False, reply=True, wait=5):
        super().__init__(daemon=True)
        self.__dict__.update(skew=skew, stratum=stratum, li=li, mode=mode, kod=kod, echo=echo, zero_tx=zero_tx, reply=reply)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(wait)      # how long it waits for the one request; a satellite process asks seconds after it starts
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        try:
            data, addr = self.sock.recvfrom(1024)
        except OSError:
            return
        if not self.reply:
            return
        t = time.time() + self.skew
        out = bytearray(48)
        out[0] = (self.li << 6) | (4 << 3) | self.mode
        out[1] = self.stratum
        out[12:16] = (self.kod + b"\0\0\0\0")[:4]
        out[24:32] = data[40:48] if self.echo else b"\x01" * 8
        out[32:40] = P._to_ntp(t)
        out[40:48] = b"\0" * 8 if self.zero_tx else P._to_ntp(t)
        self.sock.sendto(bytes(out), addr)

    def stop(self):
        self.sock.close()


def started(server):
    return server


class TestSmtp(unittest.TestCase):

    def serve(self, **kw):
        s = _Tcp(smtp(**kw))
        self.addCleanup(s.stop)
        return s

    def probe(self, s, tls="none", ctx=UNVERIFIED, **kw):
        return P.run("smtp", "127.0.0.1", s.port, {"tls": tls}, ssl_ctx=ctx, timeout=3, **kw)

    def test_a_server_that_answers_is_up_and_the_detail_says_what_it_said(self):
        s = self.serve()
        ok, detail = self.probe(s)
        self.assertTrue(ok, detail)
        self.assertIn("mail.test ESMTP ready", detail)
        self.assertRegex(detail, r"\d+ms$")
        self.assertEqual(s.seen[:1], ["EHLO remotepower"])

    def test_nothing_is_sent_that_changes_anything(self):
        s = self.serve()
        self.probe(s)
        time.sleep(0.1)
        for line in s.seen:
            self.assertRegex(line.upper(), r"^(EHLO|QUIT)\b", "only EHLO and QUIT: no MAIL FROM, no AUTH")

    def test_a_multiline_greeting_is_read_to_its_end(self):
        s = self.serve(greeting=b"220-mail.test\r\n220-second line\r\n220 ESMTP ready\r\n")
        self.assertTrue(self.probe(s)[0])

    def test_a_refused_greeting_is_down_with_the_code(self):
        ok, detail = self.probe(self.serve(greeting=b"554 no service for you\r\n"))
        self.assertFalse(ok)
        self.assertIn("554", detail)

    def test_a_banner_that_is_not_smtp_is_down(self):
        ok, detail = self.probe(self.serve(greeting=b"SSH-2.0-OpenSSH_9.6\r\n"))
        self.assertFalse(ok)
        self.assertIn("not SMTP", detail)

    def test_an_ehlo_that_is_refused_is_down(self):
        ok, detail = self.probe(self.serve(ehlo=(b"502 not implemented\r\n",)))
        self.assertFalse(ok)
        self.assertIn("EHLO refused", detail)

    def test_starttls_is_negotiated_and_the_session_is_used(self):
        s = self.serve()
        ok, detail = self.probe(s, "starttls")
        self.assertTrue(ok, detail)
        self.assertIn("STARTTLS", detail)
        time.sleep(0.1)
        self.assertEqual([x for x in s.seen if x.upper().startswith("EHLO")], ["EHLO remotepower"] * 2, "a second EHLO inside the encrypted session")

    def test_starttls_that_is_not_offered_is_down(self):
        ok, detail = self.probe(self.serve(ehlo=(b"250-mail.test\r\n", b"250 8BITMIME\r\n")), "starttls")
        self.assertEqual((ok, detail), (False, "STARTTLS is not offered"))

    def test_starttls_that_is_refused_is_down(self):
        ok, detail = self.probe(self.serve(starttls_reply=b"454 TLS not available\r\n"), "starttls")
        self.assertFalse(ok)
        self.assertIn("STARTTLS refused (454)", detail)

    def test_a_session_that_goes_quiet_after_starttls_is_down(self):
        ok, detail = self.probe(self.serve(ehlo_after_tls=False), "starttls")
        self.assertFalse(ok)
        self.assertTrue(detail)

    def test_a_session_that_answers_with_an_error_after_starttls_is_down_with_the_code(self):
        # the upgrade worked and the server then refuses to talk: the monitor has to say so, not report an encrypted session that does not work
        ok, detail = self.probe(self.serve(after_tls=b"421 service not available\r\n"), "starttls")
        self.assertEqual((ok, detail), (False, "no answer inside STARTTLS (421)"))

    def test_an_untrusted_certificate_fails_unless_the_monitor_says_not_to_check(self):
        s = self.serve()
        ok, detail = P.run("smtp", "127.0.0.1", s.port, {"tls": "starttls"}, ssl_ctx=ssl.create_default_context(), timeout=3)
        self.assertEqual((ok, detail), (False, "TLS: the certificate was not accepted"))
        s2 = self.serve()
        self.assertTrue(self.probe(s2, "starttls")[0])

    def test_tls_from_the_first_byte(self):
        s = self.serve(implicit=True)
        ok, detail = self.probe(s, "tls")
        self.assertTrue(ok, detail)
        self.assertIn("TLS", detail)
        ok, detail = P.run("smtp", "127.0.0.1", self.serve(implicit=True).port, {"tls": "tls"}, ssl_ctx=ssl.create_default_context(), timeout=3)
        self.assertEqual((ok, detail), (False, "TLS: the certificate was not accepted"))

    def test_plain_text_to_a_tls_port_is_down(self):
        ok, _ = self.probe(self.serve(implicit=True), "none")
        self.assertFalse(ok)

    def test_a_server_that_closes_without_a_word_is_down(self):
        s = _Tcp(lambda conn, seen: None)
        self.addCleanup(s.stop)
        ok, detail = self.probe(s)
        self.assertFalse(ok)
        self.assertIn("closed", detail)

    def test_silence_is_a_timeout_in_words(self):
        s = _Tcp(silent)
        self.addCleanup(s.stop)
        ok, detail = P.run("smtp", "127.0.0.1", s.port, {}, ssl_ctx=UNVERIFIED, timeout=0.3)
        self.assertEqual((ok, detail), (False, "it did not answer in time"))

    def test_a_closed_port_is_refused_in_words(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(P.run("smtp", "127.0.0.1", port, {}, timeout=2), (False, "the connection was refused"))

    def test_a_name_that_does_not_resolve_is_said_so(self):
        self.assertEqual(P.run("smtp", "no-such-host.invalid", 25, {}, timeout=2), (False, "the host name does not resolve"))

    def test_the_address_check_is_called_with_the_address_and_ends_the_probe_before_anything_is_connected_to(self):
        s = self.serve()
        asked = []
        ok, detail = self.probe(s, peer_ok=lambda ip: asked.append(ip) or False)
        self.assertEqual((ok, detail), (False, "blocked"))
        self.assertEqual(asked, ["127.0.0.1"])
        time.sleep(0.1)
        self.assertEqual(s.seen, [], "nothing was said to a blocked address")
        self.assertEqual(s.accepts, 0, "and no connection was made to it: the check comes before the connect")

    def test_a_name_with_one_blocked_address_among_its_answers_is_refused_and_a_checked_address_is_what_is_connected_to(self):
        real = P.socket.getaddrinfo
        connected = []
        real_create = P.socket.create_connection
        P.socket.getaddrinfo = lambda host, port, *a, **k: [(P.socket.AF_INET, P.socket.SOCK_STREAM, 6, "", ("203.0.113.5", port)),
                                                           (P.socket.AF_INET, P.socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        P.socket.create_connection = lambda addr, timeout=None, **k: connected.append(addr) or (_ for _ in ()).throw(OSError("not reached"))
        try:
            self.assertEqual(P.run("smtp", "twofaced.example", 25, {}, timeout=1, peer_ok=lambda ip: ip != "169.254.169.254"), (False, "blocked"))
            self.assertEqual(connected, [], "one blocked address among the answers refuses the name before any connection")
            P.run("smtp", "fine.example", 25, {}, timeout=1, peer_ok=lambda ip: True)
            self.assertEqual(connected[0], ("203.0.113.5", 25), "the connection goes to the address that was checked, not to the name")
        finally:
            P.socket.getaddrinfo = real
            P.socket.create_connection = real_create


class TestImap(unittest.TestCase):

    def serve(self, **kw):
        s = _Tcp(imap(**kw))
        self.addCleanup(s.stop)
        return s

    def probe(self, s, tls="none", ctx=UNVERIFIED, **kw):
        return P.run("imap", "127.0.0.1", s.port, {"tls": tls}, ssl_ctx=ctx, timeout=3, **kw)

    def test_a_server_that_answers_is_up_and_names_the_protocol(self):
        s = self.serve()
        ok, detail = self.probe(s)
        self.assertTrue(ok, detail)
        self.assertTrue(detail.startswith("IMAP4rev1"), detail)
        self.assertEqual(s.seen[:1], ["a1 CAPABILITY"])

    def test_nothing_is_sent_that_logs_in(self):
        s = self.serve()
        self.probe(s)
        time.sleep(0.1)
        for line in s.seen:
            self.assertNotRegex(line.upper(), r"\b(LOGIN|AUTHENTICATE|SELECT)\b")

    def test_a_bye_is_a_refusal(self):
        ok, detail = self.probe(self.serve(greeting=b"* BYE too many connections\r\n"))
        self.assertFalse(ok)
        self.assertIn("refused", detail)

    def test_a_banner_that_is_not_imap_is_down(self):
        ok, detail = self.probe(self.serve(greeting=b"+OK POP3 ready\r\n"))
        self.assertFalse(ok)
        self.assertIn("not IMAP", detail)

    def test_a_refused_capability_is_down(self):
        self.assertEqual(self.probe(self.serve(cap_ok=False)), (False, "CAPABILITY refused"))

    def test_starttls_is_negotiated(self):
        ok, detail = self.probe(self.serve(), "starttls")
        self.assertTrue(ok, detail)
        self.assertIn("STARTTLS", detail)

    def test_starttls_that_is_not_offered_is_down(self):
        self.assertEqual(self.probe(self.serve(caps=b"IMAP4rev1"), "starttls"), (False, "STARTTLS is not offered"))

    def test_starttls_that_is_refused_is_down(self):
        self.assertEqual(self.probe(self.serve(starttls_ok=False), "starttls"), (False, "STARTTLS refused"))

    def test_an_untrusted_certificate_fails_unless_the_monitor_says_not_to_check(self):
        ok, detail = P.run("imap", "127.0.0.1", self.serve().port, {"tls": "starttls"}, ssl_ctx=ssl.create_default_context(), timeout=3)
        self.assertEqual((ok, detail), (False, "TLS: the certificate was not accepted"))

    def test_tls_from_the_first_byte(self):
        ok, detail = self.probe(self.serve(implicit=True), "tls")
        self.assertTrue(ok, detail)
        self.assertIn("TLS", detail)

    def test_the_address_check_ends_the_probe(self):
        s = self.serve()
        self.assertEqual(self.probe(s, peer_ok=lambda ip: False), (False, "blocked"))
        time.sleep(0.1)
        self.assertEqual(s.seen, [])


class TestSsh(unittest.TestCase):

    def probe(self, data, **kw):
        s = _Tcp(banner(data))
        self.addCleanup(s.stop)
        return P.run("ssh", "127.0.0.1", s.port, {}, timeout=2, **kw)

    def test_the_banner_is_the_detail(self):
        ok, detail = self.probe(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")
        self.assertTrue(ok, detail)
        self.assertTrue(detail.startswith("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3 · "), detail)

    def test_lines_before_the_banner_are_allowed(self):
        self.assertTrue(self.probe(b"This server is monitored.\r\nUse is logged.\r\nSSH-2.0-dropbear_2022.83\r\n")[0])

    def test_ssh_one_dot_99_is_ssh_two(self):
        self.assertTrue(self.probe(b"SSH-1.99-OpenSSH_3.9\r\n")[0])

    def test_the_old_protocol_is_not_accepted(self):
        ok, detail = self.probe(b"SSH-1.5-old\r\n")
        self.assertFalse(ok)
        self.assertIn("not SSH 2", detail)

    def test_a_banner_that_is_not_ssh_is_down(self):
        self.assertEqual(self.probe(b"220 mail ready\r\n" * 9), (False, "no SSH banner"))

    def test_a_server_that_says_nothing_and_closes_is_down(self):
        ok, detail = self.probe(b"")
        self.assertFalse(ok)

    def test_a_banner_full_of_control_characters_is_shown_clean(self):
        ok, detail = self.probe(b"SSH-2.0-evil\x1b[31m\x07\x00thing\r\n")
        self.assertTrue(ok)
        self.assertNotRegex(detail, r"[\x00-\x1f\x7f]")

    def test_a_very_long_banner_line_is_cut(self):
        ok, detail = self.probe(b"SSH-2.0-" + b"x" * 5000 + b"\r\n")
        self.assertTrue(ok)
        self.assertLessEqual(len(detail), 100)

    def test_the_address_check_ends_the_probe(self):
        s = _Tcp(banner(b"SSH-2.0-x\r\n"))
        self.addCleanup(s.stop)
        self.assertEqual(P.run("ssh", "127.0.0.1", s.port, {}, timeout=2, peer_ok=lambda ip: False), (False, "blocked"))


class TestNtp(unittest.TestCase):

    def probe(self, limit=None, peer_ok=None, timeout=2, **server):
        s = _Ntp(**server)
        self.addCleanup(s.stop)
        m = {} if limit is None else {"max_offset_ms": limit}
        return P.run("ntp", "127.0.0.1", s.port, m, timeout=timeout, peer_ok=peer_ok)

    def test_a_synchronised_server_is_up_with_its_stratum_offset_and_delay(self):
        ok, detail = self.probe()
        self.assertTrue(ok, detail)
        self.assertRegex(detail, r"^stratum 2 · offset [+-]\d+\.\d ms · delay \d+ ms$")

    def test_a_clock_ahead_by_five_seconds_has_a_positive_offset_and_fails_a_limit(self):
        ok, detail = self.probe(skew=5.0)
        self.assertTrue(ok, "no limit set: a drifting clock is not a failure")
        self.assertRegex(detail, r"offset \+49\d\d\.\d ms|offset \+50\d\d\.\d ms")
        ok, detail = self.probe(limit=1000, skew=5.0)
        self.assertFalse(ok)
        self.assertIn("(limit 1000 ms)", detail)

    def test_a_clock_behind_has_a_negative_offset(self):
        ok, detail = self.probe(skew=-3.0)
        self.assertIn("offset -", detail)

    def test_an_offset_inside_the_limit_is_up(self):
        self.assertTrue(self.probe(limit=1000, skew=0.2)[0])

    def test_a_kiss_of_death_is_down_and_names_the_code(self):
        self.assertEqual(self.probe(stratum=0, kod=b"RATE"), (False, "kiss-of-death RATE"))
        self.assertEqual(self.probe(stratum=0, kod=b"DENY"), (False, "kiss-of-death DENY"))

    def test_stratum_sixteen_and_the_alarm_flag_are_not_synchronised(self):
        self.assertEqual(self.probe(stratum=16), (False, "not synchronised (stratum 16)"))
        self.assertEqual(self.probe(li=3), (False, "not synchronised (stratum 2)"))

    def test_a_reply_that_is_not_a_server_reply_is_down(self):
        ok, detail = self.probe(mode=3)
        self.assertFalse(ok)
        self.assertIn("not a server reply", detail)

    def test_a_reply_that_does_not_answer_our_request_is_down(self):
        self.assertEqual(self.probe(echo=False), (False, "the reply does not match the request"))

    def test_a_reply_with_no_time_is_down(self):
        self.assertEqual(self.probe(zero_tx=True), (False, "the reply carries no time"))

    def test_silence_is_a_timeout_in_words(self):
        self.assertEqual(self.probe(reply=False, timeout=0.3), (False, "it did not answer in time"))

    def test_the_address_check_is_called_with_the_address_it_would_send_to(self):
        asked = []
        s = _Ntp()
        self.addCleanup(s.stop)
        ok, detail = P.run("ntp", "127.0.0.1", s.port, {}, timeout=1, peer_ok=lambda ip: asked.append(ip) or False)
        self.assertEqual((ok, detail), (False, "blocked"))
        self.assertEqual(asked, ["127.0.0.1"])

    def test_a_name_that_does_not_resolve_is_said_so(self):
        self.assertEqual(P.run("ntp", "no-such-host.invalid", 123, {}, timeout=1), (False, "the host name does not resolve"))

    def test_the_timestamps_round_trip(self):
        for ts in (0.0, 1.5, 1794045600.123456):
            self.assertAlmostEqual(P._from_ntp(P._to_ntp(ts)), ts, places=5)

    def test_the_timestamps_survive_the_wrap_of_2036_when_the_local_clock_says_which_era(self):
        # the seconds field wraps in February 2036: a server and a client on either side of it must still agree
        for ts in (2 ** 31 + 0.999, 2085978496.5, 2 ** 32 + 5.5, 2 ** 33 + 0.25):
            wire = P._to_ntp(ts)
            self.assertEqual(len(wire), 8)
            self.assertAlmostEqual(P._from_ntp(wire, ts + 0.3), ts, places=5, msg=ts)
            self.assertAlmostEqual(P._from_ntp(wire, ts - 0.3), ts, places=5, msg=ts)


class _FakeUdp:
    """A socket that answers with a packet made from times the test chose, to hold the arithmetic where the right answer is known."""

    def __init__(self, t2, t3, stratum=2):
        self.t2, self.t3, self.stratum, self.sent = t2, t3, stratum, None

    def settimeout(self, t):
        pass

    def sendto(self, data, sa):
        self.sent, self.sa = data, sa

    def recvfrom(self, n):
        out = bytearray(48)
        out[0] = (4 << 3) | 4
        out[1] = self.stratum
        out[24:32] = self.sent[40:48]
        out[32:40] = P._to_ntp(self.t2)
        out[40:48] = P._to_ntp(self.t3)
        return bytes(out), self.sa

    def close(self):
        pass


class TestTheArithmetic(unittest.TestCase):

    def run_with(self, t1, t4, t2, t3, limit=None):
        clock = iter([t1, t4])
        fake = _FakeUdp(t2, t3)
        return P.ntp_probe("127.0.0.1", 123, limit, now=lambda: next(clock), sock_factory=lambda fam: fake)

    def test_offset_is_the_mean_of_the_two_legs_and_delay_is_the_round_trip_minus_the_servers_time(self):
        # sent at 1000.0, received at 1000.2; the server received at 1000.6 and replied at 1000.7:
        # offset = ((0.6) + (0.5)) / 2 = +0.55 s, delay = 0.2 - 0.1 = 0.1 s
        ok, detail = self.run_with(1000.0, 1000.2, 1000.6, 1000.7)
        self.assertTrue(ok)
        self.assertEqual(detail, "stratum 2 · offset +550.0 ms · delay 100 ms")

    def test_a_server_behind_us_has_a_negative_offset(self):
        ok, detail = self.run_with(1000.0, 1000.2, 999.4, 999.5)
        self.assertEqual(detail, "stratum 2 · offset -650.0 ms · delay 100 ms")

    def test_the_limit_is_compared_with_the_size_not_the_sign(self):
        self.assertFalse(self.run_with(1000.0, 1000.2, 999.4, 999.5, limit=600)[0])
        self.assertTrue(self.run_with(1000.0, 1000.2, 999.4, 999.5, limit=700)[0])
        self.assertFalse(self.run_with(1000.0, 1000.2, 1000.6, 1000.7, limit=500)[0])

    def test_a_negative_delay_from_clock_noise_is_shown_as_zero(self):
        ok, detail = self.run_with(1000.0, 1000.0, 1000.0, 1000.001)
        self.assertTrue(ok)
        self.assertIn("delay 0 ms", detail)


class TestRun(unittest.TestCase):

    def test_an_unknown_type_is_a_failure_not_an_exception(self):
        self.assertEqual(P.run("ftp", "127.0.0.1", 21, {}), (False, "unknown protocol check"))

    def test_a_tls_mode_that_is_not_one_of_the_three_is_none(self):
        s = _Tcp(smtp())
        self.addCleanup(s.stop)
        for bad in ("STARTTLS", "ssl", None, 5, True, ["tls"]):
            ok, detail = P.run("smtp", "127.0.0.1", s.port, {"tls": bad}, ssl_ctx=UNVERIFIED, timeout=3)
            self.assertTrue(ok, (bad, detail))
            self.assertNotIn("STARTTLS", detail)

    def test_an_offset_limit_that_is_not_a_sane_number_is_no_limit(self):
        for bad in (True, False, 0, -5, P.MAX_OFFSET_MS + 1, "100", None, [], float("nan")):
            s = _Ntp(skew=5.0)
            self.addCleanup(s.stop)
            ok, detail = P.run("ntp", "127.0.0.1", s.port, {"max_offset_ms": bad}, timeout=2)
            self.assertTrue(ok, (bad, detail))

    def test_the_default_ports_are_the_protocols_own(self):
        self.assertEqual(P.DEFAULT_PORTS, {"smtp": 25, "imap": 143, "ssh": 22, "ntp": 123})
        self.assertEqual(set(P.TYPES), set(P.DEFAULT_PORTS))

    def test_what_a_server_says_is_never_shown_raw(self):
        self.assertEqual(P._clean("a\x00b\x1b[31mc\r\nd\t" + "x" * 500, 20), "a b [31mc d xxxxxxxx".replace("[31m", "[31m")[:20])
        self.assertNotRegex(P._clean("\x00\x01\x7f\xff‮"), r"[^\x20-\x7e]")


if __name__ == "__main__":
    unittest.main()
