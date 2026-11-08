"""A fake mail submission server on the loopback, for the tests of the e-mail guide.

It speaks the part of SMTP that smtplib uses to send one message: the greeting, EHLO, STARTTLS (or TLS from the first byte), AUTH PLAIN and
AUTH LOGIN, MAIL FROM, RCPT TO, DATA and QUIT. Every connection leaves a record in `sessions`, so a test reads what the server was sent
(the user name and password, whether the connection was encrypted, the addresses, the message and its readable text) instead of trusting a log line.

    mail = FakeMail(user="ops", password="s3cret", tls="starttls")
    ... point the code at 127.0.0.1:mail.port ...
    mail.sessions[-1]["auth"]      # ("ops", "s3cret")
    mail.stop()
"""
import base64
import email
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from test_v800_protocol_probes import self_signed_pair       # a throwaway key and certificate for localhost, made when the first TLS server starts

_CTX = []


def _server_context():
    if not _CTX:
        d = tempfile.mkdtemp(prefix="rp-smtp-fake-cert-")
        f = Path(d) / "pair.pem"
        f.write_bytes(self_signed_pair())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(f))
        _CTX.append(ctx)
    return _CTX[0]


def _plain_text(raw):
    """The readable body of a message the way a mail program shows it: the text/plain part, decoded."""
    msg = email.message_from_string(raw)
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            payload = part.get_payload(decode=True) or b""
            return payload.decode(part.get_content_charset() or "utf-8", "replace")
    return ""


class FakeMail(threading.Thread):
    """tls: 'none' (no encryption offered), 'starttls' (offered, and AUTH only after it, like most providers) or 'implicit'.
    user/password: when set, a message is accepted only after AUTH with them. refuse_sender / refuse_rcpt / auth_code: answers to refuse."""

    def __init__(self, tls="none", user=None, password=None, refuse_sender=False, refuse_rcpt=False, auth_code="535 5.7.8 Authentication failed",
                 auth_before_tls=False):
        super().__init__(daemon=True)
        self.tls, self.user, self.password = tls, user, password
        self.refuse_sender, self.refuse_rcpt, self.auth_code = refuse_sender, refuse_rcpt, auth_code
        self.auth_before_tls = auth_before_tls
        self.sessions = []
        self._socks = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass

    # ── one connection ──────────────────────────────────────────────────────────────────────────────────────────────────────
    def _serve(self, conn):
        rec = {"tls": False, "auth": None, "auth_ok": False, "from": None, "to": [], "data": None, "text": None, "helo": None, "lines": []}
        self.sessions.append(rec)
        self._socks.append(conn)
        try:
            conn.settimeout(5)
            if self.tls == "implicit":
                conn = _server_context().wrap_socket(conn, server_side=True)
                self._socks.append(conn)
                rec["tls"] = True
            self._talk(conn, rec)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send(self, conn, text):
        conn.sendall(text.encode() + b"\r\n")

    def _read(self, conn, rec, buf):
        while b"\n" not in buf[0]:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf[0] += chunk
        line, _, buf[0] = buf[0].partition(b"\n")
        text = line.rstrip(b"\r").decode("latin-1")
        rec["lines"].append(text)
        return text

    def _talk(self, conn, rec):
        buf = [b""]
        self._send(conn, "220 mail.test ESMTP ready")
        while True:
            line = self._read(conn, rec, buf)
            if line is None:
                return
            word = line.split(" ", 1)[0].upper()
            if word in ("EHLO", "HELO"):
                rec["helo"] = line.split(" ", 1)[1] if " " in line else ""
                lines = ["mail.test", "8BITMIME"]
                if self.tls == "starttls" and not rec["tls"]:
                    lines.append("STARTTLS")
                if self.user is not None and (rec["tls"] or self.tls == "none" or self.auth_before_tls):
                    lines.append("AUTH PLAIN LOGIN")
                for i, t in enumerate(lines):
                    self._send(conn, ("250-" if i < len(lines) - 1 else "250 ") + t)
            elif word == "STARTTLS":
                self._send(conn, "220 go ahead")
                conn = _server_context().wrap_socket(conn, server_side=True)
                self._socks.append(conn)
                rec["tls"] = True
                buf[0] = b""
            elif word == "AUTH":
                self._auth(conn, rec, buf, line)
            elif word == "MAIL":
                if self.user is not None and not rec["auth_ok"]:
                    self._send(conn, "530 5.7.0 Authentication required")
                elif self.refuse_sender:
                    self._send(conn, "550 5.7.1 Sender address rejected")
                else:
                    rec["from"] = line.split(":", 1)[1].strip().strip("<>").split(">")[0]
                    self._send(conn, "250 ok")
            elif word == "RCPT":
                if self.refuse_rcpt:
                    self._send(conn, "550 5.7.1 Relay access denied")
                else:
                    rec["to"].append(line.split(":", 1)[1].strip().strip("<>").split(">")[0])
                    self._send(conn, "250 ok")
            elif word == "DATA":
                self._send(conn, "354 end with a dot on a line of its own")
                data = b""
                while not data.endswith(b"\r\n.\r\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                rec["data"] = data[:-5].decode("utf-8", "replace")
                rec["text"] = _plain_text(rec["data"])
                self._send(conn, "250 2.0.0 queued")
            elif word in ("RSET", "NOOP"):
                self._send(conn, "250 ok")
            elif word == "QUIT":
                self._send(conn, "221 bye")
                return
            else:
                self._send(conn, "502 command not implemented")

    def _auth(self, conn, rec, buf, line):
        parts = line.split(" ")
        mech = parts[1].upper() if len(parts) > 1 else ""
        creds = None
        if mech == "PLAIN":
            token = parts[2] if len(parts) > 2 else None
            if token is None:
                self._send(conn, "334 ")
                token = self._read(conn, rec, buf)
            try:
                _, user, pw = base64.b64decode(token or "").decode().split("\x00")
                creds = (user, pw)
            except (ValueError, UnicodeDecodeError):
                creds = None
        elif mech == "LOGIN":
            self._send(conn, "334 VXNlcm5hbWU6")
            user = base64.b64decode(self._read(conn, rec, buf) or "").decode()
            self._send(conn, "334 UGFzc3dvcmQ6")
            pw = base64.b64decode(self._read(conn, rec, buf) or "").decode()
            creds = (user, pw)
        rec["auth"] = creds
        if creds is not None and creds == (self.user, self.password):
            rec["auth_ok"] = True
            self._send(conn, "235 2.7.0 Authentication successful")
        else:
            self._send(conn, self.auth_code)
