"""RemotePower: protocol handshakes for monitors. SMTP, IMAP, SSH and NTP (8.0.0).

A TCP monitor says a port accepts a connection. These say the service behind it answers the way it should, without a password and without
changing anything:

  smtp   connects, reads the 220 greeting, says EHLO. With STARTTLS it checks the server offers it and that the encrypted session works
         (a second EHLO inside it); with TLS the session is encrypted from the first byte (port 465). No mail is sent.
  imap   the same for IMAP: the "* OK" greeting, CAPABILITY, and with STARTTLS or TLS the handshake. No login.
  ssh    reads the identification line a server sends ("SSH-2.0-OpenSSH_9.6"). No login, no key exchange.
  ntp    sends one SNTP request and reads the answer: is the server synchronised (stratum 1 to 15, not an alarm, not a kiss-of-death), and how far
         is its clock from this machine's. A limit on that offset turns a drifting clock into a failure.

Every function returns ``(ok, detail)`` and never raises through ``run``. They are pure of the application: the address check a probe needs
(the server's rule that a cloud metadata or link-local address is never reached, and loopback only when it is allowed) is passed in as
``peer_ok``, called with the peer's address after the connection is made, so a name that resolved to somewhere else at connect time is caught.
A monitor of these types runs from the RemotePower server like the TCP and database ones; a host's agent and a satellite do not run them.
"""

import socket
import ssl
import struct
import time

DEFAULT_PORTS = {"smtp": 25, "imap": 143, "ssh": 22, "ntp": 123}
TYPES = tuple(DEFAULT_PORTS)
TLS_MODES = ("none", "starttls", "tls")
MAX_OFFSET_MS = 3_600_000  # an hour: past that the clock is not "a little off"
_NTP_EPOCH = 2208988800  # seconds from 1900-01-01 to 1970-01-01
_LINE_MAX = 1024
_REPLY_LINES_MAX = 40


class ProbeError(Exception):
    """A probe that failed in a way worth saying in words."""


def _clean(text, limit=60):
    """One printable line, cut: what a server said, safe to show in a table and to put in a message."""
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in str(text))
    return " ".join(s.split())[:limit]


def _connect(host, port, timeout, peer_ok):
    """Resolve the name once, refuse it when any address it resolves to is one the check will not allow, and connect to an address that
    was checked, so a name cannot answer one thing to the check and another to the connection and nothing is connected to that should not
    be. The peer is checked again once connected, which costs nothing."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if peer_ok is not None:
        for info in infos:
            if not peer_ok(info[4][0]):
                raise ProbeError("blocked")
    err = None
    for info in infos:
        try:
            s = socket.create_connection((info[4][0], info[4][1]), timeout=timeout)
        except OSError as e:
            err = e
            continue
        try:
            peer = s.getpeername()[0]
        except (OSError, IndexError):
            peer = None
        if peer_ok is not None and peer and not peer_ok(peer):
            s.close()
            raise ProbeError("blocked")
        s.settimeout(timeout)
        return s
    raise err or OSError("no address to connect to")


def _wrap(sock, host, ctx):
    ctx = ctx or ssl.create_default_context()
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError:
        sock.close()
        raise ProbeError("TLS: the certificate was not accepted") from None
    except ssl.SSLError as e:
        sock.close()
        raise ProbeError(
            "TLS: " + _clean(getattr(e, "reason", None) or "handshake failed", 40)
        ) from None


class _Conn:
    """A socket and the bytes read from it but not yet used, so a line is read whole whatever way the segments fall."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def readline(self, limit=_LINE_MAX):
        while b"\n" not in self.buf:
            if len(self.buf) >= limit:
                break
            chunk = self.sock.recv(512)
            if not chunk:
                if not self.buf:
                    raise ProbeError("the connection closed with no answer")
                break
            self.buf += chunk
        line, sep, rest = self.buf.partition(b"\n")
        if not sep and len(line) > limit:
            line, rest = line[:limit], line[limit:]
        self.buf = rest
        return line.rstrip(b"\r").decode("latin-1")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _smtp_reply(c):
    """(code, lines) of one SMTP reply. A line 'ddd-text' continues it, 'ddd text' or 'ddd' ends it."""
    lines = []
    for _ in range(_REPLY_LINES_MAX):
        line = c.readline()
        lines.append(line)
        if len(line) < 3 or not (line[:3].isascii() and line[:3].isdigit()):
            raise ProbeError("not SMTP: " + _clean(line, 40))
        if len(line) == 3 or line[3] == " ":
            return int(line[:3]), lines
    raise ProbeError("an SMTP reply that does not end")


def smtp_probe(host, port, tls="none", ctx=None, timeout=5, peer_ok=None):
    t0 = time.monotonic()
    sock = _connect(host, port, timeout, peer_ok)
    if tls == "tls":
        sock = _wrap(sock, host, ctx)
    c = _Conn(sock)
    try:
        code, lines = _smtp_reply(c)
        if code != 220:
            return False, "greeting %d %s" % (code, _clean(lines[0][4:], 40))
        greeting = _clean(lines[0][4:], 50)
        c.send(b"EHLO remotepower\r\n")
        code, ehlo = _smtp_reply(c)
        if code != 250:
            return False, "EHLO refused (%d)" % code
        used = "TLS" if tls == "tls" else ""
        if tls == "starttls":
            if not any(ln[4:].strip().upper().startswith("STARTTLS") for ln in ehlo[1:]):
                return False, "STARTTLS is not offered"
            c.send(b"STARTTLS\r\n")
            code, _ = _smtp_reply(c)
            if code != 220:
                return False, "STARTTLS refused (%d)" % code
            c.sock = _wrap(c.sock, host, ctx)
            c.buf = b""
            # the server forgets everything said before the upgrade: a second EHLO is what shows the encrypted session works
            c.send(b"EHLO remotepower\r\n")
            code, _ = _smtp_reply(c)
            if code != 250:
                return False, "no answer inside STARTTLS (%d)" % code
            used = "STARTTLS"
        try:
            c.send(b"QUIT\r\n")
        except OSError:
            pass
        return True, " · ".join(
            x for x in (greeting, used, "%dms" % int((time.monotonic() - t0) * 1000)) if x
        )
    finally:
        c.close()


def _imap_until(c, tag):
    """Lines of an IMAP answer up to and including the tagged completion; returns (ok, untagged_lines)."""
    untagged = []
    for _ in range(_REPLY_LINES_MAX):
        line = c.readline()
        if line.startswith(tag + " "):
            return line[len(tag) + 1 :].upper().startswith("OK"), untagged
        untagged.append(line)
    raise ProbeError("an IMAP answer that does not end")


def imap_probe(host, port, tls="none", ctx=None, timeout=5, peer_ok=None):
    t0 = time.monotonic()
    sock = _connect(host, port, timeout, peer_ok)
    if tls == "tls":
        sock = _wrap(sock, host, ctx)
    c = _Conn(sock)
    try:
        greeting = c.readline()
        if greeting.upper().startswith("* BYE"):
            return False, "refused: " + _clean(greeting[5:], 40)
        if not greeting.upper().startswith("* OK"):
            return False, "not IMAP: " + _clean(greeting, 40)
        c.send(b"a1 CAPABILITY\r\n")
        ok, untagged = _imap_until(c, "a1")
        caps = []
        for ln in untagged:
            if ln.upper().startswith("* CAPABILITY"):
                caps = ln.split()[2:]
        if not ok:
            return False, "CAPABILITY refused"
        used = "TLS" if tls == "tls" else ""
        if tls == "starttls":
            if not any(x.upper() == "STARTTLS" for x in caps):
                return False, "STARTTLS is not offered"
            c.send(b"a2 STARTTLS\r\n")
            ok, _ = _imap_until(c, "a2")
            if not ok:
                return False, "STARTTLS refused"
            c.sock = _wrap(c.sock, host, ctx)
            c.buf = b""
            c.send(b"a3 CAPABILITY\r\n")
            ok, _ = _imap_until(c, "a3")
            if not ok:
                return False, "no answer inside STARTTLS"
            used = "STARTTLS"
        try:
            c.send(b"a9 LOGOUT\r\n")
        except OSError:
            pass
        proto = next((_clean(x, 12) for x in caps if x.upper().startswith("IMAP4")), "IMAP")
        return True, " · ".join(
            x for x in (proto, used, "%dms" % int((time.monotonic() - t0) * 1000)) if x
        )
    finally:
        c.close()


def ssh_banner_probe(host, port, timeout=5, peer_ok=None):
    t0 = time.monotonic()
    c = _Conn(_connect(host, port, timeout, peer_ok))
    try:
        for _ in range(8):  # a server may send other lines before its identification
            line = c.readline(255)
            if line.startswith("SSH-"):
                banner = _clean(line, 80)
                if not (banner.startswith("SSH-2.0-") or banner.startswith("SSH-1.99-")):
                    return False, "not SSH 2: " + banner
                return True, "%s · %dms" % (banner, int((time.monotonic() - t0) * 1000))
        return False, "no SSH banner"
    finally:
        c.close()


def _to_ntp(ts):
    secs = int(ts)
    # the seconds field is 32 bits and wraps in February 2036 (and every 136 years after): the wrapped value is what goes on the wire
    return struct.pack(
        ">II", (secs + _NTP_EPOCH) & 0xFFFFFFFF, int((ts - secs) * (1 << 32)) & 0xFFFFFFFF
    )


def _from_ntp(b, ref=None):
    """Seconds since 1970 for an NTP timestamp. The field wraps every 136 years, so with `ref` (a time known to be near, which is this
    machine's own clock) the era is the one that puts the result closest to it; without it the first era is assumed.
    """
    secs, frac = struct.unpack(">II", b)
    unix = secs - _NTP_EPOCH + frac / float(1 << 32)
    if ref is not None:
        unix += round((ref - unix) / float(1 << 32)) * float(1 << 32)
    return unix


def ntp_probe(
    host, port, max_offset_ms=None, timeout=5, peer_ok=None, now=time.time, sock_factory=None
):
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
    chosen = None
    for family, _t, _p, _c, sa in infos:
        if peer_ok is None or peer_ok(sa[0]):
            chosen = (family, sa)
            break
    if chosen is None:
        return False, "blocked"
    family, sa = chosen
    sock = sock_factory(family) if sock_factory else socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        t1 = now()
        req = bytearray(48)
        req[0] = 0x23  # leap indicator 0, version 4, mode 3 (client)
        req[40:48] = _to_ntp(t1)
        sock.sendto(bytes(req), sa)
        data = None
        for _ in range(4):  # a stray datagram from somewhere else is not the answer
            d, addr = sock.recvfrom(1024)
            if addr[0] == sa[0] and len(d) >= 48:
                data = d
                break
        t4 = now()
    finally:
        sock.close()
    if data is None:
        return False, "no answer"
    if data[24:32] != bytes(req[40:48]):
        return False, "the reply does not match the request"
    mode, li, stratum = data[0] & 7, data[0] >> 6, data[1]
    if mode != 4:
        return False, "not a server reply (mode %d)" % mode
    if stratum == 0:
        return False, "kiss-of-death %s" % (
            _clean(data[12:16].decode("ascii", "replace"), 8) or "?"
        )
    if li == 3 or stratum >= 16:
        return False, "not synchronised (stratum %d)" % stratum
    if data[40:48] == b"\0" * 8:
        return False, "the reply carries no time"
    t2, t3 = _from_ntp(data[32:40], t1), _from_ntp(data[40:48], t1)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay = (t4 - t1) - (t3 - t2)
    detail = "stratum %d · offset %+.1f ms · delay %.0f ms" % (
        stratum,
        offset * 1000,
        max(delay, 0.0) * 1000,
    )
    if max_offset_ms is not None and abs(offset * 1000) > max_offset_ms:
        return False, "%s (limit %d ms)" % (detail, int(max_offset_ms))
    return True, detail


def _why(e):
    """A network failure in words an operator can act on."""
    if isinstance(e, socket.gaierror):
        return "the host name does not resolve"
    if isinstance(e, ConnectionRefusedError):
        return "the connection was refused"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "it did not answer in time"
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "the connection was dropped"
    text = str(e).lower()
    if "unreachable" in text or "no route" in text:
        return "the network is unreachable"
    return "the connection failed"


def run(mtype, host, port, m, peer_ok=None, ssl_ctx=None, timeout=5):
    """``(ok, detail)`` for a monitor `m` of one of TYPES. Never raises: every failure is a result."""
    tls = m.get("tls") if m.get("tls") in TLS_MODES else "none"
    try:
        if mtype == "smtp":
            return smtp_probe(host, port, tls, ssl_ctx, timeout, peer_ok)
        if mtype == "imap":
            return imap_probe(host, port, tls, ssl_ctx, timeout, peer_ok)
        if mtype == "ssh":
            return ssh_banner_probe(host, port, timeout, peer_ok)
        if mtype == "ntp":
            limit = m.get("max_offset_ms")
            limit = (
                limit
                if isinstance(limit, (int, float))
                and not isinstance(limit, bool)
                and 0 < limit <= MAX_OFFSET_MS
                else None
            )
            return ntp_probe(host, port, limit, timeout, peer_ok)
        return False, "unknown protocol check"
    except ProbeError as e:
        return False, str(e)
    except ssl.SSLError as e:
        return False, "TLS: " + _clean(getattr(e, "reason", None) or "handshake failed", 40)
    except OSError as e:
        return False, _why(e)
    except Exception:
        return False, "error"
