"""
RemotePower TLS expiry monitor — v1.11.0.

Probes a configured list of (hostname, port) pairs from the server's
network position and records when each certificate expires. Optionally
checks DNS resolution at the same time. Wired into the existing webhook
plumbing so users can be alerted at configurable warn/critical
thresholds.

This module is server-side only. The probe runs from a cron'd helper
script (``remotepower-tls-check`` in the cgi-bin directory, or from a
manual ``POST /api/tls/scan`` button) — it does NOT run inside the
CGI request because TCP+TLS handshakes against many hosts can take
30+ seconds and CGI is for fast responses.

Design choices:
  - Uses :mod:`ssl` from the standard library for the handshake. No
    extra dependency; ``cryptography`` is already a dependency for the
    CMDB vault but we don't need it here.
  - Verifies the cert against the system trust store but does NOT fail
    on verification errors — those become a recorded result with a
    ``verify_error`` field so the user can see "the cert chain is
    broken" alongside "expires in N days".
  - DNS check is a single ``getaddrinfo`` call and stores the resolved
    addresses for context.
  - Probe timeout is intentionally short (5s connect, 5s handshake) so
    a single dead host can't hold up the whole batch.

Storage:
  - ``tls_targets.json`` — the user-configured watchlist
  - ``tls_results.json`` — last probe result per target

Both files are flat dicts keyed by an opaque target ID. Same shape as
the rest of the project's storage.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any

# Probe knobs. 5+5s is generous — Cloudflare-fronted hosts respond in
# well under a second; the timeout exists for the unreachable case.
CONNECT_TIMEOUT_S = 5.0
HANDSHAKE_TIMEOUT_S = 5.0


def _now() -> int:
    """Wrapper for testability."""
    return int(time.time())


# Supported STARTTLS protocols. Order matters — "auto" maps to one of the
# others based on the port number; the caller passes "auto" by default and
# we resolve to a concrete value in parse_target.
STARTTLS_PROTOCOLS = ("none", "auto", "smtp", "imap", "pop3", "ldap")

# Port → protocol auto-detection. Anything not in this map gets ``none``
# (direct TLS, the v1.11.0 behaviour). Multiple SMTP submission ports
# are mapped because the wild contains 587 (RFC 6409), 25 (legacy MTA-MTA
# upgrade), and 2525 (some hosts that block 25).
_PORT_TO_STARTTLS = {
    25:   "smtp",
    587:  "smtp",
    2525: "smtp",
    143:  "imap",
    110:  "pop3",
    389:  "ldap",
}


def parse_target(spec: Any) -> dict | None:
    """Validate and normalise a user-supplied watchlist entry.

    Args:
        spec: Dict with at minimum ``host`` and optionally ``port``,
            ``label``, ``warn_days``, ``crit_days``, ``connect_address``,
            ``dane_check``, and ``starttls``.

    Returns:
        Normalised dict, or ``None`` if the input is unusable.

    Optional fields (added in v1.11.2):
        connect_address: An IPv4/IPv6 literal or hostname to connect to,
            instead of resolving ``host`` via DNS. Useful for probing
            internal certs by IP while sending the real SNI in the
            handshake. Empty / None means "use ``host`` as the connect
            target" (the v1.11.0 behaviour).
        dane_check: When True, look up DANE/TLSA records via DNSSEC and
            check the cert against them.

    Optional fields (added in v1.11.3):
        starttls: One of ``none``, ``auto``, ``smtp``, ``imap``, ``pop3``,
            ``ldap``. ``none`` means immediate TLS (HTTPS, IMAPS, etc).
            ``auto`` infers from the port number. Anything else picks the
            specific STARTTLS protocol regardless of port.
    """
    if not isinstance(spec, dict):
        return None
    host = str(spec.get("host", "")).strip().lower()
    if not host or len(host) > 255:
        return None
    # Reject anything obviously not a hostname or IP. We allow alphanumerics,
    # dots, hyphens, colons (for IPv6), and slashes are forbidden so a sneaky
    # input can't escape the host slot in an alert message.
    if any(c.isspace() or c in "/\\\"'<>" for c in host):
        return None
    try:
        port = int(spec.get("port", 443))
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    label = str(spec.get("label", "")).strip()[:128]
    try:
        warn_days = int(spec.get("warn_days", 14))
        crit_days = int(spec.get("crit_days", 3))
    except (TypeError, ValueError):
        warn_days, crit_days = 14, 3
    warn_days = max(0, min(warn_days, 365))
    crit_days = max(0, min(crit_days, warn_days))

    # v1.11.2: optional connect_address override. Same charset rules as
    # ``host``; empty/None becomes "" which the prober interprets as
    # "use host as the connect target."
    raw_addr = spec.get("connect_address")
    if raw_addr is None or raw_addr == "":
        connect_address = ""
    else:
        connect_address = str(raw_addr).strip().lower()
        if not connect_address or len(connect_address) > 255:
            return None
        if any(c.isspace() or c in "/\\\"'<>" for c in connect_address):
            return None

    dane_check = bool(spec.get("dane_check", False))

    # v1.11.3: STARTTLS protocol selection. Default ``auto`` so existing
    # targets at port 25/587/143/etc. start working without re-saving.
    raw_starttls = spec.get("starttls", "auto")
    starttls = str(raw_starttls).strip().lower() if raw_starttls else "auto"
    if starttls not in STARTTLS_PROTOCOLS:
        return None
    # Resolve "auto" to a concrete value so the prober has nothing
    # to second-guess. Unknown ports → "none" (direct TLS).
    if starttls == "auto":
        starttls = _PORT_TO_STARTTLS.get(port, "none")

    return {
        "host": host,
        "port": port,
        "label": label,
        "warn_days": warn_days,
        "crit_days": crit_days,
        "connect_address": connect_address,
        "dane_check": dane_check,
        "starttls": starttls,
    }


def _resolve_dns(host: str) -> tuple[list[str], str]:
    """Return (addresses, error). Empty error string on success."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        return addrs, ""
    except socket.gaierror as e:
        return [], f"DNS lookup failed: {e}"
    except Exception as e:  # noqa: BLE001 — we want to never crash
        return [], f"DNS error: {e}"


def _parse_cert_der(der: bytes) -> dict:
    """Parse DER-encoded cert into a dict of fields we care about.

    Uses ``cryptography`` (already a dependency for the CMDB vault). We
    use it here rather than parsing the dict that ``ssl.getpeercert()``
    returns because the latter only populates that dict when
    verification is enabled — and we deliberately disable verification
    on the first pass so we can capture the cert from misconfigured
    hosts. Parsing the DER ourselves works regardless of verify mode.
    """
    if not der:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes  # noqa: F401
    except ImportError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return {}

    out: dict = {}
    # Expiry — use UTC; not_valid_after_utc is the modern attribute,
    # not_valid_after the deprecated one. Try the new one first.
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after
    try:
        out["expires_at"] = int(not_after.timestamp())
    except Exception:  # noqa: BLE001
        out["expires_at"] = 0

    # Issuer / subject as RFC 4514 strings — clean and stable
    try:
        out["issuer"] = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        out["issuer"] = ""
    try:
        out["subject"] = cert.subject.rfc4514_string()
    except Exception:  # noqa: BLE001
        out["subject"] = ""

    # SAN: pull DNS entries
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out["san"] = list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:  # noqa: BLE001 — extension absent or parse error
        out["san"] = []

    return out


# v1.11.3: STARTTLS upgrade helpers. Each function takes an already-connected
# socket and drives the plaintext handshake required to upgrade to TLS for
# its protocol. Returns the same socket (now ready to be wrap_socket'd) on
# success, or raises an OSError / TimeoutError / RuntimeError on failure.
#
# We deliberately keep these tiny — they handle the success path and a
# couple of common failure modes, nothing more. The full quirks of every
# mail server are not our concern here; we just need to get to the TLS
# handshake.


def _read_until(sock, terminator: bytes, max_bytes: int = 8192) -> bytes:
    """Read from ``sock`` until ``terminator`` appears or buffer fills.

    Used by line-oriented STARTTLS protocols (SMTP/IMAP/POP3) where the
    server's reply is delimited by CRLF. Bounded so a misbehaving server
    can't make us read forever.
    """
    buf = b""
    while terminator not in buf and len(buf) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _starttls_smtp(sock, host: str) -> None:
    """Drive an SMTP STARTTLS exchange.

    ``EHLO`` first, expect 250, send ``STARTTLS``, expect 220. Anything
    else raises ``RuntimeError`` with the actual server reply for
    diagnostics.
    """
    # Banner — server sends the 220 greeting first
    banner = _read_until(sock, b"\r\n")
    if not banner.startswith(b"220"):
        raise RuntimeError(f"unexpected SMTP banner: {banner[:80]!r}")
    # EHLO — most servers want a hostname here. We pass the SNI as a
    # reasonable default; some pedantic servers reject EHLO from an IP
    # but we don't have a better option without running a hostname
    # lookup of our own outbound IP, which is too much.
    sock.sendall(b"EHLO " + host.encode("ascii", "ignore") + b"\r\n")
    reply = _read_until(sock, b"\r\n", max_bytes=16384)
    if not reply.startswith(b"250"):
        raise RuntimeError(f"SMTP EHLO refused: {reply[:120]!r}")
    sock.sendall(b"STARTTLS\r\n")
    reply = _read_until(sock, b"\r\n")
    if not reply.startswith(b"220"):
        raise RuntimeError(f"SMTP STARTTLS refused: {reply[:120]!r}")


def _starttls_imap(sock, host: str) -> None:
    """Drive an IMAP STARTTLS exchange.

    Server sends the OK greeting; we send ``A001 STARTTLS`` and expect
    ``A001 OK``.
    """
    banner = _read_until(sock, b"\r\n")
    if b"OK" not in banner.upper():
        raise RuntimeError(f"unexpected IMAP banner: {banner[:80]!r}")
    sock.sendall(b"A001 STARTTLS\r\n")
    reply = _read_until(sock, b"\r\n")
    if b"A001 OK" not in reply.upper():
        raise RuntimeError(f"IMAP STARTTLS refused: {reply[:120]!r}")


def _starttls_pop3(sock, host: str) -> None:
    """Drive a POP3 STLS exchange.

    Server sends ``+OK`` greeting; we send ``STLS`` and expect ``+OK``.
    """
    banner = _read_until(sock, b"\r\n")
    if not banner.startswith(b"+OK"):
        raise RuntimeError(f"unexpected POP3 banner: {banner[:80]!r}")
    sock.sendall(b"STLS\r\n")
    reply = _read_until(sock, b"\r\n")
    if not reply.startswith(b"+OK"):
        raise RuntimeError(f"POP3 STLS refused: {reply[:120]!r}")


def _starttls_ldap(sock, host: str) -> None:
    """Drive an LDAP StartTLS extended request.

    Builds a minimal LDAPv3 ExtendedRequest with OID 1.3.6.1.4.1.1466.20037
    using BER encoding. We don't pull in `ldap3` — for one upgrade message
    the encoding is short enough to hand-write, and this avoids adding a
    runtime dependency.

    The bytes below were generated by `ldap3.protocol.rfc4511` on a known-
    good install and verified against `openssl s_client -starttls ldap`.
    Don't edit them.
    """
    # MessageID 1, ExtendedRequest, OID 1.3.6.1.4.1.1466.20037, no value
    msg = bytes.fromhex(
        "30"        # SEQUENCE
        "1d"        # length 29
        "02 01 01"  # MessageID = 1
        "77 18"     # [APPLICATION 23] ExtendedRequest, length 24
        "80 16"     # [0] requestName, length 22
        "312e332e362e312e342e312e313436362e3230303337"  # ASCII OID
        .replace(" ", "")
    )
    sock.sendall(msg)
    # Response: SEQUENCE { messageID, ExtendedResponse { resultCode, ... } }
    # We just look at the resultCode byte. A success is enumerated 0; any
    # other value means the server refused.
    resp = b""
    deadline_chunks = 0
    while len(resp) < 32 and deadline_chunks < 4:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        deadline_chunks += 1
    # The structure is variable-length, but the resultCode appears just
    # after the application tag at offset >= 9. Look for ENUMERATED 0 (0a 01 00).
    if b"\x0a\x01\x00" not in resp[:64]:
        raise RuntimeError(f"LDAP StartTLS refused: {resp[:80]!r}")


def _do_starttls(sock, protocol: str, host: str) -> None:
    """Dispatch to the appropriate STARTTLS handler.

    ``protocol="none"`` is a no-op — caller is doing direct TLS.
    Unknown protocols raise so we don't silently fall through to direct
    TLS on a port that needs the upgrade.
    """
    if protocol == "none":
        return
    handlers = {
        "smtp": _starttls_smtp,
        "imap": _starttls_imap,
        "pop3": _starttls_pop3,
        "ldap": _starttls_ldap,
    }
    handler = handlers.get(protocol)
    if handler is None:
        raise RuntimeError(f"unknown STARTTLS protocol: {protocol}")
    handler(sock, host)


def _probe_tls(host: str, port: int, connect_address: str = "",
               starttls: str = "none") -> dict:
    """Connect, do TLS handshake, return parsed cert details.

    Catches every exception we can think of and turns them into a
    structured result. Never raises — the caller stores whatever we
    return as the "last probe" for that target.

    Args:
        host: The hostname for SNI and (when no override) the DNS lookup.
        port: TCP port.
        connect_address: Optional override — connect to this address
            instead of resolving ``host``. ``host`` is still sent as the
            SNI in the handshake. Useful when:
              - DNS doesn't resolve ``host`` from the server's network
              - You want to probe a specific IP behind a load balancer
              - The cert's CN/SAN names a host that doesn't resolve from
                the server (internal cert with public-style names)

    Returns:
        A dict with all the keys the UI consumes; never raises.
    """
    # Pick the actual address to connect to. If ``connect_address`` is set
    # we use it directly; otherwise we resolve ``host`` via DNS as before.
    target_for_dns = connect_address if connect_address else host
    addrs, dns_err = _resolve_dns(target_for_dns)
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "connect_address": connect_address,
        "starttls": starttls or "none",
        "checked_at": _now(),
        "addresses": addrs,
        "dns_error": dns_err,
        "tls_error": "",
        "verify_error": "",
        "expires_at": 0,
        "issuer": "",
        "subject": "",
        "san": [],
        # v1.11.2: hostname-vs-cert match is now reported separately from
        # full chain verification because users probing by IP routinely
        # have a working cert that just doesn't match the connect target.
        "hostname_match": None,    # True / False / None (not checked)
        # DANE fields populated by _check_dane() when enabled
        "dane_status": "not_checked",
        "dane_records": [],
        "dane_error": "",
    }
    if dns_err:
        return result

    # First pass: capture the cert with verification disabled so we get
    # the cert even from misconfigured hosts (wrong hostname, expired,
    # internal CA, etc.). Parse the DER ourselves — the dict-form
    # output of ``ssl.getpeercert()`` is empty when CERT_NONE is set.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = None
    der = b""
    try:
        # Connect to ``target_for_dns`` (which is connect_address if set,
        # else host). SNI is always the original ``host`` so the server
        # serves the right cert.
        sock = socket.create_connection((target_for_dns, port), timeout=CONNECT_TIMEOUT_S)
        sock.settimeout(HANDSHAKE_TIMEOUT_S)
        # v1.11.3: drive STARTTLS upgrade if requested. ``none`` is a no-op.
        # Errors here become tls_error so they stand out from "the server
        # did TLS but the cert is bad."
        if starttls and starttls != "none":
            try:
                _do_starttls(sock, starttls, host)
            except (RuntimeError, OSError) as e:
                result["tls_error"] = f"{starttls.upper()} STARTTLS failed: {e}"
                return result
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True) or b""
    except (socket.timeout, TimeoutError):
        result["tls_error"] = "connect/handshake timed out"
        return result
    except ssl.SSLError as e:
        result["tls_error"] = f"TLS error: {e}"
        return result
    except OSError as e:
        result["tls_error"] = f"connection failed: {e}"
        return result
    except Exception as e:  # noqa: BLE001
        result["tls_error"] = f"unexpected error: {e}"
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

    parsed = _parse_cert_der(der)
    result["expires_at"] = parsed.get("expires_at", 0)
    result["issuer"] = parsed.get("issuer", "")
    result["subject"] = parsed.get("subject", "")
    result["san"] = parsed.get("san", [])

    # v1.11.2: hostname match is its own check. Useful when probing by IP —
    # the cert may be perfectly valid, just bound to a different name.
    result["hostname_match"] = _hostname_matches_cert(host, parsed)

    # Stash the DER for the caller — used by DANE comparison if requested.
    # Not exposed in the API response (it's binary).
    result["_der"] = der

    # Second pass: verify against the system trust store. Errors here
    # become ``verify_error`` rather than ``tls_error`` so an internal
    # CA looks different from a broken cert chain.
    verify_ctx = ssl.create_default_context()
    sock2 = None
    try:
        sock2 = socket.create_connection((target_for_dns, port), timeout=CONNECT_TIMEOUT_S)
        sock2.settimeout(HANDSHAKE_TIMEOUT_S)
        # v1.11.3: same STARTTLS upgrade for the verification probe.
        # Without this we'd be doing a direct-TLS handshake on the SMTP
        # port, which would fail with garbage and obscure the actual
        # verify result.
        if starttls and starttls != "none":
            try:
                _do_starttls(sock2, starttls, host)
            except (RuntimeError, OSError):
                # First pass already caught this; don't override its
                # tls_error with a duplicate. The second-pass failure is
                # a consequence of the same problem.
                pass
            else:
                with verify_ctx.wrap_socket(sock2, server_hostname=host) as tls:
                    tls.getpeercert()
        else:
            with verify_ctx.wrap_socket(sock2, server_hostname=host) as tls:
                tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        result["verify_error"] = f"verification failed: {e.verify_message}"
    except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
        # Already captured in tls_error above; verification probe is best-effort
        pass
    except Exception as e:  # noqa: BLE001
        result["verify_error"] = f"verify error: {e}"
    finally:
        if sock2 is not None:
            try:
                sock2.close()
            except Exception:  # noqa: BLE001
                pass

    return result


def _hostname_matches_cert(host: str, parsed: dict) -> bool:
    """Return True if ``host`` matches any of the cert's SANs or CN.

    Wildcard handling: ``*.example.com`` matches ``foo.example.com`` but
    not ``example.com`` itself, per RFC 6125. Compares case-insensitively.
    """
    if not parsed:
        return False
    candidates = list(parsed.get("san") or [])
    # Fall back to the CN if there are no SANs (legacy certs).
    if not candidates:
        subject = parsed.get("subject", "")
        # subject is "CN=foo.example.com,O=..." — extract the CN
        for part in subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                candidates.append(part[3:])
                break
    h = host.lower()
    for name in candidates:
        n = (name or "").lower()
        if not n:
            continue
        if n == h:
            return True
        if n.startswith("*.") and "." in h:
            # Wildcard matches exactly one label
            if h.split(".", 1)[1] == n[2:]:
                return True
    return False


def _check_dane(host: str, port: int, der: bytes) -> dict:
    """Look up DANE/TLSA records and compare against the live cert.

    Returns a dict with three keys:
        - status:   "ok" / "missing" / "insecure" / "mismatch" / "error"
        - records:  list of {usage, selector, matching_type, data} dicts
        - error:    human-readable error string (empty when status is
                    a clean state)

    Status meanings:
        ok        — at least one TLSA record matches the live cert
        missing   — no TLSA records published (not configured)
        insecure  — records exist but DNSSEC validation failed; we
                    deliberately refuse to trust them. DANE without
                    DNSSEC is theatre.
        mismatch  — records exist and validate but none match the cert
        error     — DNS lookup failed or some other unexpected condition

    Requires ``dnspython``. Returns ``status="error"`` if it's missing.
    """
    out = {"status": "error", "records": [], "error": ""}
    try:
        import dns.resolver
        import dns.flags
        import dns.exception
    except ImportError:
        out["error"] = "dnspython not installed (pip install dnspython)"
        return out

    qname = f"_{port}._tcp.{host}"
    try:
        # Request DNSSEC validation explicitly. We check the AD (Authentic
        # Data) flag in the response — if it's not set, the resolver
        # didn't validate, and we treat the records as untrusted.
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        answer = resolver.resolve(qname, "TLSA", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        out["status"] = "missing"
        return out
    except dns.resolver.NoAnswer:
        out["status"] = "missing"
        return out
    except dns.exception.Timeout:
        out["error"] = "DNS lookup timed out"
        return out
    except Exception as e:  # noqa: BLE001
        out["error"] = f"DNS lookup failed: {e}"
        return out

    if not answer.rrset or len(answer.rrset) == 0:
        out["status"] = "missing"
        return out

    # Check the AD flag on the response. Without it, the records aren't
    # DNSSEC-validated and we won't trust them.
    ad_set = bool(answer.response.flags & dns.flags.AD)
    if not ad_set:
        out["status"] = "insecure"
        out["error"] = "TLSA records found but DNSSEC validation failed"
        # Still surface them so the user can see what was published
        for rdata in answer.rrset:
            out["records"].append(_serialise_tlsa(rdata))
        return out

    records = []
    matched = False
    for rdata in answer.rrset:
        rec = _serialise_tlsa(rdata)
        records.append(rec)
        if _tlsa_matches_cert(rec, der):
            matched = True
    out["records"] = records
    out["status"] = "ok" if matched else "mismatch"
    return out


def _serialise_tlsa(rdata: Any) -> dict:
    """Convert a dnspython TLSA rdata to a JSON-serialisable dict."""
    try:
        return {
            "usage":         int(rdata.usage),
            "selector":      int(rdata.selector),
            "matching_type": int(rdata.mtype),
            "data":          rdata.cert.hex() if isinstance(rdata.cert, bytes) else str(rdata.cert),
        }
    except AttributeError:
        # Defensive — older / different dnspython API
        return {"usage": 0, "selector": 0, "matching_type": 0, "data": str(rdata)}


def _tlsa_matches_cert(rec: dict, der: bytes) -> bool:
    """Compare one TLSA record against a cert's DER bytes.

    Handles selector 0 (full cert) and 1 (SubjectPublicKeyInfo) and
    matching_type 0 (exact), 1 (SHA-256), 2 (SHA-512). Doesn't yet
    walk the certificate chain to check end-entity vs CA constraints
    (``usage`` field) — that requires capturing the full chain during
    the handshake which is fiddly and rarely matters for homelab
    use cases. We just compare against the leaf cert.
    """
    if not der or not rec:
        return False
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        return False
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return False

    selector = rec.get("selector", 0)
    if selector == 0:
        # Full cert
        material = der
    elif selector == 1:
        # SubjectPublicKeyInfo
        try:
            material = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:  # noqa: BLE001
            return False
    else:
        return False  # unknown selector

    matching = rec.get("matching_type", 0)
    if matching == 0:
        digest = material
    elif matching == 1:
        h = hashes.Hash(hashes.SHA256())
        h.update(material)
        digest = h.finalize()
    elif matching == 2:
        h = hashes.Hash(hashes.SHA512())
        h.update(material)
        digest = h.finalize()
    else:
        return False  # unknown matching_type

    expected = rec.get("data", "")
    if isinstance(expected, str):
        try:
            expected_bytes = bytes.fromhex(expected)
        except ValueError:
            return False
    else:
        expected_bytes = expected

    return digest == expected_bytes


def _flatten_dn(dn: Any) -> str:
    """Flatten a Python ssl-style DN (tuple of tuples) to a string.

    Kept for backward compatibility with older callers that may still
    pass ssl-dict-style DNs. The current probe path uses
    :func:`_parse_cert_der` which produces RFC 4514 strings directly.
    """
    if not dn:
        return ""
    parts = []
    try:
        for rdn in dn:
            for k, v in rdn:
                parts.append(f"{k}={v}")
    except (TypeError, ValueError):
        return ""
    return ", ".join(parts)


def status_for(result: dict, warn_days: int, crit_days: int) -> str:
    """Return 'critical' / 'warning' / 'ok' / 'error' for a probe result.

    'error' covers both DNS failures and TLS errors — the caller usually
    wants to surface those as red regardless of expiry.
    """
    if result.get("dns_error") or result.get("tls_error"):
        return "error"
    expires = result.get("expires_at", 0)
    if not expires:
        return "error"
    days_left = (expires - _now()) / 86400.0
    if days_left <= crit_days:
        return "critical"
    if days_left <= warn_days:
        return "warning"
    return "ok"


def days_until_expiry(result: dict) -> int:
    """Return integer days until the cert expires; negative if expired."""
    expires = result.get("expires_at", 0)
    if not expires:
        return 0
    return int((expires - _now()) / 86400.0)


def probe_all(targets: dict) -> dict:
    """Run probes for every target. Returns a results dict keyed by target id.

    Args:
        targets: Mapping of ``target_id -> {host, port, connect_address?,
            dane_check?, ...}``.

    Returns:
        Mapping of ``target_id -> result dict``. Every input target
        gets a result entry, even if the probe failed.
    """
    out: dict[str, dict] = {}
    for tid, spec in targets.items():
        if not isinstance(spec, dict):
            continue
        host = spec.get("host")
        if not host:
            continue
        port = int(spec.get("port", 443))
        connect_address = spec.get("connect_address", "") or ""
        starttls = spec.get("starttls", "none") or "none"
        result = _probe_tls(host, port,
                            connect_address=connect_address,
                            starttls=starttls)

        # DANE check is independent of TLS handshake success — we always
        # try if requested, because the DNS lookup tells us something
        # useful even if the host is unreachable. We pass the DER bytes
        # we captured (might be empty if TLS failed); the DANE checker
        # just won't find a cert match in that case but will still
        # surface the published records.
        if spec.get("dane_check"):
            der = result.pop("_der", b"")
            dane = _check_dane(host, port, der)
            result["dane_status"] = dane["status"]
            result["dane_records"] = dane["records"]
            result["dane_error"] = dane["error"]
        else:
            # Strip the internal-only DER field
            result.pop("_der", None)

        out[tid] = result
    return out
