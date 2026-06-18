#!/usr/bin/env python3
"""Live DNS resolution helpers for the Admin → DNS dashboard.

v4.9.0 "ResolutionMatters". Pure functions over dnspython that let the dashboard
show what a name *actually* resolves to — provider/zone state vs. reality —
and how far a recent edit has propagated:

  * resolve_public(name, type)        -> answers from a vetted set of public
                                         recursive resolvers (1.1.1.1, 8.8.8.8, …)
  * resolve_authoritative(name, type) -> answers straight from the zone's own
                                         authoritative nameservers
  * propagation(name, type, expected) -> how many public resolvers already serve
                                         the expected value ("propagated X/N")

SSRF posture: callers NEVER pass a resolver IP. Lookups target the fixed
PUBLIC_RESOLVERS allowlist, or authoritative-NS IPs we derive from the zone with
private / loopback / link-local / multicast / reserved addresses filtered out.
The query NAME is validated as a hostname and the TYPE against RECORD_TYPES.
DNS queries are port-53 UDP/TCP and return only DNS records.

The resolver factory is injectable (``_resolver_factory``) so the logic is
unit-testable without real DNS.
"""

import ipaddress
import re

# Vetted public recursive resolvers (label, IP). Used both for the side-by-side
# "what the world sees" view and the propagation checker.
PUBLIC_RESOLVERS = (
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
)

# Record types the dashboard can resolve.
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR")

# Hostname per RFC 1123 (labels 1-63, total ≤253), trailing dot allowed, and we
# permit '_' for service/DKIM names like _dmarc / _acme-challenge.
_HOSTNAME_RX = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)" r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$"
)

# Bound the work per request so the dashboard can't be turned into a DNS
# amplification / scanning tool.
DEFAULT_TIMEOUT = 3.0
MAX_NS = 6


def valid_name(name):
    return isinstance(name, str) and bool(_HOSTNAME_RX.match(name.strip()))


def valid_type(rtype):
    return isinstance(rtype, str) and rtype.strip().upper() in RECORD_TYPES


def _blocked_ip(ip):
    """True for addresses an authoritative NS must not point at (SSRF guard)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        a.is_private
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )


def _resolver_at(ip, timeout):
    """A dnspython resolver pinned to one nameserver IP (no system config)."""
    import dns.resolver

    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ip]
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _answers(res, name, rtype):
    """Run one query, normalise to {'answers': [...], 'error': str|None}."""
    import dns.exception
    import dns.resolver

    try:
        ans = res.resolve(name, rtype, raise_on_no_answer=False)
        rr = ans.rrset
        out = [r.to_text() for r in rr] if rr is not None else []
        return {"answers": sorted(out), "error": None}
    except dns.resolver.NXDOMAIN:
        return {"answers": [], "error": "NXDOMAIN"}
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        return {"answers": [], "error": "SERVFAIL"}
    except dns.exception.Timeout:
        return {"answers": [], "error": "timeout"}
    except Exception as e:  # noqa: BLE001 — report, don't crash
        return {"answers": [], "error": str(e)[:80] or "error"}


def resolve_at(name, rtype, resolver_ip, timeout=DEFAULT_TIMEOUT, _resolver_factory=None):
    """Resolve name/type at a single resolver IP."""
    factory = _resolver_factory or _resolver_at
    return _answers(factory(resolver_ip, timeout), name.strip(), rtype.strip().upper())


def resolve_public(name, rtype, timeout=DEFAULT_TIMEOUT, _resolver_factory=None):
    """Resolve name/type at every vetted public resolver."""
    out = []
    for label, ip in PUBLIC_RESOLVERS:
        r = resolve_at(name, rtype, ip, timeout, _resolver_factory)
        out.append({"resolver": label, "ip": ip, **r})
    return out


def authoritative_ns(name, timeout=DEFAULT_TIMEOUT, _resolver_factory=None):
    """Discover the zone's authoritative NS (name + public IP), walking up labels.

    Uses a public resolver to find the closest enclosing zone with NS records,
    then resolves each NS hostname to an A address (private/blocked IPs dropped).
    Returns a list of {'ns': hostname, 'ip': addr}."""
    factory = _resolver_factory or _resolver_at
    pub = factory(PUBLIC_RESOLVERS[0][1], timeout)
    labels = name.strip().rstrip(".").split(".")
    ns_names = []
    for i in range(len(labels) - 1):  # never query the bare TLD's root
        zone = ".".join(labels[i:])
        r = _answers(pub, zone, "NS")
        if r["answers"]:
            ns_names = [a.rstrip(".") for a in r["answers"]]
            break
    out = []
    for ns in ns_names[:MAX_NS]:
        a = _answers(pub, ns, "A")
        for ip in a["answers"]:
            if not _blocked_ip(ip):
                out.append({"ns": ns, "ip": ip})
                break
    return out


def resolve_authoritative(name, rtype, timeout=DEFAULT_TIMEOUT, _resolver_factory=None):
    """Resolve name/type directly at the zone's authoritative nameservers."""
    nss = authoritative_ns(name, timeout, _resolver_factory)
    out = []
    for ns in nss:
        r = resolve_at(name, rtype, ns["ip"], timeout, _resolver_factory)
        out.append({"ns": ns["ns"], "ip": ns["ip"], **r})
    return out


def _matches(rec, expected):
    """Whether one resolver result counts as 'has the expected value'."""
    if rec["error"]:
        return False
    if expected:
        exp = expected.strip().lower()
        return any(exp in a.lower() for a in rec["answers"])
    return bool(rec["answers"])


def propagation(name, rtype, expected=None, timeout=DEFAULT_TIMEOUT, _resolver_factory=None):
    """Poll public resolvers; count how many already serve the expected value
    (substring match) or, when no expected value is given, any answer at all."""
    results = resolve_public(name, rtype, timeout, _resolver_factory)
    tagged = [{**r, "match": _matches(r, expected)} for r in results]
    return {
        "resolvers": tagged,
        "propagated": sum(1 for r in tagged if r["match"]),
        "total": len(tagged),
    }
