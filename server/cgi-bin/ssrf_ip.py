"""The ONE per-IP SSRF classifier.

Every outbound feature that resolves an operator-supplied host has to answer
the same question — "is this IP a class an SSRF attacker would aim at?" — and
until v6.4.3 five modules answered it with five hand-rolled copies:

    api._ip_class_blocked          the canonical one
    ai_provider._peer_ip_blocked   with a comment saying it cannot import api
    opnsense._peer_ip_blocked      byte-identical to routeros'
    routeros._peer_ip_blocked      byte-identical to opnsense'
    proxmox_client._peer_ip_blocked

A behavioural drift guard covered three of the five, so the two it did not
cover were free to diverge — and one had. `ai_provider` checked loopback LAST,
after the reserved test. `::1` is BOTH loopback and reserved, so with
`allow_loopback=True` — which `insecure_ssl` sets, and which exists precisely
so an operator can point the AI at a local Ollama — the reserved test fired
first and blocked it. Same configuration on `127.0.0.1` worked. A feature that
fails only on IPv6 loopback, from a copy that had lost one ordering decision
the original documents in a comment.

That is the whole argument for this module. The circular-import objection in
`ai_provider`'s comment was real about importing *api*; it is not an argument
against a leaf module with no imports beyond `ipaddress`, which everything
including api can import.

WHAT IS BLOCKED, and why each:

  link-local        169.254.0.0/16 — cloud instance metadata lives at
                    169.254.169.254 on AWS, GCP, Azure, DigitalOcean, Hetzner
  unspecified       0.0.0.0 / :: — resolves to localhost on most stacks
  multicast         amplification, and never a legitimate HTTP target
  reserved          the IETF-reserved space, a grab-bag worth refusing
  loopback          only when the caller says so — see below
  cloud metadata    fd00:ec2::254 (AWS IMDS over IPv6), 100.100.100.200
                    (Alibaba), 192.0.0.192 (Oracle legacy). None of these is
                    link-local, so `is_link_local` alone misses all three.

WHAT IS DELIBERATELY ALLOWED: RFC1918 private ranges. This is a fleet-
management product whose entire job is reaching LAN hosts; blocking 10/8 would
block the product. That is a considered decision, not an oversight.

IPv6 UNWRAPPING: an IPv4 target can be smuggled past every v6 check by
wrapping it — v4-mapped (`::ffff:169.254.169.254`), 6to4 (`2002:a9fe:a9fe::`)
or the NAT64 well-known prefix (`64:ff9b::a9fe:a9fe`). Each is unwrapped and
the inner v4 re-classified.
"""
import ipaddress

# Cloud instance-metadata endpoints that `is_link_local` does NOT catch.
METADATA_IPS = frozenset({
    'fd00:ec2::254',        # AWS IMDS over IPv6 (ULA)
    '100.100.100.200',      # Alibaba Cloud
    '192.0.0.192',          # Oracle Cloud (legacy)
})

_NAT64_PREFIX = 0x0064ff9b << 64


def unwrap(ip):
    """Re-classify the inner IPv4 of a v6 address that embeds one.

    PUBLIC because it is policy-free: which classes you then block is a
    per-feature decision, but "what address is this really" is not. tls_monitor
    deliberately allows loopback and RFC1918 (probing an internal host's cert is
    the feature) and so cannot use blocked() — but it had hand-rolled this
    unwrapping and the METADATA_IPS set alongside it, which is the half most
    likely to drift, and the half an attacker probes.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return ip
    inner = ip.ipv4_mapped or ip.sixtofour
    if inner is None and (int(ip) >> 32) == _NAT64_PREFIX:
        inner = ipaddress.IPv4Address(int(ip) & 0xffffffff)
    return inner if inner is not None else ip


def block_reason(ip_str, allow_loopback=False):
    """The human-readable class name for a blocked IP, or None if allowed.

    This is the PRIMARY implementation and `blocked` is derived from it, so the
    two can never disagree. api.py used to carry a second copy of the whole
    ladder for the message text, under a docstring asking whoever touched it to
    "keep the two in step" — an instruction to a human is not a mechanism, and
    the identical arrangement between api and ai_provider is what drifted.
    """
    ip = unwrap(ipaddress.ip_address(ip_str))
    if str(ip) in METADATA_IPS:
        return 'a cloud instance-metadata address'
    if ip.is_loopback:
        return None if allow_loopback else 'a loopback address'
    if ip.is_link_local:
        return 'a link-local / cloud-metadata address'
    if ip.is_unspecified:
        return ('the unspecified address 0.0.0.0 (a filtering resolver such as '
                'Pi-hole or AdGuard answers this way for a blocked domain)')
    if ip.is_multicast:
        return 'a multicast address'
    if ip.is_reserved:
        return 'a reserved address'
    return None


def blocked(ip_str, allow_loopback=False):
    """True when this IP is a class an SSRF attacker would target.

    Raises ValueError on an unparseable address — the caller decides what an
    unreadable peer means. The connect-time peer checks treat it as "not
    blocked" because the string came from `getpeername()` and a failure to
    parse it is a bug in us, not an attack; the pre-flight DNS checks let it
    propagate. Both behaviours are preserved by their own wrappers rather than
    being baked in here.

    `allow_loopback` is decided FIRST and deliberately: `::1` is loopback AND
    reserved, so testing reserved first blocks a loopback target the caller
    explicitly permitted. That single ordering is what one of the five copies
    had lost.
    """
    return block_reason(ip_str, allow_loopback) is not None


def peer_blocked(ip_str, allow_loopback=False):
    """`blocked`, but an unparseable address is not blocked.

    For connect-time peer re-validation, where `ip_str` came from
    `getpeername()`. A value we cannot parse there is our own bug, and failing
    closed on it would break every connection rather than any attack.
    """
    try:
        return blocked(ip_str, allow_loopback)
    except ValueError:
        return False
