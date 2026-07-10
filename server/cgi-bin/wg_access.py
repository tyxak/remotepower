"""WG Access — pure helpers for the road-warrior WireGuard feature (v5.2.0).

Like integrations.py / dns_zones.py, this module is PURE (stdlib only, no api
globals, no privileged I/O). api.py owns the privileged orchestration (invoking
the root `remotepower-wg-apply` helper via scoped sudo) and the storage/handlers;
this module owns the things worth unit-testing without root or a network:

  * strict validation of every field that reaches the helper (pubkey / iface /
    port / CIDR / address) — the helper re-validates, this is defence in depth;
  * address-pool + interface + port + client-IP allocation;
  * the AllowedIPs a client gets for a tunnel's flags (dashboard / fleet /
    internet), and the reach CIDRs the hub firewalls to;
  * building the structured sync-spec the helper consumes, and parsing the
    `wg show <iface> dump` output back into per-client stats.

NO secrets live here. Client private keys are generated in the browser and never
reach the server; the hub private key is generated + held root-only by the helper.
"""

import ipaddress
import re

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_TUNNELS = 32
MAX_CLIENTS_PER_TUNNEL = 250
MAX_NAME_LEN = 64

# Default allocation bases (overridable via config). Each tunnel gets its own
# /24 carved from 10.97.0.0/16, its own interface rp-wgN, its own UDP port.
POOL_BASE = "10.97.0.0/16"
PORT_BASE = 51820
PORT_SPAN = 256  # ports 51820..52075

# A WireGuard public key is 32 bytes base64 → 43 chars + '=' padding.
_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_IFACE_RE = re.compile(r"^rp-wg(\d{1,3})$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._\-]{0,63}$")

# Handshake newer than this (seconds) ⇒ "connected".
CONNECTED_WINDOW_S = 180


# ── Validation ─────────────────────────────────────────────────────────────────
def valid_pubkey(s) -> bool:
    return isinstance(s, str) and bool(_PUBKEY_RE.match(s))


def valid_psk(s) -> bool:
    """docs/master-improvement-scoping-internal.md #86: a WireGuard preshared
    key is the identical format as a public key (32 random bytes, base64,
    44 chars incl. padding) -- same regex, distinct name for readability at
    call sites."""
    return valid_pubkey(s)


def valid_iface(s) -> bool:
    return isinstance(s, str) and bool(_IFACE_RE.match(s))


def valid_name(s) -> bool:
    return isinstance(s, str) and bool(_NAME_RE.match(s.strip()))


def valid_port(p) -> bool:
    try:
        p = int(p)
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


def valid_cidr(s) -> bool:
    try:
        ipaddress.ip_network(str(s), strict=False)
        return True
    except ValueError:
        return False


def valid_host_ip(s) -> bool:
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


# ── Allocation ─────────────────────────────────────────────────────────────────
def next_iface(existing) -> str:
    """Lowest free rp-wgN given a list of in-use interface names."""
    used = set()
    for n in existing or []:
        m = _IFACE_RE.match(str(n or ""))
        if m:
            used.add(int(m.group(1)))
    i = 0
    while i in used:
        i += 1
    return f"rp-wg{i}"


def next_port(existing, base=PORT_BASE, span=PORT_SPAN) -> int:
    """Lowest free UDP port in [base, base+span)."""
    used = {int(p) for p in (existing or []) if valid_port(p)}
    for p in range(base, base + span):
        if p not in used:
            return p
    raise ValueError("no free WireGuard port in range")


def next_pool(existing_pools, base=POOL_BASE) -> str:
    """Next free /24 carved from `base` not overlapping any existing tunnel pool."""
    supernet = ipaddress.ip_network(base, strict=False)
    taken = []
    for c in existing_pools or []:
        try:
            taken.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    for sub in supernet.subnets(new_prefix=24):
        if not any(sub.overlaps(t) for t in taken):
            return str(sub)
    raise ValueError("no free /24 in the WireGuard supernet")


def hub_ip(pool_cidr) -> str:
    """The hub's address inside a tunnel pool — always the first host (.1)."""
    net = ipaddress.ip_network(str(pool_cidr), strict=False)
    return str(next(net.hosts()))


def alloc_client_ip(pool_cidr, used_ips) -> str:
    """Lowest free host in the pool, skipping the hub (.1) and any in `used_ips`.
    Returns a bare address (no prefix)."""
    net = ipaddress.ip_network(str(pool_cidr), strict=False)
    used = set(str(x).split("/")[0] for x in (used_ips or []))
    used.add(hub_ip(pool_cidr))
    for host in net.hosts():
        s = str(host)
        if s not in used:
            return s
    raise ValueError("tunnel address pool exhausted")


# ── Reach / AllowedIPs ──────────────────────────────────────────────────────────
def client_allowed_ips(tunnel, reach_cidrs) -> str:
    """The AllowedIPs string a client's config gets, from the tunnel's flags.

    * internet on  → full tunnel (0.0.0.0/0)
    * fleet scope  → hub /32 + each reachable device /32
    * neither      → dashboard-only: just the hub /32
    """
    if tunnel.get("allow_internet"):
        return "0.0.0.0/0"
    parts = [hub_ip(tunnel.get("pool", "")) + "/32"]
    for c in reach_cidrs or []:
        if valid_cidr(c):
            parts.append(str(c))
    # de-dup, stable order
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return ", ".join(out)


def needs_forwarding(tunnel, reach_cidrs) -> bool:
    """True when the hub must enable ip_forward + masquerade (fleet or internet).
    Dashboard-only tunnels need neither."""
    return bool(tunnel.get("allow_internet") or (reach_cidrs and len(reach_cidrs) > 0))


# ── Helper sync-spec ────────────────────────────────────────────────────────────
def build_sync_spec(tunnel, clients, reach_cidrs):
    """Structured spec the root helper consumes on `sync` (it re-validates every
    field and BUILDS the wg/nft config itself — no shell interpolation). Only
    enabled, non-expired clients are included (caller filters).

    #86: a client dict MAY carry a plaintext `preshared_key` (the caller is
    responsible for decrypting it first -- this module is a pure spec-builder,
    it never touches the encryption-at-rest layer). Invalid/malformed PSKs are
    dropped silently (the peer still syncs pubkey-only) rather than failing
    the whole tunnel sync over one bad field."""
    pool = tunnel.get("pool", "")
    peers = []
    for c in clients:
        if not valid_pubkey(c.get("pubkey")):
            continue
        addr = str(c.get("address", "")).split("/")[0]
        if not valid_host_ip(addr):
            continue
        peer = {"pubkey": c["pubkey"], "allowed_ips": addr + "/32"}
        if valid_psk(c.get("preshared_key")):
            peer["preshared_key"] = c["preshared_key"]
        peers.append(peer)
    return {
        "iface": tunnel.get("iface"),
        "listen_port": int(tunnel.get("listen_port") or 0),
        "address": hub_ip(pool) + "/" + str(ipaddress.ip_network(pool, strict=False).prefixlen),
        "forward": needs_forwarding(tunnel, reach_cidrs),
        "masquerade": bool(tunnel.get("allow_internet") or reach_cidrs),
        "reach_cidrs": [str(c) for c in (reach_cidrs or []) if valid_cidr(c)],
        "full_tunnel": bool(tunnel.get("allow_internet")),
        "peers": peers,
    }


# ── wg show dump parsing ────────────────────────────────────────────────────────
def parse_wg_dump(text):
    """Parse `wg show <iface> dump` into {pubkey: {endpoint, last_handshake,
    rx_bytes, tx_bytes}}. The first line is the interface itself (no peer pubkey
    in the per-peer sense) → skipped. Peer lines are tab-separated:
      pubkey  psk  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
    """
    out = {}
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    for ln in lines[1:]:  # line 0 = interface
        f = ln.split("\t")
        if len(f) < 7:
            continue
        pub = f[0]
        if not valid_pubkey(pub):
            continue
        endpoint = f[2] if f[2] != "(none)" else ""
        # strip :port for privacy (host only)
        host = endpoint.rsplit(":", 1)[0] if endpoint else ""
        try:
            hs = int(f[4])
        except ValueError:
            hs = 0
        try:
            rx = int(f[5])
            tx = int(f[6])
        except ValueError:
            rx = tx = 0
        out[pub] = {"endpoint": host, "last_handshake": hs, "rx_bytes": rx, "tx_bytes": tx}
    return out


def client_status(last_handshake, now) -> str:
    """connected / idle / offline from a last-handshake epoch."""
    if not last_handshake:
        return "offline"
    age = now - int(last_handshake)
    if age <= CONNECTED_WINDOW_S:
        return "connected"
    if age <= 3600:
        return "idle"
    return "offline"
