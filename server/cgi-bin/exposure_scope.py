"""RemotePower — an "internal" host and how its listeners are graded (v7.4.5, issue #55).

The agent grades each listening socket by the address it is bound to. A service on every address
(0.0.0.0 or ::) is graded "world". On a host behind a NAT firewall with no port forwards nothing
outside the local network can reach that service, and Docker makes the case constant, because a
published port binds every address by default. So the host carries a warning that is not an exposure.

An operator can mark such a host internal. Its wildcard listeners are then graded "lan" and carry
`assumed: true`, which the pages print as "assumed internal". The grade holds only while the host has
nothing but private addresses. A public IPv4 address, or any IPv6 address that is not local, puts the
listeners back to "world", because a NAT does not protect IPv6. A host that does not say what its
addresses are is treated the same way: what cannot be checked is not assumed.

Nothing here imports api. The caller hands in the switch, the addresses and the rows.

Why the rows are changed in place and kept as the agent reported them otherwise: a host that has not
changed its ports sends none, and the server hands its stored rows back. The `assumed` mark is what
lets a stored row be put back to "world" when the switch is turned off or a public address appears,
without keeping a second copy of the agent's grade.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# More addresses than this in one report are not taken as a complete list. A host with that many has
# more going on than the switch can vouch for, and a list cut short could hide the one public address.
MAX_ADDRESSES = 64

# Only these count as private. The standard library's own is_private is not used: for IPv6 it also
# covers 6to4 (2002::/16) and Teredo (2001::/32), which are tunnels to a public IPv4 address and are
# reachable from the internet, and for IPv4 it covers ranges nobody means by "my LAN".
_PRIVATE_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",  # RFC 1918
        "169.254.0.0/16",  # link-local
        "127.0.0.0/8",  # loopback
        "100.64.0.0/10",  # shared address space: carrier NAT, Tailscale
    )
)
_PRIVATE_V6 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::1/128",  # loopback
        "fe80::/10",  # link-local
        "fc00::/7",  # unique local
    )
)

REASONS = ("public_address", "no_address_data")


def _parse(addr: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address in a string, or None. A zone id ("fe80::1%eth0") is dropped: it names the interface."""
    if not isinstance(addr, str):
        return None
    text = addr.strip().split("%", 1)[0]
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # ::ffff:10.0.0.1 is the IPv4 address it carries
    return ip


def is_private(addr: Any) -> bool:
    """True for an address that cannot be reached from the internet. Anything that does not parse, and
    anything not listed above, is not private."""
    ip = _parse(addr)
    if ip is None:
        return False
    nets = _PRIVATE_V4 if ip.version == 4 else _PRIVATE_V6
    return any(ip in n for n in nets)


def clean_addresses(raw: Any) -> list[str] | None:
    """The addresses of a report as plain text without repeats, or None when the list cannot be taken
    as the whole truth: not a list, longer than MAX_ADDRESSES, or holding something that is not an
    address. None means "unknown", never "none"."""
    if not isinstance(raw, list) or len(raw) > MAX_ADDRESSES:
        return None
    out: list[str] = []
    for item in raw:
        ip = _parse(item)
        if ip is None:
            return None
        text = str(ip)
        if text not in out:
            out.append(text)
    return out


def assess(addresses: Any) -> tuple[str, list[str]]:
    """('private', []) when there is at least one address and every one is private, ('public', the ones
    that are not) when any is not, and ('unknown', []) when there is no list or it is empty. An empty
    list is not "nothing to worry about": a probe that found no address at all has not seen the host.
    """
    if not isinstance(addresses, list) or not addresses:
        return "unknown", []
    bad = [a for a in addresses if not is_private(a)]
    return ("public", bad) if bad else ("private", [])


def host_state(switch: Any, addresses: Any) -> dict:
    """What the switch does for one host right now.

    internal  the switch as an operator left it
    assumed   the switch is on and holds: the host has addresses and they are all private
    blocked   '' or why a switch that is on does not hold: 'public_address' (the host has an address
              that is not private) or 'no_address_data' (the agent does not report its addresses)
    public    the addresses that block it, at most eight
    """
    on = switch is True
    state, public = assess(addresses)
    assumed = on and state == "private"
    blocked = ""
    if on and not assumed:
        blocked = "public_address" if state == "public" else "no_address_data"
    return {"internal": on, "assumed": assumed, "blocked": blocked, "public": public[:8]}


def regrade(ports: Any, assumed: bool) -> int:
    """Grade the rows of a host's listening ports in place and return how many changed.

    assumed: a row the agent graded "world" becomes "lan" with `assumed: true`.
    not assumed: a row marked `assumed` goes back to "world" and loses the mark.
    A row the agent graded "lan" or "local" is never touched, and never gets the mark.
    """
    if not isinstance(ports, list):
        return 0
    changed = 0
    for row in ports:
        if not isinstance(row, dict):
            continue
        if assumed:
            if row.get("scope") == "world":
                row["scope"] = "lan"
                row["assumed"] = True
                changed += 1
        elif row.get("assumed"):
            row["scope"] = "world"
            row.pop("assumed", None)
            changed += 1
    return changed


def apply(switch: Any, sysinfo: Any) -> int:
    """Grade the listening ports in one sysinfo record for a host with this switch, by the addresses the
    same record carries. Returns how many rows changed."""
    if not isinstance(sysinfo, dict):
        return 0
    state, _ = assess(sysinfo.get("host_addresses"))
    return regrade(sysinfo.get("listening_ports"), switch is True and state == "private")
