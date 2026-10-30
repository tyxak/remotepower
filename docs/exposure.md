# Exposure

**Security → Exposure** classifies every listening socket across the fleet
by where it can be reached from:

- **World** — bound to a public or wildcard address and reachable beyond
  your networks. A service that shouldn't be world-reachable raises the
  world-exposed-port check.
- **LAN** — private-network reachable.
- **Local** — loopback only.

## Using it

- Filter by class/host/port; sort by any column.
- **Mute** a finding (per host + port) when the exposure is intentional —
  mutes are honoured by the checks engine and alerting.
- Pairs with [Firewall](firewall.md) (is it *filtered*?) and
  [Pentest](security-scans.md) (is it *actually* reachable from outside?).

## Hosts behind a NAT firewall

A service that listens on every address (`0.0.0.0` or `::`) is graded **world**, because the host
cannot tell who can reach it. Docker does this for every published port. On a host behind a NAT
firewall with no port forwards, nothing outside your network can reach those services, so the
warning is not an exposure.

Mark such a host **internal**. Click **Treat as internal** beside one of its world sockets on the
Exposure page, or on the Ports card of the host. Only administrators can. Its services that listen
on every address are then graded **assumed internal**, which counts as LAN: they no longer raise the
*World-exposed ports* check, a *World-exposed service* alert or risk-score points. The Checks row
says how many services it is not warning about.

The mark holds only while every address the host has is private: 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 (Tailscale and carrier NAT), and for IPv6 fc00::/7
and fe80::/10. A public IPv4 address, or any IPv6 address that is not local, puts the services back
to **world**, because a NAT does not protect IPv6. The page then names the address. An agent that
does not report its addresses keeps the grade at world too, and the page says so: the Linux agent
reports them from 7.4.6 with its system information, about every ten minutes, and the Windows and
macOS agents do not yet.

A new listener is still reported, because *New listening port* does not depend on the grade. When
you turn the mark off, or a marked host gains a public address, the page changes at once. The
alerts follow at the host's next report, and each service that is world again raises *World-exposed
service* as if it had just been opened.
