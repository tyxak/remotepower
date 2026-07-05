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
