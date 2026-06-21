# Network metrics

*Introduced in v5.0.0.*

The **Network metrics** page (Monitoring → Network metrics) shows per-device
network throughput across the fleet, built from the RX/TX byte-rate samples the
agents already report (`network_io` in the heartbeat). It answers "who's pushing
traffic right now, and where?" without standing up a separate flow collector.

## What it shows

- **Fleet totals** — total RX and TX across the devices in scope, and how many
  hosts are currently reporting interface counters.
- **A top-talkers table** — one row per device, sorted by RX+TX, with each host's
  busiest interface. The table is sortable and box-capped (it scrolls rather than
  growing without bound).
- **Roll-up tiles** — when you scope by group, tag or site, a tile per scope value
  shows that scope's aggregate RX/TX and device count.

Unmonitored and decommissioned hosts are *shown* (telemetry shouldn't hide a
machine that's still pushing traffic) but clearly flagged.

## Scope

A segmented control at the top of the page chooses how the data is grouped:

- **Fleet** — everything in one view, top talkers first.
- **Group** / **Tag** / **Site** — roll up by that dimension. A **site** typically
  represents a customer, so "by site" doubles as a per-customer throughput view.

RBAC applies: a scoped role only sees the devices it's allowed to see.

## Where the numbers come from

Each agent samples its interface counters every heartbeat and sends per-NIC
`rx_bps` / `tx_bps`. The server sums them per device and rolls them up by the
selected scope. There's nothing to configure on the agent; values appear as soon
as a host has reported at least one interval.

## API

`GET /api/network-metrics?by=fleet|group|tag|site`

Returns `{ by, totals: {rx_bps, tx_bps, devices, reporting}, tiles: [...],
devices: [{id, name, group, site, tags, rx_bps, tx_bps, ifaces, reporting,
monitored, decommissioned}] }`. The device list is capped at the top talkers.
