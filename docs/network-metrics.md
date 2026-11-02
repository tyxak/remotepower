# Network Metrics

The **Network Metrics** page (**Monitoring → Network Metrics**) shows per-host
network throughput across the fleet, built from the receive and transmit rates the
agents already report with each check-in. It answers "who's pushing traffic right
now, and where?" without standing up a separate flow collector.

## What it shows

- **Total RX, Total TX and Reporting.** Receive and transmit across the hosts in
  scope, and how many hosts are currently reporting interface counters.
- **A By Group, By Tag or By Site table.** When you scope by group, tag or site, one
  row per value shows that scope's aggregate RX and TX and its host count. A host
  with several tags counts under each of them. A host with none counts under
  `(untagged)`.
- **Per-host throughput.** One row per host, sorted by RX plus TX, with the host's
  group and site and its busiest interface. The columns are sortable, and the table
  scrolls rather than growing without bound. It lists the top 300 hosts.

Rates are shown in bytes per second (B/s, KB/s, MB/s, GB/s).

Unmonitored and decommissioned hosts are *shown*, because telemetry shouldn't hide a
machine that is still pushing traffic. They carry an `unmon` or `decomm` badge.
Only alerting leaves them out.

## Scope

A segmented control at the top of the page chooses how the data is grouped:

- **Fleet**: everything in one view, top talkers first.
- **Group**, **Tag** and **Site**: roll up by that dimension. A **site** typically
  represents a customer, so "by site" doubles as a per-customer throughput view.

A scoped role only sees the hosts it is allowed to see.

## Where the numbers come from

Each agent reads its interface counters and works out a per-interface receive and
transmit rate from two samples, so a new agent shows nothing for the first
interval. The server adds the interfaces up per host and rolls the hosts up by the
scope you pick. There is nothing to configure: values appear as soon as a host has
reported two samples.

The agent leaves out the loopback interface and virtual interfaces that only carry
traffic between containers and bridges (`veth*`, `docker*`, `br-*`, `virbr*`,
`tap*`, `tun*`, `cni*` and `flannel*`). It reports up to 20 interfaces, busiest
first, and the page keeps the 12 busiest for each host. The Linux agent needs the
`psutil` Python module to collect them. The Windows and macOS agents report
interface rates too.

For where traffic goes rather than how much there is, see [Flow](flow.md), and for
how hosts are wired together, see [Network map](network-map.md).

## API

`GET /api/network-metrics?by=fleet|group|tag|site`

Returns

```json
{
  "by": "group",
  "totals": {"rx_bps": 0, "tx_bps": 0, "devices": 0, "reporting": 0},
  "tiles": [{"key": "", "name": "", "rx_bps": 0, "tx_bps": 0, "devices": 0}],
  "devices": [
    {"id": "", "name": "", "group": "", "site": "", "tags": [], "rx_bps": 0,
     "tx_bps": 0, "ifaces": [{"iface": "", "rx_bps": 0, "tx_bps": 0}],
     "reporting": true, "monitored": true, "decommissioned": false}
  ]
}
```

`tiles` is empty for `by=fleet`. Despite the name, the `*_bps` fields are bytes per
second. The `devices` list is capped at the top 300 talkers and `tiles` at 120.

## See also

- [Network map](network-map.md): the topology.
- [Flow](flow.md): NetFlow and IPFIX.
