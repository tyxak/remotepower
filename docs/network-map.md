# Network map

*Introduced in v1.11.0. Drag-to-reposition and tunnels added in v1.11.1.*

The Network page renders your fleet as a node-and-edge graph based
on a `connected_to` field you fill in manually. No auto-discovery,
no LLDP polling, no ARP-table scraping — just a record of "this
plugs into that" maintained by hand. It sounds tedious but it isn't:
you set it up once when you add devices, occasionally when you
re-rack things, and the graph stays useful indefinitely.

*v1.11.1 adds two things*: drag any node to a position you prefer
(positions persist across refresh and across browsers — they're
stored on the server), and **tunnels** as a second kind of edge
between two devices (peer link, dashed amber, intended for VPN
tunnels and site-to-site links).

---

## What it shows

Every enrolled device and every agentless device appears as a node.
Online devices are green, offline ones are red. Agent devices are
outlined in accent blue; agentless devices (switches, APs, etc.)
are outlined in amber so you can see at a glance which are actively
heartbeating and which are user-maintained records.

Edges follow `connected_to`: if device A has `connected_to: B`, an
edge is drawn from A to B. Edges to non-existent devices are
silently dropped — convenient when you delete the upstream switch
without remembering to clear the downstream pointers, but worth
mentioning because it can leave nodes looking unconnected when
they aren't.

---

## Setting it up

Once your devices and agentless devices are in the system:

1. Click **Edit links** on the Network page.
2. The modal shows every device with a dropdown of all other
   devices as possible upstreams. Pick the right one for each.
3. Click **Save changes**. Each modified link saves as a separate
   API call (idempotent — you can hit Save multiple times with no
   ill effect).
4. Refresh — the graph renders with the new edges.

Devices with no upstream (the internet gateway, the root switch,
the edge router) get the empty `— none —` option. Self-links are
rejected at the API layer; that's not a useful topology.

The dropdown filters out the device itself, so you can't
accidentally pick yourself. It does NOT detect cycles
(`A → B → A`), because in some weird edge cases (LACP rings,
back-up links) you might want them. The graph rendering handles
cycles gracefully.

---

## Layout

The current layout is a simple "rows by device type" arrangement:
all switches in one row, routers in another, hosts in a third.
Edges are drawn straight between the connected nodes. It's not the
prettiest force-directed layout, but:

- It's deterministic — the same data always lays out the same way
- It runs in the browser without a layout library
- For 20-30 nodes (the homelab/small-business size) it works fine
- For 100+ nodes it gets cluttered, but at that scale you probably
  want a real network monitoring product

If you want a proper force-directed layout, the rendering function
in `server/html/index.html` (search for `renderNetmap`) is the
single point of replacement — drop in d3-force or a similar
library and you're done.

---

## API

`GET /api/network-map`:

```json
{
  "nodes": [
    {
      "id": "dev-abc123",
      "name": "web-1",
      "hostname": "web-1.lan",
      "ip": "10.0.0.10",
      "os": "Ubuntu 22.04",
      "type": "host",
      "group": "production",
      "agentless": false,
      "online": true
    },
    {
      "id": "al_5e3f4a",
      "name": "core-switch-1",
      "type": "switch",
      "agentless": true,
      "online": true
    }
  ],
  "edges": [
    {"from": "dev-abc123", "to": "al_5e3f4a"}
  ]
}
```

`PUT /api/devices/{id}/connected-to` with body
`{"connected_to": "<device_id>" | ""}` to set or clear the link.
Empty string clears it. Self-links and pointers to nonexistent
devices both get a 400.

---

## Why manual

Auto-discovery for "what's plugged into what" is genuinely hard:

- ARP tables tell you who's reachable on a subnet, not who's
  plugged into which port
- LLDP tells you neighbour information but only for managed
  switches that have it enabled, and not all consumer/SOHO gear
  does
- mDNS / SSDP / etc. find services, not topology
- Probing from multiple vantage points to triangulate is a real
  network monitoring product, not a sidebar feature

Since most homelab setups have under thirty nodes and don't move
around much, manual entry is fine and doesn't depend on managed-
switch fiddly bits. Auto-discovery is on the long-term roadmap as
its own release, not a feature snuck into v1.11.0.

---

## Why agentless devices matter for this

Until v1.11.0, the only way to have a device record in RemotePower
was to enrol an agent. That works for hosts but not for the things
that connect them — switches, APs, routers — which can't run a
Python agent. The map was useless without those nodes; agentless
devices fill the gap.

If you want a map of just the agented hosts, set their
`connected_to` to each other directly. The graph won't be wrong,
just less informative. The "real" payoff comes when you can model
the switches and APs too.

---

## Troubleshooting

**Edge missing despite setting connected_to.** Check the device
list response — `GET /api/devices` includes `connected_to` for
each device. If it's set there but doesn't show on the map, the
upstream device might have been deleted (dangling edges are
dropped silently). The Edit links modal will show the dropdown
selecting `— none —` for those.

**Layout is cluttered.** That's the layout, not the data. Either
reduce node count or replace `renderNetmap` with a real layout
library. The data structure is graph-friendly enough that any
JS graph library can render it directly.

**Cycle in the map.** Allowed but rendered as crossing edges. If
you genuinely have a back-up link or LACP ring, this is correct;
if it's a mistake, fix one of the `connected_to` values via the
Edit links modal.
